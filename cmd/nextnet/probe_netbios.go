package nextnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

const MaxPendingReplies int = 256
const MaxProbeResponseTime time.Duration = time.Second * 2

// NetbiosInfo tracks state for a single target IP across the two-phase
// (status → name) NetBIOS probe exchange.
type NetbiosInfo struct {
	statusRecv  time.Time
	nameSent    time.Time
	nameRecv    time.Time
	statusReply NetbiosReplyStatus
	nameReply   NetbiosReplyStatus
}

// ProbeNetbios sends UDP NetBIOS name-service queries and decodes replies.
type ProbeNetbios struct {
	Probe
	socket  net.PacketConn
	replies map[string]*NetbiosInfo
}

// NetbiosReplyHeader is the fixed-length header present in every NBNS reply.
type NetbiosReplyHeader struct {
	XID             uint16
	Flags           uint16
	QuestionCount   uint16
	AnswerCount     uint16
	AuthCount       uint16
	AdditionalCount uint16
	QuestionName    [34]byte
	RecordType      uint16
	RecordClass     uint16
	RecordTTL       uint32
	RecordLength    uint16
}

// NetbiosReplyName holds a single NBNS name entry.
type NetbiosReplyName struct {
	Name [15]byte
	Type uint8
	Flag uint16
}

// NetbiosReplyAddress holds a single IP address from an NBNS name reply.
type NetbiosReplyAddress struct {
	Flag    uint16
	Address [4]uint8
}

// NetbiosReplyStatus is the decoded payload of a NetBIOS reply.
type NetbiosReplyStatus struct {
	Header    NetbiosReplyHeader
	HostName  [15]byte
	UserName  [15]byte
	Names     []NetbiosReplyName
	Addresses []NetbiosReplyAddress
	HWAddr    string
}

// ProcessReplies reads incoming UDP packets and dispatches them as status or
// name replies.
func (this *ProbeNetbios) ProcessReplies() {
	buff := make([]byte, 1500)
	this.replies = make(map[string]*NetbiosInfo)

	for {
		rlen, raddr, rerr := this.socket.ReadFrom(buff)
		if rerr != nil {
			if nerr, ok := rerr.(net.Error); ok && nerr.Timeout() {
				log.Printf("probe %s receiver timed out: %s", this, rerr)
				continue
			}
			log.Printf("probe %s receiver returned error: %s", this, rerr)
			return
		}

		ip := raddr.(*net.UDPAddr).IP.String()
		if rlen < 1 {
			continue
		}
		reply := this.ParseReply(buff[0 : rlen-1])
		if len(reply.Names) == 0 && len(reply.Addresses) == 0 {
			continue
		}

		if _, found := this.replies[ip]; !found {
			this.replies[ip] = new(NetbiosInfo)
		}

		// Status reply → send name request
		if reply.Header.RecordType == 0x21 {
			this.replies[ip].statusReply = reply
			this.replies[ip].statusRecv = time.Now()
			if this.replies[ip].nameSent.IsZero() {
				this.replies[ip].nameSent = time.Now()
				this.SendNameRequest(ip)
			}
		}

		// Name reply → report result
		if reply.Header.RecordType == 0x20 {
			this.replies[ip].nameReply = reply
			this.replies[ip].nameRecv = time.Now()
			this.ReportResult(ip)
		}
	}
}

// SendRequest transmits an NBNS request to ip:137 with retry logic.
func (this *ProbeNetbios) SendRequest(ip string, req []byte) {
	addr, aerr := net.ResolveUDPAddr("udp", ip+":137")
	if aerr != nil {
		log.Printf("probe %s failed to resolve %s (%s)", this, ip, aerr)
		return
	}
	for wcnt := 0; wcnt < 5; wcnt++ {
		this.CheckRateLimit()
		if _, werr := this.socket.WriteTo(req, addr); werr != nil {
			log.Printf("probe %s [%d/5] failed to send to %s (%s)", this, wcnt+1, ip, werr)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return
	}
	log.Printf("probe %s gave up sending to %s", this, ip)
}

// SendStatusRequest sends the initial NBNS status probe to ip.
func (this *ProbeNetbios) SendStatusRequest(ip string) {
	this.SendRequest(ip, this.CreateStatusRequest())
}

// SendNameRequest sends an NBNS name-resolution probe for the host named in
// the previously received status reply.
func (this *ProbeNetbios) SendNameRequest(ip string) {
	name := TrimName(string(this.replies[ip].statusReply.HostName[:]))
	this.SendRequest(ip, this.CreateNameRequest(name))
}

// ResultFromIP assembles a ScanResult from the recorded NBNS replies for ip.
func (this *ProbeNetbios) ResultFromIP(ip string) ScanResult {
	sreply := this.replies[ip].statusReply
	nreply := this.replies[ip].nameReply

	res := ScanResult{
		Host:  ip,
		Port:  "137",
		Proto: "udp",
		Probe: this.String(),
	}
	res.Info = make(map[string]string)
	res.Name = TrimName(string(sreply.HostName[:]))

	if nreply.Header.RecordType == 0x20 {
		for _, ainfo := range nreply.Addresses {
			addr := fmt.Sprintf("%d.%d.%d.%d",
				ainfo.Address[0], ainfo.Address[1],
				ainfo.Address[2], ainfo.Address[3])
			if addr == "0.0.0.0" {
				continue
			}
			res.Nets = append(res.Nets, addr)
		}
	}

	if sreply.HWAddr != "00:00:00:00:00:00" {
		res.Info["hwaddr"] = sreply.HWAddr
	}

	username := TrimName(string(sreply.UserName[:]))
	if len(username) > 0 && username != res.Name {
		res.Info["username"] = username
	}

	for _, rname := range sreply.Names {
		tname := TrimName(string(rname.Name[:]))
		if tname == res.Name {
			continue
		}
		if rname.Flag&0x0800 != 0 {
			continue
		}
		res.Info["domain"] = tname
	}

	return res
}

// ReportResult emits the result for ip on the output channel.
func (this *ProbeNetbios) ReportResult(ip string) {
	this.output <- this.ResultFromIP(ip)
	delete(this.replies, ip)
}

// ReportIncompleteResults reports any hosts for which we got a status reply
// but no name reply (e.g. the target timed out on the name request).
func (this *ProbeNetbios) ReportIncompleteResults() {
	for ip := range this.replies {
		this.ReportResult(ip)
	}
}

// EncodeNetbiosName encodes a 16-byte name using the standard NBNS encoding.
func (this *ProbeNetbios) EncodeNetbiosName(name [16]byte) [32]byte {
	encoded := [32]byte{}
	for i := 0; i < 16; i++ {
		if name[i] == 0 {
			encoded[(i*2)+0] = 'C'
			encoded[(i*2)+1] = 'A'
		} else {
			encoded[(i*2)+0] = byte((name[i]/16)+0x41)
			encoded[(i*2)+1] = byte((name[i]%16)+0x41)
		}
	}
	return encoded
}

// DecodeNetbiosName reverses the NBNS name encoding.
func (this *ProbeNetbios) DecodeNetbiosName(name [32]byte) [16]byte {
	decoded := [16]byte{}
	for i := 0; i < 16; i++ {
		if name[(i*2)+0] == 'C' && name[(i*2)+1] == 'A' {
			decoded[i] = 0
		} else {
			decoded[i] = ((name[(i*2)+0] * 16) - 0x41) + (name[(i*2)+1] - 0x41)
		}
	}
	return decoded
}

// ParseReply decodes raw bytes from an NBNS response into a NetbiosReplyStatus.
func (this *ProbeNetbios) ParseReply(buff []byte) NetbiosReplyStatus {
	resp := NetbiosReplyStatus{}
	temp := bytes.NewBuffer(buff)

	binary.Read(temp, binary.BigEndian, &resp.Header) // #nosec G104

	if resp.Header.QuestionCount != 0 || resp.Header.AnswerCount == 0 {
		return resp
	}

	if resp.Header.RecordType == 0x21 {
		var rcnt uint8
		binary.Read(temp, binary.BigEndian, &rcnt) // #nosec G104
		for i := uint8(0); i < rcnt; i++ {
			name := NetbiosReplyName{}
			binary.Read(temp, binary.BigEndian, &name) // #nosec G104
			resp.Names = append(resp.Names, name)
			if name.Type == 0x20 {
				resp.HostName = name.Name
			}
			if name.Type == 0x03 {
				resp.UserName = name.Name
			}
		}
		var hwbytes [6]uint8
		binary.Read(temp, binary.BigEndian, &hwbytes) // #nosec G104
		resp.HWAddr = fmt.Sprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			hwbytes[0], hwbytes[1], hwbytes[2], hwbytes[3], hwbytes[4], hwbytes[5])
		return resp
	}

	if resp.Header.RecordType == 0x20 {
		for ridx := uint16(0); ridx < resp.Header.RecordLength/6; ridx++ {
			addr := NetbiosReplyAddress{}
			binary.Read(temp, binary.BigEndian, &addr) // #nosec G104
			resp.Addresses = append(resp.Addresses, addr)
		}
	}

	return resp
}

// CreateStatusRequest builds the fixed-format NBNS node-status request packet.
func (this *ProbeNetbios) CreateStatusRequest() []byte {
	return []byte{
		byte(rand.Intn(256)), byte(rand.Intn(256)), // #nosec G404
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
	}
}

// CreateNameRequest builds an NBNS name query for the given hostname.
func (this *ProbeNetbios) CreateNameRequest(name string) []byte {
	nbytes := [16]byte{}
	upperName := strings.ToUpper(name)
	if len(upperName) > 15 {
		upperName = upperName[:15]
	}
	copy(nbytes[0:15], []byte(upperName))

	req := []byte{
		byte(rand.Intn(256)), byte(rand.Intn(256)), // #nosec G404
		0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x20,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00, 0x00, 0x20, 0x00, 0x01,
	}
	encoded := this.EncodeNetbiosName(nbytes)
	copy(req[13:45], encoded[0:32])
	return req
}

// Initialize sets up the probe goroutine and opens the UDP socket.
func (this *ProbeNetbios) Initialize() {
	this.Setup()
	this.name = "netbios"
	this.waiter.Add(1)

	var err error
	this.socket, err = net.ListenPacket("udp", "")
	if err != nil {
		log.Printf("probe %s failed to open socket: %s", this, err)
		this.waiter.Done()
		return
	}

	go func() {
		go this.ProcessReplies()

		for dip := range this.input {
			this.SendStatusRequest(dip)
			if len(this.replies) > MaxPendingReplies {
				log.Printf("probe %s flushing (max replies reached: %d)", this, len(this.replies))
				time.Sleep(MaxProbeResponseTime)
				this.ReportIncompleteResults()
			}
		}

		log.Printf("probe %s waiting for final status replies", this)
		time.Sleep(MaxProbeResponseTime)
		log.Printf("probe %s waiting for final name replies", this)
		time.Sleep(MaxProbeResponseTime)
		this.socket.Close()
		this.ReportIncompleteResults()
		this.waiter.Done()
	}()
}

func init() {
	probes = append(probes, new(ProbeNetbios))
}
