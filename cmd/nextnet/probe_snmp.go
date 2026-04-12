package nextnet

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// ProbeSNMP sends SNMP v2c GET and v3 discovery probes via UDP port 161.
type ProbeSNMP struct {
	Probe
	socket  net.PacketConn
	mu      sync.Mutex
	pending map[string]*snmpPendingResult
}

// snmpPendingResult accumulates SNMP responses for a single target IP.
type snmpPendingResult struct {
	sent     time.Time
	sysDescr string
	sysName  string
	hwAddr   string
	ips      []string
	engineID string
}

// ---- BER encoding helpers ----

func snmpBerEncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length <= 0xff {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length & 0xff)}
}

func snmpBerWrap(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, snmpBerEncodeLength(len(content))...)
	out = append(out, content...)
	return out
}

func snmpBerSequence(parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return snmpBerWrap(0x30, content)
}

func snmpBerConstructed(tag byte, parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return snmpBerWrap(tag, content)
}

func snmpBerInteger(value int) []byte {
	if value == 0 {
		return snmpBerWrap(0x02, []byte{0})
	}
	var buf []byte
	if value > 0 {
		v := value
		for v > 0 {
			buf = append([]byte{byte(v & 0xff)}, buf...)
			v >>= 8
		}
		// Leading zero to keep the value positive in two's complement.
		if buf[0]&0x80 != 0 {
			buf = append([]byte{0}, buf...)
		}
	} else {
		v := value
		for v < -1 {
			buf = append([]byte{byte(v & 0xff)}, buf...)
			v >>= 8
		}
		buf = append([]byte{byte(v & 0xff)}, buf...)
	}
	return snmpBerWrap(0x02, buf)
}

func snmpBerOctetString(value []byte) []byte {
	return snmpBerWrap(0x04, value)
}

func snmpBerNull() []byte {
	return []byte{0x05, 0x00}
}

func snmpBerEncodeOIDComponent(value int) []byte {
	if value < 128 {
		return []byte{byte(value)}
	}
	var result []byte
	result = append(result, byte(value&0x7f))
	value >>= 7
	for value > 0 {
		result = append([]byte{byte(value&0x7f | 0x80)}, result...)
		value >>= 7
	}
	return result
}

func snmpBerOID(oid []int) []byte {
	if len(oid) < 2 {
		return snmpBerWrap(0x06, nil)
	}
	content := []byte{byte(oid[0]*40 + oid[1])}
	for i := 2; i < len(oid); i++ {
		content = append(content, snmpBerEncodeOIDComponent(oid[i])...)
	}
	return snmpBerWrap(0x06, content)
}

// ---- BER decoding helpers ----

func snmpBerDecodeLength(data []byte) (length int, consumed int) {
	if len(data) == 0 {
		return 0, -1
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	n := int(data[0] & 0x7f)
	if n == 0 || len(data) < 1+n {
		return 0, -1
	}
	length = 0
	for i := 1; i <= n; i++ {
		length = (length << 8) | int(data[i])
	}
	return length, 1 + n
}

type snmpBerElement struct {
	tag     byte
	content []byte
}

func snmpBerDecodeTLV(data []byte) (elem snmpBerElement, rest []byte, err error) {
	if len(data) < 2 {
		return elem, nil, fmt.Errorf("data too short for TLV")
	}
	elem.tag = data[0]
	length, consumed := snmpBerDecodeLength(data[1:])
	if consumed < 0 {
		return elem, nil, fmt.Errorf("invalid BER length")
	}
	end := 1 + consumed + length
	if len(data) < end {
		return elem, nil, fmt.Errorf("truncated TLV")
	}
	elem.content = data[1+consumed : end]
	rest = data[end:]
	return elem, rest, nil
}

func snmpBerDecodeInteger(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	val := 0
	if data[0]&0x80 != 0 {
		val = -1 // sign-extend for negative values
	}
	for _, b := range data {
		val = (val << 8) | int(b)
	}
	return val
}

func snmpBerDecodeOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	parts := []string{
		fmt.Sprintf("%d", int(data[0])/40),
		fmt.Sprintf("%d", int(data[0])%40),
	}
	i := 1
	for i < len(data) {
		val := 0
		for i < len(data) {
			val = (val << 7) | int(data[i]&0x7f)
			if data[i]&0x80 == 0 {
				i++
				break
			}
			i++
		}
		parts = append(parts, fmt.Sprintf("%d", val))
	}
	return strings.Join(parts, ".")
}

// ---- SNMP varbind parsing ----

type snmpVarbind struct {
	oid      string
	valueTag byte
	value    []byte
}

func snmpParseVarbindList(data []byte) []snmpVarbind {
	var result []snmpVarbind
	rest := data
	for len(rest) > 0 {
		vbElem, remaining, err := snmpBerDecodeTLV(rest)
		if err != nil || vbElem.tag != 0x30 {
			break
		}
		rest = remaining
		oidElem, valData, err := snmpBerDecodeTLV(vbElem.content)
		if err != nil || oidElem.tag != 0x06 {
			continue
		}
		valElem, _, err := snmpBerDecodeTLV(valData)
		if err != nil {
			continue
		}
		result = append(result, snmpVarbind{
			oid:      snmpBerDecodeOID(oidElem.content),
			valueTag: valElem.tag,
			value:    valElem.content,
		})
	}
	return result
}

// ---- SNMP packet builders ----

// buildV2cGetRequest builds an SNMPv2c GET for sysDescr.0 and sysName.0.
func (p *ProbeSNMP) buildV2cGetRequest() []byte {
	reqID := rand.Int31() // #nosec G404

	// sysDescr.0  = 1.3.6.1.2.1.1.1.0
	// sysName.0   = 1.3.6.1.2.1.1.5.0
	vb1 := snmpBerSequence(snmpBerOID([]int{1, 3, 6, 1, 2, 1, 1, 1, 0}), snmpBerNull())
	vb2 := snmpBerSequence(snmpBerOID([]int{1, 3, 6, 1, 2, 1, 1, 5, 0}), snmpBerNull())
	vbList := snmpBerSequence(vb1, vb2)

	// GetRequest PDU (tag 0xa0)
	pdu := snmpBerConstructed(0xa0,
		snmpBerInteger(int(reqID)),
		snmpBerInteger(0),
		snmpBerInteger(0),
		vbList,
	)

	// version 1 = SNMPv2c, community "public"
	return snmpBerSequence(
		snmpBerInteger(1),
		snmpBerOctetString([]byte("public")),
		pdu,
	)
}

// buildV2cGetNextRequest builds an SNMPv2c GET-NEXT for ifPhysAddress and ipAdEntAddr.
func (p *ProbeSNMP) buildV2cGetNextRequest() []byte {
	reqID := rand.Int31() // #nosec G404

	// ifPhysAddress  = 1.3.6.1.2.1.2.2.1.6
	// ipAdEntAddr    = 1.3.6.1.2.1.4.20.1.1
	vb1 := snmpBerSequence(snmpBerOID([]int{1, 3, 6, 1, 2, 1, 2, 2, 1, 6}), snmpBerNull())
	vb2 := snmpBerSequence(snmpBerOID([]int{1, 3, 6, 1, 2, 1, 4, 20, 1, 1}), snmpBerNull())
	vbList := snmpBerSequence(vb1, vb2)

	// GetNextRequest PDU (tag 0xa1)
	pdu := snmpBerConstructed(0xa1,
		snmpBerInteger(int(reqID)),
		snmpBerInteger(0),
		snmpBerInteger(0),
		vbList,
	)

	return snmpBerSequence(
		snmpBerInteger(1),
		snmpBerOctetString([]byte("public")),
		pdu,
	)
}

// buildV3DiscoveryRequest builds an SNMPv3 discovery message (no auth, no priv).
func (p *ProbeSNMP) buildV3DiscoveryRequest() []byte {
	msgID := rand.Int31() // #nosec G404

	// USM security parameters: all fields empty/zero.
	usmParams := snmpBerSequence(
		snmpBerOctetString(nil), // msgAuthoritativeEngineID
		snmpBerInteger(0),       // msgAuthoritativeEngineBoots
		snmpBerInteger(0),       // msgAuthoritativeEngineTime
		snmpBerOctetString(nil), // msgUserName
		snmpBerOctetString(nil), // msgAuthenticationParameters
		snmpBerOctetString(nil), // msgPrivacyParameters
	)

	// HeaderData
	header := snmpBerSequence(
		snmpBerInteger(int(msgID)),
		snmpBerInteger(65507),
		snmpBerOctetString([]byte{0x04}), // reportable, noAuth, noPriv
		snmpBerInteger(3),                // USM security model
	)

	// ScopedPDU with empty GetRequest
	emptyVBList := snmpBerSequence()
	pdu := snmpBerConstructed(0xa0,
		snmpBerInteger(0),
		snmpBerInteger(0),
		snmpBerInteger(0),
		emptyVBList,
	)
	scopedPDU := snmpBerSequence(
		snmpBerOctetString(nil), // contextEngineID
		snmpBerOctetString(nil), // contextName
		pdu,
	)

	return snmpBerSequence(
		snmpBerInteger(3), // version = SNMPv3
		header,
		snmpBerOctetString(usmParams), // security params wrapped as OCTET STRING
		scopedPDU,
	)
}

// ---- Response parsers ----

// parseV2cResponse decodes an SNMPv1/v2c GetResponse and returns the varbinds.
func (p *ProbeSNMP) parseV2cResponse(data []byte) ([]snmpVarbind, error) {
	msg, _, err := snmpBerDecodeTLV(data)
	if err != nil || msg.tag != 0x30 {
		return nil, fmt.Errorf("not a SEQUENCE")
	}

	verElem, rest, err := snmpBerDecodeTLV(msg.content)
	if err != nil || verElem.tag != 0x02 {
		return nil, fmt.Errorf("no version")
	}
	version := snmpBerDecodeInteger(verElem.content)
	if version != 0 && version != 1 { // accept v1 (0) and v2c (1)
		return nil, fmt.Errorf("not v1/v2c (version=%d)", version)
	}

	// community
	_, rest, err = snmpBerDecodeTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("no community")
	}

	// GetResponse PDU (0xa2)
	pduElem, _, err := snmpBerDecodeTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("no PDU")
	}
	if pduElem.tag != 0xa2 {
		return nil, fmt.Errorf("not GetResponse (tag=0x%02x)", pduElem.tag)
	}

	// request-id
	_, rest, err = snmpBerDecodeTLV(pduElem.content)
	if err != nil {
		return nil, fmt.Errorf("no request-id")
	}

	// error-status
	errElem, rest, err := snmpBerDecodeTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("no error-status")
	}
	if snmpBerDecodeInteger(errElem.content) != 0 {
		return nil, fmt.Errorf("SNMP error-status=%d", snmpBerDecodeInteger(errElem.content))
	}

	// error-index
	_, rest, err = snmpBerDecodeTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("no error-index")
	}

	// VarBindList
	vbListElem, _, err := snmpBerDecodeTLV(rest)
	if err != nil || vbListElem.tag != 0x30 {
		return nil, fmt.Errorf("no varbind list")
	}

	return snmpParseVarbindList(vbListElem.content), nil
}

// parseV3Response decodes an SNMPv3 response and extracts the engine ID from
// the USM security parameters.
func (p *ProbeSNMP) parseV3Response(data []byte) (string, error) {
	msg, _, err := snmpBerDecodeTLV(data)
	if err != nil || msg.tag != 0x30 {
		return "", fmt.Errorf("not a SEQUENCE")
	}

	verElem, rest, err := snmpBerDecodeTLV(msg.content)
	if err != nil || verElem.tag != 0x02 {
		return "", fmt.Errorf("no version")
	}
	if snmpBerDecodeInteger(verElem.content) != 3 {
		return "", fmt.Errorf("not v3")
	}

	// skip HeaderData
	_, rest, err = snmpBerDecodeTLV(rest)
	if err != nil {
		return "", fmt.Errorf("no header")
	}

	// msgSecurityParameters (OCTET STRING wrapping the BER-encoded USM SEQUENCE)
	secElem, _, err := snmpBerDecodeTLV(rest)
	if err != nil {
		return "", fmt.Errorf("no security params")
	}

	usmSeq, _, err := snmpBerDecodeTLV(secElem.content)
	if err != nil || usmSeq.tag != 0x30 {
		return "", fmt.Errorf("USM not a SEQUENCE")
	}

	// First field: msgAuthoritativeEngineID
	engineElem, _, err := snmpBerDecodeTLV(usmSeq.content)
	if err != nil {
		return "", fmt.Errorf("no engine ID")
	}
	if len(engineElem.content) == 0 {
		return "", fmt.Errorf("empty engine ID")
	}

	return hex.EncodeToString(engineElem.content), nil
}

// ---- Probe lifecycle ----

// Initialize sets up the SNMP probe goroutines and opens the UDP socket.
func (p *ProbeSNMP) Initialize() {
	p.Setup()
	p.name = "snmp"
	p.pending = make(map[string]*snmpPendingResult)
	p.waiter.Add(1)

	var err error
	p.socket, err = net.ListenPacket("udp", "")
	if err != nil {
		log.Printf("probe %s failed to open socket: %s", p, err)
		p.waiter.Done()
		return
	}

	go func() {
		go p.processReplies()

		for ip := range p.input {
			p.sendProbes(ip)
			p.mu.Lock()
			n := len(p.pending)
			p.mu.Unlock()
			if n > MaxPendingReplies {
				log.Printf("probe %s flushing (max replies reached: %d)", p, n)
				time.Sleep(MaxProbeResponseTime)
				p.flushPending()
			}
		}

		log.Printf("probe %s waiting for final replies", p)
		time.Sleep(MaxProbeResponseTime)
		p.socket.Close()
		p.flushPending()
		p.waiter.Done()
	}()
}

func (p *ProbeSNMP) sendProbes(ip string) {
	addr, err := net.ResolveUDPAddr("udp", ip+":161")
	if err != nil {
		log.Printf("probe %s failed to resolve %s: %s", p, ip, err)
		return
	}

	p.mu.Lock()
	p.pending[ip] = &snmpPendingResult{sent: time.Now()}
	p.mu.Unlock()

	// v2c GET for sysDescr.0 + sysName.0
	p.CheckRateLimit()
	if _, werr := p.socket.WriteTo(p.buildV2cGetRequest(), addr); werr != nil {
		log.Printf("probe %s failed to send v2c GET to %s: %s", p, ip, werr)
	}

	// v2c GET-NEXT for ifPhysAddress + ipAdEntAddr
	p.CheckRateLimit()
	if _, werr := p.socket.WriteTo(p.buildV2cGetNextRequest(), addr); werr != nil {
		log.Printf("probe %s failed to send v2c GETNEXT to %s: %s", p, ip, werr)
	}

	// v3 discovery
	p.CheckRateLimit()
	if _, werr := p.socket.WriteTo(p.buildV3DiscoveryRequest(), addr); werr != nil {
		log.Printf("probe %s failed to send v3 discovery to %s: %s", p, ip, werr)
	}
}

func (p *ProbeSNMP) processReplies() {
	buf := make([]byte, 4096)
	for {
		n, raddr, rerr := p.socket.ReadFrom(buf)
		if rerr != nil {
			if nerr, ok := rerr.(net.Error); ok && nerr.Timeout() {
				log.Printf("probe %s receiver timed out: %s", p, rerr)
				continue
			}
			log.Printf("probe %s receiver returned error: %s", p, rerr)
			return
		}
		if n < 2 {
			continue
		}

		ip := raddr.(*net.UDPAddr).IP.String()
		data := make([]byte, n)
		copy(data, buf[:n])

		// Try v2c parse
		if varbinds, verr := p.parseV2cResponse(data); verr == nil {
			p.mu.Lock()
			if info, ok := p.pending[ip]; ok {
				p.applyV2cVarbinds(info, varbinds)
			}
			p.mu.Unlock()
			continue
		}

		// Try v3 parse
		if engineID, verr := p.parseV3Response(data); verr == nil {
			p.mu.Lock()
			if info, ok := p.pending[ip]; ok {
				info.engineID = engineID
			}
			p.mu.Unlock()
		}
	}
}

// applyV2cVarbinds merges parsed varbind data into the pending result.
// Caller must hold p.mu.
func (p *ProbeSNMP) applyV2cVarbinds(info *snmpPendingResult, varbinds []snmpVarbind) {
	for _, vb := range varbinds {
		switch {
		case vb.oid == "1.3.6.1.2.1.1.1.0" && vb.valueTag == 0x04: // sysDescr.0
			info.sysDescr = string(vb.value)

		case vb.oid == "1.3.6.1.2.1.1.5.0" && vb.valueTag == 0x04: // sysName.0
			info.sysName = string(vb.value)

		case strings.HasPrefix(vb.oid, "1.3.6.1.2.1.2.2.1.6.") && vb.valueTag == 0x04: // ifPhysAddress
			if len(vb.value) == 6 && info.hwAddr == "" {
				hw := fmt.Sprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
					vb.value[0], vb.value[1], vb.value[2],
					vb.value[3], vb.value[4], vb.value[5])
				if hw != "00:00:00:00:00:00" {
					info.hwAddr = hw
				}
			}

		case strings.HasPrefix(vb.oid, "1.3.6.1.2.1.4.20.1.1."): // ipAdEntAddr
			// IpAddress is APPLICATION 0 (tag 0x40); some agents use OCTET STRING (0x04)
			if (vb.valueTag == 0x40 || vb.valueTag == 0x04) && len(vb.value) == 4 {
				addr := fmt.Sprintf("%d.%d.%d.%d",
					vb.value[0], vb.value[1], vb.value[2], vb.value[3])
				if addr != "0.0.0.0" && addr != "127.0.0.1" {
					info.ips = append(info.ips, addr)
				}
			}
		}
	}
}

func (p *ProbeSNMP) reportPending(ip string, info *snmpPendingResult) {
	if info.sysDescr == "" && info.sysName == "" && info.hwAddr == "" &&
		info.engineID == "" && len(info.ips) == 0 {
		return
	}

	res := ScanResult{
		Host:  ip,
		Port:  "161",
		Proto: "udp",
		Probe: "snmp",
		Info:  make(map[string]string),
	}
	if info.sysDescr != "" {
		res.Info["sysDescr"] = info.sysDescr
	}
	if info.sysName != "" {
		res.Name = info.sysName
	}
	if info.hwAddr != "" {
		res.Info["hwaddr"] = info.hwAddr
	}
	if info.engineID != "" {
		res.Info["snmpv3_engine_id"] = info.engineID
	}
	if len(info.ips) > 0 {
		res.Nets = info.ips
	}

	p.output <- res
}

func (p *ProbeSNMP) flushPending() {
	p.mu.Lock()
	old := p.pending
	p.pending = make(map[string]*snmpPendingResult)
	p.mu.Unlock()

	for ip, info := range old {
		p.reportPending(ip, info)
	}
}

func init() {
	probes = append(probes, new(ProbeSNMP))
}
