package input_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/runZeroInc/runZeroHound/pkg/input"
)

// TestDetectFileType validates file type detection.
func TestDetectFileType(t *testing.T) {
	dir := t.TempDir()

	writeFile := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}

	tests := []struct {
		filename string
		content  string
		want     input.FileType
	}{
		{
			filename: "scan.nxt",
			content:  `{"host":"1.2.3.4","probe":"netbios"}`,
			want:     input.FileTypeNextnet,
		},
		{
			filename: "scan.xml",
			content:  `<?xml version="1.0"?><nmaprun></nmaprun>`,
			want:     input.FileTypeNmapXML,
		},
		{
			filename: "scan.txt",
			content:  "SNMPv2-MIB::sysDescr.0 = STRING: Linux\nSNMPv2-MIB::sysName.0 = STRING: router\n",
			want:     input.FileTypeSNMPWalk,
		},
		{
			filename: "assets.jsonl",
			content:  `{"id":"aaa","addresses":["1.2.3.4"]}`,
			want:     input.FileTypeRunZeroJSONL,
		},
	}

	for _, tc := range tests {
		tc := tc
		path := writeFile(tc.filename, tc.content)
		t.Run(tc.filename, func(t *testing.T) {
			got, err := input.DetectFileType(path)
			if err != nil {
				t.Fatalf("DetectFileType(%s): %v", path, err)
			}
			if got != tc.want {
				t.Errorf("DetectFileType(%s) = %v, want %v", path, got, tc.want)
			}
		})
	}
}

// TestParseNmapXML validates Nmap XML parsing.
func TestParseNmapXML(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="myhost.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.4" accuracy="95"/></os>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>`

	path := filepath.Join(t.TempDir(), "test.xml")
	if err := os.WriteFile(path, []byte(xml), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseNmapXML(path)
	if err != nil {
		t.Fatalf("ParseNmapXML: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1 (down host must be excluded)", len(result.Hosts))
	}
	h := result.Hosts[0]
	if len(h.Addresses) == 0 || h.Addresses[0] != "10.0.0.1" {
		t.Errorf("unexpected addresses: %v", h.Addresses)
	}
	if len(h.Names) == 0 || h.Names[0] != "myhost.local" {
		t.Errorf("unexpected names: %v", h.Names)
	}
	if h.OS != "Linux 5.4" {
		t.Errorf("unexpected OS: %q", h.OS)
	}
	if len(h.Services) != 1 {
		t.Fatalf("got %d services, want 1", len(h.Services))
	}
	svc := h.Services[0]
	if svc.Port != "22" || svc.Protocol != "tcp" {
		t.Errorf("unexpected service: %+v", svc)
	}
}

// TestParseSNMPWalk validates snmpwalk parsing.
func TestParseSNMPWalk(t *testing.T) {
	content := `# Target: 10.0.0.5
SNMPv2-MIB::sysDescr.0 = STRING: Linux myswitch 5.15.0
SNMPv2-MIB::sysName.0 = STRING: myswitch
IF-MIB::ifPhysAddress.1 = Hex-STRING: AA BB CC DD EE FF
SNMP-FRAMEWORK-MIB::snmpEngineID.0 = Hex-STRING: 80 00 1F 88 04 DE AD BE EF
IP-MIB::ipAdEntAddr.10.0.0.5 = IpAddress: 10.0.0.5
`

	path := filepath.Join(t.TempDir(), "walk.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseSNMPWalk(path)
	if err != nil {
		t.Fatalf("ParseSNMPWalk: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(result.Hosts))
	}
	h := result.Hosts[0]
	if len(h.Addresses) == 0 || h.Addresses[0] != "10.0.0.5" {
		t.Errorf("unexpected addresses: %v", h.Addresses)
	}
	if len(h.Names) == 0 || h.Names[0] != "myswitch" {
		t.Errorf("unexpected names: %v", h.Names)
	}
	if _, ok := h.UniqueKeys["snmpv3_engine_id"]; !ok {
		t.Error("expected snmpv3_engine_id unique key to be set")
	}
}

// TestParseNextnet validates nextnet .nxt JSONL parsing.
func TestParseNextnet(t *testing.T) {
	content := `{"host":"192.168.1.1","port":"137","proto":"udp","probe":"netbios","name":"ROUTER","nets":["192.168.1.1","10.10.10.1"],"info":{"hwaddr":"aa:bb:cc:dd:ee:01","domain":"LAB"}}
{"host":"192.168.1.2","port":"137","proto":"udp","probe":"netbios","name":"PC","nets":["192.168.1.2"],"info":{"ssh_hostkey_fp":"aa:bb:cc:dd:ee:ff","smb_guid":"12345678-ABCD-EF01-2345-6789ABCDEF01"}}
`

	path := filepath.Join(t.TempDir(), "scan.nxt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseNextnet(path)
	if err != nil {
		t.Fatalf("ParseNextnet: %v", err)
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(result.Hosts))
	}

	// First host: multi-homed (nets contains secondary address)
	h0 := result.Hosts[0]
	if h0.Addresses[0] != "192.168.1.1" {
		t.Errorf("h0 address: %v", h0.Addresses)
	}
	if len(h0.Addresses) < 2 || h0.Addresses[1] != "10.10.10.1" {
		t.Errorf("h0 secondary address missing: %v", h0.Addresses)
	}

	// Second host: has fingerprints
	h1 := result.Hosts[1]
	if _, ok := h1.UniqueKeys["ssh_hostkey_fp"]; !ok {
		t.Error("expected ssh_hostkey_fp unique key")
	}
	if _, ok := h1.UniqueKeys["smb_guid"]; !ok {
		t.Error("expected smb_guid unique key")
	}
}

// TestBuildOpenGraph validates that BuildOpenGraph produces nodes and edges.
func TestBuildOpenGraph(t *testing.T) {
	hosts := []*input.ParsedHost{
		{
			Source:    input.FileTypeNextnet,
			Addresses: []string{"192.168.1.1"},
			Names:     []string{"ROUTER"},
			UniqueKeys: map[string]string{
				"ssh_hostkey_fp": "aa:bb:cc:dd:ee:ff",
			},
			Attributes: make(map[string]string),
		},
		{
			Source:    input.FileTypeNmapXML,
			Addresses: []string{"192.168.1.2"},
			UniqueKeys: map[string]string{
				"ssh_hostkey_fp": "aa:bb:cc:dd:ee:ff", // same key → shared fingerprint node
			},
			Attributes: make(map[string]string),
		},
	}

	nodes, edges := input.BuildOpenGraph(hosts)

	if len(nodes) == 0 {
		t.Fatal("expected nodes, got none")
	}
	if len(edges) == 0 {
		t.Fatal("expected edges, got none")
	}

	// Count fingerprint nodes
	fpCount := 0
	for _, n := range nodes {
		for _, k := range n.Kinds {
			if k == "RZSSHHostKey" {
				fpCount++
			}
		}
	}
	// Two hosts share the same SSH key → only one fingerprint node
	if fpCount != 1 {
		t.Errorf("expected 1 RZSSHHostKey fingerprint node, got %d", fpCount)
	}
}
