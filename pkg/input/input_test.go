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

// TestParseNessus validates Nessus .nessus XML parsing.
func TestParseNessus(t *testing.T) {
	content := `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test Scan">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="host-ip">10.0.0.1</tag>
        <tag name="host-fqdn">myhost.example.com</tag>
        <tag name="operating-system">Linux Kernel 5.15</tag>
        <tag name="mac-address">aa:bb:cc:dd:ee:ff</tag>
      </HostProperties>
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0"
                  pluginID="53491" pluginName="SSH Host Key Fingerprint">
        <plugin_output>RSA key fingerprint : ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90</plugin_output>
      </ReportItem>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="0"
                  pluginID="10863" pluginName="SSL Certificate Information">
        <plugin_output>Subject: CN=myhost
SHA-1 Fingerprint: AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD</plugin_output>
      </ReportItem>
      <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="0"
                  pluginID="10785" pluginName="SMB Info">
        <plugin_output>Server GUID : 12345678-ABCD-EF01-2345-6789ABCDEF01</plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

	path := filepath.Join(t.TempDir(), "scan.nessus")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseNessus(path)
	if err != nil {
		t.Fatalf("ParseNessus: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(result.Hosts))
	}
	h := result.Hosts[0]

	if len(h.Addresses) == 0 || h.Addresses[0] != "10.0.0.1" {
		t.Errorf("unexpected address: %v", h.Addresses)
	}
	if len(h.Names) == 0 || h.Names[0] != "myhost.example.com" {
		t.Errorf("unexpected names: %v", h.Names)
	}
	if h.OS != "Linux Kernel 5.15" {
		t.Errorf("unexpected OS: %q", h.OS)
	}
	if _, ok := h.UniqueKeys["ssh_hostkey_fp"]; !ok {
		t.Error("expected ssh_hostkey_fp")
	}
	if _, ok := h.UniqueKeys["tls_cert_fp"]; !ok {
		t.Error("expected tls_cert_fp")
	}
	if _, ok := h.UniqueKeys["smb_guid"]; !ok {
		t.Error("expected smb_guid")
	}
}

// TestParseOpenVAS validates OpenVAS/GVM XML report parsing.
func TestParseOpenVAS(t *testing.T) {
	content := `<?xml version="1.0"?>
<report id="test-id" type="scan" xmlns:gvm="http://www.openvas.org/omp/gvm-2">
  <results max="10" start="1">
    <result id="r1">
      <name>SSH Host Key Fingerprint</name>
      <host><ip>10.0.0.2</ip><hostname>server.example.com</hostname></host>
      <port>22/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103997">
        <name>SSH Host Key Fingerprint</name>
        <family>General</family>
        <cvss_base>0.0</cvss_base>
        <tags>summary=key fp retrieved</tags>
      </nvt>
      <description>RSA key fingerprint: ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90</description>
      <severity>0.0</severity>
    </result>
    <result id="r2">
      <name>SNMP Detection</name>
      <host><ip>10.0.0.2</ip><hostname></hostname></host>
      <port>161/udp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.10264">
        <name>SNMP Detection</name>
        <family>Service detection</family>
        <cvss_base>5.0</cvss_base>
        <tags>summary=SNMP open</tags>
      </nvt>
      <description>Engine ID: 800000090300AABBCCDDEEFF</description>
      <severity>5.0</severity>
    </result>
  </results>
  <host>
    <ip>10.0.0.2</ip>
    <detail><name>OS</name><value>Ubuntu 22.04</value><source><type>nvt</type><name>oid</name></source></detail>
  </host>
</report>`

	path := filepath.Join(t.TempDir(), "openvas.xml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseOpenVAS(path)
	if err != nil {
		t.Fatalf("ParseOpenVAS: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(result.Hosts))
	}
	h := result.Hosts[0]

	if len(h.Addresses) == 0 || h.Addresses[0] != "10.0.0.2" {
		t.Errorf("unexpected address: %v", h.Addresses)
	}
	if _, ok := h.UniqueKeys["ssh_hostkey_fp"]; !ok {
		t.Error("expected ssh_hostkey_fp")
	}
	if _, ok := h.UniqueKeys["snmpv3_engine_id"]; !ok {
		t.Error("expected snmpv3_engine_id")
	}
}

// TestParseNetBox validates NetBox JSON API export parsing.
func TestParseNetBox(t *testing.T) {
	content := `{
  "count": 2,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 1,
      "name": "router01",
      "device_type": {"id": 1, "name": "CSR1000v", "slug": "csr1000v"},
      "device_role": {"id": 1, "name": "Router", "slug": "router"},
      "platform": {"id": 1, "name": "Cisco IOS-XE", "slug": "cisco-ios-xe"},
      "site": {"id": 1, "name": "Main Office", "slug": "main-office"},
      "rack": {"id": 1, "name": "Rack A01", "slug": "rack-a01"},
      "status": {"value": "active", "label": "Active"},
      "primary_ip4": {"id": 1, "address": "192.168.1.1/24", "family": {"value": 4, "label": "IPv4"}},
      "primary_ip6": null,
      "comments": "",
      "custom_fields": {}
    },
    {
      "id": 2,
      "name": "server01",
      "device_type": {"id": 2, "name": "PowerEdge R740", "slug": "r740"},
      "device_role": {"id": 2, "name": "Server", "slug": "server"},
      "platform": {"id": 2, "name": "Ubuntu 22.04", "slug": "ubuntu-2204"},
      "site": {"id": 1, "name": "Main Office", "slug": "main-office"},
      "rack": {"id": 1, "name": "Rack A01", "slug": "rack-a01"},
      "status": {"value": "active", "label": "Active"},
      "primary_ip4": {"id": 2, "address": "192.168.1.2/24", "family": {"value": 4, "label": "IPv4"}},
      "primary_ip6": null,
      "comments": "Web server",
      "custom_fields": {"criticality": "high"}
    }
  ]
}`

	path := filepath.Join(t.TempDir(), "netbox.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseNetBox(path)
	if err != nil {
		t.Fatalf("ParseNetBox: %v", err)
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(result.Hosts))
	}

	// Check first device
	var router, server *input.ParsedHost
	for _, h := range result.Hosts {
		if len(h.Names) > 0 && h.Names[0] == "router01" {
			router = h
		} else if len(h.Names) > 0 && h.Names[0] == "server01" {
			server = h
		}
	}

	if router == nil {
		t.Fatal("router01 not found")
	}
	if len(router.Addresses) == 0 || router.Addresses[0] != "192.168.1.1" {
		t.Errorf("router01 address: %v", router.Addresses)
	}
	if router.Attributes["device_role"] != "Router" {
		t.Errorf("router01 role: %q", router.Attributes["device_role"])
	}
	if router.OS != "Cisco IOS-XE" {
		t.Errorf("router01 OS: %q", router.OS)
	}

	if server == nil {
		t.Fatal("server01 not found")
	}
	if server.Attributes["cf_criticality"] != "high" {
		t.Errorf("server01 custom field: %q", server.Attributes["cf_criticality"])
	}
}

