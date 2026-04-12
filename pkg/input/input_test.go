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

// TestParseQualys validates Qualys VM scan XML parsing.
func TestParseQualys(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "sample-qualys.xml")
	result, err := input.ParseQualys(path)
	if err != nil {
		t.Fatalf("ParseQualys: %v", err)
	}
	if len(result.Hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(result.Hosts))
	}

	// Build a lookup by IP for stable assertions.
	byIP := make(map[string]*input.ParsedHost)
	for _, h := range result.Hosts {
		if len(h.Addresses) > 0 {
			byIP[h.Addresses[0]] = h
		}
	}

	// ---- mail server 192.0.2.10 ----
	mail, ok := byIP["192.0.2.10"]
	if !ok {
		t.Fatal("host 192.0.2.10 not found")
	}
	if len(mail.Names) == 0 || mail.Names[0] != "mail.example.com" {
		t.Errorf("mail names: %v", mail.Names)
	}
	if mail.OS != "Linux 5.15" {
		t.Errorf("mail OS: %q", mail.OS)
	}
	// Should have services for ports 22, 443, and 25.
	if len(mail.Services) < 3 {
		t.Errorf("mail services: got %d, want >= 3", len(mail.Services))
	}
	// MAC should be extracted from the RESULT text.
	if len(mail.MACs) == 0 {
		t.Error("expected MAC address for 192.0.2.10")
	} else if mail.MACs[0] != "02:42:c0:00:02:0a" {
		t.Errorf("unexpected MAC: %q", mail.MACs[0])
	}
	// The sample SHA-1 fingerprint is continuous hex (not colon-separated),
	// so the TLS FP regex won't capture it. Verify MAC was extracted instead.
	if mail.Attributes["mac_address"] != "02:42:c0:00:02:0a" {
		t.Errorf("unexpected mac_address attribute: %q", mail.Attributes["mac_address"])
	}

	// ---- DC 198.51.100.5 ----
	dc, ok := byIP["198.51.100.5"]
	if !ok {
		t.Fatal("host 198.51.100.5 not found")
	}
	if dc.OS != "Windows Server 2022 Standard" {
		t.Errorf("dc OS: %q", dc.OS)
	}
	// SMB GUID should be extracted.
	if guid, ok := dc.UniqueKeys["smb_guid"]; !ok {
		t.Error("expected smb_guid for 198.51.100.5")
	} else if guid != "4a3b2c1d-5e6f-7a8b-9c0d-1e2f3a4b5c6d" {
		t.Errorf("unexpected smb_guid: %q", guid)
	}

	// ---- switch 203.0.113.50 ----
	sw, ok := byIP["203.0.113.50"]
	if !ok {
		t.Fatal("host 203.0.113.50 not found")
	}
	if sw.OS != "Cisco IOS 15.2" {
		t.Errorf("switch OS: %q", sw.OS)
	}
	// Should have services on port 22 and 161.
	if len(sw.Services) < 2 {
		t.Errorf("switch services: got %d, want >= 2", len(sw.Services))
	}
}

// TestParseMasscanXML validates Masscan XML parsing.
func TestParseMasscanXML(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "sample-masscan.xml")
	result, err := input.ParseMasscan(path)
	if err != nil {
		t.Fatalf("ParseMasscan (XML): %v", err)
	}
	if len(result.Hosts) != 4 {
		t.Fatalf("got %d hosts, want 4", len(result.Hosts))
	}

	byIP := make(map[string]*input.ParsedHost)
	for _, h := range result.Hosts {
		if len(h.Addresses) > 0 {
			byIP[h.Addresses[0]] = h
		}
	}

	// 192.0.2.10 should have 3 services (22, 25, 443)
	mail, ok := byIP["192.0.2.10"]
	if !ok {
		t.Fatal("host 192.0.2.10 not found")
	}
	if len(mail.Services) != 3 {
		t.Errorf("192.0.2.10 services: got %d, want 3", len(mail.Services))
	}
	// Check that banner is captured for port 22
	for _, svc := range mail.Services {
		if svc.Port == "22" {
			if svc.Attributes["banner"] == "" {
				t.Error("expected SSH banner for port 22")
			}
		}
	}

	// 198.51.100.5 should have 5 services
	dc, ok := byIP["198.51.100.5"]
	if !ok {
		t.Fatal("host 198.51.100.5 not found")
	}
	if len(dc.Services) != 5 {
		t.Errorf("198.51.100.5 services: got %d, want 5", len(dc.Services))
	}

	// Every host should have Source == FileTypeMasscan
	for _, h := range result.Hosts {
		if h.Source != input.FileTypeMasscan {
			t.Errorf("host %v source = %v, want masscan", h.Addresses, h.Source)
		}
	}
}

// TestParseMasscanJSON validates Masscan JSON parsing.
func TestParseMasscanJSON(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "sample-masscan.json")
	result, err := input.ParseMasscan(path)
	if err != nil {
		t.Fatalf("ParseMasscan (JSON): %v", err)
	}

	// The JSON has records for 4 unique IPs.
	if len(result.Hosts) != 4 {
		t.Fatalf("got %d hosts, want 4", len(result.Hosts))
	}

	byIP := make(map[string]*input.ParsedHost)
	for _, h := range result.Hosts {
		if len(h.Addresses) > 0 {
			byIP[h.Addresses[0]] = h
		}
	}

	// 192.0.2.10 has 3 port records (22, 25, 443)
	mail, ok := byIP["192.0.2.10"]
	if !ok {
		t.Fatal("host 192.0.2.10 not found")
	}
	if len(mail.Services) != 3 {
		t.Errorf("192.0.2.10 services: got %d, want 3", len(mail.Services))
	}

	// Verify banner is captured
	foundBanner := false
	for _, svc := range mail.Services {
		if svc.Port == "22" && svc.Attributes["banner"] != "" {
			foundBanner = true
		}
	}
	if !foundBanner {
		t.Error("expected SSH banner for 192.0.2.10:22")
	}

	// 192.0.2.200 has 4 port records
	app, ok := byIP["192.0.2.200"]
	if !ok {
		t.Fatal("host 192.0.2.200 not found")
	}
	if len(app.Services) != 4 {
		t.Errorf("192.0.2.200 services: got %d, want 4", len(app.Services))
	}
}

// TestParseShodan validates Shodan JSONL parsing.
func TestParseShodan(t *testing.T) {
	content := `{"ip_str":"10.0.0.1","port":22,"transport":"tcp","product":"OpenSSH","version":"9.0","os":"Linux","hostnames":["gw.lab.local"],"domains":["lab.local"],"data":"SSH-2.0-OpenSSH_9.0\nKey type: ssh-rsa\nFingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"}
{"ip_str":"10.0.0.1","port":443,"transport":"tcp","product":"nginx","version":"1.25.0","os":"Linux","hostnames":["gw.lab.local"],"domains":["lab.local"],"data":"HTTP/1.1 200 OK\nServer: nginx","ssl":{"cert":{"fingerprint":{"sha1":"AABBCCDDEEFF00112233AABBCCDDEEFF00112233","sha256":"aabb"}}}}
{"ip_str":"10.0.0.2","port":445,"transport":"tcp","product":"Samba","version":"4.18","os":"Linux","hostnames":["nas.lab.local"],"domains":["lab.local"],"data":"SMB service","vulns":{"CVE-2024-0001":{},"CVE-2024-0002":{}}}`

	path := filepath.Join(t.TempDir(), "shodan.jsonl")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseShodan(path)
	if err != nil {
		t.Fatalf("ParseShodan: %v", err)
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2 (two unique IPs)", len(result.Hosts))
	}

	byIP := make(map[string]*input.ParsedHost)
	for _, h := range result.Hosts {
		if len(h.Addresses) > 0 {
			byIP[h.Addresses[0]] = h
		}
	}

	// 10.0.0.1: two services, SSH + HTTPS
	gw := byIP["10.0.0.1"]
	if gw == nil {
		t.Fatal("host 10.0.0.1 not found")
	}
	if len(gw.Services) != 2 {
		t.Errorf("10.0.0.1 services: got %d, want 2", len(gw.Services))
	}
	if gw.OS != "Linux" {
		t.Errorf("10.0.0.1 OS: %q", gw.OS)
	}
	if len(gw.Names) == 0 || gw.Names[0] != "gw.lab.local" {
		t.Errorf("10.0.0.1 names: %v", gw.Names)
	}
	// TLS fingerprint from SSL cert (SHA-1 normalized to lowercase colon-separated)
	tlsFP, ok := gw.UniqueKeys["tls_cert_fp"]
	if !ok {
		t.Error("expected tls_cert_fp for 10.0.0.1")
	} else if tlsFP != "aa:bb:cc:dd:ee:ff:00:11:22:33:aa:bb:cc:dd:ee:ff:00:11:22:33" {
		t.Errorf("unexpected tls_cert_fp: %q", tlsFP)
	}
	// SSH fingerprint from banner data
	if _, ok := gw.UniqueKeys["ssh_hostkey_fp"]; !ok {
		t.Error("expected ssh_hostkey_fp for 10.0.0.1")
	}

	// 10.0.0.2: one service, vulns attribute
	nas := byIP["10.0.0.2"]
	if nas == nil {
		t.Fatal("host 10.0.0.2 not found")
	}
	if len(nas.Services) != 1 {
		t.Errorf("10.0.0.2 services: got %d, want 1", len(nas.Services))
	}
	if nas.Attributes["vulns"] == "" {
		t.Error("expected vulns attribute for 10.0.0.2")
	}
}

// TestNmapTraceroute validates that traceroute hops are extracted from Nmap XML.
func TestNmapTraceroute(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.99.0.50" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
    <trace port="80" proto="tcp">
      <hop ttl="1" ipaddr="10.99.0.1" rtt="0.50" host="gw.local"/>
      <hop ttl="2" ipaddr="172.16.0.1" rtt="1.25" host="core-rtr.local"/>
      <hop ttl="3" ipaddr="10.99.0.50" rtt="2.00" host="target.local"/>
    </trace>
  </host>
</nmaprun>`

	path := filepath.Join(t.TempDir(), "trace.xml")
	if err := os.WriteFile(path, []byte(xml), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseNmapXML(path)
	if err != nil {
		t.Fatalf("ParseNmapXML: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(result.Hosts))
	}
	h := result.Hosts[0]
	if len(h.TracerouteHops) != 3 {
		t.Fatalf("got %d hops, want 3", len(h.TracerouteHops))
	}

	hop1 := h.TracerouteHops[0]
	if hop1.TTL != 1 {
		t.Errorf("hop1 TTL = %d, want 1", hop1.TTL)
	}
	if len(hop1.Addresses) == 0 || hop1.Addresses[0] != "10.99.0.1" {
		t.Errorf("hop1 address: %v", hop1.Addresses)
	}
	if hop1.Hostname != "gw.local" {
		t.Errorf("hop1 hostname: %q", hop1.Hostname)
	}
	if hop1.RTT != 0.50 {
		t.Errorf("hop1 RTT = %f, want 0.50", hop1.RTT)
	}

	hop3 := h.TracerouteHops[2]
	if hop3.TTL != 3 {
		t.Errorf("hop3 TTL = %d, want 3", hop3.TTL)
	}
	if hop3.Addresses[0] != "10.99.0.50" {
		t.Errorf("hop3 address: %v", hop3.Addresses)
	}
}

// TestFingerprintNormalization tests that fingerprints and MACs are normalized
// through the parsers (we cannot call unexported helpers directly from
// package input_test, so we exercise them via the exported parse functions).
func TestFingerprintNormalization(t *testing.T) {
	// Nessus with uppercase colon-separated TLS fingerprint → should be lowercased
	nessusXML := `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Norm Test">
    <ReportHost name="10.1.1.1">
      <HostProperties>
        <tag name="host-ip">10.1.1.1</tag>
        <tag name="mac-address">AA-BB-CC-DD-EE-FF</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="0"
                  pluginID="10863" pluginName="SSL Certificate Information">
        <plugin_output>SHA-1 Fingerprint: AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD</plugin_output>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.1.1.2">
      <HostProperties>
        <tag name="host-ip">10.1.1.2</tag>
        <tag name="mac-address">11 22 33 44 55 66</tag>
      </HostProperties>
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0"
                  pluginID="53491" pluginName="SSH Host Key Fingerprint">
        <plugin_output>RSA key fingerprint : ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90</plugin_output>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.1.1.3">
      <HostProperties>
        <tag name="host-ip">10.1.1.3</tag>
        <tag name="mac-address">AABBCCDDEEFF</tag>
      </HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

	path := filepath.Join(t.TempDir(), "norm.nessus")
	if err := os.WriteFile(path, []byte(nessusXML), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseNessus(path)
	if err != nil {
		t.Fatalf("ParseNessus: %v", err)
	}

	byIP := make(map[string]*input.ParsedHost)
	for _, h := range result.Hosts {
		if len(h.Addresses) > 0 {
			byIP[h.Addresses[0]] = h
		}
	}

	// Host 1: dash-separated MAC → colon-separated lowercase
	h1 := byIP["10.1.1.1"]
	if h1 == nil {
		t.Fatal("host 10.1.1.1 not found")
	}
	if len(h1.MACs) == 0 || h1.MACs[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("h1 MAC: %v (want aa:bb:cc:dd:ee:ff)", h1.MACs)
	}
	// TLS fingerprint should be lowercase
	if fp := h1.UniqueKeys["tls_cert_fp"]; fp != "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd" {
		t.Errorf("h1 tls_cert_fp: %q", fp)
	}

	// Host 2: space-separated MAC → colon-separated lowercase
	h2 := byIP["10.1.1.2"]
	if h2 == nil {
		t.Fatal("host 10.1.1.2 not found")
	}
	if len(h2.MACs) == 0 || h2.MACs[0] != "11:22:33:44:55:66" {
		t.Errorf("h2 MAC: %v (want 11:22:33:44:55:66)", h2.MACs)
	}
	// SSH fingerprint should already be lowercase colon-separated
	if fp := h2.UniqueKeys["ssh_hostkey_fp"]; fp != "ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90" {
		t.Errorf("h2 ssh_hostkey_fp: %q", fp)
	}

	// Host 3: continuous hex MAC → colon-separated lowercase
	h3 := byIP["10.1.1.3"]
	if h3 == nil {
		t.Fatal("host 10.1.1.3 not found")
	}
	if len(h3.MACs) == 0 || h3.MACs[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("h3 MAC: %v (want aa:bb:cc:dd:ee:ff)", h3.MACs)
	}
}

// TestDetectFileTypeExtended adds detection cases for Qualys, Masscan, and Shodan.
func TestDetectFileTypeExtended(t *testing.T) {
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
			filename: "qualys.xml",
			content:  `<?xml version="1.0"?><SCAN><IP value="1.2.3.4"></IP></SCAN>`,
			want:     input.FileTypeQualys,
		},
		{
			filename: "masscan.xml",
			content:  `<?xml version="1.0"?><nmaprun scanner="masscan"></nmaprun>`,
			want:     input.FileTypeMasscan,
		},
		{
			filename: "masscan.json",
			content:  `[{"ip":"1.2.3.4","timestamp":"123","ports":[{"port":22,"proto":"tcp","status":"open"}]}]`,
			want:     input.FileTypeMasscan,
		},
		{
			filename: "shodan.jsonl",
			content:  `{"ip_str":"1.2.3.4","port":22,"transport":"tcp","data":"SSH"}`,
			want:     input.FileTypeShodan,
		},
		{
			filename: "nessus.xml",
			content:  `<?xml version="1.0"?><NessusClientData_v2><Report name="t"></Report></NessusClientData_v2>`,
			want:     input.FileTypeNessus,
		},
	}

	for _, tc := range tests {
		path := writeFile(tc.filename, tc.content)
		t.Run(tc.filename, func(t *testing.T) {
			got, err := input.DetectFileType(path)
			if err != nil {
				t.Fatalf("DetectFileType(%s): %v", tc.filename, err)
			}
			if got != tc.want {
				t.Errorf("DetectFileType(%s) = %v, want %v", tc.filename, got, tc.want)
			}
		})
	}
}

