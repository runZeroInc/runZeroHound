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
			filename: "device.walk",
			content:  "iso.3.6.1.2.1.1.1.0 = STRING: some device\niso.3.6.1.2.1.1.5.0 = STRING: hostname\n",
			want:     input.FileTypeSNMPWalk,
		},
		{
			filename: "numeric_oids.txt",
			content:  "iso.3.6.1.2.1.1.1.0 = STRING: \"APC UPS\"\niso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.318\n",
			want:     input.FileTypeSNMPWalk,
		},
		{
			filename: "snmp_scan.161",
			content:  "Scanning 256 hosts, 2 communities\n192.168.0.19 [public] APC Web/SNMP Management Card\n",
			want:     input.FileTypeOneSixtyOne,
		},
		{
			filename: "snmp_scan_content.txt",
			content:  "192.168.0.19 [public] APC Web/SNMP Management Card\n192.168.0.81 [public] Cisco NX-OS\n",
			want:     input.FileTypeOneSixtyOne,
		},
		{
			filename: "nexpose_simple.xml",
			content:  `<NeXposeSimpleXML version="1.0"><generated>20240111</generated><devices></devices></NeXposeSimpleXML>`,
			want:     input.FileTypeNexpose,
		},
		{
			filename: "nexpose_report.xml",
			content:  `<NexposeReport version="2.0"><scans></scans><nodes></nodes></NexposeReport>`,
			want:     input.FileTypeNexpose,
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

// TestParseSNMPWalkISOFormat validates snmpwalk parsing with numeric "iso." prefix OIDs.
func TestParseSNMPWalkISOFormat(t *testing.T) {
	content := `iso.3.6.1.2.1.1.1.0 = STRING: "Cisco NX-OS(tm) nxos.9.3.7.bin"
iso.3.6.1.2.1.1.5.0 = STRING: "LAB-N9K"
iso.3.6.1.2.1.2.2.1.6.1 = Hex-STRING: 2C 4F 52 BC 07 F6
iso.3.6.1.2.1.4.20.1.1.192.168.0.81 = IpAddress: 192.168.0.81
iso.3.6.1.2.1.4.20.1.1.10.114.122.31 = IpAddress: 10.114.122.31
iso.3.6.1.2.1.4.22.1.2.1.192.168.0.1 = Hex-STRING: F4 90 EA 00 82 3F
`

	path := filepath.Join(t.TempDir(), "rzlab-192.168.0.81.walk")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseSNMPWalk(path)
	if err != nil {
		t.Fatalf("ParseSNMPWalk (iso): %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(result.Hosts))
	}
	h := result.Hosts[0]

	// IP should be extracted from both the filename hint and the ipAdEntAddr OIDs
	if len(h.Addresses) < 2 {
		t.Errorf("expected >= 2 addresses, got %v", h.Addresses)
	}
	foundIP := false
	for _, a := range h.Addresses {
		if a == "192.168.0.81" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("expected address 192.168.0.81, got %v", h.Addresses)
	}

	// sysName should be extracted (with quotes stripped)
	if len(h.Names) == 0 || h.Names[0] != "LAB-N9K" {
		t.Errorf("unexpected names: %v", h.Names)
	}

	// sysDescr → OS
	if h.OS == "" {
		t.Error("expected OS to be set from sysDescr")
	}

	// MAC from ifPhysAddress
	if len(h.MACs) == 0 {
		t.Error("expected MAC address from ifPhysAddress")
	} else if h.MACs[0] != "2c:4f:52:bc:07:f6" {
		t.Errorf("unexpected MAC: %q", h.MACs[0])
	}

	// ARP entry should create a SubAsset
	if len(h.SubAssets) == 0 {
		t.Error("expected SubAsset from ipNetToMediaPhysAddress")
	}
}

// TestBuildOpenGraph validates that BuildOpenGraph produces nodes and edges.
func TestBuildOpenGraph(t *testing.T) {
	hosts := []*input.ParsedHost{
		{
			Source:    input.FileTypeNmapXML,
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

// TestParseNessusTraceroute validates Nessus bare-IP traceroute parsing.
func TestParseNessusTraceroute(t *testing.T) {
	content := `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Policy><policyName>Test</policyName></Policy>
  <Report name="Test Scan">
    <ReportHost name="10.0.1.50">
      <HostProperties>
        <tag name="host-ip">10.0.1.50</tag>
      </HostProperties>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0"
                  pluginID="10287" pluginName="Traceroute Information">
        <plugin_output>For your information, here is the traceroute from 192.168.0.3 to 10.0.1.50 :
192.168.0.3
192.168.0.1
10.0.1.50

Hop Count: 2
</plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

	path := filepath.Join(t.TempDir(), "trace.nessus")
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

	if len(h.TracerouteHops) != 1 {
		t.Fatalf("got %d traceroute hops, want 1 (intermediate only)", len(h.TracerouteHops))
	}
	hop := h.TracerouteHops[0]
	if hop.Addresses[0] != "192.168.0.1" {
		t.Errorf("expected intermediate hop 192.168.0.1, got %s", hop.Addresses[0])
	}
	if hop.TTL != 1 {
		t.Errorf("expected TTL 1, got %d", hop.TTL)
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
	path := filepath.Join("..", "..", "examples", "rzlab-qualys.xml")
	result, err := input.ParseQualys(path)
	if err != nil {
		t.Fatalf("ParseQualys: %v", err)
	}
	if len(result.Hosts) != 4 {
		t.Fatalf("got %d hosts, want 4", len(result.Hosts))
	}

	// Build a lookup by IP for stable assertions.
	byIP := make(map[string]*input.ParsedHost)
	for _, h := range result.Hosts {
		if len(h.Addresses) > 0 {
			byIP[h.Addresses[0]] = h
		}
	}

	// ---- win2022-infra01 10.114.128.23 ----
	infra, ok := byIP["10.114.128.23"]
	if !ok {
		t.Fatal("host 10.114.128.23 not found")
	}
	if len(infra.Names) == 0 || infra.Names[0] != "win2022-infra01.corp.neonray.biz" {
		t.Errorf("infra names: %v", infra.Names)
	}
	if infra.OS != "Windows 2016/2019/10" {
		t.Errorf("infra OS: %q", infra.OS)
	}
	if len(infra.Services) < 5 {
		t.Errorf("infra services: got %d, want >= 5", len(infra.Services))
	}

	// ---- win2022-adc01 10.114.128.21 ----
	adc, ok := byIP["10.114.128.21"]
	if !ok {
		t.Fatal("host 10.114.128.21 not found")
	}
	if adc.OS != "Windows 2016/2019/10" {
		t.Errorf("adc OS: %q", adc.OS)
	}
	if len(adc.Services) < 5 {
		t.Errorf("adc services: got %d, want >= 5", len(adc.Services))
	}

	// ---- unnamed host 10.114.128.32 ----
	unnamed, ok := byIP["10.114.128.32"]
	if !ok {
		t.Fatal("host 10.114.128.32 not found")
	}
	if unnamed.OS != "" {
		t.Errorf("unnamed OS: %q, want empty", unnamed.OS)
	}
}

// TestParseQualysCSV validates Qualys VM scan CSV parsing.
func TestParseQualysCSV(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "rzlab-qualys.csv")
	result, err := input.ParseQualysCSV(path)
	if err != nil {
		t.Fatalf("ParseQualysCSV: %v", err)
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

	// win2022-infra01
	infra, ok := byIP["10.114.128.23"]
	if !ok {
		t.Fatal("host 10.114.128.23 not found")
	}
	if infra.OS != "Windows 2016/2019/10" {
		t.Errorf("infra OS: %q", infra.OS)
	}
	foundDNS := false
	foundNB := false
	for _, n := range infra.Names {
		if n == "win2022-infra01.corp.neonray.biz" {
			foundDNS = true
		}
		if n == "WIN2022-INFRA01" {
			foundNB = true
		}
	}
	if !foundDNS {
		t.Errorf("missing DNS name, got %v", infra.Names)
	}
	if !foundNB {
		t.Errorf("missing NetBIOS name, got %v", infra.Names)
	}
	if len(infra.Services) < 5 {
		t.Errorf("infra services: got %d, want >= 5", len(infra.Services))
	}
	if infra.Attributes["vuln_count"] == "" || infra.Attributes["vuln_count"] == "0" {
		t.Error("expected vuln_count > 0")
	}

	// unnamed host 10.114.128.32 — no OS
	unnamed, ok := byIP["10.114.128.32"]
	if !ok {
		t.Fatal("host 10.114.128.32 not found")
	}
	if unnamed.OS != "" {
		t.Errorf("unnamed OS: %q, want empty", unnamed.OS)
	}
}

// TestParseMasscanXML validates Masscan XML parsing.
func TestParseMasscanXML(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "rzlab-masscan.xml")
	result, err := input.ParseMasscan(path)
	if err != nil {
		t.Fatalf("ParseMasscan (XML): %v", err)
	}
	if len(result.Hosts) < 100 {
		t.Fatalf("got %d hosts, want >= 100", len(result.Hosts))
	}

	byIP := make(map[string]*input.ParsedHost)
	for _, h := range result.Hosts {
		if len(h.Addresses) > 0 {
			byIP[h.Addresses[0]] = h
		}
	}

	// 192.168.0.4 should have multiple services
	host, ok := byIP["192.168.0.4"]
	if !ok {
		t.Fatal("host 192.168.0.4 not found")
	}
	if len(host.Services) < 2 {
		t.Errorf("192.168.0.4 services: got %d, want >= 2", len(host.Services))
	}

	// Every host should have Source == FileTypeMasscan
	for _, h := range result.Hosts {
		if h.Source != input.FileTypeMasscan {
			t.Errorf("host %v source = %v, want masscan", h.Addresses, h.Source)
		}
	}
}

// TestParseMasscanJSON validates Masscan JSON parsing using inline data.
func TestParseMasscanJSON(t *testing.T) {
	content := `{ "ip": "10.0.0.1", "timestamp": "1700000000", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64, "service": {"name": "ssh", "banner": "SSH-2.0-OpenSSH_9.0"}} ] }
{ "ip": "10.0.0.1", "timestamp": "1700000001", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
{ "ip": "10.0.0.2", "timestamp": "1700000002", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128} ] }
{ "ip": "10.0.0.3", "timestamp": "1700000003", "ports": [ {"port": 445, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 128, "service": {"name": "smb", "banner": "SMBv2  guid=61746164-6573-7374-0000-000000000000 time=2026-01-01  domain=TESTDOMAIN version=6.1.0"}} ] }
{   "finished": 1 }
`
	path := filepath.Join(t.TempDir(), "masscan.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseMasscan(path)
	if err != nil {
		t.Fatalf("ParseMasscan (JSON): %v", err)
	}

	if len(result.Hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(result.Hosts))
	}

	byIP := make(map[string]*input.ParsedHost)
	for _, h := range result.Hosts {
		if len(h.Addresses) > 0 {
			byIP[h.Addresses[0]] = h
		}
	}

	// 10.0.0.1 has 2 port records (22, 443)
	host1, ok := byIP["10.0.0.1"]
	if !ok {
		t.Fatal("host 10.0.0.1 not found")
	}
	if len(host1.Services) != 2 {
		t.Errorf("10.0.0.1 services: got %d, want 2", len(host1.Services))
	}

	// Verify banner is captured and SSH version extracted
	foundBanner := false
	for _, svc := range host1.Services {
		if svc.Port == "22" && svc.Attributes["banner"] != "" {
			foundBanner = true
			if svc.Version != "OpenSSH_9.0" {
				t.Errorf("expected SSH version OpenSSH_9.0, got %q", svc.Version)
			}
			if svc.Attributes["reason"] != "syn-ack" {
				t.Errorf("expected reason syn-ack, got %q", svc.Attributes["reason"])
			}
			if svc.Attributes["ttl"] != "64" {
				t.Errorf("expected ttl 64, got %q", svc.Attributes["ttl"])
			}
		}
	}
	if !foundBanner {
		t.Error("expected SSH banner for 10.0.0.1:22")
	}

	// Verify timestamp stored on host
	if host1.Attributes["timestamp"] == "" {
		t.Error("expected timestamp on host 10.0.0.1")
	}

	// 10.0.0.2 has 1 port record
	host2, ok := byIP["10.0.0.2"]
	if !ok {
		t.Fatal("host 10.0.0.2 not found")
	}
	if len(host2.Services) != 1 {
		t.Errorf("10.0.0.2 services: got %d, want 1", len(host2.Services))
	}

	// 10.0.0.3: SMB banner enrichment
	host3, ok := byIP["10.0.0.3"]
	if !ok {
		t.Fatal("host 10.0.0.3 not found")
	}
	if len(host3.Services) != 1 {
		t.Fatalf("10.0.0.3 services: got %d, want 1", len(host3.Services))
	}
	smbSvc := host3.Services[0]
	if smbSvc.Product != "smb" {
		t.Errorf("expected SMB product, got %q", smbSvc.Product)
	}
	if smbSvc.Version != "6.1.0" {
		t.Errorf("expected SMB version 6.1.0, got %q", smbSvc.Version)
	}
	if smbSvc.Attributes["smb_guid"] != "61746164-6573-7374-0000-000000000000" {
		t.Errorf("expected smb_guid, got %q", smbSvc.Attributes["smb_guid"])
	}
	if smbSvc.Attributes["smb_domain"] != "TESTDOMAIN" {
		t.Errorf("expected smb_domain TESTDOMAIN, got %q", smbSvc.Attributes["smb_domain"])
	}
	if host3.UniqueKeys["smb_guid"] == "" {
		t.Error("expected smb_guid in host UniqueKeys")
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

// TestParseOneSixtyOne validates onesixtyone output parsing.
func TestParseOneSixtyOne(t *testing.T) {
	content := `Scanning 256 hosts, 2 communities
192.168.0.19 [public] APC Web/SNMP Management Card (MB:v4.1.0)
192.168.0.81 [public] Cisco NX-OS(tm) nxos.9.3.7.bin
Error in sendto: Permission denied
192.168.0.19 [private] APC Web/SNMP Management Card (MB:v4.1.0)
`

	path := filepath.Join(t.TempDir(), "scan.161")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseOneSixtyOne(path)
	if err != nil {
		t.Fatalf("ParseOneSixtyOne: %v", err)
	}

	if len(result.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(result.Hosts))
	}

	// First host: 192.168.0.19 with two communities
	h0 := result.Hosts[0]
	if len(h0.Addresses) == 0 || h0.Addresses[0] != "192.168.0.19" {
		t.Errorf("host 0 addresses: %v", h0.Addresses)
	}
	if h0.Attributes["snmp_communities"] != "public,private" {
		t.Errorf("host 0 communities: %q, want 'public,private'", h0.Attributes["snmp_communities"])
	}
	if h0.OS == "" {
		t.Error("host 0 OS should be set from sysDescr")
	}
	if len(h0.Services) != 1 || h0.Services[0].Port != "161" || h0.Services[0].Protocol != "udp" {
		t.Errorf("host 0 services: %+v", h0.Services)
	}

	// Second host: 192.168.0.81 with one community
	h1 := result.Hosts[1]
	if len(h1.Addresses) == 0 || h1.Addresses[0] != "192.168.0.81" {
		t.Errorf("host 1 addresses: %v", h1.Addresses)
	}
	if h1.Attributes["snmp_communities"] != "public" {
		t.Errorf("host 1 communities: %q, want 'public'", h1.Attributes["snmp_communities"])
	}
}

// TestOneSixtyOneGraph validates that SNMP community nodes and edges are generated.
func TestOneSixtyOneGraph(t *testing.T) {
	hosts := []*input.ParsedHost{
		{
			Source:    input.FileTypeOneSixtyOne,
			Addresses: []string{"192.168.0.19"},
			OS:        "APC Web/SNMP Management Card",
			Attributes: map[string]string{
				"snmp_communities": "public,private",
				"snmp.sysDescr":    "APC Web/SNMP Management Card",
			},
			UniqueKeys: make(map[string]string),
			Services: []input.ParsedService{
				{Address: "192.168.0.19", Port: "161", Protocol: "udp", Product: "snmp"},
			},
		},
	}

	nodes, edges := input.BuildOpenGraph(hosts)

	// Check for RZSNMPCommunity nodes
	commNodes := 0
	for _, n := range nodes {
		for _, k := range n.Kinds {
			if k == "RZSNMPCommunity" {
				commNodes++
			}
		}
	}
	if commNodes != 2 {
		t.Errorf("expected 2 RZSNMPCommunity nodes (public, private), got %d", commNodes)
	}

	// Check for RZHasSNMPCommunity and RZSNMPCommunityUsedBy edges
	hasCommunity := 0
	usedBy := 0
	for _, e := range edges {
		if e.Kind == "RZHasSNMPCommunity" {
			hasCommunity++
		}
		if e.Kind == "RZSNMPCommunityUsedBy" {
			usedBy++
		}
	}
	if hasCommunity != 2 {
		t.Errorf("expected 2 RZHasSNMPCommunity edges, got %d", hasCommunity)
	}
	if usedBy != 2 {
		t.Errorf("expected 2 RZSNMPCommunityUsedBy edges, got %d", usedBy)
	}
}

// TestParseNexposeSimple validates Nexpose Simple XML parsing.
func TestParseNexposeSimple(t *testing.T) {
	content := `<NeXposeSimpleXML version="1.0">
<generated>20240111T214351891</generated>
<devices>
<device address="10.0.0.1" id="1">
<fingerprint certainty="0.90">
<description>Ubuntu Linux 22.04</description>
<vendor>Ubuntu</vendor>
<family>Linux</family>
<product>Linux</product>
<version>22.04</version>
<device-class>General</device-class>
<architecture>x86_64</architecture>
</fingerprint>
<services>
<service name="SSH" port="22" protocol="tcp">
<fingerprint certainty="0.90">
<description>OpenSSH 8.9p1</description>
<vendor>OpenBSD</vendor>
<family></family>
<product>OpenSSH</product>
<version>8.9p1</version>
</fingerprint>
</service>
</services>
<vulnerabilities>
<vulnerability id="test-vuln-1" resultCode="VE"/>
</vulnerabilities>
</device>
</devices>
</NeXposeSimpleXML>`

	path := filepath.Join(t.TempDir(), "test-nexpose-simple.xml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseNexpose(path)
	if err != nil {
		t.Fatalf("ParseNexpose (simple): %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(result.Hosts))
	}
	h := result.Hosts[0]
	if h.Addresses[0] != "10.0.0.1" {
		t.Errorf("address = %q, want 10.0.0.1", h.Addresses[0])
	}
	if h.OS != "Ubuntu Linux 22.04" {
		t.Errorf("OS = %q, want 'Ubuntu Linux 22.04'", h.OS)
	}
	if len(h.Services) != 1 || h.Services[0].Port != "22" {
		t.Errorf("services = %+v, want 1 service on port 22", h.Services)
	}
	if h.Services[0].Product != "OpenSSH" {
		t.Errorf("service product = %q, want 'OpenSSH'", h.Services[0].Product)
	}
}

// TestParseNexposeReport validates Nexpose Report v1/v2 parsing.
func TestParseNexposeReport(t *testing.T) {
	content := `<NexposeReport version="2.0">
<scans>
<scan id="1" name="TestScan" startTime="20240101T000000000" endTime="20240101T010000000" status="finished"/>
</scans>
<nodes>
<node address="10.0.0.2" status="alive" hardware-address="AABBCCDDEEFF" device-id="5" site-name="Lab" risk-score="123.45">
<names><name>myhost.local</name></names>
<fingerprints>
<os certainty="1.00" vendor="Ubuntu" family="Linux" product="Linux" version="22.04" arch="x86_64"/>
</fingerprints>
<software>
<fingerprint certainty="1.00" vendor="OpenBSD" product="OpenSSH" version="8.9"/>
</software>
<endpoints>
<endpoint protocol="tcp" port="22" status="open">
<services><service name="SSH">
<configuration>
<config name="ssh.hostkey.rsa.fingerprint">aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99</config>
</configuration>
</service></services>
</endpoint>
<endpoint protocol="tcp" port="443" status="open">
<services><service name="HTTPS">
<configuration>
<config name="ssl.cert.sha1.fingerprint">AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD</config>
<config name="ssl.cert.subject.dn">CN=myhost.local</config>
</configuration>
</service></services>
</endpoint>
</endpoints>
<tests>
<test id="vuln-1" status="vulnerable-exploited" key="" scan-id="1"/>
<test id="vuln-2" status="vulnerable-version" key="" scan-id="1"/>
<test id="not-vuln" status="not-vulnerable" key="" scan-id="1"/>
</tests>
</node>
<node address="10.0.0.3" status="dead"/>
</nodes>
</NexposeReport>`

	path := filepath.Join(t.TempDir(), "test-nexpose-v2.xml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := input.ParseNexpose(path)
	if err != nil {
		t.Fatalf("ParseNexpose (report): %v", err)
	}
	// Dead node should be excluded
	if len(result.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1 (dead node excluded)", len(result.Hosts))
	}
	h := result.Hosts[0]
	if h.Addresses[0] != "10.0.0.2" {
		t.Errorf("address = %q, want 10.0.0.2", h.Addresses[0])
	}
	if len(h.MACs) == 0 || h.MACs[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MACs = %v, want [aa:bb:cc:dd:ee:ff]", h.MACs)
	}
	if len(h.Names) == 0 || h.Names[0] != "myhost.local" {
		t.Errorf("Names = %v, want [myhost.local]", h.Names)
	}
	if h.OS != "Linux 22.04 (x86_64)" {
		t.Errorf("OS = %q, want 'Linux 22.04 (x86_64)'", h.OS)
	}
	if h.Attributes["site_name"] != "Lab" {
		t.Errorf("site_name = %q, want 'Lab'", h.Attributes["site_name"])
	}
	if h.Attributes["risk_score"] != "123.45" {
		t.Errorf("risk_score = %q, want '123.45'", h.Attributes["risk_score"])
	}
	if len(h.Services) != 2 {
		t.Fatalf("got %d services, want 2", len(h.Services))
	}
	// SSH host key fingerprint
	if h.UniqueKeys["ssh_hostkey_fp"] == "" {
		t.Error("expected ssh_hostkey_fp to be set")
	}
	// TLS cert fingerprint
	if h.UniqueKeys["tls_cert_fp"] == "" {
		t.Error("expected tls_cert_fp to be set")
	}
	// Vulnerability count: 2 vulnerable tests (not-vulnerable excluded)
	if h.Attributes["vulnerability_count"] != "2" {
		t.Errorf("vulnerability_count = %q, want '2'", h.Attributes["vulnerability_count"])
	}
	// Software count
	if h.Attributes["software_count"] != "1" {
		t.Errorf("software_count = %q, want '1'", h.Attributes["software_count"])
	}
}
