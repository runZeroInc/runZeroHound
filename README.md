# ZeroHound (aka runZeroHound)

Bring Exposure Management data into BloodHound via [OpenGraph](https://bloodhound.specterops.io/opengraph/overview).

Read our [initial blog post](https://www.runzero.com/blog/introducing-runzerohound/).

runZeroHound is now just `ZeroHound` to make it clear that this is a general-purpose loader/correlation tool for BloodHound OpenGraph and not specific to runZero data. The entites still prefix with `RZ` to avoid conflicting with other imports in the same database.

ZeroHound imports data from Nmap, runZero, Qualys, snmpwalk, Tenable (Nessus), OpenVAS/GVM, Masscan, Shodan, NetBox, and many more!


## Getting Started

### Setup BloodHound CE With 'pg' Graph DB

1. Ensure that you have Docker or Podman (in Docker-compatibility mode). The command “docker compose ls” should not return an error.
   
2. Git clone the BloodHound source tree:
   
```
git clone https://github.com/SpecterOps/BloodHound.git
```

3. Open a terminal in the `BloodHound/examples/docker-compoose` subdirectory
   
4. Adjust `docker-compose.yml` to enable the `pg` graph-db driver

```
bhe_graph_driver=pg
```

5. Adjust bloodhound.config.json to set the graph_driver to “pg”

```
"graph_driver": "pg",
```

6. Run “docker compose up” to launch BloodHound
7. Copy the initial admin password shown in the output
8. Login to http://127.0.0.1:8080/ui/login with username admin and your password
9. Change the password to something else and remember or save it
10. Hurray! At this point you are ready to load and explore data

### Setup runZeroHound

1. Ensure that you have a recent version of Go installed (1.25+)
2. Git clone the runZeroHound source tree

```
git clone https://github.com/runZeroInc/runZeroHound.git
```

3. Ensure that the tool runs:

```
go run main.go -h
```

### Download Your runZero Asset Inventory in JSONL Format

1. Login to your runZero Console
2. Navigate to Inventory -> Assets
3. Under Export, select “As JSON Lines…”
4. Wait for this to download to disk

### Create and Import runZeroHound Graphs

1. Open the runZeroHound directory in your terminal
2. Run the convert command to create an OpenGraph JSON

```
go run main.go convert <runZeroInventory.jsonl> opengraph.json
```

3. Use the Quick Upload option on the left and drag your opengraph.json onto it
4. Watch the File Ingest history at http://127.0.0.1:8080/ui/administration/file-ingest
5. Once import completes, access Explore and then select the Cypher tab
6. Enter a test query to verify your data:

```
match (n:RZNetwork) where n.network_address = '0.0.0.0' return n
```

7. Confirm that this query shows the RZ-NETWORK-PUBLIC subnet node

### Upload Directly to BloodHound CE via CLI

Instead of manually dragging the file, you can upload using the `upload` command.

All BloodHound CE commands (`upload`, `cypher`, `purge`) share the same authentication flags and accept either **API token** or **username/password** credentials. Environment variables are used when flags are not set.

| Flag | Environment Variable | Description |
|------|---------------------|-------------|
| `--url` | `BLOODHOUND_URL` | BloodHound CE base URL |
| `--token-id` | `BLOODHOUND_TOKEN_ID` | API token ID |
| `--token-key` | `BLOODHOUND_TOKEN_KEY` | API token key/secret |
| `--username` | `BLOODHOUND_USERNAME` | BloodHound CE username |
| `--password` | `BLOODHOUND_PASSWORD` | BloodHound CE password |
| `--insecure` | | Skip TLS certificate verification |

To create an API token in BloodHound CE, navigate to Administration → API Tokens.

```bash
# Using API token auth
export BLOODHOUND_URL=http://127.0.0.1:8080
export BLOODHOUND_TOKEN_ID=<your-token-id>
export BLOODHOUND_TOKEN_KEY=<your-token-key>
go run main.go upload opengraph.json

# Using username/password auth
export BLOODHOUND_URL=http://127.0.0.1:8080
export BLOODHOUND_USERNAME=admin
export BLOODHOUND_PASSWORD=<your-password>
go run main.go upload opengraph.json
```

Or pass credentials as flags:

```bash
go run main.go upload \
  --url http://127.0.0.1:8080 \
  --token-id <id> \
  --token-key <key> \
  opengraph.json
```

#### Waiting for Ingest Completion

Use `--wait` to block until all ingest jobs finish and the datapipe is idle:

```bash
# Upload and wait for ingest to complete
go run main.go upload --wait opengraph.json

# Just wait for pending jobs to finish (no file upload)
go run main.go upload --wait
```

| Flag | Default | Description |
|------|---------|-------------|
| `--wait` | `false` | Wait for all ingest jobs to complete |
| `--wait-timeout` | `300` | Maximum seconds to wait for ingest completion |
| `--wait-interval` | `5` | Seconds between status checks |

### Run Cypher Queries via CLI

The `cypher` command executes a Cypher query against BloodHound CE and prints the raw JSON response to stdout:

```bash
go run main.go cypher 'MATCH (n) RETURN labels(n) AS kind, count(n) AS total ORDER BY total DESC'
```

Pipe through `jq` for pretty-printing or field extraction:

```bash
go run main.go cypher 'MATCH (n:RZNetwork) RETURN n.displayname LIMIT 5' | jq .
```

### Purge BloodHound CE Data

The `purge` command deletes all collected graph data, file ingest history, and data quality history:

```bash
go run main.go purge
```

This is useful for starting fresh before loading a new dataset.

### TODO: Configure Custom Icons

BloodHound OpenGraph supports custom icons for specific node types. Setting this up requires a bit of
API interaction and we plan to add a helper tool to support this in the future.

## What It Extracts

runZeroHound converts flat asset data into a richly connected graph with **30+ node types** and **50+ edge types** spanning IT, OT, and IoT environments.

| Category | Node Types |
|----------|------------|
| **Core** | `RZAsset`, `RZService`, `RZNetwork`, `RZDomain`, `RZVLAN` |
| **Cryptographic Identity** | `RZSSHKey`, `RZTLSCert`, `RZTLSCAChain`, `RZSMBGUID`, `RZSerialNumber` |
| **Network Infrastructure** | `RZRouter`, `RZMACAddress`, `RZMACVendor`, `RZSwitch`, `RZSwitchPort`, `RZSubAsset` |
| **Protocol Fingerprints** | `RZSNMPEngineID`, `RZSNMPDeviceType`, `RZSNMPCommunity`, `RZIPMICredential`, `RZFavicon`, `RZIKEIdentity` |
| **OT / Building Automation** | `RZGateway`, `RZKNXnetDevice`, `RZBACnetDevice` |
| **Time & DNS** | `RZNTPReference`, `RZDNSIdentity`, `RZDNSVersion` |
| **Windows / AD** | `RZNTLMDomain`, `RZNTLMComputer` |
| **Vulnerabilities** | `RZVuln` |

18 relationship extractors automatically create edges between nodes wherever assets share a cryptographic key, serial number, CA chain, NTP source, NTLM domain, favicon hash, vulnerability finding, or any other correlatable identity.

For the complete schema (every node kind, edge, and property), see [QUERIES.md](QUERIES.md#schema-reference).

## Example Cypher Queries

All queries run in the BloodHound CE **Explore → Cypher** tab or via `go run main.go cypher '<query>'`. For 75+ queries organized by difficulty and category, see [QUERIES.md](QUERIES.md).

### Simple — What do I have?

Count every node type in the graph:

```cypher
MATCH (n)
RETURN labels(n) AS kind, count(n) AS total
ORDER BY total DESC
```

Top open ports across all assets:

```cypher
MATCH (svc:RZService)
WHERE svc.port IS NOT NULL
RETURN svc.port + '/' + svc.transport AS port, count(svc) AS total
ORDER BY total DESC
LIMIT 20
```

### Moderate — Identity & Correlation

SSH key reuse — find keys shared across multiple assets:

```cypher
MATCH (a:RZAsset)-[:RZHasSSHKey]->(key:RZSSHKey)
WITH key, collect(DISTINCT a.displayname) AS hosts
WHERE size(hosts) > 1
RETURN key.fingerprint, key.key_type, hosts
ORDER BY size(hosts) DESC
LIMIT 20
```

BACnet devices by vendor:

```cypher
MATCH (dev:RZBACnetDevice)
RETURN dev.vendor_name, dev.vendor_id, count(dev) AS count
ORDER BY count DESC
```

### Advanced — Cross-Network Analysis

Certificates reused across different subnets:

```cypher
MATCH (a:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH cert, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE size(subnets) > 1
RETURN cert.cn, cert.sha1, subnets, hosts
ORDER BY hosts DESC
LIMIT 10
```

NTLM domains spanning multiple subnets (lateral movement surface):

```cypher
MATCH (a:RZAsset)-[:RZHasNTLMDomain]->(dom:RZNTLMDomain),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH dom, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE size(subnets) > 1
RETURN dom.dns_domain, subnets, hosts
ORDER BY hosts DESC
```

### Vulnerabilities

Most widespread vulnerabilities (affecting the most hosts):

```cypher
MATCH (a)-[:RZHasVuln]->(v:RZVuln)
WITH v, count(a) AS affected_hosts
RETURN v.displayname, v.source, v.severity, affected_hosts
ORDER BY affected_hosts DESC
LIMIT 20
```

High-severity vulnerabilities with CVEs:

```cypher
MATCH (v:RZVuln)
WHERE v.cve IS NOT NULL
RETURN v.displayname, v.cve, v.source
LIMIT 20
```

### Expert — Full Graph Traversal

Relationship richness per asset (how many different identity types link to each host):

```cypher
MATCH (a:RZAsset)
OPTIONAL MATCH (a)-[:RZHasSSHKey]->(ssh:RZSSHKey)
OPTIONAL MATCH (a)-[:RZHasTLSCert]->(tls:RZTLSCert)
OPTIONAL MATCH (a)-[:RZHasGateway]->(gw:RZGateway)
OPTIONAL MATCH (a)-[:RZHasFavicon]->(fav:RZFavicon)
OPTIONAL MATCH (a)-[:RZHasBACnetDevice]->(bac:RZBACnetDevice)
OPTIONAL MATCH (a)-[:RZHasSerialNumber]->(sn:RZSerialNumber)
WITH a,
     count(DISTINCT ssh) AS ssh_keys,
     count(DISTINCT tls) AS tls_certs,
     count(DISTINCT gw)  AS gateways,
     count(DISTINCT fav)  AS favicons,
     count(DISTINCT bac)  AS bacnet_devs,
     count(DISTINCT sn)   AS serials
WHERE ssh_keys + tls_certs + gateways + favicons + bacnet_devs + serials > 0
RETURN a.displayname, ssh_keys, tls_certs, gateways, favicons, bacnet_devs, serials
ORDER BY ssh_keys + tls_certs + gateways + favicons + bacnet_devs + serials DESC
LIMIT 20
```

See [QUERIES.md](QUERIES.md) for the full collection including inter-asset relationships and quirky/surprising results.

### Validating Queries

The `test_queries.sh` script extracts every query from QUERIES.md and runs each one via the `cypher` CLI command:

```bash
# Full run: convert sample data, purge, upload, wait, then test all queries
./test_queries.sh

# Skip data loading — just test queries against existing data
./test_queries.sh --skip-load
```

## Supported Data Sources

runZeroHound can ingest data from any of the following sources:

| Source | Format | Detection | Key Data Extracted |
|--------|--------|-----------|-------------------|
| **runZero** | JSONL / JSONL.gz | gzip header or JSON lines | Full asset model with all attributes, services, IPs, MACs, domains, VLANs |
| **Nmap** | XML (-oX) | `<nmaprun` XML tag | IPs, MACs, hostnames, OS, services, SSH keys, TLS certs, SMB GUIDs, SNMP engine IDs, traceroute hops |
| **Nessus** | .nessus XML | Extension or `NessusClientData` tag | IPs, MACs, hostnames, OS, services, SSH keys, TLS certs, SMB GUIDs, SNMP engine IDs, traceroute hops |
| **OpenVAS/GVM** | XML | `<report` + `openvas`/`gvm` | IPs, MACs, hostnames, OS, services, SSH keys, TLS certs, SMB GUIDs, SNMP engine IDs |
| **Qualys** | VM scan XML | `<SCAN` + `<IP` tags | IPs, MACs, hostnames, OS, services, SSH keys, TLS certs, SMB GUIDs, SNMP engine IDs |
| **Masscan** | XML or JSON | `scanner="masscan"` or JSON with `ip`+`ports` | IPs, open ports, service banners |
| **Shodan** | JSONL | `ip_str` in JSON | IPs, hostnames, OS, services, TLS certs, SSH keys, vulnerabilities |
| **NetBox** | JSON API export | `count`+`results` JSON | IPs, hostnames, device types, roles, platforms, sites, racks |
| **snmpwalk** | Text output | OID = TYPE: VALUE pattern | IPs, MACs, hostnames, OS (sysDescr), SNMP engine IDs, ARP cache, MAC table |
| **oobscan** | JSONL | gzip header or JSON lines  | Detailed data from out-of-band device scans |

### Ideal Nmap Command

For the best data from Nmap for use with runZeroHound, see [docs/nmap-commands.md](docs/nmap-commands.md).

Quick reference for a comprehensive scan:

```bash
sudo nmap -sS -sU -sV -O --traceroute \
  --script ssh-hostkey,ssl-cert,smb2-security-mode,snmp-info,nbstat \
  -p T:22,80,443,445,3389,8080,8443,U:161,137 \
  -oX scan.xml 192.168.1.0/24
```

### Cross-Source Correlation

When loading data from multiple sources, runZeroHound automatically correlates assets using shared cryptographic identities:
- **SSH host keys** — Same host key fingerprint from Nmap, Nessus, and runZero links them as the same device
- **TLS certificates** — Shared certificate SHA-1 fingerprints connect scanners observing the same endpoint
- **SMB GUIDs** — Windows machine GUIDs link SMB-visible hosts across sources
- **SNMPv3 Engine IDs** — Unique SNMP engine identifiers correlate managed network devices

These fingerprints are normalised to a consistent lowercase colon-hex format across all parsers.

## Contact

runZeroHound is not an officially supported runZero product, but we still want to hear your feedback and bug reports.
Please open an issue in this repository or email support[at]runZero.com.

## Supported Data Sources

runZeroHound can ingest data from any of the following sources:

| Source | Format | Detection | Key Data Extracted |
|--------|--------|-----------|-------------------|
| **runZero** | JSONL / JSONL.gz | gzip header or JSON lines | Full asset model with all attributes, services, IPs, MACs, domains, VLANs |
| **Nmap** | XML (-oX) | `<nmaprun` XML tag | IPs, MACs, hostnames, OS, services, SSH keys, TLS certs, SMB GUIDs, SNMP engine IDs, traceroute hops |
| **Nessus** | .nessus XML | Extension or `NessusClientData` tag | IPs, MACs, hostnames, OS, services, SSH keys, TLS certs, SMB GUIDs, SNMP engine IDs, traceroute hops |
| **OpenVAS/GVM** | XML | `<report` + `openvas`/`gvm` | IPs, MACs, hostnames, OS, services, SSH keys, TLS certs, SMB GUIDs, SNMP engine IDs |
| **Qualys** | VM scan XML | `<SCAN` + `<IP` tags | IPs, MACs, hostnames, OS, services, SSH keys, TLS certs, SMB GUIDs, SNMP engine IDs |
| **Masscan** | XML or JSON | `scanner="masscan"` or JSON with `ip`+`ports` | IPs, open ports, service banners |
| **Shodan** | JSONL | `ip_str` in JSON | IPs, hostnames, OS, services, TLS certs, SSH keys, vulnerabilities |
| **NetBox** | JSON API export | `count`+`results` JSON | IPs, hostnames, device types, roles, platforms, sites, racks |
| **snmpwalk** | Text output | OID = TYPE: VALUE pattern | IPs, MACs, hostnames, OS (sysDescr), SNMP engine IDs, ARP cache, MAC table |
| **nextnet** | .nxt JSONL | `.nxt` extension | IPs, NetBIOS names, MACs, secondary addresses, SNMP engine IDs |

### Ideal Nmap Command

For the best data from Nmap for use with runZeroHound, see [docs/nmap-commands.md](docs/nmap-commands.md).

Quick reference for a comprehensive scan:

```bash
sudo nmap -sS -sU -sV -O --traceroute \
  --script ssh-hostkey,ssl-cert,smb2-security-mode,snmp-info,nbstat \
  -p T:22,80,443,445,3389,8080,8443,U:161,137 \
  -oX scan.xml 192.168.1.0/24
```

### nextnet Scanner

runZeroHound includes a built-in network scanner (`nextnet`) that probes for:
- **NetBIOS** (UDP 137): Discovers hostnames, domains, MAC addresses, and multi-homed interface addresses
- **SNMP** (UDP 161): Discovers sysDescr, sysName, SNMP engine IDs, interface addresses, ARP cache, and MAC tables

```bash
go run main.go nextnet 192.168.1.0/24 10.0.0.0/8
```

### Cross-Source Correlation

When loading data from multiple sources, runZeroHound automatically correlates assets using shared cryptographic identities:
- **SSH host keys** — Same host key fingerprint from Nmap, Nessus, and runZero links them as the same device
- **TLS certificates** — Shared certificate SHA-1 fingerprints connect scanners observing the same endpoint
- **SMB GUIDs** — Windows machine GUIDs link SMB-visible hosts across sources
- **SNMPv3 Engine IDs** — Unique SNMP engine identifiers correlate managed network devices

These fingerprints are normalised to a consistent lowercase colon-hex format across all parsers.
