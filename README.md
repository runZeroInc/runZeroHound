# runZeroHound

Bring runZero Exposure Management into BloodHound via [OpenGraph](https://bloodhound.specterops.io/opengraph/overview).

## Getting Started

### Setup BloodHound CE With 'pg' Graph DB

1. Ensure that you have Docker or Podman (in Docker-compatibility mode). The command “docker compose ls” should not return an error.
   
3. Git clone the BloodHound source tree:
   
```
git clone https://github.com/SpecterOps/BloodHound.git
```

4. Open a terminal in the BloodHound/examples/docker-compoose subdirectory
5. 
6. Adjust docker-compose.yml to enable the “pg” graph-db driver

```
bhe_graph_driver=pg
```

6. Adjust bloodhound.config.json to set the graph_driver to “pg”

```
"graph_driver": "pg",
```

7. Run “docker compose up” to launch BloodHound
8. Copy the initial admin password shown in the output
9. Login to http://127.0.0.1:8080/ui/login with username admin and your password
10. Change the password to something else and remember or save it
11. Hurray! At this point you are ready to load and explore data

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

### TODO: Configure Custom Icons

BloodHound OpenGraph supports custom icons for specific node types. Setting this up requires a bit of
API interaction and we plan to add a helper tool to support this in the future.

## Nodes

- **RZAsset** - Connected devices with IPs, open ports, and system info
    - Connected to services via RZHasService and RZRunsOnAsset edges
    - Connected to subnets via RZInsideOfSubnet and RZSubnetContains edges
- **RZService** - Identified services on assets
    - Connected to assets via RZHasService and RZRunsOnAsset edges
- **RZSubnet** - Network subnets with CIDR notation and host counts
    - Connected to assets via RZInsideOfSubnet and RZSubnetContains edges
    - Subnets assume /24 and /56 masks for IPv4 and IPv6 respectively
    - External subnets are connected to an "Internet" node
- **RZDomain** - Active Directory domain name if available
    - Connected to assets via RZPartOfDomain and RZDomainContains edges
- **RZVLAN**   - VLAN IDs if available from asset attributes
    - Connected to assets via RZPartOfVLAN and RZVLANContains edges

### Node Properties

**Asset Nodes:**
- `ip_addresses[]`: All resolved IP addresses
- `ip_addresses_extra[]`: All resolved IP addresses
- `hostname`: Primary hostname
- `names[]`: All resolved names
- `domains[]`: All resolved domains
- `service_ports_tcp[]`: Discovered TCP open ports
- `service_ports_udp[]`: Discovered UDP services
- `os`: Operating system information
- `hw`: Hardware information
- `mac_addresses[]`: All resolved MAC addresses
- `newest_mac`: Newest MAC address
- `newest_mac_vendor`: Vendor of newest MAC address
- `newest_mac_age`: Age of newest MAC address
- `lowest_ttl`: Lowest observed TTL value
- `lowest_rtt`: Lowest observed RTT value
- `alive`: Boolean indicating if the device is alive
- `services{}`: List of discovered services
- `credentials[]`: List of discovered credentials
- `tags[]`: Asset tags
- `scanned`: Last scanned timestamp
- `comments`: Asset comments
- `service_protocols[]`: List of service protocols
- `service_products[]`: List of service products
- `software_count`: Number of installed software items
- `vulnerability_count`: Number of identified vulnerabilities
- `risk`: Risk level as a string
- `risk_rank`: Numerical risk rank
- `first_seen`: Timestamp of first sighting
- `last_seen`: Timestamp of last sighting
- `created_at`: Asset creation timestamp
- `updated_at`: Asset last updated timestamp
- `sources[]`: List of data sources
- `tags[]`: All unique tags (bare and key-values)

Asset nodes also include flattened attributes, prefixed by the source type (runzero, crowdstrike.dev, etc)

**Service Nodes:**
- `address`: IP address (v4 or v6)
- `port`: Port number if relevant (as a string)
- `transport`: Underlying transport (tcp, udp, icmp, arp)

Service nodes also include flattened attributes, prefixed by "attr_"

**Subnet Nodes:**
- `subnet`: CIDR notation
- `network_address`: Network address
- `host_count`: Number of hosts in subnet

**Domain Nodes:**
- `domain`: Domain name
- `host_count`: Number of hosts in domain

**VLAN Nodes:**
- `vlan`: VLAN ID
- `host_count`: Number of hosts in VLAN

## Example Cypher Queries

Please see the [Cypher documentation](https://bloodhound.specterops.io/analyze-data/cypher-search) for more details.

### Windows Machines With External IPs

```
match p=(t1:RZAsset)-[:RZInsideOfSubnet]->(a:RZNetwork)-[:RZInsideOfSubnet]->(b:RZNetwork)
where b.network_address = '0.0.0.0'
and a.version = '4'
and t1.os contains 'Windows'
return
```

![Screenshot of BloodHound CE showing Windows machines with external IPs](/docs/bhce_windows_internet.png)



### Paths From the Internet To The Internal 10.0.0.0/8

```
match p=(public:RZNetwork)-[:RZSubnetContains]->(hop1:RZNetwork)-[:RZSubnetContains]->(a1:RZAsset)
where 
public.network_address = '0.0.0.0'
and hop1.version = '4'
and a1.ip_addresses contains '10.'
return p
```

![Screenshot of BloodHound CE showing paths from the internet to the 10.0.0.0/8 subnet](/docs/bhce_external_internal_10.png)



### Find BYOD iPhones On The Same Subnet As Cisco Devices with Default SNMP

```
match p=(byod:RZAsset)-[:RZInsideOfSubnet]->(net1:RZNetwork)-[:RZSubnetContains]->(mgmt:RZAsset)
where 
byod.os contains 'Apple iOS'
AND mgmt.os contains ‘Cisco’
AND mgmt.service_protocols contains 'snmp2'
return p
```

![Screenshot of BloodHound CE showing subnets with both iPhones and Cisco devices with default SNMP v2](/docs/bhce_iphone_cisco.png)

## Contact

runZeroHound is not an officially supported runZero product, but we still want to hear your feedback and bug reports.
Please open an issue in this repository or email support[at]runZero.com.
