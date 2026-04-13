# runZeroHound

Bring runZero Exposure Management into BloodHound via [OpenGraph](https://bloodhound.specterops.io/opengraph/overview).

Read our [initial blog post](https://www.runzero.com/blog/introducing-runzerohound/).

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

### TODO: Configure Custom Icons

BloodHound OpenGraph supports custom icons for specific node types. Setting this up requires a bit of
API interaction and we plan to add a helper tool to support this in the future.

## Nodes

- **RZAsset** - Connected devices with IPs, open ports, system info, device type, category, and functions
    - Connected to services via `RZHasService` and `RZRunsOnAsset` edges
    - Connected to subnets via `RZInsideOfSubnet` and `RZSubnetContains` edges
    - Connected to domains via `RZPartOfDomain` and `RZDomainContains` edges
    - Connected to VLANs via `RZPartOfVLAN` and `RZVLANContains` edges
- **RZService** - Identified services on assets
    - Connected to assets via `RZHasService` and `RZRunsOnAsset` edges
- **RZNetwork** - Network subnets with CIDR notation and host counts
    - Connected to assets via `RZInsideOfSubnet` and `RZSubnetContains` edges
    - Subnets assume /24 and /56 masks for IPv4 and IPv6 respectively
    - External subnets are connected to an "Internet" node
- **RZDomain** - Active Directory domain name if available
    - Connected to assets via `RZPartOfDomain` and `RZDomainContains` edges
- **RZVLAN** - VLAN IDs if available from asset attributes
    - Connected to assets via `RZPartOfVLAN` and `RZVLANContains` edges

### Node Properties

**Asset Nodes:**
- `ip_addresses[]`: All resolved IP addresses
- `ip_addresses_extra[]`: Additional resolved IP addresses
- `ip_address_count`: Number of primary IP addresses
- `ip_address_extra_count`: Number of additional IP addresses
- `hostname`: Primary hostname
- `name`: BloodHound-style hostname (derived from NTLM responses when available)
- `names[]`: All resolved hostnames
- `domains[]`: All resolved Active Directory domains
- `type`: Device type (e.g., Server, Desktop, Mobile, Printer, Router, OT Device, etc.)
- `category`: Device category (e.g., IT, OT, IoT, Mobile)
- `functions[]`: Device functions (e.g., Router, Firewall, Switch, Controller, Historian)
- `os`: Operating system string
- `hw`: Hardware description string
- `mac_addresses[]`: All resolved MAC addresses
- `newest_mac`: Most recently observed MAC address
- `newest_mac_vendor`: Vendor of the newest MAC address
- `newest_mac_age`: Age of the newest MAC address (epoch seconds)
- `lowest_ttl`: Lowest observed IP TTL value
- `lowest_rtt`: Lowest observed round-trip time (microseconds)
- `alive`: Boolean indicating the device responded to probes
- `scanned`: Boolean indicating the device was actively scanned
- `comments`: Free-text asset comments
- `service_count`: Total number of discovered services
- `services_tcp_count`: Number of discovered TCP services
- `services_udp_count`: Number of discovered UDP services
- `services_icmp_count`: Number of discovered ICMP services
- `services_arp_count`: Number of discovered ARP services
- `service_protocols[]`: List of identified service protocols
- `service_products[]`: List of identified service products
- `service_ports_tcp[]`: Discovered open TCP ports
- `service_ports_udp[]`: Discovered open UDP ports
- `software_count`: Number of identified software items
- `vulnerability_count`: Number of identified vulnerabilities
- `risk`: Risk level as a string (none, info, low, medium, high, critical)
- `risk_rank`: Numerical risk rank (-1=none, 0=info, 1=low, 2=medium, 3=high, 4=critical)
- `outlier_score`: Outlier score (higher = more unusual)
- `outlier_raw`: Raw outlier value
- `first_seen`: Unix timestamp of first observation
- `last_seen`: Unix timestamp of last observation
- `created_at`: Unix timestamp when the asset record was created
- `updated_at`: Unix timestamp when the asset record was last updated
- `sources[]`: List of data source names that contributed to this asset
- `tags[]`: All unique tags (bare tags and key=value pairs)
- `organization_name`: runZero organization name
- `site_name`: runZero site name
- `agent_name`: Name of the runZero agent that scanned this asset
- `agent_external_ip`: External IP of the agent that scanned this asset
- `hosted_zone_name`: Hosted zone name (cloud environments)
- `last_agent_id`: UUID of the most recent scanning agent
- `last_task_id`: UUID of the most recent scan task
- `first_task_id`: UUID of the first scan task
- `subnets[]`: runZero site-level subnet assignments

Asset nodes also include flattened attributes prefixed by the source type (e.g., `runzero.*`, `crowdstrike.*`, `azure.*`).

**Service Nodes:**
- `address`: IP address (v4 or v6)
- `port`: Port number if relevant (as a string)
- `transport`: Underlying transport protocol (tcp, udp, icmp, arp)

Service nodes also include flattened service attributes prefixed by `attr_`.

**Subnet Nodes:**
- `displayname`: CIDR notation
- `network_address`: Base network address
- `host_count`: Number of observed hosts in this subnet
- `version`: IP version (`4` or `6`)

**Domain Nodes:**
- `displayname`: Domain name
- `host_count`: Number of hosts in this domain

**VLAN Nodes:**
- `displayname`: VLAN ID
- `host_count`: Number of hosts in this VLAN

## Example Cypher Queries

Please see [QUERIES.md](QUERIES.md) for a full collection of queries, including novel risk-identification patterns.

Please see the [Cypher documentation](https://bloodhound.specterops.io/analyze-data/cypher-search) for more details on Cypher syntax.


## Contact

runZeroHound is not an officially supported runZero product, but we still want to hear your feedback and bug reports.
Please open an issue in this repository or email support[at]runZero.com.
