# runZeroHound Cypher Query Reference

A curated collection of Cypher queries for exploring runZeroHound graphs in BloodHound CE.
See the [Cypher documentation](https://bloodhound.specterops.io/analyze-data/cypher-search) for language details.

---

## Table of Contents

- [Schema Reference](#schema-reference)
  - [Node Kinds](#node-kinds)
  - [Edge Kinds](#edge-kinds)
- [1 — Getting Started](#1--getting-started)
- [2 — Simple Queries](#2--simple-queries)
  - [Asset Inventory](#asset-inventory)
  - [Services & Ports](#services--ports)
  - [Network Topology](#network-topology)
- [3 — Intermediate Queries](#3--intermediate-queries)
  - [Cryptographic Identity](#cryptographic-identity)
  - [OT / Building Automation](#ot--building-automation)
  - [Infrastructure Fingerprinting](#infrastructure-fingerprinting)
  - [Windows / Active Directory](#windows--active-directory)
- [4 — Advanced Queries](#4--advanced-queries)
  - [Cross-Source Correlation](#cross-source-correlation)
  - [Exposure & Risk](#exposure--risk)
  - [Dependency Mapping](#dependency-mapping)
- [5 — Expert Queries](#5--expert-queries)
- [6 — Quirky & Surprising](#6--quirky--surprising)

---

## Schema Reference

### Node Kinds

| Kind | Description |
|------|-------------|
| `RZAsset` | A network asset (runZero-discovered) |
| `RZService` | A network service running on an asset |
| `RZNetwork` | An IP subnet (/24 IPv4, /56 IPv6) |
| `RZDomain` | A DNS / AD domain |
| `RZVLAN` | A VLAN ID |
| `RZGateway` | A BACnet / CIP / Modbus / KNXnet gateway |
| `RZSSHKey` | An SSH host key fingerprint |
| `RZTLSCert` | A TLS certificate (SHA-1) |
| `RZTLSCAChain` | A TLS signing CA (CA cert SHA-1) |
| `RZSNMPEngineID` | An SNMPv3 Engine ID |
| `RZSNMPDeviceType` | An SNMP device type (sysObjectID) |
| `RZSMBGUID` | An SMB machine GUID |
| `RZIPMICredential` | An IPMI credential/configuration |
| `RZRouter` | A layer-3 traceroute hop |
| `RZMACAddress` | A MAC address with vendor metadata |
| `RZMACVendor` | A MAC OUI vendor |
| `RZSwitch` | A layer-2 switch |
| `RZSwitchPort` | A physical switch port |
| `RZSubAsset` | A sub-asset (ARP cache, MAC table entry) |
| `RZFavicon` | A web favicon fingerprint (MD5 + mmh3) |
| `RZIKEIdentity` | An IKE/IPsec VPN fingerprint |
| `RZKNXnetDevice` | A KNXnet/IP building automation device |
| `RZBACnetDevice` | A BACnet building automation device |
| `RZNTPReference` | An NTP upstream reference clock |
| `RZDNSIdentity` | A DNS server identity (CHAOS TXT) |
| `RZDNSVersion` | A DNS software version (version.bind) |
| `RZSerialNumber` | A device serial number (cross-protocol) |
| `RZNTLMDomain` | An NTLM SSP domain |
| `RZNTLMComputer` | An NTLM SSP computer identity |

### Edge Kinds

| Edge | Direction | Description |
|------|-----------|-------------|
| `RZHasService` / `RZRunsOnAsset` | Asset ↔ Service | Service relationship |
| `RZInsideOfSubnet` / `RZSubnetContains` | Asset ↔ Network | Subnet membership |
| `RZPartOfDomain` / `RZDomainContains` | Asset ↔ Domain | Domain membership |
| `RZPartOfVLAN` / `RZVLANContains` | Asset ↔ VLAN | VLAN membership |
| `RZHasGateway` / `RZHasGatewayAssets` | Asset ↔ Gateway | OT gateway relationship |
| `RZHasSSHKey` / `RZHasSSHService` | Asset → SSHKey → Service | SSH key chain |
| `RZHasTLSCert` / `RZHasTLSService` | Asset → TLSCert → Service | TLS cert chain |
| `RZSignedByCA` / `RZCASignedCert` | Asset → TLSCAChain → Service | CA signing chain |
| `RZHasSNMPEngineID` / `RZHasSNMPService` | Asset → SNMPEngineID → Service | SNMP engine chain |
| `RZHasSNMPDeviceType` / `RZSNMPDeviceTypeUsedBy` | Asset ↔ SNMPDeviceType | Device type grouping |
| `RZHasSMBGUID` / `RZHasSMBService` | Asset → SMBGUID → Service | SMB identity chain |
| `RZHasIPMICredential` / `RZHasIPMIService` | Asset → IPMICredential → Service | IPMI chain |
| `RZHasRouter` | Asset ↔ Router (bidirectional) | Traceroute hops |
| `RZHasMAC` / `RZHasMACHost` | Asset ↔ MACAddress | MAC ownership |
| `RZHasMACVendor` | MACAddress → MACVendor | Vendor lookup |
| `RZHasSwitch` / `RZHasSwitchAssets` | Asset ↔ Switch | Switch connection |
| `RZHasSwitchPort` / `RZConnectedToPort` | Switch/Asset → SwitchPort | Port mapping |
| `RZHasFavicon` / `RZFaviconUsedBy` | Asset → Favicon → Service | Favicon fingerprint |
| `RZHasIKEIdentity` / `RZIKEIdentityUsedBy` | Asset → IKEIdentity → Service | VPN identity |
| `RZHasKNXnetDevice` / `RZKNXnetDeviceOnAsset` | Asset → KNXnetDevice → Service | KNXnet device |
| `RZHasBACnetDevice` / `RZBACnetDeviceOnAsset` | Asset → BACnetDevice → Service | BACnet device |
| `RZHasNTPReference` / `RZNTPReferenceUsedBy` | Asset → NTPReference → Service | NTP sync |
| `RZHasDNSIdentity` / `RZDNSIdentityUsedBy` | Asset → DNSIdentity → Service | DNS identity |
| `RZHasDNSVersion` / `RZDNSVersionUsedBy` | Asset → DNSVersion → Service | DNS version |
| `RZHasSerialNumber` / `RZSerialNumberUsedBy` | Asset ↔ SerialNumber | Serial number |
| `RZHasNTLMDomain` / `RZNTLMDomainUsedBy` | Asset → NTLMDomain → Service | NTLM domain |
| `RZHasNTLMComputer` / `RZNTLMComputerUsedBy` | Asset → NTLMComputer → Service | NTLM computer |
| `RZNTLMPartOfDomain` / `RZNTLMDomainContains` | NTLMComputer ↔ NTLMDomain | Domain membership |

---

## 1 — Getting Started

Queries to verify your import and understand the shape of your data.

### Count all node types
`tags: inventory, basics`

```cypher
MATCH (n)
WITH labels(n) AS kind, count(n) AS total
RETURN kind, total
ORDER BY total DESC
```

### Count all edge types
`tags: inventory, basics`

```cypher
MATCH ()-[r]->()
WITH type(r) AS edge_type, count(r) AS total
RETURN edge_type, total
ORDER BY total DESC
```

### Verify the internet node exists
`tags: basics, topology`

```cypher
MATCH (n:RZNetwork)
WHERE n.network_address = '0.0.0.0'
RETURN n.displayname
```

---

## 2 — Simple Queries

Everyday queries for browsing assets, services, and network structure.

### Asset Inventory

#### List all assets sorted by risk
`tags: inventory, exposure`

```cypher
MATCH (a:RZAsset)
RETURN a.displayname, a.ip_addresses, a.os, a.risk
ORDER BY a.risk_rank DESC
LIMIT 50
```

#### Assets by device category (IT, OT, IoT)
`tags: inventory, classification`

```cypher
MATCH (a:RZAsset)
WHERE a.category IS NOT NULL
WITH a.category AS category, count(a) AS total
RETURN category, total
ORDER BY total DESC
```

#### Assets by operating system
`tags: inventory, classification`

```cypher
MATCH (a:RZAsset)
WHERE a.os IS NOT NULL
WITH a.os AS os, count(a) AS total
RETURN os, total
ORDER BY total DESC
LIMIT 20
```

#### Assets by hardware vendor
`tags: inventory, classification`

```cypher
MATCH (a:RZAsset)
WHERE a.hw IS NOT NULL
WITH a.hw AS hw, count(a) AS total
RETURN hw, total
ORDER BY total DESC
LIMIT 20
```

### Services & Ports

#### Top services across all assets
`tags: inventory, services`

```cypher
MATCH (svc:RZService)
WHERE svc.port IS NOT NULL
WITH svc.port + '/' + svc.transport AS port, count(svc) AS total
RETURN port, total
ORDER BY total DESC
LIMIT 20
```

#### Find all assets with a specific open port
`tags: inventory, services`

```cypher
MATCH (a:RZAsset)-[:RZHasService]->(svc:RZService)
WHERE svc.port = '445' AND svc.transport = 'tcp'
RETURN a.displayname, a.ip_addresses, a.os
LIMIT 50
```

### Network Topology

#### List subnets by host count
`tags: topology, inventory`

```cypher
MATCH (net:RZNetwork)
WHERE net.host_count > 0
RETURN net.displayname, net.host_count, net.version
ORDER BY net.host_count DESC
LIMIT 20
```

#### List all domains
`tags: topology, inventory`

```cypher
MATCH (d:RZDomain)
RETURN d.displayname, d.host_count
ORDER BY d.host_count DESC
```

#### Group assets by MAC vendor
`tags: inventory, classification`

```cypher
MATCH (a:RZAsset)-[:RZHasMAC]->(mac:RZMACAddress)-[:RZHasMACVendor]->(v:RZMACVendor)
WITH v, count(DISTINCT a) AS asset_count
RETURN v.vendor, v.country, asset_count
ORDER BY asset_count DESC
LIMIT 20
```

#### Find assets with virtual machine MACs
`tags: inventory, classification`

```cypher
MATCH (a:RZAsset)-[:RZHasMAC]->(mac:RZMACAddress)
WHERE mac.virtual_platform IS NOT NULL
RETURN a.displayname, mac.mac_address, mac.virtual_platform
```

---

## 3 — Intermediate Queries

Dig deeper into identity, fingerprinting, and protocol-specific relationships.

### Cryptographic Identity

#### SSH key reuse — assets sharing the same host key
`tags: exposure, identity, correlation`

```cypher
MATCH (a1:RZAsset)-[:RZHasSSHKey]->(key:RZSSHKey)<-[:RZHasSSHKey]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN key.fingerprint, key.key_type, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

#### Shared SSH keys ranked by reuse count
`tags: exposure, identity`

```cypher
MATCH (key:RZSSHKey)<-[:RZHasSSHKey]-(a:RZAsset)
WITH key, collect(a.displayname) AS hosts, count(a) AS cnt
WHERE cnt > 1
RETURN key.fingerprint, key.key_type, hosts, cnt
ORDER BY cnt DESC
LIMIT 20
```

#### TLS certificate reuse across assets
`tags: exposure, identity, correlation`

```cypher
MATCH (a1:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert)<-[:RZHasTLSCert]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN cert.cn, cert.sha1, a1.displayname, a2.displayname
LIMIT 20
```

#### Self-signed TLS certificates
`tags: exposure, identity`

```cypher
MATCH (cert:RZTLSCert)
WHERE cert.self_signed IS NOT NULL
RETURN cert.cn, cert.sha1, cert.issuer, cert.not_after
ORDER BY cert.not_after
LIMIT 20
```

#### Expired TLS certificates
`tags: exposure, compliance`

```cypher
MATCH (a:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert)
WHERE cert.not_after < datetime().epochMillis
RETURN a.displayname, cert.cn, cert.sha1, cert.not_after
LIMIT 20
```

#### TLS certificates by signing CA
`tags: dependency, identity`

```cypher
MATCH (ca:RZTLSCAChain)<-[:RZSignedByCA]-(a:RZAsset)
WITH ca, count(a) AS signed_count
RETURN ca.issuer, ca.ca_sha1, signed_count
ORDER BY signed_count DESC
LIMIT 20
```

#### Internal CAs (signing 10+ assets)
`tags: dependency, identity, infrastructure`

```cypher
MATCH (ca:RZTLSCAChain)<-[:RZSignedByCA]-(a:RZAsset)
WITH ca, count(a) AS cnt
WHERE cnt > 10
RETURN ca.issuer, ca.ca_sha1, cnt
ORDER BY cnt DESC
```

#### SMB GUID sharing across assets
`tags: identity, correlation`

```cypher
MATCH (a1:RZAsset)-[:RZHasSMBGUID]->(guid:RZSMBGUID)<-[:RZHasSMBGUID]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN guid.guid, a1.displayname, a2.displayname
LIMIT 20
```

#### SNMPv3 engine IDs by vendor
`tags: inventory, identity`

```cypher
MATCH (eid:RZSNMPEngineID)
WITH eid.vendor AS vendor, count(eid) AS total
RETURN vendor, total
ORDER BY total DESC
```

### OT / Building Automation

#### Gateways ranked by device count
`tags: inventory, ot, dependency`

```cypher
MATCH (gw:RZGateway)<-[:RZHasGateway]-(device:RZAsset)
WITH gw, count(device) AS device_count
RETURN gw.displayname, gw.protocol, gw.ip, device_count
ORDER BY device_count DESC
LIMIT 20
```

#### Devices behind a specific BACnet gateway
`tags: inventory, ot`

```cypher
MATCH (gw:RZGateway {protocol: "bacnet"})-[:RZHasGatewayAssets]->(device:RZAsset)
WHERE gw.ip = "68.162.161.186"
RETURN device.displayname, device.ip_addresses, device.os, device.hw
```

#### CIP / Modbus industrial controllers
`tags: inventory, ot, exposure`

```cypher
MATCH (gw:RZGateway)-[:RZHasGatewayAssets]->(device:RZAsset)
WHERE gw.protocol IN ["cip", "modbus"]
RETURN gw.protocol, gw.ip, device.displayname, device.type, device.hw
ORDER BY gw.protocol, gw.ip
```

#### BACnet devices by vendor
`tags: inventory, ot`

```cypher
MATCH (dev:RZBACnetDevice)
WITH dev.vendor_name AS vendor_name, dev.vendor_id AS vendor_id, count(dev) AS total
RETURN vendor_name, vendor_id, total
ORDER BY total DESC
```

#### BACnet devices with location metadata
`tags: inventory, ot`

```cypher
MATCH (a:RZAsset)-[:RZHasBACnetDevice]->(dev:RZBACnetDevice)
WHERE dev.location IS NOT NULL
RETURN dev.instance_id, dev.object_name, dev.location, dev.description, a.displayname
ORDER BY dev.location
LIMIT 30
```

#### KNXnet devices with their properties
`tags: inventory, ot`

```cypher
MATCH (a:RZAsset)-[:RZHasKNXnetDevice]->(dev:RZKNXnetDevice)
RETURN dev.serial, dev.name, dev.mac, dev.device_type, a.displayname
ORDER BY dev.name
LIMIT 50
```

#### SNMP device types ranked
`tags: inventory, classification`

```cypher
MATCH (oid:RZSNMPDeviceType)<-[:RZHasSNMPDeviceType]-(a:RZAsset)
WITH oid, count(a) AS device_count
RETURN oid.sys_object_id, oid.sys_descr, device_count
ORDER BY device_count DESC
LIMIT 20
```

### Infrastructure Fingerprinting

#### Favicons shared by the most assets (same web app)
`tags: inventory, fingerprinting, correlation`

```cypher
MATCH (fav:RZFavicon)<-[:RZHasFavicon]-(a:RZAsset)
WITH fav, collect(a.displayname) AS hosts, count(a) AS cnt
WHERE cnt > 1
RETURN fav.md5, fav.mmh3, fav.url, hosts, cnt
ORDER BY cnt DESC
LIMIT 20
```

#### IKE/VPN endpoints grouped by identity
`tags: inventory, identity, infrastructure`

```cypher
MATCH (ike:RZIKEIdentity)<-[:RZHasIKEIdentity]-(a:RZAsset)
WITH ike, collect(a.displayname) AS hosts, count(a) AS cnt
RETURN ike.sha1, ike.version, ike.exchange_type, hosts, cnt
ORDER BY cnt DESC
LIMIT 20
```

#### NTP reference clocks by client count
`tags: dependency, infrastructure`

```cypher
MATCH (ntp:RZNTPReference)<-[:RZHasNTPReference]-(a:RZAsset)
WITH ntp, count(a) AS client_count
RETURN ntp.reference_id, ntp.stratum, ntp.version, client_count
ORDER BY client_count DESC
LIMIT 20
```

#### DNS servers grouped by software version
`tags: inventory, infrastructure, exposure`

```cypher
MATCH (ver:RZDNSVersion)<-[:RZHasDNSVersion]-(a:RZAsset)
WITH ver, count(a) AS host_count
RETURN ver.version_bind, host_count
ORDER BY host_count DESC
LIMIT 20
```

#### DNS servers running outdated BIND
`tags: exposure, infrastructure`

```cypher
MATCH (a:RZAsset)-[:RZHasDNSVersion]->(ver:RZDNSVersion)
WHERE ver.version_bind CONTAINS "9.11" OR ver.version_bind CONTAINS "9.9"
RETURN a.displayname, ver.version_bind
ORDER BY ver.version_bind
LIMIT 20
```

#### Routers ranked by traceroute appearances (core infrastructure)
`tags: topology, dependency, infrastructure`

```cypher
MATCH (router:RZRouter)<-[:RZHasRouter]-(a:RZAsset)
WITH router, count(DISTINCT a) AS assets_routed
WHERE assets_routed > 100
RETURN router.displayname, router.ip_addresses, assets_routed
ORDER BY assets_routed DESC
```

#### Switches and their connected asset counts
`tags: topology, inventory`

```cypher
MATCH (sw:RZSwitch)-[:RZHasSwitchAssets]->(a:RZAsset)
WITH sw, count(a) AS connected_assets
RETURN sw.displayname, sw.ip, connected_assets
ORDER BY connected_assets DESC
```

### Windows / Active Directory

#### NTLM domains and their computers
`tags: inventory, identity, windows`

```cypher
MATCH (dom:RZNTLMDomain)<-[:RZNTLMPartOfDomain]-(comp:RZNTLMComputer)
WITH dom, collect(comp.dns_computer) AS computers, count(comp) AS total
RETURN dom.dns_domain, dom.netbios_domain, computers, total
ORDER BY total DESC
```

#### NTLM computers with domain and Windows version
`tags: inventory, identity, windows`

```cypher
MATCH (a:RZAsset)-[:RZHasNTLMComputer]->(comp:RZNTLMComputer)
OPTIONAL MATCH (comp)-[:RZNTLMPartOfDomain]->(dom:RZNTLMDomain)
RETURN comp.dns_computer, comp.version, comp.target_name,
       dom.dns_domain, a.displayname
ORDER BY dom.dns_domain, comp.dns_computer
```

#### Assets sharing the same NTLM domain (domain peers)
`tags: identity, correlation, windows`

```cypher
MATCH (a1:RZAsset)-[:RZHasNTLMDomain]->(dom:RZNTLMDomain)<-[:RZHasNTLMDomain]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN dom.dns_domain, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

#### IPMI services with cipher zero enabled
`tags: exposure, identity`

```cypher
MATCH (a:RZAsset)-[:RZHasIPMICredential]->(ipmi:RZIPMICredential)
WHERE ipmi.cipher_zero = "enabled"
RETURN a.displayname, a.ip_addresses, ipmi.conn_versions, ipmi.user_auth
```

---

## 4 — Advanced Queries

Cross-protocol correlation, multi-hop traversals, and risk analysis.

### Cross-Source Correlation

#### SSH key reuse across different subnets
`tags: correlation, exposure, topology`

```cypher
MATCH (a1:RZAsset)-[:RZHasSSHKey]->(key:RZSSHKey)<-[:RZHasSSHKey]-(a2:RZAsset),
      (a1)-[:RZInsideOfSubnet]->(n1:RZNetwork),
      (a2)-[:RZInsideOfSubnet]->(n2:RZNetwork)
WHERE n1 <> n2 AND id(a1) < id(a2)
RETURN key.fingerprint, a1.displayname, n1.displayname, a2.displayname, n2.displayname
LIMIT 10
```

#### TLS cert reuse across subnets
`tags: correlation, identity, topology`

```cypher
MATCH (a:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH cert, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE size(subnets) > 1
RETURN cert.cn, cert.sha1, subnets, hosts
ORDER BY hosts DESC
LIMIT 10
```

#### CA chains spanning multiple subnets
`tags: dependency, identity, topology`

```cypher
MATCH (a:RZAsset)-[:RZSignedByCA]->(ca:RZTLSCAChain),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH ca, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE size(subnets) > 1
RETURN ca.issuer, ca.ca_sha1, subnets, hosts
ORDER BY hosts DESC
LIMIT 10
```

#### Serial numbers shared across subnets (same device, multiple paths)
`tags: correlation, identity, topology`

```cypher
MATCH (a:RZAsset)-[:RZHasSerialNumber]->(sn:RZSerialNumber),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH sn, collect(DISTINCT net.displayname) AS subnets, collect(DISTINCT a.displayname) AS hosts
WHERE size(subnets) > 1
RETURN sn.serial_number, sn.source, subnets, hosts
ORDER BY size(subnets) DESC
LIMIT 10
```

#### KNXnet devices visible through multiple gateways
`tags: correlation, ot`

```cypher
MATCH (a1:RZAsset)-[:RZHasKNXnetDevice]->(dev:RZKNXnetDevice)<-[:RZHasKNXnetDevice]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN dev.serial, dev.name, dev.mac, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

#### BACnet devices visible through multiple gateways
`tags: correlation, ot`

```cypher
MATCH (a1:RZAsset)-[:RZHasBACnetDevice]->(dev:RZBACnetDevice)<-[:RZHasBACnetDevice]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN dev.instance_id, dev.object_name, dev.vendor_name,
       a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### Exposure & Risk

#### NTLM-enabled services spanning multiple subnets (lateral movement)
`tags: exposure, identity, topology, windows`

```cypher
MATCH (a:RZAsset)-[:RZHasNTLMDomain]->(dom:RZNTLMDomain),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH dom, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE size(subnets) > 1
RETURN dom.dns_domain, subnets, hosts
ORDER BY hosts DESC
```

#### VPN concentrators (IKE identities shared by many assets)
`tags: exposure, infrastructure, dependency`

```cypher
MATCH (ike:RZIKEIdentity)<-[:RZHasIKEIdentity]-(a:RZAsset)
WITH ike, count(a) AS cnt
WHERE cnt > 5
RETURN ike.sha1, ike.version, cnt
ORDER BY cnt DESC
```

#### Gateway controllers with SSH or TLS services (management interfaces)
`tags: exposure, ot, identity`

```cypher
MATCH (gw:RZGateway)<-[:RZHasGateway]-(a:RZAsset)
WHERE (a)-[:RZHasSSHKey]->() OR (a)-[:RZHasTLSCert]->()
WITH DISTINCT a, gw
OPTIONAL MATCH (a)-[:RZHasSSHKey]->(key:RZSSHKey)
OPTIONAL MATCH (a)-[:RZHasTLSCert]->(cert:RZTLSCert)
RETURN a.displayname, gw.protocol, key.fingerprint, cert.cn
LIMIT 20
```

#### MikroTik devices (by SNMP OID)
`tags: inventory, exposure, infrastructure`

```cypher
MATCH (a:RZAsset)-[:RZHasSNMPDeviceType]->(oid:RZSNMPDeviceType)
WHERE oid.sys_object_id STARTS WITH ".1.3.6.1.4.1.14988"
RETURN a.displayname, oid.sys_object_id, oid.sys_name
ORDER BY a.displayname
```

### Dependency Mapping

#### Assets using the same NTP infrastructure by subnet
`tags: dependency, infrastructure, topology`

```cypher
MATCH (a:RZAsset)-[:RZHasNTPReference]->(ntp:RZNTPReference),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH ntp, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE hosts > 5
RETURN ntp.reference_id, ntp.stratum, subnets, hosts
ORDER BY hosts DESC
LIMIT 10
```

#### DNS server clustering (shared CHAOS identity)
`tags: dependency, infrastructure, correlation`

```cypher
MATCH (a1:RZAsset)-[:RZHasDNSIdentity]->(dns:RZDNSIdentity)<-[:RZHasDNSIdentity]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN dns.server_id, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

#### SNMP devices with both engine ID and device type (enriched view)
`tags: inventory, identity, infrastructure`

```cypher
MATCH (a:RZAsset)-[:RZHasSNMPDeviceType]->(oid:RZSNMPDeviceType),
      (a)-[:RZHasSNMPEngineID]->(eid:RZSNMPEngineID)
RETURN a.displayname, oid.sys_object_id, oid.sys_name, eid.engine_id, eid.vendor
ORDER BY oid.sys_object_id
LIMIT 20
```

#### Switch port → asset → service mapping
`tags: topology, dependency`

```cypher
MATCH (sw:RZSwitch)-[:RZHasSwitchPort]->(port:RZSwitchPort)<-[:RZConnectedToPort]-(a:RZAsset)
RETURN sw.displayname, port.port, a.displayname, a.ip_addresses
ORDER BY sw.displayname, port.port
```

---

## 5 — Expert Queries

Multi-pattern joins, aggregations, and full graph traversals for deep analysis.

### Relationship richness per asset
`tags: inventory, correlation`

```cypher
MATCH (a:RZAsset)
OPTIONAL MATCH (a)-[:RZHasSSHKey]->(ssh:RZSSHKey)
OPTIONAL MATCH (a)-[:RZHasTLSCert]->(tls:RZTLSCert)
OPTIONAL MATCH (a)-[:RZHasGateway]->(gw:RZGateway)
OPTIONAL MATCH (a)-[:RZHasMAC]->(mac:RZMACAddress)
OPTIONAL MATCH (a)-[:RZHasFavicon]->(fav:RZFavicon)
OPTIONAL MATCH (a)-[:RZHasIKEIdentity]->(ike:RZIKEIdentity)
OPTIONAL MATCH (a)-[:RZHasBACnetDevice]->(bac:RZBACnetDevice)
OPTIONAL MATCH (a)-[:RZHasKNXnetDevice]->(knx:RZKNXnetDevice)
OPTIONAL MATCH (a)-[:RZHasSerialNumber]->(sn:RZSerialNumber)
WITH a,
     count(DISTINCT ssh) AS ssh_keys,
     count(DISTINCT tls) AS tls_certs,
     count(DISTINCT gw)  AS gateways,
     count(DISTINCT mac)  AS macs,
     count(DISTINCT fav)  AS favicons,
     count(DISTINCT ike)  AS ike_ids,
     count(DISTINCT bac)  AS bacnet_devs,
     count(DISTINCT knx)  AS knxnet_devs,
     count(DISTINCT sn)   AS serials
WHERE ssh_keys + tls_certs + gateways + macs + favicons + ike_ids + bacnet_devs + knxnet_devs + serials > 0
RETURN a.displayname, ssh_keys, tls_certs, gateways, macs, favicons,
       ike_ids, bacnet_devs, knxnet_devs, serials
ORDER BY ssh_keys + tls_certs + gateways + macs + favicons + ike_ids
         + bacnet_devs + knxnet_devs + serials DESC
LIMIT 20
```

### OT devices with both BACnet identity and gateway — full enrichment
`tags: ot, dependency, identity`

```cypher
MATCH (a:RZAsset)-[:RZHasBACnetDevice]->(dev:RZBACnetDevice),
      (a)-[:RZHasGateway]->(gw:RZGateway)
OPTIONAL MATCH (a)-[:RZHasSerialNumber]->(sn:RZSerialNumber)
RETURN gw.displayname AS gateway, dev.instance_id, dev.object_name,
       dev.vendor_name, dev.firmware_revision, sn.serial_number, a.displayname
ORDER BY gw.displayname
LIMIT 30
```

### Find the full path: CA → cert → asset → subnet → internet
`tags: dependency, topology, identity`

```cypher
MATCH (ca:RZTLSCAChain)<-[:RZSignedByCA]-(a:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH ca.issuer AS ca_issuer, cert.cn AS cert_cn,
     a.displayname AS asset, net.displayname AS subnet,
     count(*) AS cnt
RETURN ca_issuer, cert_cn, asset, subnet
ORDER BY ca_issuer, subnet
LIMIT 30
```

### Self-signed vs CA-signed breakdown
`tags: exposure, identity, compliance`

```cypher
MATCH (a:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert)
OPTIONAL MATCH (a)-[:RZSignedByCA]->(ca:RZTLSCAChain)
RETURN cert.self_signed IS NOT NULL AS is_self_signed,
       ca IS NOT NULL AS has_ca,
       count(DISTINCT a) AS asset_count
```

### Traceroute: core routers handling the most diverse subnets
`tags: topology, dependency, infrastructure`

```cypher
MATCH (router:RZRouter)<-[:RZHasRouter]-(a:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH router, count(DISTINCT a) AS assets, count(DISTINCT net) AS subnets
WHERE subnets > 3
RETURN router.displayname, router.ip_addresses, assets, subnets
ORDER BY subnets DESC
LIMIT 15
```

### Combined VPN + TLS identity overlap
`tags: exposure, identity, correlation`

```cypher
MATCH (a:RZAsset)-[:RZHasIKEIdentity]->(ike:RZIKEIdentity),
      (a)-[:RZHasTLSCert]->(cert:RZTLSCert)
RETURN a.displayname, ike.sha1, cert.cn, cert.issuer
LIMIT 20
```

### Serial numbers by source protocol — inventory health
`tags: inventory, identity`

```cypher
MATCH (sn:RZSerialNumber)<-[:RZHasSerialNumber]-(a:RZAsset)
WITH sn.source AS source, count(DISTINCT sn) AS serial_count, count(DISTINCT a) AS asset_count
RETURN source, serial_count, asset_count
ORDER BY serial_count DESC
```

---

## 6 — Quirky & Surprising

Unexpected patterns, edge cases, and fun things to look for in your data.

### Gateways with 50+ devices — "entire buildings on one IP"
`tags: ot, exposure, fun`

```cypher
MATCH (gw:RZGateway)-[:RZHasGatewayAssets]->(device:RZAsset)
WITH gw, count(device) AS cnt
WHERE cnt > 50
RETURN gw.displayname, gw.protocol, gw.ip, cnt
ORDER BY cnt DESC
```

### Favicon collisions — different IPs serving the same web UI
`tags: fingerprinting, correlation, fun`

```cypher
MATCH (fav:RZFavicon)<-[:RZHasFavicon]-(a:RZAsset)
WITH fav, count(a) AS cnt, collect(a.displayname)[..5] AS samples
WHERE cnt > 10
RETURN fav.mmh3, fav.md5, cnt, samples
ORDER BY cnt DESC
LIMIT 10
```

### The loneliest subnets — networks with exactly one host
`tags: topology, fun`

```cypher
MATCH (net:RZNetwork)
WHERE net.host_count = 1
RETURN net.displayname, net.version
ORDER BY net.displayname
LIMIT 20
```

### BACnet device names that reveal physical locations
`tags: ot, fun`

```cypher
MATCH (dev:RZBACnetDevice)
WHERE dev.object_name IS NOT NULL
RETURN dev.object_name, dev.location, dev.vendor_name
ORDER BY dev.object_name
LIMIT 30
```

### KNXnet devices all using the default serial "010203040506"
`tags: ot, exposure, fun`

```cypher
MATCH (dev:RZKNXnetDevice)<-[:RZHasKNXnetDevice]-(a:RZAsset)
WHERE dev.serial = "010203040506"
RETURN a.displayname, dev.name, dev.mac
LIMIT 20
```

### NTLM computer name reuse (same name, different assets)
`tags: identity, exposure, fun`

```cypher
MATCH (a1:RZAsset)-[:RZHasNTLMComputer]->(comp:RZNTLMComputer)<-[:RZHasNTLMComputer]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN comp.dns_computer, comp.version, a1.displayname, a2.displayname
LIMIT 20
```

### Router hop chains — visualise path topology
`tags: topology, fun`

```cypher
MATCH (r1:RZRouter)-[:RZHasRouter]->(r2:RZRouter)
WHERE r1.ttl < r2.ttl
RETURN r1.displayname AS hop1, r1.ttl AS ttl1, r2.displayname AS hop2, r2.ttl AS ttl2
LIMIT 20
```

### The "most connected" asset — highest total relationship count
`tags: inventory, fun`

```cypher
MATCH (a:RZAsset)-[r]-()
WITH a, count(r) AS rels
RETURN a.displayname, a.ip_addresses, rels
ORDER BY rels DESC
LIMIT 10
```

### NTP stratum-1 sources — who's syncing to GPS/atomic clocks?
`tags: infrastructure, dependency, fun`

```cypher
MATCH (ntp:RZNTPReference)<-[:RZHasNTPReference]-(a:RZAsset)
WHERE ntp.stratum = "1"
WITH ntp, count(a) AS clients
RETURN ntp.reference_id, clients
ORDER BY clients DESC
LIMIT 10
```
