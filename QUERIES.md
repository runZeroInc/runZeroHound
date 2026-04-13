# runZeroHound Cypher Query Reference

This document provides example Cypher queries for exploring the graph data
produced by `runZeroHound convert`. The queries are written for BloodHound CE
(Neo4j-backed) and use the node kinds and edge types emitted by the converter.

## Node Kinds

| Kind | Description |
|------|-------------|
| `RZAsset` | A runZero-discovered network asset |
| `RZService` | A network service running on an asset |
| `RZNetwork` | An IP subnet (aggregated to /24 IPv4, /56 IPv6) |
| `RZDomain` | A DNS domain |
| `RZVLAN` | A VLAN ID |
| `RZGateway` | A BACnet / CIP / Modbus / KNXnet gateway controller |
| `RZSSHKey` | An SSH host key fingerprint |
| `RZTLSCert` | A TLS certificate (identified by SHA-1 fingerprint) |
| `RZSNMPEngineID` | An SNMPv3 Engine ID |
| `RZIPMICredential` | An IPMI service credential/configuration |
| `RZRouter` | A layer-3 router hop from traceroute |
| `RZMACAddress` | A MAC address with vendor metadata |
| `RZMACVendor` | A MAC OUI vendor (e.g. "Cisco Systems") |
| `RZSwitch` | A layer-2 switch (from SNMP switch data) |
| `RZSwitchPort` | A physical switch port |
| `RZSubAsset` | A sub-asset discovered via SNMP ARP/MAC tables |
| `RZFavicon` | A web favicon fingerprint (MD5 + MurmurHash3) |
| `RZIKEIdentity` | An IKE/IPsec VPN identity fingerprint |
| `RZKNXnetDevice` | A KNXnet/IP building automation device (by serial) |
| `RZBACnetDevice` | A BACnet building automation device (by instance ID) |
| `RZNTPReference` | An NTP reference clock / upstream time source |
| `RZDNSIdentity` | A DNS server identity (CHAOS TXT id.server) |
| `RZDNSVersion` | A DNS software version (CHAOS TXT version.bind) |
| `RZSNMPDeviceType` | An SNMP device type (sysObjectID grouping) |
| `RZTLSCAChain` | A TLS signing CA (by CA certificate SHA-1) |
| `RZSerialNumber` | A device serial number (cross-protocol) |
| `RZNTLMDomain` | An NTLM SSP domain identity (dnsDomain) |
| `RZNTLMComputer` | An NTLM SSP computer identity (dnsComputer) |

## Edge Kinds

| Edge | Direction | Description |
|------|-----------|-------------|
| `RZHasService` | Asset → Service | Asset exposes this service |
| `RZRunsOnAsset` | Service → Asset | Service runs on this asset |
| `RZInsideOfSubnet` | Asset → Network | Asset belongs to this subnet |
| `RZSubnetContains` | Network → Asset | Subnet contains this asset |
| `RZPartOfDomain` | Asset → Domain | Asset is part of this domain |
| `RZDomainContains` | Domain → Asset | Domain contains this asset |
| `RZPartOfVLAN` | Asset → VLAN | Asset belongs to this VLAN |
| `RZVLANContains` | VLAN → Asset | VLAN contains this asset |
| `RZHasGateway` | Asset → Gateway | Device is behind this gateway |
| `RZHasGatewayAssets` | Gateway → Asset | Gateway controls this device |
| `RZHasSSHKey` | Asset → SSHKey | Asset presents this SSH key |
| `RZHasSSHService` | SSHKey → Service | SSH key is served by this service |
| `RZHasTLSCert` | Asset → TLSCert | Asset presents this TLS certificate |
| `RZHasTLSService` | TLSCert → Service | TLS cert is served by this service |
| `RZHasSNMPEngineID` | Asset → SNMPEngineID | Asset has this SNMP engine |
| `RZHasSNMPService` | SNMPEngineID → Service | Engine belongs to this service |
| `RZHasIPMICredential` | Asset → IPMICredential | Asset has IPMI with these settings |
| `RZHasIPMIService` | IPMICredential → Service | IPMI credential is on this service |
| `RZHasRouter` | Asset ↔ Router | Asset has this traceroute hop (bidirectional) |
| `RZHasMAC` | Asset → MACAddress | Asset has this MAC address |
| `RZHasMACHost` | MACAddress → Asset | MAC address belongs to this asset |
| `RZHasMACVendor` | MACAddress → MACVendor | MAC is registered to this vendor |
| `RZHasSwitch` | Asset → Switch | Asset is connected to this switch |
| `RZHasSwitchAssets` | Switch → Asset | Switch has this asset connected |
| `RZHasSwitchPort` | Switch → SwitchPort | Switch has this port |
| `RZConnectedToPort` | Asset → SwitchPort | Asset is physically connected to port |
| `RZHasFavicon` | Asset → Favicon | Asset serves this favicon |
| `RZFaviconUsedBy` | Favicon → Service | Favicon is served by this service |
| `RZHasIKEIdentity` | Asset → IKEIdentity | Asset has this IKE/VPN fingerprint |
| `RZIKEIdentityUsedBy` | IKEIdentity → Service | IKE identity belongs to this service |
| `RZHasKNXnetDevice` | Asset → KNXnetDevice | Asset exposes this KNXnet device |
| `RZKNXnetDeviceOnAsset` | KNXnetDevice → Service | KNXnet device is on this service |
| `RZHasBACnetDevice` | Asset → BACnetDevice | Asset exposes this BACnet device |
| `RZBACnetDeviceOnAsset` | BACnetDevice → Service | BACnet device is on this service |
| `RZHasNTPReference` | Asset → NTPReference | Asset syncs to this NTP reference |
| `RZNTPReferenceUsedBy` | NTPReference → Service | NTP reference is used by this service |
| `RZHasDNSIdentity` | Asset → DNSIdentity | Asset has this DNS server identity |
| `RZDNSIdentityUsedBy` | DNSIdentity → Service | DNS identity belongs to this service |
| `RZHasDNSVersion` | Asset → DNSVersion | Asset runs this DNS software version |
| `RZDNSVersionUsedBy` | DNSVersion → Service | DNS version is on this service |
| `RZHasSNMPDeviceType` | Asset → SNMPDeviceType | Asset is this SNMP device type |
| `RZSNMPDeviceTypeUsedBy` | SNMPDeviceType → Service | SNMP device type belongs to service |
| `RZSignedByCA` | Asset → TLSCAChain | Asset's TLS cert is signed by this CA |
| `RZCASignedCert` | TLSCAChain → Service | CA signed this service's certificate |
| `RZHasSerialNumber` | Asset → SerialNumber | Asset has this serial number |
| `RZSerialNumberUsedBy` | SerialNumber → Asset | Serial number belongs to this asset |
| `RZHasNTLMDomain` | Asset → NTLMDomain | Asset advertises this NTLM domain |
| `RZNTLMDomainUsedBy` | NTLMDomain → Service | NTLM domain is on this service |
| `RZHasNTLMComputer` | Asset → NTLMComputer | Asset has this NTLM computer identity |
| `RZNTLMComputerUsedBy` | NTLMComputer → Service | NTLM computer is on this service |
| `RZNTLMPartOfDomain` | NTLMComputer → NTLMDomain | Computer belongs to this NTLM domain |
| `RZNTLMDomainContains` | NTLMDomain → NTLMComputer | Domain contains this computer |

---

## Basic Exploration

### Count all node types

```cypher
MATCH (n)
RETURN labels(n) AS kind, count(n) AS total
ORDER BY total DESC
```

### Count all edge types

```cypher
MATCH ()-[r]->()
RETURN type(r) AS edge_type, count(r) AS total
ORDER BY total DESC
```

### List all assets

```cypher
MATCH (a:RZAsset)
RETURN a.displayname, a.ip_addresses, a.os, a.risk
ORDER BY a.risk_rank DESC
LIMIT 50
```

---

## Gateway Queries (BACnet, CIP, Modbus, KNXnet)

### Find all gateways and the number of devices behind them

```cypher
MATCH (gw:RZGateway)<-[:RZHasGateway]-(device:RZAsset)
RETURN gw.displayname AS gateway, gw.protocol, gw.ip, count(device) AS device_count
ORDER BY device_count DESC
LIMIT 20
```

### Find all devices behind a specific BACnet gateway

```cypher
MATCH (gw:RZGateway {protocol: "bacnet"})-[:RZHasGatewayAssets]->(device:RZAsset)
WHERE gw.ip = "68.162.161.186"
RETURN device.displayname, device.ip_addresses, device.os, device.hw
```

### Find gateways with the most devices (potential high-value targets)

```cypher
MATCH (gw:RZGateway)-[:RZHasGatewayAssets]->(device:RZAsset)
WITH gw, count(device) AS cnt
WHERE cnt > 10
RETURN gw.displayname, gw.protocol, gw.ip, cnt
ORDER BY cnt DESC
```

### Find CIP/Modbus industrial controllers

```cypher
MATCH (gw:RZGateway)-[:RZHasGatewayAssets]->(device:RZAsset)
WHERE gw.protocol IN ["cip", "modbus"]
RETURN gw.protocol, gw.ip, device.displayname, device.type, device.hw
ORDER BY gw.protocol, gw.ip
```

---

## SSH Host Key Queries

### Find assets sharing the same SSH host key (key reuse)

```cypher
MATCH (a1:RZAsset)-[:RZHasSSHKey]->(key:RZSSHKey)<-[:RZHasSSHKey]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN key.fingerprint, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List all SSH keys with multiple hosts (shared keys)

```cypher
MATCH (key:RZSSHKey)<-[:RZHasSSHKey]-(a:RZAsset)
WITH key, collect(a.displayname) AS hosts, count(a) AS host_count
WHERE host_count > 1
RETURN key.fingerprint, key.key_type, hosts, host_count
ORDER BY host_count DESC
LIMIT 20
```

### Find the SSH service behind a specific key

```cypher
MATCH (key:RZSSHKey)-[:RZHasSSHService]->(svc:RZService)
WHERE key.fingerprint STARTS WITH "EAUadxjr"
RETURN key.fingerprint, svc.displayname, svc.address, svc.port
```

---

## TLS Certificate Queries

### Find assets sharing the same TLS certificate

```cypher
MATCH (a1:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert)<-[:RZHasTLSCert]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN cert.cn, cert.sha1, a1.displayname, a2.displayname
LIMIT 20
```

### Find self-signed TLS certificates

```cypher
MATCH (cert:RZTLSCert)
WHERE cert.self_signed IS NOT NULL
RETURN cert.cn, cert.sha1, cert.issuer, cert.not_after
ORDER BY cert.not_after
LIMIT 20
```

### Find expired TLS certificates

```cypher
MATCH (a:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert)
WHERE cert.not_after < datetime().epochMillis
RETURN a.displayname, cert.cn, cert.sha1, cert.not_after
LIMIT 20
```

### TLS certificate reuse across subnets

```cypher
MATCH (a:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH cert, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE size(subnets) > 1
RETURN cert.cn, cert.sha1, subnets, hosts
ORDER BY hosts DESC
LIMIT 10
```

---

## SNMP v3 Engine ID Queries

### Find all SNMPv3 engine IDs and their hosts

```cypher
MATCH (a:RZAsset)-[:RZHasSNMPEngineID]->(eid:RZSNMPEngineID)
RETURN eid.engine_id, eid.vendor, a.displayname, a.ip_addresses
ORDER BY eid.vendor
```

### Find assets sharing the same SNMP engine ID

```cypher
MATCH (a1:RZAsset)-[:RZHasSNMPEngineID]->(eid:RZSNMPEngineID)<-[:RZHasSNMPEngineID]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN eid.engine_id, eid.vendor, a1.displayname, a2.displayname
```

### Group SNMP engines by vendor

```cypher
MATCH (eid:RZSNMPEngineID)
RETURN eid.vendor, count(eid) AS count
ORDER BY count DESC
```

---

## IPMI Queries

### Find all IPMI services with cipher zero enabled (critical risk)

```cypher
MATCH (a:RZAsset)-[:RZHasIPMICredential]->(ipmi:RZIPMICredential)
WHERE ipmi.cipher_zero = "enabled"
RETURN a.displayname, a.ip_addresses, ipmi.conn_versions, ipmi.user_auth
ORDER BY a.displayname
```

### Find all IPMI services

```cypher
MATCH (a:RZAsset)-[:RZHasIPMICredential]->(ipmi:RZIPMICredential)-[:RZHasIPMIService]->(svc:RZService)
RETURN a.displayname, svc.address, svc.port, ipmi.cipher_zero, ipmi.user_auth
```

---

## Traceroute / Router Queries

### Find all routers and the assets they route to

```cypher
MATCH (router:RZRouter)<-[:RZHasRouter]-(a:RZAsset)
RETURN router.displayname, router.ttl, count(a) AS asset_count
ORDER BY asset_count DESC
LIMIT 20
```

### Trace the path from an asset to the internet

```cypher
MATCH path = (a:RZAsset)-[:RZHasRouter*1..10]->(router:RZRouter)
WHERE a.displayname CONTAINS "10.0.0"
RETURN [n IN nodes(path) | n.displayname] AS hop_path
LIMIT 5
```

### Find routers that appear in many traceroutes (core infrastructure)

```cypher
MATCH (router:RZRouter)<-[:RZHasRouter]-(a:RZAsset)
WITH router, count(DISTINCT a) AS assets_routed
WHERE assets_routed > 100
RETURN router.displayname, router.ip_addresses, assets_routed
ORDER BY assets_routed DESC
```

### Find router chains (hop-to-hop topology)

```cypher
MATCH (r1:RZRouter)-[:RZHasRouter]->(r2:RZRouter)
WHERE r1.ttl < r2.ttl
RETURN r1.displayname AS hop1, r1.ttl AS ttl1, r2.displayname AS hop2, r2.ttl AS ttl2
LIMIT 20
```

---

## MAC Address & Vendor Queries

### Find all MAC addresses and their vendors

```cypher
MATCH (mac:RZMACAddress)-[:RZHasMACVendor]->(vendor:RZMACVendor)
RETURN mac.mac_address, vendor.vendor, vendor.country
ORDER BY vendor.vendor
LIMIT 50
```

### Group assets by MAC vendor

```cypher
MATCH (a:RZAsset)-[:RZHasMAC]->(mac:RZMACAddress)-[:RZHasMACVendor]->(v:RZMACVendor)
RETURN v.vendor, v.country, count(DISTINCT a) AS asset_count
ORDER BY asset_count DESC
LIMIT 20
```

### Find assets with virtual machine MAC addresses

```cypher
MATCH (a:RZAsset)-[:RZHasMAC]->(mac:RZMACAddress)
WHERE mac.virtual_platform IS NOT NULL
RETURN a.displayname, mac.mac_address, mac.virtual_platform
```

### Find all MAC vendors and when they were registered

```cypher
MATCH (v:RZMACVendor)
RETURN v.vendor, v.country, v.added
ORDER BY v.added DESC
LIMIT 20
```

---

## Switch / Layer-2 Queries

### Find all switches and their connected assets

```cypher
MATCH (sw:RZSwitch)-[:RZHasSwitchAssets]->(a:RZAsset)
RETURN sw.displayname, sw.ip, count(a) AS connected_assets
ORDER BY connected_assets DESC
```

### Find assets connected to a specific switch

```cypher
MATCH (sw:RZSwitch)-[:RZHasSwitchAssets]->(a:RZAsset)
WHERE sw.name = "M4300-OFFICE"
RETURN a.displayname, a.ip_addresses, a.mac_addresses
```

### Find switch ports and what's connected

```cypher
MATCH (sw:RZSwitch)-[:RZHasSwitchPort]->(port:RZSwitchPort)<-[:RZConnectedToPort]-(a:RZAsset)
RETURN sw.displayname, port.port, a.displayname, a.ip_addresses
ORDER BY sw.displayname, port.port
```

---

## Cross-Source Correlation

### Find assets linked by shared SSH key across different subnets

```cypher
MATCH (a1:RZAsset)-[:RZHasSSHKey]->(key:RZSSHKey)<-[:RZHasSSHKey]-(a2:RZAsset),
      (a1)-[:RZInsideOfSubnet]->(n1:RZNetwork),
      (a2)-[:RZInsideOfSubnet]->(n2:RZNetwork)
WHERE n1 <> n2 AND id(a1) < id(a2)
RETURN key.fingerprint, a1.displayname, n1.displayname, a2.displayname, n2.displayname
LIMIT 10
```

### Find assets linked by shared TLS cert AND same subnet

```cypher
MATCH (a1:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert)<-[:RZHasTLSCert]-(a2:RZAsset),
      (a1)-[:RZInsideOfSubnet]->(net:RZNetwork)<-[:RZInsideOfSubnet]-(a2)
WHERE id(a1) < id(a2)
RETURN cert.cn, net.displayname, a1.displayname, a2.displayname
LIMIT 10
```

### Find gateway controllers that also have SSH/TLS services

```cypher
MATCH (gw:RZGateway)<-[:RZHasGateway]-(a:RZAsset)
WHERE (a)-[:RZHasSSHKey]->() OR (a)-[:RZHasTLSCert]->()
WITH DISTINCT a, gw
OPTIONAL MATCH (a)-[:RZHasSSHKey]->(key:RZSSHKey)
OPTIONAL MATCH (a)-[:RZHasTLSCert]->(cert:RZTLSCert)
RETURN a.displayname, gw.protocol, key.fingerprint, cert.cn
LIMIT 20
```

---

## Risk & Security Queries

### High-risk assets with exposed IPMI (cipher zero)

```cypher
MATCH (a:RZAsset)-[:RZHasIPMICredential]->(ipmi:RZIPMICredential)
WHERE ipmi.cipher_zero = "enabled"
RETURN a.displayname, a.ip_addresses, a.risk, a.os
```

### Assets behind industrial gateways that are internet-exposed

```cypher
MATCH (a:RZAsset)-[:RZHasGateway]->(gw:RZGateway),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZInsideOfSubnet]->(pub:RZNetwork {displayname: "Global Internet"})
RETURN gw.protocol, gw.ip, a.displayname, net.displayname
ORDER BY gw.protocol
```

---

## Favicon Queries (Web App Fingerprinting)

### Find assets sharing the same favicon (same web application)

```cypher
MATCH (a1:RZAsset)-[:RZHasFavicon]->(fav:RZFavicon)<-[:RZHasFavicon]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN fav.md5, fav.mmh3, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List favicons shared by the most assets (common web apps/appliances)

```cypher
MATCH (fav:RZFavicon)<-[:RZHasFavicon]-(a:RZAsset)
WITH fav, collect(a.displayname) AS hosts, count(a) AS host_count
WHERE host_count > 1
RETURN fav.md5, fav.mmh3, fav.url, hosts, host_count
ORDER BY host_count DESC
LIMIT 20
```

### Find assets with Shodan-searchable favicon hashes

```cypher
MATCH (a:RZAsset)-[:RZHasFavicon]->(fav:RZFavicon)
WHERE fav.mmh3 IS NOT NULL
RETURN fav.mmh3, fav.md5, collect(DISTINCT a.displayname) AS hosts, count(a) AS count
ORDER BY count DESC
LIMIT 20
```

---

## IKE / VPN Identity Queries

### Find assets sharing the same IKE/VPN fingerprint (VPN clusters)

```cypher
MATCH (a1:RZAsset)-[:RZHasIKEIdentity]->(ike:RZIKEIdentity)<-[:RZHasIKEIdentity]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN ike.sha1, ike.version, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List all IKE/VPN endpoints grouped by identity

```cypher
MATCH (ike:RZIKEIdentity)<-[:RZHasIKEIdentity]-(a:RZAsset)
WITH ike, collect(a.displayname) AS hosts, count(a) AS host_count
RETURN ike.sha1, ike.version, ike.exchange_type, hosts, host_count
ORDER BY host_count DESC
LIMIT 20
```

### Find VPN concentrators (IKE identities shared by many assets)

```cypher
MATCH (ike:RZIKEIdentity)<-[:RZHasIKEIdentity]-(a:RZAsset)
WITH ike, count(a) AS cnt
WHERE cnt > 5
RETURN ike.sha1, ike.version, cnt
ORDER BY cnt DESC
```

---

## KNXnet Device Queries (Building Automation)

### Find KNXnet devices shared across multiple gateways

```cypher
MATCH (a1:RZAsset)-[:RZHasKNXnetDevice]->(dev:RZKNXnetDevice)<-[:RZHasKNXnetDevice]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN dev.serial, dev.name, dev.mac, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List all KNXnet devices with their properties

```cypher
MATCH (a:RZAsset)-[:RZHasKNXnetDevice]->(dev:RZKNXnetDevice)
RETURN dev.serial, dev.name, dev.mac, dev.device_type, a.displayname
ORDER BY dev.name
LIMIT 50
```

### Find KNXnet devices also behind a gateway (enriched view)

```cypher
MATCH (a:RZAsset)-[:RZHasKNXnetDevice]->(dev:RZKNXnetDevice),
      (a)-[:RZHasGateway]->(gw:RZGateway)
WHERE gw.protocol = "knxnet"
RETURN gw.displayname AS gateway, dev.serial, dev.name, dev.mac, a.displayname
ORDER BY gw.displayname
LIMIT 30
```

---

## BACnet Device Queries (Building Automation)

### Find BACnet devices shared across multiple gateways

```cypher
MATCH (a1:RZAsset)-[:RZHasBACnetDevice]->(dev:RZBACnetDevice)<-[:RZHasBACnetDevice]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN dev.instance_id, dev.object_name, dev.vendor_name,
       a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List all BACnet devices by vendor

```cypher
MATCH (dev:RZBACnetDevice)
RETURN dev.vendor_name, dev.vendor_id, count(dev) AS count
ORDER BY count DESC
```

### Find BACnet devices with firmware/model info

```cypher
MATCH (a:RZAsset)-[:RZHasBACnetDevice]->(dev:RZBACnetDevice)
RETURN dev.instance_id, dev.object_name, dev.model_name,
       dev.firmware_revision, dev.vendor_name, a.displayname
ORDER BY dev.vendor_name, dev.model_name
LIMIT 50
```

### Find BACnet devices with location metadata

```cypher
MATCH (a:RZAsset)-[:RZHasBACnetDevice]->(dev:RZBACnetDevice)
WHERE dev.location IS NOT NULL
RETURN dev.instance_id, dev.object_name, dev.location, dev.description, a.displayname
ORDER BY dev.location
LIMIT 30
```

---

## NTP Reference Clock Queries

### Find assets syncing to the same NTP reference clock

```cypher
MATCH (a1:RZAsset)-[:RZHasNTPReference]->(ntp:RZNTPReference)<-[:RZHasNTPReference]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN ntp.reference_id, ntp.stratum, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List NTP reference clocks by number of clients

```cypher
MATCH (ntp:RZNTPReference)<-[:RZHasNTPReference]-(a:RZAsset)
RETURN ntp.reference_id, ntp.stratum, ntp.version, count(a) AS client_count
ORDER BY client_count DESC
LIMIT 20
```

### Find assets using the same time infrastructure (NTP + subnet)

```cypher
MATCH (a:RZAsset)-[:RZHasNTPReference]->(ntp:RZNTPReference),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH ntp, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE hosts > 5
RETURN ntp.reference_id, ntp.stratum, subnets, hosts
ORDER BY hosts DESC
LIMIT 10
```

---

## DNS Server Identity Queries

### Find DNS servers sharing the same identity (clustered DNS)

```cypher
MATCH (a1:RZAsset)-[:RZHasDNSIdentity]->(dns:RZDNSIdentity)<-[:RZHasDNSIdentity]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN dns.server_id, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List all DNS server identities and their host count

```cypher
MATCH (dns:RZDNSIdentity)<-[:RZHasDNSIdentity]-(a:RZAsset)
RETURN dns.server_id, count(a) AS host_count
ORDER BY host_count DESC
LIMIT 20
```

### Find DNS servers grouped by software version

```cypher
MATCH (ver:RZDNSVersion)<-[:RZHasDNSVersion]-(a:RZAsset)
RETURN ver.version_bind, count(a) AS host_count
ORDER BY host_count DESC
LIMIT 20
```

### Find DNS servers running outdated BIND versions

```cypher
MATCH (a:RZAsset)-[:RZHasDNSVersion]->(ver:RZDNSVersion)
WHERE ver.version_bind CONTAINS "9.11" OR ver.version_bind CONTAINS "9.9"
RETURN a.displayname, ver.version_bind
ORDER BY ver.version_bind
LIMIT 20
```

---

## SNMP Device Type Queries

### Find all device types by sysObjectID

```cypher
MATCH (oid:RZSNMPDeviceType)<-[:RZHasSNMPDeviceType]-(a:RZAsset)
RETURN oid.sys_object_id, oid.sys_descr, count(a) AS device_count
ORDER BY device_count DESC
LIMIT 20
```

### Find assets of the same SNMP device type

```cypher
MATCH (a1:RZAsset)-[:RZHasSNMPDeviceType]->(oid:RZSNMPDeviceType)<-[:RZHasSNMPDeviceType]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN oid.sys_object_id, oid.sys_name, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### Find MikroTik devices (common OID prefix)

```cypher
MATCH (a:RZAsset)-[:RZHasSNMPDeviceType]->(oid:RZSNMPDeviceType)
WHERE oid.sys_object_id STARTS WITH ".1.3.6.1.4.1.14988"
RETURN a.displayname, oid.sys_object_id, oid.sys_name
ORDER BY a.displayname
```

### Find SNMP device types that also have engine IDs (enriched view)

```cypher
MATCH (a:RZAsset)-[:RZHasSNMPDeviceType]->(oid:RZSNMPDeviceType),
      (a)-[:RZHasSNMPEngineID]->(eid:RZSNMPEngineID)
RETURN a.displayname, oid.sys_object_id, oid.sys_name, eid.engine_id, eid.vendor
ORDER BY oid.sys_object_id
LIMIT 20
```

---

## TLS CA Chain Queries

### Find all assets whose certificates are signed by a specific CA

```cypher
MATCH (ca:RZTLSCAChain)<-[:RZSignedByCA]-(a:RZAsset)
RETURN ca.issuer, ca.ca_sha1, count(a) AS signed_count
ORDER BY signed_count DESC
LIMIT 20
```

### Find internal CAs (CAs that signed certificates for many assets)

```cypher
MATCH (ca:RZTLSCAChain)<-[:RZSignedByCA]-(a:RZAsset)
WITH ca, count(a) AS cnt
WHERE cnt > 10
RETURN ca.issuer, ca.ca_sha1, cnt
ORDER BY cnt DESC
```

### Find CA chains spanning multiple subnets

```cypher
MATCH (a:RZAsset)-[:RZSignedByCA]->(ca:RZTLSCAChain),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH ca, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE size(subnets) > 1
RETURN ca.issuer, ca.ca_sha1, subnets, hosts
ORDER BY hosts DESC
LIMIT 10
```

### Find self-signed cert assets vs. CA-signed assets

```cypher
MATCH (a:RZAsset)-[:RZHasTLSCert]->(cert:RZTLSCert)
OPTIONAL MATCH (a)-[:RZSignedByCA]->(ca:RZTLSCAChain)
RETURN cert.self_signed IS NOT NULL AS is_self_signed,
       ca IS NOT NULL AS has_ca,
       count(DISTINCT a) AS asset_count
```

---

## Serial Number Queries

### Find assets sharing the same serial number (same physical device)

```cypher
MATCH (a1:RZAsset)-[:RZHasSerialNumber]->(sn:RZSerialNumber)<-[:RZHasSerialNumber]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN sn.serial_number, sn.source, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List serial numbers by source protocol

```cypher
MATCH (sn:RZSerialNumber)<-[:RZHasSerialNumber]-(a:RZAsset)
RETURN sn.source, count(DISTINCT sn) AS serial_count, count(DISTINCT a) AS asset_count
ORDER BY serial_count DESC
```

### Find serial numbers shared by assets in different subnets

```cypher
MATCH (a:RZAsset)-[:RZHasSerialNumber]->(sn:RZSerialNumber),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH sn, collect(DISTINCT net.displayname) AS subnets, collect(DISTINCT a.displayname) AS hosts
WHERE size(subnets) > 1
RETURN sn.serial_number, sn.source, subnets, hosts
ORDER BY size(subnets) DESC
LIMIT 10
```

### Find BACnet/CIP devices by serial number

```cypher
MATCH (a:RZAsset)-[:RZHasSerialNumber]->(sn:RZSerialNumber)
WHERE sn.source IN ["bacnet", "cip"]
RETURN sn.serial_number, sn.source, a.displayname, a.hw
ORDER BY sn.source, sn.serial_number
LIMIT 30
```

---

## NTLM SSP Queries (Windows Domain/Computer Identity)

### Find all NTLM domains and their member computers

```cypher
MATCH (dom:RZNTLMDomain)<-[:RZNTLMPartOfDomain]-(comp:RZNTLMComputer)
RETURN dom.dns_domain, dom.netbios_domain, collect(comp.dns_computer) AS computers, count(comp) AS count
ORDER BY count DESC
```

### Find assets sharing the same NTLM domain

```cypher
MATCH (a1:RZAsset)-[:RZHasNTLMDomain]->(dom:RZNTLMDomain)<-[:RZHasNTLMDomain]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN dom.dns_domain, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### Find assets sharing the same NTLM computer name (identity reuse)

```cypher
MATCH (a1:RZAsset)-[:RZHasNTLMComputer]->(comp:RZNTLMComputer)<-[:RZHasNTLMComputer]-(a2:RZAsset)
WHERE id(a1) < id(a2)
RETURN comp.dns_computer, comp.version, a1.displayname AS host1, a2.displayname AS host2
LIMIT 20
```

### List all NTLM computers with their domain and Windows version

```cypher
MATCH (a:RZAsset)-[:RZHasNTLMComputer]->(comp:RZNTLMComputer)
OPTIONAL MATCH (comp)-[:RZNTLMPartOfDomain]->(dom:RZNTLMDomain)
RETURN comp.dns_computer, comp.version, comp.target_name,
       dom.dns_domain, a.displayname
ORDER BY dom.dns_domain, comp.dns_computer
```

### Find NTLM-enabled services across subnets (lateral movement paths)

```cypher
MATCH (a:RZAsset)-[:RZHasNTLMDomain]->(dom:RZNTLMDomain),
      (a)-[:RZInsideOfSubnet]->(net:RZNetwork)
WITH dom, collect(DISTINCT net.displayname) AS subnets, count(DISTINCT a) AS hosts
WHERE size(subnets) > 1
RETURN dom.dns_domain, subnets, hosts
ORDER BY hosts DESC
```

---

## Cross-Protocol Correlation Queries

### Find assets linked by multiple relationship types

```cypher
MATCH (a:RZAsset)
OPTIONAL MATCH (a)-[:RZHasFavicon]->(fav:RZFavicon)
OPTIONAL MATCH (a)-[:RZHasIKEIdentity]->(ike:RZIKEIdentity)
OPTIONAL MATCH (a)-[:RZHasKNXnetDevice]->(knx:RZKNXnetDevice)
OPTIONAL MATCH (a)-[:RZHasBACnetDevice]->(bac:RZBACnetDevice)
OPTIONAL MATCH (a)-[:RZHasSerialNumber]->(sn:RZSerialNumber)
WITH a,
     count(DISTINCT fav) AS favicons,
     count(DISTINCT ike) AS ike_ids,
     count(DISTINCT knx) AS knx_devs,
     count(DISTINCT bac) AS bac_devs,
     count(DISTINCT sn)  AS serials
WHERE favicons + ike_ids + knx_devs + bac_devs + serials > 1
RETURN a.displayname, favicons, ike_ids, knx_devs, bac_devs, serials
ORDER BY favicons + ike_ids + knx_devs + bac_devs + serials DESC
LIMIT 20
```

### Find OT devices with both BACnet identity and gateway relationship

```cypher
MATCH (a:RZAsset)-[:RZHasBACnetDevice]->(dev:RZBACnetDevice),
      (a)-[:RZHasGateway]->(gw:RZGateway)
RETURN gw.displayname AS gateway, dev.instance_id, dev.object_name,
       dev.vendor_name, a.displayname
ORDER BY gw.displayname
LIMIT 30
```

### Find assets with both IKE VPN and TLS certificates

```cypher
MATCH (a:RZAsset)-[:RZHasIKEIdentity]->(ike:RZIKEIdentity),
      (a)-[:RZHasTLSCert]->(cert:RZTLSCert)
RETURN a.displayname, ike.sha1, cert.cn, cert.issuer
LIMIT 20
```

---

### Summary: count of each relationship type per asset

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
RETURN a.displayname, ssh_keys, tls_certs, gateways, macs, favicons, ike_ids, bacnet_devs, knxnet_devs, serials
ORDER BY ssh_keys + tls_certs + gateways + macs + favicons + ike_ids + bacnet_devs + knxnet_devs + serials DESC
LIMIT 20
```
