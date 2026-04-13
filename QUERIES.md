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

### Summary: count of each relationship type per asset

```cypher
MATCH (a:RZAsset)
OPTIONAL MATCH (a)-[:RZHasSSHKey]->(ssh:RZSSHKey)
OPTIONAL MATCH (a)-[:RZHasTLSCert]->(tls:RZTLSCert)
OPTIONAL MATCH (a)-[:RZHasGateway]->(gw:RZGateway)
OPTIONAL MATCH (a)-[:RZHasMAC]->(mac:RZMACAddress)
WITH a,
     count(DISTINCT ssh) AS ssh_keys,
     count(DISTINCT tls) AS tls_certs,
     count(DISTINCT gw)  AS gateways,
     count(DISTINCT mac)  AS macs
WHERE ssh_keys + tls_certs + gateways + macs > 0
RETURN a.displayname, ssh_keys, tls_certs, gateways, macs
ORDER BY ssh_keys + tls_certs + gateways + macs DESC
LIMIT 20
```
