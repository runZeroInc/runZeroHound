# runZeroHound Cypher Query Collection

This document provides a curated set of Cypher queries for BloodHound CE to help identify risk, misconfigurations,
and interesting relationships in your runZero asset graph.

Please see the [Cypher documentation](https://bloodhound.specterops.io/analyze-data/cypher-search) for more details on Cypher syntax.

---

## Basic Exploration

### All Asset Nodes

```
match (a:RZAsset) return a limit 25
```

### All Subnet Nodes

```
match (n:RZNetwork) return n
```

### Verify the Public Internet Node

```
match (n:RZNetwork) where n.network_address = '0.0.0.0' return n
```

### Assets By Device Type

```
match (a:RZAsset) return a.type, count(a) order by count(a) desc
```

### Assets By Category

```
match (a:RZAsset) return a.category, count(a) order by count(a) desc
```

### Assets By Function

```
match (a:RZAsset) unwind a.functions as f return f, count(a) order by count(a) desc
```

---

## Internet Exposure

### Windows Machines With External IPs

```
match p=(t1:RZAsset)-[:RZInsideOfSubnet]->(a:RZNetwork)-[:RZInsideOfSubnet]->(b:RZNetwork)
where b.network_address = '0.0.0.0'
and a.version = '4'
and t1.os contains 'Windows'
return p
```

![Screenshot of BloodHound CE showing Windows machines with external IPs](/docs/bhce_windows_internet.png)

### Paths From the Internet to the Internal 10.0.0.0/8

```
match p=(public:RZNetwork)-[:RZSubnetContains]->(hop1:RZNetwork)-[:RZSubnetContains]->(a1:RZAsset)
where
public.network_address = '0.0.0.0'
and hop1.version = '4'
and a1.ip_addresses contains '10.'
return p
```

![Screenshot of BloodHound CE showing paths from the internet to the 10.0.0.0/8 subnet](/docs/bhce_external_internal_10.png)

### Linux Devices With External IPs

```
match p=(a:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZInsideOfSubnet]->(pub:RZNetwork)
where pub.network_address = '0.0.0.0'
and net.version = '4'
and a.os contains 'Linux'
return p
```

### High-Risk Assets Reachable From the Internet

```
match p=(pub:RZNetwork)-[:RZSubnetContains]->(net:RZNetwork)-[:RZSubnetContains]->(a:RZAsset)
where pub.network_address = '0.0.0.0'
and a.risk_rank >= 3
return p
```

### Assets With Both Internal and External Addresses

```
match (a:RZAsset)-[:RZInsideOfSubnet]->(n1:RZNetwork)
where n1.network_address <> '0.0.0.0'
with a, collect(n1) as nets
where any(n in nets where not exists((n)-[:RZInsideOfSubnet]->(:RZNetwork {network_address: '0.0.0.0'})))
and any(n in nets where exists((n)-[:RZInsideOfSubnet]->(:RZNetwork {network_address: '0.0.0.0'})))
return a
```

---

## OT / ICS Risks

### OT Devices on the Same Subnet as Mobile/IT Devices (Unexpected Convergence)

```
match p=(ot:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZSubnetContains]->(mobile:RZAsset)
where ot.category = 'OT'
and mobile.type contains 'Mobile'
return p
```

### OT Devices With Direct Internet Exposure

```
match p=(ot:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZInsideOfSubnet]->(pub:RZNetwork)
where ot.category = 'OT'
and pub.network_address = '0.0.0.0'
return p
```

### OT Historians on the Same Subnet as Corporate IT Assets

```
match p=(hist:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZSubnetContains]->(corp:RZAsset)
where 'Historian' in hist.functions
and corp.category <> 'OT'
return p
```

### PLCs or Controllers Reachable From Windows Machines

```
match p=(win:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZSubnetContains]->(ot:RZAsset)
where win.os contains 'Windows'
and ('Controller' in ot.functions or 'PLC' in ot.functions)
return p
```

### ICS/SCADA Devices With Open Remote Access Ports

Find OT devices that have remote management services (RDP, SSH, Telnet) accessible:

```
match (a:RZAsset)
where a.category = 'OT'
and (a.service_ports_tcp contains '22'
  or a.service_ports_tcp contains '23'
  or a.service_ports_tcp contains '3389')
return a
```

### OT Devices Running End-of-Life Operating Systems

```
match (a:RZAsset)
where a.category = 'OT'
and a.os is not null
and (a.os contains 'Windows XP'
  or a.os contains 'Windows 2003'
  or a.os contains 'Windows CE'
  or a.os contains 'Linux 2.6')
return a
```

### OT Devices With Critical or High Risk Score

```
match (a:RZAsset)
where a.category = 'OT'
and a.risk_rank >= 3
return a order by a.risk_rank desc
```

---

## Unexpected Device Adjacency

### BYOD iPhones on the Same Subnet as Cisco Devices with Default SNMP

```
match p=(byod:RZAsset)-[:RZInsideOfSubnet]->(net1:RZNetwork)-[:RZSubnetContains]->(mgmt:RZAsset)
where
byod.os contains 'Apple iOS'
AND mgmt.os contains 'Cisco'
AND mgmt.service_protocols contains 'snmp2'
return p
```

![Screenshot of BloodHound CE showing subnets with both iPhones and Cisco devices with default SNMP v2](/docs/bhce_iphone_cisco.png)

### Mobile Devices on the Same Subnet as Critical Infrastructure

```
match p=(mobile:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZSubnetContains]->(crit:RZAsset)
where mobile.type contains 'Mobile'
and crit.risk_rank >= 3
return p
```

### Personal/Consumer Devices (IoT) on a Corporate Domain

```
match (a:RZAsset)-[:RZPartOfDomain]->(d:RZDomain)
where a.category = 'IoT'
return a, d
```

### Printers or MFDs on the Same Subnet as Domain Controllers

Find printers co-located with Windows Server assets (potential domain controllers):

```
match p=(printer:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZSubnetContains]->(dc:RZAsset)
where (printer.type contains 'Printer' or 'Printer' in printer.functions)
and dc.os contains 'Windows Server'
return p
```

### Medical Devices on the Same Subnet as Non-Medical Systems

```
match p=(med:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZSubnetContains]->(other:RZAsset)
where med.category = 'Medical'
and other.category <> 'Medical'
return p
```

---

## Weak Authentication & Insecure Protocols

### Assets Running SNMPv1 or SNMPv2 (Cleartext Community Strings)

```
match (a:RZAsset)
where a.service_protocols contains 'snmp'
  or a.service_protocols contains 'snmp2'
return a
```

### Assets With Telnet Open (Cleartext Remote Access)

```
match (a:RZAsset)
where a.service_ports_tcp contains '23'
return a
```

### Assets With FTP Open (Cleartext File Transfer)

```
match (a:RZAsset)
where a.service_ports_tcp contains '21'
return a
```

### Assets Exposing Unencrypted HTTP Administration (Port 80)

```
match (a:RZAsset)
where a.service_ports_tcp contains '80'
and (a.type contains 'Router'
  or a.type contains 'Switch'
  or 'Router' in a.functions
  or 'Switch' in a.functions
  or 'Firewall' in a.functions)
return a
```

---

## Lateral Movement Risk

### Assets That Are a Bridge Between Two Different Domains

Find assets that appear in more than one Active Directory domain — potential dual-homed pivots:

```
match (a:RZAsset)-[:RZPartOfDomain]->(d:RZDomain)
with a, collect(d.displayname) as doms
where size(doms) > 1
return a, doms
```

### Assets Spanning Two Different VLANs

Assets that appear on more than one VLAN — could indicate misconfiguration or pivot opportunity:

```
match (a:RZAsset)-[:RZPartOfVLAN]->(v:RZVLAN)
with a, collect(v.displayname) as vlans
where size(vlans) > 1
return a, vlans
```

### High-Service-Count Assets in Internal Subnets (Possible Jump Hosts)

Assets with many open services inside private ranges may function as jump hosts:

```
match (a:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)
where net.network_address starts with '10.'
   or net.network_address starts with '192.168.'
   or net.network_address starts with '172.'
and a.services_count > 10
return a order by a.services_count desc
```

### Assets With Both RDP and SSH Enabled (Multi-Protocol Remote Access)

```
match (a:RZAsset)
where a.service_ports_tcp contains '22'
and a.service_ports_tcp contains '3389'
return a
```

---

## Vulnerability and Risk

### Critical-Risk Assets Connected to the Internet

```
match p=(pub:RZNetwork)-[:RZSubnetContains]->(net:RZNetwork)-[:RZSubnetContains]->(a:RZAsset)
where pub.network_address = '0.0.0.0'
and a.risk_rank = 4
return p
```

### Assets With Known Vulnerabilities Connected to OT Systems

```
match p=(vuln:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZSubnetContains]->(ot:RZAsset)
where vuln.vulnerability_count > 0
and ot.category = 'OT'
return p
```

### Assets With the Highest Outlier Scores (Anomalous Devices)

```
match (a:RZAsset)
where a.outlier_score > 80
return a order by a.outlier_score desc limit 25
```

### End-of-Life OS Devices With Network Exposure

```
match p=(eol:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)-[:RZInsideOfSubnet]->(pub:RZNetwork)
where pub.network_address = '0.0.0.0'
and (eol.os contains 'Windows XP'
  or eol.os contains 'Windows 7'
  or eol.os contains 'Windows 2003'
  or eol.os contains 'Windows 2008'
  or eol.os contains 'CentOS 6'
  or eol.os contains 'Ubuntu 14'
  or eol.os contains 'Ubuntu 16')
return p
```

---

## Supply Chain and Shadow IT

### Assets From Cloud Sources on Internal Subnets (Shadow Cloud)

Assets discovered only by cloud sources but residing on internal subnets:

```
match (a:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)
where any(s in a.sources where s in ['aws', 'azure', 'gcp'])
and (net.network_address starts with '10.'
  or net.network_address starts with '172.'
  or net.network_address starts with '192.168.')
return a
```

### Assets Seen by CrowdStrike Not Seen by runZero Scanner

```
match (a:RZAsset)
where any(s in a.sources where s = 'crowdstrike')
and not any(s in a.sources where s = 'runzero')
return a
```

### Assets With No Identified OS (Unknown / Unmanaged)

```
match (a:RZAsset)
where (a.os is null or a.os = '')
and a.alive = true
return a
```

### Assets With Only a Single Data Source (Potentially Unmanaged)

```
match (a:RZAsset)
where size(a.sources) = 1
and a.sources[0] = 'runzero'
return a limit 25
```

---

## Network Segmentation Validation

### OT Subnets That Contain More Than One Category of Device

Identify subnets that are supposed to be OT-only but contain non-OT devices:

```
match (ot:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)<-[:RZInsideOfSubnet]-(other:RZAsset)
where ot.category = 'OT'
and other.category <> 'OT'
return net, collect(distinct ot.hostname) as ot_devices, collect(distinct other.hostname) as non_ot_devices
```

### Subnets With the Most Diverse Device Categories

Subnets mixing many device categories may indicate poor segmentation:

```
match (a:RZAsset)-[:RZInsideOfSubnet]->(net:RZNetwork)
with net, collect(distinct a.category) as cats
where size(cats) > 2
return net, cats order by size(cats) desc
```

### Assets Crossing VLAN and Subnet Boundaries (Multi-Homed)

```
match (a:RZAsset)-[:RZInsideOfSubnet]->(n1:RZNetwork),
      (a)-[:RZInsideOfSubnet]->(n2:RZNetwork)
where id(n1) < id(n2)
return a, n1, n2
```
