# Nmap Commands for runZeroHound

This guide covers the ideal Nmap command-line invocations for generating scan
data that runZeroHound can ingest and correlate.

## Quick Reference

```bash
# /24 full discovery scan
nmap -sS -sU -p T:1-65535,U:161,500,4500,5353 -sV -O \
  --script ssh-hostkey,ssl-cert,smb2-security-mode,snmp-info,nbstat \
  --script-args snmp.version=all \
  --traceroute -oX scan.xml 192.168.1.0/24

# Single-host deep scan
nmap -sS -sU -p T:1-65535,U:53,67,123,161,162,500,623,1900,4500,5353 -sV -O \
  --script default,ssh-hostkey,ssl-cert,ssl-enum-ciphers,smb2-security-mode,smb-os-discovery,\
nbstat,snmp-info,snmp-sysdescr,snmp-interfaces,dns-nsid,ntp-info,banner \
  --script-args snmp.version=all,snmpcommunity=public \
  --traceroute --reason -oX deep-scan.xml 192.168.1.1
```

## Recommended Full Discovery Command

```bash
nmap -sS -sU \
  -p T:1-65535,U:161,500,4500,5353 \
  -sV -O \
  --script ssh-hostkey,ssl-cert,smb2-security-mode,snmp-info,nbstat \
  --script-args snmp.version=all \
  --traceroute \
  -oX scan.xml \
  192.168.1.0/24
```

### Flag-by-flag explanation

| Flag / Option | Purpose |
|---|---|
| `-sS` | TCP SYN scan — fast, stealthy, and reliable for open-port detection. |
| `-sU` | UDP scan — required to discover SNMP (161) and other UDP services. |
| `-p T:1-65535,U:161,500,4500,5353` | Scan all TCP ports; target key UDP ports (SNMP, ISAKMP, mDNS). |
| `-sV` | Service/version detection — populates Product and Version fields. |
| `-O` | OS detection — populates the OS fingerprint for each host. |
| `--script ssh-hostkey` | Retrieves SSH host public keys. runZeroHound uses the fingerprint as a unique correlation key (`ssh_hostkey_fp`). |
| `--script ssl-cert` | Retrieves TLS/SSL certificate details including the SHA-1 fingerprint (`tls_cert_fp`). |
| `--script smb2-security-mode` | Retrieves the SMB server GUID from Windows hosts (`smb_guid`). |
| `--script snmp-info` | Retrieves the SNMPv3 engine ID (`snmpv3_engine_id`) plus system description. |
| `--script nbstat` | Retrieves NetBIOS name, domain, and MAC address. |
| `--script-args snmp.version=all` | Probes SNMPv1, v2c, and v3 so the engine ID is collected regardless of the version the device supports. |
| `--traceroute` | Discovers layer-3 path to each host. runZeroHound creates Router nodes from intermediate hops. |
| `-oX scan.xml` | Writes Nmap XML output that runZeroHound ingests directly. |

## Single-Host Deep Scan

When you need maximum detail on one target:

```bash
nmap -sS -sU \
  -p T:1-65535,U:53,67,123,161,162,500,623,1900,4500,5353 \
  -sV -O \
  --script default,ssh-hostkey,ssl-cert,ssl-enum-ciphers,\
smb2-security-mode,smb-os-discovery,nbstat,\
snmp-info,snmp-sysdescr,snmp-interfaces,\
dns-nsid,ntp-info,banner \
  --script-args snmp.version=all,snmpcommunity=public \
  --traceroute --reason \
  -oX deep-scan.xml \
  192.168.1.1
```

### Additional flags for deep scans

| Flag / Option | Purpose |
|---|---|
| `U:53,67,123,161,162,500,623,1900,4500,5353` | Broader UDP coverage: DNS, DHCP, NTP, SNMP (both ports), ISAKMP, IPMI, SSDP, mDNS. |
| `--script default` | Runs the default NSE script category for general enumeration. |
| `--script ssl-enum-ciphers` | Enumerates supported TLS cipher suites. |
| `--script smb-os-discovery` | Extracts Windows OS version and NetBIOS domain via SMB. |
| `--script snmp-sysdescr` | Retrieves the full SNMP sysDescr string. |
| `--script snmp-interfaces` | Enumerates network interfaces and their IP/MAC addresses. |
| `--script dns-nsid` | Retrieves DNS Name Server ID (useful for identifying recursive resolvers). |
| `--script ntp-info` | Retrieves NTP server information. |
| `--script banner` | Grabs raw service banners for unknown services. |
| `--reason` | Records why each port was marked open (SYN-ACK, etc.). |

## Tips for Best runZeroHound Correlation

1. **Always use `-oX`** — runZeroHound parses Nmap XML. Plain text (`-oN`)
   and grepable (`-oG`) formats are not supported.

2. **Include `--traceroute`** — Traceroute data creates Router nodes in the
   graph, revealing network topology between scan source and targets.

3. **Run the fingerprint scripts** — The four key identity scripts
   (`ssh-hostkey`, `ssl-cert`, `smb2-security-mode`, `snmp-info`) produce the
   unique keys that runZeroHound uses to correlate hosts across different data
   sources (Nmap, Nessus, Qualys, Shodan, etc.).

4. **Scan UDP 161** — Many network devices (switches, routers, printers) are
   only discoverable via SNMP. The SNMPv3 engine ID is one of the strongest
   correlation fingerprints.

5. **Combine with other sources** — Nmap excels at active discovery. Pair it
   with passive sources like Shodan exports or vulnerability scanner output
   (Nessus, Qualys) to enrich the graph with additional context and
   cross-validate findings.

6. **Avoid `-Pn` unless necessary** — Host discovery (ping) filters out
   unreachable hosts early. If you use `-Pn` (treat all hosts as up), the scan
   takes much longer and may produce entries for non-existent hosts.

7. **Adjust `--min-rate` for large scans** — For `/16` or larger scans,
   consider `--min-rate 1000` to speed things up, but be mindful of network
   capacity.

8. **Use `--script-args snmp.version=all`** — Without this, Nmap may only
   probe SNMPv1/v2c and miss the v3 engine ID. The `all` setting ensures all
   three versions are attempted.

9. **Privileged execution** — SYN scans (`-sS`), OS detection (`-O`), and
   traceroute require root or `CAP_NET_RAW`. Run with `sudo` or equivalent.

10. **Gzip is supported** — If you compress the XML output (`gzip scan.xml`),
    runZeroHound can read `.xml.gz` files directly.
