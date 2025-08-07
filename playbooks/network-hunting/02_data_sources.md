# 📊 Network Data Sources for Threat Hunting

---

## 📥 Why Data Sources Matter

Your hunt is only as good as the data you can see. Without sufficient logs, telemetry, or packet captures, you’re essentially hunting blind.

This section will guide you through the **most critical network data sources**, what they’re good for, and how to use them effectively in your hunts.

---

## 🔑 Primary Data Types for Network Hunting

| Data Source       | What It Captures                            | Use Cases                                 |
|-------------------|---------------------------------------------|--------------------------------------------|
| **PCAP**          | Full packet capture (all traffic details)   | Deep inspection, payload analysis          |
| **Zeek Logs**     | Protocol-level metadata from traffic        | Session context, application behavior      |
| **NetFlow/sFlow** | Connection metadata (no payload)            | Flow-based anomalies, traffic volume       |
| **DNS Logs**      | DNS queries/responses                       | Domain profiling, DGA detection, tunneling |
| **Proxy Logs**    | HTTP/S requests via web proxy               | User-agent profiling, URI analysis         |
| **Firewall Logs** | Connection attempts, allowed/denied traffic | Port scans, lateral movement, blocked IOCs |
| **IDS/IPS Alerts**| Signature-based detections (e.g., Suricata) | Confirm known threats, refine hypotheses   |
| **TLS Fingerprints** | JA3/JA3s hashes, certificate metadata     | C2 detection, rare SSL fingerprint hunting |

---

## 📦 Data Source: PCAP

**PCAP** gives you the most detailed view — every bit of traffic including payloads, headers, and protocol behavior.

> 🔧 **Tool Tip:** Use `Wireshark` or `tshark` for deep inspection.  
> Extract all HTTP hosts:  
> `tshark -r capture.pcap -Y http.request -T fields -e http.host | sort | uniq -c`

> 🧠 Use PCAPs when:
- You suspect exfiltration or malicious payload delivery
- You need to extract files, certificates, or full conversations
- You want to confirm protocol anomalies

---

## 🧮 Data Source: Zeek (formerly Bro)

Zeek generates structured logs for many protocols — it's your best friend for **huntable metadata**.

| Zeek Log File       | Key Use Cases                             |
|----------------------|--------------------------------------------|
| `dns.log`            | Detect tunneling, DGA, rare domains        |
| `http.log`           | Analyze URIs, user-agents, uncommon methods|
| `ssl.log`            | Analyze JA3/JA3s, self-signed certs        |
| `conn.log`           | Session-level insights, lateral movement   |

> 🔧 **Tool Tip:** Filter Zeek DNS logs for long queries (potential tunneling):  
> `cat dns.log | jq 'select(.query | length > 50)'`

> 🧠 Use Zeek when:
- You want structured, search-friendly network metadata
- PCAPs are too large or unavailable
- You’re analyzing across days or weeks

---

## 🌐 Data Source: NetFlow / sFlow

NetFlow provides **network flow records** — source/destination IPs, ports, bytes, packets, durations.

| Pros                 | Cons                     |
|----------------------|--------------------------|
| Lightweight          | No content/payload       |
| Great for patterns   | Can't see protocol misuse|

> 🔧 **Tool Tip:** Use `nfdump` or `Elastiflow` to visualize flows by top talkers, uncommon ports, or protocol usage.

> 🧠 Use NetFlow when:
- You’re looking for beaconing or scanning
- You need high-level summaries over large networks
- You're looking at port anomalies or high-volume outliers

---

## 🌐 Data Source: DNS Logs

Logs of DNS queries and responses are **gold** for detecting early attacker behavior, especially in:

- Beaconing to C2 domains
- Domain generation algorithms (DGAs)
- DNS tunneling

> 🔧 **Tool Tip:** Look for:
- High entropy domains
- Rare TLDs
- Frequent subdomain queries from one host

> 🧠 Use DNS logs when:
- You suspect malware is using dynamic C2 infrastructure
- You want to profile domain use per host
- You’re investigating phishing domains or staging servers

---

## 🌐 Data Source: Proxy Logs

HTTP/HTTPS proxy logs show which **external resources** users or malware are trying to access.

| Log Field        | Use for…                                   |
|------------------|---------------------------------------------|
| URI              | Detecting suspicious strings, encoded data |
| User-Agent       | Detecting anomalous clients or implants     |
| Referer          | Identifying pivot points                    |

> 🔧 **Tool Tip:** Search for user-agents like `python-requests` or `curl` to detect non-browser tools.

> 🧠 Use proxy logs when:
- You suspect malware is using cloud services for C2
- You want to correlate internal users to external hits
- You’re hunting for staging or exfil platforms

---

## 🔐 Data Source: TLS/SSL Metadata

Even when traffic is encrypted, TLS metadata reveals useful hunting leads:

- JA3 / JA3s fingerprints
- Server Name Indication (SNI)
- Certificate validity, issuer, self-signed flags

> 🔧 **Tool Tip:** Use `Zeek ssl.log` or `Suricata eve.json` to extract JA3s:  
> Look for rarely seen hashes or mismatched JA3/JA3s pairs.

> 🧠 Use TLS logs when:
- You want to hunt for C2 over HTTPS
- You need to detect misuse of legitimate services
- You want to pivot from known malicious SSL fingerprints

---

## 🧱 Other Supplemental Sources

- **Firewall Logs** – Port scanning, lateral movement, blocked outbound traffic
- **VPN Logs** – Insider threat, after-hours access
- **WAF Logs** – Web attacks and exploitation attempts

---

## 📎 Mapping Data to ATT&CK

| MITRE ATT&CK Technique       | Data Sources                        |
|------------------------------|-------------------------------------|
| T1071: Application Layer C2  | PCAP, Zeek HTTP, TLS logs, Proxy    |
| T1008: Fallback Channels     | DNS logs, NetFlow, SSL fingerprints |
| T1040: Network Sniffing      | PCAP, conn.log                      |
| T1071.004: DNS Tunneling     | DNS logs, entropy tools             |

> 🔧 **Tool Tip:** Tag logs with ATT&CK mappings in Kibana or Elastic for filtered hunts.

---

## 📚 Related Resources

- [Zeek Log Cheat Sheet](https://docs.zeek.org/en/current/logs/index.html)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)
- [JA3 Fingerprinting](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/)
- [Elastiflow](https://www.elastiflow.com/)
- [DNS Sight - Passive DNS](https://www.farsightsecurity.com/)

---

📘 *Next up: [03_dns_traffic.md](03_dns_traffic.md) — Start your hunt with DNS: one of the most abused and most overlooked protocols in attacker infrastructure.*
