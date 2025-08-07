# 🌐 DNS Traffic Hunting

---

## 🧠 Why Hunt DNS?

DNS is the phone book of the internet — and attackers love to hide in it.

Because DNS is:
- Ubiquitous
- Often allowed outbound (even when other traffic is blocked)
- Typically uninspected beyond domain reputation

...it becomes a **high-value C2 and exfiltration channel** for adversaries.

---

## 🎯 Hunting Goals

When hunting DNS traffic, your objectives might include:

- Detecting **domain generation algorithm (DGA)** activity
- Identifying **DNS tunneling or exfiltration**
- Uncovering **rare or suspicious domains**
- Discovering **early signs of command and control (C2)**

---

## 🧾 DNS Log Fields to Focus On

| Field             | Why It Matters                                   |
|------------------|---------------------------------------------------|
| `query`          | The domain or subdomain requested                 |
| `qtype`          | Type of DNS request (A, AAAA, TXT, etc.)          |
| `rcode`          | DNS response code (e.g., NXDOMAIN, NOERROR)       |
| `answers`        | Resolved IPs or data                              |
| `id.resp_h`      | The DNS server responding                         |
| `uid` / `ts`     | Unique session ID and timestamp                   |

> 🔧 **Tool Tip:** If using **Zeek**, most DNS hunting is done in `dns.log`.  
> To filter NXDOMAIN results:  
> `cat dns.log | jq 'select(.rcode_name == "NXDOMAIN")'`

---

## 🧬 Domain Generation Algorithm (DGA) Detection

DGAs generate domain names like:

```
- nxjne3vq23rf8er.com
- lpxwoa9vg3493a.info
- vggrewub213gff.org
```


**Hunting Techniques:**
- High entropy or randomness in subdomains
- Domains never seen before (low frequency)
- Short TTLs or excessive NXDOMAINs
- Unusual TLDs or uncommon registrars

> 🔧 **Tool Tip:** Use entropy scoring tools (e.g., `ent`, `CyberChef`) or regex filters:
>  
> `grep -E '[a-zA-Z0-9]{25,}' dns.log`

---

## 📡 DNS Tunneling Detection

Attackers may use DNS to exfiltrate data or communicate with C2 via encoded subdomains.

### Common Indicators:
- Very **long subdomains** (often base64/base32 encoded)
- **Unusual query types** (e.g., TXT, NULL)
- **High frequency** from a single host
- Lots of **NXDOMAINs**

> 🧪 Example:

```
abcd1234.maliciousdomain.com
eyJ0eXAiOiJKV1QiLCJh.attacker.site
```

> 🔧 **Tool Tip:** Detect long queries in Zeek:
> 
> `jq 'select(.query | length > 50)' dns.log`

> 🔧 **Tool Tip:** Use **RITA** to detect DNS tunnels:
> 
> `rita analyze logs/ dns_tunnel_output`  
> `rita dns-tunnels dns_tunnel_output`

---

## 🕵️ Rare or Suspicious Domains

### What to Hunt For:
- Domains never seen in your network before
- Rare TLDs (`.top`, `.xyz`, `.gq`, etc.)
- Numeric-only subdomains
- Domains with no reverse DNS
- Fast-flux or changing IPs for the same domain

> 🔧 **Tool Tip:** Use Zeek with frequency counting:
> 
> `cat dns.log | jq -r '.query' | sort | uniq -c | sort -nr | head`

---

## 🧪 Frequency & Timing Analysis

- Identify **hosts making DNS queries at regular intervals**
- Detect **burst traffic** followed by long silence (beaconing behavior)

> 🔧 **Tool Tip:** Use `RITA` to detect periodic behavior in DNS logs:  
> `rita analyze /path/to/logs dns_output`  
> `rita show-beacons dns_output`

---

## 🛑 Indicators of Suspicious DNS Behavior

| Indicator                        | Potential Threat                 |
|----------------------------------|----------------------------------|
| High query entropy               | DGA, tunneling                   |
| Repeated NXDOMAINs               | DGA, probing, C2 beacon failures |
| Long subdomain chains            | Tunneling                        |
| Frequent TXT record queries      | C2, DNS-based payload transfer   |
| Rare TLDs or domains             | Malicious infrastructure         |
| DNS over HTTPS (DoH)             | Evasion, encrypted C2            |

---

## 🧩 Combining DNS with Other Data Sources

- Match DNS queries with **HTTP or TLS logs** for correlated activity
- Pivot from domains to **IP addresses** and check **Suricata alerts**
- Cross-reference with **Threat Intelligence feeds**

> 🔧 **Tool Tip:** Use `VirusTotal` or `AbuseIPDB` to enrich suspicious domains:
> 
> `curl -s -H "x-apikey:YOUR_API_KEY" https://www.virustotal.com/api/v3/domains/example.com`

---

## 🛠 Tools for DNS Hunting

| Tool         | Purpose                              |
|--------------|---------------------------------------|
| **Zeek**     | Structured DNS logs with detail       |
| **RITA**     | DNS tunnel & beacon detection         |
| **Wireshark**| Deep packet analysis                  |
| **dnscat2**  | Simulated DNS C2 testing              |
| **CyberChef**| Decode base64/base32 encoded queries  |
| **Entropy Tools** | Evaluate randomness in domains  |

---

## 📚 Related Resources

- [Zeek DNS Log Reference](https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html)
- [RITA Tool by Active Countermeasures](https://www.activecountermeasures.com/free-tools/rita/)
- [Passive DNS Lookup (Farsight Security)](https://www.farsightsecurity.com/)

---

📘 *Next up: [04_http_traffic.md](04_http_traffic.md) — Hunt through HTTP traffic to detect suspicious URIs, user-agents, and encoded payloads.*
