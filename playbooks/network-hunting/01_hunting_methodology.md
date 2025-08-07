# 🧭 Network Hunting Methodology

---

## 🔄 What Is a Hunting Methodology?

**Network threat hunting** is a proactive, hypothesis-driven process for uncovering threats that evade detection tools. It’s about **asking smart questions**, **sifting through network telemetry**, and **uncovering attacker behaviors** early in the intrusion chain.

Where detection engineering builds alert logic, threat hunting explores the unknown and discovers new detection opportunities.

---

## 🧠 The Hunt Loop

A repeatable hunt loop can be summarized as:

[Develop Hypothesis] → [Collect Data] → [Analyze] → [Enrich] → [Report & Iterate]


| Stage               | Purpose                                                |
|---------------------|--------------------------------------------------------|
| **Develop Hypothesis** | Ask "what could an attacker be doing on our network?" |
| **Collect Data**       | Identify and pull relevant logs or traffic captures  |
| **Analyze**            | Slice/dice the data, look for indicators or patterns |
| **Enrich**             | Add context (threat intel, sandbox results, etc.)    |
| **Report & Iterate**   | Document findings, build detections, repeat          |

---

## 🧪 Hypothesis-Driven Hunting

A **good hunt starts with a hypothesis**, often based on:

- Threat intel reports
- Known attacker TTPs (e.g., MITRE ATT&CK)
- Anomalies in normal network behavior
- Visibility gaps in detection

> 🔧 **Tool Tip:** Use the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to map out possible attack paths or gaps you want to investigate.

Example hypotheses:
- “An attacker may be using DNS tunneling for C2.”
- “A phishing campaign may have dropped a remote access trojan using HTTP.”
- “Exfiltration might be occurring over cloud-based services.”

---

## 🧩 Frameworks to Structure Your Hunt

### 🔹 MITRE ATT&CK

Use ATT&CK to:
- Develop hypotheses (e.g., T1046: Network Service Scanning)
- Identify known techniques used by threat actors
- Evaluate current detection coverage

> 🔧 **Tool Tip:** Combine ATT&CK mappings with Zeek logs and Kibana dashboards to trace techniques across data sources.

### 🔹 Lockheed Martin Cyber Kill Chain

Use the Kill Chain to align detection efforts with attacker progression:

1. **Reconnaissance**
2. **Weaponization**
3. **Delivery**
4. **Exploitation**
5. **Installation**
6. **Command & Control (C2)**
7. **Actions on Objectives**

This helps highlight **where your hunting focus is** (e.g., detecting delivery vs. lateral movement).

---

## 📊 Pre-Hunt Checklist

Before launching a hunt, validate:

- ✅ Hypothesis is specific and testable
- ✅ Required data sources (e.g., Zeek, NetFlow, PCAP) are available
- ✅ Tools are ready and functional
- ✅ You can pivot to enrichment (e.g., threat intel)
- ✅ Findings will be documented for future use

> 🔧 **Tool Tip:** Test your visibility with simulated traffic using tools like [Caldera](https://github.com/mitre/caldera) or [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).

---

## 🧾 Tracking Your Hunt (Hunt Log)

Maintain a **hunt log** to ensure transparency and reproducibility. You can use Markdown, Jupyter, Obsidian, or a hunt template.

Example:

```md
- Hunt: Suspicious DNS Tunneling
- Hypothesis: Attacker is using DNS tunneling for C2
- Timeframe: Last 14 days (December 01, 2024 - December 15, 2024)
- Data: Zeek DNS logs
- Tools: Zeek, RITA, Wireshark
- Key Queries: High entropy domains, long subdomain chains, query volume per host
- Observations: Noted base32-style subdomains with consistent timing
- Actions: Developed custom Suricata rule and added detection to ELK
```

> 🔧 **Tool Tip:** Use `jq` and `grep` to slice Zeek logs quickly:  
> `cat dns.log | jq -r '.query' | grep -E '[A-Za-z0-9]{30,}'`

---

## 🛠 Tool Recommendations per Stage

| Stage             | Tools                                                                 |
|------------------|------------------------------------------------------------------------|
| Hypothesis Dev    | MITRE ATT&CK, Threat Reports, ATT&CK Navigator                        |
| Collection        | Zeek, Wireshark, tcpdump, tshark, NetFlow, Suricata, ELK              |
| Analysis          | Zeek logs, Kibana, jq, grep, RITA, Wireshark                          |
| Enrichment        | VirusTotal, Shodan, AbuseIPDB, Hybrid Analysis, PassiveTotal          |
| Reporting         | Markdown, Jupyter, Google Docs, Detection Engineering Repos           |

> 🔧 **Tool Tip:**  
> Use `RITA` for detecting beaconing and long connection gaps:  
> `rita analyze /var/log/zeek logs_output` → `rita show-beacons logs_output`

> 🔧 **Tool Tip:**  
> Use `tshark` to extract HTTP User-Agent strings:  
> `tshark -r traffic.pcap -Y http.request -T fields -e http.user_agent | sort | uniq -c`

---

## 🧠 Methodology in Action

Putting it all together:

1. **Read Threat Intel** → Learn a C2 method that may be in use (e.g., Telegram over HTTPS)
2. **Form Hypothesis** → "Attacker may be using Telegram domains for C2"
3. **Pull Logs** → Extract DNS & HTTP logs over 14 days
4. **Analyze** → Search for `.t.me` domains, analyze traffic timing
5. **Enrich** → Check domains/IPs in VirusTotal and Shodan
6. **Report** → Write detection logic and update threat model

---

## 📚 Related Resources

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [SANS Threat Hunting Maturity Model](https://www.sans.org/posters/threat-hunting-maturity-model/)
- [Active Countermeasures RITA](https://www.activecountermeasures.com/free-tools/rita/)
- [Zeek Documentation](https://docs.zeek.org/en/current/)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)

---

📘 *Next up: [02_data_sources.md](02_data_sources.md) — Understand what logs, flows, and packet captures to use for maximum hunting visibility.*
