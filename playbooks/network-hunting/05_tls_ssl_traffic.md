# 🔐 TLS/SSL Traffic Hunting

---

## 🧠 Why Hunt Encrypted Traffic?

TLS/SSL encryption hides payloads — but attackers still leave fingerprints. Even without decrypting traffic, TLS metadata reveals useful hunting leads:

- JA3/JA3s fingerprints
- Server Name Indication (SNI)
- Certificate details (self-signed, issuer, validity)
- Protocol versions and cipher suites

These artifacts can help detect:

- Malware using known JA3 hashes
- Encrypted C2 tunnels (HTTPS, Tor, Telegram over TLS)
- Domain fronting
- TLS tunneling
- Suspicious or rare SNI values

---

## 🧾 Key Fields in TLS Logs

| Field             | Description                                |
|------------------|--------------------------------------------|
| `server_name`    | SNI value (hostname during TLS handshake)  |
| `ja3`            | Client-side TLS fingerprint (TLS settings) |
| `ja3s`           | Server-side TLS fingerprint                |
| `subject`        | Certificate subject (e.g., CN)             |
| `issuer`         | Certificate issuer                         |
| `version`        | TLS protocol version (e.g., TLSv1.2)       |
| `validation_status` | Whether cert is self-signed or valid   |

> 🔧 **Tool Tip:** Zeek logs TLS metadata in `ssl.log`. Even though traffic is encrypted, handshake data remains accessible.

---

## 🧬 Hunting with JA3 and JA3s

**JA3** and **JA3s** are TLS fingerprinting methods that summarize a client’s or server’s TLS negotiation details. They help identify:

- Malware families that use fixed TLS fingerprints
- Tools (e.g., Cobalt Strike, Metasploit)
- Unusual or spoofed clients/servers

> 🔧 **Tool Tip:** Search for rare or known-malicious JA3 hashes using:

cat ssl.log | jq -r '.ja3' | sort | uniq -c | sort -nr

### 🧠 Tip: Pivoting Off Rare JA3s

Rare JA3 hashes can be strong indicators of **command-and-control (C2)** activity, especially when they:

- Appear only once or twice across large datasets
- Are not associated with common browsers or tools
- Match known malware JA3 signatures (e.g., Cobalt Strike, Meterpreter)

#### How to Pivot:

- Identify the rare JA3 hash from Zeek `ssl.log`
- Search across your dataset for:
  - Other internal hosts using the same JA3
  - External IPs frequently communicating with that JA3
  - Corresponding SNI values or domains

> 🔧 **Tool Tip:** Use the following to list JA3s by frequency:
> 
> ```bash
> cat ssl.log | jq -r '.ja3' | sort | uniq -c | sort -n | tail -n 10
> ```

Once you identify a suspicious JA3:

1. Investigate the JA3’s behavior over time
2. Enrich it via open-source intelligence (e.g., [ja3er.com](https://ja3er.com), VirusTotal)
3. Map the JA3 to known malware (using threat reports or community signatures)
4. Build detection rules around this fingerprint for early C2 detection

## 🌐 Hunting by Server Name (SNI)

**Server Name Indication (SNI)** reveals the intended domain during the TLS handshake — even if the traffic payload is encrypted.

### 🔍 What to Look For:
- Rare or never-before-seen domains in `server_name`
- Suspicious or encoded subdomains (e.g., long base64-like values)
- Common cloud services being misused (e.g., `*.discordapp.com`, `*.telegram.org`, `*.dropboxusercontent.com`)
- SNI patterns consistent with domain fronting (SNI doesn't match actual certificate or IP routing)

> 🔧 **Tool Tip:** Filter suspicious SNI values from Zeek `ssl.log`:

jq 'select(.server_name | test("discord|telegram|googleusercontent"))' ssl.log

## 🧪 Certificate Anomalies

TLS certificates offer valuable metadata for hunting — even without decrypting the session. Certain certificate patterns are commonly associated with malware or stealthy communications.

### 🔍 What to Look For:
- **Self-signed certificates** – No trusted CA, often used in malware infrastructure
- **SNI mismatch with CN (Common Name)** – Indicates possible domain fronting or spoofed identity
- **Very short certificate lifespans** – May indicate ephemeral infrastructure or Let's Encrypt abuse
- **Suspicious issuers** – Unknown, generic, or mismatched certificate authorities

> 🔧 **Tool Tip:** Extract and sort certificate issuers by frequency:
`cat ssl.log | jq -r '.issuer' | sort | uniq -c | sort -nr`

## 📊 Anomaly-Based Hunting

Even without payload visibility, anomalies in TLS behavior can help uncover C2 activity, malware staging, or stealthy tunneling.

### 🔍 What to Look For:
- **Rare JA3/JA3s combinations** – TLS fingerprints not seen elsewhere on your network
- **Deprecated or uncommon TLS versions** – e.g., SSLv3, TLS 1.0
- **Unusual cipher suites** – Legacy or non-standard cryptographic settings
- **High number of external TLS connections** – Especially from a single internal host
- **Many short-duration TLS sessions** – Indicates potential beaconing or exfil attempts

> 🔧 **Tool Tip:** Use RITA to analyze TLS beaconing patterns:
```
rita analyze /path/to/zeek logs_output
rita show-beacons logs_output
```

## 📎 Pivoting Techniques

Once you identify a suspicious artifact in TLS traffic, use it to expand your investigation across other data sources and hosts.

### 🔁 Common Pivots:

- **JA3 ➝** Find other hosts using the same TLS fingerprint  
  - Useful for tracking malware families or cloned implants
- **SNI ➝** Cross-reference with DNS and HTTP logs  
  - Helps confirm domain usage and uncover payload delivery
- **Issuer ➝** Investigate all connections using a suspicious certificate authority  
  - Spot shared infrastructure or clone certificates
- **Subject ➝** Look for generic values like `CN=localhost` or wildcard cloudfront certs  
  - May indicate default configs or obfuscation
- **IP ➝** Trace the destination IP through firewall or NetFlow logs  
  - Reveal who else is talking to that infrastructure internally

*Effective pivoting connects isolated events into attacker patterns and builds a broader picture of the campaign.*

## 🛠 Tools for TLS Hunting

These tools help extract, analyze, and enrich TLS metadata to support encrypted traffic hunting.

| Tool              | Use Case                                         |
|-------------------|--------------------------------------------------|
| **Zeek**          | Logs TLS handshake metadata (e.g., JA3, SNI, certs) |
| **RITA**          | Detects beaconing and JA3 anomalies              |
| **Wireshark**     | Deep inspection of TLS handshakes in PCAPs       |
| **Suricata**      | Identifies TLS characteristics, alerts on known JA3 |
| **JA3 Hash DB**   | Lookup database of known JA3 hashes              |
| **jq / CyberChef**| Parsing certificates, decoding fingerprints      |

Use these tools together to build detection pipelines, enrich logs, and pivot between artifacts during your hunt.



