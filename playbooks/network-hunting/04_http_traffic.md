# 🌐 HTTP Traffic Hunting

---

## 🧠 Why Hunt HTTP?

Attackers frequently use HTTP to deliver payloads, establish command and control, and exfiltrate data — because:

- HTTP is almost always allowed outbound  
- It blends in with legitimate web traffic  
- It’s flexible, widely supported, and often poorly inspected

By analyzing HTTP logs and packet data, you can uncover signs of phishing, malware delivery, tunneling, and custom backdoors.

---

## 🎯 Hunting Goals

Key objectives when hunting HTTP traffic:

- Detect **malicious or suspicious URIs**  
- Identify **non-browser user agents**  
- Spot **beaconing or repetitive callbacks**  
- Detect **staging servers or payload download behavior**  
- Uncover **command and control channels** disguised as web traffic  

---

## 📁 Data Sources for HTTP Hunting

- Zeek `http.log`  
- Proxy logs (e.g., Bluecoat, Squid)  
- PCAP (HTTP payload analysis)  
- Suricata or Snort alerts  
- Web server access logs  

> 🔧 **Tool Tip:** Use Zeek to extract HTTP method, URI, host, and User-Agent from traffic. Logs are human-readable and easy to parse.

---

## 🔍 Fields to Focus On

| Field           | Description                                       |
|----------------|---------------------------------------------------|
| `host`         | Domain contacted                                  |
| `uri`          | Requested path or resource                        |
| `method`       | HTTP verb (GET, POST, PUT, etc.)                  |
| `user_agent`   | Reported client making the request                |
| `status_code`  | Server response (e.g., 200, 404, 500)             |
| `referrer`     | Previous URL (can be used for pivoting)           |
| `resp_body_len`| Size of the response (e.g., payload size)         |

> 🔧 **Tool Tip:** To identify large HTTP responses (e.g., payload delivery), filter where `resp_body_len > 500000`.

---

## 🧪 Suspicious URI Patterns

Look for:

- Long, random-looking strings in URLs (e.g., base64-encoded data)  
- Paths like `/load.php`, `/gate.php`, `/panel/` often used by C2 frameworks  
- Suspicious file types: `.docx`, `.js`, `.zip`, `.exe`  
- Obfuscated or hex-encoded strings (e.g., `%2e%2e` or `/0x414141`)  

> 🔧 **Tool Tip:** Use `tshark` to extract HTTP URIs from a PCAP:  
```
tshark -r traffic.pcap -Y http.request -T fields -e http.host -e http.request.uri
```

> 🔧 **Tool Tip:** Use CyberChef to decode suspicious URI strings found in logs.

## 🧬 Hunting Non-Browser User Agents
Malware and scripts often use non-standard or hardcoded User-Agent strings.

Examples of suspicious agents:
```
- curl/7.79.1
- python-requests/2.25.1
- powershell/2.0
- Java/1.8.0
- Strings with "bot", "scanner", or "malware"
```

> 🔧 **Tool Tip:** Use Zeek’s http.log and filter by User-Agent:

`cat http.log | jq -r '.user_agent' | sort | uniq -c | sort -nr`

> 🔧 **Tool Tip:** Create a baseline of User-Agent strings used in your environment and look for outliers.

## 🔁 Repetitive Callbacks and Beaconing
Some malware phones home at regular intervals using HTTP GET or POST.

Indicators:
```
- Same URI accessed repeatedly over time by same host
- Identical response sizes
- Low variation in URI parameters
- Fixed timing between requests (beaconing)
```
> 🔧 **Tool Tip:** Use ***RITA*** to detect beaconing via HTTP:
```
rita analyze logs/ http_beacons
rita show-beacons http_beacons
```
## 📎 Pivoting Techniques
Use these to expand your hunt:
```
- URI ➝ Check for similar URIs across multiple hosts
- Host ➝ Resolve IP and check for other activity (via DNS, TLS, etc.)
- Referrer ➝ Find where the client came from
- JA3/JA3s ➝ Correlate with TLS fingerprinting to track unique malware families
- User-Agent ➝ Find all requests using the same custom agent
```

## 🛠 Tools for HTTP Hunting

| Tool       | Use Case                              |
|------------|----------------------------------------|
| **Zeek**   | Structured HTTP metadata               |
| **Wireshark** | Payload and header inspection      |
| **CyberChef** | URI/parameter decoding and analysis |
| **Suricata**  | Signature-based HTTP detections     |
| **RITA**      | Beacon detection                    |
| **tshark**    | Command-line traffic extraction     |

## 📚 Related Resources

- [Zeek HTTP Log Fields](https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html)  
- [Common URI Patterns Used in Malware – Palo Alto Unit 42](https://unit42.paloaltonetworks.com)  
- [CyberChef – The Cyber Swiss Army Knife](https://gchq.github.io/CyberChef/)  

**📘 Next up: 05_tls_ssl_traffic.md — Learn to hunt encrypted traffic using JA3 hashes, SNI fields, and certificate anomalies.**
