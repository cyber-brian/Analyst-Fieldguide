# 🧭 Introduction to Network Hunting

---

## 🔍 What is Network Threat Hunting?

**Network threat hunting** is the proactive, hypothesis-driven process of searching through network data to detect signs of malicious activity that have evaded traditional security controls.

Unlike alert-based monitoring, hunting is not reactive — it is **analyst-initiated** and focused on uncovering **hidden threats**, **early-stage intrusions**, or **advanced adversary behaviors**.

---

## 🎯 Objectives of Network Hunting

- Detect threats missed by automated tools (e.g., zero-day malware, slow-and-low C2, lateral movement)
- Identify anomalies and weak signals across traffic patterns
- Validate the presence (or absence) of compromise
- Improve detection logic and threat intelligence feedback loops
- Harden infrastructure based on findings (shift from detection to prevention)

---

## 🧠 The Hunter’s Mindset

> "Threat hunting is more about asking the right questions than having the right tools."

A successful hunter is:
- **Curious** – willing to explore strange patterns and follow rabbit holes
- **Skeptical** – doesn’t take benign-looking traffic at face value
- **Tactical** – hunts with purpose, using structured methods
- **Analytical** – capable of extracting signal from noise

---

## ⚔️ Hunting vs. Detection Engineering

| Aspect              | Threat Hunting                          | Detection Engineering                  |
|---------------------|------------------------------------------|----------------------------------------|
| Trigger             | Hypothesis or anomaly                    | Alert or known signature               |
| Output              | Observations, insights, new detections   | Rules, queries, signatures             |
| Frequency           | Periodic, proactive                      | Continuous, reactive                   |
| Approach            | Exploratory, iterative                   | Structured, codified                   |

---

## 🔗 Network Hunting in the Cyber Kill Chain

Network hunting is often aligned to the **Cyber Kill Chain** or **MITRE ATT&CK** framework. Many hunts focus on identifying:

- **Reconnaissance**: DNS tunneling, mass scanning
- **Weaponization/Delivery**: Malicious payloads in HTTP/S, phishing artifacts
- **Exploitation/Installation**: Exploit kits, callback domains
- **Command & Control (C2)**: Beaconing, rare JA3 hashes, encrypted tunnels
- **Actions on Objectives**: Data exfiltration, lateral movement

---

## 🛠 What You'll Learn in This Playbook

This playbook is broken into topic-based sections designed to sharpen your ability to:

- Identify malicious DNS, HTTP, and TLS traffic
- Analyze NetFlow, Zeek, PCAP, and other network logs
- Use tools like Wireshark, tshark, and Zeek effectively
- Create and test hypotheses using real-world datasets
- Pivot off IOCs and behavioral anomalies
- Integrate threat intelligence into your hunts

Each section will include:
- Detection logic
- Sample queries or tools
- Realistic use cases
- Links to hands-on labs (when available)

---

## ✅ Prerequisites

To follow this playbook effectively, you should be comfortable with:

- Basic network protocols (DNS, HTTP, TLS, TCP/IP)
- Using CLI tools (grep, jq, tcpdump, etc.)
- Operating in a Linux or VM-based lab environment

If you're new to these concepts, see the `docs/setup.md` guide or start with beginner labs in `labs/network`.

---

🧵 *Move on to [01_hunting_methodology.md](01_hunting_methodology.md) to learn how to structure your hunts with repeatable frameworks and techniques.*
