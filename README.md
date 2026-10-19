# 🛡️ LogSentinel-Lite // Enterprise SOC Log Analyzer

[🇺🇸 English](#english) | [🇪🇸 Español](#español)

---

<a name="english"></a>
## 🇺🇸 English

**LogSentinel-Lite** is a lightweight, professional-grade security log analysis and threat intelligence platform designed for Blue Team operations and SOC automation. Inspired by enterprise vulnerability management consoles (such as DefectDojo), it parses raw system telemetry streams using optimized regular expressions to detect active threat vectors and system anomalies.

> *Note: This project was built entirely through **vibecoding** and AI-assisted development workflows, demonstrating modern rapid-prototyping and engineering velocity.*

### 🚀 Key Features
- **Enterprise Dashboard Interface:** Clean, dark-mode analytics platform built with Streamlit, featuring KPI metric summary cards (Critical, High, Medium risks) and structured data tables.
- **Advanced Heuristics Engine:** Native Python regex-powered detection covering multiple security domains.
- **Export Capabilities:** Instant JSON threat intelligence export for downstream SIEM or ticketing integrations.
- **Zero Heavy Dependencies:** Built using pure Python standard libraries alongside robust data handling (`pandas`).

### 📋 Supported Detection Rules
1. **SSH Brute Force:** Identifies repeated authentication failures from malicious source IPs.
2. **Web 403 Forbidden Scans:** Detects directory fuzzing and unauthorized administrative path probes against Nginx/Apache web servers.
3. **Multi-Source Authentication (Impossible Travel / Credential Compromise):** Flags successful logins originating from multiple distinct source locations/IPs.
4. **Privilege Escalation Failures:** Tracks repeated authentication errors during `sudo` executions.
5. **Web Login Form Brute Force:** Monitors malicious `POST` requests failing with `401/403` status codes against authentication endpoints.
6. **Internal Server Errors (HTTP 500):** Identifies traffic spikes resulting in server crashes or potential injection payloads.
7. **System Daemons / Service Crashes:** Captures critical kernel flags, fatal drops, and segment faults.

### ⚙️ Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR-USERNAME/logsentinel-lite.git](https://github.com/YOUR-USERNAME/logsentinel-lite.git)
   cd logsentinel-lite

