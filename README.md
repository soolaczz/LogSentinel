# 🛡️ LogSentinel-Lite

<p align="center">
  <b>Enterprise SOC Log Telemetry & Threat Detection Engine</b><br>
  <i>A lightweight, professional-grade security log parser inspired by enterprise vulnerability management consoles.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Streamlit-Enterprise-red.svg" alt="Streamlit">
  <img src="https://img.shields.io/badge/Security-Blue%20Team-green.svg" alt="Blue Team">
  <img src="https://img.shields.io/badge/Development-Vibecoding%20%2F%20AI-purple.svg" alt="AI Assisted">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg" alt="License">
</p>

<p align="center">
  <a href="#-english">🇺🇸 English</a> | <a href="#-español">🇪🇸 Español</a>
</p>

---

<a name="-english"></a>
## English

**LogSentinel-Lite** is an enterprise-grade log telemetry and threat intelligence platform built for Blue Team operations and SOC automation. Inspired by modern vulnerability management consoles (such as DefectDojo), it parses raw system logs using optimized regular expressions to surface active threat vectors and system anomalies instantly via an interactive dashboard.

> *Note: This project was engineered entirely through **vibecoding** and AI-assisted development workflows, demonstrating modern rapid prototyping and software engineering velocity.*

### 🚀 Key Features
- **Enterprise Dashboard UI:** A clean, dark-mode analytics console built with Streamlit featuring KPI summary cards (Critical, High, Medium risks) and structured data tables.
- **Advanced Heuristics Engine:** Native Python regex pattern-matching covering multi-domain security indicators.
- **Instant JSON Export:** Export structured threat intelligence payloads for downstream SIEM or ticketing system integrations.
- **Zero Heavy Dependencies:** Built using Python's standard libraries alongside efficient data handling (`pandas`).

### 📋 Supported Detection Rules
1. **SSH Brute Force:** Identifies repeated authentication failures originating from malicious source IPs.
2. **Web 403 Forbidden Scans:** Detects directory fuzzing and unauthorized administrative path probes against web servers (Nginx/Apache).
3. **Multi-Source Authentication (Impossible Travel / Credential Compromise):** Flags successful logins originating from multiple distinct source locations/IPs.
4. **Privilege Escalation Failures:** Tracks repeated authentication errors during `sudo` execution attempts.
5. **Web Login Form Brute Force:** Monitors malicious `POST` requests failing with `401/403` status codes against authentication endpoints.
6. **Internal Server Errors (HTTP 500):** Identifies traffic spikes resulting in server errors or potential injection payload fuzzing.
7. **System Daemons / Service Crashes:** Captures critical kernel flags, fatal drops, and segmentation faults.

### ⚙️ Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/soolaczz/logsentinel-lite.git](https://github.com/soolaczz/logsentinel-lite.git)
   cd logsentinel-lite

   ```

2. **Set up a virtual environment and install dependencies:**
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1   # On Windows PowerShell
python -m pip install --upgrade pip
pip install streamlit pandas

```


3. **Run the platform:**
```bash
python -m streamlit run src/analyzer.py

```



---

## Español

**LogSentinel-Lite** es una plataforma de telemetría de registros y inteligencia de amenazas de nivel empresarial diseñada para operaciones de Blue Team y automatización de SOC. Inspirada en consolas corporativas de gestión de vulnerabilidades (como DefectDojo), analiza registros de sistemas mediante expresiones regulares optimizadas para detectar vectores de amenazas activos y anomalías a través de un panel interactivo.

> *Nota: Este proyecto fue desarrollado en su totalidad mediante **vibecoding** y flujos de trabajo asistidos por IA, demostrando prototipado rápido moderno y velocidad de ingeniería de software.*

### 🚀 Características Principales

* **Interfaz de Panel Empresarial:** Una consola analítica limpia en modo oscuro construida con Streamlit, que incluye tarjetas de resumen KPI (riesgos Críticos, Altos y Medios) y tablas de datos estructuradas.
* **Motor Heurístico Avanzado:** Coincidencia de patrones basada en expresiones regulares nativas de Python que cubren indicadores de seguridad de múltiples dominios.
* **Exportación Instantánea en JSON:** Permite exportar cargas de inteligencia de amenazas estructuradas para integraciones con SIEM o sistemas de tickets.
* **Sin Dependencias Pesadas:** Construido utilizando bibliotecas estándar de Python junto con un manejo eficiente de datos (`pandas`).

### 📋 Reglas de Soportadas

1. **Fuerza Bruta SSH:** Identifica fallos de autenticación repetidos originados desde IPs maliciosas.
2. **Escaneos Web 403 Forbidden:** Detecta *fuzzing* de directorios y sondeos de rutas administrativas no autorizadas en servidores web (Nginx/Apache).
3. **Autenticación Multi-Origen (Posible Compromiso de Credenciales):** Señala inicios de sesión exitosos provenientes de múltiples ubicaciones/IPs distintas.
4. **Fallos de Escalado de Privilegios:** Rastrea errores de autenticación repetidos durante intentos de ejecución de `sudo`.
5. **Fuerza Bruta en Formularios Web:** Monitorea solicitudes `POST` maliciosas que fallan con códigos `401/403` en endpoints de autenticación.
6. **Errores Internos de Servidor (HTTP 500):** Identifica picos de tráfico que generan errores de servidor o posibles *payloads* de inyección.
7. **Daemons del Sistema / Crashes de Servicios:** Captura indicadores críticos del núcleo, caídas fatales y errores de segmentación.

### ⚙️ Instalación y Uso

1. **Clonar el repositorio:**
```bash
git clone [https://github.com/soolaczz/logsentinel-lite.git](https://github.com/soolaczz/logsentinel-lite.git)
cd logsentinel-lite

```


2. **Configurar un entorno virtual e instalar dependencias:**
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1   # En Windows PowerShell
python -m pip install --upgrade pip
pip install streamlit pandas

```


3. **Ejecutar la plataforma:**
```bash
python -m streamlit run src/analyzer.py

```
