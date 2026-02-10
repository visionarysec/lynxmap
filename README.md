# LynxMap

**OCI Attack Surface Management Dashboard**

LynxMap is a modular security tool designed to help security teams understand and explore attack surface maps for Oracle Cloud Infrastructure (OCI).

## Features

- 📊 **Dashboard Overview** - High-level asset inventory with bar charts and risk scoring
- 🎯 **Attack Surface Visualization** - Interactive sunburst charts mapping resource relationships and blast radius
- 📋 **Security Playbooks** - YAML-based security checks (CIS OCI Benchmarks) with automated scanning
- 🔍 **Exposure Analysis** - Identify publicly exposed resources and potential attack paths


## Quick Start

1. **Install dependencies:**
   ```bash
   cd lynxmap
   pip install -r requirements.txt
   ```

2. **Configure Environment:**
### OCI Credentials
   The tool automatically fetches your OCI credentials from the standard SDK configuration file. Ensure you have a valid config file at:
   - `~/.oci/config` (Linux/Mac)
   - `%UserProfile%\.oci\config` (Windows)
   
   The tool uses the `[DEFAULT]` profile. If no configuration is found, the application will automatically fall back to **Mock Data Mode** for demonstration.

   ### Application Settings
   Copy the example environment file to configure web server settings:
   ```bash
   cp .env.example .env
   ```
   
   The `.env` file supports the following options:
   
   | Variable | Description | Default |
   |----------|-------------|---------|
   | `LYNXMAP_DEBUG` | Enable debug mode for development | `true` |
   | `LYNXMAP_PORT` | Port to run the web server on | `8050` |
   | `LYNXMAP_HOST` | Host address to bind to | `127.0.0.1` |

3. **Run the application:**
   ```bash
   cd ui
   python app.py
   ```

4. **Open in browser:**
   Navigate to `http://127.0.0.1:8050`

## Technology Stack

- **Framework:** Plotly Dash (Python)
- **Visualizations:** Plotly (Sunburst, Bar, Gauge charts)
- **UI Components:** Dash Bootstrap Components
- **Cloud SDK:** OCI Python SDK
- **Configuration:** YAML playbooks, dotenv

## Roadmap

- **Phase 1:** ✅ Multi-page app architecture
- **Phase 2:** 🔄 Playbook scanning with CIS benchmarks
- **Phase 3:** 🔜 Automated risk scoring and alerting
- **Phase 4:** 🔜 Multi-cloud support (AWS, Azure, GCP)

## License

MIT License
