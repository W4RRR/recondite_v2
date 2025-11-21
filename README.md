# Recondite v2 - Advanced Reconnaissance Pipeline

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗████████╗███████╗    ██╗   ██╗██████╗ 
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║╚══██╔══╝██╔════╝    ██║   ██║╚════██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║██║   ██║   █████╗      ██║   ██║ █████╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██║   ██║   ██╔══╝      ╚██╗ ██╔╝██╔═══╝ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║   ██║   ███████╗     ╚████╔╝ ███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝   ╚═╝   ╚══════╝      ╚═══╝  ╚══════╝
                                                                           v2.0  by: .W4R
```

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Recondite v2** is a comprehensive, funnel-based reconnaissance tool designed for offensive security professionals. It follows a systematic approach: starting from the broadest scope (ASN/Infrastructure), moving to asset enumeration (Subdomains), filtering live services (Ports/HTTP), and ending with deep analysis (JS, Endpoints, Specific Vulnerabilities).

## 🎯 Features

- **Funnel Methodology**: Systematic reconnaissance from broad to specific
- **Modular Architecture**: Each phase is independent and can be customized
- **Intermediate Results**: All findings are saved for audit purposes
- **Multiple Report Formats**: HTML (visual), TXT, Markdown, and CSV
- **Passive Mode**: Option to run without active scanning
- **Random User Agents**: Built-in rotation to avoid detection
- **Configurable Delays**: Random delays between requests (0.3-0.9 seconds)
- **API Key Management**: Centralized configuration file
- **No Sudo Required**: Designed to run without elevated privileges

## 📋 Table of Contents

- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Usage](#usage)
- [Pipeline Phases](#pipeline-phases)
- [Output Structure](#output-structure)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## 🔧 Installation

### Quick Installation (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/W4RRR/recondite_v2
cd recondite_v2
```

Or download the repository as a ZIP file and extract it.

2. Make scripts executable:
```bash
chmod +x recondite_v2.sh install.sh
```

3. Run the automatic installation script:
```bash
./install.sh
```

This script will:
- Check for prerequisites (Go, Python3, pip3, gcc)
- Install all Go tools from source or via `go install`
- Install all Python tools and their dependencies
- Create a local `bin/` directory with all tools
- Verify installation and provide next steps

4. Add tools to your PATH (add to `~/.bashrc` or `~/.zshrc`):
```bash
export PATH="$PWD/bin:$PATH"
```

Or if you installed to a different location:
```bash
export PATH="/path/to/recondite_v2/bin:$PATH"
```

5. Configure API keys (see [Configuration](#-configuration))

### Manual Installation

If you prefer to install tools manually, see [Prerequisites](#prerequisites) for individual tool installation instructions.

## 📦 Prerequisites

Recondite v2 integrates with multiple reconnaissance tools. Install the following tools and ensure they are in your `$PATH`:

### Core Tools (Required)

- **[subfinder](https://github.com/projectdiscovery/subfinder)** - Fast subdomain enumeration
  ```bash
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```

- **[httpx](https://github.com/projectdiscovery/httpx)** - HTTP probing and technology detection
  ```bash
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  ```

### Recommended Tools

- **[asnmap](https://github.com/projectdiscovery/asnmap)** - ASN discovery
  ```bash
  go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
  ```

- **[naabu](https://github.com/projectdiscovery/naabu)** - Fast port scanner
  ```bash
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  ```

- **[bbot](https://github.com/blacklanternsecurity/bbot)** - Deep OSINT enumeration
  ```bash
  pip install bbot
  ```

- **[Smap](https://github.com/s0md3v/Smap)** - Shodan-based passive port scanning
  ```bash
  git clone https://github.com/s0md3v/Smap.git
  cd Smap && pip install -r requirements.txt
  ```

- **[wafw00f](https://github.com/EnableSecurity/wafw00f)** - WAF detection
  ```bash
  pip install wafw00f
  ```

- **[cariddi](https://github.com/edoardottt/cariddi)** - Parameter and endpoint discovery
  ```bash
  go install -v github.com/edoardottt/cariddi@latest
  ```

- **[gau](https://github.com/lc/gau)** - Get All URLs from Wayback Machine
  ```bash
  go install github.com/lc/gau/v2/cmd/gau@latest
  ```

- **[403jump](https://github.com/trap-bytes/403jump)** - 403 bypass attempts
  ```bash
  git clone https://github.com/trap-bytes/403jump.git
  cd 403jump && pip install -r requirements.txt
  ```

- **[Corsy](https://github.com/s0md3v/Corsy)** - CORS vulnerability scanner
  ```bash
  git clone https://github.com/s0md3v/Corsy.git
  cd Corsy && pip install -r requirements.txt
  ```

- **[Logsensor](https://github.com/Mr-Robert0/Logsensor)** - Login panel detection
  ```bash
  git clone https://github.com/Mr-Robert0/Logsensor.git
  cd Logsensor && pip install -r requirements.txt
  ```

- **[favicorn](https://github.com/sharsil/favicorn)** - Favicon fingerprinting
  ```bash
  go install github.com/sharsil/favicorn@latest
  ```

- **[ipranges](https://github.com/lord-alfred/ipranges)** - Cloud infrastructure detection
  ```bash
  go install github.com/lord-alfred/ipranges@latest
  ```

- **[JSMap-Inspector](https://github.com/ynsmroztas/JSMap-Inspector)** - JavaScript analysis
  ```bash
  git clone https://github.com/ynsmroztas/JSMap-Inspector.git
  cd JSMap-Inspector && pip install -r requirements.txt
  ```

- **[CSP-Stalker](https://github.com/0xakashk/CSP-Stalker)** - CSP header analysis
  ```bash
  git clone https://github.com/0xakashk/CSP-Stalker.git
  cd CSP-Stalker && pip install -r requirements.txt
  ```

- **[cvemap](https://github.com/projectdiscovery/cvemap)** - CVE mapping
  ```bash
  go install -v github.com/projectdiscovery/cvemap/cmd/cvemap@latest
  ```

- **[Caduceus](https://github.com/g0ldencybersec/Caduceus)** - Cloud bucket enumeration
  ```bash
  git clone https://github.com/g0ldencybersec/Caduceus.git
  cd Caduceus && pip install -r requirements.txt
  ```

## ⚙️ Configuration

1. Edit the API keys configuration file:
```bash
nano config/api_keys.conf
```

2. Add your API keys (at minimum, Shodan API key for passive scanning):
```bash
SHODAN_API_KEY=your_shodan_api_key_here
GITHUB_TOKEN=your_github_token_here
# ... etc
```

3. Configure subfinder providers (optional but recommended):
```bash
subfinder -pc ~/.config/subfinder/provider-config.yaml
```

## 🚀 Usage

### Basic Usage

```bash
./recondite_v2.sh -t example.com -o ./results
```

### Passive Mode

Run without active scanning (only passive enumeration):

```bash
./recondite_v2.sh -t example.com -o ./results --passive
```

### With Full URL

```bash
./recondite_v2.sh -t https://example.com -o ./recon_results
```

### Update Information

View tool update information:

```bash
./recondite_v2.sh --update
```

### Help

```bash
./recondite_v2.sh --help
```

## 🔄 Pipeline Phases

### Phase 0: ASN & Infrastructure Discovery

- **Tools**: `asnmap`, `ipranges`
- **Purpose**: Map ASN information and detect cloud infrastructure (AWS, GCP, Azure)
- **Output**: `asn_results.txt`, `cloud_ranges.txt`

### Phase 1: Subdomain Discovery

- **Tools**: `subfinder`, `bbot`
- **Purpose**: Horizontal enumeration of subdomains
- **Output**: `all_subdomains.txt`
- **Note**: `bbot` runs in passive mode to complement `subfinder`

### Phase 2: Port Scanning & Resolution

- **Tools**: `Smap` (passive), `naabu` (active)
- **Purpose**: Identify open ports and filter alive hosts
- **Output**: `alive_hosts.txt`, `all_ports.txt`
- **Logic**: Uses Shodan API first (passive), then validates with active scanning

### Phase 3: HTTP Probing & Technology Detection

- **Tools**: `httpx`, `wafw00f`, `favicorn`
- **Purpose**: Convert IPs/ports to URLs, detect WAFs, fingerprint technologies
- **Output**: `http_urls.txt`, `waf_results.txt`, `favicorn_results.txt`, `403_urls.txt`

### Phase 4: Deep Crawling & Data Mining

- **Tools**: `gau`, `cariddi`, `JSMap-Inspector`, `CSP-Stalker`
- **Purpose**: Extract URLs, discover endpoints, analyze JavaScript, check CSP headers
- **Output**: `gau_sensitive_files.txt`, `cariddi_results.txt`, `jsmap_results.txt`

### Phase 5: Vulnerability Scanning

- **Tools**: `403jump`, `Corsy`, `Logsensor`, `cvemap`, `Caduceus`
- **Purpose**: Test specific vulnerabilities (403 bypass, CORS, login panels, CVEs, cloud buckets)
- **Output**: `403_bypass_results.txt`, `cors_results.txt`, `login_panels.txt`

## 📁 Output Structure

```
results/
├── report.html              # Visual HTML report
├── report.txt               # Text report
├── report.md                # Markdown report
├── report.csv               # CSV report
├── execution.log            # Detailed execution log
│
├── Phase 0: Infrastructure
│   ├── asn_results.txt
│   └── cloud_ranges.txt
│
├── Phase 1: Subdomains
│   ├── subfinder_results.txt
│   ├── bbot_subdomains.txt
│   └── all_subdomains.txt
│
├── Phase 2: Ports
│   ├── smap_results.txt
│   ├── naabu_results.txt
│   ├── all_ports.txt
│   └── alive_hosts.txt
│
├── Phase 3: HTTP
│   ├── httpx_results.txt
│   ├── httpx_results.json
│   ├── http_urls.txt
│   ├── waf_results.txt
│   ├── favicorn_results.txt
│   └── 403_urls.txt
│
├── Phase 4: Deep Crawling
│   ├── gau_sensitive_files.txt
│   ├── cariddi_results.txt
│   ├── jsmap_results.txt
│   └── csp_results.json
│
└── Phase 5: Vulnerabilities
    ├── 403_bypass_results.txt
    ├── cors_results.txt
    ├── login_panels.txt
    └── cloud_buckets.txt
```

## 📊 Report Features

### HTML Report

The HTML report includes:
- **Visual Statistics Dashboard**: Color-coded metrics
- **Subdomain Table**: With status codes, WAF detection, and login panel indicators
- **HTTP Services Table**: URLs, status codes (color-coded by family), titles, servers
- **Key Findings Section**: Login panels, CORS vulnerabilities, sensitive files
- **Responsive Design**: Modern, gradient-based UI

### Text Report

Plain text summary with:
- Statistics overview
- Subdomain list
- Key findings
- Formatted for easy reading

### Markdown Report

Structured Markdown format suitable for:
- Documentation
- GitHub issues
- Team sharing

### CSV Report

Machine-readable format for:
- Data analysis
- Import into other tools
- Automated processing

## 💡 Examples

### Example 1: Basic Reconnaissance

```bash
./recondite_v2.sh -t example.com -o ./example_recon
```

This will:
1. Discover ASN and cloud infrastructure
2. Enumerate subdomains
3. Scan for open ports
4. Probe HTTP services
5. Perform deep crawling
6. Scan for vulnerabilities
7. Generate all report formats

### Example 2: Passive Reconnaissance

```bash
./recondite_v2.sh -t example.com -o ./passive_recon --passive
```

This will:
- Skip active port scanning (naabu)
- Skip active bbot enumeration
- Use only passive methods (Shodan API, subfinder, etc.)

### Example 3: Full URL Target

```bash
./recondite_v2.sh -t https://example.com -o ./full_recon
```

The script automatically extracts the domain from the URL.

## 🔍 Key Features Explained

### Random User Agents

The script rotates through multiple user agents to avoid detection:
- Chrome (Windows, macOS, Linux)
- Firefox
- Safari

### Configurable Delays

Random delays between requests (0.3-0.9 seconds) help:
- Avoid rate limiting
- Reduce WAF blocking
- Mimic human behavior

### 403 Bypass Logic

Instead of testing all URLs for 403 bypasses, the script:
1. First identifies URLs returning 403
2. Creates a filtered list (`403_urls.txt`)
3. Only tests those specific URLs with `403jump`

This saves time and reduces WAF noise.

### Cloud Infrastructure Detection

The script uses `ipranges` to:
- Detect if targets are hosted on AWS, GCP, or Azure
- Adjust scanning aggressiveness accordingly
- Identify cloud-specific attack surfaces

## 🛠️ Troubleshooting

### Tool Not Found

If you see "Tool 'X' not found":
1. Ensure the tool is installed and in your `$PATH`
2. Or place the tool binary in the `tools/` directory
3. Check the tool's installation documentation

### API Key Issues

If passive scanning fails:
1. Verify your API keys in `config/api_keys.conf`
2. Check API key permissions and quotas
3. Some tools require additional configuration files

### Permission Errors

The script is designed to run without `sudo`. If you encounter permission errors:
1. Check file permissions in the output directory
2. Ensure you have write access to the output location
3. Some tools may require specific permissions (check individual tool docs)

### Empty Results

If results are empty:
1. Check the execution log: `results/execution.log`
2. Verify the target domain is valid
3. Ensure you have internet connectivity
4. Check if tools are functioning correctly (test individually)

## 📝 Notes

- **Gungnir**: This tool is designed for continuous monitoring (daemon mode). For one-shot reconnaissance, it's recommended to run Gungnir separately and analyze its historical data.

- **Rate Limiting**: The script includes delays and rate limiting, but be mindful of:
  - API quotas (Shodan, VirusTotal, etc.)
  - Target server rate limits
  - Your network bandwidth

- **Legal Use**: This tool is for authorized security testing only. Always ensure you have explicit permission before scanning any target.

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

Recondite v2 integrates with many excellent open-source tools. Special thanks to:
- ProjectDiscovery team (subfinder, httpx, naabu, asnmap, cvemap)
- s0md3v (Smap, Corsy)
- Black Lantern Security (bbot)
- And all other tool developers

## 📧 Contact

For issues, questions, or suggestions, please open an issue on GitHub.

---

**Remember**: Always use this tool responsibly and only on systems you own or have explicit permission to test.


