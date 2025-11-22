# Recondite v2

```
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗████████╗███████╗    ██╗   ██╗██████╗ 
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║╚══██╔══╝██╔════╝    ██║   ██║╚════██╗
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║██║   ██║   █████╗      ██║   ██║ █████╔╝
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██║   ██║   ██╔══╝      ╚██╗ ██╔╝██╔═══╝ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║   ██║   ███████╗     ╚████╔╝ ███████╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝   ╚═╝   ╚══════╝      ╚═══╝  ╚══════╝
                                                                           v2.0   by: .W4R 
```

**Recondite v2** is a comprehensive reconnaissance pipeline for offensive security, bug bounty hunting, and asset discovery. It follows a funnel-based methodology from infrastructure discovery to vulnerability identification.

## Overview

Recondite v2 implements a complete reconnaissance workflow:

> **Infra / ASN → Cloud & Certs → Subdomains → Ports → HTTP → WAF/403 → Content & JS → CORS/CSP → Logins & vulns → Reporting**

The tool is designed to be:
- **Non-interactive**: Runs end-to-end without user prompts
- **Modular**: Each phase is implemented as an independent function
- **Configurable**: Supports passive mode, custom delays, random user agents, and more
- **Comprehensive**: Integrates 18+ specialized reconnaissance tools

## Integrated Tools

| Tool | Purpose | Phase |
|------|---------|-------|
| [asnmap](https://github.com/projectdiscovery/asnmap) | ASN to IP range mapping | ASN/Infra |
| [ipranges](https://github.com/lord-alfred/ipranges) | Cloud provider IP ranges | Cloud & Certs |
| [Caduceus](https://github.com/g0ldencybersec/Caduceus) | Certificate discovery | Cloud & Certs |
| [gungnir](https://github.com/g0ldencybersec/gungnir) | Certificate monitoring | Cloud & Certs |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | Subdomains |
| [bbot](https://github.com/blacklanternsecurity/bbot) | Deep subdomain enumeration | Subdomains |
| [naabu](https://github.com/projectdiscovery/naabu) | Active port scanning | Ports |
| [Smap](https://github.com/s0md3v/Smap) | Passive port scanning (Shodan) | Ports |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing & fingerprinting | HTTP |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | WAF detection | WAF/403 |
| [403jump](https://github.com/trap-bytes/403jump) | 403 bypass attempts | WAF/403 |
| [gau](https://github.com/lc/gau) | Historical URL discovery | Content & JS |
| [cariddi](https://github.com/edoardottt/cariddi) | Endpoint & parameter discovery | Content & JS |
| [JSMap-Inspector](https://github.com/ynsmroztas/JSMap-Inspector) | JavaScript analysis | Content & JS |
| [Corsy](https://github.com/s0md3v/Corsy) | CORS misconfiguration detection | Policies |
| [CSP-Stalker](https://github.com/0xakashk/CSP-Stalker) | Content Security Policy analysis | Policies |
| [favicorn](https://github.com/sharsil/favicorn) | Favicon fingerprinting | Policies |
| [Logsensor](https://github.com/Mr-Robert0/Logsensor) | Login panel detection | Logins & Vulns |
| [cvemap](https://github.com/projectdiscovery/cvemap) | CVE mapping by technology | Logins & Vulns |

## Requirements

- **OS**: Linux (Kali Linux, Ubuntu, etc.) or macOS
- **Bash**: Version 4.0 or higher
- **Dependencies**: Go, Python 3, jq (for JSON processing)
- **Tools**: All tools will be installed by `install.sh`

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/W4RRR/recondite_v2.git
   cd recondite_v2
   ```

2. **Give execution permissions**:
   ```bash
   chmod +x recondite_v2.sh install.sh
   ```

3. **Run the installer**:
   ```bash
   ./install.sh
   ```
   
   The installer will:
   - Clone all required tool repositories into `tools/`
   - Install dependencies (Go tools, Python packages)
   - Set up configuration files
   - **Note**: Some steps may require `sudo` (e.g., `apt install`). The installer will print commands for you to run manually.

4. **Configure API keys** (optional but recommended):
   ```bash
   cp config/apikeys.example.env config/apikeys.env
   nano config/apikeys.env  # Edit with your API keys
   
   # Fix line endings if edited on Windows
   dos2unix config/apikeys.env
   ```
   
   **Note**: If you edit `apikeys.env` on Windows and transfer to Linux, run `dos2unix config/apikeys.env` to fix line endings, otherwise you'll get `$'\r': command not found` errors.

## Usage

### Basic Usage

```bash
# Single domain reconnaissance
./recondite_v2.sh -d example.com --full -o reports

# Full reconnaissance on domains from scope.txt
./recondite_v2.sh -d scope.txt --full -o reports

# Passive-only reconnaissance
./recondite_v2.sh -d scope.txt --passive -o reports_passive

# With cloud & certificates phase
./recondite_v2.sh -d scope.txt --cloud --full -o reports
```

### Advanced Options

```bash
# With ASN file
./recondite_v2.sh -d scope.txt -a asns.txt --full -o reports

# Custom threads and delays
./recondite_v2.sh -d scope.txt --full \
    --threads-httpx 100 \
    --threads-naabu 2000 \
    --delay 0.5 \
    -o reports

# Random user agent rotation
./recondite_v2.sh -d scope.txt --full -ua -o reports

# Verbose mode
./recondite_v2.sh -d scope.txt --full -v -o reports

# Update tools only
./recondite_v2.sh --update
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-d, --domains DOMAIN\|FILE` | **Required**. Single domain (e.g., `example.com`) or file with domains (one per line) |
| `-a, --asn FILE` | File with list of ASNs (e.g. `AS1234`) |
| `-o, --output DIR` | Base output directory for reports (default: `./reports`) |
| `--cloud` | Enable cloud/CDN & certs phase |
| `--full` | Run all phases end-to-end |
| `--passive` | Passive-only mode (disable active scanning) |
| `--threads-httpx INT` | Threads for httpx (default: 50) |
| `--threads-naabu INT` | Threads for naabu (default: 1000) |
| `-ua, --random-ua` | Enable random User-Agent rotation |
| `--delay SECONDS` | Fixed delay between operations (can be fractional) |
| `--delay-random MIN-MAX` | Random delay range (e.g. `0.3-0.9`) |
| `-v, --verbose` | Verbose mode (extra logs) |
| `-up, --update` | Update mode (update tools and exit) |
| `-h, --help` | Show help message |

## Output Structure

### Per-Target Raw Data

Each target gets a directory under `recon/<target>/`:

```
recon/
└── example.com/
    ├── 01_asn_ips/          # ASN to IP mappings
    ├── 02_cloud_certs/       # Cloud ranges, certificates
    ├── 03_subdomains/        # Subdomain enumeration results
    ├── 04_ports/             # Port scanning results
    ├── 05_http/              # HTTP probing results
    ├── 06_waf_403/           # WAF detection, 403 bypasses
    ├── 07_content_js/        # URLs, endpoints, JS analysis
    ├── 08_policies/          # CORS, CSP, favicon results
    ├── 09_logins_vulns/      # Login panels, CVE mappings
    └── logs/                  # Execution logs
```

### Consolidated Reports

Reports are generated in the output directory (`-o`):

- `report.html` - **Colorful HTML dashboard** with:
  - Subdomain listing with HTTP status codes (color-coded)
  - WAF detection status
  - Login panel locations
  - CORS/CSP misconfigurations
  - Sensitive files discovered
  - Bypassed 403s
  - CVE candidates by technology
- `report.txt` - Text summary
- `report.md` - Markdown summary
- `report.csv` - CSV export for analysis
- `run.log` - Execution log

## Configuration

### ASN Discovery

To discover ASNs (Autonomous System Numbers) for your target organization:

1. **Using bgp.he.net**: Visit [Hurricane Electric BGP Toolkit](http://bgp.he.net) and search for your target organization name or domain
2. **Identify ASNs**: Look for ASN numbers (e.g., `AS13335` for Cloudflare)
3. **Create ASN file**: Add discovered ASNs to `asns.txt` (one per line):
   ```
   AS13335
   AS14618
   AS16509
   ```
4. **Run with ASN mapping**: Use the `-a` flag to include ASN to IP range mapping:
   ```bash
   ./recondite_v2.sh -d example.com -a asns.txt --full -o reports
   ```

The tool will use [asnmap](https://github.com/projectdiscovery/asnmap) to convert ASNs to IP ranges, which helps identify all network blocks owned by the target organization for comprehensive reconnaissance.

### Cloud Provider Identification

Recondite v2 includes an extensive IP ranges database (`ipranges_with_names.txt`) with **213,000+ entries** mapping IP ranges to cloud providers:

- **Automatic Detection**: During HTTP probing, the tool automatically identifies which cloud provider hosts each discovered service
- **Supported Providers**: Amazon/AWS, Google Cloud, Azure, Oracle, Cloudflare, DigitalOcean, Linode, Vultr, Hetzner, and many more
- **Enriched Reports**: All reports (HTML, CSV, TXT, MD) include cloud provider information
- **Infrastructure Insights**: Understand your target's cloud infrastructure at a glance

The database is used automatically—no configuration needed. The tool will:
1. Extract IPs from HTTP probing results
2. Match each IP against the cloud provider database
3. Generate statistics and detailed mappings
4. Include provider information in all reports

**Benefits**:
- Identify hosting patterns (multi-cloud, single provider)
- Prioritize targets based on cloud provider
- Understand attack surface distribution
- Export data with provider info for further analysis

### API Keys

Create `config/apikeys.env` from the example:

```bash
cp config/apikeys.example.env config/apikeys.env
nano config/apikeys.env  # Edit with your actual API keys

# Important: Fix line endings if edited on Windows
dos2unix config/apikeys.env
```

**API Key Format**: All API keys must be enclosed in double quotes:
```bash
export SHODAN_API_KEY="your_actual_key_here"
export GITHUB_TOKEN="ghp_your_github_token"
```

Key API keys to configure:
- **PDCP_API_KEY**: For asnmap, cvemap (ProjectDiscovery Cloud Platform)
- **SHODAN_API_KEY**: For Smap passive port scanning
- **GITHUB_TOKEN**: For subfinder, bbot (optional but recommended)

**Troubleshooting**: If you see `$'\r': command not found` errors, your file has Windows line endings. Fix with:
```bash
sudo apt install dos2unix -y
dos2unix config/apikeys.env
```

### Passive Mode

When `--passive` is enabled:
- Active port scanning (naabu) is **disabled**
- Intrusive modules (e.g., Logsensor SQLi) are **disabled**
- Only passive enumeration and detection runs

### Delays

Control the rate of requests:
- `--delay 0.5`: Fixed 0.5 second delay between operations
- `--delay-random 0.3-0.9`: Random delay between 0.3 and 0.9 seconds

### User Agents

Enable random user agent rotation with `-ua` to avoid detection patterns.

## Examples

### Example 1: Full Reconnaissance

```bash
./recondite_v2.sh -d scope.txt --full -o reports
```

Runs all phases on all domains in `scope.txt`, generates reports in `reports/`.

### Example 2: Passive Reconnaissance

```bash
./recondite_v2.sh -d scope.txt --passive -o reports_passive
```

Runs passive-only reconnaissance (no active port scanning, no intrusive modules).

### Example 3: With ASN and Cloud Discovery

```bash
./recondite_v2.sh -d scope.txt -a asns.txt --cloud --full -o reports
```

Includes ASN mapping and cloud/certificate discovery phases.

### Example 4: Verbose with Custom Settings

```bash
./recondite_v2.sh -d scope.txt --full \
    -v \
    -ua \
    --delay-random 0.3-0.9 \
    --threads-httpx 100 \
    -o reports
```

Runs with verbose output, random user agents, random delays, and custom thread counts.

## Workflow Phases

1. **ASN / Infrastructure**: Map ASNs to IP ranges
2. **Cloud & Certs**: Discover cloud providers, certificates, SANs
3. **Subdomain Enumeration**: Passive + active subdomain discovery
4. **Port Scanning**: Active (naabu) + passive (Smap/Shodan) port discovery
5. **HTTP Probing**: Fingerprint HTTP services, extract metadata
6. **WAF / 403 Bypass**: Detect WAFs, attempt 403 bypasses
7. **Content & JS**: Historical URLs (GAU), endpoints (cariddi), JS analysis
8. **Policies**: CORS, CSP, favicon fingerprinting
9. **Logins & Vulns**: Login panel detection, CVE mapping

## Troubleshooting

### Tools Not Found

If a tool is not found, run:
```bash
./recondite_v2.sh --update
```

Or manually run `install.sh` to reinstall tools.

### Missing API Keys

Some tools work without API keys but with limited functionality:
- **Smap**: Requires SHODAN_API_KEY for passive scanning
- **asnmap/cvemap**: Works better with PDCP_API_KEY
- **subfinder/bbot**: More sources with API keys (GitHub, SecurityTrails, etc.)

### Permission Errors

Some tools may require specific permissions:
- Port scanning may require elevated privileges (use `sudo` if needed)
- File system access for writing results

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for **authorized security testing only**. Only use on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

## Author

**.W4R** - Advanced Reconnaissance Pipeline v2.0

---

For issues, questions, or contributions, please open an issue on GitHub.

