#!/usr/bin/env bash

###############################################################################
# Recondite v2 - Advanced Reconnaissance Pipeline
# A comprehensive funnel-based reconnaissance tool for offensive security
###############################################################################

set -u
set -o pipefail

# Script version
VERSION="2.0.0"
SCRIPT_NAME="recondite_v2.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
DIM='\033[2m'

# Global variables
DOMAINS_INPUT=""
DOMAINS_FILE=""
DIRECT_DOMAIN=""
IS_DIRECT_DOMAIN=false
ASN_FILE=""
OUTPUT_DIR="./reports"
CLOUD_MODE=false
FULL_MODE=false
PASSIVE_MODE=false
THREADS_HTTPX=50
THREADS_NAABU=1000
RANDOM_UA=false
FIXED_DELAY=""
RANDOM_DELAY=""
VERBOSE=false
UPDATE_MODE=false
GLOBAL_UA=""

# User agents pool
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
)

# Tools directory
TOOLS_DIR="tools"
CONFIG_DIR="config"

###############################################################################
# ASCII Art Logo
###############################################################################

logo() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗████████╗███████╗    ██╗   ██╗██████╗ 
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║╚══██╔══╝██╔════╝    ██║   ██║╚════██╗
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║██║   ██║   █████╗      ██║   ██║ █████╔╝
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██║   ██║   ██╔══╝      ╚██╗ ██╔╝██╔═══╝ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║   ██║   ███████╗     ╚████╔╝ ███████╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝   ╚═╝   ╚══════╝      ╚═══╝  ╚══════╝
                                                                           v2.0   by: .W4R 
EOF
    echo -e "${NC}"
}

###############################################################################
# Logging Functions
###############################################################################

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${BLUE}[*]${NC} $message"
            ;;
        SUCCESS)
            echo -e "${GREEN}[+]${NC} $message"
            ;;
        WARNING)
            echo -e "${YELLOW}[!]${NC} $message"
            ;;
        ERROR)
            echo -e "${RED}[-]${NC} $message" >&2
            ;;
        DEBUG)
            if [ "$VERBOSE" = true ]; then
                echo -e "${MAGENTA}[D]${NC} $message"
            fi
            ;;
    esac
}

log_to_file() {
    local log_file="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$log_file"
}

###############################################################################
# Helper Functions
###############################################################################

get_random_ua() {
    if [ "$RANDOM_UA" = true ]; then
        local size=${#USER_AGENTS[@]}
        local index=$((RANDOM % size))
        GLOBAL_UA="${USER_AGENTS[$index]}"
    else
        GLOBAL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    fi
}

apply_delay() {
    if [ -n "$FIXED_DELAY" ]; then
        sleep "$FIXED_DELAY"
    elif [ -n "$RANDOM_DELAY" ]; then
        local min=$(echo "$RANDOM_DELAY" | cut -d'-' -f1)
        local max=$(echo "$RANDOM_DELAY" | cut -d'-' -f2)
        local delay=$(awk "BEGIN {printf \"%.2f\", $min + ($max - $min) * rand()}")
        sleep "$delay"
    fi
}

check_tool() {
    local tool_name=$1
    if command -v "$tool_name" &> /dev/null; then
        return 0
    fi
    return 1
}

identify_cloud_provider() {
    local ip=$1
    local ipranges_file="ipranges_with_names.txt"
    
    # Return empty if file doesn't exist
    if [ ! -f "$ipranges_file" ]; then
        echo "unknown"
        return 1
    fi
    
    # Use grepcidr if available (fastest method)
    if command -v grepcidr &> /dev/null; then
        local result=$(grepcidr "$ip" "$ipranges_file" 2>/dev/null | head -1 | awk '{print $2}')
        if [ -n "$result" ]; then
            echo "$result"
            return 0
        fi
    fi
    
    # Fallback: use Python if available (most reliable)
    if command -v python3 &> /dev/null; then
        local result=$(python3 -c "
import ipaddress
import sys

target_ip = ipaddress.ip_address('$ip')

with open('$ipranges_file', 'r') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 2:
            try:
                network = ipaddress.ip_network(parts[0], strict=False)
                if target_ip in network:
                    print(parts[1])
                    sys.exit(0)
            except:
                continue
" 2>/dev/null)
        
        if [ -n "$result" ]; then
            echo "$result"
            return 0
        fi
    fi
    
    # Last resort: simple grep for first 2 octets (less accurate but fast)
    local first_octets=$(echo "$ip" | cut -d'.' -f1-2)
    local result=$(grep "^${first_octets}\." "$ipranges_file" 2>/dev/null | head -1 | awk '{print $2}')
    
    if [ -n "$result" ]; then
        echo "$result"
        return 0
    else
        echo "unknown"
        return 1
    fi
}

load_api_keys() {
    local apikeys_file="${CONFIG_DIR}/apikeys.env"
    if [[ -f "$apikeys_file" ]]; then
        log DEBUG "Loading API keys from $apikeys_file"
        # shellcheck disable=SC1090
        source "$apikeys_file"
    else
        log WARNING "API keys file not found: $apikeys_file (using defaults)"
    fi
}

setup_environment() {
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$TOOLS_DIR"
    mkdir -p "$CONFIG_DIR"
    
    if [ "$VERBOSE" = true ]; then
        log INFO "Output directory: $OUTPUT_DIR"
        log INFO "Tools directory: $TOOLS_DIR"
        log INFO "Config directory: $CONFIG_DIR"
    fi
}

###############################################################################
# Argument Parsing
###############################################################################

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domains)
                DOMAINS_INPUT="$2"
                shift 2
                ;;
            -a|--asn)
                ASN_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --cloud)
                CLOUD_MODE=true
                shift
                ;;
            --full)
                FULL_MODE=true
                shift
                ;;
            --passive|-passive)
                PASSIVE_MODE=true
                shift
                ;;
            --threads-httpx)
                THREADS_HTTPX="$2"
                shift 2
                ;;
            --threads-naabu)
                THREADS_NAABU="$2"
                shift 2
                ;;
            -ua|--random-ua)
                RANDOM_UA=true
                shift
                ;;
            --delay)
                FIXED_DELAY="$2"
                shift 2
                ;;
            --delay-random)
                RANDOM_DELAY="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -up|--update)
                UPDATE_MODE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validation
    if [ "$UPDATE_MODE" = false ] && [ -z "$DOMAINS_INPUT" ]; then
        log ERROR "Domain or domain file (-d) is required"
        show_help
        exit 1
    fi
    
    # Check if input is a file or a direct domain
    if [ "$UPDATE_MODE" = false ]; then
        if [ -f "$DOMAINS_INPUT" ]; then
            # It's a file
            DOMAINS_FILE="$DOMAINS_INPUT"
            IS_DIRECT_DOMAIN=false
        else
            # Assume it's a direct domain name
            DIRECT_DOMAIN="$DOMAINS_INPUT"
            IS_DIRECT_DOMAIN=true
        fi
    fi
}

show_help() {
    cat << EOF
Usage: $SCRIPT_NAME -d <domain|file> [OPTIONS]

Required:
    -d, --domains DOMAIN|FILE   Single domain (e.g., example.com) or file with domains (one per line)

Options:
    -a, --asn FILE          File with list of ASNs (e.g. AS1234)
    -o, --output DIR        Base output directory for reports (default: ./reports)
    --cloud                 Enable cloud/CDN & certs phase
    --full                  Run all phases end-to-end
    --passive               Passive-only mode (disable active scanning)
    --threads-httpx INT     Threads for httpx (default: 50)
    --threads-naabu INT     Threads for naabu (default: 1000)
    -ua, --random-ua        Enable random User-Agent rotation
    --delay SECONDS         Fixed delay between operations (can be fractional)
    --delay-random MIN-MAX  Random delay range (e.g. 0.3-0.9)
    -v, --verbose           Verbose mode (extra logs)
    -up, --update           Update mode (update tools and exit)
    -h, --help              Show this help message

Examples:
    # Single domain
    $SCRIPT_NAME -d example.com --full -v -o reports/example
    
    # Domain file
    $SCRIPT_NAME -d scope.txt --full -o reports
    
    # With all options
    $SCRIPT_NAME -d hunty.es --full --threads-httpx 5 --threads-naabu 5 -ua -v --cloud --delay-random 0.3-0.9 -o /path/to/output
    
    # Passive mode from file
    $SCRIPT_NAME -d scope.txt --passive -o reports_passive
    
    # Update tools
    $SCRIPT_NAME -up

EOF
}

###############################################################################
# Phase 1: ASN / Infrastructure
###############################################################################

run_asnmap() {
    local target=$1
    local asn=$2
    local recon_dir="recon/$target/01_asn_ips"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running asnmap for $asn"
    log_to_file "$recon_dir/../logs/run.log" "Starting asnmap for $asn"
    
    if check_tool "asnmap"; then
        if [ "$VERBOSE" = true ]; then
            echo "$asn" | asnmap -silent > "$recon_dir/${asn}-ips.txt" 2>&1
        else
            echo "$asn" | asnmap -silent > "$recon_dir/${asn}-ips.txt" 2>/dev/null
        fi
        
        if [ -f "$recon_dir/${asn}-ips.txt" ] && [ -s "$recon_dir/${asn}-ips.txt" ]; then
            local count=$(wc -l < "$recon_dir/${asn}-ips.txt")
            log SUCCESS "Found $count IP ranges for $asn"
        fi
    else
        log ERROR "asnmap not found. Please run install.sh"
        return 1
    fi
    
    apply_delay
}

run_asnmap_if_asn() {
    local target=$1
    
    if [ -z "$ASN_FILE" ] || [ ! -f "$ASN_FILE" ]; then
        log DEBUG "No ASN file provided, skipping ASN phase"
        return 0
    fi
    
    log INFO "Processing ASNs from $ASN_FILE"
    
    while IFS= read -r asn; do
        [ -z "$asn" ] && continue
        run_asnmap "$target" "$asn"
    done < "$ASN_FILE"
}

###############################################################################
# Phase 2: Cloud & Certs
###############################################################################

run_ipranges() {
    local target=$1
    local recon_dir="recon/$target/02_cloud_certs/ipranges"
    
    mkdir -p "$recon_dir"
    
    log INFO "Loading cloud provider IP ranges from local database"
    
    # Use local ipranges_with_names.txt file
    local ipranges_file="ipranges_with_names.txt"
    
    if [ ! -f "$ipranges_file" ]; then
        log WARNING "ipranges_with_names.txt not found. Skipping cloud provider identification"
        return 0
    fi
    
    # Copy to recon directory for reference
    cp "$ipranges_file" "$recon_dir/all_providers_with_names.txt"
    
    local total_ranges=$(wc -l < "$ipranges_file" 2>/dev/null || echo "0")
    log SUCCESS "Loaded cloud provider IP ranges database ($total_ranges entries)"
    
    # Extract unique provider names for statistics
    awk '{print $2}' "$ipranges_file" 2>/dev/null | sort -u > "$recon_dir/providers_list.txt" || true
    
    if [ -f "$recon_dir/providers_list.txt" ]; then
        local providers_count=$(wc -l < "$recon_dir/providers_list.txt")
        log INFO "Database contains $providers_count different cloud providers"
        
        if [ "$VERBOSE" = true ]; then
            log DEBUG "Providers: $(head -20 "$recon_dir/providers_list.txt" | tr '\n' ', ' | sed 's/,$//')"
        fi
    fi
    
    apply_delay
}

run_caduceus() {
    local target=$1
    local recon_dir="recon/$target/02_cloud_certs/caduceus"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running Caduceus for certificate discovery"
    
    # Check if we have IPs from ASN phase
    local ip_file="recon/$target/01_asn_ips/all_ips.txt"
    if [ ! -f "$ip_file" ]; then
        # Create consolidated IP file from ASN results
        find "recon/$target/01_asn_ips" -name "*-ips.txt" -exec cat {} \; > "$ip_file" 2>/dev/null || true
    fi
    
    if check_tool "caduceus"; then
        if [ -f "$ip_file" ] && [ -s "$ip_file" ]; then
            # Caduceus uses -i flag for input file with IPs/CIDRs
            if [ "$VERBOSE" = true ]; then
                caduceus -i "$ip_file" 2>&1 | tee "$recon_dir/certs.txt"
            else
                caduceus -i "$ip_file" > "$recon_dir/certs.txt" 2>/dev/null
            fi
        else
            # For single domain, create a temp file with the domain
            echo "$target" > "$recon_dir/target_temp.txt"
            if [ "$VERBOSE" = true ]; then
                caduceus -i "$recon_dir/target_temp.txt" 2>&1 | tee "$recon_dir/certs.txt"
            else
                caduceus -i "$recon_dir/target_temp.txt" > "$recon_dir/certs.txt" 2>/dev/null
            fi
            rm -f "$recon_dir/target_temp.txt"
        fi
        
        log SUCCESS "Certificate discovery completed"
    else
        log WARNING "Caduceus not found. Skipping certificate discovery"
    fi
    
    apply_delay
}

run_gungnir() {
    local target=$1
    local recon_dir="recon/$target/02_cloud_certs/gungnir"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running gungnir for certificate monitoring"
    
    if check_tool "gungnir"; then
        # Gungnir requires -r flag with a file containing root domains
        local domain_file="$recon_dir/target_domains.txt"
        echo "$target" > "$domain_file"
        
        if [ "$VERBOSE" = true ]; then
            gungnir -r "$domain_file" -o "$recon_dir" 2>&1
        else
            gungnir -r "$domain_file" -o "$recon_dir" 2>/dev/null
        fi
        
        # Consolidate results if any
        cat "$recon_dir"/*.txt 2>/dev/null | sort -u > "$recon_dir/${target}-certs.txt" || true
        
        log SUCCESS "Gungnir certificate monitoring completed"
    else
        log WARNING "gungnir not found. Skipping gungnir"
    fi
    
    apply_delay
}

run_ipranges_caduceus_if_cloud() {
    local target=$1
    
    if [ "$CLOUD_MODE" = false ] && [ "$FULL_MODE" = false ]; then
        log DEBUG "Cloud mode not enabled, skipping cloud & certs phase"
        return 0
    fi
    
    log INFO "Starting cloud & certificates phase"
    
    run_ipranges "$target"
    run_caduceus "$target"
    run_gungnir "$target"
    
    # Extract subdomains from certificates
    local certs_subs="recon/$target/03_subdomains/certs_subs.txt"
    mkdir -p "$(dirname "$certs_subs")"
    
    grep -Rho "[A-Za-z0-9._-]\+\.$target" "recon/$target/02_cloud_certs" 2>/dev/null | \
        sort -u > "$certs_subs" || true
    
    if [ -f "$certs_subs" ] && [ -s "$certs_subs" ]; then
        local count=$(wc -l < "$certs_subs")
        log SUCCESS "Extracted $count subdomains from certificates"
    fi
}

###############################################################################
# Phase 3: Subdomain Enumeration
###############################################################################

run_subfinder_bbot() {
    local target=$1
    local recon_dir="recon/$target/03_subdomains"
    
    mkdir -p "$recon_dir"
    
    log INFO "Starting subdomain enumeration for $target"
    
    # Subfinder
    if check_tool "subfinder"; then
        log INFO "Running subfinder"
        if [ "$VERBOSE" = true ]; then
            subfinder -d "$target" -all -silent > "$recon_dir/subfinder.txt" 2>&1
        else
            subfinder -d "$target" -all -silent > "$recon_dir/subfinder.txt" 2>/dev/null
        fi
        apply_delay
    else
        log WARNING "subfinder not found. Skipping subfinder"
    fi
    
    # BBOT
    if check_tool "bbot"; then
        log INFO "Running bbot"
        local bbot_output="$recon_dir/bbot"
        mkdir -p "$bbot_output"
        
        # BBOT 2.x+ uses different flags: -f subdomain-enum to use the subdomain-enum preset
        # Or just run without module flags to use default passive reconnaissance
        if [ "$VERBOSE" = true ]; then
            bbot -t "$target" -f subdomain-enum -o "$bbot_output" 2>&1 || \
            bbot -t "$target" -o "$bbot_output" 2>&1
        else
            bbot -t "$target" -f subdomain-enum -o "$bbot_output" 2>/dev/null || \
            bbot -t "$target" -o "$bbot_output" 2>/dev/null
        fi
        
        # Extract subdomains from bbot output (they're usually in output.txt or subdomains.txt)
        find "$bbot_output" -type f \( -name '*.txt' -o -name 'output.txt' -o -name 'subdomains.txt' \) \
            -exec grep -Eo "([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+$target" {} \; 2>/dev/null | \
            sort -u > "$recon_dir/bbot_subs.txt" || true
        apply_delay
    else
        log WARNING "bbot not found. Skipping bbot"
    fi
    
    # Merge all subdomains
    cat "$recon_dir"/*.txt 2>/dev/null | sort -u > "$recon_dir/all_subdomains.txt" || true
    
    if [ -f "$recon_dir/all_subdomains.txt" ] && [ -s "$recon_dir/all_subdomains.txt" ]; then
        local count=$(wc -l < "$recon_dir/all_subdomains.txt")
        log SUCCESS "Found $count unique subdomains"
    else
        log WARNING "No subdomains found"
    fi
}

###############################################################################
# Phase 4: Port Scanning
###############################################################################

run_naabu_smap() {
    local target=$1
    local recon_dir="recon/$target/04_ports"
    
    mkdir -p "$recon_dir"
    
    log INFO "Starting port scanning phase"
    
    # Naabu (active scanning)
    if [ "$PASSIVE_MODE" = false ]; then
        if check_tool "naabu"; then
            log INFO "Running naabu (active port scan)"
            local subdomains_file="recon/$target/03_subdomains/all_subdomains.txt"
            
            if [ -f "$subdomains_file" ] && [ -s "$subdomains_file" ]; then
                if [ "$VERBOSE" = true ]; then
                    naabu -l "$subdomains_file" -p 80,443,8080,8443,4443,8888 \
                        -rate "$THREADS_NAABU" -o "$recon_dir/naabu_ports.txt" 2>&1
                else
                    naabu -l "$subdomains_file" -p 80,443,8080,8443,4443,8888 \
                        -rate "$THREADS_NAABU" -o "$recon_dir/naabu_ports.txt" 2>/dev/null
                fi
                apply_delay
            fi
        else
            log WARNING "naabu not found. Skipping active port scan"
        fi
    else
        log INFO "Passive mode: skipping naabu"
    fi
    
    # Smap (passive via Shodan)
    if check_tool "smap"; then
        log INFO "Running smap (passive port scan via Shodan)"
        local subdomains_file="recon/$target/03_subdomains/all_subdomains.txt"
        
        if [ -f "$subdomains_file" ] && [ -s "$subdomains_file" ]; then
            if [ -n "${SHODAN_API_KEY:-}" ]; then
                # Smap requires: smap -iL <file> or individual IPs
                # Process each subdomain individually to avoid argument errors
                while IFS= read -r subdomain; do
                    [ -z "$subdomain" ] && continue
                    
                    if [ "$VERBOSE" = true ]; then
                        echo "$subdomain" | smap >> "$recon_dir/smap_ports.txt" 2>&1 || true
                    else
                        echo "$subdomain" | smap >> "$recon_dir/smap_ports.txt" 2>/dev/null || true
                    fi
                done < "$subdomains_file"
                
                # Alternative: use smap with proper syntax
                # smap -iL expects one input per line, no output flag needed
                if [ "$VERBOSE" = true ]; then
                    cat "$subdomains_file" | smap > "$recon_dir/smap_ports.txt" 2>&1 || true
                else
                    cat "$subdomains_file" | smap > "$recon_dir/smap_ports.txt" 2>/dev/null || true
                fi
                
                apply_delay
            else
                log WARNING "SHODAN_API_KEY not set. Skipping smap"
            fi
        fi
    else
        log WARNING "smap not found. Skipping passive port scan"
    fi
    
    # Consolidate HTTP targets
    cat "$recon_dir"/*.txt 2>/dev/null | grep -E ":(80|443|8080|8443|4443|8888)" | \
        sort -u > "$recon_dir/ports_http_targets.txt" || true
}

###############################################################################
# Phase 5: HTTP Probing
###############################################################################

run_httpx() {
    local target=$1
    local recon_dir="recon/$target/05_http"
    
    mkdir -p "$recon_dir"
    
    log INFO "Starting HTTP probing phase"
    
    if ! check_tool "httpx"; then
        log ERROR "httpx not found. Please run install.sh"
        return 1
    fi
    
    local subdomains_file="recon/$target/03_subdomains/all_subdomains.txt"
    
    if [ ! -f "$subdomains_file" ] || [ ! -s "$subdomains_file" ]; then
        log WARNING "No subdomains file found. Skipping HTTP probing"
        return 0
    fi
    
    get_random_ua
    
    local httpx_cmd="httpx -l \"$subdomains_file\" \
        -status-code -title -content-length -web-server -asn -location \
        -follow-redirects -t $THREADS_HTTPX \
        -ports 80,8080,443,8443,4443,8888 \
        -no-fallback -probe-all-ips \
        -H \"User-Agent: $GLOBAL_UA\" \
        -json \
        -o \"$recon_dir/httpx.json\""
    
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Running: $httpx_cmd"
        eval "$httpx_cmd" 2>&1
    else
        eval "$httpx_cmd" 2>/dev/null
    fi
    
    # Create pretty text output
    if [ -f "$recon_dir/httpx.json" ] && [ -s "$recon_dir/httpx.json" ]; then
        if command -v jq &> /dev/null; then
            jq -r '. | "\(.url) [\(.status_code)] \(.title // "N/A") \(.webserver // "N/A")"' \
                "$recon_dir/httpx.json" > "$recon_dir/httpx_pretty.txt" 2>/dev/null || true
        fi
        
        # Extract URLs by status code family
        for family in 2xx 3xx 4xx 5xx; do
            case $family in
                2xx) pattern='select(.status_code >= 200 and .status_code < 300)' ;;
                3xx) pattern='select(.status_code >= 300 and .status_code < 400)' ;;
                4xx) pattern='select(.status_code >= 400 and .status_code < 500)' ;;
                5xx) pattern='select(.status_code >= 500)' ;;
            esac
            
            if command -v jq &> /dev/null; then
                jq -r "$pattern | .url" "$recon_dir/httpx.json" > "$recon_dir/status_${family}.txt" 2>/dev/null || true
            fi
        done
        
        # Extract 403 URLs
        if command -v jq &> /dev/null; then
            jq -r 'select(.status_code == 403) | .url' "$recon_dir/httpx.json" > \
                "recon/$target/06_waf_403/403_urls.txt" 2>/dev/null || true
        fi
        
        # Extract likely login URLs
        if command -v jq &> /dev/null; then
            jq -r 'select(.url | test("(login|signin|auth|admin|dashboard)"; "i")) | .url' \
                "$recon_dir/httpx.json" > "$recon_dir/likely_logins.txt" 2>/dev/null || true
        fi
        
        # Identify cloud providers for each IP found
        log INFO "Identifying cloud providers for discovered IPs..."
        if command -v jq &> /dev/null; then
            echo "# IP | Provider | URL | Status" > "$recon_dir/cloud_providers_mapping.txt"
            
            jq -r '.host + "|" + .url + "|" + (.status_code|tostring)' "$recon_dir/httpx.json" 2>/dev/null | \
            while IFS='|' read -r ip url status; do
                # Skip if IP is IPv6 or empty
                if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    local provider=$(identify_cloud_provider "$ip" 2>/dev/null)
                    if [ -n "$provider" ] && [ "$provider" != "unknown" ]; then
                        echo "$ip | $provider | $url | $status" >> "$recon_dir/cloud_providers_mapping.txt"
                    fi
                fi
            done
            
            # Create summary by provider
            if [ -f "$recon_dir/cloud_providers_mapping.txt" ]; then
                awk -F'|' 'NR>1 {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' "$recon_dir/cloud_providers_mapping.txt" 2>/dev/null | \
                    sort | uniq -c | sort -rn > "$recon_dir/providers_summary.txt" || true
                
                if [ -s "$recon_dir/providers_summary.txt" ]; then
                    local providers_found=$(wc -l < "$recon_dir/providers_summary.txt")
                    log SUCCESS "Identified $providers_found different cloud providers"
                    
                    if [ "$VERBOSE" = true ]; then
                        log DEBUG "Cloud providers found:"
                        head -5 "$recon_dir/providers_summary.txt" | while read count provider; do
                            log DEBUG "  - $provider: $count IPs"
                        done
                    fi
                fi
            fi
        fi
        
        local count=$(jq -r '.url' "$recon_dir/httpx.json" 2>/dev/null | wc -l)
        log SUCCESS "Probed $count HTTP services"
    else
        log WARNING "No HTTP services found"
    fi
    
    apply_delay
}

###############################################################################
# Phase 6: WAF / 403 Bypass
###############################################################################

run_wafw00f() {
    local target=$1
    local recon_dir="recon/$target/06_waf_403"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running WAF detection"
    
    if ! check_tool "wafw00f"; then
        log WARNING "wafw00f not found. Skipping WAF detection"
        return 0
    fi
    
    local httpx_json="recon/$target/05_http/httpx.json"
    
    if [ ! -f "$httpx_json" ] || [ ! -s "$httpx_json" ]; then
        log WARNING "No httpx results found. Skipping WAF detection"
        return 0
    fi
    
    # Extract unique hosts (without port)
    if command -v jq &> /dev/null; then
        jq -r '.url' "$httpx_json" | sed 's|https\?://||' | sed 's|:.*||' | sed 's|/.*||' | sort -u > "$recon_dir/hosts_http.txt"
        
        # Add protocol back for wafw00f
        sed 's|^|https://|' "$recon_dir/hosts_http.txt" > "$recon_dir/hosts_http_full.txt"
        
        if [ "$VERBOSE" = true ]; then
            wafw00f -i "$recon_dir/hosts_http_full.txt" -o "$recon_dir/wafw00f.txt" 2>&1
        else
            wafw00f -i "$recon_dir/hosts_http_full.txt" -o "$recon_dir/wafw00f.txt" 2>/dev/null
        fi
        
        log SUCCESS "WAF detection completed"
    else
        log WARNING "jq not found. Cannot extract hosts for WAF detection"
    fi
    
    apply_delay
}

run_403jump() {
    local target=$1
    local recon_dir="recon/$target/06_waf_403"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running 403 bypass attempts"
    
    if ! check_tool "403jump"; then
        log WARNING "403jump not found. Skipping 403 bypass"
        return 0
    fi
    
    local urls_403="$recon_dir/403_urls.txt"
    
    if [ ! -f "$urls_403" ] || [ ! -s "$urls_403" ]; then
        log DEBUG "No 403 URLs found. Skipping 403 bypass"
        return 0
    fi
    
    local count=$(wc -l < "$urls_403")
    log INFO "Attempting 403 bypass on $count URLs"
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        if [ "$VERBOSE" = true ]; then
            if [[ "$(command -v 403jump)" == *.py ]]; then
                python3 "$(command -v 403jump)" -u "$url" >> "$recon_dir/403jump_results.txt" 2>&1
            else
                403jump -u "$url" >> "$recon_dir/403jump_results.txt" 2>&1
            fi
        else
            if [[ "$(command -v 403jump)" == *.py ]]; then
                python3 "$(command -v 403jump)" -u "$url" >> "$recon_dir/403jump_results.txt" 2>/dev/null
            else
                403jump -u "$url" >> "$recon_dir/403jump_results.txt" 2>/dev/null
            fi
        fi
        apply_delay
    done < "$urls_403"
    
    log SUCCESS "403 bypass attempts completed"
}

###############################################################################
# Phase 7: Content, Endpoints & JS
###############################################################################

run_gau_sensitive() {
    local target=$1
    local recon_dir="recon/$target/07_content_js/gau"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running GAU for historical URLs and sensitive files"
    
    if ! check_tool "gau"; then
        log WARNING "gau not found. Skipping GAU"
        return 0
    fi
    
    local target_url="https://$target"
    
    if [ "$VERBOSE" = true ]; then
        echo "$target_url" | gau | tee "$recon_dir/all_urls.txt" | \
            grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$" \
            > "$recon_dir/sensitive_files.txt" 2>&1
    else
        echo "$target_url" | gau 2>/dev/null | tee "$recon_dir/all_urls.txt" | \
            grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$" \
            > "$recon_dir/sensitive_files.txt" 2>/dev/null
    fi
    
    if [ -f "$recon_dir/sensitive_files.txt" ] && [ -s "$recon_dir/sensitive_files.txt" ]; then
        local count=$(wc -l < "$recon_dir/sensitive_files.txt")
        log SUCCESS "Found $count sensitive files from Wayback Machine"
    fi
    
    apply_delay
}

run_cariddi() {
    local target=$1
    local recon_dir="recon/$target/07_content_js/cariddi"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running cariddi for endpoint and parameter discovery"
    
    if ! check_tool "cariddi"; then
        log WARNING "cariddi not found. Skipping cariddi"
        return 0
    fi
    
    local httpx_json="recon/$target/05_http/httpx.json"
    local urls_file="$recon_dir/input_urls.txt"
    
    # Prepare input URLs (200/302 from httpx + subset of gau)
    if [ -f "$httpx_json" ] && command -v jq &> /dev/null; then
        jq -r 'select(.status_code >= 200 and .status_code < 400) | .url' "$httpx_json" > "$urls_file" 2>/dev/null || true
    fi
    
    local gau_urls="recon/$target/07_content_js/gau/all_urls.txt"
    if [ -f "$gau_urls" ]; then
        head -100 "$gau_urls" >> "$urls_file" 2>/dev/null || true
    fi
    
    if [ -f "$urls_file" ] && [ -s "$urls_file" ]; then
        # Cariddi reads from stdin, not from -l flag
        # Use -plain for cleaner output, -e for endpoints, -s for secrets
        if [ "$VERBOSE" = true ]; then
            cat "$urls_file" | cariddi -e -s -plain > "$recon_dir/results.txt" 2>&1
        else
            cat "$urls_file" | cariddi -e -s -plain > "$recon_dir/results.txt" 2>/dev/null
        fi
        log SUCCESS "Cariddi endpoint discovery completed"
    else
        log WARNING "No URLs available for cariddi"
    fi
    
    apply_delay
}

run_jsmap() {
    local target=$1
    local recon_dir="recon/$target/07_content_js/jsmap"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running JSMap-Inspector for JavaScript analysis"
    
    local jsmap_tool=""
    if [ -f "${TOOLS_DIR}/JSMap-Inspector-main/JSMap-Inspector.py" ]; then
        jsmap_tool="${TOOLS_DIR}/JSMap-Inspector-main/JSMap-Inspector.py"
    elif command -v JSMap-Inspector &> /dev/null; then
        jsmap_tool="JSMap-Inspector"
    else
        log WARNING "JSMap-Inspector not found. Skipping JSMap"
        return 0
    fi
    
    # Extract .js URLs from gau and cariddi
    local js_urls="$recon_dir/js_urls.txt"
    local gau_urls="recon/$target/07_content_js/gau/all_urls.txt"
    local cariddi_results="recon/$target/07_content_js/cariddi/results.txt"
    
    grep -E "\.js$" "$gau_urls" "$cariddi_results" 2>/dev/null | sort -u > "$js_urls" || true
    
    if [ -f "$js_urls" ] && [ -s "$js_urls" ]; then
        if [[ "$jsmap_tool" == *.py ]]; then
            if [ "$VERBOSE" = true ]; then
                python3 "$jsmap_tool" -l "$js_urls" -o "$recon_dir/jsmap_report.json" 2>&1
            else
                python3 "$jsmap_tool" -l "$js_urls" -o "$recon_dir/jsmap_report.json" 2>/dev/null
            fi
        else
            if [ "$VERBOSE" = true ]; then
                "$jsmap_tool" -l "$js_urls" -o "$recon_dir/jsmap_report.json" 2>&1
            else
                "$jsmap_tool" -l "$js_urls" -o "$recon_dir/jsmap_report.json" 2>/dev/null
            fi
        fi
        log SUCCESS "JSMap-Inspector analysis completed"
    else
        log WARNING "No JavaScript URLs found for analysis"
    fi
    
    apply_delay
}

###############################################################################
# Phase 8: CORS / CSP / Favicon
###############################################################################

run_corsy() {
    local target=$1
    local recon_dir="recon/$target/08_policies/corsy"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running Corsy for CORS misconfiguration detection"
    
    local corsy_tool=""
    if [ -f "${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py" ]; then
        corsy_tool="${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py"
    elif [ -f "${TOOLS_DIR}/Corsy-master/corsy.py" ]; then
        corsy_tool="${TOOLS_DIR}/Corsy-master/corsy.py"
    elif command -v corsy &> /dev/null; then
        corsy_tool="corsy"
    else
        log WARNING "Corsy not found. Skipping CORS detection"
        return 0
    fi
    
    local httpx_json="recon/$target/05_http/httpx.json"
    local urls_file="$recon_dir/input_urls.txt"
    
    if [ -f "$httpx_json" ] && command -v jq &> /dev/null; then
        jq -r 'select(.status_code >= 200 and .status_code < 400) | .url' "$httpx_json" > "$urls_file" 2>/dev/null || true
    fi
    
    if [ -f "$urls_file" ] && [ -s "$urls_file" ]; then
        if [[ "$corsy_tool" == *.py ]]; then
            if [ "$VERBOSE" = true ]; then
                python3 "$corsy_tool" -i "$urls_file" -o "$recon_dir/cors_results.txt" 2>&1
            else
                python3 "$corsy_tool" -i "$urls_file" -o "$recon_dir/cors_results.txt" 2>/dev/null
            fi
        else
            if [ "$VERBOSE" = true ]; then
                "$corsy_tool" -i "$urls_file" -o "$recon_dir/cors_results.txt" 2>&1
            else
                "$corsy_tool" -i "$urls_file" -o "$recon_dir/cors_results.txt" 2>/dev/null
            fi
        fi
        log SUCCESS "CORS detection completed"
    else
        log WARNING "No URLs available for CORS detection"
    fi
    
    apply_delay
}

run_csp_stalker() {
    local target=$1
    local recon_dir="recon/$target/08_policies/csp_stalker"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running CSP-Stalker for Content Security Policy analysis"
    
    local csp_tool=""
    if [ -f "${TOOLS_DIR}/CSP-Stalker-main/cli_CSP_Stalker.py" ]; then
        csp_tool="${TOOLS_DIR}/CSP-Stalker-main/cli_CSP_Stalker.py"
    elif command -v csp-stalker &> /dev/null; then
        csp_tool="csp-stalker"
    else
        log WARNING "CSP-Stalker not found. Skipping CSP analysis"
        return 0
    fi
    
    local httpx_json="recon/$target/05_http/httpx.json"
    
    if [ -f "$httpx_json" ] && command -v jq &> /dev/null; then
        local url_count=0
        jq -r 'select(.status_code >= 200 and .status_code < 400) | .url' "$httpx_json" | head -20 | while IFS= read -r url; do
            [ -z "$url" ] && continue
            url_count=$((url_count + 1))
            
            if [[ "$csp_tool" == *.py ]]; then
                if [ "$VERBOSE" = true ]; then
                    python3 "$csp_tool" -u "$url" -o "$recon_dir" 2>&1
                else
                    python3 "$csp_tool" -u "$url" -o "$recon_dir" 2>/dev/null
                fi
            else
                if [ "$VERBOSE" = true ]; then
                    "$csp_tool" -u "$url" -o "$recon_dir" 2>&1
                else
                    "$csp_tool" -u "$url" -o "$recon_dir" 2>/dev/null
                fi
            fi
            apply_delay
        done
        
        log SUCCESS "CSP analysis completed"
    else
        log WARNING "No URLs available for CSP analysis"
    fi
    
    apply_delay
}

run_favicorn() {
    local target=$1
    local recon_dir="recon/$target/08_policies/favicorn"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running favicorn for favicon fingerprinting"
    
    if ! check_tool "favicorn"; then
        log WARNING "favicorn not found. Skipping favicon fingerprinting"
        return 0
    fi
    
    local httpx_json="recon/$target/05_http/httpx.json"
    local urls_file="$recon_dir/input_urls.txt"
    
    if [ -f "$httpx_json" ] && command -v jq &> /dev/null; then
        jq -r '.url' "$httpx_json" > "$urls_file" 2>/dev/null || true
    fi
    
    if [ -f "$urls_file" ] && [ -s "$urls_file" ]; then
        # Favicorn uses -f for file input, not -l
        if [ "$VERBOSE" = true ]; then
            favicorn -f "$urls_file" > "$recon_dir/favicorn_results.txt" 2>&1
        else
            favicorn -f "$urls_file" > "$recon_dir/favicorn_results.txt" 2>/dev/null
        fi
        log SUCCESS "Favicon fingerprinting completed"
    else
        log WARNING "No URLs available for favicon fingerprinting"
    fi
    
    apply_delay
}

###############################################################################
# Phase 9: Logins, Vulns, CVE Mapping
###############################################################################

run_logsensor() {
    local target=$1
    local recon_dir="recon/$target/09_logins_vulns"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running Logsensor for login panel detection"
    
    local logsensor_tool=""
    if [ -f "${TOOLS_DIR}/Logsensor-main/logsensor.py" ]; then
        logsensor_tool="${TOOLS_DIR}/Logsensor-main/logsensor.py"
    elif command -v logsensor &> /dev/null; then
        logsensor_tool="logsensor"
    else
        log WARNING "Logsensor not found. Skipping login detection"
        return 0
    fi
    
    local input_file=""
    local likely_logins="recon/$target/05_http/likely_logins.txt"
    local httpx_pretty="recon/$target/05_http/httpx_pretty.txt"
    
    if [ -f "$likely_logins" ] && [ -s "$likely_logins" ]; then
        input_file="$likely_logins"
    elif [ -f "$httpx_pretty" ] && [ -s "$httpx_pretty" ]; then
        input_file="$httpx_pretty"
    fi
    
    if [ -n "$input_file" ] && [ -f "$input_file" ]; then
        local flags="--login"
        if [ "$PASSIVE_MODE" = true ]; then
            log INFO "Passive mode: skipping intrusive SQLi modules"
            # Only login detection, no SQLi
        fi
        
        if [[ "$logsensor_tool" == *.py ]]; then
            if [ "$VERBOSE" = true ]; then
                python3 "$logsensor_tool" -f "$input_file" $flags > "$recon_dir/logins.txt" 2>&1
            else
                python3 "$logsensor_tool" -f "$input_file" $flags > "$recon_dir/logins.txt" 2>/dev/null
            fi
        else
            if [ "$VERBOSE" = true ]; then
                "$logsensor_tool" -f "$input_file" $flags > "$recon_dir/logins.txt" 2>&1
            else
                "$logsensor_tool" -f "$input_file" $flags > "$recon_dir/logins.txt" 2>/dev/null
            fi
        fi
        
        # Filter out ASCII art, ANSI codes, and extract only URLs
        # Remove ANSI escape sequences and extract only lines that look like URLs
        sed 's/\x1b\[[0-9;]*m//g' "$recon_dir/logins.txt" | \
            grep -E "^https?://" | \
            grep -v "SyntaxWarning" | \
            sort -u > "$recon_dir/logins_clean.txt" 2>/dev/null || true
        
        if [ -f "$recon_dir/logins_clean.txt" ] && [ -s "$recon_dir/logins_clean.txt" ]; then
            mv "$recon_dir/logins_clean.txt" "$recon_dir/logins.txt"
            local count=$(wc -l < "$recon_dir/logins.txt")
            log SUCCESS "Found $count login panels"
        else
            # If no URLs found, create empty file to avoid errors in reporting
            touch "$recon_dir/logins.txt"
            log INFO "No login panels detected"
        fi
    else
        log WARNING "No input file available for Logsensor"
    fi
    
    apply_delay
}

run_cvemap() {
    local target=$1
    local recon_dir="recon/$target/09_logins_vulns"
    
    mkdir -p "$recon_dir"
    
    log INFO "Running cvemap for CVE mapping"
    
    if ! check_tool "cvemap"; then
        log WARNING "cvemap not found. Skipping CVE mapping"
        return 0
    fi
    
    local httpx_json="recon/$target/05_http/httpx.json"
    
    if [ -f "$httpx_json" ] && command -v jq &> /dev/null; then
        # Extract unique technologies from httpx results
        jq -r '.webserver // empty' "$httpx_json" | sort -u | while IFS= read -r tech; do
            [ -z "$tech" ] && continue
            
            # Normalize tech name (strip versions)
            local normalized=$(echo "$tech" | sed 's/[0-9].*//' | tr -d ' ')
            
            if [ -n "$normalized" ]; then
                log DEBUG "Checking CVEs for technology: $normalized"
                
                if [ "$VERBOSE" = true ]; then
                    cvemap -p "$normalized" >> "$recon_dir/cves_by_tech.txt" 2>&1
                else
                    cvemap -p "$normalized" >> "$recon_dir/cves_by_tech.txt" 2>/dev/null
                fi
                apply_delay
            fi
        done
        
        log SUCCESS "CVE mapping completed"
    else
        log WARNING "No httpx results available for CVE mapping"
    fi
}

###############################################################################
# Target Processing
###############################################################################

init_target_dirs() {
    local target=$1
    mkdir -p "recon/$target/"{01_asn_ips,02_cloud_certs,03_subdomains,04_ports,05_http,06_waf_403,07_content_js,08_policies,09_logins_vulns,logs}
}

start_target_log() {
    local target=$1
    local log_file="recon/$target/logs/run-$(date +%Y%m%d-%H%M%S).log"
    mkdir -p "$(dirname "$log_file")"
    
    log_to_file "$log_file" "Starting reconnaissance for target: $target"
    log_to_file "$log_file" "Arguments: $*"
    log_to_file "$log_file" "Timestamp: $(date)"
    
    echo "$log_file"
}

run_for_target() {
    local target=$1
    local log_file=$(start_target_log "$target")
    
    log INFO "Processing target: $target"
    log_to_file "$log_file" "=============================================="
    log_to_file "$log_file" "Processing target: $target"
    log_to_file "$log_file" "=============================================="
    
    init_target_dirs "$target"
    
    # Run phases
    log_to_file "$log_file" "Phase 1: ASN/Infrastructure discovery"
    run_asnmap_if_asn "$target"
    
    log_to_file "$log_file" "Phase 2: Cloud & Certificates discovery"
    run_ipranges_caduceus_if_cloud "$target"
    
    log_to_file "$log_file" "Phase 3: Subdomain enumeration"
    run_subfinder_bbot "$target"
    
    log_to_file "$log_file" "Phase 4: Port scanning"
    run_naabu_smap "$target"
    
    log_to_file "$log_file" "Phase 5: HTTP probing"
    run_httpx "$target"
    
    log_to_file "$log_file" "Phase 6: WAF detection"
    run_wafw00f "$target"
    
    log_to_file "$log_file" "Phase 7: 403 bypass attempts"
    run_403jump "$target"
    
    log_to_file "$log_file" "Phase 8: Content & JS discovery (GAU)"
    run_gau_sensitive "$target"
    
    log_to_file "$log_file" "Phase 9: Endpoint discovery (Cariddi)"
    run_cariddi "$target"
    
    log_to_file "$log_file" "Phase 10: JS analysis"
    run_jsmap "$target"
    
    log_to_file "$log_file" "Phase 11: CORS analysis"
    run_corsy "$target"
    
    log_to_file "$log_file" "Phase 12: CSP analysis"
    run_csp_stalker "$target"
    
    log_to_file "$log_file" "Phase 13: Favicon fingerprinting"
    run_favicorn "$target"
    
    log_to_file "$log_file" "Phase 14: Login panel detection"
    run_logsensor "$target"
    
    log_to_file "$log_file" "Phase 15: CVE mapping"
    run_cvemap "$target"
    
    # Generate reports
    log_to_file "$log_file" "=============================================="
    log_to_file "$log_file" "Generating reports..."
    generate_target_reports "$target"
    
    log_to_file "$log_file" "=============================================="
    log_to_file "$log_file" "Reconnaissance completed for: $target"
    log_to_file "$log_file" "Total execution time: $SECONDS seconds"
    log_to_file "$log_file" "=============================================="
    
    summarize_target_to_stdout "$target"
}

###############################################################################
# Report Generation
###############################################################################

generate_target_reports() {
    local target=$1
    log INFO "Generating reports for $target"
    
    local report_dir="$OUTPUT_DIR"
    mkdir -p "$report_dir"
    
    # Generate HTML report
    generate_html_report "$target" "$report_dir"
    
    # Generate text report
    generate_text_report "$target" "$report_dir"
    
    # Generate markdown report
    generate_markdown_report "$target" "$report_dir"
    
    # Generate CSV report
    generate_csv_report "$target" "$report_dir"
    
    # Copy execution log
    local latest_log=$(ls -t "recon/$target/logs/run-"*.log 2>/dev/null | head -1)
    if [ -n "$latest_log" ]; then
        cp "$latest_log" "$report_dir/${target}-run.log" 2>/dev/null || true
    fi
    
    log SUCCESS "Reports generated in $report_dir"
}

generate_html_report() {
    local target=$1
    local report_dir=$2
    local html_file="$report_dir/${target}-report.html"
    
    log DEBUG "Generating HTML report: $html_file"
    
    # Gather statistics
    local subdomains_file="recon/$target/03_subdomains/all_subdomains.txt"
    local httpx_json="recon/$target/05_http/httpx.json"
    local logins_file="recon/$target/09_logins_vulns/logins.txt"
    local cors_file="recon/$target/08_policies/corsy/cors_results.txt"
    local sensitive_file="recon/$target/07_content_js/gau/sensitive_files.txt"
    local waf_file="recon/$target/06_waf_403/wafw00f.txt"
    local bypass_file="recon/$target/06_waf_403/403jump_results.txt"
    local providers_file="recon/$target/05_http/providers_summary.txt"
    
    local sub_count=0
    local http_count=0
    local login_count=0
    local cors_count=0
    local sens_count=0
    local waf_count=0
    local bypass_count=0
    local providers_count=0
    
    [ -f "$subdomains_file" ] && sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo "0")
    [ -f "$httpx_json" ] && command -v jq &> /dev/null && http_count=$(jq -r '.url' "$httpx_json" 2>/dev/null | wc -l)
    [ -f "$logins_file" ] && login_count=$(wc -l < "$logins_file" 2>/dev/null || echo "0")
    [ -f "$cors_file" ] && cors_count=$(grep -ic "vulnerable\|misconfigured" "$cors_file" 2>/dev/null || echo "0")
    [ -f "$sensitive_file" ] && sens_count=$(wc -l < "$sensitive_file" 2>/dev/null || echo "0")
    [ -f "$waf_file" ] && waf_count=$(grep -ic "waf\|detected" "$waf_file" 2>/dev/null || echo "0")
    [ -f "$bypass_file" ] && bypass_count=$(grep -c "200\|302" "$bypass_file" 2>/dev/null || echo "0")
    [ -f "$providers_file" ] && providers_count=$(wc -l < "$providers_file" 2>/dev/null || echo "0")
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recondite v2 - Reconnaissance Report: $target</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 1.1em; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            margin-top: 10px;
            font-size: 0.9em;
        }
        .section {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        .section:last-child { border-bottom: none; }
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        tr:hover { background: #f8f9fa; }
        .status-code {
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85em;
        }
        .code-2xx { background: #d4edda; color: #155724; }
        .code-3xx { background: #fff3cd; color: #856404; }
        .code-4xx { background: #f8d7da; color: #721c24; }
        .code-5xx { background: #f5c6cb; color: #721c24; }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-waf { background: #ffc107; color: #000; }
        .badge-login { background: #17a2b8; color: white; }
        .badge-cors { background: #dc3545; color: white; }
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            background: #f8f9fa;
        }
        details {
            margin: 15px 0;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background: #f9f9f9;
        }
        summary {
            cursor: pointer;
            padding: 10px;
            background: #667eea;
            color: white;
            border-radius: 4px;
            font-weight: bold;
            user-select: none;
        }
        summary:hover {
            background: #5568d3;
        }
        details[open] summary {
            margin-bottom: 10px;
        }
        .finding-item {
            padding: 8px;
            margin: 5px 0;
            background: white;
            border-left: 3px solid #667eea;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Recondite v2</h1>
            <p>Advanced Reconnaissance Report</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Target: $target | Generated: $timestamp</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">$sub_count</div>
                <div class="stat-label">Subdomains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$http_count</div>
                <div class="stat-label">HTTP Services</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$providers_count</div>
                <div class="stat-label">Cloud Providers</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$waf_count</div>
                <div class="stat-label">WAF Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$login_count</div>
                <div class="stat-label">Login Panels</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$cors_count</div>
                <div class="stat-label">CORS Vulnerable</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$bypass_count</div>
                <div class="stat-label">403 Bypassed</div>
            </div>
        </div>
EOF

    # Add subdomains table with collapse
    if [ -f "$httpx_json" ] && command -v jq &> /dev/null; then
        # Create deduplicated subdomains with unique URLs
        jq -r '. | "\(.url)|\(.status_code)|\(.title // \"N/A\")"' "$httpx_json" 2>/dev/null | sort -u > "/tmp/subdomains_tmp_$$"
        
        cat >> "$html_file" << 'EOF'
        <div class="section">
            <h2>🌐 Discovered Subdomains</h2>
            <details open>
                <summary>Click to expand/collapse subdomain list</summary>
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>Status</th>
                            <th>Title</th>
                        </tr>
                    </thead>
                    <tbody>
EOF
        
        # Add all subdomains (deduplicated)
        while IFS='|' read -r url status title; do
            local status_class="code-${status:0:1}xx"
            echo "                    <tr><td>$url</td><td><span class=\"status-code $status_class\">$status</span></td><td>${title:0:50}</td></tr>" >> "$html_file"
        done < "/tmp/subdomains_tmp_$$"
        rm -f "/tmp/subdomains_tmp_$$"
        
        cat >> "$html_file" << 'EOF'
                    </tbody>
                </table>
            </details>
        </div>
EOF
    fi
    
    # Add cloud providers section
    local cloud_mapping_file="recon/$target/05_http/cloud_providers_mapping.txt"
    if [ -f "$providers_file" ] && [ -s "$providers_file" ]; then
        cat >> "$html_file" << 'EOF'
        <div class="section">
            <h2>☁️ Cloud Infrastructure</h2>
            <details open>
                <summary>Cloud Providers Identified</summary>
                <table>
                    <thead>
                        <tr>
                            <th>Provider</th>
                            <th>IPs Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
EOF
        
        # Calculate total IPs
        local total_ips=$(awk '{sum+=$1} END {print sum}' "$providers_file" 2>/dev/null || echo "1")
        
        # Add providers to table
        while read -r count provider; do
            local percentage=$(awk "BEGIN {printf \"%.1f\", ($count/$total_ips)*100}")
            echo "                    <tr><td><strong>$provider</strong></td><td>$count</td><td>$percentage%</td></tr>" >> "$html_file"
        done < "$providers_file"
        
        cat >> "$html_file" << 'EOF'
                    </tbody>
                </table>
            </details>
EOF
        
        # Add detailed IP mapping if available
        if [ -f "$cloud_mapping_file" ] && [ -s "$cloud_mapping_file" ]; then
            cat >> "$html_file" << 'EOF'
            <details style="margin-top: 15px;">
                <summary>Detailed IP to Provider Mapping</summary>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Provider</th>
                            <th>URL</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
EOF
            
            tail -n +2 "$cloud_mapping_file" 2>/dev/null | head -100 | while IFS='|' read -r ip provider url status; do
                # Clean whitespace
                ip=$(echo "$ip" | xargs)
                provider=$(echo "$provider" | xargs)
                url=$(echo "$url" | xargs)
                status=$(echo "$status" | xargs)
                
                # Determine status class
                local status_class="code-${status:0:1}xx"
                
                echo "                    <tr><td>$ip</td><td><span class=\"badge badge-waf\">$provider</span></td><td>$url</td><td><span class=\"status-code $status_class\">$status</span></td></tr>" >> "$html_file"
            done
            
            cat >> "$html_file" << 'EOF'
                    </tbody>
                </table>
            </details>
EOF
        fi
        
        cat >> "$html_file" << 'EOF'
        </div>
EOF
    fi
    
    # Add findings sections with top 10
    cat >> "$html_file" << 'EOF'
        <div class="section">
            <h2>🎯 Key Findings</h2>
EOF
    
    # Login Panels (top 10)
    if [ -f "$logins_file" ] && [ -s "$logins_file" ]; then
        cat >> "$html_file" << 'EOF'
            <details open>
                <summary>🔐 Login Panels Detected (Top 10)</summary>
EOF
        head -10 "$logins_file" 2>/dev/null | while IFS= read -r line; do
            echo "                <div class=\"finding-item\">$line</div>" >> "$html_file"
        done
        cat >> "$html_file" << 'EOF'
            </details>
EOF
    fi
    
    # Sensitive Files (top 10)
    if [ -f "$sensitive_file" ] && [ -s "$sensitive_file" ]; then
        cat >> "$html_file" << 'EOF'
            <details>
                <summary>⚠️ Sensitive Files Found (Top 10)</summary>
EOF
        sort -u "$sensitive_file" | head -10 2>/dev/null | while IFS= read -r line; do
            echo "                <div class=\"finding-item\">$line</div>" >> "$html_file"
        done
        cat >> "$html_file" << 'EOF'
            </details>
EOF
    fi
    
    # CORS Vulnerabilities (top 10)
    if [ -f "$cors_file" ] && [ -s "$cors_file" ]; then
        cat >> "$html_file" << 'EOF'
            <details>
                <summary>🌐 CORS Vulnerabilities (Top 10)</summary>
EOF
        grep -i "vulnerable\|misconfigured" "$cors_file" 2>/dev/null | head -10 | while IFS= read -r line; do
            echo "                <div class=\"finding-item\">$line</div>" >> "$html_file"
        done
        cat >> "$html_file" << 'EOF'
            </details>
EOF
    fi
    
    # 403 Bypasses (top 10)
    if [ -f "$bypass_file" ] && [ -s "$bypass_file" ]; then
        cat >> "$html_file" << 'EOF'
            <details>
                <summary>🚀 403 Bypasses Successful (Top 10)</summary>
EOF
        grep "200\|302" "$bypass_file" 2>/dev/null | head -10 | while IFS= read -r line; do
            echo "                <div class=\"finding-item\">$line</div>" >> "$html_file"
        done
        cat >> "$html_file" << 'EOF'
            </details>
EOF
    fi
    
    # WAF Detections (top 10)
    if [ -f "$waf_file" ] && [ -s "$waf_file" ]; then
        cat >> "$html_file" << 'EOF'
            <details>
                <summary>🛡️ WAF Detections (Top 10)</summary>
EOF
        grep -i "waf\|detected" "$waf_file" 2>/dev/null | head -10 | while IFS= read -r line; do
            echo "                <div class=\"finding-item\">$line</div>" >> "$html_file"
        done
        cat >> "$html_file" << 'EOF'
            </details>
EOF
    fi
    
    cat >> "$html_file" << 'EOF'
        </div>
EOF
    
    cat >> "$html_file" << 'EOF'
        <div class="footer">
            <p>Generated by Recondite v2 - Advanced Reconnaissance Pipeline</p>
            <p style="margin-top: 5px; font-size: 0.85em;">For authorized security testing only</p>
        </div>
    </div>
</body>
</html>
EOF
}

generate_text_report() {
    local target=$1
    local report_dir=$2
    local txt_file="$report_dir/${target}-report.txt"
    
    log DEBUG "Generating text report: $txt_file"
    
    {
        echo "Recondite v2 - Reconnaissance Report"
        echo "===================================="
        echo "Target: $target"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        
        if [ -f "recon/$target/05_http/providers_summary.txt" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "  CLOUD PROVIDERS"
            echo "═══════════════════════════════════════════════════════════"
            cat "recon/$target/05_http/providers_summary.txt"
            echo ""
        fi
        
        if [ -f "recon/$target/03_subdomains/all_subdomains.txt" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "  SUBDOMAINS"
            echo "═══════════════════════════════════════════════════════════"
            head -100 "recon/$target/03_subdomains/all_subdomains.txt"
            echo ""
        fi
        
        if [ -f "recon/$target/09_logins_vulns/logins.txt" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "  LOGIN PANELS"
            echo "═══════════════════════════════════════════════════════════"
            cat "recon/$target/09_logins_vulns/logins.txt"
            echo ""
        fi
    } > "$txt_file"
}

generate_markdown_report() {
    local target=$1
    local report_dir=$2
    local md_file="$report_dir/${target}-report.md"
    
    log DEBUG "Generating markdown report: $md_file"
    
    {
        echo "# Recondite v2 - Reconnaissance Report"
        echo ""
        echo "**Target:** $target"
        echo "**Generated:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        
        if [ -f "recon/$target/05_http/providers_summary.txt" ]; then
            echo "## ☁️ Cloud Providers"
            echo ""
            echo "| Provider | IPs Count |"
            echo "|----------|-----------|"
            while read count provider; do
                echo "| $provider | $count |"
            done < "recon/$target/05_http/providers_summary.txt"
            echo ""
        fi
        
        if [ -f "recon/$target/03_subdomains/all_subdomains.txt" ]; then
            echo "## Subdomains"
            echo ""
            echo "\`\`\`"
            head -100 "recon/$target/03_subdomains/all_subdomains.txt"
            echo "\`\`\`"
            echo ""
        fi
        
        if [ -f "recon/$target/09_logins_vulns/logins.txt" ]; then
            echo "## Login Panels"
            echo ""
            echo "\`\`\`"
            cat "recon/$target/09_logins_vulns/logins.txt"
            echo "\`\`\`"
            echo ""
        fi
    } > "$md_file"
}

generate_csv_report() {
    local target=$1
    local report_dir=$2
    local csv_file="$report_dir/${target}-report.csv"
    
    log DEBUG "Generating CSV report: $csv_file"
    
    {
        echo "Type,URL/IP,Status,Details,CloudProvider"
        
        # Add cloud provider mapping
        if [ -f "recon/$target/05_http/cloud_providers_mapping.txt" ]; then
            tail -n +2 "recon/$target/05_http/cloud_providers_mapping.txt" 2>/dev/null | while IFS='|' read -r ip provider url status; do
                ip=$(echo "$ip" | xargs)
                provider=$(echo "$provider" | xargs)
                url=$(echo "$url" | xargs)
                status=$(echo "$status" | xargs)
                echo "Cloud IP,$url,$status,$ip,$provider"
            done
        fi
        
        if [ -f "recon/$target/05_http/httpx.json" ] && command -v jq &> /dev/null; then
            jq -r '. | "HTTP Service,\(.url),\(.status_code),\(.title // "N/A"),"' "recon/$target/05_http/httpx.json" 2>/dev/null
        fi
        
        if [ -f "recon/$target/09_logins_vulns/logins.txt" ]; then
            while IFS= read -r url; do
                echo "Login Panel,$url,Found,,"
            done < "recon/$target/09_logins_vulns/logins.txt"
        fi
        
        if [ -f "recon/$target/08_policies/corsy/cors_results.txt" ]; then
            while IFS= read -r line; do
                echo "CORS Vulnerability,$line,Vulnerable,,"
            done < "recon/$target/08_policies/corsy/cors_results.txt"
        fi
    } > "$csv_file"
}

summarize_target_to_stdout() {
    local target=$1
    
    echo ""
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  SUMMARY FOR: $target${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Count subdomains
    local subdomains_file="recon/$target/03_subdomains/all_subdomains.txt"
    if [ -f "$subdomains_file" ]; then
        local sub_count=$(wc -l < "$subdomains_file")
        echo -e "  ${GREEN}Subdomains discovered:${NC} $sub_count"
        if [ "$sub_count" -gt 0 ]; then
            echo -e "  ${DIM}Top 10:${NC}"
            head -10 "$subdomains_file" | sed 's/^/    • /'
        fi
        echo ""
    fi
    
    # Count HTTP services
    local httpx_json="recon/$target/05_http/httpx.json"
    if [ -f "$httpx_json" ] && command -v jq &> /dev/null; then
        local http_count=$(jq -r '.url' "$httpx_json" 2>/dev/null | wc -l)
        echo -e "  ${GREEN}HTTP services found:${NC} $http_count"
        if [ "$http_count" -gt 0 ]; then
            echo -e "  ${DIM}Top 10:${NC}"
            jq -r '.url' "$httpx_json" 2>/dev/null | sort -u | head -10 | sed 's/^/    • /'
        fi
        echo ""
    fi
    
    # Show cloud providers
    local providers_file="recon/$target/05_http/providers_summary.txt"
    if [ -f "$providers_file" ] && [ -s "$providers_file" ]; then
        local providers_count=$(wc -l < "$providers_file")
        echo -e "  ${CYAN}Cloud providers identified:${NC} $providers_count"
        echo -e "  ${DIM}Top providers:${NC}"
        head -10 "$providers_file" | while read count provider; do
            echo -e "    • ${BOLD}$provider${NC}: $count IPs"
        done
        echo ""
    fi
    
    # Count login panels
    local logins_file="recon/$target/09_logins_vulns/logins.txt"
    if [ -f "$logins_file" ] && [ -s "$logins_file" ]; then
        local login_count=$(wc -l < "$logins_file")
        echo -e "  ${YELLOW}Login panels found:${NC} $login_count"
        if [ "$login_count" -gt 0 ]; then
            echo -e "  ${DIM}Top 10:${NC}"
            head -10 "$logins_file" | sed 's/^/    • /'
        fi
        echo ""
    fi
    
    # Count 403 URLs and bypasses
    local urls_403="recon/$target/06_waf_403/403_urls.txt"
    if [ -f "$urls_403" ] && [ -s "$urls_403" ]; then
        local count_403=$(wc -l < "$urls_403")
        echo -e "  ${YELLOW}403 URLs found:${NC} $count_403"
    fi
    
    local bypass_file="recon/$target/06_waf_403/403jump_results.txt"
    if [ -f "$bypass_file" ] && [ -s "$bypass_file" ]; then
        local bypass_count=$(grep -c "200\|302" "$bypass_file" 2>/dev/null || echo "0")
        if [ "$bypass_count" -gt 0 ]; then
            echo -e "  ${GREEN}403 bypasses successful:${NC} $bypass_count"
            echo -e "  ${DIM}Top 10 bypassed URLs:${NC}"
            grep "200\|302" "$bypass_file" 2>/dev/null | head -10 | sed 's/^/    • /'
            echo ""
        fi
    fi
    
    # Count sensitive files
    local sensitive_file="recon/$target/07_content_js/gau/sensitive_files.txt"
    if [ -f "$sensitive_file" ] && [ -s "$sensitive_file" ]; then
        local sens_count=$(wc -l < "$sensitive_file")
        echo -e "  ${RED}Sensitive files discovered:${NC} $sens_count"
        if [ "$sens_count" -gt 0 ]; then
            echo -e "  ${DIM}Top 10:${NC}"
            sort -u "$sensitive_file" | head -10 | sed 's/^/    • /'
        fi
        echo ""
    fi
    
    # Count WAFs
    local waf_file="recon/$target/06_waf_403/wafw00f.txt"
    if [ -f "$waf_file" ] && [ -s "$waf_file" ]; then
        local waf_count=$(grep -ic "waf\|detected" "$waf_file" 2>/dev/null || echo "0")
        if [ "$waf_count" -gt 0 ]; then
            echo -e "  ${YELLOW}WAFs detected:${NC} $waf_count"
            echo -e "  ${DIM}Top 10:${NC}"
            grep -i "waf\|detected" "$waf_file" 2>/dev/null | head -10 | sed 's/^/    • /'
            echo ""
        fi
    fi
    
    # Count CORS issues
    local cors_file="recon/$target/08_policies/corsy/cors_results.txt"
    if [ -f "$cors_file" ] && [ -s "$cors_file" ]; then
        local cors_count=$(grep -ic "vulnerable\|misconfigured" "$cors_file" 2>/dev/null || echo "0")
        if [ "$cors_count" -gt 0 ]; then
            echo -e "  ${RED}CORS misconfigurations:${NC} $cors_count"
            echo -e "  ${DIM}Top 10:${NC}"
            grep -i "vulnerable\|misconfigured" "$cors_file" 2>/dev/null | head -10 | sed 's/^/    • /'
            echo ""
        fi
    fi
    
    # Count CSP issues
    local csp_file="recon/$target/08_policies/csp_stalker/csp_results.txt"
    if [ -f "$csp_file" ] && [ -s "$csp_file" ]; then
        local csp_count=$(wc -l < "$csp_file" 2>/dev/null || echo "0")
        if [ "$csp_count" -gt 0 ]; then
            echo -e "  ${YELLOW}CSP issues found:${NC} $csp_count"
            echo -e "  ${DIM}Top 10:${NC}"
            head -10 "$csp_file" | sed 's/^/    • /'
            echo ""
        fi
    fi
    
    echo ""
    echo -e "  ${BOLD}Raw data location:${NC} $(pwd)/recon/$target/"
    echo -e "  ${BOLD}Reports location:${NC} $(realpath "$OUTPUT_DIR" 2>/dev/null || echo "$OUTPUT_DIR")"
    echo ""
}

print_global_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  RECONNAISSANCE PIPELINE COMPLETED${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Reports generated at:${NC} $(realpath "$OUTPUT_DIR" 2>/dev/null || echo "$OUTPUT_DIR")"
    echo -e "  ${BOLD}Per-target raw data:${NC} $(pwd)/recon/"
    echo ""
}

###############################################################################
# Update Mode
###############################################################################

run_update_mode() {
    log INFO "Update mode: updating tools and repositories"
    
    if [ -f "install.sh" ]; then
        bash install.sh --update
    else
        log ERROR "install.sh not found. Cannot update tools."
        exit 1
    fi
}

###############################################################################
# Main Function
###############################################################################

main() {
    parse_args "$@"
    
    logo
    
    load_api_keys
    setup_environment
    
    if [ "$UPDATE_MODE" = true ]; then
        run_update_mode
        exit 0
    fi
    
    get_random_ua
    
    if [ "$VERBOSE" = true ]; then
        log INFO "Verbose mode: ENABLED"
        log INFO "Output directory: $OUTPUT_DIR"
        [ "$RANDOM_UA" = true ] && log INFO "Random user agent: ENABLED"
        [ -n "$FIXED_DELAY" ] && log INFO "Fixed delay: ${FIXED_DELAY}s"
        [ -n "$RANDOM_DELAY" ] && log INFO "Random delay: ${RANDOM_DELAY}s"
        [ "$PASSIVE_MODE" = true ] && log INFO "Passive mode: ENABLED"
    fi
    
    # Process each target
    if [ "$IS_DIRECT_DOMAIN" = true ]; then
        # Single domain provided directly
        local target=$(echo "$DIRECT_DOMAIN" | tr -d '\r\n' | sed 's|^https\?://||' | sed 's|/.*||')
        if [ -n "$target" ]; then
            run_for_target "$target"
        else
            log ERROR "Invalid domain provided: $DIRECT_DOMAIN"
            exit 1
        fi
    else
        # File with domains
        while IFS= read -r target; do
            [ -z "$target" ] && continue
            target=$(echo "$target" | tr -d '\r\n' | sed 's|^https\?://||' | sed 's|/.*||')
            [ -z "$target" ] && continue
            
            run_for_target "$target"
        done < "$DOMAINS_FILE"
    fi
    
    print_global_summary
}

# Run main function
main "$@"

