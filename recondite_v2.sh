#!/bin/bash

###############################################################################
# Recondite v2 - Advanced Reconnaissance Pipeline
# A comprehensive funnel-based reconnaissance tool for offensive security
###############################################################################

set -uo pipefail

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

# Global variables
TARGET=""
OUTPUT_DIR=""
PASSIVE_MODE=false
UPDATE_TOOLS=false
VERBOSE=false
RANDOM_UA=false
CUSTOM_DELAY=""
CONFIG_FILE="config/api_keys.conf"
TOOLS_DIR="tools"
DELAY_MIN=0.3
DELAY_MAX=0.9
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36 OPR/104.0.0.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 14; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7_10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
    "Mozilla/5.0 (Linux; Android 13; Redmi Note 12 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 12; ONEPLUS A6013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    "Mozilla/5.0 (Linux; Android 13; Pixel 6a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
    "Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)"
    "Mozilla/5.0 (Linux; Android 13; CPH2135) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Manjaro; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"
    "Mozilla/5.0 (Linux; Android 12; moto g(60)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:118.0) Gecko/20100101 Firefox/118.0"
    "Mozilla/5.0 (Linux; Android 12; SM-A528B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/121.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Linux; Android 13; VOG-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Vivaldi/6.5.3206.63 Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Linux; Android 12; SM-G781B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 13; M2101K6G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
    "Mozilla/5.0 (Linux; Android 11; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.96 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/118.0.5993.88 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:117.0) Gecko/20100101 Firefox/117.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:111.0) Gecko/20100101 Firefox/111.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave/1.61.120 Chrome/118.0.5993.88 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Vivaldi/6.1.3035.84 Chrome/114.0.5735.134 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Opera/104.0.0.0 Chrome/119.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 13; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.134 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 11; Mi 11 Lite) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 10; HMA-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 9; ONEPLUS A5000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 12; CPH2219) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.60 Mobile Safari/537.36"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_7_9 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7.9 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.8.1 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (iPod touch; CPU iPhone OS 13_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36"
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"
    "Mozilla/5.0 (compatible; Sogou web spider/4.0; +http://www.sogou.com/docs/help/webmasters.htm#07)"
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
    "Twitterbot/1.0"
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
    "curl/8.5.0"
    "Wget/1.21.3 (linux-gnu)"
    "python-requests/2.31.0"
    "Go-http-client/2.0"
    "okhttp/4.12.0"
    "PostmanRuntime/7.36.3"
    "Java/1.8.0_361"
    "libwww-perl/6.66"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) WhatsApp/2.2407.1 Chrome/108.0.5359.215 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) TelegramDesktop/5.4 Chrome/120.0.6099.224 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:2.0) Gecko/20100101 SeaMonkey/2.53.18"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:31.0) Gecko/20100101 PaleMoon/31.4.2"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Spotify/1.2.25.1006 Chrome/114.0.5735.199 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Electron/28.1.0 Chrome/120.0.6099.109 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Thunderbird/90.0"
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)"
)

# Statistics
STATS_SUBDOMAINS=0
STATS_ALIVE=0
STATS_HTTP=0
STATS_WAF=0
STATS_LOGIN_PANELS=0
STATS_CORS_VULN=0
STATS_403=0
STATS_ENDPOINTS=0
STATS_SECRETS=0

###############################################################################
# Utility Functions
###############################################################################

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Only write to log file if OUTPUT_DIR exists
    if [ -n "$OUTPUT_DIR" ] && [ -d "$OUTPUT_DIR" ]; then
        local log_file="${OUTPUT_DIR}/execution.log"
        
        case $level in
            INFO)
                echo -e "${BLUE}[*]${NC} $message" | tee -a "$log_file"
                ;;
            SUCCESS)
                echo -e "${GREEN}[+]${NC} $message" | tee -a "$log_file"
                ;;
            WARNING)
                echo -e "${YELLOW}[!]${NC} $message" | tee -a "$log_file"
                ;;
            ERROR)
                echo -e "${RED}[-]${NC} $message" | tee -a "$log_file"
                ;;
            PHASE)
                echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}" | tee -a "$log_file"
                echo -e "${BOLD}${CYAN}  $message${NC}" | tee -a "$log_file"
                echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}\n" | tee -a "$log_file"
                ;;
            DEBUG)
                if [ "$VERBOSE" = true ]; then
                    echo -e "${MAGENTA}[DEBUG]${NC} $message" | tee -a "$log_file"
                fi
                ;;
        esac
        
        echo "[$timestamp] [$level] $message" >> "$log_file"
    else
        # Just print to console if OUTPUT_DIR not set yet
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
                echo -e "${RED}[-]${NC} $message"
                ;;
            PHASE)
                echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
                echo -e "${BOLD}${CYAN}  $message${NC}"
                echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
                ;;
            DEBUG)
                if [ "$VERBOSE" = true ]; then
                    echo -e "${MAGENTA}[DEBUG]${NC} $message"
                fi
                ;;
        esac
    fi
}

get_random_user_agent() {
    if [ "$RANDOM_UA" = true ]; then
        local size=${#USER_AGENTS[@]}
        local index=$((RANDOM % size))
        echo "${USER_AGENTS[$index]}"
    else
        # Default user agent if random is not enabled
        echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    fi
}

random_delay() {
    local delay
    if [ -n "$CUSTOM_DELAY" ]; then
        delay="$CUSTOM_DELAY"
    else
        delay=$(awk "BEGIN {printf \"%.2f\", $DELAY_MIN + ($DELAY_MAX - $DELAY_MIN) * rand()}")
    fi
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Delaying ${delay}s before next operation"
    fi
    sleep "$delay"
}

# Helper function to handle command output based on verbose mode
run_command() {
    local cmd="$@"
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Executing: $cmd"
        eval "$cmd"
    else
        eval "$cmd" 2>/dev/null || true
    fi
}

# Helper function to handle command output with file redirection
run_command_silent() {
    local cmd="$1"
    local output_file="$2"
    shift 2
    local args="$@"
    
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Executing: $cmd $args > $output_file"
        eval "$cmd $args" > "$output_file" 2>&1 || true
    else
        eval "$cmd $args" > "$output_file" 2>/dev/null || true
    fi
}

check_tool() {
    local tool=$1
    local path_var=$2
    
    # Check if tool is in PATH
    if command -v "$tool" &> /dev/null; then
        eval "$path_var=$tool"
        return 0
    fi
    
    # Check in tools directory (for binaries)
    if [ -f "${TOOLS_DIR}/${tool}" ] && [ -x "${TOOLS_DIR}/${tool}" ]; then
        eval "$path_var=${TOOLS_DIR}/${tool}"
        return 0
    fi
    
    # Check for Python tools in subdirectories
    local tool_dirs=(
        "${TOOLS_DIR}/${tool}-main/${tool}-main"
        "${TOOLS_DIR}/${tool}-main"
        "${TOOLS_DIR}/${tool}-master"
        "${TOOLS_DIR}/${tool}-dev"
        "${TOOLS_DIR}/${tool}-stable"
        "${TOOLS_DIR}/${tool}"
    )
    
    for tool_dir in "${tool_dirs[@]}"; do
        if [ -d "$tool_dir" ]; then
            # Look for main Python script
            local script_name=$(basename "$tool_dir" | sed 's/-main$//;s/-master$//;s/-dev$//;s/-stable$//')
            # Try various naming patterns
            local patterns=(
                "${tool_dir}/${script_name}.py"
                "${tool_dir}/cli_${script_name}.py"
                "${tool_dir}/cli_CSP_Stalker.py"  # Special case
                "${tool_dir}/${script_name}"
                "${tool_dir}/main.py"
            )
            for pattern in "${patterns[@]}"; do
                if [ -f "$pattern" ]; then
                    eval "$path_var=$pattern"
                    return 0
                fi
            done
        fi
    done
    
    # For specific tools, check common patterns
    case "$tool" in
        "logsensor")
            if [ -f "${TOOLS_DIR}/Logsensor-main/logsensor.py" ]; then
                eval "$path_var=${TOOLS_DIR}/Logsensor-main/logsensor.py"
                return 0
            fi
            ;;
        "Corsy")
            if [ -f "${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py" ]; then
                eval "$path_var=${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py"
                return 0
            elif [ -f "${TOOLS_DIR}/Corsy-master/corsy.py" ]; then
                eval "$path_var=${TOOLS_DIR}/Corsy-master/corsy.py"
                return 0
            fi
            ;;
        "CSP-Stalker")
            if [ -f "${TOOLS_DIR}/CSP-Stalker-main/cli_CSP_Stalker.py" ]; then
                eval "$path_var=${TOOLS_DIR}/CSP-Stalker-main/cli_CSP_Stalker.py"
                return 0
            fi
            ;;
        "JSMap-Inspector")
            if [ -f "${TOOLS_DIR}/JSMap-Inspector-main/JSMap-Inspector.py" ]; then
                eval "$path_var=${TOOLS_DIR}/JSMap-Inspector-main/JSMap-Inspector.py"
                return 0
            fi
            ;;
        "403jump")
            if [ -f "${TOOLS_DIR}/403jump-main/403jump.py" ]; then
                eval "$path_var=${TOOLS_DIR}/403jump-main/403jump.py"
                return 0
            fi
            ;;
        "Caduceus")
            if [ -f "${TOOLS_DIR}/Caduceus-main/caduceus.py" ]; then
                eval "$path_var=${TOOLS_DIR}/Caduceus-main/caduceus.py"
                return 0
            fi
            ;;
        "wafw00f")
            if [ -d "${TOOLS_DIR}/wafw00f-master" ]; then
                eval "$path_var=python3 -m wafw00f"
                return 0
            fi
            ;;
        "bbot")
            if command -v bbot &> /dev/null; then
                eval "$path_var=bbot"
                return 0
            fi
            ;;
    esac
    
    log WARNING "Tool '$tool' not found. Skipping related phase."
    return 1
}

load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log WARNING "Config file not found. Creating template at $CONFIG_FILE"
        mkdir -p "$(dirname "$CONFIG_FILE")"
        cat > "$CONFIG_FILE" << 'EOF'
# API Keys Configuration for Recondite v2
# Add your API keys below (one per line, format: KEY_NAME=value)

# ProjectDiscovery Cloud Platform API (for asnmap, cvemap, etc.)
# Get your API key at: https://cloud.projectdiscovery.io/?ref=api_key
PDCP_API_KEY=

# Shodan API (for Smap)
SHODAN_API_KEY=

# VirusTotal API (optional)
VT_API_KEY=

# GitHub Token (optional, for subfinder)
GITHUB_TOKEN=

# SecurityTrails API (optional)
SECURITYTRAILS_API_KEY=

# Censys API (optional)
CENSYS_API_ID=
CENSYS_SECRET=

# BinaryEdge API (optional)
BINARYEDGE_API_KEY=

# PassiveTotal API (optional)
PASSIVETOTAL_USERNAME=
PASSIVETOTAL_KEY=
EOF
        log INFO "Template config file created. Please edit $CONFIG_FILE with your API keys."
    fi
    
    # Source the config file (fix Windows line endings)
    if [ -f "$CONFIG_FILE" ]; then
        # Remove Windows line endings (\r) before sourcing
        local temp_config=$(mktemp)
        sed 's/\r$//' "$CONFIG_FILE" > "$temp_config"
        set -a
        source "$temp_config"
        set +a
        rm -f "$temp_config"
    fi
}

###############################################################################
# Phase 0: ASN & Infrastructure Discovery
###############################################################################

phase0_asn_discovery() {
    log PHASE "Phase 0: ASN & Infrastructure Discovery"
    
    local asnmap_cmd=""
    local ipranges_cmd=""
    
    if ! check_tool "asnmap" "asnmap_cmd"; then
        log WARNING "asnmap not found, skipping ASN discovery"
        return
    fi
    
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Using asnmap: $asnmap_cmd"
    fi
    
    if ! check_tool "ipranges" "ipranges_cmd"; then
        log WARNING "ipranges not found, skipping cloud detection"
    else
        if [ "$VERBOSE" = true ]; then
            log DEBUG "Using ipranges: $ipranges_cmd"
        fi
    fi
    
    log INFO "Discovering ASN information for $TARGET"
    random_delay
    
    # Extract domain from target
    local domain=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*||')
    
    if [ -n "$asnmap_cmd" ]; then
        log INFO "Running asnmap..."
        # Set PDCP API key if available
        if [ -n "${PDCP_API_KEY:-}" ]; then
            export PDCP_API_KEY
            [ "$VERBOSE" = true ] && log DEBUG "Using PDCP API key for asnmap"
        fi
        if [ "$VERBOSE" = true ]; then
            "$asnmap_cmd" -d "$domain" -o "${OUTPUT_DIR}/asn_results.txt" -v || true
        else
            "$asnmap_cmd" -d "$domain" -o "${OUTPUT_DIR}/asn_results.txt" 2>/dev/null || true
        fi
        if [ -f "${OUTPUT_DIR}/asn_results.txt" ] && [ -s "${OUTPUT_DIR}/asn_results.txt" ]; then
            local asn_count=$(wc -l < "${OUTPUT_DIR}/asn_results.txt" 2>/dev/null || echo "0")
            log SUCCESS "ASN information saved to asn_results.txt ($asn_count entries)"
            [ "$VERBOSE" = true ] && log DEBUG "ASN results: $(head -3 "${OUTPUT_DIR}/asn_results.txt" 2>/dev/null | tr '\n' '; ')"
        fi
    fi
    
    if [ -n "$ipranges_cmd" ]; then
        log INFO "Checking cloud infrastructure..."
        random_delay
        if [ "$VERBOSE" = true ]; then
            "$ipranges_cmd" -d "$domain" -o "${OUTPUT_DIR}/cloud_ranges.txt" || true
        else
            "$ipranges_cmd" -d "$domain" -o "${OUTPUT_DIR}/cloud_ranges.txt" 2>/dev/null || true
        fi
        if [ -f "${OUTPUT_DIR}/cloud_ranges.txt" ] && [ -s "${OUTPUT_DIR}/cloud_ranges.txt" ]; then
            log SUCCESS "Cloud infrastructure information saved"
            [ "$VERBOSE" = true ] && log DEBUG "Cloud ranges: $(head -3 "${OUTPUT_DIR}/cloud_ranges.txt" 2>/dev/null | tr '\n' '; ')"
        fi
    fi
}

###############################################################################
# Phase 1: Subdomain Discovery
###############################################################################

phase1_subdomain_discovery() {
    log PHASE "Phase 1: Subdomain Discovery"
    
    local subfinder_cmd=""
    local bbot_cmd=""
    
    if ! check_tool "subfinder" "subfinder_cmd"; then
        log ERROR "subfinder is required but not found"
        return 1
    fi
    
    local domain=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*||')
    
    log INFO "Starting subdomain enumeration for $domain"
    random_delay
    
    # Subfinder - Fast enumeration
    log INFO "Running subfinder (fast enumeration)..."
    local subfinder_flags="-d $domain -o ${OUTPUT_DIR}/subfinder_results.txt"
    
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        subfinder_flags="$subfinder_flags -pc ~/.config/subfinder/provider-config.yaml"
        [ "$VERBOSE" = true ] && log DEBUG "Using GitHub token for subfinder"
    fi
    
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Running: $subfinder_cmd $subfinder_flags"
        "$subfinder_cmd" $subfinder_flags || "$subfinder_cmd" -d "$domain" -o "${OUTPUT_DIR}/subfinder_results.txt" || true
    else
        "$subfinder_cmd" $subfinder_flags 2>/dev/null || "$subfinder_cmd" -d "$domain" -o "${OUTPUT_DIR}/subfinder_results.txt" 2>/dev/null || true
    fi
    random_delay
    
    # BBOT - Deep enumeration (if not in passive mode)
    if [ "$PASSIVE_MODE" = false ] && check_tool "bbot" "bbot_cmd"; then
        log INFO "Running bbot (deep enumeration)..."
        [ "$VERBOSE" = true ] && log DEBUG "Using bbot: $bbot_cmd"
        random_delay
        if [ "$VERBOSE" = true ]; then
            $bbot_cmd -t "$domain" -p subdomain-enum -rf passive -o "${OUTPUT_DIR}/bbot_results" -v || true
        else
            $bbot_cmd -t "$domain" -p subdomain-enum -rf passive -o "${OUTPUT_DIR}/bbot_results" 2>/dev/null || true
        fi
        if [ -d "${OUTPUT_DIR}/bbot_results" ]; then
            find "${OUTPUT_DIR}/bbot_results" -name "*.txt" -exec cat {} \; >> "${OUTPUT_DIR}/bbot_subdomains.txt" 2>/dev/null || true
            [ "$VERBOSE" = true ] && log DEBUG "BBOT results saved to bbot_results directory"
        fi
    fi
    
    # Merge and deduplicate subdomains
    log INFO "Merging and deduplicating subdomain results..."
    cat "${OUTPUT_DIR}/subfinder_results.txt" "${OUTPUT_DIR}/bbot_subdomains.txt" 2>/dev/null | \
        sort -u > "${OUTPUT_DIR}/all_subdomains.txt" || true
    
    STATS_SUBDOMAINS=$(wc -l < "${OUTPUT_DIR}/all_subdomains.txt" 2>/dev/null || echo "0")
    log SUCCESS "Found $STATS_SUBDOMAINS unique subdomains"
    
    if [ "$VERBOSE" = true ] && [ "$STATS_SUBDOMAINS" -gt 0 ] && [ "$STATS_SUBDOMAINS" -le 20 ]; then
        log DEBUG "Subdomains found: $(cat "${OUTPUT_DIR}/all_subdomains.txt" 2>/dev/null | tr '\n' ' ')"
    elif [ "$VERBOSE" = true ] && [ "$STATS_SUBDOMAINS" -gt 20 ]; then
        log DEBUG "First 10 subdomains: $(head -10 "${OUTPUT_DIR}/all_subdomains.txt" 2>/dev/null | tr '\n' ' ')"
    fi
}

###############################################################################
# Phase 2: Port Scanning & Resolution
###############################################################################

phase2_port_scanning() {
    log PHASE "Phase 2: Port Scanning & Resolution"
    
    if [ ! -f "${OUTPUT_DIR}/all_subdomains.txt" ] || [ ! -s "${OUTPUT_DIR}/all_subdomains.txt" ]; then
        log WARNING "No subdomains found, skipping port scanning"
        return
    fi
    
    local smap_cmd=""
    local naabu_cmd=""
    
    # Passive scanning with Smap (Shodan)
    if [ -n "${SHODAN_API_KEY:-}" ] && check_tool "smap" "smap_cmd"; then
        log INFO "Running passive port scan with Smap (Shodan)..."
        export SHODAN_API_KEY
        [ "$VERBOSE" = true ] && log DEBUG "Using Shodan API key for passive scanning"
        random_delay
        if [ "$VERBOSE" = true ]; then
            "$smap_cmd" -iL "${OUTPUT_DIR}/all_subdomains.txt" -o "${OUTPUT_DIR}/smap_results.txt" || true
        else
            "$smap_cmd" -iL "${OUTPUT_DIR}/all_subdomains.txt" -o "${OUTPUT_DIR}/smap_results.txt" 2>/dev/null || true
        fi
        if [ -f "${OUTPUT_DIR}/smap_results.txt" ] && [ -s "${OUTPUT_DIR}/smap_results.txt" ]; then
            local smap_count=$(wc -l < "${OUTPUT_DIR}/smap_results.txt" 2>/dev/null || echo "0")
            log SUCCESS "Passive scan results saved ($smap_count entries)"
        fi
    elif [ "$VERBOSE" = true ] && [ -z "${SHODAN_API_KEY:-}" ]; then
        log DEBUG "Skipping Smap: SHODAN_API_KEY not configured"
    fi
    
    # Active scanning with Naabu (if not in passive mode)
    if [ "$PASSIVE_MODE" = false ] && check_tool "naabu" "naabu_cmd"; then
        log INFO "Running active port scan with Naabu..."
        [ "$VERBOSE" = true ] && log DEBUG "Using naabu: $naabu_cmd"
        [ "$VERBOSE" = true ] && log DEBUG "Scanning $(wc -l < "${OUTPUT_DIR}/all_subdomains.txt" 2>/dev/null || echo "0") subdomains"
        random_delay
        if [ "$VERBOSE" = true ]; then
            "$naabu_cmd" -l "${OUTPUT_DIR}/all_subdomains.txt" -o "${OUTPUT_DIR}/naabu_results.txt" -rate 1000 -v || true
        else
            "$naabu_cmd" -l "${OUTPUT_DIR}/all_subdomains.txt" -o "${OUTPUT_DIR}/naabu_results.txt" -rate 1000 2>/dev/null || true
        fi
        if [ -f "${OUTPUT_DIR}/naabu_results.txt" ] && [ -s "${OUTPUT_DIR}/naabu_results.txt" ]; then
            local naabu_count=$(wc -l < "${OUTPUT_DIR}/naabu_results.txt" 2>/dev/null || echo "0")
            log SUCCESS "Active scan results saved ($naabu_count entries)"
        fi
    elif [ "$VERBOSE" = true ] && [ "$PASSIVE_MODE" = true ]; then
        log DEBUG "Skipping Naabu: Passive mode enabled"
    fi
    
    # Merge port scan results
    cat "${OUTPUT_DIR}/smap_results.txt" "${OUTPUT_DIR}/naabu_results.txt" 2>/dev/null | \
        sort -u > "${OUTPUT_DIR}/all_ports.txt" || true
    
    # Extract alive hosts
    grep -E "^(http|https)://" "${OUTPUT_DIR}/all_ports.txt" 2>/dev/null | \
        sed 's|:\([0-9]*\)|://\1|' | sort -u > "${OUTPUT_DIR}/alive_hosts.txt" || true
    
    STATS_ALIVE=$(wc -l < "${OUTPUT_DIR}/alive_hosts.txt" 2>/dev/null || echo "0")
    log SUCCESS "Found $STATS_ALIVE alive hosts"
}

###############################################################################
# Phase 3: HTTP Probing & Technology Detection
###############################################################################

phase3_http_probing() {
    log PHASE "Phase 3: HTTP Probing & Technology Detection"
    
    local httpx_cmd=""
    local wafw00f_cmd=""
    local favicorn_cmd=""
    
    if ! check_tool "httpx" "httpx_cmd"; then
        log ERROR "httpx is required but not found"
        return 1
    fi
    
    # Prepare input for httpx
    local input_file="${OUTPUT_DIR}/alive_hosts.txt"
    if [ ! -f "$input_file" ] || [ ! -s "$input_file" ]; then
        input_file="${OUTPUT_DIR}/all_subdomains.txt"
    fi
    
    if [ ! -f "$input_file" ] || [ ! -s "$input_file" ]; then
        log WARNING "No hosts to probe, skipping HTTP phase"
        return
    fi
    
    log INFO "Probing HTTP/HTTPS services..."
    random_delay
    
    local user_agent=$(get_random_user_agent)
    [ "$VERBOSE" = true ] && log DEBUG "Using User-Agent: $user_agent"
    
    # HTTP probing with httpx
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Running httpx on $(wc -l < "$input_file" 2>/dev/null || echo "0") targets"
        "$httpx_cmd" -l "$input_file" \
            -title -tech-detect -status-code -content-length -server \
            -H "User-Agent: $user_agent" \
            -o "${OUTPUT_DIR}/httpx_results.txt" \
            -json-output "${OUTPUT_DIR}/httpx_results.json" \
            -rate-limit 50 -v || true
    else
        "$httpx_cmd" -l "$input_file" \
            -title -tech-detect -status-code -content-length -server \
            -H "User-Agent: $user_agent" \
            -o "${OUTPUT_DIR}/httpx_results.txt" \
            -json-output "${OUTPUT_DIR}/httpx_results.json" \
            -rate-limit 50 2>/dev/null || true
    fi
    
    random_delay
    
    # Extract URLs from httpx results
    grep -E "^(http|https)://" "${OUTPUT_DIR}/httpx_results.txt" 2>/dev/null | \
        sort -u > "${OUTPUT_DIR}/http_urls.txt" || true
    
    STATS_HTTP=$(wc -l < "${OUTPUT_DIR}/http_urls.txt" 2>/dev/null || echo "0")
    log SUCCESS "Found $STATS_HTTP HTTP/HTTPS services"
    
    # WAF Detection
    if check_tool "wafw00f" "wafw00f_cmd"; then
        log INFO "Detecting WAFs..."
        [ "$VERBOSE" = true ] && log DEBUG "Scanning $(wc -l < "${OUTPUT_DIR}/http_urls.txt" 2>/dev/null || echo "0") URLs for WAFs"
        random_delay
        local url_count=0
        while IFS= read -r url; do
            random_delay
            url_count=$((url_count + 1))
            [ "$VERBOSE" = true ] && [ $((url_count % 10)) -eq 0 ] && log DEBUG "WAF detection progress: $url_count URLs processed"
            if [[ "$wafw00f_cmd" == *"python3 -m wafw00f"* ]] || [[ "$wafw00f_cmd" == *"python -m wafw00f"* ]]; then
                if [ "$VERBOSE" = true ]; then
                    $wafw00f_cmd "$url" | grep -i "waf\|detected" >> "${OUTPUT_DIR}/waf_results.txt" || true
                else
                    $wafw00f_cmd "$url" 2>/dev/null | grep -i "waf\|detected" >> "${OUTPUT_DIR}/waf_results.txt" || true
                fi
            elif command -v wafw00f &> /dev/null; then
                if [ "$VERBOSE" = true ]; then
                    wafw00f "$url" | grep -i "waf\|detected" >> "${OUTPUT_DIR}/waf_results.txt" || true
                else
                    wafw00f "$url" 2>/dev/null | grep -i "waf\|detected" >> "${OUTPUT_DIR}/waf_results.txt" || true
                fi
            fi
        done < "${OUTPUT_DIR}/http_urls.txt"
        
        if [ -f "${OUTPUT_DIR}/waf_results.txt" ] && [ -s "${OUTPUT_DIR}/waf_results.txt" ]; then
            STATS_WAF=$(grep -c "detected\|waf" "${OUTPUT_DIR}/waf_results.txt" 2>/dev/null || echo "0")
            log SUCCESS "WAF detection completed ($STATS_WAF WAFs detected)"
            [ "$VERBOSE" = true ] && log DEBUG "WAF results: $(head -5 "${OUTPUT_DIR}/waf_results.txt" 2>/dev/null | tr '\n' '; ')"
        fi
    fi
    
    # Favicon fingerprinting
    if check_tool "favicorn" "favicorn_cmd"; then
        log INFO "Running favicon fingerprinting..."
        [ "$VERBOSE" = true ] && log DEBUG "Using favicorn: $favicorn_cmd"
        [ "$VERBOSE" = true ] && log DEBUG "Processing $(wc -l < "${OUTPUT_DIR}/http_urls.txt" 2>/dev/null || echo "0") URLs"
        random_delay
        if [ "$VERBOSE" = true ]; then
            "$favicorn_cmd" -l "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/favicorn_results.txt" || true
        else
            "$favicorn_cmd" -l "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/favicorn_results.txt" 2>/dev/null || true
        fi
        if [ -f "${OUTPUT_DIR}/favicorn_results.txt" ] && [ -s "${OUTPUT_DIR}/favicorn_results.txt" ]; then
            local favicorn_count=$(wc -l < "${OUTPUT_DIR}/favicorn_results.txt" 2>/dev/null || echo "0")
            log SUCCESS "Favicon fingerprinting completed ($favicorn_count results)"
        fi
    fi
    
    # Filter 403 responses for later bypass attempts
    grep "403" "${OUTPUT_DIR}/httpx_results.txt" 2>/dev/null | \
        awk '{print $1}' > "${OUTPUT_DIR}/403_urls.txt" || true
    STATS_403=$(wc -l < "${OUTPUT_DIR}/403_urls.txt" 2>/dev/null || echo "0")
}

###############################################################################
# Phase 4: Deep Crawling & Data Mining
###############################################################################

phase4_deep_crawling() {
    log PHASE "Phase 4: Deep Crawling & Data Mining"
    
    if [ ! -f "${OUTPUT_DIR}/http_urls.txt" ] || [ ! -s "${OUTPUT_DIR}/http_urls.txt" ]; then
        log WARNING "No HTTP URLs to crawl, skipping deep crawling"
        return
    fi
    
    local gau_cmd=""
    local cariddi_cmd=""
    local jsmap_cmd=""
    local csp_stalker_cmd=""
    
    # GAU - Get All URLs from Wayback Machine
    if check_tool "gau" "gau_cmd"; then
        log INFO "Fetching historical URLs with GAU..."
        [ "$VERBOSE" = true ] && log DEBUG "Processing $(wc -l < "${OUTPUT_DIR}/http_urls.txt" 2>/dev/null || echo "0") URLs with GAU"
        random_delay
        # Use the correct gau syntax: echo url | gau | grep pattern
        if [ "$VERBOSE" = true ]; then
            while IFS= read -r url; do
                random_delay
                echo "$url" | "$gau_cmd" | \
                    grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$" \
                    >> "${OUTPUT_DIR}/gau_sensitive_files.txt" || true
            done < "${OUTPUT_DIR}/http_urls.txt"
        else
            while IFS= read -r url; do
                random_delay
                echo "$url" | "$gau_cmd" 2>/dev/null | \
                    grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$" \
                    >> "${OUTPUT_DIR}/gau_sensitive_files.txt" 2>/dev/null || true
            done < "${OUTPUT_DIR}/http_urls.txt"
        fi
        
        if [ -f "${OUTPUT_DIR}/gau_sensitive_files.txt" ] && [ -s "${OUTPUT_DIR}/gau_sensitive_files.txt" ]; then
            sort -u "${OUTPUT_DIR}/gau_sensitive_files.txt" -o "${OUTPUT_DIR}/gau_sensitive_files.txt"
            local sensitive_count=$(wc -l < "${OUTPUT_DIR}/gau_sensitive_files.txt" 2>/dev/null || echo "0")
            log SUCCESS "Found sensitive files from Wayback Machine ($sensitive_count files)"
            [ "$VERBOSE" = true ] && log DEBUG "Sample sensitive files: $(head -5 "${OUTPUT_DIR}/gau_sensitive_files.txt" 2>/dev/null | tr '\n' '; ')"
        fi
    fi
    
    # Cariddi - Parameter and endpoint discovery
    if check_tool "cariddi" "cariddi_cmd"; then
        log INFO "Running Cariddi for parameter and endpoint discovery..."
        [ "$VERBOSE" = true ] && log DEBUG "Using cariddi: $cariddi_cmd"
        [ "$VERBOSE" = true ] && log DEBUG "Processing $(wc -l < "${OUTPUT_DIR}/http_urls.txt" 2>/dev/null || echo "0") URLs"
        random_delay
        if [ "$VERBOSE" = true ]; then
            "$cariddi_cmd" -l "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/cariddi_results.txt" || true
        else
            "$cariddi_cmd" -l "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/cariddi_results.txt" 2>/dev/null || true
        fi
        if [ -f "${OUTPUT_DIR}/cariddi_results.txt" ] && [ -s "${OUTPUT_DIR}/cariddi_results.txt" ]; then
            STATS_ENDPOINTS=$(grep -c "endpoint\|parameter" "${OUTPUT_DIR}/cariddi_results.txt" 2>/dev/null || echo "0")
            log SUCCESS "Endpoint discovery completed ($STATS_ENDPOINTS endpoints/parameters found)"
            [ "$VERBOSE" = true ] && log DEBUG "Sample results: $(head -3 "${OUTPUT_DIR}/cariddi_results.txt" 2>/dev/null | tr '\n' '; ')"
        fi
    fi
    
    # JSMap Inspector - JavaScript analysis
    if check_tool "JSMap-Inspector" "jsmap_cmd"; then
        log INFO "Analyzing JavaScript files for secrets..."
        random_delay
        if [[ "$jsmap_cmd" == *.py ]]; then
            python3 "$jsmap_cmd" -l "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/jsmap_results.txt" 2>/dev/null || true
        else
            "$jsmap_cmd" -l "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/jsmap_results.txt" 2>/dev/null || true
        fi
        if [ -f "${OUTPUT_DIR}/jsmap_results.txt" ] && [ -s "${OUTPUT_DIR}/jsmap_results.txt" ]; then
            STATS_SECRETS=$(grep -ic "secret\|api\|key\|token" "${OUTPUT_DIR}/jsmap_results.txt" 2>/dev/null || echo "0")
            log SUCCESS "JavaScript analysis completed"
        fi
    fi
    
    # CSP Stalker - Content Security Policy analysis
    if check_tool "CSP-Stalker" "csp_stalker_cmd"; then
        log INFO "Analyzing CSP headers..."
        [ "$VERBOSE" = true ] && log DEBUG "Using CSP-Stalker: $csp_stalker_cmd"
        random_delay
        local csp_count=0
        if [[ "$csp_stalker_cmd" == *.py ]]; then
            while IFS= read -r url; do
                random_delay
                csp_count=$((csp_count + 1))
                [ "$VERBOSE" = true ] && [ $((csp_count % 5)) -eq 0 ] && log DEBUG "CSP analysis progress: $csp_count URLs processed"
                if [ "$VERBOSE" = true ]; then
                    python3 "$csp_stalker_cmd" -u "$url" -o "${OUTPUT_DIR}/csp_results" || true
                else
                    python3 "$csp_stalker_cmd" -u "$url" -o "${OUTPUT_DIR}/csp_results" 2>/dev/null || true
                fi
            done < <(head -20 "${OUTPUT_DIR}/http_urls.txt")
        else
            while IFS= read -r url; do
                random_delay
                csp_count=$((csp_count + 1))
                [ "$VERBOSE" = true ] && [ $((csp_count % 5)) -eq 0 ] && log DEBUG "CSP analysis progress: $csp_count URLs processed"
                if [ "$VERBOSE" = true ]; then
                    "$csp_stalker_cmd" -u "$url" -o "${OUTPUT_DIR}/csp_results" || true
                else
                    "$csp_stalker_cmd" -u "$url" -o "${OUTPUT_DIR}/csp_results" 2>/dev/null || true
                fi
            done < <(head -20 "${OUTPUT_DIR}/http_urls.txt")
        fi
        log SUCCESS "CSP analysis completed ($csp_count URLs analyzed)"
    fi
}

###############################################################################
# Phase 5: Vulnerability Scanning
###############################################################################

phase5_vulnerability_scanning() {
    log PHASE "Phase 5: Vulnerability Scanning"
    
    local logsensor_cmd=""
    local corsy_cmd=""
    local cvemap_cmd=""
    local caduceus_cmd=""
    local jump403_cmd=""
    
    # 403 Bypass attempts
    if [ -f "${OUTPUT_DIR}/403_urls.txt" ] && [ -s "${OUTPUT_DIR}/403_urls.txt" ]; then
        if check_tool "403jump" "jump403_cmd"; then
            local bypass_count=$(wc -l < "${OUTPUT_DIR}/403_urls.txt" 2>/dev/null || echo "0")
            log INFO "Attempting 403 bypasses on $bypass_count URLs..."
            [ "$VERBOSE" = true ] && log DEBUG "Using 403jump: $jump403_cmd"
            random_delay
            local processed=0
            while IFS= read -r url; do
                random_delay
                processed=$((processed + 1))
                [ "$VERBOSE" = true ] && [ $((processed % 5)) -eq 0 ] && log DEBUG "403 bypass progress: $processed/$bypass_count URLs"
                if [[ "$jump403_cmd" == *.py ]]; then
                    if [ "$VERBOSE" = true ]; then
                        python3 "$jump403_cmd" -u "$url" >> "${OUTPUT_DIR}/403_bypass_results.txt" || true
                    else
                        python3 "$jump403_cmd" -u "$url" >> "${OUTPUT_DIR}/403_bypass_results.txt" 2>/dev/null || true
                    fi
                else
                    if [ "$VERBOSE" = true ]; then
                        "$jump403_cmd" -u "$url" >> "${OUTPUT_DIR}/403_bypass_results.txt" || true
                    else
                        "$jump403_cmd" -u "$url" >> "${OUTPUT_DIR}/403_bypass_results.txt" 2>/dev/null || true
                    fi
                fi
            done < "${OUTPUT_DIR}/403_urls.txt"
            [ "$VERBOSE" = true ] && log DEBUG "403 bypass attempts completed"
        fi
    elif [ "$VERBOSE" = true ]; then
        log DEBUG "No 403 URLs found, skipping bypass attempts"
    fi
    
    # Login panel detection
    if check_tool "logsensor" "logsensor_cmd"; then
        log INFO "Scanning for login panels..."
        [ "$VERBOSE" = true ] && log DEBUG "Using logsensor: $logsensor_cmd"
        [ "$VERBOSE" = true ] && log DEBUG "Scanning $(wc -l < "${OUTPUT_DIR}/http_urls.txt" 2>/dev/null || echo "0") URLs for login panels"
        random_delay
        if [[ "$logsensor_cmd" == *.py ]]; then
            if [ "$VERBOSE" = true ]; then
                python3 "$logsensor_cmd" -f "${OUTPUT_DIR}/http_urls.txt" --login 2>&1 | tee "${OUTPUT_DIR}/login_panels.txt" || true
            else
                python3 "$logsensor_cmd" -f "${OUTPUT_DIR}/http_urls.txt" --login 2>/dev/null | tee "${OUTPUT_DIR}/login_panels.txt" || true
            fi
        else
            if [ "$VERBOSE" = true ]; then
                "$logsensor_cmd" -f "${OUTPUT_DIR}/http_urls.txt" --login 2>&1 | tee "${OUTPUT_DIR}/login_panels.txt" || true
            else
                "$logsensor_cmd" -f "${OUTPUT_DIR}/http_urls.txt" --login 2>/dev/null | tee "${OUTPUT_DIR}/login_panels.txt" || true
            fi
        fi
        if [ -f "${OUTPUT_DIR}/login_panels.txt" ] && [ -s "${OUTPUT_DIR}/login_panels.txt" ]; then
            # Extract only URLs from logsensor output (filter out ASCII art and messages)
            grep -E "^https?://" "${OUTPUT_DIR}/login_panels.txt" > "${OUTPUT_DIR}/login_panels_clean.txt" 2>/dev/null || true
            STATS_LOGIN_PANELS=$(wc -l < "${OUTPUT_DIR}/login_panels_clean.txt" 2>/dev/null || echo "0")
            if [ "$STATS_LOGIN_PANELS" -gt 0 ]; then
                mv "${OUTPUT_DIR}/login_panels_clean.txt" "${OUTPUT_DIR}/login_panels.txt"
                log SUCCESS "Found $STATS_LOGIN_PANELS login panels"
                [ "$VERBOSE" = true ] && log DEBUG "Login panels: $(head -3 "${OUTPUT_DIR}/login_panels.txt" 2>/dev/null | tr '\n' '; ')"
            else
                STATS_LOGIN_PANELS=0
                log INFO "No login panels detected"
            fi
        else
            STATS_LOGIN_PANELS=0
        fi
    fi
    
    # CORS vulnerability scanning
    if check_tool "Corsy" "corsy_cmd"; then
        log INFO "Scanning for CORS misconfigurations..."
        [ "$VERBOSE" = true ] && log DEBUG "Using Corsy: $corsy_cmd"
        [ "$VERBOSE" = true ] && log DEBUG "Scanning $(wc -l < "${OUTPUT_DIR}/http_urls.txt" 2>/dev/null || echo "0") URLs for CORS"
        random_delay
        if [[ "$corsy_cmd" == *.py ]]; then
            if [ "$VERBOSE" = true ]; then
                python3 "$corsy_cmd" -i "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/cors_results.txt" || true
            else
                python3 "$corsy_cmd" -i "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/cors_results.txt" 2>/dev/null || true
            fi
        else
            if [ "$VERBOSE" = true ]; then
                "$corsy_cmd" -i "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/cors_results.txt" || true
            else
                "$corsy_cmd" -i "${OUTPUT_DIR}/http_urls.txt" -o "${OUTPUT_DIR}/cors_results.txt" 2>/dev/null || true
            fi
        fi
        if [ -f "${OUTPUT_DIR}/cors_results.txt" ] && [ -s "${OUTPUT_DIR}/cors_results.txt" ]; then
            STATS_CORS_VULN=$(grep -ic "vulnerable\|misconfigured\|CORS" "${OUTPUT_DIR}/cors_results.txt" 2>/dev/null || echo "0")
            log SUCCESS "CORS scanning completed ($STATS_CORS_VULN vulnerabilities found)"
            [ "$VERBOSE" = true ] && log DEBUG "CORS vulnerabilities: $(head -3 "${OUTPUT_DIR}/cors_results.txt" 2>/dev/null | tr '\n' '; ')"
        fi
    fi
    
    # CVE mapping (if cvemap is available)
    if check_tool "cvemap" "cvemap_cmd"; then
        log INFO "Checking for known CVEs..."
        [ "$VERBOSE" = true ] && log DEBUG "Using cvemap: $cvemap_cmd"
        # Set PDCP API key if available
        if [ -n "${PDCP_API_KEY:-}" ]; then
            export PDCP_API_KEY
            [ "$VERBOSE" = true ] && log DEBUG "Using PDCP API key for cvemap"
        fi
        random_delay
        # CVE mapping requires server version information from httpx results
        if [ -f "${OUTPUT_DIR}/httpx_results.json" ] && [ -s "${OUTPUT_DIR}/httpx_results.json" ]; then
            log INFO "CVE mapping requires server version information from httpx results"
            [ "$VERBOSE" = true ] && log DEBUG "httpx_results.json available for CVE mapping"
        else
            log INFO "CVE mapping requires server version information (httpx results not available)"
        fi
    fi
    
    # Cloud bucket enumeration (Caduceus)
    if check_tool "Caduceus" "caduceus_cmd"; then
        log INFO "Enumerating cloud storage buckets..."
        random_delay
        local domain=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*||')
        if [[ "$caduceus_cmd" == *.py ]]; then
            python3 "$caduceus_cmd" -d "$domain" -o "${OUTPUT_DIR}/cloud_buckets.txt" 2>/dev/null || true
        else
            "$caduceus_cmd" -d "$domain" -o "${OUTPUT_DIR}/cloud_buckets.txt" 2>/dev/null || true
        fi
    fi
}

###############################################################################
# Report Generation
###############################################################################

generate_html_report() {
    log INFO "Generating HTML report..."
    
    local html_file="${OUTPUT_DIR}/report.html"
    local domain=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*||')
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recondite v2 - Reconnaissance Report</title>
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
        .badge-403 { background: #6c757d; color: white; }
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Recondite v2</h1>
            <p>Advanced Reconnaissance Report</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Target: DOMAIN_PLACEHOLDER | Generated: TIMESTAMP_PLACEHOLDER</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">SUBDOMAINS_PLACEHOLDER</div>
                <div class="stat-label">Subdomains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">ALIVE_PLACEHOLDER</div>
                <div class="stat-label">Alive Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">HTTP_PLACEHOLDER</div>
                <div class="stat-label">HTTP Services</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">WAF_PLACEHOLDER</div>
                <div class="stat-label">WAF Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">LOGIN_PLACEHOLDER</div>
                <div class="stat-label">Login Panels</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">CORS_PLACEHOLDER</div>
                <div class="stat-label">CORS Vulnerable</div>
            </div>
        </div>
EOF

    # Add subdomains section
    if [ -f "${OUTPUT_DIR}/all_subdomains.txt" ] && [ -s "${OUTPUT_DIR}/all_subdomains.txt" ]; then
        cat >> "$html_file" << 'EOF'
        <div class="section">
            <h2>🌐 Discovered Subdomains</h2>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Status</th>
                        <th>WAF</th>
                        <th>Login Panel</th>
                    </tr>
                </thead>
                <tbody>
EOF
        while IFS= read -r subdomain; do
            local status="Unknown"
            local waf="No"
            local login="No"
            
            # Check status code
            if [ -f "${OUTPUT_DIR}/httpx_results.txt" ]; then
                local status_line=$(grep "$subdomain" "${OUTPUT_DIR}/httpx_results.txt" 2>/dev/null | head -1)
                if [ -n "$status_line" ]; then
                    status=$(echo "$status_line" | grep -oE '[0-9]{3}' | head -1 || echo "Unknown")
                fi
            fi
            
            # Check WAF
            if [ -f "${OUTPUT_DIR}/waf_results.txt" ]; then
                grep -qi "$subdomain" "${OUTPUT_DIR}/waf_results.txt" && waf="Yes"
            fi
            
            # Check login panel
            if [ -f "${OUTPUT_DIR}/login_panels.txt" ]; then
                grep -qi "$subdomain" "${OUTPUT_DIR}/login_panels.txt" && login="Yes"
            fi
            
            local status_class=""
            case "$status" in
                2??) status_class="code-2xx" ;;
                3??) status_class="code-3xx" ;;
                4??) status_class="code-4xx" ;;
                5??) status_class="code-5xx" ;;
            esac
            
            cat >> "$html_file" << EOF
                    <tr>
                        <td>$subdomain</td>
                        <td><span class="status-code $status_class">$status</span></td>
                        <td>$waf</td>
                        <td>$login</td>
                    </tr>
EOF
        done < <(head -100 "${OUTPUT_DIR}/all_subdomains.txt")
        
        cat >> "$html_file" << 'EOF'
                </tbody>
            </table>
        </div>
EOF
    fi
    
    # Add HTTP services section
    if [ -f "${OUTPUT_DIR}/httpx_results.txt" ] && [ -s "${OUTPUT_DIR}/httpx_results.txt" ]; then
        cat >> "$html_file" << 'EOF'
        <div class="section">
            <h2>🌍 HTTP Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status Code</th>
                        <th>Title</th>
                        <th>Server</th>
                    </tr>
                </thead>
                <tbody>
EOF
        while IFS= read -r line; do
            local url=$(echo "$line" | awk '{print $1}')
            local status=$(echo "$line" | grep -oE '[0-9]{3}' | head -1 || echo "N/A")
            local title=$(echo "$line" | sed -n 's/.*\[\(.*\)\].*/\1/p' || echo "N/A")
            local server=$(echo "$line" | grep -oE '\[.*\]' | tail -1 | tr -d '[]' || echo "N/A")
            
            local status_class=""
            case "$status" in
                2??) status_class="code-2xx" ;;
                3??) status_class="code-3xx" ;;
                4??) status_class="code-4xx" ;;
                5??) status_class="code-5xx" ;;
            esac
            
            cat >> "$html_file" << EOF
                    <tr>
                        <td><a href="$url" target="_blank">$url</a></td>
                        <td><span class="status-code $status_class">$status</span></td>
                        <td>$title</td>
                        <td>$server</td>
                    </tr>
EOF
        done < <(head -50 "${OUTPUT_DIR}/httpx_results.txt")
        
        cat >> "$html_file" << 'EOF'
                </tbody>
            </table>
        </div>
EOF
    fi
    
    # Add findings section
    cat >> "$html_file" << 'EOF'
        <div class="section">
            <h2>🎯 Key Findings</h2>
EOF
    
    if [ -f "${OUTPUT_DIR}/login_panels.txt" ] && [ -s "${OUTPUT_DIR}/login_panels.txt" ]; then
        cat >> "$html_file" << 'EOF'
            <h3 style="margin-top: 20px; color: #17a2b8;">Login Panels Detected</h3>
            <div class="code-block">
EOF
        head -20 "${OUTPUT_DIR}/login_panels.txt" >> "$html_file" 2>/dev/null || true
        cat >> "$html_file" << 'EOF'
            </div>
EOF
    fi
    
    if [ -f "${OUTPUT_DIR}/cors_results.txt" ] && [ -s "${OUTPUT_DIR}/cors_results.txt" ]; then
        cat >> "$html_file" << 'EOF'
            <h3 style="margin-top: 20px; color: #dc3545;">CORS Vulnerabilities</h3>
            <div class="code-block">
EOF
        head -20 "${OUTPUT_DIR}/cors_results.txt" >> "$html_file" 2>/dev/null || true
        cat >> "$html_file" << 'EOF'
            </div>
EOF
    fi
    
    if [ -f "${OUTPUT_DIR}/gau_sensitive_files.txt" ] && [ -s "${OUTPUT_DIR}/gau_sensitive_files.txt" ]; then
        cat >> "$html_file" << 'EOF'
            <h3 style="margin-top: 20px; color: #ffc107;">Sensitive Files Found</h3>
            <div class="code-block">
EOF
        head -30 "${OUTPUT_DIR}/gau_sensitive_files.txt" >> "$html_file" 2>/dev/null || true
        cat >> "$html_file" << 'EOF'
            </div>
EOF
    fi
    
    # Replace placeholders (clean variables to avoid sed errors)
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local clean_login_panels=$(echo "$STATS_LOGIN_PANELS" | tr -d '\n\r ' | head -1)
    # Use a temporary file for sed replacements to avoid issues with special characters
    local temp_html=$(mktemp)
    cp "$html_file" "$temp_html"
    sed "s|DOMAIN_PLACEHOLDER|$domain|g" "$temp_html" | \
        sed "s|TIMESTAMP_PLACEHOLDER|$timestamp|g" | \
        sed "s|SUBDOMAINS_PLACEHOLDER|$STATS_SUBDOMAINS|g" | \
        sed "s|ALIVE_PLACEHOLDER|$STATS_ALIVE|g" | \
        sed "s|HTTP_PLACEHOLDER|$STATS_HTTP|g" | \
        sed "s|WAF_PLACEHOLDER|$STATS_WAF|g" | \
        sed "s|LOGIN_PLACEHOLDER|${clean_login_panels:-0}|g" | \
        sed "s|CORS_PLACEHOLDER|$STATS_CORS_VULN|g" > "$html_file"
    rm -f "$temp_html"
    
    cat >> "$html_file" << 'EOF'
        </div>
        
        <div class="footer">
            <p>Generated by Recondite v2 - Advanced Reconnaissance Pipeline</p>
            <p style="margin-top: 5px; font-size: 0.85em;">For authorized security testing only</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log SUCCESS "HTML report generated: $html_file"
}

generate_text_report() {
    log INFO "Generating text report..."
    
    local txt_file="${OUTPUT_DIR}/report.txt"
    local domain=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*||')
    
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "  Recondite v2 - Reconnaissance Report"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "Target: $domain"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "  STATISTICS"
        echo "═══════════════════════════════════════════════════════════"
        echo "Subdomains Found:     $STATS_SUBDOMAINS"
        echo "Alive Hosts:          $STATS_ALIVE"
        echo "HTTP Services:        $STATS_HTTP"
        echo "WAF Detected:         $STATS_WAF"
        echo "Login Panels:         $STATS_LOGIN_PANELS"
        echo "CORS Vulnerable:      $STATS_CORS_VULN"
        echo "403 Responses:        $STATS_403"
        echo "Endpoints Found:      $STATS_ENDPOINTS"
        echo "Secrets in JS:        $STATS_SECRETS"
        echo ""
        
        if [ -f "${OUTPUT_DIR}/all_subdomains.txt" ] && [ -s "${OUTPUT_DIR}/all_subdomains.txt" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "  SUBDOMAINS"
            echo "═══════════════════════════════════════════════════════════"
            head -50 "${OUTPUT_DIR}/all_subdomains.txt"
            echo ""
        fi
        
        if [ -f "${OUTPUT_DIR}/login_panels.txt" ] && [ -s "${OUTPUT_DIR}/login_panels.txt" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "  LOGIN PANELS"
            echo "═══════════════════════════════════════════════════════════"
            cat "${OUTPUT_DIR}/login_panels.txt"
            echo ""
        fi
        
        if [ -f "${OUTPUT_DIR}/cors_results.txt" ] && [ -s "${OUTPUT_DIR}/cors_results.txt" ]; then
            echo "═══════════════════════════════════════════════════════════"
            echo "  CORS VULNERABILITIES"
            echo "═══════════════════════════════════════════════════════════"
            head -20 "${OUTPUT_DIR}/cors_results.txt"
            echo ""
        fi
    } > "$txt_file"
    
    log SUCCESS "Text report generated: $txt_file"
}

generate_markdown_report() {
    log INFO "Generating Markdown report..."
    
    local md_file="${OUTPUT_DIR}/report.md"
    local domain=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*||')
    
    {
        echo "# Recondite v2 - Reconnaissance Report"
        echo ""
        echo "**Target:** \`$domain\`"
        echo "**Generated:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "## Statistics"
        echo ""
        echo "| Metric | Count |"
        echo "|--------|-------|"
        echo "| Subdomains Found | $STATS_SUBDOMAINS |"
        echo "| Alive Hosts | $STATS_ALIVE |"
        echo "| HTTP Services | $STATS_HTTP |"
        echo "| WAF Detected | $STATS_WAF |"
        echo "| Login Panels | $STATS_LOGIN_PANELS |"
        echo "| CORS Vulnerable | $STATS_CORS_VULN |"
        echo "| 403 Responses | $STATS_403 |"
        echo "| Endpoints Found | $STATS_ENDPOINTS |"
        echo "| Secrets in JS | $STATS_SECRETS |"
        echo ""
        
        if [ -f "${OUTPUT_DIR}/all_subdomains.txt" ] && [ -s "${OUTPUT_DIR}/all_subdomains.txt" ]; then
            echo "## Subdomains"
            echo ""
            echo "\`\`\`"
            head -100 "${OUTPUT_DIR}/all_subdomains.txt"
            echo "\`\`\`"
            echo ""
        fi
        
        if [ -f "${OUTPUT_DIR}/login_panels.txt" ] && [ -s "${OUTPUT_DIR}/login_panels.txt" ]; then
            echo "## Login Panels"
            echo ""
            echo "\`\`\`"
            cat "${OUTPUT_DIR}/login_panels.txt"
            echo "\`\`\`"
            echo ""
        fi
    } > "$md_file"
    
    log SUCCESS "Markdown report generated: $md_file"
}

generate_csv_report() {
    log INFO "Generating CSV report..."
    
    local csv_file="${OUTPUT_DIR}/report.csv"
    
    {
        echo "Type,URL,Status,Details"
        
        if [ -f "${OUTPUT_DIR}/http_urls.txt" ] && [ -s "${OUTPUT_DIR}/http_urls.txt" ]; then
            while IFS= read -r url; do
                echo "HTTP Service,$url,Active,"
            done < "${OUTPUT_DIR}/http_urls.txt"
        fi
        
        if [ -f "${OUTPUT_DIR}/login_panels.txt" ] && [ -s "${OUTPUT_DIR}/login_panels.txt" ]; then
            while IFS= read -r url; do
                echo "Login Panel,$url,Found,"
            done < "${OUTPUT_DIR}/login_panels.txt"
        fi
        
        if [ -f "${OUTPUT_DIR}/cors_results.txt" ] && [ -s "${OUTPUT_DIR}/cors_results.txt" ]; then
            while IFS= read -r line; do
                echo "CORS Vulnerability,$line,Vulnerable,"
            done < "${OUTPUT_DIR}/cors_results.txt"
        fi
    } > "$csv_file"
    
    log SUCCESS "CSV report generated: $csv_file"
}

generate_summary() {
    log PHASE "Generating Summary Report"
    
    local domain=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*||')
    
    echo ""
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  RECONNAISSANCE SUMMARY${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BOLD}Target Domain:${NC} $domain"
    echo -e "${BOLD}Scan Date:${NC} $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo -e "${BOLD}${GREEN}KEY METRICS:${NC}"
    echo -e "  • Subdomains Discovered:     ${GREEN}$STATS_SUBDOMAINS${NC}"
    echo -e "  • Alive Hosts:               ${GREEN}$STATS_ALIVE${NC}"
    echo -e "  • HTTP/HTTPS Services:        ${GREEN}$STATS_HTTP${NC}"
    echo -e "  • WAF Detected:               ${YELLOW}$STATS_WAF${NC}"
    echo -e "  • Login Panels Found:         ${YELLOW}$STATS_LOGIN_PANELS${NC}"
    echo -e "  • CORS Vulnerabilities:       ${RED}$STATS_CORS_VULN${NC}"
    echo -e "  • 403 Forbidden Responses:   ${YELLOW}$STATS_403${NC}"
    echo -e "  • Endpoints Discovered:       ${GREEN}$STATS_ENDPOINTS${NC}"
    echo -e "  • Secrets in JavaScript:     ${RED}$STATS_SECRETS${NC}"
    echo ""
    
    local clean_login_panels=$(echo "$STATS_LOGIN_PANELS" | tr -d '\n\r ' | head -1)
    if [ -n "$clean_login_panels" ] && [ "$clean_login_panels" -gt 0 ] 2>/dev/null; then
        echo -e "${BOLD}${YELLOW}⚠️  LOGIN PANELS DETECTED:${NC}"
        if [ -f "${OUTPUT_DIR}/login_panels.txt" ]; then
            head -5 "${OUTPUT_DIR}/login_panels.txt" | while read -r panel; do
                echo -e "  • $panel"
            done
        fi
        echo ""
    fi
    
    if [ "$STATS_CORS_VULN" -gt 0 ]; then
        echo -e "${BOLD}${RED}🚨 CORS VULNERABILITIES FOUND:${NC}"
        if [ -f "${OUTPUT_DIR}/cors_results.txt" ]; then
            head -3 "${OUTPUT_DIR}/cors_results.txt" | while read -r cors; do
                echo -e "  • $cors"
            done
        fi
        echo ""
    fi
    
    if [ "$STATS_SECRETS" -gt 0 ]; then
        echo -e "${BOLD}${RED}🔑 SECRETS DETECTED IN JAVASCRIPT:${NC}"
        echo -e "  Review jsmap_results.txt for potential API keys, tokens, and secrets"
        echo ""
    fi
    
    if [ -f "${OUTPUT_DIR}/gau_sensitive_files.txt" ] && [ -s "${OUTPUT_DIR}/gau_sensitive_files.txt" ]; then
        local sensitive_count=$(wc -l < "${OUTPUT_DIR}/gau_sensitive_files.txt")
        echo -e "${BOLD}${YELLOW}📄 SENSITIVE FILES FOUND:${NC} $sensitive_count files"
        echo -e "  Review gau_sensitive_files.txt for backup files, configs, and sensitive data"
        echo ""
    fi
    
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}REPORT FILES GENERATED:${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  📊 ${GREEN}HTML Report:${NC}     ${OUTPUT_DIR}/report.html"
    echo -e "  📝 ${GREEN}Text Report:${NC}     ${OUTPUT_DIR}/report.txt"
    echo -e "  📋 ${GREEN}Markdown Report:${NC}  ${OUTPUT_DIR}/report.md"
    echo -e "  📈 ${GREEN}CSV Report:${NC}       ${OUTPUT_DIR}/report.csv"
    echo -e "  📜 ${GREEN}Execution Log:${NC}    ${OUTPUT_DIR}/execution.log"
    echo ""
    echo -e "  ${BOLD}All intermediate results are stored in:${NC}"
    echo -e "  ${OUTPUT_DIR}/"
    echo ""
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

###############################################################################
# Tool Update Function
###############################################################################

update_tools() {
    log PHASE "Updating Reconnaissance Tools"
    
    log INFO "This function would update all tools. Manual update recommended."
    log INFO "Please refer to each tool's GitHub repository for update instructions."
    
    # List of tool repositories
    local tools=(
        "projectdiscovery/subfinder"
        "projectdiscovery/naabu"
        "projectdiscovery/httpx"
        "projectdiscovery/asnmap"
        "projectdiscovery/cvemap"
        "s0md3v/Smap"
        "s0md3v/Corsy"
        "blacklanternsecurity/bbot"
        "edoardottt/cariddi"
        "trap-bytes/403jump"
        "g0ldencybersec/Caduceus"
        "g0ldencybersec/gungnir"
        "sharsil/favicorn"
        "EnableSecurity/wafw00f"
        "lord-alfred/ipranges"
        "ynsmroztas/JSMap-Inspector"
        "Mr-Robert0/Logsensor"
        "0xakashk/CSP-Stalker"
    )
    
    log INFO "Tool repositories:"
    for tool in "${tools[@]}"; do
        echo "  • https://github.com/$tool"
    done
    
    log SUCCESS "Update information displayed"
}

###############################################################################
# Main Function
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
                                                                           v2.0  by: .W4R
EOF
    echo -e "${NC}\n"
}

main() {
    # Display logo
    logo
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -p|--passive)
                PASSIVE_MODE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -up|--update)
                UPDATE_TOOLS=true
                shift
                ;;
            -h|--help)
                cat << EOF
Usage: $SCRIPT_NAME -t TARGET [OPTIONS]

Options:
    -t, --target TARGET    Target domain or URL (required)
    -o, --output DIR      Output directory for results (required)
    -p, --passive         Enable passive mode (no active scanning)
    -v, --verbose         Enable verbose mode (show detailed output)
    -ua, --random-ua      Enable random user agent rotation
    -d, --delay SECONDS   Set custom delay between requests (overrides random delay)
    -up, --update         Show tool update information
    -h, --help            Show this help message

Examples:
    $SCRIPT_NAME -t example.com -o ./results
    $SCRIPT_NAME -t https://example.com -o ./recon_results --passive
    $SCRIPT_NAME -t example.com -o ./results --verbose --random-ua
    $SCRIPT_NAME -t example.com -o ./results --delay 0.5

EOF
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    if [ "$UPDATE_TOOLS" = true ]; then
        update_tools
        exit 0
    fi
    
    if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
        log ERROR "Target and output directory are required"
        echo "Use -h or --help for usage information"
        exit 1
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Load configuration
    load_config
    
    # Start reconnaissance pipeline
    log INFO "Starting reconnaissance pipeline for: $TARGET"
    log INFO "Output directory: $OUTPUT_DIR"
    [ "$PASSIVE_MODE" = true ] && log INFO "Passive mode: ENABLED"
    [ "$VERBOSE" = true ] && log INFO "Verbose mode: ENABLED"
    
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Script version: $VERSION"
        log DEBUG "Tools directory: $TOOLS_DIR"
        log DEBUG "Config file: $CONFIG_FILE"
        log DEBUG "Delay range: ${DELAY_MIN}-${DELAY_MAX} seconds"
        log DEBUG "User agent rotation: ${#USER_AGENTS[@]} agents available"
    fi
    
    # Execute phases
    phase0_asn_discovery
    phase1_subdomain_discovery
    phase2_port_scanning
    phase3_http_probing
    phase4_deep_crawling
    phase5_vulnerability_scanning
    
    # Generate reports
    generate_html_report
    generate_text_report
    generate_markdown_report
    generate_csv_report
    
    # Display summary
    generate_summary
    
    log SUCCESS "Reconnaissance pipeline completed successfully!"
}

# Run main function
main "$@"

