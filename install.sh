#!/usr/bin/env bash

###############################################################################
# Recondite v2 - Installation Script
# Installs all required tools and dependencies
###############################################################################

set -u
set -o pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

# Directories
TOOLS_DIR="tools"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPDATE_MODE=false

# Parse arguments
if [[ "$*" == *"--update"* ]]; then
    UPDATE_MODE=true
fi

log() {
    local level=$1
    shift
    local message="$@"
    
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
    esac
}

check_command() {
    command -v "$1" &> /dev/null
}

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            echo "debian"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

install_go_tool() {
    local repo=$1
    local tool_name=$2
    local install_path=$3
    
    log INFO "Installing $tool_name from $repo"
    
    if [ "$UPDATE_MODE" = true ] && [ -d "$TOOLS_DIR/$tool_name" ]; then
        log INFO "Updating $tool_name..."
        cd "$TOOLS_DIR/$tool_name" && git pull && cd "$SCRIPT_DIR" || true
    fi
    
    if [ ! -d "$TOOLS_DIR/$tool_name" ]; then
        log INFO "Cloning $repo..."
        git clone "https://github.com/$repo.git" "$TOOLS_DIR/$tool_name" || {
            log ERROR "Failed to clone $repo"
            return 1
        }
    fi
    
    if check_command "$tool_name"; then
        log SUCCESS "$tool_name is already installed at: $(command -v $tool_name)"
        return 0
    fi
    
    log INFO "Building $tool_name..."
    if go install "github.com/$repo/cmd/$tool_name@latest" 2>&1 | tee -a install.log; then
        log SUCCESS "$tool_name installed successfully"
        return 0
    else
        log WARNING "Failed to install $tool_name via go install. Trying local build..."
        
        # Try building from source
        if [ -f "$TOOLS_DIR/$tool_name/go.mod" ] || [ -f "$TOOLS_DIR/$tool_name/main.go" ]; then
            cd "$TOOLS_DIR/$tool_name"
            if go build -o "$install_path" . 2>&1 | tee -a "$SCRIPT_DIR/install.log"; then
                log SUCCESS "$tool_name built successfully"
                cd "$SCRIPT_DIR"
                return 0
            fi
            cd "$SCRIPT_DIR"
        fi
        
        log ERROR "Failed to install $tool_name. Please install manually."
        return 1
    fi
}

install_python_tool() {
    local repo=$1
    local tool_name=$2
    local tool_dir=$3
    
    log INFO "Installing $tool_name from $repo"
    
    if [ "$UPDATE_MODE" = true ] && [ -d "$TOOLS_DIR/$tool_dir" ]; then
        log INFO "Updating $tool_name..."
        cd "$TOOLS_DIR/$tool_dir" && git pull && cd "$SCRIPT_DIR" || true
    fi
    
    if [ ! -d "$TOOLS_DIR/$tool_dir" ]; then
        log INFO "Cloning $repo..."
        git clone "https://github.com/$repo.git" "$TOOLS_DIR/$tool_dir" || {
            log ERROR "Failed to clone $repo"
            return 1
        }
    fi
    
    # Check for requirements.txt
    if [ -f "$TOOLS_DIR/$tool_dir/requirements.txt" ]; then
        log INFO "Installing Python dependencies for $tool_name..."
        pip3 install -r "$TOOLS_DIR/$tool_dir/requirements.txt" 2>&1 | tee -a install.log || {
            log WARNING "Failed to install some dependencies for $tool_name"
        }
    fi
    
    # Check for setup.py
    if [ -f "$TOOLS_DIR/$tool_dir/setup.py" ]; then
        log INFO "Running setup.py for $tool_name..."
        cd "$TOOLS_DIR/$tool_dir"
        python3 setup.py install --user 2>&1 | tee -a "$SCRIPT_DIR/install.log" || {
            log WARNING "setup.py install failed for $tool_name"
        }
        cd "$SCRIPT_DIR"
    fi
    
    log SUCCESS "$tool_name setup completed"
}

main() {
    log INFO "Recondite v2 - Installation Script"
    log INFO "===================================="
    echo ""
    
    # Detect OS
    local os=$(detect_os)
    log INFO "Detected OS: $os"
    
    # Check prerequisites
    if ! check_command git; then
        log ERROR "git is not installed. Please install git first."
        if [ "$os" = "debian" ]; then
            log INFO "Run: sudo apt update && sudo apt install -y git"
        fi
        exit 1
    fi
    
    if ! check_command go; then
        log ERROR "Go is not installed. Please install Go first."
        if [ "$os" = "debian" ]; then
            log INFO "Run: sudo apt update && sudo apt install -y golang-go"
        elif [ "$os" = "macos" ]; then
            log INFO "Run: brew install go"
        fi
        exit 1
    fi
    
    if ! check_command python3; then
        log ERROR "Python 3 is not installed. Please install Python 3 first."
        if [ "$os" = "debian" ]; then
            log INFO "Run: sudo apt update && sudo apt install -y python3 python3-pip"
        fi
        exit 1
    fi
    
    if ! check_command jq; then
        log WARNING "jq is not installed. Some features may not work."
        if [ "$os" = "debian" ]; then
            log INFO "Run: sudo apt install -y jq"
        elif [ "$os" = "macos" ]; then
            log INFO "Run: brew install jq"
        fi
    fi
    
    # Create tools directory
    mkdir -p "$TOOLS_DIR"
    cd "$SCRIPT_DIR"
    
    # Initialize install log
    echo "Installation log - $(date)" > install.log
    
    log INFO "Installing tools..."
    echo ""
    
    # Go tools (ProjectDiscovery)
    log INFO "=== Installing Go Tools ==="
    install_go_tool "projectdiscovery/asnmap" "asnmap" "$TOOLS_DIR/asnmap/asnmap"
    install_go_tool "projectdiscovery/subfinder" "subfinder" "$TOOLS_DIR/subfinder/subfinder"
    install_go_tool "projectdiscovery/naabu" "naabu" "$TOOLS_DIR/naabu/naabu"
    install_go_tool "projectdiscovery/httpx" "httpx" "$TOOLS_DIR/httpx/httpx"
    install_go_tool "projectdiscovery/cvemap" "cvemap" "$TOOLS_DIR/cvemap/cvemap"
    
    # Go tools (Other)
    install_go_tool "edoardottt/cariddi" "cariddi" "$TOOLS_DIR/cariddi/cariddi"
    install_go_tool "sharsil/favicorn" "favicorn" "$TOOLS_DIR/favicorn/favicorn"
    install_go_tool "lord-alfred/ipranges" "ipranges" "$TOOLS_DIR/ipranges/ipranges"
    
    # Python tools
    log INFO ""
    log INFO "=== Installing Python Tools ==="
    install_python_tool "blacklanternsecurity/bbot" "bbot" "bbot-stable"
    install_python_tool "EnableSecurity/wafw00f" "wafw00f" "wafw00f"
    install_python_tool "s0md3v/Corsy" "Corsy" "Corsy-master"
    install_python_tool "0xakashk/CSP-Stalker" "CSP-Stalker" "CSP-Stalker-main"
    install_python_tool "ynsmroztas/JSMap-Inspector" "JSMap-Inspector" "JSMap-Inspector-main"
    install_python_tool "Mr-Robert0/Logsensor" "Logsensor" "Logsensor-main"
    
    # Special cases
    log INFO ""
    log INFO "=== Installing Special Tools ==="
    
    # Smap
    log INFO "Installing Smap..."
    if [ "$UPDATE_MODE" = true ] && [ -d "$TOOLS_DIR/Smap" ]; then
        cd "$TOOLS_DIR/Smap" && git pull && cd "$SCRIPT_DIR" || true
    fi
    if [ ! -d "$TOOLS_DIR/Smap" ]; then
        git clone "https://github.com/s0md3v/Smap.git" "$TOOLS_DIR/Smap" || log ERROR "Failed to clone Smap"
    fi
    if [ -f "$TOOLS_DIR/Smap/requirements.txt" ]; then
        pip3 install -r "$TOOLS_DIR/Smap/requirements.txt" 2>&1 | tee -a install.log || true
    fi
    if [ -f "$TOOLS_DIR/Smap/smap.py" ]; then
        chmod +x "$TOOLS_DIR/Smap/smap.py" 2>/dev/null || true
    fi
    
    # 403jump
    log INFO "Installing 403jump..."
    install_go_tool "trap-bytes/403jump" "403jump" "$TOOLS_DIR/403jump/403jump"
    
    # Caduceus
    log INFO "Installing Caduceus..."
    install_python_tool "g0ldencybersec/Caduceus" "Caduceus" "Caduceus"
    
    # gungnir
    log INFO "Installing gungnir..."
    install_go_tool "g0ldencybersec/gungnir" "gungnir" "$TOOLS_DIR/gungnir/gungnir"
    
    # gau
    log INFO "Installing gau..."
    install_go_tool "lc/gau" "gau" "$TOOLS_DIR/gau/gau"
    
    log INFO ""
    log INFO "=== Installation Summary ==="
    echo ""
    
    # Verify installations
    local tools=(
        "asnmap" "subfinder" "naabu" "httpx" "cvemap"
        "cariddi" "favicorn" "ipranges"
        "bbot" "wafw00f" "gau"
    )
    
    local installed=0
    local missing=0
    
    for tool in "${tools[@]}"; do
        if check_command "$tool"; then
            log SUCCESS "$tool: ✓ installed"
            ((installed++))
        else
            log WARNING "$tool: ✗ not found in PATH"
            ((missing++))
        fi
    done
    
    echo ""
    log INFO "Installed: $installed | Missing: $missing"
    echo ""
    
    if [ $missing -gt 0 ]; then
        log WARNING "Some tools are not in PATH. You may need to:"
        log INFO "1. Add Go bin directory to PATH: export PATH=\$PATH:\$(go env GOPATH)/bin"
        log INFO "2. Add Python user bin to PATH: export PATH=\$PATH:~/.local/bin"
        log INFO "3. Or use tools from $TOOLS_DIR/ directly"
    fi
    
    log SUCCESS "Installation completed!"
    log INFO "Installation log saved to: install.log"
}

main "$@"
