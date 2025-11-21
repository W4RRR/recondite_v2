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
    
    # Check if tool is already installed in PATH
    if check_command "$tool_name"; then
        log SUCCESS "$tool_name is already installed at: $(command -v $tool_name)"
        if [ "$UPDATE_MODE" = false ]; then
            return 0
        else
            log INFO "Update mode: checking for updates..."
        fi
    fi
    
    # Update mode: pull latest changes
    if [ "$UPDATE_MODE" = true ] && [ -d "$TOOLS_DIR/$tool_name" ]; then
        log INFO "Updating $tool_name repository..."
        cd "$TOOLS_DIR/$tool_name" && git pull && cd "$SCRIPT_DIR" || true
    fi
    
    # Clone repository if not exists
    if [ ! -d "$TOOLS_DIR/$tool_name" ]; then
        log INFO "Cloning $repo..."
        if ! git clone "https://github.com/$repo.git" "$TOOLS_DIR/$tool_name" 2>&1 | tee -a install.log; then
            log ERROR "Failed to clone $repo (network error or repo not found)"
            log WARNING "Skipping $tool_name installation. You can install it manually later."
            return 1
        fi
    else
        log INFO "$tool_name repository already exists at $TOOLS_DIR/$tool_name"
    fi
    
    # If tool is already in PATH and we're not in update mode, skip build
    if check_command "$tool_name" && [ "$UPDATE_MODE" = false ]; then
        log SUCCESS "$tool_name is ready"
        return 0
    fi
    
    # Try to install/update via go install
    log INFO "Installing/updating $tool_name via go install..."
    if go install "github.com/$repo/cmd/$tool_name@latest" 2>&1 | tee -a install.log; then
        log SUCCESS "$tool_name installed successfully"
        return 0
    else
        log WARNING "Failed to install $tool_name via go install. Trying local build..."
        
        # Try building from source
        if [ -f "$TOOLS_DIR/$tool_name/go.mod" ] || [ -f "$TOOLS_DIR/$tool_name/main.go" ]; then
            cd "$TOOLS_DIR/$tool_name"
            if go build -o "$install_path" . 2>&1 | tee -a "$SCRIPT_DIR/install.log"; then
                log SUCCESS "$tool_name built successfully at $install_path"
                cd "$SCRIPT_DIR"
                return 0
            fi
            cd "$SCRIPT_DIR"
        fi
        
        # Check one more time if it's installed (sometimes go install succeeds despite error output)
        if check_command "$tool_name"; then
            log SUCCESS "$tool_name is available"
            return 0
        fi
        
        log ERROR "Failed to install $tool_name. Please install manually or try again later."
        return 1
    fi
}

install_python_tool() {
    local repo=$1
    local tool_name=$2
    local tool_dir=$3
    
    # Check if tool is already installed
    local tool_lower=$(echo "$tool_name" | tr '[:upper:]' '[:lower:]')
    if check_command "$tool_lower" || check_command "$tool_name"; then
        log SUCCESS "$tool_name is already installed"
        if [ "$UPDATE_MODE" = false ]; then
            return 0
        else
            log INFO "Update mode: checking for updates..."
        fi
    fi
    
    # Update mode: pull latest changes
    if [ "$UPDATE_MODE" = true ] && [ -d "$TOOLS_DIR/$tool_dir" ]; then
        log INFO "Updating $tool_name repository..."
        cd "$TOOLS_DIR/$tool_dir" && git pull && cd "$SCRIPT_DIR" || true
    fi
    
    # Clone repository if not exists
    if [ ! -d "$TOOLS_DIR/$tool_dir" ]; then
        log INFO "Cloning $repo..."
        if ! git clone "https://github.com/$repo.git" "$TOOLS_DIR/$tool_dir" 2>&1 | tee -a install.log; then
            log ERROR "Failed to clone $repo (network error or repo not found)"
            log WARNING "Skipping $tool_name installation. You can install it manually later."
            return 1
        fi
    else
        log INFO "$tool_name repository already exists at $TOOLS_DIR/$tool_dir"
    fi
    
    # Check for requirements.txt
    if [ -f "$TOOLS_DIR/$tool_dir/requirements.txt" ]; then
        log INFO "Installing Python dependencies for $tool_name..."
        
        # Use --break-system-packages for Kali Linux / Debian managed environments
        if pip3 install --break-system-packages -r "$TOOLS_DIR/$tool_dir/requirements.txt" 2>&1 | tee -a install.log; then
            log SUCCESS "Dependencies installed for $tool_name"
        else
            log WARNING "Python package installation failed for $tool_name"
            log INFO "To install manually, run:"
            log INFO "  cd $TOOLS_DIR/$tool_dir"
            log INFO "  pip3 install --break-system-packages -r requirements.txt"
        fi
    fi
    
    # Check for setup.py
    if [ -f "$TOOLS_DIR/$tool_dir/setup.py" ]; then
        log INFO "Running setup.py for $tool_name..."
        cd "$TOOLS_DIR/$tool_dir"
        
        # Use pip3 install with --break-system-packages
        if pip3 install --break-system-packages -e . 2>&1 | tee -a "$SCRIPT_DIR/install.log"; then
            log SUCCESS "setup.py completed for $tool_name"
        else
            log WARNING "setup.py install may have failed for $tool_name"
            log INFO "The tool may still be usable from $TOOLS_DIR/$tool_dir"
        fi
        cd "$SCRIPT_DIR"
    fi
    
    # Final check
    if check_command "$tool_lower" || check_command "$tool_name" || [ -f "$TOOLS_DIR/$tool_dir/${tool_name}.py" ] || [ -f "$TOOLS_DIR/$tool_dir/${tool_lower}.py" ]; then
        log SUCCESS "$tool_name is ready"
        return 0
    else
        log WARNING "$tool_name may not be properly installed. Check install.log for details."
        return 1
    fi
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
    
    # ipranges - special handling due to network issues
    log INFO "Installing ipranges..."
    if check_command "ipranges"; then
        log SUCCESS "ipranges is already installed at: $(command -v ipranges)"
    else
        if [ ! -d "$TOOLS_DIR/ipranges" ]; then
            log INFO "Cloning lord-alfred/ipranges..."
            if git clone "https://github.com/lord-alfred/ipranges.git" "$TOOLS_DIR/ipranges" 2>&1 | tee -a install.log; then
                log SUCCESS "ipranges cloned successfully"
            else
                log ERROR "Failed to clone ipranges"
            fi
        fi
        
        if [ -d "$TOOLS_DIR/ipranges" ]; then
            log INFO "Building ipranges from source..."
            cd "$TOOLS_DIR/ipranges"
            if go build -o ipranges . 2>&1 | tee -a "$SCRIPT_DIR/install.log"; then
                # Copy to go bin or local bin
                local go_bin=$(go env GOPATH)/bin
                if [ -d "$go_bin" ]; then
                    cp ipranges "$go_bin/" 2>/dev/null && log SUCCESS "ipranges installed to $go_bin/ipranges"
                else
                    log SUCCESS "ipranges built at $TOOLS_DIR/ipranges/ipranges"
                fi
            else
                log WARNING "Failed to build ipranges from source"
            fi
            cd "$SCRIPT_DIR"
        fi
    fi
    
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
    if check_command "smap" || [ -f "$TOOLS_DIR/Smap/smap.py" ]; then
        log SUCCESS "Smap is already available"
        [ "$UPDATE_MODE" = false ] && { log INFO "Skipping Smap (already installed)"; } || { log INFO "Update mode: checking Smap..."; }
    fi
    
    if [ "$UPDATE_MODE" = true ] && [ -d "$TOOLS_DIR/Smap" ]; then
        log INFO "Updating Smap..."
        cd "$TOOLS_DIR/Smap" && git pull && cd "$SCRIPT_DIR" || true
    fi
    
    if [ ! -d "$TOOLS_DIR/Smap" ]; then
        if git clone "https://github.com/s0md3v/Smap.git" "$TOOLS_DIR/Smap" 2>&1 | tee -a install.log; then
            log SUCCESS "Smap cloned successfully"
        else
            log ERROR "Failed to clone Smap"
            return 1
        fi
    fi
    
    if [ -f "$TOOLS_DIR/Smap/requirements.txt" ]; then
        log INFO "Installing Smap dependencies..."
        pip3 install --break-system-packages -r "$TOOLS_DIR/Smap/requirements.txt" 2>&1 | tee -a install.log || true
    fi
    
    if [ -f "$TOOLS_DIR/Smap/smap.py" ]; then
        chmod +x "$TOOLS_DIR/Smap/smap.py" 2>/dev/null || true
        log SUCCESS "Smap is ready at $TOOLS_DIR/Smap/smap.py"
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
    if ! install_go_tool "lc/gau" "gau" "$TOOLS_DIR/gau/gau"; then
        # Try alternative installation method for gau
        if ! check_command "gau"; then
            log WARNING "Trying alternative installation for gau..."
            go install "github.com/lc/gau/v2/cmd/gau@latest" 2>&1 | tee -a install.log || true
        fi
    fi
    
    log INFO ""
    log INFO "=== Installation Summary ==="
    echo ""
    
    # Verify installations
    local tools=(
        "asnmap:Go" "subfinder:Go" "naabu:Go" "httpx:Go" "cvemap:Go"
        "cariddi:Go" "favicorn:Go" "ipranges:Go"
        "bbot:Python" "wafw00f:Python" "gau:Go"
        "403jump:Go" "gungnir:Go"
    )
    
    local installed=0
    local missing=0
    local in_tools=0
    
    for tool_info in "${tools[@]}"; do
        local tool_name=$(echo "$tool_info" | cut -d':' -f1)
        local tool_type=$(echo "$tool_info" | cut -d':' -f2)
        
        if check_command "$tool_name"; then
            log SUCCESS "$tool_name: ✓ installed at $(command -v $tool_name)"
            ((installed++))
        else
            # Check if available in tools directory
            local found_in_tools=false
            
            if [ "$tool_type" = "Python" ]; then
                # Check for Python scripts in tools/
                if [ -f "$TOOLS_DIR/${tool_name}"*"/${tool_name}.py" ] || [ -f "$TOOLS_DIR/${tool_name}"*"/${tool_name}"*".py" ]; then
                    log INFO "$tool_name: ✓ available in $TOOLS_DIR (Python script)"
                    ((in_tools++))
                    found_in_tools=true
                fi
            elif [ "$tool_type" = "Go" ]; then
                # Check for Go binaries in tools/
                if [ -f "$TOOLS_DIR/${tool_name}/${tool_name}" ]; then
                    log INFO "$tool_name: ✓ available in $TOOLS_DIR (binary)"
                    ((in_tools++))
                    found_in_tools=true
                fi
            fi
            
            if [ "$found_in_tools" = false ]; then
                log WARNING "$tool_name: ✗ not found"
                ((missing++))
            fi
        fi
    done
    
    echo ""
    log INFO "Summary: $installed in PATH | $in_tools in tools/ | $missing missing"
    echo ""
    
    if [ $missing -gt 0 ] || [ $in_tools -gt 0 ]; then
        echo ""
        log INFO "Installation notes:"
        if [ $missing -gt 0 ]; then
            log WARNING "Some tools could not be installed (network errors or other issues)"
            log INFO "You can try running this script again or install them manually"
        fi
        if [ $in_tools -gt 0 ]; then
            log INFO "Some tools are available in $TOOLS_DIR/ directory"
            log INFO "recondite_v2.sh will use them automatically"
        fi
        echo ""
        log INFO "To add tools to your PATH:"
        log INFO "  1. Go tools: export PATH=\$PATH:\$(go env GOPATH)/bin"
        log INFO "  2. Python tools: export PATH=\$PATH:~/.local/bin"
        log INFO "  3. Add to ~/.bashrc or ~/.zshrc to make permanent"
    fi
    
    echo ""
    log SUCCESS "Installation process completed!"
    log INFO "Installation log saved to: $(pwd)/install.log"
    log INFO ""
    log INFO "Next steps:"
    log INFO "  1. Configure API keys: cp config/apikeys.example.env config/apikeys.env"
    log INFO "  2. Edit config/apikeys.env with your API keys"
    log INFO "  3. Run: ./recondite_v2.sh -d scope.txt --full -o reports"
}

main "$@"
