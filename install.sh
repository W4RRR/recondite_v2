#!/bin/bash

###############################################################################
# Recondite v2 - Installation Script
# Automatically installs all required tools following each tool's specific
# installation instructions from their README files
###############################################################################

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/tools"
INSTALL_LOG="${SCRIPT_DIR}/install.log"
LOCAL_BIN="${SCRIPT_DIR}/bin"

# Initialize log file
> "$INSTALL_LOG"

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${BLUE}[*]${NC} $message" | tee -a "$INSTALL_LOG"
            ;;
        SUCCESS)
            echo -e "${GREEN}[+]${NC} $message" | tee -a "$INSTALL_LOG"
            ;;
        WARNING)
            echo -e "${YELLOW}[!]${NC} $message" | tee -a "$INSTALL_LOG"
            ;;
        ERROR)
            echo -e "${RED}[-]${NC} $message" | tee -a "$INSTALL_LOG"
            ;;
        PHASE)
            echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}" | tee -a "$INSTALL_LOG"
            echo -e "${BOLD}${CYAN}  $message${NC}" | tee -a "$INSTALL_LOG"
            echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}\n" | tee -a "$INSTALL_LOG"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$INSTALL_LOG"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

check_go_version() {
    if ! check_command "go"; then
        return 1
    fi
    
    local go_version=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
    local major=$(echo "$go_version" | cut -d. -f1)
    local minor=$(echo "$go_version" | cut -d. -f2)
    
    # Check if Go version is >= 1.21 (minimum for most tools)
    if [ "$major" -gt 1 ] || ([ "$major" -eq 1 ] && [ "$minor" -ge 21 ]); then
        return 0
    fi
    return 1
}

install_go_tool_from_source() {
    local tool_name=$1
    local tool_path=$2
    local build_path=$3
    local output_name=$4
    
    log INFO "Building $tool_name from source..."
    
    if [ ! -d "$tool_path" ]; then
        log WARNING "Tool directory not found: $tool_path"
        log WARNING "Cannot build $tool_name from source - directory missing"
        return 1
    fi
    
    local original_dir=$(pwd)
    cd "$tool_path" || {
        log ERROR "Cannot change to directory: $tool_path"
        return 1
    }
    
    # Check if go.mod exists
    if [ ! -f "go.mod" ]; then
        log WARNING "go.mod not found in $tool_path"
        log WARNING "Cannot build $tool_name - missing go.mod file"
        cd "$original_dir"
        return 1
    fi
    
    # Build the tool
    log INFO "Running: go build -o ${LOCAL_BIN}/${output_name} $build_path"
    if go build -o "${LOCAL_BIN}/${output_name}" "$build_path" >>"$INSTALL_LOG" 2>&1; then
        if [ -f "${LOCAL_BIN}/${output_name}" ]; then
            chmod +x "${LOCAL_BIN}/${output_name}"
            log SUCCESS "$tool_name built and installed successfully to ${LOCAL_BIN}/${output_name}"
            cd "$original_dir"
            return 0
        else
            log ERROR "Build succeeded but binary not found at ${LOCAL_BIN}/${output_name}"
            cd "$original_dir"
            return 1
        fi
    else
        log ERROR "Failed to build $tool_name from source"
        log WARNING "Check install.log for build errors"
        cd "$original_dir"
        return 1
    fi
}

install_go_tool_remote() {
    local tool_name=$1
    local install_cmd=$2
    
    log INFO "Installing $tool_name via go install..."
    
    if eval "$install_cmd" >>"$INSTALL_LOG" 2>&1; then
        # Verify installation
        if command -v "$tool_name" &> /dev/null; then
            log SUCCESS "$tool_name installed successfully"
            return 0
        else
            log WARNING "$tool_name installation command succeeded but tool not found in PATH"
            log WARNING "Trying to install from source..."
            return 1
        fi
    else
        log WARNING "Failed to install $tool_name via go install (check install.log for details)"
        log WARNING "Trying to install from source..."
        return 1
    fi
}

install_python_tool() {
    local tool_name=$1
    local tool_path=$2
    local install_method=$3
    
    log INFO "Installing $tool_name (Python)..."
    
    if [ ! -d "$tool_path" ]; then
        log WARNING "Tool directory not found: $tool_path"
        return 1
    fi
    
    cd "$tool_path"
    
    case "$install_method" in
        "requirements")
            if [ -f "requirements.txt" ]; then
                log INFO "Installing Python dependencies for $tool_name..."
                if pip3 install -r requirements.txt >>"$INSTALL_LOG" 2>&1; then
                    log SUCCESS "Dependencies installed for $tool_name"
                    return 0
                else
                    log WARNING "Some dependencies may have failed for $tool_name"
                    return 1
                fi
            fi
            ;;
        "setup_py")
            if [ -f "setup.py" ]; then
                log INFO "Installing $tool_name via setup.py..."
                if pip3 install . >>"$INSTALL_LOG" 2>&1; then
                    log SUCCESS "$tool_name installed successfully"
                    return 0
                else
                    log WARNING "setup.py installation may have failed for $tool_name"
                    return 1
                fi
            fi
            ;;
        "pipx")
            if check_command "pipx"; then
                log INFO "Installing $tool_name via pipx..."
                if pipx install "$tool_name" >>"$INSTALL_LOG" 2>&1; then
                    log SUCCESS "$tool_name installed successfully"
                    return 0
                else
                    log WARNING "pipx installation failed, trying pip..."
                    pip3 install "$tool_name" >>"$INSTALL_LOG" 2>&1 || true
                fi
            else
                log INFO "pipx not found, using pip..."
                pip3 install "$tool_name" >>"$INSTALL_LOG" 2>&1 || true
            fi
            ;;
        "custom")
            # For tools with custom installation scripts
            if [ -f "install.sh" ]; then
                log INFO "Running custom install script for $tool_name..."
                chmod +x install.sh
                if ./install.sh >>"$INSTALL_LOG" 2>&1; then
                    log SUCCESS "$tool_name installed successfully"
                    return 0
                else
                    log WARNING "Custom install script may have failed for $tool_name"
                    return 1
                fi
            fi
            ;;
    esac
    
    return 0
}

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
    
    # Check prerequisites
    log PHASE "Checking Prerequisites"
    
    if ! check_go_version; then
        log ERROR "Go 1.21+ is required but not found or version is too old."
        log ERROR "Please install Go from https://golang.org/dl/"
        exit 1
    fi
    log SUCCESS "Go found: $(go version)"
    
    if ! check_command "python3"; then
        log ERROR "Python3 is not installed. Please install Python 3.8+ first."
        exit 1
    fi
    log SUCCESS "Python3 found: $(python3 --version)"
    
    if ! check_command "pip3"; then
        log ERROR "pip3 is not installed. Please install pip3 first."
        exit 1
    fi
    log SUCCESS "pip3 found: $(pip3 --version)"
    
    # Check for gcc (required for Caduceus)
    if ! check_command "gcc"; then
        log WARNING "gcc not found. Caduceus requires gcc for CGO. Install with: sudo apt install gcc"
    else
        log SUCCESS "gcc found: $(gcc --version | head -1)"
    fi
    
    # Create local bin directory
    mkdir -p "$LOCAL_BIN"
    export PATH="${LOCAL_BIN}:${PATH}"
    
    log INFO "Tools will be installed to: $LOCAL_BIN"
    echo ""
    
    # Install Go tools
    log PHASE "Installing Go Tools"
    
    # 1. subfinder - From README: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    log INFO "Installing subfinder..."
    if ! install_go_tool_remote "subfinder" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"; then
        if [ -d "${TOOLS_DIR}/subfinder-dev/subfinder-dev" ]; then
            if ! install_go_tool_from_source "subfinder" \
                "${TOOLS_DIR}/subfinder-dev/subfinder-dev" \
                "./cmd/subfinder" \
                "subfinder"; then
                log WARNING "subfinder installation failed from both remote and source"
                log WARNING "You may need to install manually: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            fi
        else
            log WARNING "subfinder source directory not found - cannot build from source"
        fi
    fi
    
    # 2. httpx - From README: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest (requires go >=1.24.0)
    log INFO "Installing httpx..."
    if ! install_go_tool_remote "httpx" "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"; then
        if [ -d "${TOOLS_DIR}/httpx-dev/httpx-dev" ]; then
            if ! install_go_tool_from_source "httpx" \
                "${TOOLS_DIR}/httpx-dev/httpx-dev" \
                "./cmd/httpx" \
                "httpx"; then
                log WARNING "httpx installation failed from both remote and source"
            fi
        else
            log WARNING "httpx source directory not found - cannot build from source"
        fi
    fi
    
    # 3. naabu - From README: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    log INFO "Installing naabu..."
    if ! install_go_tool_remote "naabu" "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"; then
        if [ -d "${TOOLS_DIR}/naabu-dev/naabu-dev" ]; then
            if ! install_go_tool_from_source "naabu" \
                "${TOOLS_DIR}/naabu-dev/naabu-dev" \
                "./cmd/naabu" \
                "naabu"; then
                log WARNING "naabu installation failed from both remote and source"
            fi
        else
            log WARNING "naabu source directory not found - cannot build from source"
        fi
    fi
    
    # 4. asnmap - From README: go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest (requires Go 1.21)
    log INFO "Installing asnmap..."
    if ! install_go_tool_remote "asnmap" "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"; then
        if [ -d "${TOOLS_DIR}/asnmap-main/asnmap-main" ]; then
            if ! install_go_tool_from_source "asnmap" \
                "${TOOLS_DIR}/asnmap-main/asnmap-main" \
                "./cmd/asnmap" \
                "asnmap"; then
                log WARNING "asnmap installation failed from both remote and source"
            fi
        else
            log WARNING "asnmap source directory not found - cannot build from source"
        fi
    fi
    
    # 5. cvemap - From README: go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest
    log INFO "Installing cvemap..."
    if ! install_go_tool_remote "cvemap" "go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest"; then
        if [ -d "${TOOLS_DIR}/cvemap-main/cvemap-main" ]; then
            if ! install_go_tool_from_source "cvemap" \
                "${TOOLS_DIR}/cvemap-main/cvemap-main" \
                "./cmd/cvemap" \
                "cvemap"; then
                log WARNING "cvemap installation failed from both remote and source"
            fi
        else
            log WARNING "cvemap source directory not found - cannot build from source"
        fi
    fi
    
    # 6. Smap - From README: go install -v github.com/s0md3v/smap/cmd/smap@latest
    log INFO "Installing Smap..."
    if ! install_go_tool_remote "smap" "go install -v github.com/s0md3v/smap/cmd/smap@latest"; then
        if [ -d "${TOOLS_DIR}/Smap-main/Smap-main" ]; then
            if ! install_go_tool_from_source "smap" \
                "${TOOLS_DIR}/Smap-main/Smap-main" \
                "./cmd/smap" \
                "smap"; then
                log WARNING "smap installation failed from both remote and source"
            fi
        else
            log WARNING "smap source directory not found - cannot build from source"
        fi
    fi
    
    # 7. cariddi - From README: go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest (requires Go >=1.24.0)
    log INFO "Installing cariddi..."
    if ! install_go_tool_remote "cariddi" "go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest"; then
        if [ -d "${TOOLS_DIR}/cariddi-main/cariddi-main" ]; then
            if ! install_go_tool_from_source "cariddi" \
                "${TOOLS_DIR}/cariddi-main/cariddi-main" \
                "./cmd/cariddi" \
                "cariddi"; then
                log WARNING "cariddi installation failed from both remote and source"
            fi
        else
            log WARNING "cariddi source directory not found - cannot build from source"
        fi
    fi
    
    # 8. Caduceus - From README: go install github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest (requires gcc, CGO enabled)
    log INFO "Installing Caduceus (requires gcc for CGO)..."
    if check_command "gcc"; then
        if ! install_go_tool_remote "caduceus" "go install github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest"; then
            if [ -d "${TOOLS_DIR}/Caduceus-main/Caduceus-main" ]; then
                if ! install_go_tool_from_source "caduceus" \
                    "${TOOLS_DIR}/Caduceus-main/Caduceus-main" \
                    "./cmd/caduceus" \
                    "caduceus"; then
                    log WARNING "Caduceus installation failed from both remote and source"
                    log WARNING "Caduceus requires CGO and gcc - ensure gcc is properly installed"
                fi
            else
                log WARNING "Caduceus source directory not found - cannot build from source"
            fi
        fi
    else
        log WARNING "Skipping Caduceus - gcc not found. Install with: sudo apt install gcc"
        log WARNING "Caduceus requires gcc for CGO compilation"
    fi
    
    # 9. gungnir - From README: go install github.com/g0ldencybersec/gungnir/cmd/gungnir@latest
    log INFO "Installing gungnir..."
    if ! install_go_tool_remote "gungnir" "go install github.com/g0ldencybersec/gungnir/cmd/gungnir@latest"; then
        if [ -d "${TOOLS_DIR}/gungnir-main/gungnir-main" ]; then
            if ! install_go_tool_from_source "gungnir" \
                "${TOOLS_DIR}/gungnir-main/gungnir-main" \
                "./cmd/gungnir" \
                "gungnir"; then
                log WARNING "gungnir installation failed from both remote and source"
            fi
        else
            log WARNING "gungnir source directory not found - cannot build from source"
        fi
    fi
    
    # 10. 403jump - From README: go install github.com/trap-bytes/403jump@latest
    log INFO "Installing 403jump..."
    if ! install_go_tool_remote "403jump" "go install github.com/trap-bytes/403jump@latest"; then
        if [ -d "${TOOLS_DIR}/403jump-main/403jump-main" ]; then
            if ! install_go_tool_from_source "403jump" \
                "${TOOLS_DIR}/403jump-main/403jump-main" \
                "." \
                "403jump"; then
                log WARNING "403jump installation failed from both remote and source"
            fi
        else
            log WARNING "403jump source directory not found - cannot build from source"
        fi
    fi
    
    # 11. favicorn - From README: go install github.com/sharsil/favicorn@latest (also has Python version)
    log INFO "Installing favicorn (Go version)..."
    if ! install_go_tool_remote "favicorn" "go install github.com/sharsil/favicorn@latest"; then
        log WARNING "favicorn (Go) installation failed - Python version will be installed below"
    fi
    
    # 12. gau - From README: go install github.com/lc/gau/v2/cmd/gau@latest
    log INFO "Installing gau..."
    if ! install_go_tool_remote "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"; then
        log WARNING "gau installation failed - check install.log for details"
        log WARNING "You may need to install manually: go install github.com/lc/gau/v2/cmd/gau@latest"
    fi
    
    # 13. ipranges - This is not a CLI tool, it's just a collection of IP range files
    log INFO "ipranges is a data repository, not a CLI tool - skipping installation"
    
    echo ""
    
    # Install Python tools
    log PHASE "Installing Python Tools"
    
    # 1. bbot - From README: pipx install bbot (or pip install bbot)
    log INFO "Installing bbot..."
    local bbot_installed=false
    if check_command "pipx"; then
        log INFO "Trying pipx install bbot..."
        if pipx install bbot >>"$INSTALL_LOG" 2>&1; then
            bbot_installed=true
        else
            log WARNING "pipx installation failed, trying pip..."
            if pip3 install bbot >>"$INSTALL_LOG" 2>&1; then
                bbot_installed=true
            fi
        fi
    else
        log INFO "pipx not found, using pip..."
        if pip3 install bbot >>"$INSTALL_LOG" 2>&1; then
            bbot_installed=true
        fi
    fi
    if check_command "bbot"; then
        log SUCCESS "bbot installed successfully"
    elif [ "$bbot_installed" = false ]; then
        log WARNING "bbot installation failed - check install.log for details"
        log WARNING "You may need to install bbot manually: pip3 install bbot"
    else
        log WARNING "bbot installed but not found in PATH - you may need to reload your shell"
    fi
    
    # 2. wafw00f - From README: pip install wafw00f or pip install . from directory
    log INFO "Installing wafw00f..."
    local wafw00f_installed=false
    if [ -d "${TOOLS_DIR}/wafw00f-master/wafw00f-master" ]; then
        log INFO "Installing wafw00f from source directory..."
        if install_python_tool "wafw00f" "${TOOLS_DIR}/wafw00f-master/wafw00f-master" "setup_py"; then
            wafw00f_installed=true
        fi
        # Also try pip install as fallback
        if ! $wafw00f_installed; then
            log INFO "Trying pip install wafw00f..."
            if pip3 install wafw00f >>"$INSTALL_LOG" 2>&1; then
                wafw00f_installed=true
            fi
        fi
    else
        log INFO "Source directory not found, installing via pip..."
        if pip3 install wafw00f >>"$INSTALL_LOG" 2>&1; then
            wafw00f_installed=true
        fi
    fi
    if check_command "wafw00f"; then
        log SUCCESS "wafw00f installed successfully"
    elif [ "$wafw00f_installed" = false ]; then
        log WARNING "wafw00f installation failed - check install.log for details"
        log WARNING "You may need to install manually: pip3 install wafw00f"
    else
        log WARNING "wafw00f installed but not found in PATH - you may need to reload your shell"
    fi
    
    # 3. Logsensor - From README: pip install -r requirements.txt && ./install.sh
    log INFO "Installing Logsensor..."
    local logsensor_installed=false
    if [ -d "${TOOLS_DIR}/Logsensor-main/Logsensor-main" ]; then
        log INFO "Installing Logsensor dependencies..."
        if install_python_tool "logsensor" "${TOOLS_DIR}/Logsensor-main/Logsensor-main" "requirements"; then
            logsensor_installed=true
        fi
        log INFO "Running Logsensor install.sh..."
        if install_python_tool "logsensor" "${TOOLS_DIR}/Logsensor-main/Logsensor-main" "custom"; then
            logsensor_installed=true
        fi
        # Create local symlink (the install.sh creates one in /usr/local/bin)
        if [ -f "${TOOLS_DIR}/Logsensor-main/Logsensor-main/logsensor.py" ]; then
            chmod +x "${TOOLS_DIR}/Logsensor-main/Logsensor-main/logsensor.py"
            ln -sf "${TOOLS_DIR}/Logsensor-main/Logsensor-main/logsensor.py" "${LOCAL_BIN}/logsensor" 2>/dev/null || {
                log WARNING "Could not create symlink for logsensor in ${LOCAL_BIN}"
            }
        fi
    else
        log WARNING "Logsensor source directory not found: ${TOOLS_DIR}/Logsensor-main/Logsensor-main"
        log WARNING "Cannot install Logsensor - source code missing"
    fi
    if check_command "logsensor" || [ -f "${LOCAL_BIN}/logsensor" ]; then
        log SUCCESS "logsensor installed successfully"
    elif [ "$logsensor_installed" = false ]; then
        log WARNING "logsensor installation may have failed - check install.log"
    else
        log WARNING "logsensor installed but not found - you may need to use full path: ${TOOLS_DIR}/Logsensor-main/Logsensor-main/logsensor.py"
    fi
    
    # 4. Corsy - From README: pip3 install requests
    log INFO "Installing Corsy..."
    local corsy_installed=false
    if [ -d "${TOOLS_DIR}/Corsy-master/Corsy-master" ]; then
        if install_python_tool "Corsy" "${TOOLS_DIR}/Corsy-master/Corsy-master" "requirements"; then
            corsy_installed=true
        fi
        # Make corsy.py executable
        if [ -f "${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py" ]; then
            chmod +x "${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py"
            log SUCCESS "Corsy script is ready at ${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py"
        else
            log WARNING "Corsy script not found: ${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py"
        fi
    else
        log WARNING "Corsy source directory not found: ${TOOLS_DIR}/Corsy-master/Corsy-master"
    fi
    if [ "$corsy_installed" = false ]; then
        log WARNING "Corsy dependencies installation may have failed - check install.log"
    fi
    
    # 5. CSP-Stalker - From README: pip install -r requirements.txt
    log INFO "Installing CSP-Stalker..."
    local csp_stalker_installed=false
    if [ -d "${TOOLS_DIR}/CSP-Stalker-main/CSP-Stalker-main" ]; then
        if install_python_tool "CSP-Stalker" "${TOOLS_DIR}/CSP-Stalker-main/CSP-Stalker-main" "requirements"; then
            csp_stalker_installed=true
        fi
        # Make script executable
        if [ -f "${TOOLS_DIR}/CSP-Stalker-main/CSP-Stalker-main/cli_CSP_Stalker.py" ]; then
            chmod +x "${TOOLS_DIR}/CSP-Stalker-main/CSP-Stalker-main/cli_CSP_Stalker.py"
            log SUCCESS "CSP-Stalker script is ready at ${TOOLS_DIR}/CSP-Stalker-main/CSP-Stalker-main/cli_CSP_Stalker.py"
        else
            log WARNING "CSP-Stalker script not found: ${TOOLS_DIR}/CSP-Stalker-main/CSP-Stalker-main/cli_CSP_Stalker.py"
        fi
    else
        log WARNING "CSP-Stalker source directory not found: ${TOOLS_DIR}/CSP-Stalker-main/CSP-Stalker-main"
    fi
    if [ "$csp_stalker_installed" = false ]; then
        log WARNING "CSP-Stalker dependencies installation may have failed - check install.log"
    fi
    
    # 6. favicorn (Python version) - From README: has requirements.txt
    log INFO "Installing favicorn (Python version)..."
    local favicorn_py_installed=false
    if [ -d "${TOOLS_DIR}/favicorn-main/favicorn-main" ]; then
        if install_python_tool "favicorn" "${TOOLS_DIR}/favicorn-main/favicorn-main" "requirements"; then
            favicorn_py_installed=true
        fi
        # Make script executable
        if [ -f "${TOOLS_DIR}/favicorn-main/favicorn-main/favicorn.py" ]; then
            chmod +x "${TOOLS_DIR}/favicorn-main/favicorn-main/favicorn.py"
            log SUCCESS "favicorn (Python) script is ready at ${TOOLS_DIR}/favicorn-main/favicorn-main/favicorn.py"
        else
            log WARNING "favicorn (Python) script not found: ${TOOLS_DIR}/favicorn-main/favicorn-main/favicorn.py"
        fi
    else
        log WARNING "favicorn (Python) source directory not found: ${TOOLS_DIR}/favicorn-main/favicorn-main"
    fi
    if [ "$favicorn_py_installed" = false ]; then
        log WARNING "favicorn (Python) dependencies installation may have failed - check install.log"
    fi
    
    # 7. JSMap-Inspector - This is an HTML tool, not a CLI, skip installation
    log INFO "JSMap-Inspector is an HTML-based tool, not a CLI - skipping installation"
    
    echo ""
    
    # Summary
    log PHASE "Installation Summary"
    
    log INFO "Tools installed to: $LOCAL_BIN"
    log INFO "Installation log: $INSTALL_LOG"
    echo ""
    
    log SUCCESS "Installation completed!"
    echo ""
    log INFO "Next steps:"
    echo "  1. Add ${LOCAL_BIN} to your PATH (add to ~/.bashrc or ~/.zshrc):"
    echo "     ${BOLD}export PATH=\"${LOCAL_BIN}:\$PATH\"${NC}"
    echo ""
    echo "  2. Configure API keys in config/api_keys.conf"
    echo ""
    echo "  3. Run Recondite v2:"
    echo "     ${BOLD}./recondite_v2.sh -t example.com -o ./results${NC}"
    echo ""
    
    # Check which tools are now available
    log INFO "Verifying installed tools..."
    local missing_tools=()
    
    # Check Go tools
    for tool in subfinder httpx naabu asnmap cvemap smap cariddi gungnir 403jump gau favicorn; do
        if command -v "$tool" &> /dev/null || [ -f "${LOCAL_BIN}/${tool}" ]; then
            log SUCCESS "$tool: ✓"
        else
            log WARNING "$tool: ✗ (not found in PATH or ${LOCAL_BIN})"
            missing_tools+=("$tool")
        fi
    done
    
    # Check Python tools (global installs)
    for tool in bbot wafw00f; do
        if command -v "$tool" &> /dev/null; then
            log SUCCESS "$tool: ✓"
        else
            log WARNING "$tool: ✗ (not found in PATH)"
            missing_tools+=("$tool")
        fi
    done
    
    # Check Python tools (local scripts)
    if [ -f "${TOOLS_DIR}/Logsensor-main/Logsensor-main/logsensor.py" ] || [ -f "${LOCAL_BIN}/logsensor" ] || command -v logsensor &> /dev/null; then
        log SUCCESS "logsensor: ✓"
    else
        log WARNING "logsensor: ✗ (not found)"
        missing_tools+=("logsensor")
    fi
    
    # Check Python scripts that need to be run directly
    if [ -f "${TOOLS_DIR}/Corsy-master/Corsy-master/corsy.py" ]; then
        log SUCCESS "Corsy: ✓ (script available)"
    else
        log WARNING "Corsy: ✗ (script not found)"
        missing_tools+=("Corsy")
    fi
    
    if [ -f "${TOOLS_DIR}/CSP-Stalker-main/CSP-Stalker-main/cli_CSP_Stalker.py" ]; then
        log SUCCESS "CSP-Stalker: ✓ (script available)"
    else
        log WARNING "CSP-Stalker: ✗ (script not found)"
        missing_tools+=("CSP-Stalker")
    fi
    
    if [ -f "${TOOLS_DIR}/favicorn-main/favicorn-main/favicorn.py" ] || command -v favicorn &> /dev/null; then
        log SUCCESS "favicorn (Python): ✓"
    else
        log WARNING "favicorn (Python): ✗ (not found)"
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo ""
        log WARNING "═══════════════════════════════════════════════════════════"
        log WARNING "Some tools may not be installed correctly: ${missing_tools[*]}"
        log WARNING "═══════════════════════════════════════════════════════════"
        log INFO "Check the installation log for details: $INSTALL_LOG"
        log INFO "You may need to:"
        log INFO "  1. Install missing dependencies (gcc, etc.)"
        log INFO "  2. Check your Go version (requires 1.21+)"
        log INFO "  3. Check your Python/pip installation"
        log INFO "  4. Install tools manually following their READMEs"
        echo ""
    else
        log SUCCESS "All tools verified successfully!"
    fi
}

main "$@"

