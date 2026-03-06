#!/bin/bash
# =============================================================================
# Penetration Testing Toolkit v3.0 — Installer
# =============================================================================
# Installs all system tools and Python dependencies.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
err()  { echo -e "${RED}  ✗ $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${NC}"; }
info() { echo -e "${CYAN}  → $*${NC}"; }
hdr()  {
    echo -e "\n${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}${BOLD}  $*${NC}"
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="unknown"
[[ "$OSTYPE" == "linux-gnu"* ]] && OS="linux"
[[ "$OSTYPE" == "darwin"*    ]] && OS="macos"

INSTALLED=()
FAILED=()
SKIPPED=()

# ── Helpers ───────────────────────────────────────────────────────────────────
has() { command -v "$1" &>/dev/null; }

try_install_brew() {
    local pkg="$1"; local label="${2:-$1}"
    info "brew install $pkg"
    if brew install "$pkg" &>/dev/null; then
        ok "$label installed"
        INSTALLED+=("$label")
    else
        warn "$label — brew install failed (may already be installed)"
        SKIPPED+=("$label")
    fi
}

try_install_apt() {
    local pkg="$1"; local label="${2:-$1}"
    info "apt-get install $pkg"
    if sudo apt-get install -y "$pkg" &>/dev/null; then
        ok "$label installed"
        INSTALLED+=("$label")
    else
        warn "$label — apt install failed"
        FAILED+=("$label")
    fi
}

pip_install() {
    local pkg="$1"; local label="${2:-$1}"
    info "pip install $pkg"
    if python3 -m pip install --break-system-packages -q "$pkg" 2>/dev/null \
    || python3 -m pip install -q "$pkg" 2>/dev/null; then
        ok "$label installed"
        INSTALLED+=("$label")
    else
        warn "$label — pip install failed"
        FAILED+=("$label")
    fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║     🔒  Penetration Testing Toolkit v3.0 — Installer         ║${NC}"
echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e ""
info "Detected OS: $OS"

# ── Python check ──────────────────────────────────────────────────────────────
hdr "Python"
if has python3; then
    PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
    ok "Python $PY_VER found"
    MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [[ $MAJOR -lt 3 ]] || [[ $MAJOR -eq 3 && $MINOR -lt 9 ]]; then
        err "Python 3.9+ required (found $PY_VER)"
        exit 1
    fi
else
    err "python3 not found — install from https://python.org"
    exit 1
fi

# =============================================================================
#  macOS
# =============================================================================
if [[ "$OS" == "macos" ]]; then

    # ── Homebrew ─────────────────────────────────────────────────────────────
    hdr "Homebrew"
    if has brew; then
        ok "Homebrew already installed"
        info "Updating Homebrew..."
        brew update --quiet 2>/dev/null || true
    else
        warn "Homebrew not found — installing now..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        # Add brew to PATH for Apple Silicon
        if [[ -f /opt/homebrew/bin/brew ]]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
        ok "Homebrew installed"
    fi

    # ── Core scanning ─────────────────────────────────────────────────────────
    hdr "Core Scanning Tools"
    for pkg in nmap nikto; do
        if has "$pkg"; then ok "$pkg already installed"; SKIPPED+=("$pkg")
        else try_install_brew "$pkg"; fi
    done

    # ── Web fuzzing ───────────────────────────────────────────────────────────
    hdr "Web Fuzzing Tools"
    for pkg in gobuster ffuf; do
        if has "$pkg"; then ok "$pkg already installed"; SKIPPED+=("$pkg")
        else try_install_brew "$pkg"; fi
    done

    # feroxbuster — not in default Homebrew tap
    if has feroxbuster; then
        ok "feroxbuster already installed"
        SKIPPED+=("feroxbuster")
    else
        info "Installing feroxbuster via Homebrew..."
        if brew install feroxbuster &>/dev/null; then
            ok "feroxbuster installed"
            INSTALLED+=("feroxbuster")
        else
            warn "feroxbuster not in brew — trying cargo..."
            if has cargo; then
                cargo install feroxbuster &>/dev/null && ok "feroxbuster installed via cargo" \
                    || warn "feroxbuster install failed — install manually: https://github.com/epi052/feroxbuster"
            else
                warn "feroxbuster skipped — install manually: https://github.com/epi052/feroxbuster"
                SKIPPED+=("feroxbuster")
            fi
        fi
    fi

    # Wordlists
    hdr "Wordlists (SecLists)"
    SECLISTS_PATH="/usr/local/share/seclists"
    SECLISTS_PATH_ARM="/opt/homebrew/share/seclists"
    if [[ -d "$SECLISTS_PATH" ]] || [[ -d "$SECLISTS_PATH_ARM" ]]; then
        ok "SecLists already installed"
        SKIPPED+=("seclists")
    else
        try_install_brew "seclists" "SecLists"
    fi

    # ── OSINT tools ───────────────────────────────────────────────────────────
    hdr "OSINT Tools"

    # subfinder
    if has subfinder; then ok "subfinder already installed"; SKIPPED+=("subfinder")
    else try_install_brew "subfinder"; fi

    # amass
    if has amass; then ok "amass already installed"; SKIPPED+=("amass")
    else try_install_brew "amass"; fi

    # whois + dig
    for pkg in whois; do
        if has "$pkg"; then ok "$pkg already installed"; SKIPPED+=("$pkg")
        else try_install_brew "$pkg"; fi
    done
    # dig is part of bind on macOS
    if ! has dig; then
        info "Installing bind (provides dig)..."
        try_install_brew "bind" "dig"
    else
        ok "dig already available"
        SKIPPED+=("dig")
    fi

    # traceroute
    if has traceroute; then ok "traceroute already installed"; SKIPPED+=("traceroute")
    else try_install_brew "traceroute"; fi

# =============================================================================
#  Linux
# =============================================================================
elif [[ "$OS" == "linux" ]]; then

    hdr "Updating Package Lists"
    sudo apt-get update -q

    # ── Core scanning ─────────────────────────────────────────────────────────
    hdr "Core Scanning Tools"
    for pkg in nmap nikto traceroute whois dnsutils; do
        if has "${pkg%%:*}"; then ok "$pkg already installed"; SKIPPED+=("$pkg")
        else try_install_apt "$pkg"; fi
    done

    # ── Web fuzzing ───────────────────────────────────────────────────────────
    hdr "Web Fuzzing Tools"

    # gobuster
    if has gobuster; then ok "gobuster already installed"; SKIPPED+=("gobuster")
    else try_install_apt "gobuster"; fi

    # ffuf
    if has ffuf; then ok "ffuf already installed"; SKIPPED+=("ffuf")
    else try_install_apt "ffuf"; fi

    # feroxbuster
    if has feroxbuster; then ok "feroxbuster already installed"; SKIPPED+=("feroxbuster")
    else
        info "Installing feroxbuster via install script..."
        if curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
            | bash -s "$HOME/.local/bin" &>/dev/null; then
            ok "feroxbuster installed to ~/.local/bin"
            INSTALLED+=("feroxbuster")
        else
            try_install_apt "feroxbuster" || warn "feroxbuster not available — try: cargo install feroxbuster"
        fi
    fi

    # SecLists
    hdr "Wordlists"
    if [[ -d /usr/share/seclists ]]; then ok "SecLists already installed"; SKIPPED+=("seclists")
    else try_install_apt "seclists" "SecLists"; fi

    # ── OSINT tools ───────────────────────────────────────────────────────────
    hdr "OSINT Tools"
    for pkg in subfinder amass; do
        if has "$pkg"; then ok "$pkg already installed"; SKIPPED+=("$pkg")
        else try_install_apt "$pkg"; fi
    done

else
    warn "Unsupported OS ($OSTYPE) — skipping system tool installation."
    warn "Install tools manually: nmap nikto gobuster ffuf subfinder amass whois"
fi

# =============================================================================
#  Python deps (both platforms)
# =============================================================================
hdr "Python Dependencies"

PY_PKGS=(
    "flask"
    "requests"
    "cryptography"
    "pycryptodome"
    "colorama"
    "weasyprint"
    "theHarvester"
    "dnsrecon"
    "python-dotenv"
)

for pkg in "${PY_PKGS[@]}"; do
    # Import name differs for some packages
    import_name="$pkg"
    [[ "$pkg" == "theHarvester"  ]] && import_name="theHarvester"
    [[ "$pkg" == "python-dotenv" ]] && import_name="dotenv"
    [[ "$pkg" == "pycryptodome"  ]] && import_name="Crypto"

    if python3 -c "import $import_name" &>/dev/null; then
        ok "$pkg already installed"
        SKIPPED+=("$pkg")
    else
        pip_install "$pkg"
    fi
done

# =============================================================================
#  Go tools (optional — only if Go is installed)
# =============================================================================
if has go; then
    hdr "Go-based Tools (optional)"
    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/OJ/gobuster/v3@latest"
        "github.com/ffuf/ffuf/v2@latest"
    )
    for tool in "${GO_TOOLS[@]}"; do
        bin=$(basename "${tool%%@*}")
        if has "$bin"; then
            ok "$bin already installed (skipping go install)"
            SKIPPED+=("$bin (go)")
        else
            info "go install $tool"
            if go install "$tool" &>/dev/null; then
                ok "$bin installed via go"
                INSTALLED+=("$bin (go)")
            else
                warn "$bin go install failed"
                FAILED+=("$bin (go)")
            fi
        fi
    done
else
    info "Go not installed — skipping go-based tool installation"
    info "Install Go from https://go.dev/dl/ for newer versions of gobuster/ffuf/subfinder"
fi

# =============================================================================
#  Make scripts executable
# =============================================================================
hdr "Permissions"
chmod +x toolkit.py server.py 2>/dev/null && ok "toolkit.py and server.py marked executable" || true

# =============================================================================
#  Verification
# =============================================================================
hdr "Verification"

VERIFY_TOOLS=(nmap nikto gobuster ffuf feroxbuster subfinder amass whois dig)
VERIFY_PY=(flask requests cryptography)

echo -e "  ${BOLD}System tools:${NC}"
for t in "${VERIFY_TOOLS[@]}"; do
    if has "$t"; then
        VER=$("$t" --version 2>&1 | head -1 | tr -d '\n' || echo "ok")
        printf "    ${GREEN}✓${NC} %-20s %s\n" "$t" "${VER:0:50}"
    else
        printf "    ${YELLOW}–${NC} %-20s not installed\n" "$t"
    fi
done

echo ""
echo -e "  ${BOLD}Python packages:${NC}"
for m in "${VERIFY_PY[@]}"; do
    if python3 -c "import $m" &>/dev/null; then
        VER=$(python3 -c "import $m; print(getattr($m,'__version__','ok'))" 2>/dev/null || echo "ok")
        printf "    ${GREEN}✓${NC} %-20s %s\n" "$m" "$VER"
    else
        printf "    ${RED}✗${NC} %-20s MISSING — run: pip3 install $m\n" "$m"
    fi
done

# =============================================================================
#  Summary
# =============================================================================
hdr "Installation Summary"
echo -e "  ${GREEN}Installed:${NC}  ${#INSTALLED[@]} packages"
echo -e "  ${CYAN}Skipped:${NC}    ${#SKIPPED[@]} (already present)"
echo -e "  ${YELLOW}Failed:${NC}     ${#FAILED[@]} packages"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo ""
    warn "The following failed to install — install manually:"
    for f in "${FAILED[@]}"; do echo -e "    ${YELLOW}•${NC} $f"; done
fi

echo ""
echo -e "${GREEN}${BOLD}  Ready to go!${NC}"
echo ""
echo -e "  ${BOLD}CLI:${NC}     python3 toolkit.py"
echo -e "  ${BOLD}Web UI:${NC}  python3 server.py  →  http://127.0.0.1:5000"
echo ""
echo -e "  ${YELLOW}⚠  Authorized testing only.${NC}"
echo ""
