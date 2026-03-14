#!/bin/bash

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "  CypherX v1.0.0"
echo "  ──────────────────────────────────"
echo ""

command -v python3 >/dev/null 2>&1 || { echo "  [ERROR] Python3 not found."; exit 1; }
echo "  [*] Python3 found"

echo "  [*] Installing packages..."
pip3 install -r "$INSTALL_DIR/requirements.txt" --break-system-packages -q 2>/dev/null \
    || pip3 install -r "$INSTALL_DIR/requirements.txt" -q 2>/dev/null
echo "  [OK] Packages installed"

echo "  [*] Installing system tools..."
sudo apt-get install -y nmap tor -qq 2>/dev/null
echo "  [OK] nmap, tor ready"

mkdir -p "$INSTALL_DIR"/{results,reports,logs,wordlists}
echo "  [OK] Directories created"

LOGO=""
for ext in jpg png jpeg; do
    [ -f "$INSTALL_DIR/logo.$ext" ] && LOGO="$INSTALL_DIR/logo.$ext" && break
done

cat > /tmp/cypherx.desktop << DESK
[Desktop Entry]
Name=CypherX
Comment=Cyber Intelligence Suite
Exec=bash -c "cd $INSTALL_DIR && python3 cypherx.py; exec bash"
Icon=$LOGO
Terminal=true
Type=Application
Categories=Security;Network;
Keywords=osint;security;cypherx;
DESK

sudo cp /tmp/cypherx.desktop /usr/share/applications/cypherx.desktop 2>/dev/null
sudo update-desktop-database 2>/dev/null
chmod +x "$INSTALL_DIR/cypherx.py"
echo "  [OK] Added to menu"

echo ""
echo "  CypherX v1.0.0 installed."
echo "  Run: python3 cypherx.py --help"
echo ""
echo "alias cypherx='python3 ${INSTALL_DIR}/cypherx.py'" >> ~/.bashrc
source ~/.bashrc 2>/dev/null || true
