# Create scripts directory
mkdir -p scripts

# Create installation script
cat > scripts/install.sh << 'EOF'
#!/bin/bash
set -e

echo "🔐 Aegis-HV Security Hardening Installation"
echo "=============================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Build the daemon
echo -e "${YELLOW}[1/5] Building daemon...${NC}"
cargo build --release

# 2. Compute binary hash
echo -e "${YELLOW}[2/5] Computing binary integrity hash...${NC}"
BINARY_HASH=$(sha256sum target/release/aegis-daemon | cut -d' ' -f1)
echo -e "${GREEN}Hash: $BINARY_HASH${NC}"

# 3. Install binary
echo -e "${YELLOW}[3/5] Installing daemon to /usr/local/bin...${NC}"
sudo cp target/release/aegis-daemon /usr/local/bin/
sudo chmod 0755 /usr/local/bin/aegis-daemon
sudo chown root:root /usr/local/bin/aegis-daemon

# 4. Create directories
echo -e "${YELLOW}[4/5] Creating secure directories...${NC}"
sudo mkdir -p /etc/aegis/policies
sudo chmod 0750 /etc/aegis/policies
sudo mkdir -p /var/lib/aegis
sudo chmod 0700 /var/lib/aegis
sudo mkdir -p /var/log/aegis
sudo chmod 0700 /var/log/aegis

# 5. Install systemd service
echo -e "${YELLOW}[5/5] Installing systemd service...${NC}"
sudo cp aegis-hv.service /etc/systemd/system/
sudo sed -i "s/AEGIS_BINARY_HASH=.*/AEGIS_BINARY_HASH=$BINARY_HASH/" /etc/systemd/system/aegis-hv.service
sudo chmod 0644 /etc/systemd/system/aegis-hv.service
sudo systemctl daemon-reload

# 6. Copy policy
sudo cp policies/default.yaml /etc/aegis/policies/
sudo chmod 0640 /etc/aegis/policies/default.yaml

echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Review the policy: sudo nano /etc/aegis/policies/default.yaml"
echo "2. Enable the service: sudo systemctl enable aegis-hv.service"
echo "3. Start the service: sudo systemctl start aegis-hv.service"
echo "4. Check status: sudo systemctl status aegis-hv.service"
echo "5. View logs: sudo journalctl -u aegis-hv.service -f"
EOF

chmod +x scripts/install.sh

# Verify
ls -la scripts/install.sh