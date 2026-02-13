#!/bin/bash
# Script update untuk dijalankan di Secondary DNS
# Mengambil update dari GitHub dan menerapkannya

REPO_URL="https://github.com/solinos-utab/dnsMars.git"
REPO_DIR="/home/dns/dnsMars"

echo "--- Starting Update from GitHub ---"

# 1. Update Repo
if [ -d "$REPO_DIR" ]; then
    echo "Updating existing repo..."
    cd $REPO_DIR
    git fetch origin
    git reset --hard origin/main
else
    echo "Cloning repo..."
    git clone $REPO_URL $REPO_DIR
fi

# 2. Copy Files
echo "Copying files..."
sudo mkdir -p /home/dns/web_gui/templates
sudo cp $REPO_DIR/src/web_gui/templates/index.html /home/dns/web_gui/templates/
sudo cp $REPO_DIR/src/blocked_final.html /home/dns/blocked_final.html
sudo cp $REPO_DIR/src/blocked_final.html /var/www/html/index.html

# 3. Restart Services
echo "Restarting services..."
sudo systemctl restart nginx
if systemctl list-units --full -all | grep -q 'dnsmars-gui.service'; then
    sudo systemctl restart dnsmars-gui
fi

echo "--- Update Complete! ---"
