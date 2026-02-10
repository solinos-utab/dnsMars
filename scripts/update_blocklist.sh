#!/bin/bash
# Script Auto-Update Database Blokir (Hagezi Edition with Overlap Removal)
# 1. Malware/Adware (Hagezi Pro) - Cleaned of any Porn/Gambling domains
# 2. Porn/Gambling (Hagezi Gambling + NSFW) - Managed via Internet Positif Toggle

SERVER_IP="103.68.213.74"
MALWARE_TARGET="/etc/dnsmasq.d/malware.conf"
PORN_TARGET="/etc/dnsmasq.d/internet_positif.conf"
PORN_DISABLED="/home/dns/blocklists/disabled/internet_positif.conf"

# Ensure disabled directory exists
mkdir -p /home/dns/blocklists/disabled

# Cleanup temp files from previous runs to avoid permission issues
rm -f /tmp/malware_raw /tmp/malware_sorted /tmp/malware_final
rm -f /tmp/gambling_raw /tmp/nsfw_raw /tmp/porn_sorted

echo "[$(date)] Memulai update database blokir (Hagezi Cleaned)..."

# Function to download and convert to dnsmasq format
# Usage: download_convert "URL" "OUTPUT_FILE"
download_convert() {
    local url="$1"
    local output="$2"
    echo "Downloading $url..."
    curl -s "$url" | \
        grep "^local=/" | \
        sed "s|^local=/|address=/|; s|/$|/$SERVER_IP|" > "$output"
}

# --- 1. DOWNLOAD RAW LISTS ---
echo "[$(date)] Downloading lists..."

# Download Malware (Hagezi Pro)
download_convert "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/pro.txt" "/tmp/malware_raw"

# Download Gambling
download_convert "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/gambling.txt" "/tmp/gambling_raw"

# Download NSFW
download_convert "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/nsfw.txt" "/tmp/nsfw_raw"

# --- 2. PREPARE PORN/GAMBLING LIST ---
echo "[$(date)] Merging and sorting Porn/Gambling list..."
cat "/tmp/gambling_raw" "/tmp/nsfw_raw" | sort | uniq > "/tmp/porn_sorted"

# --- 3. PREPARE MALWARE LIST (REMOVE OVERLAPS) ---
echo "[$(date)] Processing Malware list (removing overlaps)..."
sort "/tmp/malware_raw" | uniq > "/tmp/malware_sorted"

# Comm -23: Lines in malware_sorted but NOT in porn_sorted
# This ensures Malware list does NOT contain any domain present in the Porn list
comm -23 "/tmp/malware_sorted" "/tmp/porn_sorted" > "/tmp/malware_final"

# --- 4. DEPLOY MALWARE LIST ---
if [ -s "/tmp/malware_final" ]; then
    sudo mv "/tmp/malware_final" "$MALWARE_TARGET"
    echo "[$(date)] Malware list updated (Overlap cleaned)."
else
    echo "[$(date)] Error: Malware list empty!"
fi

# --- 5. DEPLOY PORN/GAMBLING LIST ---
if [ -s "/tmp/porn_sorted" ]; then
    # Check current status: Active or Disabled?
    if [ -f "$PORN_TARGET" ]; then
        # Currently Active -> Update active file
        sudo mv "/tmp/porn_sorted" "$PORN_TARGET"
        echo "[$(date)] Porn/Gambling list updated (Active)."
    elif [ -f "$PORN_DISABLED" ]; then
        # Currently Disabled -> Update disabled file
        sudo mv "/tmp/porn_sorted" "$PORN_DISABLED"
        echo "[$(date)] Porn/Gambling list updated (Inactive/Disabled)."
    else
        # File not found anywhere -> Create as Disabled default
        sudo mv "/tmp/porn_sorted" "$PORN_DISABLED"
        echo "[$(date)] Porn/Gambling list created (Inactive)."
    fi
else
    echo "[$(date)] Error: Porn/Gambling list empty!"
fi

# --- 6. CLEANUP & RESTART ---
rm -f /tmp/malware_raw /tmp/malware_sorted /tmp/malware_final
rm -f /tmp/gambling_raw /tmp/nsfw_raw /tmp/porn_sorted

# Safety: Remove any stray .disabled files in active directory to prevent ghost blocks
rm -f /etc/dnsmasq.d/*.disabled

sudo systemctl restart dnsmasq
echo "[$(date)] Update selesai. Malware list bersih dari domain porno/judi."
