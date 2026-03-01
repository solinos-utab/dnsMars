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

# Function to download raw domain list and convert to dnsmasq format
# Usage: download_convert_raw "URL" "OUTPUT_FILE"
download_convert_raw() {
    local url="$1"
    local output="$2"
    echo "Downloading Raw List $url..."
    curl -s "$url" | \
        sed '/^#/d; /^$/d' | \
        awk "{print \"address=/\"\$0\"/$SERVER_IP\"}" > "$output"
}

# --- 1. DOWNLOAD RAW LISTS ---
echo "[$(date)] Downloading lists..."

# Download Kominfo Mirror (Alsyundawy TrustPositif) - EXCLUSIVE SOURCE
# Only download from Kominfo Mirror as requested
download_convert_raw "https://raw.githubusercontent.com/alsyundawy/TrustPositif/main/alsyundawy_porn.txt" "/tmp/porn_kominfo"
download_convert_raw "https://raw.githubusercontent.com/alsyundawy/TrustPositif/main/gambling_indonesia.txt" "/tmp/gambling_kominfo"

# --- 2. PREPARE PORN/GAMBLING LIST ---
echo "[$(date)] Merging and sorting Porn/Gambling list (Kominfo Only)..."
cat "/tmp/porn_kominfo" "/tmp/gambling_kominfo" | sort | uniq > "/tmp/porn_raw_merged"

# --- 2.5 FILTER OUT WHITELIST DOMAINS (PORN) ---
WHITELIST_FILE="/home/dns/dnsMars/whitelist_domains.txt"
if [ -f "$WHITELIST_FILE" ]; then
    echo "[$(date)] Applying whitelist filter to Porn/Gambling list..."
    
    # Sanitize whitelist: remove comments and empty lines
    sed '/^#/d; /^$/d' "$WHITELIST_FILE" > "/tmp/whitelist_clean"
    
    if [ -s "/tmp/whitelist_clean" ]; then
        grep -v -F -f "/tmp/whitelist_clean" "/tmp/porn_raw_merged" > "/tmp/porn_sorted"
    else
        echo "[$(date)] Warning: Whitelist is empty!"
        mv "/tmp/porn_raw_merged" "/tmp/porn_sorted"
    fi
else
    echo "[$(date)] Warning: Whitelist file not found! Skipping filter."
    mv "/tmp/porn_raw_merged" "/tmp/porn_sorted"
fi

# --- 3. PREPARE MALWARE LIST (REMOVE OVERLAPS) ---
# SKIP MALWARE LIST AS REQUESTED (ONLY TRUSTPOSITIF)
echo "[$(date)] Skipping Malware list (Only TrustPositif requested)..."
touch "/tmp/malware_final" # Create empty file to skip malware update

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
rm -f /tmp/porn_kominfo /tmp/gambling_kominfo /tmp/porn_raw_merged /tmp/malware_final

# Safety: Remove any stray .disabled files in active directory to prevent ghost blocks
rm -f /etc/dnsmasq.d/*.disabled

sudo systemctl restart dnsmasq
echo "[$(date)] Update selesai. Malware list bersih dari domain porno/judi."
