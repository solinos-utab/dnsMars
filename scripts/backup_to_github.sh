#!/bin/bash
# Script Auto Backup dnsMars ke GitHub
# Menggunakan token yang tersimpan di ~/.git-credentials

REPO_DIR="/home/dns/dnsMars"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "=== Memulai Backup dnsMars ke GitHub ==="
echo "Waktu: $TIMESTAMP"

# Pindah ke direktori repo
cd "$REPO_DIR" || { echo "Gagal masuk direktori $REPO_DIR"; exit 1; }

# Tambahkan semua perubahan
git add .

# Commit dengan timestamp
git commit -m "Auto Backup: $TIMESTAMP"

# Push ke GitHub
echo "Mengupload ke GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo "=== Backup Berhasil! ==="
else
    echo "=== Backup Gagal! Silakan cek koneksi atau token. ==="
fi
