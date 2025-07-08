#!/usr/bin/env bash
set -euo pipefail

# Constants
OVA_URL="https://www.passbolt.com/pro/download/vm/debian/latest"
VMDK_FILE="passbolt-pro-debian-latest-stable-disk1.vmdk"
DEFAULT_QCOW2="pbp.qcow2"

# Input: use CLI arg or fallback
QCOW2_INPUT="${1:-$DEFAULT_QCOW2}"

# Function: wait for SSH port
wait_for_ssh() {
  echo "⏳ Waiting for SSH port (localhost:2222)..."
  for i in {1..30}; do
    if nc -z localhost 2222; then
      echo "✅ SSH port is open."
      return
    fi
    sleep 2
  done
  echo "❌ SSH port did not open. Exiting."
  exit 1
}

# Function: wait for SSH login
wait_for_ssh_login() {
  echo "⏳ Waiting for SSH login to succeed..."
  for i in {1..30}; do
    if sshpass -p 'admin' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 passbolt@localhost "echo SSH is ready" &>/dev/null; then
      echo "✅ SSH login successful."
      return
    fi
    sleep 2
  done
  echo "❌ SSH login failed after timeout. Exiting."
  exit 1
}

# Download & convert OVA if QCOW2 not found
if [[ -f "$QCOW2_INPUT" ]]; then
  QCOW2_FILE="$(realpath "$QCOW2_INPUT")"
  echo "🟢 Using existing QCOW2 file: $QCOW2_FILE"
else
  echo "📥 QCOW2 file not found: $QCOW2_INPUT"

  echo "🧹 Removing previous OVA files..."
  rm -f passbolt-pro-debian-latest*.ova

  echo "⬇️  Downloading Passbolt Pro Debian OVA (quiet mode)..."
  aria2c \
    --summary-interval=0 \
    --console-log-level=warn \
    -x 16 -s 16 -k 1M \
    -o "passbolt-pro-debian-latest-stable.ova" "$OVA_URL"

  # Resolve actual downloaded file (handles .1.ova etc)
  OVA_FILE=$(ls -t passbolt-pro-debian-latest*.ova | head -n1)

  echo "🔍 Downloading SHA-512 checksum..."
  CHECKSUM=$(curl -sS https://storage.googleapis.com/artifacts-00-production569e8230/pro/vm/debian/SHA512SUMS.txt | grep -w "passbolt-pro-debian-latest-stable.ova" | awk '{print $1}')

  if [[ -z "$CHECKSUM" ]]; then
    echo "❌ Failed to extract checksum from remote file. Aborting."
    exit 1
  fi

  echo "$CHECKSUM  passbolt-pro-debian-latest-stable.ova" > passbolt-pro-debian-latest-stable.ova.sha512

  # Determine which checksum command to use (macOS uses shasum, Linux uses sha512sum)
  if command -v shasum &> /dev/null; then
    SHASUM_CMD="shasum -a 512"
  elif command -v sha512sum &> /dev/null; then
    SHASUM_CMD="sha512sum"
  else
    echo "❌ Neither shasum nor sha512sum found. Cannot verify checksum."
    exit 1
  fi

  echo "🔐 Verifying SHA-512 checksum..."
  if ! $SHASUM_CMD -c passbolt-pro-debian-latest-stable.ova.sha512 --ignore-missing; then
    echo "❌ Checksum verification failed. Aborting."
    exit 1
  fi

  rm -f "${OVA_FILE}.sha512"

  echo "📦 Extracting OVA contents..."
  tar xf "$OVA_FILE"

  echo "💿 Converting VMDK to QCOW2..."
  qemu-img convert -O qcow2 "$VMDK_FILE" "$DEFAULT_QCOW2"
  QCOW2_FILE="$(realpath "$DEFAULT_QCOW2")"
  
  echo "🧹 Cleaning up extracted and temporary files..."
  rm -f "$OVA_FILE" "$VMDK_FILE" "${OVA_FILE}.sha512"

fi

# Start VM
echo "🚀 Starting the VM in QEMU..."
qemu-system-x86_64 \
  -m 8192 \
  -cpu qemu64 \
  -drive file="$QCOW2_FILE",if=virtio,format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::4433-:443,hostfwd=tcp::8080-:80,hostfwd=tcp::9025-:8025 \
  -device virtio-net,netdev=net0 > /dev/null 2>&1 &
sleep 1
QEMU_PID=$(pgrep -fn qemu-system-x86_64)

# Wait for boot and login readiness
wait_for_ssh
wait_for_ssh_login

# Interactive SSH session
echo "🔐 Connecting via SSH..."
sshpass -p 'admin' ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null passbolt@localhost -p 2222

# Shutdown
echo "🛑 Cleaning up QEMU VM..."
if [[ -n "$QEMU_PID" ]] && kill "$QEMU_PID" 2>/dev/null; then
  echo "✅ QEMU VM stopped."
else
  echo "⚠️ QEMU process not found or already terminated."
fi
