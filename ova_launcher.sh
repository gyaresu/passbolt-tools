#!/usr/bin/env bash
set -euo pipefail

# Constants
OVA_URL="https://www.passbolt.com/pro/download/vm/debian/latest"
VMDK_FILE="passbolt-pro-debian-latest-stable-disk1.vmdk"
DEFAULT_QCOW2="pbp.qcow2"

# Parse command line arguments
SKIP_CHECKSUM="false"
SKIP_SSH_WAIT="false"
QCOW2_INPUT="$DEFAULT_QCOW2"
BROWSER_CHOICE="auto"
BROWSER_PROFILE_DIR=""
QEMU_PID=""

for arg in "$@"; do
  case "$arg" in
    --skip-checksum|--no-verify)
      SKIP_CHECKSUM="true"
      ;;
    --skip-ssh-wait|--no-ssh-wait)
      SKIP_SSH_WAIT="true"
      ;;
    --browser=*)
      BROWSER_CHOICE="${arg#--browser=}"
      ;;
    --no-browser)
      BROWSER_CHOICE="none"
      ;;
    --help|-h)
      echo "Usage: $0 [QCOW2_FILE] [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  QCOW2_FILE            Path to existing QCOW2 file (default: $DEFAULT_QCOW2)"
      echo "  --skip-checksum       Skip checksum verification (useful for local builds)"
      echo "  --skip-ssh-wait       Skip waiting for SSH and connect manually"
      echo "  --no-verify           Alias for --skip-checksum"
      echo "  --no-ssh-wait         Alias for --skip-ssh-wait"
      echo "  --browser=BROWSER     Launch browser with temp profile: chrome, firefox, auto (default: auto)"
      echo "  --no-browser          Skip automatic browser launch"
      echo "  --help, -h            Show this help message"
      exit 0
      ;;
    *)
      if [[ "$arg" != --* ]]; then
        QCOW2_INPUT="$arg"
      fi
      ;;
  esac
done

# Cleanup function -- registered via trap to ensure QEMU is killed and temp dirs removed
cleanup() {
  if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "🛑 Cleaning up QEMU VM..."
    kill "$QEMU_PID" 2>/dev/null && echo "✅ QEMU VM stopped." || echo "⚠️ QEMU process already terminated."
  fi
  if [[ -n "$BROWSER_PROFILE_DIR" && -d "$BROWSER_PROFILE_DIR" ]]; then
    rm -rf "$BROWSER_PROFILE_DIR"
    echo "🧹 Removed temporary browser profile."
  fi
}
trap cleanup EXIT

# Function: check if a port is already in use
check_port() {
  local port="$1"
  if nc -z localhost "$port" 2>/dev/null; then
    echo "❌ Port $port is already in use."
    echo "   Run: lsof -i :$port"
    exit 1
  fi
}

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
  local last_error=""
  local ssh_output
  for i in {1..60}; do
    # Try to connect and capture error output
    ssh_output=$(sshpass -p 'admin' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o PreferredAuthentications=password -p 2222 passbolt@localhost "echo SSH is ready" 2>&1) || true
    if echo "$ssh_output" | grep -q "SSH is ready"; then
      echo "✅ SSH login successful."
      return
    fi
    # Capture the last meaningful error
    if echo "$ssh_output" | grep -qE "(Connection|kex_exchange|Permission denied|Authentication failed)"; then
      last_error=$(echo "$ssh_output" | grep -E "(Connection|kex_exchange|Permission denied|Authentication failed)" | tail -1)
    fi
    # Show progress every 10 attempts
    if (( i % 10 == 0 )); then
      echo "   Still waiting... (attempt $i/60)"
      if [[ -n "$last_error" ]]; then
        echo "   Last error: $last_error"
      fi
    fi
    sleep 2
  done
  echo "❌ SSH login failed after timeout."
  if [[ -n "$last_error" ]]; then
    echo "   Last error: $last_error"
  fi
  echo ""
  echo "💡 The locally built OVA may have different SSH configuration."
  echo "   Try connecting manually with different credentials:"
  echo "   sshpass -p 'admin' ssh -p 2222 passbolt@localhost"
  echo "   sshpass -p 'admin' ssh -p 2222 root@localhost"
  echo "   ssh -p 2222 root@localhost  # (may prompt for password)"
  echo ""
  echo "   Or check the QEMU console for boot messages."
  exit 1
}

# Function: wait for web service to respond
# Checks HTTP (port 8081→80) because HTTPS (port 4433→443) requires SSL
# certs which may not exist yet on a fresh OVA (pre-setup wizard).
wait_for_https() {
  echo "⏳ Waiting for web service (localhost:8081)..."
  for i in {1..150}; do
    if curl -s -o /dev/null http://localhost:8081 2>/dev/null; then
      echo "✅ Web service is responding."
      return
    fi
    sleep 2
  done
  echo "⚠️  Web service did not respond within timeout. Continuing anyway."
}

# Function: detect browser
detect_browser() {
  case "$BROWSER_CHOICE" in
    none)
      return
      ;;
    chrome)
      if [[ -d "/Applications/Google Chrome.app" ]]; then
        BROWSER_CHOICE="chrome"
      else
        echo "⚠️  Google Chrome not found. Skipping browser launch."
        BROWSER_CHOICE="none"
      fi
      ;;
    firefox)
      if [[ -d "/Applications/Firefox.app" ]]; then
        BROWSER_CHOICE="firefox"
      else
        echo "⚠️  Firefox not found. Skipping browser launch."
        BROWSER_CHOICE="none"
      fi
      ;;
    auto)
      if [[ -d "/Applications/Google Chrome.app" ]]; then
        BROWSER_CHOICE="chrome"
      elif [[ -d "/Applications/Firefox.app" ]]; then
        BROWSER_CHOICE="firefox"
      else
        echo "⚠️  No supported browser found. Skipping browser launch."
        BROWSER_CHOICE="none"
      fi
      ;;
    *)
      echo "⚠️  Unknown browser: $BROWSER_CHOICE. Use chrome, firefox, or auto."
      BROWSER_CHOICE="none"
      ;;
  esac
}

# Function: launch browser with ephemeral profile
launch_browser() {
  if [[ "$BROWSER_CHOICE" == "none" ]]; then
    return
  fi

  BROWSER_PROFILE_DIR=$(mktemp -d /tmp/passbolt-test-XXXXXX)

  case "$BROWSER_CHOICE" in
    chrome)
      echo "🌐 Launching Chrome with temporary profile..."
      open -na "Google Chrome" --args \
        --user-data-dir="$BROWSER_PROFILE_DIR" \
        --ignore-certificate-errors \
        --test-type \
        --no-first-run \
        --no-default-browser-check \
        http://localhost:8081/install
      ;;
    firefox)
      echo "🌐 Launching Firefox with temporary profile..."
      /Applications/Firefox.app/Contents/MacOS/firefox \
        -profile "$BROWSER_PROFILE_DIR" \
        -no-remote \
        http://localhost:8081/install &
      ;;
  esac
}

# --- Helpers for OVA handling ---

download_ova() {
  echo "⬇️  Downloading Passbolt Pro Debian OVA (quiet mode)..."
  aria2c \
    --summary-interval=0 \
    --console-log-level=warn \
    -x 16 -s 16 -k 1M \
    -o "passbolt-pro-debian-latest-stable.ova" "$OVA_URL"
}

fetch_expected_checksum() {
  curl -sS https://storage.googleapis.com/artifacts-00-production569e8230/pro/vm/debian/SHA512SUMS.txt \
    | awk '$2=="passbolt-pro-debian-latest-stable.ova"{print $1}'
}

verify_ova_checksum() {
  local ova="$1"

  local expected_checksum
  expected_checksum="$(fetch_expected_checksum)"
  if [[ -z "$expected_checksum" ]]; then
    echo "❌ Failed to extract checksum from remote file. Aborting."
    exit 1
  fi

  # Determine checksum command
  local shasum_cmd=""
  if command -v shasum &>/dev/null; then
    shasum_cmd="shasum -a 512"
  elif command -v sha512sum &>/dev/null; then
    shasum_cmd="sha512sum"
  else
    echo "❌ Neither shasum nor sha512sum found. Cannot verify checksum."
    exit 1
  fi

  echo "🔐 Verifying SHA-512 checksum for: $ova"

  # Compute actual checksum of the OVA file
  local actual_checksum
  actual_checksum="$($shasum_cmd "$ova" | awk '{print $1}')"

  # Compare checksums
  if [[ "$actual_checksum" != "$expected_checksum" ]]; then
    echo "❌ Checksum verification failed."
    echo "   Expected: $expected_checksum"
    echo "   Actual:   $actual_checksum"
    exit 1
  fi

  echo "✅ Checksum verification passed."
}

extract_vmdk_from_ova() {
  local ova="$1"

  echo "📦 Extracting OVA contents..."
  # Try to extract just the known vmdk name first (fast path).
  # If it isn't present (name mismatch), fall back to extracting all.
  if tar tf "$ova" | grep -q -F "$VMDK_FILE"; then
    tar xf "$ova" "$VMDK_FILE"
  else
    tar xf "$ova"
  fi

  if [[ ! -f "$VMDK_FILE" ]]; then
    echo "❌ Expected VMDK not found after extraction: $VMDK_FILE"
    echo "   Files extracted:"
    ls -la
    exit 1
  fi
}

# --- Download/convert logic ---

if [[ -f "$QCOW2_INPUT" ]]; then
  QCOW2_FILE="$(realpath "$QCOW2_INPUT")"
  echo "🟢 Using existing QCOW2 file: $QCOW2_FILE"
else
  echo "📥 QCOW2 file not found: $QCOW2_INPUT"

  # Prefer an existing OVA in the current directory (where script is launched)
  OVA_FILE=""
  DOWNLOADED_OVA="false"

  if [[ -f "./passbolt-pro-debian-latest-stable.ova" ]]; then
    OVA_FILE="./passbolt-pro-debian-latest-stable.ova"
  else
    # Pick newest matching local OVA if present
    OVA_FILE="$(ls -t ./passbolt-pro-debian-latest*.ova 2>/dev/null | head -n1 || true)"
  fi

  if [[ -n "$OVA_FILE" && -f "$OVA_FILE" ]]; then
    echo "🟢 Using existing OVA in current directory: $(realpath "$OVA_FILE")"
    if [[ "$SKIP_CHECKSUM" == "true" ]]; then
      echo "⚠️  Skipping checksum verification (--skip-checksum flag)"
    else
      echo "⚠️  Skipping checksum verification for existing OVA file"
    fi
  else
    echo "🌐 No local OVA found; downloading..."
    download_ova
    OVA_FILE="./passbolt-pro-debian-latest-stable.ova"
    DOWNLOADED_OVA="true"
    if [[ "$SKIP_CHECKSUM" == "true" ]]; then
      echo "⚠️  Skipping checksum verification (--skip-checksum flag)"
    else
      echo "🔐 Verifying checksum for downloaded OVA..."
      verify_ova_checksum "$(realpath "$OVA_FILE")"
    fi
  fi

  extract_vmdk_from_ova "$OVA_FILE"

  echo "💿 Converting VMDK to QCOW2..."
  qemu-img convert -O qcow2 "$VMDK_FILE" "$DEFAULT_QCOW2"
  QCOW2_FILE="$(realpath "$DEFAULT_QCOW2")"

  echo "🧹 Cleaning up extracted VMDK..."
  rm -f "$VMDK_FILE"

  # Optional: if you *only* want to keep a downloaded OVA around sometimes, toggle this.
  # If you want to delete only the downloaded OVA, uncomment:
  # if [[ "$DOWNLOADED_OVA" == "true" ]]; then rm -f "$OVA_FILE"; fi
fi

# Check for port conflicts before launching QEMU
echo "🔍 Checking for port conflicts..."
check_port 2222
check_port 4433
check_port 8081
check_port 9025

# Start VM
echo "🚀 Starting the VM in QEMU..."
qemu-system-x86_64 \
  -m 8192 \
  -cpu qemu64 \
  -smp 4 \
  -drive file="$QCOW2_FILE",if=virtio,format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::4433-:443,hostfwd=tcp::8081-:80,hostfwd=tcp::9025-:8025 \
  -device virtio-net,netdev=net0 > /dev/null 2>&1 &
QEMU_PID=$!

# Wait for boot and login readiness
if [[ "$SKIP_SSH_WAIT" == "true" ]]; then
  echo "⚠️  Skipping SSH wait (--skip-ssh-wait flag)"
  echo "💡 VM is running. Connect manually when ready:"
  echo "   sshpass -p 'admin' ssh -p 2222 passbolt@localhost"
  echo "   sshpass -p 'admin' ssh -p 2222 root@localhost"
  echo ""
  echo "Press Enter when ready to connect, or Ctrl+C to exit..."
  read -r
else
  wait_for_ssh
  wait_for_ssh_login
fi

# Launch browser with ephemeral profile
detect_browser
if [[ "$BROWSER_CHOICE" != "none" ]]; then
  wait_for_https
  launch_browser
fi

# Interactive SSH session
echo "🔐 Connecting via SSH..."
# Try passbolt user first, fall back to root if that fails
if sshpass -p 'admin' ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o ConnectTimeout=5 -p 2222 passbolt@localhost "echo connected" &>/dev/null; then
  sshpass -p 'admin' ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -p 2222 passbolt@localhost
elif sshpass -p 'admin' ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o ConnectTimeout=5 -p 2222 root@localhost "echo connected" &>/dev/null; then
  echo "⚠️  Using root user instead of passbolt"
  sshpass -p 'admin' ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -p 2222 root@localhost
else
  echo "❌ Could not connect with passbolt or root user."
  echo "💡 Try connecting manually:"
  echo "   sshpass -p 'admin' ssh -p 2222 passbolt@localhost"
  echo "   sshpass -p 'admin' ssh -p 2222 root@localhost"
  echo "   ssh -p 2222 root@localhost"
  exit 1
fi
