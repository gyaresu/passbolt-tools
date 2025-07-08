# passbolt-tools

A collection of tools for working with Passbolt password manager.

## run_ova.sh

A bash script to download, convert, and run the Passbolt Pro Debian OVA in QEMU. This allows you to easily test or use Passbolt Pro in a virtual environment without needing VirtualBox or VMware.

### Features

- Automatic download of the latest Passbolt Pro Debian OVA
- SHA-512 checksum verification
- Conversion from VMDK to QCOW2 format
- Automatic VM startup with port forwarding
- SSH access to the VM
- Cross-platform compatibility (macOS and Linux)

### Requirements

- QEMU (`qemu-system-x86_64` and `qemu-img`)
- aria2c (for faster downloads)
- sshpass (for password-based SSH login)
- tar (for extracting OVA files)
- nc (netcat, for port checking)
- curl (for downloading checksums)
- Either `shasum` (macOS) or `sha512sum` (Linux) for checksum verification

### Usage

```bash
# Use default QCOW2 name (pbp.qcow2)
./run_ova.sh

# Or specify a custom QCOW2 image
./run_ova.sh custom-image.qcow2
```

### Port Forwarding

The script sets up the following port forwarding:

| Host Port | VM Port | Service |
|-----------|---------|---------|
| 2222      | 22      | SSH     |
| 4433      | 443     | HTTPS   |
| 8080      | 80      | HTTP    |
| 9025      | 8025    | Mail    |

### Default Credentials

- SSH: `passbolt` / `admin`
