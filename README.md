# passbolt-tools

Tools for Passbolt password manager administration and testing.

## ova_launcher.sh

Bash script for downloading, converting, and running Passbolt Pro Debian OVA in QEMU. Provides a local testing environment without VirtualBox or VMware dependencies.

### Capabilities

- Downloads latest Passbolt Pro Debian OVA
- SHA-512 checksum verification
- VMDK to QCOW2 conversion
- VM startup with port forwarding
- SSH access to VM
- macOS and Linux support

### Dependencies

- QEMU (`qemu-system-x86_64`, `qemu-img`)
- aria2c
- sshpass
- tar
- netcat
- curl
- `shasum` (macOS) or `sha512sum` (Linux)

### Usage

```bash
# Use default QCOW2 name (pbp.qcow2)
./ova_launcher.sh

# Or specify a custom QCOW2 image
./ova_launcher.sh custom-image.qcow2
```

### Port Forwarding

| Host Port | VM Port | Service |
|-----------|---------|---------|
| 2222      | 22      | SSH     |
| 4433      | 443     | HTTPS   |
| 8080      | 80      | HTTP    |
| 9025      | 8025    | Mail    |

### Default Credentials

SSH: `passbolt` / `admin`

## cert_wizard.py

TLS certificate testing and validation tool for Passbolt deployments. Diagnoses certificate issues across LDAP, SMTP, HTTPS, and cache services.

### Capabilities

- Multi-service TLS certificate testing
- Protocol detection (STARTTLS, Implicit TLS)
- Certificate analysis (SAN, expiration, trust chain)
- Passbolt configuration integration
- Trust analysis and troubleshooting
- HTML report generation
- Docker container support

### Dependencies

- Python 3.6+
- OpenSSL command-line tools
- Network access to target services

### Usage

Test all configured services:
```bash
python3 cert_wizard.py
python3 cert_wizard.py --report
```

Test specific service:
```bash
python3 cert_wizard.py --service ldaps --host ldap.local --port 636
python3 cert_wizard.py --service smtps --host smtp.local --port 25
python3 cert_wizard.py --service https --host passbolt.local --port 443
```

Debug mode:
```bash
python3 cert_wizard.py --debug
```

### Service Detection

The script automatically detects services from Passbolt configuration:

- **Passbolt HTTPS**: Extracted from `App.fullBaseUrl` in PHP config
- **LDAP Service**: From LDAP configuration if present
- **SMTP Service**: From email transport configuration if present  
- **Cache Service**: From session/cache configuration (Valkey/Redis)

**Fallback**: If no services are configured, tests localhost defaults:
- Passbolt HTTPS: `localhost:443`
- Cache: `localhost:6379`

**Note**: When using the OVA launcher, external access is available through port forwarding:
- Passbolt HTTPS: External port 4433 → Internal port 443
- SSH: External port 2222 → Internal port 22

### Configuration Detection

Reads Passbolt configuration from multiple sources:

- **Environment files**: `/etc/environment` and current environment
- **PHP configuration**: `/etc/passbolt/passbolt.php` (with sudo access)
- **Key variables**:
  - `PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_*` (LDAP SSL)
  - `EMAIL_TRANSPORT_DEFAULT_*` (SMTP configuration)
  - `PASSBOLT_PLUGINS_SAML_SECURITY_SSL_CUSTOM_OPTIONS_*` (SSO SSL)
  - `CACHE_CAKECORE_*` (Cache configuration)
  - `PASSBOLT_APP_FULL_BASE_URL` (from PHP config)

### Certificate Validation

- Certificate validity (expiration, format)
- Hostname matching (SAN verification)
- Trust chain analysis (self-signed vs CA-signed)
- Purpose validation (key usage, extended key usage)
- TLS configuration (protocol versions, cipher suites)
- Service-specific trust requirements

### Trust Analysis

**LDAPS (Passbolt → LDAP Server)**
- LDAP server certificate validation
- CA file configuration verification
- ldapsearch testing commands

**SMTPS (Passbolt → SMTP Server)**
- STARTTLS vs Implicit TLS detection
- SMTP server certificate validation
- Configuration guidance

**HTTPS (Users → Passbolt/Keycloak)**
- Browser trust requirements
- OAuth2 SSO bidirectional trust
- Certificate warning guidance

**Valkey (Passbolt → Cache)**
- Unencrypted connection analysis
- Network security recommendations

### HTML Reports

The `--report` flag generates HTML reports containing:

- Service status summary
- Certificate information
- Trust analysis and troubleshooting steps
- Environment variable analysis
- Network routes and port information
- Administrative guidance

### Common Issues

**Certificate Hostname Mismatch**
- Issue: Hostname not found in SAN
- Solution: Update certificate to include hostname in Subject Alternative Names

**Self-Signed Certificates**
- Issue: Certificate is self-signed
- Solution: Use CA-signed certificate or add to trusted store

**Private CA Certificates**
- Issue: Certificate signed by private CA
- Solution: Use public CA (Let's Encrypt) or distribute private CA to all devices

**Connection Failures**
- Issue: Connection refused
- Solution: Check service is running and port is correct

### Troubleshooting Commands

**LDAP Testing**
```bash
ldapsearch -H ldaps://ldap.local:636 -D "cn=admin,dc=local" -W -o tls_cacert=/etc/ssl/certs/ldaps_bundle.crt
```

**SMTP Testing**
```bash
openssl s_client -connect smtp.local:465
openssl s_client -connect smtp.local:587 -starttls smtp
```

**HTTPS Testing**
```bash
# Internal testing (from within VM/container)
curl -I https://passbolt.local:443

# External testing (from host machine with port forwarding)
curl -I https://passbolt.local:4433
```

### Output Examples

**JSON Output**
```json
{
  "service": "ldaps",
  "host": "ldap.local",
  "port": 636,
  "certificate": {
    "subject": "CN=ldap.local",
    "issuer": "CN=Passbolt Root CA",
    "valid_from": "Jan 1 00:00:00 2024 GMT",
    "valid_to": "Dec 31 23:59:59 2024 GMT",
    "san": ["ldap.local"],
    "is_self_signed": false,
    "is_private_ca": true
  },
  "validation": {
    "valid": true,
    "issues": [],
    "warnings": ["Certificate is signed by a private CA"],
    "admin_guidance": ["For production: Use public CA certificate"]
  }
}
```

**HTML Report Features**
- Status indicators
- Detailed sections
- Troubleshooting steps
- Environment variable analysis
- Network topology

### Integration with Passbolt

- Reads Passbolt environment variables automatically
- Validates Passbolt-specific TLS configurations
- Provides Passbolt-specific troubleshooting guidance
- Generates reports suitable for Passbolt administrators

### Security Considerations

- Tool only reads configuration and tests connections
- No sensitive data is logged or transmitted
- Certificate validation follows security best practices
- Provides guidance for secure certificate management
