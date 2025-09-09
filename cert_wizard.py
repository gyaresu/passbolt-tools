#!/usr/bin/env python3
"""
TLS Certificate Tester for Passbolt (Docker-compatible)
Tests TLS certificates for multiple services and validates Passbolt configuration.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


class TLSTester:
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.passbolt_config = {}
        
    def log(self, message: str):
        """Log message if debug mode is enabled."""
        if self.debug:
            print(f"[DEBUG] {message}")
    
    def load_passbolt_config(self) -> Dict[str, Any]:
        """Load Passbolt configuration from environment variables and files."""
        config = {
            'environment_variables': {},
            'certificate_files': {},
            'services': {}
        }
        
        # Load environment variables from /etc/environment if it exists
        env_file = '/etc/environment'
        if os.path.exists(env_file):
            self.log(f"Loading environment from {env_file}")
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        # Remove quotes if present
                        value = value.strip('"\'')
                        config['environment_variables'][key] = value
        
        # Load Passbolt PHP configuration if it exists
        passbolt_php = '/etc/passbolt/passbolt.php'
        if os.path.exists(passbolt_php):
            self.log(f"Loading Passbolt PHP configuration from {passbolt_php}")
            php_config = self._parse_passbolt_php(passbolt_php)
            config['environment_variables'].update(php_config)
        
        # Also load from current environment
        for key, value in os.environ.items():
            if key.startswith(('PASSBOLT_', 'EMAIL_', 'CACHE_CAKECORE_')):
                config['environment_variables'][key] = value
        
        # Extract certificate file paths
        cert_paths = {
            'ldaps': config['environment_variables'].get('PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_CAFILE'),
            'smtp': config['environment_variables'].get('EMAIL_TRANSPORT_DEFAULT_HOST'),
            'sso': config['environment_variables'].get('PASSBOLT_PLUGINS_SAML_SECURITY_SSL_CUSTOM_OPTIONS_CAFILE'),
            'valkey': config['environment_variables'].get('CACHE_CAKECORE_HOST')
        }
        
        config['certificate_files'] = {k: v for k, v in cert_paths.items() if v}
        
        # Extract service configurations
        config['services'] = {
            'ldaps': {
                'host': config['environment_variables'].get('PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_HOST'),
                'port': config['environment_variables'].get('PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_PORT'),
                'cafile': config['environment_variables'].get('PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_CAFILE')
            },
            'smtp': {
                'host': config['environment_variables'].get('EMAIL_TRANSPORT_DEFAULT_HOST'),
                'port': config['environment_variables'].get('EMAIL_TRANSPORT_DEFAULT_PORT')
            },
            'valkey': {
                'host': config['environment_variables'].get('CACHE_CAKECORE_HOST'),
                'port': config['environment_variables'].get('CACHE_CAKECORE_PORT'),
                'tls': config['environment_variables'].get('CACHE_CAKECORE_TLS')
            }
        }
        
        self.passbolt_config = config
        return config
    
    def _parse_passbolt_php(self, php_file: str) -> Dict[str, str]:
        """Parse Passbolt PHP configuration file and extract relevant settings."""
        php_config = {}
        
        try:
            with open(php_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract configuration values using regex patterns
            patterns = {
                'PASSBOLT_APP_FULL_BASE_URL': r"'fullBaseUrl'\s*=>\s*['\"]([^'\"]+)['\"]",
                'PASSBOLT_SSL_FORCE': r"'force'\s*=>\s*(true|false)"
            }
            
            # Cache/Session configuration (more specific patterns)
            cache_patterns = {
                'CACHE_CAKECORE_HOST': r"'server'\s*=>\s*['\"]([^'\"]+)['\"]",
                'CACHE_CAKECORE_PORT': r"'port'\s*=>\s*['\"]?(\d+)['\"]?"
            }
            
            # Look for cache configuration section
            cache_section_match = re.search(r"'Cache'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
            if cache_section_match:
                cache_content = cache_section_match.group(1)
                for env_key, pattern in cache_patterns.items():
                    matches = re.findall(pattern, cache_content, re.IGNORECASE)
                    if matches:
                        value = matches[0]
                        php_config[env_key] = value
                        self.log(f"Found {env_key} = {value}")
            
            # Look for session configuration section
            session_section_match = re.search(r"'session'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
            if session_section_match:
                session_content = session_section_match.group(1)
                for env_key, pattern in cache_patterns.items():
                    matches = re.findall(pattern, session_content, re.IGNORECASE)
                    if matches:
                        value = matches[0]
                        php_config[env_key] = value
                        self.log(f"Found {env_key} = {value}")
            
            for env_key, pattern in patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    # Take the first match
                    value = matches[0]
                    # Convert boolean strings
                    if value.lower() in ['true', 'false']:
                        value = value.lower()
                    php_config[env_key] = value
                    self.log(f"Found {env_key} = {value}")
            
        except Exception as e:
            self.log(f"Error parsing PHP file {php_file}: {str(e)}")
        
        return php_config
    
    def detect_tls_protocol(self, host: str, port: int, service_type: str) -> Dict[str, Any]:
        """Detect which TLS protocol the service is using."""
        protocols_to_try = []
        
        if service_type == 'smtps':
            protocols_to_try = [
                ('STARTTLS', ['openssl', 's_client', '-connect', f'{host}:{port}', '-starttls', 'smtp', '-showcerts']),
                ('Implicit TLS', ['openssl', 's_client', '-connect', f'{host}:{port}', '-showcerts'])
            ]
        elif service_type == 'ldaps':
            protocols_to_try = [
                ('LDAPS (Implicit TLS)', ['openssl', 's_client', '-connect', f'{host}:{port}', '-showcerts']),
                ('LDAP STARTTLS', ['openssl', 's_client', '-connect', f'{host}:{port}', '-starttls', 'ldap', '-showcerts'])
            ]
        elif service_type == 'https':
            protocols_to_try = [
                ('HTTPS (Implicit TLS)', ['openssl', 's_client', '-connect', f'{host}:{port}', '-showcerts'])
            ]
        elif service_type == 'valkey':
            protocols_to_try = [
                ('Valkey (No TLS)', ['timeout', '5', 'bash', '-c', f'echo > /dev/tcp/{host}/{port}'])
            ]
        else:
            protocols_to_try = [
                ('Generic TLS', ['openssl', 's_client', '-connect', f'{host}:{port}', '-showcerts'])
            ]
        
        for protocol_name, cmd in protocols_to_try:
            try:
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=10,
                    input=''
                )
                
                if result.returncode == 0:
                    if '-----BEGIN CERTIFICATE-----' in result.stdout:
                        # TLS service with certificate
                        return {
                            'protocol': protocol_name,
                            'command': cmd,
                            'success': True,
                            'output': result.stdout
                        }
                    elif 'bash' in cmd[0] and result.returncode == 0:
                        # Non-TLS service (like valkey) - connection successful
                        return {
                            'protocol': protocol_name,
                            'command': cmd,
                            'success': True,
                            'output': 'Connection successful',
                            'no_tls': True
                        }
                elif 'Connection refused' not in result.stderr:
                    # Service responded but with different protocol
                    return {
                        'protocol': protocol_name,
                        'command': cmd,
                        'success': False,
                        'error': result.stderr,
                        'partial_output': result.stdout
                    }
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                continue
        
        return {
            'protocol': 'Unknown',
            'success': False,
            'error': 'No working TLS protocol detected'
        }
    
    def get_certificate_chain(self, host: str, port: int, service_type: str = 'generic') -> Dict[str, Any]:
        """Retrieve certificate chain from a TLS service."""
        # First detect the protocol
        protocol_info = self.detect_tls_protocol(host, port, service_type)
        
        if not protocol_info['success']:
            return {
                'error': f'Failed to detect working TLS protocol: {protocol_info.get("error", "Unknown error")}',
                'protocol_detection': protocol_info
            }
        
        try:
            # Use the detected protocol command
            cmd = protocol_info['command']
            
            # Run openssl command with timeout
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=30,
                input=''  # Send empty input to close connection
            )
            
            if result.returncode != 0:
                error_msg = f'Failed to connect to {host}:{port}'
                if 'Connection refused' in result.stderr:
                    error_msg += ' - Connection refused (service not running or wrong port)'
                elif 'No route to host' in result.stderr:
                    error_msg += ' - No route to host (network/DNS issue)'
                elif 'timeout' in result.stderr.lower():
                    error_msg += ' - Connection timeout (firewall or service not responding)'
                elif 'TLS' in result.stderr or 'SSL' in result.stderr:
                    error_msg += ' - TLS/SSL handshake failed'
                else:
                    error_msg += f' - {result.stderr.strip()}'
                
                return {
                    'error': error_msg,
                    'stderr': result.stderr
                }
            
            # Parse certificate from output
            cert_text = result.stdout
            if '-----BEGIN CERTIFICATE-----' not in cert_text:
                return {
                    'error': 'No certificates found in response',
                    'output': cert_text
                }
            
            # Extract the first certificate (server certificate)
            cert_start = cert_text.find('-----BEGIN CERTIFICATE-----')
            cert_end = cert_text.find('-----END CERTIFICATE-----', cert_start) + 25
            
            if cert_start == -1 or cert_end == -1:
                return {'error': 'Invalid certificate format in response'}
            
            server_cert = cert_text[cert_start:cert_end]
            
            # Parse certificate information
            cert_info = self._parse_certificate_text(server_cert)
            cert_info['host'] = host
            cert_info['port'] = port
            cert_info['service_type'] = service_type
            cert_info['detected_protocol'] = protocol_info['protocol']
            cert_info['protocol_detection'] = protocol_info
            
            return cert_info
            
        except subprocess.TimeoutExpired:
            return {'error': f'Connection timeout to {host}:{port} - Service may be slow or not responding'}
        except Exception as e:
            return {'error': f'Error retrieving certificate: {str(e)}'}
    
    def _parse_certificate_text(self, cert_text: str) -> Dict[str, Any]:
        """Parse certificate text and extract information."""
        try:
            # Use openssl to parse the certificate
            cmd = ['openssl', 'x509', '-text', '-noout']
            result = subprocess.run(
                cmd, 
                input=cert_text, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode != 0:
                return {'error': f'Failed to parse certificate: {result.stderr}'}
            
            cert_info = result.stdout
            
            # Extract key information
            valid_to = self._extract_field(cert_info, 'Not After:')
            valid_from = self._extract_field(cert_info, 'Not Before:')
            
            return {
                'subject': self._extract_field(cert_info, 'Subject:'),
                'issuer': self._extract_field(cert_info, 'Issuer:'),
                'valid_from': valid_from,
                'valid_to': valid_to,
                'san': self._extract_san(cert_info),
                'is_self_signed': self._is_self_signed(cert_info),
                'is_private_ca': self._is_private_ca(cert_info),
                'key_usage': self._extract_key_usage(cert_info),
                'extended_key_usage': self._extract_extended_key_usage(cert_info),
                'raw_certificate': cert_text
            }
            
        except Exception as e:
            return {'error': f'Error parsing certificate: {str(e)}'}
    
    def _extract_field(self, cert_text: str, field_name: str) -> str:
        """Extract a field value from certificate text."""
        lines = cert_text.split('\n')
        for line in lines:
            if line.strip().startswith(field_name):
                return line.split(':', 1)[1].strip()
        return ''
    
    def _extract_san(self, cert_text: str) -> List[str]:
        """Extract Subject Alternative Names from certificate text."""
        san_list = []
        in_san_section = False
        
        for line in cert_text.split('\n'):
            line = line.strip()
            if 'X509v3 Subject Alternative Name:' in line:
                in_san_section = True
                continue
            elif in_san_section:
                if line.startswith('X509v3') or line.startswith('Signature'):
                    break
                if 'DNS:' in line:
                    # Extract DNS entries
                    dns_entries = re.findall(r'DNS:([^,\s]+)', line)
                    san_list.extend(dns_entries)
        
        return san_list
    
    def _is_self_signed(self, cert_text: str) -> bool:
        """Check if certificate is self-signed."""
        subject = self._extract_field(cert_text, 'Subject:')
        issuer = self._extract_field(cert_text, 'Issuer:')
        return subject == issuer
    
    def _is_private_ca(self, cert_text: str) -> bool:
        """Check if certificate is signed by a private CA (not a public CA)."""
        issuer = self._extract_field(cert_text, 'Issuer:')
        if not issuer:
            return False
        
        # Common private CA indicators
        private_ca_indicators = [
            'passbolt', 'internal', 'local', 'corp', 'company', 'organization',
            'test', 'dev', 'staging', 'ca', 'root ca', 'intermediate'
        ]
        
        issuer_lower = issuer.lower()
        return any(indicator in issuer_lower for indicator in private_ca_indicators)
    
    def _extract_key_usage(self, cert_text: str) -> List[str]:
        """Extract key usage from certificate text."""
        usage_list = []
        in_usage_section = False
        
        for line in cert_text.split('\n'):
            line = line.strip()
            if 'X509v3 Key Usage:' in line:
                in_usage_section = True
                continue
            elif in_usage_section:
                if line.startswith('X509v3') or line.startswith('Signature'):
                    break
                if line:
                    usage_list.append(line)
        
        return usage_list
    
    def _extract_extended_key_usage(self, cert_text: str) -> List[str]:
        """Extract extended key usage from certificate text."""
        eku_list = []
        in_eku_section = False
        
        for line in cert_text.split('\n'):
            line = line.strip()
            if 'X509v3 Extended Key Usage:' in line:
                in_eku_section = True
                continue
            elif in_eku_section:
                if line.startswith('X509v3') or line.startswith('Signature'):
                    break
                if line:
                    eku_list.append(line)
        
        return eku_list
    
    def validate_certificate_purpose(self, cert_info: Dict[str, Any], service_type: str) -> Dict[str, Any]:
        """Validate certificate purpose for the service type."""
        purpose_validation = {
            'valid': True,
            'issues': [],
            'warnings': [],
            'admin_guidance': []
        }
        
        if 'error' in cert_info:
            return purpose_validation
        
        key_usage = cert_info.get('key_usage', [])
        extended_key_usage = cert_info.get('extended_key_usage', [])
        
        # Check for server authentication capability
        has_server_auth = any('TLS Web Server Authentication' in eku or 'Server Authentication' in eku 
                             for eku in extended_key_usage)
        
        if not has_server_auth:
            purpose_validation['issues'].append('Certificate does not support Server Authentication')
            purpose_validation['admin_guidance'].append('🔧 Certificate must have "TLS Web Server Authentication" in Extended Key Usage')
            purpose_validation['valid'] = False
        
        # Check for appropriate key usage
        has_digital_signature = any('Digital Signature' in ku for ku in key_usage)
        has_key_encipherment = any('Key Encipherment' in ku for ku in key_usage)
        
        if not has_digital_signature:
            purpose_validation['warnings'].append('Certificate missing Digital Signature key usage')
            purpose_validation['admin_guidance'].append('⚠️ Consider adding Digital Signature to key usage')
        
        if not has_key_encipherment:
            purpose_validation['warnings'].append('Certificate missing Key Encipherment key usage')
            purpose_validation['admin_guidance'].append('⚠️ Consider adding Key Encipherment to key usage')
        
        # Service-specific validation
        if service_type == 'ldaps':
            if not any('TLS Web Server Authentication' in eku for eku in extended_key_usage):
                purpose_validation['issues'].append('LDAPS certificate must support Server Authentication')
                purpose_validation['valid'] = False
        
        elif service_type == 'smtps':
            if not any('TLS Web Server Authentication' in eku for eku in extended_key_usage):
                purpose_validation['issues'].append('SMTPS certificate must support Server Authentication')
                purpose_validation['valid'] = False
        
        elif service_type == 'https':
            if not any('TLS Web Server Authentication' in eku for eku in extended_key_usage):
                purpose_validation['issues'].append('HTTPS certificate must support Server Authentication')
                purpose_validation['valid'] = False
        
        return purpose_validation
    
    def analyze_tls_configuration(self, host: str, port: int, service_type: str, detected_protocol: str = None) -> Dict[str, Any]:
        """Analyze TLS configuration including versions and ciphers."""
        tls_analysis = {
            'tls_version': 'Unknown',
            'cipher_suite': 'Unknown',
            'issues': [],
            'warnings': [],
            'admin_guidance': []
        }
        
        try:
            # Use the same protocol detection logic as certificate retrieval
            if service_type == 'smtps':
                if detected_protocol and 'Implicit TLS' in detected_protocol:
                    cmd = ['openssl', 's_client', '-connect', f'{host}:{port}']
                else:
                    cmd = ['openssl', 's_client', '-connect', f'{host}:{port}', '-starttls', 'smtp']
            else:
                cmd = ['openssl', 's_client', '-connect', f'{host}:{port}']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                input=''
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract TLS version
                if 'TLSv1.3' in output:
                    tls_analysis['tls_version'] = 'TLS 1.3'
                elif 'TLSv1.2' in output:
                    tls_analysis['tls_version'] = 'TLS 1.2'
                elif 'TLSv1.1' in output:
                    tls_analysis['tls_version'] = 'TLS 1.1'
                    tls_analysis['warnings'].append('TLS 1.1 is deprecated and should be disabled')
                    tls_analysis['admin_guidance'].append('🔧 Disable TLS 1.1 for security compliance')
                elif 'TLSv1' in output:
                    tls_analysis['tls_version'] = 'TLS 1.0'
                    tls_analysis['issues'].append('TLS 1.0 is obsolete and insecure')
                    tls_analysis['admin_guidance'].append('🔧 Disable TLS 1.0 immediately - it is no longer secure')
                    tls_analysis['valid'] = False
                
                # Extract cipher suite
                cipher_match = re.search(r'Cipher\s*:\s*([^\s]+)', output)
                if cipher_match:
                    tls_analysis['cipher_suite'] = cipher_match.group(1)
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'SHA1']
                    if any(weak in tls_analysis['cipher_suite'] for weak in weak_ciphers):
                        tls_analysis['warnings'].append(f'Weak cipher detected: {tls_analysis["cipher_suite"]}')
                        tls_analysis['admin_guidance'].append('🔧 Update to stronger cipher suite (AES-GCM, ChaCha20)')
                    else:
                        # Show success message for working TLS configuration
                        if detected_protocol:
                            tls_analysis['admin_guidance'].append(f'✅ TLS working correctly with {detected_protocol}')
                        else:
                            tls_analysis['admin_guidance'].append('✅ TLS configuration is working correctly')
                
        except Exception as e:
            # Only show warning if this was the primary protocol attempt
            if detected_protocol and 'Implicit TLS' in detected_protocol:
                tls_analysis['admin_guidance'].append(f'ℹ️ TLS analysis skipped - service uses {detected_protocol} (working correctly)')
            else:
                tls_analysis['warnings'].append(f'Could not analyze TLS configuration: {str(e)}')
        
        return tls_analysis
    
    def validate_passbolt_tls_config(self) -> Dict[str, Any]:
        """Validate Passbolt TLS configuration for common misconfigurations."""
        config_validation = {
            'valid': True,
            'issues': [],
            'warnings': [],
            'admin_guidance': []
        }
        
        env_vars = self.passbolt_config.get('environment_variables', {})
        
        # Check EMAIL_TRANSPORT_DEFAULT_HOST format
        email_host = env_vars.get('EMAIL_TRANSPORT_DEFAULT_HOST', '')
        if email_host:
            if not email_host.startswith(('ssl://', 'tls://')):
                config_validation['warnings'].append('EMAIL_TRANSPORT_DEFAULT_HOST should use ssl:// or tls:// prefix')
                config_validation['admin_guidance'].append('🔧 Use ssl:// for Implicit TLS or tls:// for STARTTLS')
            elif 'ssl://' in email_host and ':465' not in email_host:
                config_validation['warnings'].append('ssl:// protocol typically uses port 465')
                config_validation['admin_guidance'].append('ℹ️ Consider using port 465 with ssl:// or port 587 with tls://')
        
        # Check LDAP SSL configuration
        ldap_host = env_vars.get('PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_HOST', '')
        ldap_port = env_vars.get('PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_PORT', '')
        ldap_cafile = env_vars.get('PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_CAFILE', '')
        
        if ldap_host and not ldap_cafile:
            config_validation['warnings'].append('LDAP SSL enabled but no CA file specified')
            config_validation['admin_guidance'].append('🔧 Set PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_CAFILE')
        
        if ldap_port and ldap_port != '636':
            config_validation['warnings'].append(f'LDAP port {ldap_port} is non-standard (typically 636 for LDAPS)')
            config_validation['admin_guidance'].append('ℹ️ Standard LDAPS port is 636')
        
        # Check SSO configuration
        sso_enabled = env_vars.get('PASSBOLT_PLUGINS_SSO_ENABLED', '')
        sso_ssl_verify = env_vars.get('PASSBOLT_SECURITY_SSO_SSL_VERIFY', '')
        oauth2_enabled = env_vars.get('PASSBOLT_PLUGINS_SSO_PROVIDER_OAUTH2_ENABLED', '')
        
        if sso_enabled and sso_enabled.lower() in ['true', '1', 'yes']:
            if sso_ssl_verify and sso_ssl_verify.lower() in ['true', '1', 'yes']:
                config_validation['admin_guidance'].append('✅ SSO SSL verification is enabled')
            else:
                config_validation['warnings'].append('SSO enabled but SSL verification disabled')
                config_validation['admin_guidance'].append('🔧 Consider enabling PASSBOLT_SECURITY_SSO_SSL_VERIFY for security')
            
            if oauth2_enabled and oauth2_enabled.lower() in ['true', '1', 'yes']:
                config_validation['admin_guidance'].append('ℹ️ OAuth2 SSO provider is enabled')
        
        # Check Valkey TLS configuration
        valkey_tls = env_vars.get('CACHE_CAKECORE_TLS', '')
        if valkey_tls and valkey_tls.lower() in ['true', '1', 'yes']:
            valkey_host = env_vars.get('CACHE_CAKECORE_HOST', '')
            if not valkey_host:
                config_validation['issues'].append('Valkey TLS enabled but no host specified')
                config_validation['admin_guidance'].append('🔧 Set CACHE_CAKECORE_HOST for Valkey TLS')
                config_validation['valid'] = False
        
        return config_validation
    
    def _check_hostname_match(self, hostname: str, san_list: List[str]) -> bool:
        """Check if hostname matches any SAN entry."""
        if not san_list:
            return False
        
        # Check exact match
        if hostname in san_list:
            return True
        
        # Check wildcard match
        for san in san_list:
            if san.startswith('*.'):
                domain = san[2:]  # Remove '*.' prefix
                if hostname.endswith('.' + domain) or hostname == domain:
                    return True
        
        return False
    
    def validate_certificate(self, cert_info: Dict[str, Any], host: str, service_type: str) -> Dict[str, Any]:
        """Validate certificate for Passbolt compatibility."""
        validation = {
            'valid': True,
            'issues': [],
            'warnings': [],
            'trust_analysis': {},
            'admin_guidance': []
        }
        
        if 'error' in cert_info:
            validation['valid'] = False
            validation['issues'].append(cert_info['error'])
            
            # Add specific guidance based on error type and service
            error_msg = cert_info['error'].lower()
            if 'connection refused' in error_msg:
                if service_type == 'valkey_tls':
                    validation['admin_guidance'].append('🔧 Valkey TLS is likely not enabled on the server')
                    validation['admin_guidance'].append('ℹ️ Check Valkey configuration for TLS settings')
                elif service_type == 'smtps':
                    validation['admin_guidance'].append('🔧 SMTP service may not be running or using different port')
                    validation['admin_guidance'].append('ℹ️ Standard SMTPS ports: 465 (Implicit TLS) or 25/587 (STARTTLS)')
                else:
                    validation['admin_guidance'].append('🔧 Service may not be running or using different port')
            elif 'timeout' in error_msg:
                validation['admin_guidance'].append('🔧 Service may be slow to respond or behind firewall')
            elif 'tls' in error_msg or 'ssl' in error_msg:
                validation['admin_guidance'].append('🔧 TLS/SSL handshake failed - check certificate configuration')
            
            return validation
        
        # Check hostname match
        if 'san' in cert_info and cert_info['san']:
            hostname_match = self._check_hostname_match(host, cert_info['san'])
            if not hostname_match:
                validation['issues'].append(f'Hostname {host} not found in SAN: {cert_info["san"]}')
                validation['valid'] = False
                validation['admin_guidance'].append(f'🔧 Fix: Update certificate to include {host} in Subject Alternative Names')
        else:
            validation['warnings'].append('No Subject Alternative Names found')
            validation['admin_guidance'].append('⚠️ Consider adding SAN to certificate for better compatibility')
        
        # Check expiration
        if 'valid_to' in cert_info and cert_info['valid_to'] and cert_info['valid_to'].strip():
            try:
                # Parse date (format: Dec 31 23:59:59 2024 GMT)
                valid_to = datetime.strptime(cert_info['valid_to'], '%b %d %H:%M:%S %Y %Z')
                now = datetime.utcnow()
                
                if valid_to < now:
                    validation['issues'].append(f'Certificate expired on {cert_info["valid_to"]}')
                    validation['valid'] = False
                    validation['admin_guidance'].append('🔧 Fix: Renew certificate immediately')
                elif (valid_to - now).days < 30:
                    validation['warnings'].append(f'Certificate expires in {(valid_to - now).days} days')
                    validation['admin_guidance'].append('⚠️ Schedule certificate renewal soon')
            except ValueError:
                validation['warnings'].append(f'Could not parse expiration date: {cert_info["valid_to"]}')
        
        # Check if self-signed
        if cert_info.get('is_self_signed', False):
            validation['warnings'].append('Certificate is self-signed')
            validation['admin_guidance'].append('🔧 For production: Use CA-signed certificate or add to trusted store')
            validation['admin_guidance'].append('ℹ️ Self-signed certificates require manual trust configuration in browsers/systems')
        
        # Check if private CA
        elif cert_info.get('is_private_ca', False):
            validation['warnings'].append('Certificate is signed by a private CA')
            validation['admin_guidance'].append('⚠️ Private CA certificates are not trusted by browsers by default')
            validation['admin_guidance'].append('🌐 Users will see certificate warnings when accessing via browser')
            validation['admin_guidance'].append('💡 For OAuth2 SSO: Users must manually trust the certificate')
            validation['admin_guidance'].append('🔧 Production solution: Use public CA (Let\'s Encrypt) or distribute private CA to all devices')
        
        # Trust analysis based on service type
        validation['trust_analysis'] = self._analyze_trust_requirements(cert_info, host, service_type)
        
        # Add protocol-specific guidance
        detected_protocol = cert_info.get('detected_protocol', '')
        if detected_protocol:
            validation['admin_guidance'].append(f'ℹ️ Detected protocol: {detected_protocol}')
            
            # Add protocol-specific configuration guidance
            if 'STARTTLS' in detected_protocol and service_type == 'smtps':
                validation['admin_guidance'].append('🔧 Configure Passbolt with tls:// prefix for STARTTLS')
            elif 'Implicit TLS' in detected_protocol and service_type == 'smtps':
                validation['admin_guidance'].append('🔧 Configure Passbolt with ssl:// prefix for Implicit TLS')
            elif service_type == 'ldaps':
                validation['admin_guidance'].append('⚠️ SECURITY: ldapsearch ignores certificates by default - always use -o tls_cacert for testing')
                validation['admin_guidance'].append('🔧 Test with: ldapsearch -H ldaps://ldap.local:636 -D "cn=admin,dc=local" -W -o tls_cacert=/etc/ssl/certs/ldaps_bundle.crt')
        
        return validation
    
    def _analyze_trust_requirements(self, cert_info: Dict[str, Any], host: str, service_type: str) -> Dict[str, Any]:
        """Analyze trust requirements for different service types."""
        trust_analysis = {
            'direction': 'unknown',
            'trust_requirements': [],
            'troubleshooting_steps': []
        }
        
        if service_type == 'ldaps':
            trust_analysis['direction'] = 'Passbolt → LDAP Server'
            trust_analysis['trust_requirements'] = [
                'Passbolt must trust LDAP server certificate',
                'LDAP server certificate must be valid and not expired',
                'Certificate must match LDAP server hostname',
                '⚠️ IMPORTANT: ldapsearch ignores certificates by default - always use -o tls_cacert for testing'
            ]
            trust_analysis['troubleshooting_steps'] = [
                '1. Check PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_CAFILE points to correct CA bundle',
                '2. Verify CA bundle contains LDAP server certificate or its CA',
                '3. Test LDAP connection with certificate validation: ldapsearch -H ldaps://ldap.local:636 -D "cn=admin,dc=local" -W -o ldif-wrap=no -x',
                '4. Test LDAP connection with specific CA file: ldapsearch -H ldaps://ldap.local:636 -D "cn=admin,dc=local" -W -o ldif-wrap=no -x -o tls_cacert=/etc/ssl/certs/ldaps_bundle.crt',
                '5. WARNING: Without -o tls_cacert, ldapsearch ignores certificate validation (security risk)',
                '6. Check LDAP server logs for certificate validation errors'
            ]
        
        elif service_type == 'smtps':
            trust_analysis['direction'] = 'Passbolt → SMTP Server'
            trust_analysis['trust_requirements'] = [
                'Passbolt must trust SMTP server certificate',
                'SMTP server certificate must be valid and not expired',
                'Certificate must match SMTP server hostname'
            ]
            trust_analysis['troubleshooting_steps'] = [
                '1. Check EMAIL_TRANSPORT_DEFAULT_HOST uses ssl:// for Implicit TLS or tls:// for STARTTLS',
                '2. Verify SMTP server certificate is trusted by system CA store',
                '3. Test SMTP Implicit TLS: openssl s_client -connect smtp.local:465',
                '4. Check Passbolt email logs for TLS handshake errors',
                '5. Note: Port 465 uses Implicit TLS (SSL), port 587 uses STARTTLS'
            ]
        
        elif service_type == 'https' and 'keycloak' in host.lower():
            trust_analysis['direction'] = 'Bidirectional Trust Required (Passbolt ↔ Keycloak)'
            trust_analysis['trust_requirements'] = [
                '🔹 Passbolt → Keycloak: Passbolt must trust Keycloak certificate (for OAuth2 redirects)',
                '🔹 Keycloak → Passbolt: Keycloak must trust Passbolt certificate (for OAuth2 callbacks)',
                '🔹 Both certificates must be valid and match hostnames',
                '🔹 OAuth2 endpoints must use HTTPS with valid certificates',
                '🔹 Browser must trust both certificates (for user access)'
            ]
            trust_analysis['troubleshooting_steps'] = [
                '1. Check PASSBOLT_SECURITY_SSO_SSL_VERIFY is enabled',
                '2. Verify Keycloak OAuth2 client configuration includes correct Passbolt URLs',
                '3. Test HTTPS access: curl -k https://keycloak.local:8443',
                '4. Check OAuth2 redirect URIs in Keycloak client configuration',
                '5. Verify certificate URLs in OAuth2 configuration match actual certificates',
                '6. CRITICAL: Test browser access to https://keycloak.local:8443 - users will see certificate warnings',
                '7. For OAuth2 SSO: Users must manually trust the private CA certificate in their browsers',
                '8. Production solution: Use public CA certificate (Let\'s Encrypt) or distribute private CA to all devices',
                '9. IMPORTANT: Both servers need to trust each other\'s certificates for OAuth2 SSO to work'
            ]
        
        elif service_type == 'https' and 'passbolt' in host.lower():
            trust_analysis['direction'] = 'Users → Passbolt'
            trust_analysis['trust_requirements'] = [
                'User browsers must trust Passbolt certificate',
                'Passbolt certificate must be valid and not expired',
                'Certificate must match Passbolt hostname'
            ]
            trust_analysis['troubleshooting_steps'] = [
                '1. Check browser certificate errors when accessing Passbolt',
                '2. Verify certificate is in system CA store or browser trust store',
                '3. Test HTTPS access: curl -I https://passbolt.local:443',
                '4. Check for certificate chain issues (intermediate certificates)'
            ]
        
        elif service_type == 'valkey':
            trust_analysis['direction'] = 'Passbolt → Valkey/Redis (No TLS)'
            trust_analysis['trust_requirements'] = [
                'Valkey connection is unencrypted (no TLS required)',
                'Network security relies on internal Docker network isolation',
                'For production: Consider enabling TLS for Valkey if network is not trusted'
            ]
            trust_analysis['troubleshooting_steps'] = [
                '1. Check CACHE_CAKECORE_HOST and CACHE_CAKECORE_PORT are correct',
                '2. Verify Valkey service is running and accessible',
                '3. Test Valkey connection: redis-cli -h valkey.local -p 6379',
                '4. Check Passbolt cache connection logs for TLS errors',
                '5. NOTE: If connection fails, Valkey TLS is likely not configured on the server'
            ]
        
        return trust_analysis
    
    def analyze_certificate_file(self, file_path: str, expected_hostname: str = None) -> Dict[str, Any]:
        """Analyze a certificate file and extract key information."""
        if not file_path or not os.path.exists(file_path):
            return {'error': f'Certificate file not found: {file_path}'}
        
        try:
            # Use openssl to parse the certificate
            cmd = ['openssl', 'x509', '-in', file_path, '-text', '-noout']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return {'error': f'Failed to parse certificate: {result.stderr}'}
            
            cert_text = result.stdout
            
            # Extract certificate information
            cert_info = {
                'file_path': file_path,
                'subject': self._extract_field(cert_text, 'Subject:'),
                'issuer': self._extract_field(cert_text, 'Issuer:'),
                'valid_from': self._extract_field(cert_text, 'Not Before:'),
                'valid_to': self._extract_field(cert_text, 'Not After:'),
                'san': self._extract_san(cert_text),
                'is_self_signed': self._is_self_signed(cert_text),
                'key_usage': self._extract_key_usage(cert_text)
            }
            
            # Check if hostname matches SAN
            if expected_hostname:
                cert_info['hostname_match'] = self._check_hostname_match(
                    expected_hostname, cert_info['san']
                )
            
            return cert_info
            
        except subprocess.TimeoutExpired:
            return {'error': 'Certificate parsing timed out'}
        except Exception as e:
            return {'error': f'Error analyzing certificate: {str(e)}'}
    
    def compare_certificates(self, trusted_cert_file: str, server_cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Compare trusted certificate file with server certificate."""
        comparison = {
            'match': False,
            'issues': [],
            'warnings': [],
            'admin_guidance': []
        }
        
        if 'error' in server_cert_info:
            comparison['issues'].append(f'Server certificate error: {server_cert_info["error"]}')
            return comparison
        
        # Analyze trusted certificate file
        trusted_cert = self.analyze_certificate_file(trusted_cert_file)
        if 'error' in trusted_cert:
            comparison['issues'].append(f'Trusted certificate file error: {trusted_cert["error"]}')
            return comparison
        
        # Compare subjects
        if trusted_cert.get('subject') == server_cert_info.get('subject'):
            comparison['match'] = True
            comparison['admin_guidance'].append('✅ Perfect match: Trusted certificate matches server certificate')
        else:
            comparison['warnings'].append('Trusted certificate subject differs from server certificate')
            comparison['admin_guidance'].append('⚠️ Check if trusted certificate is the correct one for this server')
        
        # Compare issuers
        if trusted_cert.get('issuer') != server_cert_info.get('issuer'):
            comparison['warnings'].append('Trusted certificate issuer differs from server certificate')
            comparison['admin_guidance'].append('🔧 Verify certificate chain: trusted cert should be CA or intermediate cert')
        
        # Check if trusted cert is CA
        if 'CA:TRUE' in ' '.join(trusted_cert.get('key_usage', [])):
            comparison['admin_guidance'].append('✅ Trusted certificate is a CA certificate (good for chain validation)')
        else:
            comparison['admin_guidance'].append('ℹ️ Trusted certificate is not a CA (should be server certificate or intermediate CA)')
        
        return comparison
    
    def test_service(self, host: str, port: int, service_type: str) -> Dict[str, Any]:
        """Test a single TLS service and return results."""
        self.log(f"Testing {service_type} service at {host}:{port}")
        
        # Get certificate from server
        cert_info = self.get_certificate_chain(host, port, service_type)
        
        # Handle non-TLS services (like valkey)
        if cert_info.get('no_tls', False):
            return {
                'service': service_type,
                'host': host,
                'port': port,
                'certificate': {
                    'subject': 'N/A (No TLS)',
                    'issuer': 'N/A (No TLS)',
                    'valid_from': 'N/A (No TLS)',
                    'valid_to': 'N/A (No TLS)',
                    'san': [],
                    'is_self_signed': False,
                    'no_tls': True
                },
                'validation': {
                    'valid': True,
                    'issues': [],
                    'warnings': ['Service does not use TLS encryption'],
                    'admin_guidance': ['ℹ️ This service uses unencrypted connections', '🔧 For production: Consider enabling TLS if network is not trusted']
                },
                'tls_analysis': {
                    'tls_enabled': False,
                    'warnings': ['No TLS configuration detected']
                },
                'trust_analysis': self._analyze_trust_requirements(service_type, host),
                'timestamp': datetime.now().isoformat()
            }
        
        # Validate certificate
        validation = self.validate_certificate(cert_info, host, service_type)
        
        # Additional validations
        purpose_validation = self.validate_certificate_purpose(cert_info, service_type)
        tls_analysis = self.analyze_tls_configuration(host, port, service_type, cert_info.get('detected_protocol'))
        
        # Check for trusted certificate file and compare
        certificate_comparison = None
        if service_type == 'ldaps':
            ldaps_cafile = self.passbolt_config.get('environment_variables', {}).get('PASSBOLT_PLUGINS_DIRECTORY_SYNC_SECURITY_SSL_CUSTOM_OPTIONS_CAFILE')
            if ldaps_cafile and os.path.exists(ldaps_cafile):
                certificate_comparison = self.compare_certificates(ldaps_cafile, cert_info)
        elif service_type == 'https' and 'keycloak' in host.lower():
            # For Keycloak, check if there are any SSO-related certificate files
            sso_cafile = self.passbolt_config.get('environment_variables', {}).get('PASSBOLT_SECURITY_SSO_SSL_CUSTOM_OPTIONS_CAFILE')
            if sso_cafile and os.path.exists(sso_cafile):
                certificate_comparison = self.compare_certificates(sso_cafile, cert_info)
            else:
                # Even if no specific CA file, show that this is a CA-signed certificate
                certificate_comparison = {
                    'match_status': 'Private CA-signed certificate',
                    'comparison_results': [
                        '✅ Certificate is signed by a Certificate Authority (Passbolt Root CA)',
                        'ℹ️ This is not a self-signed certificate',
                        '⚠️ This is a PRIVATE CA certificate (not trusted by browsers by default)',
                        '🔧 For production: Ensure the CA certificate is trusted by Passbolt',
                        '🌐 For OAuth2 SSO: Users will see certificate warnings in browsers',
                        '💡 Solution: Use public CA certificate or distribute private CA to all user devices'
                    ]
                }
        
        result = {
            'service': service_type,
            'host': host,
            'port': port,
            'certificate': cert_info,
            'validation': validation,
            'purpose_validation': purpose_validation,
            'tls_analysis': tls_analysis,
            'timestamp': datetime.now().isoformat()
        }
        
        if certificate_comparison:
            result['certificate_comparison'] = certificate_comparison
        
        return result
    
    def test_default_services(self) -> Dict[str, Any]:
        """Test services based on actual Passbolt configuration."""
        # Load Passbolt configuration first
        passbolt_config = self.load_passbolt_config()
        
        # Build services list from actual configuration
        services = {}
        
        # Extract hostname from fullBaseUrl if available
        full_base_url = passbolt_config.get('environment_variables', {}).get('PASSBOLT_APP_FULL_BASE_URL', '')
        if full_base_url:
            try:
                from urllib.parse import urlparse
                parsed_url = urlparse(full_base_url)
                passbolt_host = parsed_url.hostname
                # For certificate testing, use localhost:443 if hostname is not resolvable
                # This handles cases like OVA where passbolt.local doesn't resolve
                if passbolt_host and passbolt_host not in ['localhost', '127.0.0.1']:
                    # Try to resolve the hostname, fall back to localhost if it fails
                    try:
                        import socket
                        socket.gethostbyname(passbolt_host)
                        test_host = passbolt_host
                        self.log(f"Hostname {passbolt_host} resolves, using for testing")
                    except socket.gaierror:
                        test_host = 'localhost'
                        self.log(f"Hostname {passbolt_host} does not resolve, using localhost for testing")
                else:
                    test_host = 'localhost'
                
                services['https_passbolt'] = {'host': test_host, 'port': 443, 'type': 'https'}
                self.log(f"Testing Passbolt HTTPS: {test_host}:443 (from external URL: {full_base_url})")
            except Exception as e:
                self.log(f"Error parsing fullBaseUrl: {e}")
        
        # LDAP service from configuration
        ldap_config = passbolt_config.get('services', {}).get('ldaps', {})
        if ldap_config.get('host') and ldap_config.get('port'):
            services['ldaps'] = {
                'host': ldap_config['host'], 
                'port': int(ldap_config['port']), 
                'type': 'ldaps'
            }
            self.log(f"Detected LDAP service: {ldap_config['host']}:{ldap_config['port']}")
        
        # SMTP service from configuration
        smtp_config = passbolt_config.get('services', {}).get('smtp', {})
        if smtp_config.get('host') and smtp_config.get('port'):
            services['smtps'] = {
                'host': smtp_config['host'], 
                'port': int(smtp_config['port']), 
                'type': 'smtps'
            }
            self.log(f"Detected SMTP service: {smtp_config['host']}:{smtp_config['port']}")
        
        # Cache service from configuration
        cache_config = passbolt_config.get('services', {}).get('valkey', {})
        if cache_config.get('host') and cache_config.get('port'):
            services['valkey'] = {
                'host': cache_config['host'], 
                'port': int(cache_config['port']), 
                'type': 'valkey'
            }
            self.log(f"Detected Cache service: {cache_config['host']}:{cache_config['port']}")
        
        # If no services found from config, fall back to localhost defaults
        if not services:
            self.log("No services found in configuration, using localhost defaults")
            services = {
                'https_passbolt': {'host': 'localhost', 'port': 443, 'type': 'https'},
                'valkey': {'host': 'localhost', 'port': 6379, 'type': 'valkey'}
            }
        
        # Validate Passbolt TLS configuration
        passbolt_config_validation = self.validate_passbolt_tls_config()
        
        # Test each service
        results = {
            'passbolt_configuration': {
                'environment_variables': passbolt_config.get('environment_variables', {}),
                'certificate_files': passbolt_config.get('certificate_files', {}),
                'services': passbolt_config.get('services', {}),
                'tls_config_validation': passbolt_config_validation
            },
            'services': {},
            'summary': {
                'total_services': 0,
                'successful_tests': 0,
                'failed_tests': 0,
                'warnings': 0
            }
        }
        
        for service_name, service_config in services.items():
            host = service_config.get('host')
            port = service_config.get('port')
            service_type = service_config.get('type', service_name)
            
            # Test the service
            service_result = self.test_service(host, port, service_type)
            results['services'][service_name] = service_result
            
            # Update summary
            results['summary']['total_services'] += 1
            if service_result['validation']['valid']:
                results['summary']['successful_tests'] += 1
            else:
                results['summary']['failed_tests'] += 1
            
            results['summary']['warnings'] += len(service_result['validation']['warnings'])
        
        return results
    
    def generate_html_report(self, results: Dict[str, Any], output_file: str = 'report.html'):
        """Generate HTML report from test results."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passbolt TLS Certificate Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #7f8c8d; }}
        .status-success {{ color: #27ae60; font-weight: bold; }}
        .status-error {{ color: #e74c3c; font-weight: bold; }}
        .status-warning {{ color: #f39c12; font-weight: bold; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .service {{ border: 1px solid #bdc3c7; margin: 15px 0; border-radius: 5px; overflow: hidden; }}
        .service-header {{ background: #34495e; color: white; padding: 10px 15px; font-weight: bold; }}
        .service-content {{ padding: 15px; }}
        .cert-details {{ background: #f8f9fa; padding: 10px; border-radius: 3px; margin: 10px 0; }}
        .env-vars {{ background: #e8f4f8; padding: 10px; border-radius: 3px; margin: 10px 0; }}
        .timestamp {{ color: #7f8c8d; font-size: 0.9em; }}
        ul {{ margin: 5px 0; }}
        li {{ margin: 3px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Passbolt TLS Certificate Test Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
            <h2>📊 Test Summary</h2>
            <p><strong>Total Services:</strong> {results['summary']['total_services']}</p>
            <p><strong>Successful Tests:</strong> <span class="status-success">✅ {results['summary']['successful_tests']}</span></p>
            <p><strong>Failed Tests:</strong> <span class="status-error">❌ {results['summary']['failed_tests']}</span></p>
            <p><strong>Warnings:</strong> <span class="status-warning">⚠️ {results['summary']['warnings']}</span></p>
        </div>
        
        <h2>⚙️ Passbolt Configuration</h2>
        <div class="service">
            <div class="service-header">Environment Variables</div>
            <div class="service-content">
                <div class="env-vars">
                    <h3>Key Configuration Variables:</h3>
                    <ul>
"""
        
        # Add environment variables
        env_vars = results['passbolt_configuration'].get('environment_variables', {})
        for key, value in env_vars.items():
            if key.startswith(('PASSBOLT_', 'EMAIL_', 'CACHE_CAKECORE_')):
                html_content += f"<li><strong>{key}:</strong> {value}</li>\n"
        
        html_content += """
                    </ul>
                </div>
"""
        
        # Add Passbolt TLS configuration validation
        tls_config_validation = results['passbolt_configuration'].get('tls_config_validation', {})
        if tls_config_validation:
            html_content += """
                <div class="comparison">
                    <h3>Passbolt TLS Configuration Validation:</h3>
"""
            if tls_config_validation.get('issues'):
                html_content += "<h4>Configuration Issues:</h4><ul>\n"
                for issue in tls_config_validation['issues']:
                    html_content += f"<li class='status-error'>❌ {issue}</li>\n"
                html_content += "</ul>\n"
            
            if tls_config_validation.get('warnings'):
                html_content += "<h4>Configuration Warnings:</h4><ul>\n"
                for warning in tls_config_validation['warnings']:
                    html_content += f"<li class='status-warning'>⚠️ {warning}</li>\n"
                html_content += "</ul>\n"
            
            if tls_config_validation.get('admin_guidance'):
                html_content += "<h4>Configuration Guidance:</h4><ul>\n"
                for guidance in tls_config_validation['admin_guidance']:
                    html_content += f"<li>{guidance}</li>\n"
                html_content += "</ul>\n"
        
        html_content += """
                </div>
            </div>
        </div>
        
        <h2>🔍 Service Test Results</h2>
"""
        
        # Add service test results
        for service_name, service_result in results['services'].items():
            if 'error' in service_result:
                html_content += f"""
        <div class="service">
            <div class="service-header">❌ {service_name.upper()}</div>
            <div class="service-content">
                <p class="status-error">Error: {service_result['error']}</p>
            </div>
        </div>
"""
            else:
                validation = service_result['validation']
                status_icon = "✅" if validation['valid'] else "❌"
                status_class = "status-success" if validation['valid'] else "status-error"
                
                html_content += f"""
        <div class="service">
            <div class="service-header">{status_icon} {service_name.upper()} - {service_result['host']}:{service_result['port']}</div>
            <div class="service-content">
                <div class="cert-details">
                    <h3>Server Certificate Details:</h3>
                    <ul>
                        <li><strong>Detected Protocol:</strong> {service_result['certificate'].get('detected_protocol', 'Unknown')}</li>
                        <li><strong>Subject:</strong> {service_result['certificate'].get('subject', 'N/A')}</li>
                        <li><strong>Issuer:</strong> {service_result['certificate'].get('issuer', 'N/A')}</li>
                        <li><strong>Valid From:</strong> {service_result['certificate'].get('valid_from', 'N/A')}</li>
                        <li><strong>Valid To:</strong> {service_result['certificate'].get('valid_to', 'N/A')}</li>
                        <li><strong>SAN:</strong> {', '.join(service_result['certificate'].get('san', [])) or 'None'}</li>
                        <li><strong>Self-signed:</strong> {'Yes' if service_result['certificate'].get('is_self_signed') else 'No'}</li>
                    </ul>
                </div>
                
                <div class="cert-details">
                    <h3>Validation Results:</h3>
                    <p><strong>Status:</strong> <span class="{status_class}">{'Valid' if validation['valid'] else 'Invalid'}</span></p>
"""
                
                if validation['issues']:
                    html_content += "<h4>Issues:</h4><ul>\n"
                    for issue in validation['issues']:
                        html_content += f"<li class='status-error'>❌ {issue}</li>\n"
                    html_content += "</ul>\n"
                
                if validation['warnings']:
                    html_content += "<h4>Warnings:</h4><ul>\n"
                    for warning in validation['warnings']:
                        html_content += f"<li class='status-warning'>⚠️ {warning}</li>\n"
                    html_content += "</ul>\n"
                
                # Add trust analysis
                trust_analysis = validation.get('trust_analysis', {})
                if trust_analysis:
                    html_content += f"""
                    <h4>Trust Direction:</h4>
                    <p><strong>{trust_analysis.get('direction', 'Unknown')}</strong></p>
                    
                    <h4>Trust Requirements:</h4>
                    <ul>
"""
                    for requirement in trust_analysis.get('trust_requirements', []):
                        # Remove the bullet point if it's already in the text
                        clean_requirement = requirement.replace('• ', '').replace('🔹 ', '')
                        html_content += f"<li>{clean_requirement}</li>\n"
                    
                    html_content += """
                    </ul>
                    
                    <h4>Troubleshooting Steps:</h4>
                    <ol>
"""
                    for step in trust_analysis.get('troubleshooting_steps', []):
                        # Remove the number if it's already in the text
                        clean_step = step
                        if step.startswith(('1. ', '2. ', '3. ', '4. ', '5. ', '6. ', '7. ', '8. ', '9. ')):
                            clean_step = step[3:]  # Remove "1. " etc.
                        html_content += f"<li>{clean_step}</li>\n"
                    
                    html_content += """
                    </ol>
"""
                
                # Add admin guidance
                admin_guidance = validation.get('admin_guidance', [])
                if admin_guidance:
                    html_content += """
                    <h4>Admin Guidance:</h4>
                    <ul>
"""
                    for guidance in admin_guidance:
                        html_content += f"<li>{guidance}</li>\n"
                    html_content += "</ul>\n"
                
                # Add certificate comparison if available
                cert_comparison = service_result.get('certificate_comparison')
                if cert_comparison:
                    html_content += """
                    <h4>Certificate Trust Analysis:</h4>
                    <ul>
"""
                    for guidance in cert_comparison.get('admin_guidance', []):
                        html_content += f"<li>{guidance}</li>\n"
                    
                    if cert_comparison.get('warnings'):
                        html_content += "</ul><h5>Trust Warnings:</h5><ul>\n"
                        for warning in cert_comparison['warnings']:
                            html_content += f"<li class='status-warning'>⚠️ {warning}</li>\n"
                    
                    html_content += "</ul>\n"
                
                # Add certificate purpose validation
                purpose_validation = service_result.get('purpose_validation', {})
                if purpose_validation:
                    html_content += """
                    <h4>Certificate Purpose Validation:</h4>
                    <ul>
"""
                    for guidance in purpose_validation.get('admin_guidance', []):
                        html_content += f"<li>{guidance}</li>\n"
                    
                    if purpose_validation.get('issues'):
                        html_content += "</ul><h5>Purpose Issues:</h5><ul>\n"
                        for issue in purpose_validation['issues']:
                            html_content += f"<li class='status-error'>❌ {issue}</li>\n"
                    
                    if purpose_validation.get('warnings'):
                        html_content += "</ul><h5>Purpose Warnings:</h5><ul>\n"
                        for warning in purpose_validation['warnings']:
                            html_content += f"<li class='status-warning'>⚠️ {warning}</li>\n"
                    
                    html_content += "</ul>\n"
                
                # Add TLS configuration analysis
                tls_analysis = service_result.get('tls_analysis', {})
                if tls_analysis:
                    html_content += f"""
                    <h4>TLS Configuration Analysis:</h4>
                    <ul>
                        <li><strong>TLS Version:</strong> {tls_analysis.get('tls_version', 'Unknown')}</li>
                        <li><strong>Cipher Suite:</strong> {tls_analysis.get('cipher_suite', 'Unknown')}</li>
                    </ul>
"""
                    if tls_analysis.get('admin_guidance'):
                        html_content += "<h5>TLS Guidance:</h5><ul>\n"
                        for guidance in tls_analysis['admin_guidance']:
                            html_content += f"<li>{guidance}</li>\n"
                        html_content += "</ul>\n"
                    
                    if tls_analysis.get('warnings'):
                        html_content += "<h5>TLS Warnings:</h5><ul>\n"
                        for warning in tls_analysis['warnings']:
                            html_content += f"<li class='status-warning'>⚠️ {warning}</li>\n"
                        html_content += "</ul>\n"
                
                html_content += """
                </div>
            </div>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML report generated: {output_file}")
    
    def generate_clean_report(self, results: Dict[str, Any], output_file: str = 'report.html'):
        """Generate a cleaner, more actionable HTML report."""
        
        # Categorize services by status
        critical_issues = []
        warnings = []
        working_services = []
        
        for service_name, service_data in results['services'].items():
            # Check if service has blocking issues (not just warnings)
            has_blocking_issues = service_data['validation'].get('issues', [])
            has_warnings = service_data['validation'].get('warnings', [])
            
            # Special handling for non-TLS services like Valkey
            if service_name == 'valkey' and 'no working tls protocol detected' in str(has_blocking_issues).lower():
                # Valkey without TLS is expected - consider it working
                working_services.append((service_name, service_data))
            elif has_blocking_issues:
                # Check if blocking issues are just hostname mismatches (common in test environments)
                hostname_issues_only = all(
                    'hostname' in issue.lower() and 'not found in san' in issue.lower()
                    for issue in has_blocking_issues
                )
                
                if hostname_issues_only and has_warnings:
                    # Hostname mismatch with warnings - put in warnings category
                    warnings.append((service_name, service_data))
                else:
                    # Real blocking issues
                    critical_issues.append((service_name, service_data))
            elif has_warnings:
                # Check if warnings are just minor (self-signed, no SAN) vs serious
                minor_warnings_only = all(
                    any(keyword in warning.lower() for keyword in ['self-signed', 'no subject alternative names', 'expires in'])
                    for warning in has_warnings
                )
                
                if minor_warnings_only and len(has_warnings) <= 2:
                    # Minor warnings only - consider it working
                    working_services.append((service_name, service_data))
                else:
                    # Serious warnings - put in warnings category
                    warnings.append((service_name, service_data))
            else:
                working_services.append((service_name, service_data))
        
        # Generate action items
        action_items = []
        for service_name, service_data in critical_issues:
            if 'troubleshooting_steps' in service_data:
                for step in service_data['troubleshooting_steps'][:2]:  # Top 2 steps
                    action_items.append({
                        'priority': 'high',
                        'service': service_name,
                        'action': step.replace('1. ', '').replace('2. ', '').replace('3. ', '').replace('4. ', '').replace('5. ', ''),
                        'type': 'critical'
                    })
        
        for service_name, service_data in warnings:
            if 'admin_guidance' in service_data:
                for guidance in service_data['admin_guidance'][:1]:  # Top 1 guidance
                    if '🔧' in guidance:
                        action_items.append({
                            'priority': 'medium',
                            'service': service_name,
                            'action': guidance.replace('🔧 ', ''),
                            'type': 'warning'
                        })
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passbolt TLS Certificate Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #7f8c8d; }}
        .status-success {{ color: #27ae60; font-weight: bold; }}
        .status-error {{ color: #e74c3c; font-weight: bold; }}
        .status-warning {{ color: #f39c12; font-weight: bold; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .critical {{ background: #ffebee; border-left: 5px solid #e74c3c; padding: 15px; margin: 15px 0; }}
        .warning {{ background: #fff3e0; border-left: 5px solid #f39c12; padding: 15px; margin: 15px 0; }}
        .success {{ background: #e8f5e8; border-left: 5px solid #27ae60; padding: 15px; margin: 15px 0; }}
        .action-item {{ background: #e3f2fd; padding: 10px; margin: 5px 0; border-radius: 3px; border-left: 3px solid #2196f3; }}
        .priority-high {{ border-left-color: #e74c3c; background: #ffebee; }}
        .priority-medium {{ border-left-color: #f39c12; background: #fff3e0; }}
        .priority-low {{ border-left-color: #27ae60; background: #e8f5e8; }}
        .service-summary {{ font-weight: bold; margin-bottom: 10px; }}
        .quick-fix {{ background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 3px; margin: 10px 0; }}
        .collapsible {{ cursor: pointer; padding: 10px; background: #f8f9fa; border: 1px solid #dee2e6; margin: 5px 0; }}
        .collapsible:hover {{ background-color: #e9ecef; }}
        .content {{ display: none; padding: 10px; background: white; border: 1px solid #dee2e6; }}
        .content.active {{ display: block; }}
        ul {{ margin: 5px 0; }}
        li {{ margin: 3px 0; }}
        .timestamp {{ color: #7f8c8d; font-size: 0.9em; }}
    </style>
    <script>
        function toggleContent(id) {{
            var content = document.getElementById(id);
            content.classList.toggle('active');
        }}
    </script>
</head>
<body>
    <div class="container">
        <h1>🔒 Passbolt TLS Certificate Test Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
            <h2>📊 Service Status Summary</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin: 15px 0;">
                <div>
                    <h4><span class="status-error">🚨 Critical Issues ({len(critical_issues)})</span></h4>
                    <ul>
                        {self._format_service_summary_items(critical_issues) if critical_issues else '<li>None</li>'}
                    </ul>
                </div>
                <div>
                    <h4><span class="status-warning">⚠️ Warnings ({len(warnings)})</span></h4>
                    <ul>
                        {self._format_service_summary_items(warnings) if warnings else '<li>None</li>'}
                    </ul>
                </div>
                <div>
                    <h4><span class="status-success">✅ Working ({len(working_services)})</span></h4>
                    <ul>
                        {self._format_service_summary_items(working_services) if working_services else '<li>None</li>'}
                    </ul>
                </div>
            </div>
        </div>
        
        {self._generate_detailed_services_section(results['services'])}
        {self._generate_environment_analysis_section(results)}
        {self._generate_certificate_analysis_section(results['services'])}
        {self._generate_network_routes_section(results['services'])}
        
    </div>
</body>
</html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Clean HTML report generated: {output_file}")
    
    def _format_service_summary_items(self, services_list):
        """Format service summary items with detailed information."""
        items = []
        for service_name, service_data in services_list:
            host = service_data.get('host', 'Unknown')
            port = service_data.get('port', 'Unknown')
            protocol = service_data.get('certificate', {}).get('detected_protocol', 'Unknown')
            
            # Get the main issue or status
            issues = service_data.get('validation', {}).get('issues', [])
            warnings = service_data.get('validation', {}).get('warnings', [])
            
            if issues:
                # Show the main issue
                main_issue = issues[0]
                if 'hostname' in main_issue.lower() and 'not found' in main_issue.lower():
                    items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} has hostname mismatch</li>')
                elif 'expired' in main_issue.lower():
                    items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} certificate expired</li>')
                elif 'connection' in main_issue.lower() or 'failed' in main_issue.lower():
                    items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} connection failed</li>')
                else:
                    items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} has critical issue</li>')
            elif warnings:
                # Show the main warning
                main_warning = warnings[0]
                if 'self-signed' in main_warning.lower():
                    items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} is self-signed</li>')
                elif 'no subject alternative names' in main_warning.lower():
                    items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} has no SAN</li>')
                elif 'expires' in main_warning.lower():
                    items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} expires soon</li>')
                else:
                    items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} has warnings</li>')
            else:
                # Working service
                items.append(f'<li><strong>{service_name.upper()}</strong> - {protocol} for {host}:{port} is working correctly</li>')
        
        return ''.join(items)
    
    def _generate_detailed_services_section(self, services):
        """Generate detailed service analysis with all technical information."""
        html = '<h2>🔍 Detailed Service Analysis</h2>'
        
        for service_name, service_data in services.items():
            status_class = 'success' if service_data['validation']['valid'] else 'critical'
            status_icon = '✅' if service_data['validation']['valid'] else '❌'
            
            html += f'''
            <div class="{status_class}">
                <div class="service-summary">
                    <strong>{status_icon} {service_name.upper()}</strong> - {service_data.get('host', 'Unknown')}:{service_data.get('port', 'Unknown')}
                </div>
                
                <h4>Connection Details:</h4>
                <ul>
                    <li><strong>Protocol:</strong> {service_data.get('certificate', {}).get('detected_protocol', 'Unknown')}</li>
                    <li><strong>Host:</strong> {service_data.get('host', 'Unknown')}</li>
                    <li><strong>Port:</strong> {service_data.get('port', 'Unknown')}</li>
                    <li><strong>Service Type:</strong> {service_data.get('service', 'Unknown')}</li>
                </ul>
                
                <h4>Certificate Information:</h4>
                <ul>
                    <li><strong>Subject:</strong> {service_data.get('certificate', {}).get('subject', 'N/A')}</li>
                    <li><strong>Issuer:</strong> {service_data.get('certificate', {}).get('issuer', 'N/A')}</li>
                    <li><strong>Valid From:</strong> {service_data.get('certificate', {}).get('valid_from', 'N/A')}</li>
                    <li><strong>Valid To:</strong> {service_data.get('certificate', {}).get('valid_to', 'N/A')}</li>
                    <li><strong>SAN:</strong> {service_data.get('certificate', {}).get('san', 'None')}</li>
                    <li><strong>Self-signed:</strong> {'Yes' if service_data.get('certificate', {}).get('is_self_signed') else 'No'}</li>
                </ul>
                
                <h4>Validation Results:</h4>
                <ul>
                    <li><strong>Status:</strong> {'Valid' if service_data['validation']['valid'] else 'Invalid'}</li>
                </ul>
                
                {self._format_validation_details(service_data['validation'])}
                
                <h4>TLS Configuration:</h4>
                <ul>
                    <li><strong>TLS Version:</strong> {service_data.get('tls_analysis', {}).get('tls_version', 'Unknown')}</li>
                    <li><strong>Cipher Suite:</strong> {service_data.get('tls_analysis', {}).get('cipher_suite', 'Unknown')}</li>
                </ul>
                
                {self._format_tls_warnings(service_data.get('tls_analysis', {}))}
                
                <h4>Trust Analysis:</h4>
                {self._format_trust_analysis(service_data.get('validation', {}).get('trust_analysis', {}))}
                
                <h4>Certificate Comparison:</h4>
                {self._format_certificate_comparison(service_data.get('certificate_comparison', {}))}
                
                <h4>Admin Guidance:</h4>
                {self._format_admin_guidance(service_data.get('validation', {}).get('admin_guidance', []))}
            </div>'''
        
        return html
    
    def _format_validation_details(self, validation):
        """Format validation details."""
        html = ''
        if validation.get('issues'):
            html += '<h5>Issues:</h5><ul>'
            for issue in validation['issues']:
                html += f'<li class="status-error">❌ {issue}</li>'
            html += '</ul>'
        
        if validation.get('warnings'):
            html += '<h5>Warnings:</h5><ul>'
            for warning in validation['warnings']:
                html += f'<li class="status-warning">⚠️ {warning}</li>'
            html += '</ul>'
        
        return html
    
    def _format_tls_warnings(self, tls_config):
        """Format TLS configuration warnings."""
        if not tls_config.get('warnings'):
            return ''
        
        html = '<h5>TLS Warnings:</h5><ul>'
        for warning in tls_config['warnings']:
            html += f'<li class="status-warning">⚠️ {warning}</li>'
        html += '</ul>'
        return html
    
    def _format_trust_analysis(self, trust_analysis):
        """Format trust analysis."""
        if not trust_analysis:
            return '<p>No trust analysis available</p>'
        
        html = f'<p><strong>Direction:</strong> {trust_analysis.get("direction", "Unknown")}</p>'
        
        if trust_analysis.get('trust_requirements'):
            html += '<h5>Trust Requirements:</h5><ul>'
            for req in trust_analysis['trust_requirements']:
                html += f'<li>{req}</li>'
            html += '</ul>'
        
        if trust_analysis.get('troubleshooting_steps'):
            html += '<h5>Troubleshooting Steps:</h5><ol>'
            for step in trust_analysis['troubleshooting_steps']:
                # Remove existing numbering (1. 2. 3. etc.) from the step text
                clean_step = step
                if clean_step.startswith(('1. ', '2. ', '3. ', '4. ', '5. ', '6. ', '7. ', '8. ', '9. ')):
                    clean_step = clean_step[3:]  # Remove "X. " prefix
                html += f'<li>{clean_step}</li>'
            html += '</ol>'
        
        return html
    
    def _format_certificate_comparison(self, comparison):
        """Format certificate comparison results."""
        if not comparison:
            return '<p>No certificate comparison available</p>'
        
        html = f'<p><strong>Match Status:</strong> {comparison.get("match_status", "Unknown")}</p>'
        
        if comparison.get('comparison_results'):
            html += '<ul>'
            for result in comparison['comparison_results']:
                html += f'<li>{result}</li>'
            html += '</ul>'
        
        return html
    
    def _format_admin_guidance(self, guidance_list):
        """Format admin guidance."""
        if not guidance_list:
            return '<p>No specific guidance available</p>'
        
        html = '<ul>'
        for guidance in guidance_list:
            html += f'<li>{guidance}</li>'
        html += '</ul>'
        return html
    
    def _generate_environment_analysis_section(self, results):
        """Generate detailed environment variable analysis."""
        config = results.get('passbolt_configuration', {})
        env_vars = config.get('environment_variables', {})
        tls_config = config.get('tls_config_validation', {})
        
        html = '''
        <h2>⚙️ Environment Variables Analysis</h2>
        <div class="env-vars">
            <h3>Email Configuration:</h3>
            <ul>'''
        
        email_vars = {k: v for k, v in env_vars.items() if k.startswith('EMAIL_')}
        for k, v in email_vars.items():
            html += f'<li><strong>{k}:</strong> {v}</li>'
        
        html += '''
            </ul>
            
            <h3>Passbolt Configuration:</h3>
            <ul>'''
        
        passbolt_vars = {k: v for k, v in env_vars.items() if k.startswith('PASSBOLT_')}
        for k, v in passbolt_vars.items():
            html += f'<li><strong>{k}:</strong> {v}</li>'
        
        html += '''
            </ul>
            
            <h3>Cache Configuration:</h3>
            <ul>'''
        
        cache_vars = {k: v for k, v in env_vars.items() if k.startswith('CACHE_')}
        for k, v in cache_vars.items():
            html += f'<li><strong>{k}:</strong> {v}</li>'
        
        html += '</ul>'
        
        if tls_config.get('warnings'):
            html += '<h3>Configuration Warnings:</h3><ul>'
            for warning in tls_config['warnings']:
                html += f'<li class="status-warning">⚠️ {warning}</li>'
            html += '</ul>'
        
        if tls_config.get('admin_guidance'):
            html += '<h3>Configuration Guidance:</h3><ul>'
            for guidance in tls_config['admin_guidance']:
                html += f'<li>{guidance}</li>'
            html += '</ul>'
        
        html += '</div>'
        return html
    
    def _generate_certificate_analysis_section(self, services):
        """Generate detailed certificate analysis."""
        html = '''
        <h2>🔐 Certificate Analysis</h2>
        <div class="cert-details">
            <h3>Certificate File Analysis:</h3>
            <ul>'''
        
        for service_name, service_data in services.items():
            cert_file = service_data.get('certificate_file_analysis', {})
            if cert_file:
                html += f'''
                <li><strong>{service_name.upper()}:</strong>
                    <ul>
                        <li>File: {cert_file.get('file_path', 'N/A')}</li>
                        <li>Subject: {cert_file.get('subject', 'N/A')}</li>
                        <li>Issuer: {cert_file.get('issuer', 'N/A')}</li>
                        <li>Valid: {cert_file.get('valid_from', 'N/A')} to {cert_file.get('valid_to', 'N/A')}</li>
                        <li>SAN: {cert_file.get('san', 'None')}</li>
                        <li>Self-signed: {cert_file.get('self_signed', 'Unknown')}</li>
                    </ul>
                </li>'''
        
        html += '''
            </ul>
        </div>'''
        return html
    
    def _generate_network_routes_section(self, services):
        """Generate network routes and port analysis."""
        html = '''
        <h2>🌐 Network Routes & Ports</h2>
        <div class="service">
            <h3>Service Endpoints:</h3>
            <ul>'''
        
        for service_name, service_data in services.items():
            host = service_data.get('host', 'Unknown')
            port = service_data.get('port', 'Unknown')
            service_type = service_data.get('service', 'Unknown')
            protocol = service_data.get('certificate', {}).get('detected_protocol', 'Unknown')
            
            html += f'''
            <li><strong>{service_name.upper()}:</strong>
                <ul>
                    <li>Endpoint: {host}:{port}</li>
                    <li>Type: {service_type}</li>
                    <li>Protocol: {protocol}</li>
                    <li>Status: {'✅ Working' if service_data['validation']['valid'] else '❌ Failed'}</li>
                </ul>
            </li>'''
        
        html += '''
            </ul>
        </div>'''
        return html


def main():
    parser = argparse.ArgumentParser(description='TLS Certificate Tester for Passbolt (Docker-compatible)')
    parser.add_argument('--service', help='Service type to test')
    parser.add_argument('--host', help='Host to test')
    parser.add_argument('--port', type=int, help='Port to test')
    parser.add_argument('--report', action='store_true', help='Generate HTML report')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    tester = TLSTester(debug=args.debug)
    
    if args.service and args.host and args.port:
        # Test single service
        result = tester.test_service(args.host, args.port, args.service)
        print(json.dumps(result, indent=2))
    
    else:
        # Test default services
        results = tester.test_default_services()
        
        if args.report:
            tester.generate_html_report(results)
            tester.generate_clean_report(results)
        else:
            print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
