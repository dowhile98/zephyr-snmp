# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest stable release receives security updates.

## Reporting a Vulnerability

We take the security of this SNMP agent seriously. If you discover a
security vulnerability, please follow these steps:

### Do NOT

- Open a public GitHub issue
- Discuss the vulnerability in public forums
- Exploit the vulnerability beyond testing on your own device

### DO

1. **Reporting**: Open a private security advisory on GitHub under the repository's "Security > Advisories" tab, or email `security@daecge.com` with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

2. **Response**: We will acknowledge receipt within **48 hours**.

3. **Timeline**: We aim to provide a fix within **30 days** of validation.

4. **Disclosure**: We follow coordinated disclosure. Please allow us time
   to develop and distribute a fix before public disclosure.

## Known Security Considerations

### SNMPv1/v2c

- Community strings are transmitted in **plaintext** (no encryption)
- Community strings function as passwords but offer no cryptographic security
- Use SNMPv3 for any deployment where security matters

### SNMPv3

- **authNoPriv**: Provides authentication (integrity) but NOT confidentiality
- **authPriv**: Provides both authentication AND confidentiality (recommended)
- DES encryption is deprecated; prefer AES-128-CFB
- Engine boots/time persistence across reboots is recommended to prevent replay attacks

### General

- **Rate Limiting**: Configurable token-bucket rate limiting is available via `CONFIG_SNMP_RATE_LIMIT=y`. Enable this option to protect against UDP flood attacks and CPU exhaustion.
- MIB SET operations perform type validation and boundary checks in registered callbacks.
- Default community strings ("public"/"private") should be changed before deployment.
- Kconfig password values (`CONFIG_SNMP_V3_AUTH_PASS`) should be overridden at runtime or configured securely.

## Best Practices for Deployment

1. **Always use SNMPv3 authPriv** for production deployments
2. **Change default community strings** if using v1/v2c
3. **Persist engineBoots** across reboots (store in EEPROM/flash)
4. **Use strong passwords** (minimum 8 characters, mixed case, numbers)
5. **Restrict network access** to port 161 via firewall rules
6. **Monitor SNMP counters** for anomalies (`snmpInBadVersions`, `snmpInBadCommunityNames`, etc.)
7. **Disable unused SNMP versions** via Kconfig

## Security Audit History
 
| Date | Auditor | Scope | Result |
|------|---------|-------|--------|
| 2026-09 | Senior Open-Source Review | Full codebase | All critical vulnerabilities resolved (buffer overflows, stack exhaustion, thread safety, rate limiting) |

## Addressed Vulnerabilities

| Issue ID | Severity | Description | Fixed in |
|----------|----------|-------------|----------|
| SEC-01 | CRITICAL | Out-of-bounds write in scopedPDU encryption buffer | 1.0.0 |
| SEC-02 | HIGH | Thread stack exhaustion from deeply nested BER buffers | 1.0.0 |
| SEC-03 | MEDIUM | Race condition on global ASN.1 BER encoding buffers | 1.0.0 |
| SEC-04 | MEDIUM | IPv6 sockaddr truncation in socket service listener | 1.0.0 |
| SEC-05 | MEDIUM | Strict RFC 1157 SNMPv1 error mapping for missing MIB nodes | 1.0.0 |

