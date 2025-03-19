# SSL Certificate Monitoring Plugin for ChangeDetection.io

This plugin enables SSL certificate monitoring capabilities in [ChangeDetection.io](https://github.com/dgtlmoon/changedetection.io). It allows you to track and be notified about changes to SSL certificates, including expiration dates, security features, and configuration details.

## Features

The plugin checks for and reports changes to a comprehensive set of SSL certificate and security properties:

### Certificate Details
- Certificate version
- Serial number
- Signature algorithm
- Key type (RSA/ECDSA) and size
- Common Name (CN)
- Subject Alternative Names (SAN)
- Issuer information (organization, country)
- Certificate validity period and days remaining
- Certificate fingerprints (SHA-256, SHA-1)
- Key usage and extended key usage

### Security Analysis
- SSL grade (A-F rating based on security parameters)
- Weak key detection
- Self-signed certificate detection
- Browser trust level
- Wildcard certificate detection
- Certificate Transparency (CT) log presence
- Certificate revocation status (OCSP)
- Certificate chain validation
- Public key strength evaluation

### TLS Configuration
- TLS version support (TLS 1.0, 1.1, 1.2, 1.3)
- Forward secrecy support
- OCSP stapling support
- HTTP Strict Transport Security (HSTS) implementation
- TLS compression (CRIME vulnerability)
- TLS session resumption capability
- Server protocol support (HTTP/1.x, HTTP/2)
- Cipher strength and security

### Additional Security Checks
- DNS CAA records (Certificate Authority Authorization)
- Certificate chain completeness and validity
- Certificate Transparency SCT extension

## Usage

When creating a watch, select "SSL Certificate Information and Expiry Monitoring" as the processor. Enter the domain you want to monitor as the URL.

The plugin will automatically fetch the SSL certificate information and display it in a structured format. ChangeDetection.io will then track changes to this information over time, alerting you to any modifications.

This is particularly useful for:
- Monitoring certificate expiration
- Detecting unexpected certificate changes
- Tracking security improvements or regressions
- Ensuring compliance with security best practices

## Requirements

- changedetection.io >= 0.50.0

## License

This plugin is released under the same license as ChangeDetection.io


