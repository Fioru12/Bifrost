# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within this project, please report it responsibly.

**Do NOT open a public GitHub issue.**

Instead, please contact the maintainer directly via GitHub:
- Open a private conversation at [github.com/Fioru12](https://github.com/Fioru12)

### What to include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if available)

### Response Timeline:
- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 1 week
- **Resolution:** depends on severity, typically within 2 weeks

## Supported Versions

| Version | Supported |
|:---|:---:|
| Latest | Yes |

## Security Best Practices

This tool performs **port scanning** and **network traffic analysis**.
Only scan hosts and networks you own or have explicit written authorization to test.
Encrypted reports use AES-128 (Fernet) with PBKDF2 key derivation - use strong passwords.
Never expose the API server to untrusted networks.
