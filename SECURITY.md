# Security Policy

## Reporting a Vulnerability

The RedCortex team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **Email**: Send details to security@redcortex-project.org (or project maintainer email)
2. **GitHub Security Advisory**: Use the [GitHub Security Advisory](https://github.com/Jadexzc/RedCortex/security/advisories/new) feature
3. **Encrypted Communication**: For sensitive disclosures, request our PGP key

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., SQLi, XSS, command injection)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours of report submission
- **Triage**: Within 1 week - we'll confirm the issue and assess severity
- **Fix Development**: Varies by severity (Critical: 7 days, High: 14 days, Medium: 30 days)
- **Public Disclosure**: Coordinated with reporter after fix is released

## Scope

### In Scope

The following components are in scope for vulnerability reports:

- Core scanning engine
- Plugin system and built-in plugins
- API endpoints and authentication
- Web dashboard interface
- Database interactions
- File handling and evidence collection
- Configuration parsing

### Out of Scope

- Vulnerabilities in third-party dependencies (report to respective projects)
- Issues requiring physical access to the system
- Social engineering attacks
- Denial of service attacks
- Issues in outdated/unsupported versions

## Severity Assessment

We use the following criteria to assess vulnerability severity:

### Critical
- Remote code execution
- Authentication bypass
- SQL injection leading to data breach
- Privilege escalation to admin

### High
- Cross-site scripting (XSS) with session hijacking
- Local file inclusion with code execution
- Credential disclosure
- Authorization flaws

### Medium
- Information disclosure
- Cross-site request forgery (CSRF)
- Insecure direct object references (IDOR)
- Missing security headers

### Low
- Non-sensitive information leaks
- Minor configuration issues
- Low-impact XSS

## Responsible Disclosure

### Our Commitment

- We will acknowledge receipt of your vulnerability report within 48 hours
- We will provide an estimated timeline for a fix
- We will notify you when the vulnerability is fixed
- We will credit you in our security advisories (unless you prefer anonymity)

### We Ask That You

- Give us reasonable time to address the issue before public disclosure
- Do not access, modify, or delete data belonging to others
- Do not perform attacks that could harm reliability or integrity of services
- Do not use social engineering, phishing, or physical attacks
- Make a good faith effort to avoid privacy violations and data destruction

## Hall of Fame

We maintain a list of security researchers who have responsibly disclosed vulnerabilities:

<!-- Security researchers will be listed here after responsible disclosure -->

*No entries yet - be the first!*

## Security Best Practices

### For Users

1. **Keep Updated**: Always use the latest stable release
2. **Secure Configuration**: Review and harden `config.yaml` settings
3. **Access Control**: Restrict dashboard access to trusted networks
4. **API Keys**: Rotate API keys regularly, use strong authentication
5. **Evidence Storage**: Ensure evidence directory has proper permissions
6. **Logging**: Enable audit logging for security monitoring

### For Developers

1. **Input Validation**: Sanitize all user inputs
2. **Parameterized Queries**: Use prepared statements for database operations
3. **Authentication**: Implement strong authentication and session management
4. **Authorization**: Verify user permissions before actions
5. **Secrets Management**: Never hardcode credentials or API keys
6. **Dependencies**: Keep third-party libraries updated

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

**Note**: Only the latest stable release receives security updates.

## Security Features

### Current Implementation

- Rate limiting on API endpoints
- Input sanitization for scan parameters
- Secure session management
- CSRF protection on web dashboard
- Encrypted credential storage
- Audit logging

### Planned Enhancements

- Two-factor authentication (2FA) for dashboard
- Role-based access control (RBAC)
- End-to-end encryption for evidence data
- Security audit logging to SIEM

## Contact

For security-related inquiries:

- **Security Team**: security@redcortex-project.org
- **Project Maintainer**: [@Jadexzc](https://github.com/Jadexzc)
- **GPG Key**: [Available on request]

## Additional Resources

- [GitHub Security Advisories](https://github.com/Jadexzc/RedCortex/security/advisories)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

**Last Updated**: November 3, 2025

Thank you for helping keep RedCortex and its users safe!
