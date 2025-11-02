# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-03

### Added
- Initial stable release of RedCortex
- Modular plugin architecture for extensible scanning modules
- Real-time web dashboard for monitoring scans and evidence
- Telegram integration for instant notifications and alerts
- API-driven scanning with RESTful endpoints
- Evidence collection system with automated artifact gathering
- Multi-target concurrent scanning support
- Professional reporting with JSON, CSV, and HTML output formats
- SQL injection detection (error-based, blind, time-based)
- Cross-site scripting (XSS) detection (reflected, stored)
- Local file inclusion (LFI) vulnerability scanner
- Server-side request forgery (SSRF) detection
- Insecure direct object references (IDOR) scanner
- Directory enumeration via dirsearch integration
- Parameter fuzzing with SecLists wordlists
- Exploit chaining for automated privilege escalation
- Headless browser crawling with Playwright
- Configuration file parsing and credential extraction
- Comprehensive Wiki documentation
  - Usage Guides with detailed scan options
  - Plugin Development guide
  - Scan Result Interpretation reference
- Security Policy (SECURITY.md) with vulnerability disclosure guidelines
- Project badges for build status, Python version, license, and documentation
- Tagged releases with automatic citation support

### Documentation
- Created comprehensive README with shields.io badges
- Expanded Wiki with three major sections:
  - Usage Guides: Detailed scanning options, reporting, and workflows
  - Plugin Development: Complete guide to creating custom modules
  - Scan Result Interpretation: Understanding findings and evidence
- Added SECURITY.md with responsible disclosure policy
- Created CHANGELOG.md for version tracking
- Updated CONTRIBUTING.md with coding standards and guidelines

### Infrastructure
- Set up GitHub Wiki for detailed documentation
- Configured issue templates for bug reports, feature requests, and security disclosures
- Enabled GitHub Discussions for community support
- Created sample output files in /samples directory
- Added architecture diagram to README
- Visualized project roadmap as formatted table

### Security
- Implemented rate limiting on API endpoints
- Added input sanitization for scan parameters
- Integrated secure session management
- Enabled CSRF protection on web dashboard
- Configured encrypted credential storage
- Established audit logging system

## [Unreleased]

### Planned Features
- Two-factor authentication (2FA) for dashboard access
- Role-based access control (RBAC) system
- End-to-end encryption for evidence data
- Security audit logging to SIEM integration
- Advanced payload generation and evasion techniques
- Machine learning-based vulnerability detection
- Cloud platform-specific scanners (AWS, Azure, GCP)
- Container security scanning (Docker, Kubernetes)
- Mobile application security testing
- API security testing module

### Known Issues
- None reported yet

---

## Release Notes Format

### Types of Changes
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

---

[1.0.0]: https://github.com/Jadexzc/RedCortex/releases/tag/v1.0.0
