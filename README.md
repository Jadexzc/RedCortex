# RedCortex

![GitHub Actions](https://img.shields.io/github/actions/workflow/status/Jadexzc/RedCortex/ci.yml?branch=main&style=flat-square&logo=github)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/github/license/Jadexzc/RedCortex?style=flat-square)
![Documentation](https://img.shields.io/badge/docs-wiki-brightgreen?style=flat-square)
![Version](https://img.shields.io/github/v/release/Jadexzc/RedCortex?style=flat-square)

## Overview
RedCortex is an enterprise-grade automated penetration testing framework designed for red team operations and security research. Built on a modular architecture, it combines multiple reconnaissance vectors with advanced vulnerability detection and exploit chaining capabilities. The framework integrates industry-standard tools (dirsearch, Playwright) with proprietary detection engines to deliver comprehensive web application security assessments.

### Design Philosophy
RedCortex follows a chain-based exploitation methodology, enabling automatic escalation from initial vulnerability discovery to credential extraction and privilege escalation. The framework emphasizes reproducibility, evidence collection, and real-time reporting—critical requirements for professional security assessments and academic research.

---

## Features
| Category | Capability | Description |
|----------|-----------|-------------|
| **Reconnaissance** | Endpoint Discovery | Multi-vector discovery using dirsearch integration and headless browser crawling (Playwright) |
| **Parameter Analysis** | Wide-Spectrum Fuzzing | HTML form extraction and SecLists-based parameter enumeration |
| **Vulnerability Detection** | Multi-Vector Scanning | SQLi (error-based, blind, time-based), XSS (reflected, stored), LFI, SSRF, IDOR detection |
| **Exploit Chaining** | Automated Escalation | SQLi-to-shell, LFI credential extraction, IDOR privilege escalation |
| **Evidence Collection** | Credential Harvesting | Automated parsing of configuration files, environment variables, and database credentials |
| **Reporting** | Multi-Channel Output | Real-time Telegram alerts, Flask-based dashboard, JSON/CSV export |
