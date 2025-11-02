# Contributing to RedCortex

Thank you for your interest in contributing to RedCortex! This document provides guidelines and standards for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Documentation Standards](#documentation-standards)
- [Testing Requirements](#testing-requirements)
- [Submission Guidelines](#submission-guidelines)
- [Review Process](#review-process)

## Code of Conduct

This project adheres to a code of professional and respectful collaboration:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept criticism gracefully
- Prioritize community interests
- Respect differing viewpoints and experiences

## Getting Started

### Finding Issues to Work On

1. Check [open issues](https://github.com/Jadexzc/RedCortex/issues)
2. Look for issues labeled:
   - `good first issue` - Suitable for newcomers
   - `help wanted` - Actively seeking contributors
   - `bug` - Bug fixes needed
   - `enhancement` - Feature requests

### Before You Start

1. **Comment on the issue** to claim it and avoid duplicate work
2. **Fork the repository** to your GitHub account
3. **Create a feature branch** from `main`
4. **Keep your fork synced** with the upstream repository

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, virtualenv, or conda)

### Setup Instructions

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/RedCortex.git
cd RedCortex

# Add upstream remote
git remote add upstream https://github.com/Jadexzc/RedCortex.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Install pre-commit hooks
pre-commit install
```

### Development Dependencies

Install additional tools for development:

```bash
pip install pytest pytest-cov black flake8 mypy pylint
```

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with the following specifics:

#### Code Formatting

- **Line Length**: Maximum 100 characters
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Double quotes for strings, single quotes for dict keys
- **Imports**: Organized in three groups (standard library, third-party, local)

```python
# Example: Proper import organization
import os
import sys
from typing import List, Dict

import requests
from flask import Flask

from plugins.base_plugin import BasePlugin
from core.scanner import Scanner
```

#### Naming Conventions

```python
# Classes: PascalCase
class VulnerabilityScanner:
    pass

# Functions and variables: snake_case
def scan_target(target_url):
    scan_results = []
    return scan_results

# Constants: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3
DEFAULT_TIMEOUT = 30

# Private methods: leading underscore
def _internal_helper(self):
    pass
```

#### Type Hints

Use type hints for function signatures:

```python
from typing import List, Dict, Optional

def scan_endpoints(
    targets: List[str],
    config: Dict[str, any],
    timeout: Optional[int] = None
) -> List[Dict[str, any]]:
    """
    Scan multiple endpoints for vulnerabilities.
    
    Args:
        targets: List of target URLs to scan
        config: Configuration dictionary
        timeout: Optional timeout in seconds
    
    Returns:
        List of findings dictionaries
    """
    return []
```

#### Documentation

Every public function, class, and module must have docstrings:

```python
def calculate_severity_score(findings: List[Dict]) -> float:
    """
    Calculate overall severity score from findings.
    
    Uses CVSS v3.1 scoring methodology to compute weighted
    severity across all detected vulnerabilities.
    
    Args:
        findings: List of vulnerability findings with severity ratings
    
    Returns:
        Float score between 0.0 and 10.0
    
    Raises:
        ValueError: If findings list is empty
        
    Example:
        >>> findings = [{'severity': 'high', 'cvss': 7.5}]
        >>> calculate_severity_score(findings)
        7.5
    """
    pass
```

### Error Handling

```python
# Specific exceptions
try:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
except requests.Timeout:
    logger.error(f"Timeout connecting to {url}")
    raise
except requests.RequestException as e:
    logger.error(f"Request failed: {e}")
    return None

# Avoid bare except
# DON'T: except:
# DO: except Exception as e:
```

### Logging

```python
import logging

logger = logging.getLogger(__name__)

# Use appropriate levels
logger.debug("Detailed diagnostic information")
logger.info("General informational messages")
logger.warning("Warning messages for recoverable issues")
logger.error("Error messages for failures")
logger.critical("Critical failures requiring immediate attention")
```

### Security Best Practices

1. **Input Validation**: Sanitize all user inputs
2. **SQL Queries**: Use parameterized queries only
3. **File Operations**: Validate paths and prevent traversal
4. **Credentials**: Never hardcode secrets
5. **Command Execution**: Avoid shell=True, validate arguments

```python
# Good: Parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Bad: String interpolation
# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Good: Path validation
from pathlib import Path
base_dir = Path("/var/evidence")
file_path = (base_dir / user_input).resolve()
if not str(file_path).startswith(str(base_dir)):
    raise ValueError("Invalid path")
```

## Documentation Standards

### Code Comments

```python
# Explain WHY, not WHAT
# Good: 
# Delay to avoid triggering rate limiting on target server
time.sleep(2)

# Bad:
# Sleep for 2 seconds
# time.sleep(2)
```

### README Updates

- Update README.md when adding new features
- Include usage examples
- Update badges if applicable
- Keep feature list current

### Wiki Documentation

For significant features:

1. Create or update relevant Wiki pages
2. Include code examples
3. Add troubleshooting sections
4. Link from main documentation

## Testing Requirements

### Test Coverage

- **Minimum coverage**: 80% for new code
- **Critical paths**: 100% coverage required
- Run tests before submitting PR

### Writing Tests

```python
import unittest
from unittest.mock import Mock, patch

class TestVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = VulnerabilityScanner()
        self.test_url = "http://testsite.com"
    
    def tearDown(self):
        """Clean up after tests."""
        self.scanner.cleanup()
    
    def test_sqli_detection(self):
        """Test SQL injection detection."""
        payload = "' OR '1'='1"
        result = self.scanner.test_sqli(self.test_url, payload)
        self.assertTrue(result.vulnerable)
        self.assertEqual(result.confidence, "high")
    
    @patch('requests.get')
    def test_network_timeout(self, mock_get):
        """Test handling of network timeouts."""
        mock_get.side_effect = requests.Timeout()
        result = self.scanner.scan(self.test_url)
        self.assertIsNone(result)
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=core --cov=plugins --cov-report=html

# Run specific test file
pytest tests/test_scanner.py

# Run specific test
pytest tests/test_scanner.py::TestVulnerabilityScanner::test_sqli_detection
```

### Integration Tests

Create integration tests for end-to-end workflows:

```bash
# Integration tests against test environment
pytest tests/integration/ --slow
```

## Submission Guidelines

### Branch Naming

- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring

Example: `feature/add-csrf-scanner`

### Commit Messages

Follow conventional commits format:

```
type(scope): subject

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:

```
feat(scanner): add CSRF token detection

Implements automatic CSRF token detection in forms.
Supports both meta tags and hidden input fields.

Closes #123
```

```
fix(api): resolve rate limiting issue

Fixed race condition in rate limiter that caused
incorrect throttling under high concurrency.

Fixes #456
```

### Pull Request Process

1. **Update your branch**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run quality checks**
   ```bash
   black .
   flake8 .
   mypy .
   pytest
   ```

3. **Push to your fork**
   ```bash
   git push origin feature/your-feature
   ```

4. **Create Pull Request**
   - Clear, descriptive title
   - Reference related issues
   - Describe changes and rationale
   - Include screenshots for UI changes
   - Mark as draft if work in progress

### PR Description Template

```markdown
## Description
Brief description of changes

## Motivation
Why are these changes needed?

## Changes
- Change 1
- Change 2
- Change 3

## Testing
How was this tested?

## Screenshots (if applicable)

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests passing
- [ ] No new warnings introduced
```

## Review Process

### What Reviewers Look For

1. **Functionality**: Does it work as intended?
2. **Code Quality**: Is it readable and maintainable?
3. **Security**: Are there security implications?
4. **Performance**: Are there performance concerns?
5. **Testing**: Is it adequately tested?
6. **Documentation**: Is it properly documented?

### Addressing Feedback

- Respond to all comments
- Make requested changes promptly
- Ask for clarification if needed
- Mark conversations as resolved when addressed

### Merge Criteria

- ✅ All CI checks passing
- ✅ Minimum 1 approval from maintainer
- ✅ No unresolved conversations
- ✅ Up to date with main branch
- ✅ Meets all requirements above

## Additional Resources

- [Project Wiki](https://github.com/Jadexzc/RedCortex/wiki)
- [Issue Tracker](https://github.com/Jadexzc/RedCortex/issues)
- [Discussions](https://github.com/Jadexzc/RedCortex/discussions)
- [Security Policy](SECURITY.md)

## Questions?

If you have questions:

1. Check existing documentation
2. Search closed issues
3. Ask in [Discussions](https://github.com/Jadexzc/RedCortex/discussions)
4. Contact maintainers

---

Thank you for contributing to RedCortex! 🎉
