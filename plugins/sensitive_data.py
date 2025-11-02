"""Sensitive data exposure plugin.
Detects potential sensitive information in HTTP responses.
"""
import re

def run(response, url):
    """Check for sensitive data in response.
    
    Args:
        response: HTTP response object
        url: URL that was scanned
        
    Returns:
        List of findings (empty list if none found)
    """
    if response is None or not hasattr(response, "text"):
        return []
    
    findings = []
    content = response.text
    
    # Check for common sensitive patterns
    patterns = [
        (r'api[_-]?key[\s]*[:=][\s]*[\'"][a-zA-Z0-9]{20,}[\'"]', 'API Key', 'HIGH'),
        (r'access[_-]?token[\s]*[:=][\s]*[\'"][a-zA-Z0-9]{20,}[\'"]', 'Access Token', 'HIGH'),
        (r'secret[_-]?key[\s]*[:=][\s]*[\'"][a-zA-Z0-9]{20,}[\'"]', 'Secret Key', 'HIGH'),
        (r'password[\s]*[:=][\s]*[\'"][^\'"]+[\'"]', 'Password', 'HIGH'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email Address', 'MEDIUM'),
        (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN Pattern', 'HIGH'),
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', 'Credit Card Pattern', 'HIGH'),
    ]
    
    for pattern, name, severity in patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            findings.append({
                'severity': severity,
                'type': name,
                'url': url,
                'evidence': match.group(0)
            })
    
    return findings
