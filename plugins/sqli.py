#!/usr/bin/env python3
"""
SQL Injection Detection Plugin
Scans HTTP responses for SQL error patterns indicating potential SQL injection vulnerabilities.
"""

import re

# SQL error patterns from various database systems
SQL_ERROR_PATTERNS = [
    # MySQL errors
    r"SQL syntax.*?MySQL",
    r"Warning.*?mysql_.*",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server version",
    
    # PostgreSQL errors
    r"PostgreSQL.*?ERROR",
    r"Warning.*?pg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError",
    
    # Microsoft SQL Server errors
    r"Driver.*?SQL[\-\_\ ]*Server",
    r"OLE DB.*?SQL Server",
    r"\[SQL Server\]",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"Microsoft SQL Native Client error",
    
    # Oracle errors
    r"\bORA-[0-9][0-9][0-9][0-9]",
    r"Oracle error",
    r"Oracle.*?Driver",
    r"Warning.*?oci_.*",
    r"quoted string not properly terminated",
    
    # JDBC errors
    r"java\.sql\.SQLException",
    r"JDBC",
    
    # Generic SQL errors
    r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    r"Syntax error in string in query expression",
    r"unterminated quoted string",
    r"Incorrect syntax near",
    r"You have an error in your SQL syntax",
]

def run(response, url):
    """
    Main detection function for SQL injection vulnerabilities.
    
    Args:
        response: HTTP response object (should have .text or .content attribute)
        url: The URL being scanned
    
    Returns:
        list: List of findings dictionaries if SQL injection signatures are detected,
              empty list otherwise
    """
    findings = []
    
    # Get response content
    try:
        if hasattr(response, 'text'):
            content = response.text
        elif hasattr(response, 'content'):
            content = response.content.decode('utf-8', errors='ignore')
        else:
            content = str(response)
    except Exception as e:
        return findings
    
    # Check for SQL error patterns
    detected_patterns = []
    for pattern in SQL_ERROR_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        if matches:
            detected_patterns.append({
                'pattern': pattern,
                'matches': matches[:3]  # Limit to first 3 matches
            })
    
    # If SQL errors detected, create findings
    if detected_patterns:
        finding = {
            'plugin': 'sqli',
            'severity': 'high',
            'title': 'Potential SQL Injection Vulnerability Detected',
            'description': f'SQL database error messages detected in response from {url}. '
                          f'This may indicate a SQL injection vulnerability.',
            'url': url,
            'evidence': detected_patterns,
            'recommendation': 'Use parameterized queries or prepared statements. '
                            'Validate and sanitize all user inputs. '
                            'Implement proper error handling to avoid exposing database errors.'
        }
        findings.append(finding)
    
    return findings
