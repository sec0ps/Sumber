# =============================================================================
# Sumber Security Source Code Analyzer - Static Application Security Testing
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This script is part of the Sumber Security Source Code Analyzer, which provides
#          enterprise-grade static application security testing (SAST) capabilities for
#          identifying OWASP Top 10 vulnerabilities in source code. The tool performs
#          comprehensive security analysis using AST parsing and pattern matching to detect
#          injection flaws, authentication issues, cryptographic failures, and other
#          security vulnerabilities with detailed remediation guidance.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================

from .analyzer import PythonSecurityAnalyzer

__all__ = ['PythonSecurityAnalyzer']

# Module metadata
LANGUAGE_NAME = 'python'
FILE_EXTENSIONS = ['.py', '.pyw']
SUPPORTED_OWASP_CATEGORIES = [
    'A01',  # Broken Access Control
    'A02',  # Cryptographic Failures
    'A03',  # Injection
    'A05',  # Security Misconfiguration
    'A06',  # Vulnerable and Outdated Components
    'A07',  # Identification and Authentication Failures
    'A08',  # Software and Data Integrity Failures
    'A09',  # Security Logging and Monitoring Failures
    'A10'   # Server-Side Request Forgery
]

def get_analyzer():
    """
    Factory function to create a Python security analyzer instance.
    
    Returns:
        PythonSecurityAnalyzer: Configured Python analyzer instance
    """
    return PythonSecurityAnalyzer()