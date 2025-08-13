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

from core import LanguageAnalyzer
from .base_analyzer import BaseSecurityRule, RuleMatch

__all__ = ['LanguageAnalyzer', 'BaseSecurityRule', 'RuleMatch']

# Registry of available language modules
AVAILABLE_LANGUAGES = []

def register_language_module(language_name: str, module_path: str) -> None:
    """
    Register a language module for dynamic loading.
    
    Args:
        language_name (str): Name of the programming language
        module_path (str): Python module path to the analyzer
    """
    global AVAILABLE_LANGUAGES
    
    if language_name not in [lang['name'] for lang in AVAILABLE_LANGUAGES]:
        AVAILABLE_LANGUAGES.append({
            'name': language_name,
            'module_path': module_path,
            'enabled': False
        })

def get_available_languages() -> list:
    """
    Get list of all available language modules.
    
    Returns:
        list: List of available language dictionaries
    """
    return AVAILABLE_LANGUAGES.copy()

def is_language_available(language_name: str) -> bool:
    """
    Check if a language module is available.
    
    Args:
        language_name (str): Name of the programming language
        
    Returns:
        bool: True if language module is available
    """
    return language_name in [lang['name'] for lang in AVAILABLE_LANGUAGES]

# Auto-register known language modules
register_language_module('python', 'language_modules.python.analyzer')