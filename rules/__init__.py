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

from .rule_engine import (
    RuleEngine,
    RuleValidator,
    RuleManager,
    RuleExecutionContext,
    RuleExecutionResult
)

from .owasp_rules import (
    OWASPRuleSet,
    get_owasp_rule_by_id,
    get_rules_by_category,
    get_all_owasp_rules,
    OWASP_CATEGORIES,
    SEVERITY_LEVELS
)

__all__ = [
    # Rule Engine
    'RuleEngine',
    'RuleValidator', 
    'RuleManager',
    'RuleExecutionContext',
    'RuleExecutionResult',
    
    # OWASP Rules
    'OWASPRuleSet',
    'get_owasp_rule_by_id',
    'get_rules_by_category',
    'get_all_owasp_rules',
    'OWASP_CATEGORIES',
    'SEVERITY_LEVELS'
]

# Module metadata
MODULE_VERSION = "1.0.0"
SUPPORTED_OWASP_VERSION = "2021"
TOTAL_RULE_CATEGORIES = 10

def get_module_info() -> dict:
    """
    Get information about the rules module.
    
    Returns:
        dict: Module information and statistics
    """
    return {
        'version': MODULE_VERSION,
        'owasp_version': SUPPORTED_OWASP_VERSION,
        'total_categories': TOTAL_RULE_CATEGORIES,
        'available_rules': len(get_all_owasp_rules()),
        'categories': list(OWASP_CATEGORIES.keys())
    }