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

import ast
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union

from core import LanguageAnalyzer, FileAnalysisResult, Vulnerability
from language_modules.base_analyzer import (
    BaseSecurityRule, RegexSecurityRule, RuleMatch,
    RuleCategory, Severity, Confidence
)
from utils.file_utils import safe_read_file

logger = logging.getLogger(__name__)

class ASTSecurityRule(BaseSecurityRule):
    """
    Security rule that analyzes Python AST nodes for vulnerabilities.
    """
    
    def __init__(self, rule_id: str, title: str, description: str,
                 severity: Severity, owasp_category: RuleCategory):
        super().__init__(rule_id, title, description, severity, owasp_category)
    
    def check(self, content: str, file_path: Path, **kwargs) -> List[RuleMatch]:
        """
        Analyze AST for security vulnerabilities.
        
        Args:
            content (str): Source code content
            file_path (Path): Path to source file
            **kwargs: Additional context including 'parsed_data' (AST)
            
        Returns:
            list: List of RuleMatch objects
        """
        parsed_data = kwargs.get('parsed_data')
        if not parsed_data or not isinstance(parsed_data, ast.AST):
            return []
        
        return self.check_ast(parsed_data, content, file_path)
    
    def check_ast(self, tree: ast.AST, content: str, file_path: Path) -> List[RuleMatch]:
        """
        Check AST for security issues. Override in subclasses.
        
        Args:
            tree (ast.AST): Parsed AST
            content (str): Source code content
            file_path (Path): Path to source file
            
        Returns:
            list: List of RuleMatch objects
        """
        return []
    
    def get_line_column(self, node: ast.AST) -> tuple:
        """Get line and column numbers from AST node."""
        return getattr(node, 'lineno', 1), getattr(node, 'col_offset', 0)

class SQLInjectionRule(ASTSecurityRule):
    """Detects potential SQL injection vulnerabilities in Python code."""
    
    def __init__(self):
        super().__init__(
            rule_id="PY001",
            title="Potential SQL Injection",
            description="SQL query constructed using string formatting or concatenation with user input",
            severity=Severity.CRITICAL,
            owasp_category=RuleCategory.A03_INJECTION
        )
        self.confidence = Confidence.HIGH
    
    def check_ast(self, tree: ast.AST, content: str, file_path: Path) -> List[RuleMatch]:
        matches = []
        
        for node in ast.walk(tree):
            # Check for string formatting in function calls that might be SQL
            if isinstance(node, ast.Call):
                matches.extend(self._check_sql_call(node, content))
            
            # Check for string concatenation that might be SQL
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                matches.extend(self._check_sql_concatenation(node, content))
        
        return matches
    
    def _check_sql_call(self, node: ast.Call, content: str) -> List[RuleMatch]:
        """Check function calls for SQL injection patterns."""
        matches = []
        
        # Look for execute(), executemany(), format() on potential SQL strings
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr in ['execute', 'executemany', 'format']):
            
            # Check if arguments contain SQL-like keywords and formatting
            for arg in node.args:
                if self._is_sql_with_formatting(arg):
                    line, col = self.get_line_column(node)
                    matches.append(RuleMatch(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"SQL query uses string formatting: {node.func.attr}()",
                        severity=self.severity,
                        confidence=self.confidence,
                        owasp_category=self.owasp_category,
                        line_number=line,
                        column_number=col,
                        remediation="Use parameterized queries instead of string formatting"
                    ))
        
        return matches
    
    def _check_sql_concatenation(self, node: ast.BinOp, content: str) -> List[RuleMatch]:
        """Check binary operations for SQL concatenation patterns."""
        matches = []
        
        # Check if either side looks like SQL
        if (self._looks_like_sql(node.left) or self._looks_like_sql(node.right)):
            line, col = self.get_line_column(node)
            matches.append(RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                description="SQL query constructed using string concatenation",
                severity=self.severity,
                confidence=Confidence.MEDIUM,
                owasp_category=self.owasp_category,
                line_number=line,
                column_number=col,
                remediation="Use parameterized queries instead of string concatenation"
            ))
        
        return matches
    
    def _is_sql_with_formatting(self, node: ast.AST) -> bool:
        """Check if a node represents SQL with formatting."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
            format_indicators = ['%s', '{}', '{', 'format(']
            
            text = node.value.upper()
            has_sql = any(keyword in text for keyword in sql_keywords)
            has_formatting = any(indicator in node.value for indicator in format_indicators)
            
            return has_sql and has_formatting
        
        return False
    
    def _looks_like_sql(self, node: ast.AST) -> bool:
        """Check if a node looks like it contains SQL."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'JOIN']
            text = node.value.upper()
            return any(keyword in text for keyword in sql_keywords)
        return False

class CommandInjectionRule(ASTSecurityRule):
    """Detects command injection vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            rule_id="PY002",
            title="Command Injection Risk",
            description="System command execution with potential user input",
            severity=Severity.CRITICAL,
            owasp_category=RuleCategory.A03_INJECTION
        )
        self.confidence = Confidence.HIGH
        
        # Dangerous functions for command execution
        self.dangerous_functions = {
            'os.system', 'os.popen', 'os.execl', 'os.execle', 'os.execlp',
            'os.execv', 'os.execve', 'os.execvp', 'os.spawn*',
            'subprocess.call', 'subprocess.run', 'subprocess.Popen',
            'commands.getoutput', 'commands.getstatusoutput'
        }
    
    def check_ast(self, tree: ast.AST, content: str, file_path: Path) -> List[RuleMatch]:
        matches = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                matches.extend(self._check_command_call(node, content))
        
        return matches
    
    def _check_command_call(self, node: ast.Call, content: str) -> List[RuleMatch]:
        """Check function calls for command injection risks."""
        matches = []
        
        func_name = self._get_function_name(node.func)
        
        # Check if it's a dangerous function
        if any(dangerous in func_name for dangerous in self.dangerous_functions):
            
            # Check for shell=True in subprocess calls
            shell_true = self._has_shell_true(node)
            
            # Check for string formatting/concatenation in arguments
            has_dynamic_input = self._has_dynamic_input(node)
            
            if shell_true or has_dynamic_input:
                line, col = self.get_line_column(node)
                
                description = f"Command execution via {func_name}"
                if shell_true:
                    description += " with shell=True"
                if has_dynamic_input:
                    description += " with dynamic input"
                
                matches.append(RuleMatch(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=description,
                    severity=self.severity,
                    confidence=self.confidence,
                    owasp_category=self.owasp_category,
                    line_number=line,
                    column_number=col,
                    remediation="Avoid shell=True, use subprocess with list arguments, validate all input"
                ))
        
        return matches
    
    def _get_function_name(self, func_node: ast.AST) -> str:
        """Get function name from call node."""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
            else:
                return func_node.attr
        return ""
    
    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if call has shell=True parameter."""
        for keyword in node.keywords:
            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                return keyword.value.value is True
        return False
    
    def _has_dynamic_input(self, node: ast.Call) -> bool:
        """Check if call has dynamic input (formatting, variables)."""
        for arg in node.args:
            if self._is_dynamic_string(arg):
                return True
        return False
    
    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Check if node represents dynamic string construction."""
        # String formatting
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        
        # f-strings
        if isinstance(node, ast.JoinedStr):
            return True
        
        # .format() calls
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) 
            and node.func.attr == 'format'):
            return True
        
        # Variables (not string literals)
        if isinstance(node, ast.Name):
            return True
        
        return False

class HardcodedSecretsRule(RegexSecurityRule):
    """Detects hardcoded secrets and credentials in Python code."""
    
    def __init__(self):
        patterns = [
            # API keys and tokens
            r'(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
            
            # Database connection strings
            r'(?i)(mysql|postgres|mongodb)://[^:\s]+:[^@\s]+@',
            
            # AWS keys
            r'(?i)AKIA[0-9A-Z]{16}',
            
            # Private keys
            r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
            
            # Common secret patterns
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
            
            # JWT tokens
            r'eyJ[a-zA-Z0-9+/=]+\.eyJ[a-zA-Z0-9+/=]+\.[a-zA-Z0-9+/=]+'
        ]
        
        super().__init__(
            rule_id="PY003",
            title="Hardcoded Secrets",
            description="Potential hardcoded secrets, passwords, or API keys",
            severity=Severity.CRITICAL,
            owasp_category=RuleCategory.A02_CRYPTOGRAPHIC_FAILURES,
            patterns=patterns
        )
        self.confidence = Confidence.MEDIUM

class WeakCryptographyRule(ASTSecurityRule):
    """Detects weak cryptographic practices."""
    
    def __init__(self):
        super().__init__(
            rule_id="PY004",
            title="Weak Cryptography",
            description="Use of weak or deprecated cryptographic algorithms",
            severity=Severity.HIGH,
            owasp_category=RuleCategory.A02_CRYPTOGRAPHIC_FAILURES
        )
        self.confidence = Confidence.HIGH
        
        # Weak algorithms to detect
        self.weak_algorithms = {
            'md5', 'sha1', 'des', '3des', 'rc4', 'md4'
        }
    
    def check_ast(self, tree: ast.AST, content: str, file_path: Path) -> List[RuleMatch]:
        matches = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                matches.extend(self._check_crypto_call(node))
        
        return matches
    
    def _check_crypto_call(self, node: ast.Call) -> List[RuleMatch]:
        """Check for weak cryptographic function calls."""
        matches = []
        
        func_name = self._get_function_name(node.func).lower()
        
        # Check hashlib usage
        if 'hashlib.' in func_name:
            for weak_alg in self.weak_algorithms:
                if weak_alg in func_name:
                    line, col = self.get_line_column(node)
                    matches.append(RuleMatch(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Weak hash algorithm: {weak_alg}",
                        severity=self.severity,
                        confidence=self.confidence,
                        owasp_category=self.owasp_category,
                        line_number=line,
                        column_number=col,
                        remediation=f"Replace {weak_alg} with SHA-256 or stronger"
                    ))
        
        # Check for weak random number generation
        if func_name in ['random.random', 'random.randint', 'random.choice']:
            line, col = self.get_line_column(node)
            matches.append(RuleMatch(
                rule_id=self.rule_id,
                title="Weak Random Number Generation",
                description="Use of predictable random number generator",
                severity=Severity.MEDIUM,
                confidence=self.confidence,
                owasp_category=self.owasp_category,
                line_number=line,
                column_number=col,
                remediation="Use secrets module for cryptographic purposes"
            ))
        
        return matches
    
    def _get_function_name(self, func_node: ast.AST) -> str:
        """Get function name from call node."""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
            else:
                return func_node.attr
        return ""

class InsecureDeserializationRule(ASTSecurityRule):
    """Detects insecure deserialization vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            rule_id="PY005",
            title="Insecure Deserialization",
            description="Unsafe deserialization of untrusted data",
            severity=Severity.CRITICAL,
            owasp_category=RuleCategory.A08_INTEGRITY_FAILURES
        )
        self.confidence = Confidence.HIGH
        
        # Dangerous deserialization functions
        self.dangerous_functions = {
            'pickle.loads', 'pickle.load', 'cPickle.loads', 'cPickle.load',
            'yaml.load', 'eval', 'exec', 'compile'
        }
    
    def check_ast(self, tree: ast.AST, content: str, file_path: Path) -> List[RuleMatch]:
        matches = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                matches.extend(self._check_deserialization_call(node))
        
        return matches
    
    def _check_deserialization_call(self, node: ast.Call) -> List[RuleMatch]:
        """Check for dangerous deserialization calls."""
        matches = []
        
        func_name = self._get_function_name(node.func)
        
        if func_name in self.dangerous_functions:
            line, col = self.get_line_column(node)
            
            # Special handling for different functions
            if 'pickle' in func_name:
                description = "Unsafe pickle deserialization - can execute arbitrary code"
                remediation = "Validate data source, use json instead, or implement safe deserialization"
            elif func_name == 'yaml.load':
                description = "Unsafe YAML loading - use yaml.safe_load() instead"
                remediation = "Use yaml.safe_load() for untrusted input"
            elif func_name in ['eval', 'exec']:
                description = f"Dynamic code execution via {func_name}()"
                remediation = "Avoid eval/exec with user input, use ast.literal_eval for safe evaluation"
            else:
                description = f"Potentially unsafe deserialization: {func_name}"
                remediation = "Validate input source and content before deserialization"
            
            matches.append(RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                description=description,
                severity=self.severity,
                confidence=self.confidence,
                owasp_category=self.owasp_category,
                line_number=line,
                column_number=col,
                remediation=remediation
            ))
        
        return matches
    
    def _get_function_name(self, func_node: ast.AST) -> str:
        """Get function name from call node."""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
        return ""

class DebugModeRule(RegexSecurityRule):
    """Detects debug mode enabled in production code."""
    
    def __init__(self):
        patterns = [
            # Django debug mode
            r'(?i)DEBUG\s*=\s*True',
            
            # Flask debug mode
            r'(?i)app\.debug\s*=\s*True',
            r'(?i)app\.run\([^)]*debug\s*=\s*True',
            
            # General debug flags
            r'(?i)debug\s*[=:]\s*True',
            r'(?i)verbose\s*[=:]\s*True'
        ]
        
        super().__init__(
            rule_id="PY006",
            title="Debug Mode Enabled",
            description="Debug mode enabled - may expose sensitive information",
            severity=Severity.HIGH,
            owasp_category=RuleCategory.A05_SECURITY_MISCONFIGURATION,
            patterns=patterns
        )
        self.confidence = Confidence.HIGH

class PythonSecurityAnalyzer(LanguageAnalyzer):
    """
    Python-specific security analyzer implementing OWASP Top 10 detection.
    
    Uses AST analysis and pattern matching to detect security vulnerabilities
    in Python source code.
    """
    
    @property
    def language_name(self) -> str:
        return "python"
    
    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".pyw"]

    def __init__(self):
        """Initialize the Python security analyzer."""
        self.rules: List[BaseSecurityRule] = []
        self._initialize_rules()

    def _get_owasp_pattern_mapping(self) -> Dict[str, str]:
        """Map rule IDs to OWASP pattern IDs."""
        return {
            'PY001': 'A03_001',  # SQL Injection
            'PY002': 'A03_002',  # Command Injection
            'PY003': 'A02_001',  # Hardcoded Secrets
            'PY004': 'A02_002',  # Weak Cryptography
            'PY005': 'A08_001',  # Insecure Deserialization
            'PY006': 'A05_001',  # Debug Mode Enabled
            'PY007': 'A10_001',  # SSRF
            'PY008': 'A09_001',  # Sensitive Data in Logs
            'PY009': 'A07_001',  # Weak Authentication
            'PY010': 'A07_001',  # Authentication Bypass
            'PY011': 'A07_001',  # Weak Session Management
            'PY012': 'A01_001',  # Path Traversal
            'PY013': 'A03_001',  # XSS (map to injection for now)
            'PY014': 'A09_001',  # Exception Information Disclosure
            'PY015': 'A09_001',  # Sensitive Data in Debug Output
        }
    
    def _enrich_vulnerability_with_owasp_data(self, vulnerability: Vulnerability, rule_id: str) -> None:
        """Enrich vulnerability with OWASP pattern data."""
        try:
            from rules.owasp_rules import get_owasp_ruleset, OWASP_CATEGORIES
            
            # Get pattern mapping
            pattern_mapping = self._get_owasp_pattern_mapping()
            pattern_id = pattern_mapping.get(rule_id)
            
            if pattern_id:
                # Get the OWASP pattern
                ruleset = get_owasp_ruleset()
                pattern = ruleset.get_pattern(pattern_id)
                
                if pattern:
                    # Enrich the vulnerability with pattern data
                    vulnerability.enrich_with_owasp_pattern(pattern)
                    
                    # Add OWASP category name from categories dict
                    category_info = OWASP_CATEGORIES.get(pattern.owasp_category, {})
                    if category_info:
                        vulnerability.owasp_category_name = f"{pattern.owasp_category}: {category_info['name']}"
                else:
                    # Fallback to basic category info
                    category_info = OWASP_CATEGORIES.get(vulnerability.owasp_category, {})
                    if category_info:
                        vulnerability.owasp_category_name = f"{vulnerability.owasp_category}: {category_info['name']}"
            else:
                # Map to General Security category
                vulnerability.owasp_category = "GEN"
                category_info = OWASP_CATEGORIES.get("GEN", {})
                vulnerability.owasp_category_name = f"GEN: {category_info['name']}"
                
        except Exception as e:
            logger.error(f"Error enriching vulnerability with OWASP data: {e}")
    
    def _highlight_problematic_code(self, code_snippet: str, matched_text: str) -> str:
        """Highlight the problematic portion of code in the snippet."""
        if not matched_text or not code_snippet:
            return code_snippet
        
        try:
            # Simple highlighting - wrap matched text in <mark> tags
            highlighted = code_snippet.replace(
                matched_text, 
                f'<mark class="vulnerability-highlight">{matched_text}</mark>'
            )
            return highlighted
        except Exception as e:
            logger.debug(f"Error highlighting code: {e}")
            return code_snippet

    def add_rule(self, rule: BaseSecurityRule) -> None:
        """Add a security rule to the analyzer."""
        self.rules.append(rule)
    
    def get_enabled_rules(self) -> List[BaseSecurityRule]:
        """Get list of enabled rules."""
        return [rule for rule in self.rules if rule.is_enabled()]
    
    def get_rule_count_by_category(self) -> Dict[str, int]:
        """Get count of rules by OWASP category."""
        category_counts = {}
        for rule in self.rules:
            category = rule.owasp_category.value
            category_counts[category] = category_counts.get(category, 0) + 1
        return category_counts

    def _create_vulnerability_from_match(self, match: RuleMatch, file_path: Path, content: str) -> Optional[Vulnerability]:
        """Convert a RuleMatch to a Vulnerability object with OWASP enrichment."""
        try:
            # Extract code snippet around the match
            lines = content.splitlines()
            line_idx = match.line_number - 1
            
            # Get context lines (current + 2 before and after)
            start_line = max(0, line_idx - 2)
            end_line = min(len(lines), line_idx + 3)
            code_snippet = '\n'.join(lines[start_line:end_line])
            
            # Highlight the problematic code
            highlighted_code = self._highlight_problematic_code(code_snippet, match.matched_text)
            
            vulnerability = Vulnerability(
                title=match.title,
                description=match.description,
                severity=match.severity.value,
                owasp_category=match.owasp_category.value,
                line_number=match.line_number,
                column_number=match.column_number,
                code_snippet=code_snippet,
                filename=str(file_path)
            )
            
            vulnerability.confidence = match.confidence.value
            vulnerability.highlighted_code = highlighted_code
            
            # Enrich with OWASP pattern data
            self._enrich_vulnerability_with_owasp_data(vulnerability, match.rule_id)
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Error creating vulnerability from match: {e}")
            return None
    
    def _should_report_vulnerability(self, vulnerability: Vulnerability, config: Any) -> bool:
        """Check if vulnerability should be reported based on config."""
        return config.meets_severity_threshold(vulnerability.severity)
    
    def _initialize_rules(self) -> None:
        """Initialize Python-specific security rules."""
        
        # A03: Injection vulnerabilities
        self.add_rule(SQLInjectionRule())
        self.add_rule(CommandInjectionRule())
        
        # A02: Cryptographic failures
        self.add_rule(HardcodedSecretsRule())
        self.add_rule(WeakCryptographyRule())
        
        # A08: Software and data integrity failures
        self.add_rule(InsecureDeserializationRule())
        
        # A05: Security misconfiguration
        self.add_rule(DebugModeRule())
        
        # Add regex-based rules for additional patterns
        self._add_regex_rules()
        
        logger.info(f"Initialized {len(self.rules)} Python security rules")
    
    def _add_regex_rules(self) -> None:
        """Add additional regex-based security rules."""
        
        # A10: SSRF vulnerabilities
        ssrf_rule = RegexSecurityRule(
            rule_id="PY007",
            title="Server-Side Request Forgery Risk",
            description="HTTP request to user-controlled URL",
            severity=Severity.HIGH,
            owasp_category=RuleCategory.A10_SSRF,
            patterns=[
                r'requests\.(get|post|put|delete|patch)\s*\([^)]*["\']?\s*\+',
                r'urllib\.request\.urlopen\s*\([^)]*["\']?\s*\+',
                r'httplib\.(HTTPConnection|HTTPSConnection)\s*\([^)]*["\']?\s*\+'
            ]
        )
        ssrf_rule.confidence = Confidence.MEDIUM
        ssrf_rule.primary_remediation = "Implement URL validation with strict whitelisting of allowed hosts and protocols, use network segmentation to restrict outbound connections"
        ssrf_rule.alternative_remediation = "If URL whitelisting is not feasible, implement hostname validation, block private IP ranges, and use proxy servers to control outbound traffic"
        ssrf_rule.references = [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://cwe.mitre.org/data/definitions/918.html"
        ]
        self.add_rule(ssrf_rule)
        
        # A09: Security logging failures
        logging_rule = RegexSecurityRule(
            rule_id="PY008",
            title="Sensitive Data in Logs",
            description="Potential logging of sensitive information",
            severity=Severity.MEDIUM,
            owasp_category=RuleCategory.A09_LOGGING_FAILURES,
            patterns=[
                r'(?i)log[^(]*\([^)]*(?:password|token|secret|key)[^)]*\)',
                r'(?i)print\([^)]*(?:password|token|secret|key)[^)]*\)'
            ]
        )
        logging_rule.confidence = Confidence.LOW
        logging_rule.primary_remediation = "Implement log sanitization frameworks to automatically redact sensitive data, use structured logging with field-level controls"
        logging_rule.alternative_remediation = "If automated sanitization is not available, manually review all logging statements, implement custom log filters, and ensure sensitive data is masked before logging"
        logging_rule.references = [
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
            "https://cwe.mitre.org/data/definitions/532.html"
        ]
        self.add_rule(logging_rule)
        
        # A07: Authentication failures
        auth_rule = RegexSecurityRule(
            rule_id="PY009",
            title="Weak Authentication",
            description="Potentially weak authentication implementation",
            severity=Severity.MEDIUM,
            owasp_category=RuleCategory.A07_AUTHENTICATION_FAILURES,
            patterns=[
                r'(?i)if\s+password\s*==\s*["\'][^"\']*["\']',
                r'(?i)user\s*==\s*["\']admin["\']',
                r'(?i)password\s*in\s*\[["\'][^"\']*["\']'
            ]
        )
        auth_rule.confidence = Confidence.LOW
        auth_rule.primary_remediation = "Implement proper authentication with secure password hashing (bcrypt, Argon2), multi-factor authentication, and robust session management"
        auth_rule.alternative_remediation = "If advanced authentication is not feasible, implement strong password policies, account lockout mechanisms, and secure session tokens with proper expiration"
        auth_rule.references = [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://cwe.mitre.org/data/definitions/287.html"
        ]
        self.add_rule(auth_rule)
    
    def parse_file(self, content: str, file_path: Path) -> Optional[ast.AST]:
        """
        Parse Python source code into an AST.
        
        Args:
            content (str): Python source code
            file_path (Path): Path to the source file
            
        Returns:
            ast.AST: Parsed AST or None if parsing failed
        """
        try:
            # Parse the Python code into an AST
            tree = ast.parse(content, filename=str(file_path))
            return tree
            
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return None
    
    def get_imports(self, tree: ast.AST) -> Set[str]:
        """
        Extract import statements from AST.
        
        Args:
            tree (ast.AST): Parsed AST
            
        Returns:
            set: Set of imported module names
        """
        imports = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
        
        return imports
    
    def analyze_dependencies(self, file_path: Path) -> List[str]:
        """
        Analyze Python dependencies for known vulnerabilities.
        
        Args:
            file_path (Path): Path to Python file or requirements.txt
            
        Returns:
            list: List of vulnerability warnings
        """
        warnings = []
        
        # This is a placeholder for dependency analysis
        # In a full implementation, this would check against vulnerability databases
        
        if file_path.name == 'requirements.txt':
            # Parse requirements file and check for known vulnerable versions
            try:
                content = file_path.read_text()
                # Simple check for some known vulnerable packages
                vulnerable_patterns = [
                    r'django\s*[<>=]*\s*[12]\.',  # Old Django versions
                    r'flask\s*[<>=]*\s*0\.',      # Very old Flask
                    r'requests\s*[<>=]*\s*2\.[0-5]\.',  # Old requests versions
                ]
                
                for pattern in vulnerable_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        warnings.append(f"Potentially vulnerable dependency detected in {file_path}")
                        
            except Exception as e:
                logger.error(f"Error analyzing dependencies in {file_path}: {e}")
        
        return warnings
    
    def get_function_definitions(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """
        Extract function definitions from AST for analysis.
        
        Args:
            tree (ast.AST): Parsed AST
            
        Returns:
            list: List of function definition information
        """
        functions = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_info = {
                    'name': node.name,
                    'line_number': getattr(node, 'lineno', 1),
                    'args': [arg.arg for arg in node.args.args],
                    'decorators': [self._get_decorator_name(dec) for dec in node.decorator_list],
                    'has_docstring': (len(node.body) > 0 and 
                                    isinstance(node.body[0], ast.Expr) and
                                    isinstance(node.body[0].value, ast.Constant)),
                    'complexity': self._calculate_complexity(node)
                }
                functions.append(func_info)
        
        return functions
    
    def _get_decorator_name(self, decorator: ast.AST) -> str:
        """Extract decorator name from AST node."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return decorator.attr
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name):
                return decorator.func.id
            elif isinstance(decorator.func, ast.Attribute):
                return decorator.func.attr
        return "unknown"
    
    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """
        Calculate cyclomatic complexity of a function.
        
        Args:
            node (ast.FunctionDef): Function definition node
            
        Returns:
            int: Cyclomatic complexity score
        """
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            # Count decision points
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
            elif isinstance(child, ast.comprehension):
                complexity += 1
        
        return complexity
    
    def detect_authentication_issues(self, tree: ast.AST, content: str) -> List[RuleMatch]:
        """
        Detect authentication-related security issues.
        
        Args:
            tree (ast.AST): Parsed AST
            content (str): Source code content
            
        Returns:
            list: List of authentication-related rule matches
        """
        matches = []
        
        for node in ast.walk(tree):
            # Check for hardcoded authentication bypass
            if isinstance(node, ast.If):
                matches.extend(self._check_auth_bypass(node))
            
            # Check for weak session handling
            elif isinstance(node, ast.Assign):
                matches.extend(self._check_session_issues(node))
        
        return matches
    
    def _check_auth_bypass(self, node: ast.If) -> List[RuleMatch]:
        """Check for potential authentication bypass patterns."""
        matches = []
        
        # Look for always-true conditions or weak checks
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            line, col = getattr(node, 'lineno', 1), getattr(node, 'col_offset', 0)
            matches.append(RuleMatch(
                rule_id="PY010",
                title="Authentication Bypass",
                description="Always-true condition in authentication check",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                owasp_category=RuleCategory.A07_AUTHENTICATION_FAILURES,
                line_number=line,
                column_number=col,
                remediation="Implement proper authentication logic"
            ))
        
        return matches
    
    def _check_session_issues(self, node: ast.Assign) -> List[RuleMatch]:
        """Check for session management issues."""
        matches = []
        
        # Look for session assignments with weak values
        for target in node.targets:
            if isinstance(target, ast.Attribute) and target.attr == 'session':
                if isinstance(node.value, ast.Constant):
                    line, col = getattr(node, 'lineno', 1), getattr(node, 'col_offset', 0)
                    matches.append(RuleMatch(
                        rule_id="PY011",
                        title="Weak Session Management",
                        description="Session value set to constant",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        owasp_category=RuleCategory.A07_AUTHENTICATION_FAILURES,
                        line_number=line,
                        column_number=col,
                        remediation="Use secure random session identifiers"
                    ))
        
        return matches
    
    def detect_path_traversal(self, tree: ast.AST, content: str) -> List[RuleMatch]:
        """
        Detect potential path traversal vulnerabilities.
        
        Args:
            tree (ast.AST): Parsed AST
            content (str): Source code content
            
        Returns:
            list: List of path traversal rule matches
        """
        matches = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_full_function_name(node.func)
                
                # Check file operations with user input
                if func_name in ['open', 'os.path.join', 'pathlib.Path']:
                    if self._has_user_input(node):
                        line, col = getattr(node, 'lineno', 1), getattr(node, 'col_offset', 0)
                        matches.append(RuleMatch(
                            rule_id="PY012",
                            title="Path Traversal Risk",
                            description=f"File operation with potential user input: {func_name}",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            owasp_category=RuleCategory.A01_BROKEN_ACCESS_CONTROL,
                            line_number=line,
                            column_number=col,
                            remediation="Validate and sanitize file paths, use os.path.join securely"
                        ))
        
        return matches
    
    def _get_full_function_name(self, func_node: ast.AST) -> str:
        """Get fully qualified function name."""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
            elif isinstance(func_node.value, ast.Attribute):
                parent = self._get_full_function_name(func_node.value)
                return f"{parent}.{func_node.attr}"
            else:
                return func_node.attr
        return ""
    
    def _has_user_input(self, node: ast.Call) -> bool:
        """Check if function call uses potential user input."""
        for arg in node.args:
            if isinstance(arg, ast.Name):
                # Variable names that suggest user input
                if any(term in arg.id.lower() for term in ['user', 'input', 'request', 'param']):
                    return True
            elif isinstance(arg, ast.Attribute):
                # Attribute access that might be user input
                if any(term in self._get_full_function_name(arg).lower() 
                      for term in ['request', 'form', 'args', 'json']):
                    return True
            elif isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                # String operations that might include user input
                return True
        
        return False
    
    def detect_xss_vulnerabilities(self, tree: ast.AST, content: str) -> List[RuleMatch]:
        """
        Detect potential XSS vulnerabilities in template rendering.
        
        Args:
            tree (ast.AST): Parsed AST
            content (str): Source code content
            
        Returns:
            list: List of XSS-related rule matches
        """
        matches = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_full_function_name(node.func)
                
                # Check template rendering functions
                if any(template_func in func_name.lower() 
                      for template_func in ['render', 'render_template', 'render_to_string']):
                    
                    if self._has_unescaped_content(node):
                        line, col = getattr(node, 'lineno', 1), getattr(node, 'col_offset', 0)
                        matches.append(RuleMatch(
                            rule_id="PY013",
                            title="Potential XSS Vulnerability",
                            description="Template rendering with potentially unescaped user content",
                            severity=Severity.HIGH,
                            confidence=Confidence.LOW,
                            owasp_category=RuleCategory.A03_INJECTION,
                            line_number=line,
                            column_number=col,
                            remediation="Ensure proper output encoding and escaping in templates"
                        ))
        
        return matches
    
    def _has_unescaped_content(self, node: ast.Call) -> bool:
        """Check if template rendering might have unescaped content."""
        # This is a simplified check - in practice, this would be more sophisticated
        for keyword in node.keywords:
            if keyword.arg and 'safe' in keyword.arg.lower():
                return True
        return False
    
    def detect_information_disclosure(self, tree: ast.AST, content: str) -> List[RuleMatch]:
        """
        Detect potential information disclosure vulnerabilities.
        
        Args:
            tree (ast.AST): Parsed AST
            content (str): Source code content
            
        Returns:
            list: List of information disclosure rule matches
        """
        matches = []
        
        for node in ast.walk(tree):
            # Check for exception handling that might leak information
            if isinstance(node, ast.ExceptHandler):
                matches.extend(self._check_exception_disclosure(node))
            
            # Check for debug prints
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == 'print':
                    matches.extend(self._check_debug_prints(node))
        
        return matches
    
    def _check_exception_disclosure(self, node: ast.ExceptHandler) -> List[RuleMatch]:
        """Check exception handlers for information disclosure."""
        matches = []
        
        # Look for exception details being exposed
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                if child.func.id in ['print', 'return', 'render']:
                    # Check if exception details are being returned/printed
                    for arg in child.args:
                        if isinstance(arg, ast.Name) and node.name and arg.id == node.name.id:
                            line, col = getattr(child, 'lineno', 1), getattr(child, 'col_offset', 0)
                            matches.append(RuleMatch(
                                rule_id="PY014",
                                title="Exception Information Disclosure",
                                description="Exception details exposed to user",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                owasp_category=RuleCategory.A05_SECURITY_MISCONFIGURATION,
                                line_number=line,
                                column_number=col,
                                remediation="Log detailed errors securely, return generic error messages to users"
                            ))
        
        return matches
    
    def _check_debug_prints(self, node: ast.Call) -> List[RuleMatch]:
        """Check for debug print statements."""
        matches = []
        
        # Check if print contains sensitive-looking information
        for arg in node.args:
            if isinstance(arg, ast.Name):
                if any(sensitive in arg.id.lower() 
                      for sensitive in ['password', 'token', 'secret', 'key', 'auth']):
                    line, col = getattr(node, 'lineno', 1), getattr(node, 'col_offset', 0)
                    matches.append(RuleMatch(
                        rule_id="PY015",
                        title="Sensitive Data in Debug Output",
                        description="Print statement may expose sensitive information",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        owasp_category=RuleCategory.A09_LOGGING_FAILURES,
                        line_number=line,
                        column_number=col,
                        remediation="Remove debug prints or ensure no sensitive data is logged"
                    ))
        
        return matches
    
    def analyze_file(self, file_path: Path, config: Any) -> FileAnalysisResult:
        """
        Analyze a Python file for security vulnerabilities.
        
        Args:
            file_path (Path): Path to the file to analyze
            config: Configuration object
            
        Returns:
            FileAnalysisResult: Analysis results
        """
        result = FileAnalysisResult(str(file_path), self.language_name)
        
        try:
            # Read file content
            content = safe_read_file(file_path)
            if not content:
                result.error = "Could not read file content"
                return result
            
            # Count lines of code
            result.lines_of_code = len([line for line in content.splitlines() if line.strip()])
            
            # Parse AST for AST-based rules
            parsed_data = self.parse_file(content, file_path)
            
            # Run all enabled rules
            for rule in self.get_enabled_rules():
                try:
                    matches = rule.check(content, file_path, parsed_data=parsed_data)
                    
                    for match in matches:
                        vulnerability = self._create_vulnerability_from_match(match, file_path, content)
                        if vulnerability and self._should_report_vulnerability(vulnerability, config):
                            result.add_vulnerability(vulnerability)
                            
                except Exception as e:
                    logger.error(f"Error running rule {rule.rule_id} on {file_path}: {e}")
            
            # Additional Python-specific analysis
            additional_matches = []
            
            if parsed_data:  # Only if AST parsing succeeded
                # Authentication issues
                additional_matches.extend(self.detect_authentication_issues(parsed_data, content))
                
                # Path traversal
                additional_matches.extend(self.detect_path_traversal(parsed_data, content))
                
                # XSS vulnerabilities
                additional_matches.extend(self.detect_xss_vulnerabilities(parsed_data, content))
                
                # Information disclosure
                additional_matches.extend(self.detect_information_disclosure(parsed_data, content))
            
            # Convert additional matches to vulnerabilities
            for match in additional_matches:
                vulnerability = self._create_vulnerability_from_match(match, file_path, content)
                if vulnerability and self._should_report_vulnerability(vulnerability, config):
                    result.add_vulnerability(vulnerability)
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            result.error = str(e)
        
        return result
    
    def _analyze_security_imports(self, imports: Set[str], result: 'FileAnalysisResult', 
                                file_path: Path) -> None:
        """Analyze imports for security implications."""
        
        # Check for potentially dangerous imports
        dangerous_imports = {
            'subprocess': "Command execution capabilities",
            'os': "System operations access", 
            'pickle': "Insecure deserialization risk",
            'eval': "Dynamic code execution",
            'exec': "Dynamic code execution"
        }
        
        for imp in imports:
            if imp in dangerous_imports:
                # This would create informational findings about risky imports
                logger.debug(f"Potentially risky import detected in {file_path}: {imp}")
    
    def _analyze_function_security(self, functions: List[Dict[str, Any]], 
                                 result: 'FileAnalysisResult', file_path: Path) -> None:
        """Analyze function definitions for security issues."""
        
        for func in functions:
            # Check for functions with high complexity (potential security risk)
            if func['complexity'] > 15:
                logger.debug(f"High complexity function detected: {func['name']} "
                           f"(complexity: {func['complexity']}) in {file_path}")
            
            # Check for functions without docstrings (documentation issue)
            if not func['has_docstring'] and not func['name'].startswith('_'):
                logger.debug(f"Public function without docstring: {func['name']} in {file_path}")
    
    def get_analyzer_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about the Python analyzer.
        
        Returns:
            dict: Analyzer statistics and capabilities
        """
        enabled_rules = self.get_enabled_rules()
        category_counts = self.get_rule_count_by_category()
        
        return {
            'language': self.language_name,
            'file_extensions': self.file_extensions,
            'total_rules': len(self.rules),
            'enabled_rules': len(enabled_rules),
            'rules_by_category': category_counts,
            'supported_owasp_categories': self.get_supported_rules(),
            'ast_based_rules': len([r for r in self.rules if isinstance(r, ASTSecurityRule)]),
            'regex_based_rules': len([r for r in self.rules if isinstance(r, RegexSecurityRule)]),
            'rule_details': [
                {
                    'rule_id': rule.rule_id,
                    'title': rule.title,
                    'severity': rule.severity.value,
                    'category': rule.owasp_category.value,
                    'enabled': rule.is_enabled(),
                    'type': 'AST' if isinstance(rule, ASTSecurityRule) else 'Regex'
                }
                for rule in self.rules
            ]
        }

    def can_analyze(self, file_path: Path) -> bool:
        """
        Check if this analyzer can process the given file.
        
        Args:
            file_path (Path): Path to the file to check
            
        Returns:
            bool: True if this analyzer can process the file
        """
        if not file_path.exists() or not file_path.is_file():
            return False
        
        # Check file extension
        file_extension = file_path.suffix.lower()
        return file_extension in self.file_extensions
    
    def get_supported_rules(self) -> List[str]:
        """
        Get list of OWASP categories this analyzer can detect.
        
        Returns:
            list: List of OWASP category IDs
        """
        categories = set()
        for rule in self.rules:
            categories.add(rule.owasp_category.value)
        return sorted(list(categories))