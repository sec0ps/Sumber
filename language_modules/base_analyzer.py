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
import time
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union, Iterator
from dataclasses import dataclass
from enum import Enum

from core import FileAnalysisResult, Vulnerability
from utils.file_utils import safe_read_file, extract_code_snippet

logger = logging.getLogger(__name__)

class RuleCategory(Enum):
    """OWASP Top 10 categories for vulnerability classification."""
    A01_BROKEN_ACCESS_CONTROL = "A01"
    A02_CRYPTOGRAPHIC_FAILURES = "A02" 
    A03_INJECTION = "A03"
    A04_INSECURE_DESIGN = "A04"
    A05_SECURITY_MISCONFIGURATION = "A05"
    A06_VULNERABLE_COMPONENTS = "A06"
    A07_AUTHENTICATION_FAILURES = "A07"
    A08_INTEGRITY_FAILURES = "A08"
    A09_LOGGING_FAILURES = "A09"
    A10_SSRF = "A10"

class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Confidence(Enum):
    """Confidence levels for vulnerability detection."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class RuleMatch:
    """
    Represents a match found by a security rule.
    
    Contains all information needed to create a Vulnerability object,
    including location, context, and metadata about the match.
    """
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    owasp_category: RuleCategory
    line_number: int
    column_number: int = 0
    end_line_number: Optional[int] = None
    end_column_number: Optional[int] = None
    matched_text: str = ""
    context: Dict[str, Any] = None
    remediation: str = ""
    references: List[str] = None
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}
        if self.references is None:
            self.references = []

class BaseSecurityRule(ABC):
    """
    Abstract base class for security detection rules.
    
    Each rule represents a specific vulnerability pattern that can be
    detected through static analysis of source code.
    """
    
    def __init__(self, rule_id: str, title: str, description: str, 
                 severity: Severity, owasp_category: RuleCategory):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.owasp_category = owasp_category
        self.enabled = True
        self.confidence = Confidence.MEDIUM
    
    @abstractmethod
    def check(self, content: str, file_path: Path, **kwargs) -> List[RuleMatch]:
        """
        Check source code for vulnerabilities matching this rule.
        
        Args:
            content (str): Source code content to analyze
            file_path (Path): Path to the source file
            **kwargs: Additional context (AST, config, etc.)
            
        Returns:
            list: List of RuleMatch objects for found vulnerabilities
        """
        pass
    
    def is_enabled(self) -> bool:
        """Check if this rule is enabled."""
        return self.enabled
    
    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable this rule."""
        self.enabled = enabled
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get rule metadata."""
        return {
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'owasp_category': self.owasp_category.value,
            'confidence': self.confidence.value,
            'enabled': self.enabled
        }

class RegexSecurityRule(BaseSecurityRule):
    """
    Security rule based on regular expression patterns.
    
    Provides a simple way to implement rules that look for specific
    patterns in source code using regular expressions.
    """
    
    def __init__(self, rule_id: str, title: str, description: str,
                 severity: Severity, owasp_category: RuleCategory,
                 patterns: List[str], flags: int = re.MULTILINE):
        super().__init__(rule_id, title, description, severity, owasp_category)
        self.patterns = [re.compile(pattern, flags) for pattern in patterns]
        self.flags = flags
    
    def check(self, content: str, file_path: Path, **kwargs) -> List[RuleMatch]:
        """
        Check content using regex patterns.
        
        Args:
            content (str): Source code content
            file_path (Path): Path to source file
            **kwargs: Additional context
            
        Returns:
            list: List of RuleMatch objects
        """
        matches = []
        lines = content.splitlines()
        
        for pattern in self.patterns:
            for match in pattern.finditer(content):
                # Calculate line and column numbers
                line_start = content.count('\n', 0, match.start()) + 1
                col_start = match.start() - content.rfind('\n', 0, match.start()) - 1
                
                # Get the matched text
                matched_text = match.group(0)
                
                # Create context information
                context = {
                    'pattern': pattern.pattern,
                    'full_match': matched_text,
                    'groups': match.groups(),
                    'groupdict': match.groupdict()
                }
                
                rule_match = RuleMatch(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=self.description,
                    severity=self.severity,
                    confidence=self.confidence,
                    owasp_category=self.owasp_category,
                    line_number=line_start,
                    column_number=col_start,
                    matched_text=matched_text,
                    context=context
                )
                
                matches.append(rule_match)
        
        return matches