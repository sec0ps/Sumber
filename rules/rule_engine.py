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

import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class RuleExecutionStatus(Enum):
    """Status of rule execution."""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    ERROR = "error"

class RuleType(Enum):
    """Types of security rules."""
    REGEX = "regex"
    AST = "ast"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"

@dataclass
class RuleExecutionContext:
    """
    Context information for rule execution.
    
    Contains all the information needed for a rule to analyze code,
    including source content, parsed data, configuration, and metadata.
    """
    file_path: Path
    content: str
    language: str
    parsed_data: Any = None
    config: Any = None
    file_size: int = 0
    line_count: int = 0
    encoding: str = "utf-8"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_lines(self) -> List[str]:
        """Get content split into lines."""
        return self.content.splitlines()
    
    def get_line(self, line_number: int) -> Optional[str]:
        """Get a specific line by number (1-based)."""
        lines = self.get_lines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return None
    
    def get_line_range(self, start_line: int, end_line: int) -> List[str]:
        """Get a range of lines (1-based, inclusive)."""
        lines = self.get_lines()
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), end_line)
        return lines[start_idx:end_idx]

@dataclass
class RuleExecutionResult:
    """
    Result of executing a security rule.
    
    Contains the matches found, execution metadata, and any errors
    that occurred during rule execution.
    """
    rule_id: str
    status: RuleExecutionStatus
    matches: List[Any] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def has_matches(self) -> bool:
        """Check if any matches were found."""
        return len(self.matches) > 0
    
    @property
    def match_count(self) -> int:
        """Get number of matches found."""
        return len(self.matches)
    
    @property
    def is_successful(self) -> bool:
        """Check if rule execution was successful."""
        return self.status == RuleExecutionStatus.SUCCESS

class RuleValidator:
    """
    Validates security rule definitions and configurations.
    
    Ensures rules are properly defined with required fields,
    valid patterns, and correct OWASP mappings.
    """
    
    REQUIRED_FIELDS = {
        'rule_id', 'title', 'description', 'severity', 'owasp_category'
    }
    
    VALID_SEVERITIES = {'low', 'medium', 'high', 'critical'}
    VALID_CONFIDENCES = {'low', 'medium', 'high'}
    VALID_OWASP_CATEGORIES = {f'A{i:02d}' for i in range(1, 11)}
    
    def __init__(self):
        self.validation_errors = []
        self.validation_warnings = []
    
    def validate_rule(self, rule: Any) -> bool:
        """
        Validate a security rule definition.
        
        Args:
            rule: Rule object to validate
            
        Returns:
            bool: True if rule is valid
        """
        self.validation_errors.clear()
        self.validation_warnings.clear()
        
        try:
            # Check required fields
            self._check_required_fields(rule)
            
            # Validate field values
            self._validate_rule_id(rule)
            self._validate_severity(rule)
            self._validate_owasp_category(rule)
            self._validate_confidence(rule)
            
            # Check rule-specific validation
            self._validate_rule_specific(rule)
            
            return len(self.validation_errors) == 0
            
        except Exception as e:
            self.validation_errors.append(f"Validation error: {str(e)}")
            return False
    
    def _check_required_fields(self, rule: Any) -> None:
        """Check that all required fields are present."""
        for field in self.REQUIRED_FIELDS:
            if not hasattr(rule, field) or getattr(rule, field) is None:
                self.validation_errors.append(f"Missing required field: {field}")
    
    def _validate_rule_id(self, rule: Any) -> None:
        """Validate rule ID format."""
        if hasattr(rule, 'rule_id'):
            rule_id = rule.rule_id
            if not isinstance(rule_id, str) or not rule_id.strip():
                self.validation_errors.append("Rule ID must be a non-empty string")
            elif len(rule_id) > 50:
                self.validation_errors.append("Rule ID must be 50 characters or less")
            elif not rule_id.replace('_', '').replace('-', '').isalnum():
                self.validation_warnings.append("Rule ID should contain only alphanumeric characters, hyphens, and underscores")
    
    def _validate_severity(self, rule: Any) -> None:
        """Validate severity level."""
        if hasattr(rule, 'severity'):
            severity = getattr(rule.severity, 'value', rule.severity)
            if severity not in self.VALID_SEVERITIES:
                self.validation_errors.append(f"Invalid severity: {severity}. Must be one of {self.VALID_SEVERITIES}")
    
    def _validate_owasp_category(self, rule: Any) -> None:
        """Validate OWASP category."""
        if hasattr(rule, 'owasp_category'):
            category = getattr(rule.owasp_category, 'value', rule.owasp_category)
            if category not in self.VALID_OWASP_CATEGORIES:
                self.validation_errors.append(f"Invalid OWASP category: {category}. Must be one of {self.VALID_OWASP_CATEGORIES}")
    
    def _validate_confidence(self, rule: Any) -> None:
        """Validate confidence level."""
        if hasattr(rule, 'confidence'):
            confidence = getattr(rule.confidence, 'value', rule.confidence)
            if confidence not in self.VALID_CONFIDENCES:
                self.validation_errors.append(f"Invalid confidence: {confidence}. Must be one of {self.VALID_CONFIDENCES}")
    
    def _validate_rule_specific(self, rule: Any) -> None:
        """Validate rule-specific requirements."""
        # Check for regex rules
        if hasattr(rule, 'patterns'):
            if not rule.patterns or not isinstance(rule.patterns, (list, tuple)):
                self.validation_errors.append("Regex rules must have a non-empty patterns list")
        
        # Check for AST rules
        if hasattr(rule, 'check_ast'):
            if not callable(getattr(rule, 'check_ast')):
                self.validation_errors.append("AST rules must implement check_ast method")
    
    def get_validation_report(self) -> Dict[str, List[str]]:
        """Get validation errors and warnings."""
        return {
            'errors': self.validation_errors.copy(),
            'warnings': self.validation_warnings.copy()
        }

class RuleManager:
    """
    Manages collections of security rules.
    
    Provides functionality to load, validate, enable/disable,
    and organize security rules by category and type.
    """
    
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.rules_by_category: Dict[str, List[Any]] = {}
        self.rules_by_type: Dict[RuleType, List[Any]] = {rule_type: [] for rule_type in RuleType}
        self.validator = RuleValidator()
    
    def add_rule(self, rule: Any) -> bool:
        """
        Add a security rule to the manager.
        
        Args:
            rule: Security rule to add
            
        Returns:
            bool: True if rule was added successfully
        """
        try:
            # Validate the rule
            if not self.validator.validate_rule(rule):
                validation_report = self.validator.get_validation_report()
                logger.error(f"Rule validation failed for {getattr(rule, 'rule_id', 'unknown')}: {validation_report['errors']}")
                return False
            
            rule_id = rule.rule_id
            
            # Check for duplicate rule IDs
            if rule_id in self.rules:
                logger.warning(f"Rule {rule_id} already exists, replacing...")
            
            # Add to main registry
            self.rules[rule_id] = rule
            
            # Add to category index
            category = getattr(rule.owasp_category, 'value', rule.owasp_category)
            if category not in self.rules_by_category:
                self.rules_by_category[category] = []
            if rule not in self.rules_by_category[category]:
                self.rules_by_category[category].append(rule)
            
            # Add to type index
            rule_type = self._determine_rule_type(rule)
            if rule not in self.rules_by_type[rule_type]:
                self.rules_by_type[rule_type].append(rule)
            
            logger.debug(f"Added rule: {rule_id} ({category}, {rule_type.value})")
            return True
            
        except Exception as e:
            logger.error(f"Error adding rule: {str(e)}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a rule by ID.
        
        Args:
            rule_id (str): ID of rule to remove
            
        Returns:
            bool: True if rule was removed
        """
        if rule_id not in self.rules:
            return False
        
        rule = self.rules[rule_id]
        
        # Remove from main registry
        del self.rules[rule_id]
        
        # Remove from category index
        category = getattr(rule.owasp_category, 'value', rule.owasp_category)
        if category in self.rules_by_category and rule in self.rules_by_category[category]:
            self.rules_by_category[category].remove(rule)
        
        # Remove from type index
        rule_type = self._determine_rule_type(rule)
        if rule in self.rules_by_type[rule_type]:
            self.rules_by_type[rule_type].remove(rule)
        
        logger.debug(f"Removed rule: {rule_id}")
        return True
    
    def get_rule(self, rule_id: str) -> Optional[Any]:
        """Get a rule by ID."""
        return self.rules.get(rule_id)
    
    def get_rules_by_category(self, category: str) -> List[Any]:
        """Get all rules for a specific OWASP category."""
        return self.rules_by_category.get(category, []).copy()
    
    def get_rules_by_type(self, rule_type: RuleType) -> List[Any]:
        """Get all rules of a specific type."""
        return self.rules_by_type[rule_type].copy()
    
    def get_enabled_rules(self) -> List[Any]:
        """Get all enabled rules."""
        return [rule for rule in self.rules.values() if getattr(rule, 'enabled', True)]
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID."""
        rule = self.get_rule(rule_id)
        if rule and hasattr(rule, 'set_enabled'):
            rule.set_enabled(True)
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID."""
        rule = self.get_rule(rule_id)
        if rule and hasattr(rule, 'set_enabled'):
            rule.set_enabled(False)
            return True
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about managed rules."""
        enabled_rules = self.get_enabled_rules()
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': len(enabled_rules),
            'rules_by_category': {cat: len(rules) for cat, rules in self.rules_by_category.items()},
            'rules_by_type': {rule_type.value: len(rules) for rule_type, rules in self.rules_by_type.items()},
            'categories': list(self.rules_by_category.keys()),
            'rule_ids': list(self.rules.keys())
        }
    
    def _determine_rule_type(self, rule: Any) -> RuleType:
        """Determine the type of a rule based on its characteristics."""
        if hasattr(rule, 'patterns'):
            return RuleType.REGEX
        elif hasattr(rule, 'check_ast'):
            return RuleType.AST
        elif hasattr(rule, 'analyze_semantics'):
            return RuleType.SEMANTIC
        else:
            return RuleType.HYBRID

class RuleEngine:
    """
    Core rule processing engine.
    
    Executes security rules against code, manages execution context,
    and aggregates results from multiple rules.
    """
    
    def __init__(self, rule_manager: Optional[RuleManager] = None):
        self.rule_manager = rule_manager or RuleManager()
        self.execution_timeout = 30.0  # seconds
        self.max_matches_per_rule = 1000
        
    def execute_rules(self, context: RuleExecutionContext, 
                     rule_filter: Optional[Callable[[Any], bool]] = None) -> List[RuleExecutionResult]:
        """
        Execute all applicable rules against the given context.
        
        Args:
            context (RuleExecutionContext): Execution context
            rule_filter (callable, optional): Function to filter which rules to execute
            
        Returns:
            list: List of RuleExecutionResult objects
        """
        results = []
        enabled_rules = self.rule_manager.get_enabled_rules()
        
        # Apply filter if provided
        if rule_filter:
            enabled_rules = [rule for rule in enabled_rules if rule_filter(rule)]
        
        logger.debug(f"Executing {len(enabled_rules)} rules against {context.file_path}")
        
        for rule in enabled_rules:
            try:
                result = self._execute_single_rule(rule, context)
                results.append(result)
                
                # Log significant findings
                if result.has_matches:
                    logger.info(f"Rule {rule.rule_id} found {result.match_count} matches in {context.file_path}")
                
            except Exception as e:
                # Create error result for failed rule execution
                error_result = RuleExecutionResult(
                    rule_id=getattr(rule, 'rule_id', 'unknown'),
                    status=RuleExecutionStatus.ERROR,
                    error_message=str(e)
                )
                results.append(error_result)
                logger.error(f"Error executing rule {getattr(rule, 'rule_id', 'unknown')}: {str(e)}")
        
        return results
    
    def _execute_single_rule(self, rule: Any, context: RuleExecutionContext) -> RuleExecutionResult:
        """
        Execute a single rule against the context.
        
        Args:
            rule: Security rule to execute
            context (RuleExecutionContext): Execution context
            
        Returns:
            RuleExecutionResult: Execution result
        """
        start_time = time.time()
        rule_id = getattr(rule, 'rule_id', 'unknown')
        
        try:
            # Check if rule is enabled
            if not getattr(rule, 'enabled', True):
                return RuleExecutionResult(
                    rule_id=rule_id,
                    status=RuleExecutionStatus.SKIPPED
                )
            
            # Execute the rule with timeout protection
            matches = self._execute_rule_with_timeout(rule, context)
            
            # Limit number of matches to prevent memory issues
            if len(matches) > self.max_matches_per_rule:
                matches = matches[:self.max_matches_per_rule]
                warning_msg = f"Rule {rule_id} generated too many matches, limited to {self.max_matches_per_rule}"
                logger.warning(warning_msg)
                warnings = [warning_msg]
            else:
                warnings = []
            
            execution_time = time.time() - start_time
            
            return RuleExecutionResult(
                rule_id=rule_id,
                status=RuleExecutionStatus.SUCCESS,
                matches=matches,
                execution_time=execution_time,
                warnings=warnings
            )
            
        except TimeoutError:
            return RuleExecutionResult(
                rule_id=rule_id,
                status=RuleExecutionStatus.TIMEOUT,
                execution_time=self.execution_timeout,
                error_message=f"Rule execution timed out after {self.execution_timeout} seconds"
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return RuleExecutionResult(
                rule_id=rule_id,
                status=RuleExecutionStatus.FAILED,
                execution_time=execution_time,
                error_message=str(e)
            )
    
    def _execute_rule_with_timeout(self, rule: Any, context: RuleExecutionContext) -> List[Any]:
        """
        Execute rule with timeout protection.
        
        Args:
            rule: Security rule to execute
            context (RuleExecutionContext): Execution context
            
        Returns:
            list: List of matches found by the rule
        """
        # This is a simplified timeout implementation
        # In production, you might want to use threading or async execution
        try:
            if hasattr(rule, 'check'):
                # Standard rule interface
                matches = rule.check(
                    content=context.content,
                    file_path=context.file_path,
                    parsed_data=context.parsed_data,
                    config=context.config
                )
            elif hasattr(rule, 'analyze'):
                # Alternative rule interface
                matches = rule.analyze(context)
            else:
                raise AttributeError(f"Rule {getattr(rule, 'rule_id', 'unknown')} has no check() or analyze() method")
            
            return matches if matches else []
            
        except Exception as e:
            logger.error(f"Error in rule execution: {str(e)}")
            raise
    
    def execute_rules_by_category(self, context: RuleExecutionContext, 
                                 category: str) -> List[RuleExecutionResult]:
        """
        Execute all rules for a specific OWASP category.
        
        Args:
            context (RuleExecutionContext): Execution context
            category (str): OWASP category (e.g., 'A01')
            
        Returns:
            list: List of RuleExecutionResult objects
        """
        category_rules = self.rule_manager.get_rules_by_category(category)
        enabled_rules = [rule for rule in category_rules if getattr(rule, 'enabled', True)]
        
        results = []
        for rule in enabled_rules:
            result = self._execute_single_rule(rule, context)
            results.append(result)
        
        return results
    
    def get_execution_summary(self, results: List[RuleExecutionResult]) -> Dict[str, Any]:
        """
        Generate summary statistics for rule execution results.
        
        Args:
            results (list): List of RuleExecutionResult objects
            
        Returns:
            dict: Summary statistics
        """
        total_rules = len(results)
        successful_rules = len([r for r in results if r.is_successful])
        total_matches = sum(r.match_count for r in results)
        total_execution_time = sum(r.execution_time for r in results)
        
        status_counts = {}
        for status in RuleExecutionStatus:
            status_counts[status.value] = len([r for r in results if r.status == status])
        
        rules_with_matches = [r for r in results if r.has_matches]
        
        return {
            'total_rules_executed': total_rules,
            'successful_rules': successful_rules,
            'total_matches_found': total_matches,
            'total_execution_time': total_execution_time,
            'average_execution_time': total_execution_time / total_rules if total_rules > 0 else 0,
            'status_breakdown': status_counts,
            'rules_with_matches': len(rules_with_matches),
            'match_rate': len(rules_with_matches) / total_rules if total_rules > 0 else 0
        }