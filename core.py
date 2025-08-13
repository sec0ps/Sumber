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

import os
import time
import logging
import yaml
import importlib
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Type, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# =============================================================================
# DATA MODELS
# =============================================================================

class Vulnerability:
    """Represents a single security vulnerability found in code."""
    
    def __init__(self, 
                 title: str,
                 description: str,
                 severity: str,
                 owasp_category: str,
                 line_number: int,
                 column_number: int = 0,
                 code_snippet: str = "",
                 filename: str = ""):
        self.title = title
        self.description = description
        self.severity = severity.lower()
        self.owasp_category = owasp_category
        self.line_number = line_number
        self.column_number = column_number
        self.code_snippet = code_snippet
        self.filename = filename
        self.confidence: str = "medium"  # low, medium, high
        
        # Enhanced OWASP-based fields
        self.owasp_category_name: str = ""
        self.cwe_ids: List[int] = []
        self.primary_remediation: str = ""
        self.alternative_remediation: str = ""
        self.references: List[str] = []
        self.tags: List[str] = []
        self.pattern_id: str = ""
        
        # For code highlighting
        self.highlighted_code: str = ""
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary format."""
        return {
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'owasp_category': self.owasp_category,
            'owasp_category_name': self.owasp_category_name,
            'line_number': self.line_number,
            'column_number': self.column_number,
            'code_snippet': self.code_snippet,
            'highlighted_code': self.highlighted_code,
            'filename': self.filename,
            'confidence': self.confidence,
            'cwe_ids': self.cwe_ids,
            'primary_remediation': self.primary_remediation,
            'alternative_remediation': self.alternative_remediation,
            'references': self.references,
            'tags': self.tags,
            'pattern_id': self.pattern_id
        }
    
    def enrich_with_owasp_pattern(self, pattern) -> None:
        """Enrich vulnerability with OWASP pattern data."""
        if pattern:
            self.owasp_category_name = pattern.name
            self.cwe_ids = pattern.cwe_ids.copy()
            self.primary_remediation = pattern.primary_remediation
            self.alternative_remediation = pattern.alternative_remediation
            self.references = pattern.references.copy()
            self.tags = list(pattern.tags)
            self.pattern_id = pattern.pattern_id
            # Use the richer description from the pattern
            if pattern.description:
                self.description = pattern.description

class FileAnalysisResult:
    """Contains the results of analyzing a single file."""
    
    def __init__(self, filename: str, language: str):
        self.filename = filename
        self.language = language
        self.vulnerabilities: List[Vulnerability] = []
        self.analysis_duration: float = 0.0
        self.error: Optional[str] = None
        self.file_size: int = 0
        self.lines_of_code: int = 0
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to the results."""
        self.vulnerabilities.append(vulnerability)
    
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.vulnerabilities) > 0
    
    def get_vulnerability_count_by_severity(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity level."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts

class AnalysisResults:
    """Contains the complete results of a security analysis session."""
    
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.file_results: List[FileAnalysisResult] = []
        self.total_duration: float = 0.0
        self.start_time: Optional[str] = None
        self.end_time: Optional[str] = None
        self.analyzer_config: Optional[Dict] = None
    
    def add_file_result(self, result: FileAnalysisResult) -> None:
        """Add file analysis result."""
        self.file_results.append(result)
    
    def get_total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities found."""
        return sum(len(result.vulnerabilities) for result in self.file_results)
    
    def get_vulnerabilities_by_severity(self) -> Dict[str, int]:
        """Get vulnerability counts by severity across all files."""
        total_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for result in self.file_results:
            file_counts = result.get_vulnerability_count_by_severity()
            for severity, count in file_counts.items():
                total_counts[severity] += count
        
        return total_counts
    
    def get_files_with_vulnerabilities(self) -> List[FileAnalysisResult]:
        """Get only files that have vulnerabilities."""
        return [result for result in self.file_results if result.has_vulnerabilities()]

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Configuration management for the Security Code Analyzer."""
    
    # Default configuration values
    DEFAULT_CONFIG = {
        'analysis': {
            'min_severity': 'medium',
            'include_tests': False,
            'max_file_size_mb': 10,
            'timeout_per_file_seconds': 30
        },
        'exclusions': {
            'patterns': [
                '*.pyc',
                '__pycache__/*',
                '.git/*',
                '.svn/*',
                'node_modules/*',
                'venv/*',
                'env/*',
                '.env/*',
                'dist/*',
                'build/*'
            ],
            'test_patterns': [
                'test_*.py',
                '*_test.py',
                'tests/*',
                'spec/*'
            ]
        },
        'languages': {
            'python': {
                'enabled': True,
                'file_extensions': ['.py'],
                'max_ast_depth': 100
            }
        },
        'rules': {
            'owasp_categories': {
                'A01': 'Broken Access Control',
                'A02': 'Cryptographic Failures', 
                'A03': 'Injection',
                'A04': 'Insecure Design',
                'A05': 'Security Misconfiguration',
                'A06': 'Vulnerable and Outdated Components',
                'A07': 'Identification and Authentication Failures',
                'A08': 'Software and Data Integrity Failures',
                'A09': 'Security Logging and Monitoring Failures',
                'A10': 'Server-Side Request Forgery'
            }
        }
    }
    
    SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical']
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration."""
        self._config = self._load_default_config()
        
        if config_path:
            self._load_config_file(config_path)
        
        self._validate_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load the default configuration."""
        import copy
        return copy.deepcopy(self.DEFAULT_CONFIG)
    
    def _load_config_file(self, config_path: str) -> None:
        """Load configuration from YAML file."""
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f)
            
            if user_config:
                self._merge_config(user_config)
                logger.info(f"Loaded configuration from: {config_path}")
            
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Invalid YAML in config file {config_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Error loading config file {config_path}: {str(e)}")
            raise
    
    def _merge_config(self, user_config: Dict[str, Any]) -> None:
        """Merge user configuration with defaults."""
        def merge_dicts(base_dict: Dict, update_dict: Dict) -> Dict:
            """Recursively merge dictionaries."""
            for key, value in update_dict.items():
                if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                    merge_dicts(base_dict[key], value)
                else:
                    base_dict[key] = value
            return base_dict
        
        merge_dicts(self._config, user_config)
    
    def _validate_config(self) -> None:
        """Validate configuration values."""
        # Validate severity level
        min_severity = self.get_min_severity()
        if min_severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid min_severity: {min_severity}. "
                           f"Must be one of: {', '.join(self.SEVERITY_LEVELS)}")
        
        # Validate file size limit
        max_size = self.get_max_file_size_mb()
        if not isinstance(max_size, (int, float)) or max_size <= 0:
            raise ValueError(f"Invalid max_file_size_mb: {max_size}. Must be a positive number.")
        
        # Validate timeout
        timeout = self.get_timeout_per_file()
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError(f"Invalid timeout_per_file_seconds: {timeout}. Must be a positive number.")
        
        logger.debug("Configuration validation passed")
    
    # Getter methods for configuration values
    def get_min_severity(self) -> str:
        """Get minimum severity level for reporting."""
        return self._config['analysis']['min_severity']
    
    def set_min_severity(self, severity: str) -> None:
        """Set minimum severity level for reporting."""
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {severity}")
        self._config['analysis']['min_severity'] = severity
    
    def get_include_tests(self) -> bool:
        """Check if test files should be included in analysis."""
        return self._config['analysis']['include_tests']
    
    def set_include_tests(self, include: bool) -> None:
        """Set whether to include test files in analysis."""
        self._config['analysis']['include_tests'] = include
    
    def get_max_file_size_mb(self) -> float:
        """Get maximum file size limit in MB."""
        return self._config['analysis']['max_file_size_mb']
    
    def get_timeout_per_file(self) -> int:
        """Get timeout per file in seconds."""
        return self._config['analysis']['timeout_per_file_seconds']
    
    def get_exclusion_patterns(self) -> List[str]:
        """Get file exclusion patterns."""
        patterns = self._config['exclusions']['patterns'].copy()
        
        # Add test patterns if tests are excluded
        if not self.get_include_tests():
            patterns.extend(self._config['exclusions']['test_patterns'])
        
        return patterns
    
    def set_exclusions(self, patterns: List[str]) -> None:
        """Add additional exclusion patterns."""
        self._config['exclusions']['patterns'].extend(patterns)
    
    def get_supported_languages(self) -> List[str]:
        """Get list of enabled languages."""
        return [
            lang for lang, config in self._config['languages'].items()
            if config.get('enabled', False)
        ]
    
    def get_language_config(self, language: str) -> Dict[str, Any]:
        """Get configuration for a specific language."""
        return self._config['languages'].get(language, {})
    
    def get_file_extensions(self, language: str) -> List[str]:
        """Get file extensions for a specific language."""
        lang_config = self.get_language_config(language)
        return lang_config.get('file_extensions', [])
    
    def is_language_enabled(self, language: str) -> bool:
        """Check if a language is enabled for analysis."""
        lang_config = self.get_language_config(language)
        return lang_config.get('enabled', False)
    
    def should_exclude_file(self, file_path: Path) -> bool:
        """Check if a file should be excluded from analysis."""
        import fnmatch
        
        file_str = str(file_path)
        exclusion_patterns = self.get_exclusion_patterns()
        
        for pattern in exclusion_patterns:
            if fnmatch.fnmatch(file_str, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                return True
        
        return False
    
    def get_severity_order(self) -> Dict[str, int]:
        """Get severity levels with numeric ordering."""
        return {
            'low': 1,
            'medium': 2, 
            'high': 3,
            'critical': 4
        }
    
    def meets_severity_threshold(self, severity: str) -> bool:
        """Check if a severity level meets the minimum threshold."""
        severity_order = self.get_severity_order()
        min_severity_num = severity_order.get(self.get_min_severity(), 2)
        severity_num = severity_order.get(severity, 1)
        
        return severity_num >= min_severity_num
    
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary."""
        import copy
        return copy.deepcopy(self._config)

# =============================================================================
# LANGUAGE ANALYZER BASE CLASS
# =============================================================================

class LanguageAnalyzer(ABC):
    """Abstract base class for language-specific security analyzers."""
    
    @property
    @abstractmethod
    def language_name(self) -> str:
        """Return the name of the programming language this analyzer handles."""
        pass
    
    @property
    @abstractmethod
    def file_extensions(self) -> List[str]:
        """Return list of file extensions this analyzer can process."""
        pass
    
    @abstractmethod
    def can_analyze(self, file_path: Path) -> bool:
        """Check if this analyzer can process the given file."""
        pass
    
    @abstractmethod
    def analyze_file(self, file_path: Path, config: Any) -> FileAnalysisResult:
        """Analyze a single file for security vulnerabilities."""
        pass
    
    @abstractmethod
    def get_supported_rules(self) -> List[str]:
        """Get list of OWASP categories this analyzer can detect."""
        pass

# =============================================================================
# LANGUAGE REGISTRY
# =============================================================================

class LanguageRegistry:
    """Registry for language-specific analyzers."""
    
    def __init__(self):
        self._analyzers: Dict[str, Type[LanguageAnalyzer]] = {}
        self._instances: Dict[str, LanguageAnalyzer] = {}
        self._module_paths = ['language_modules']
        
    def register_analyzer(self, analyzer_class: Type[LanguageAnalyzer]) -> None:
        """Register a language analyzer class."""
        if not issubclass(analyzer_class, LanguageAnalyzer):
            raise ValueError(f"Analyzer must inherit from LanguageAnalyzer: {analyzer_class}")
        
        # Create temporary instance to get language name
        temp_instance = analyzer_class()
        language_name = temp_instance.language_name
        
        self._analyzers[language_name] = analyzer_class
        logger.info(f"Registered analyzer for language: {language_name}")
    
    def get_analyzer(self, language: str) -> Optional[LanguageAnalyzer]:
        """Get analyzer instance for a specific language."""
        if language not in self._instances:
            if language in self._analyzers:
                self._instances[language] = self._analyzers[language]()
            else:
                return None
        
        return self._instances[language]
    
    def get_supported_languages(self) -> List[str]:
        """Get list of all registered languages."""
        return list(self._analyzers.keys())
    
    def discover_analyzers(self) -> None:
        """Automatically discover and load language analyzer modules."""
        for module_path in self._module_paths:
            self._discover_in_path(module_path)
    
    def _discover_in_path(self, module_path: str) -> None:
        """Discover analyzers in a specific module path."""
        try:
            base_path = Path(module_path)
            if not base_path.exists():
                logger.debug(f"Module path does not exist: {module_path}")
                return
            
            # Look for language subdirectories
            for lang_dir in base_path.iterdir():
                if lang_dir.is_dir() and not lang_dir.name.startswith('_'):
                    self._load_language_module(module_path, lang_dir.name)
                    
        except Exception as e:
            logger.error(f"Error discovering analyzers in {module_path}: {str(e)}")
    
    def _load_language_module(self, module_path: str, language: str) -> None:
        """Load a specific language analyzer module."""
        try:
            module_name = f"{module_path}.{language}.analyzer"
            module = importlib.import_module(module_name)
            
            # Look for analyzer class in the module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, LanguageAnalyzer) and 
                    attr != LanguageAnalyzer):
                    
                    self.register_analyzer(attr)
                    logger.info(f"Loaded analyzer from {module_name}")
                    break
            else:
                logger.warning(f"No analyzer class found in {module_name}")
                
        except ImportError as e:
            logger.debug(f"Could not import {module_name}: {str(e)}")
        except Exception as e:
            logger.error(f"Error loading language module {language}: {str(e)}")
    
    def get_analyzer_for_file(self, file_path: Path) -> Optional[LanguageAnalyzer]:
        """Get appropriate analyzer for a specific file."""
        for analyzer in self._instances.values():
            if analyzer.can_analyze(file_path):
                return analyzer
        
        # Try to load analyzer if not already instantiated
        for language, analyzer_class in self._analyzers.items():
            if language not in self._instances:
                analyzer = analyzer_class()
                self._instances[language] = analyzer
                if analyzer.can_analyze(file_path):
                    return analyzer
        
        return None
    
    def get_file_extensions_map(self) -> Dict[str, str]:
        """Get mapping of file extensions to languages."""
        extension_map = {}
        
        for language, analyzer_class in self._analyzers.items():
            temp_instance = analyzer_class()
            for ext in temp_instance.file_extensions:
                extension_map[ext] = language
        
        return extension_map
    
    def validate_analyzers(self) -> Dict[str, bool]:
        """Validate all registered analyzers."""
        validation_results = {}
        
        for language, analyzer_class in self._analyzers.items():
            try:
                analyzer = analyzer_class()
                
                # Basic validation checks
                assert isinstance(analyzer.language_name, str)
                assert isinstance(analyzer.file_extensions, list)
                assert len(analyzer.file_extensions) > 0
                assert isinstance(analyzer.get_supported_rules(), list)
                
                validation_results[language] = True
                logger.debug(f"Analyzer validation passed: {language}")
                
            except Exception as e:
                validation_results[language] = False
                logger.error(f"Analyzer validation failed for {language}: {str(e)}")
        
        return validation_results

# =============================================================================
# MAIN SECURITY ANALYZER
# =============================================================================

class SecurityAnalyzer:
    """Main security analysis orchestrator."""
    
    def __init__(self, config: Config):
        """Initialize the security analyzer."""
        self.config = config
        self.registry = LanguageRegistry()
        self._setup_analyzers()
        
        # Thread safety
        self._lock = threading.Lock()
        
        logger.info("SecurityAnalyzer initialized")
    
    def _setup_analyzers(self) -> None:
        """Initialize and validate language analyzers."""
        try:
            # Discover and load language analyzers
            self.registry.discover_analyzers()
            
            # Validate loaded analyzers
            validation_results = self.registry.validate_analyzers()
            
            supported_languages = self.registry.get_supported_languages()
            logger.info(f"Loaded analyzers for languages: {', '.join(supported_languages)}")
            
            # Log validation results
            for language, is_valid in validation_results.items():
                if not is_valid:
                    logger.warning(f"Analyzer validation failed for: {language}")
            
            if not supported_languages:
                logger.warning("No language analyzers loaded - analysis will be limited")
                
        except Exception as e:
            logger.error(f"Error setting up analyzers: {str(e)}")
            raise
    
    def analyze(self, target_path: Path, language_filter: Optional[str] = None) -> AnalysisResults:
        """Perform security analysis on the target path."""
        start_time = time.time()
        
        # Validate inputs
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")
        
        if language_filter and language_filter not in self.registry.get_supported_languages():
            raise ValueError(f"Unsupported language filter: {language_filter}")
        
        # Initialize results
        results = AnalysisResults(str(target_path))
        results.start_time = time.strftime('%Y-%m-%d %H:%M:%S')
        results.analyzer_config = self.config.to_dict()
        
        logger.info(f"Starting analysis of: {target_path}")
        
        try:
            # Discover files to analyze
            files_to_analyze = self._discover_files(target_path, language_filter)
            logger.info(f"Found {len(files_to_analyze)} files to analyze")
            
            if not files_to_analyze:
                logger.warning("No files found for analysis")
                return results
            
            # Perform analysis
            file_results = self._analyze_files(files_to_analyze)
            
            # Add results
            for result in file_results:
                results.add_file_result(result)
            
            # Calculate final statistics
            end_time = time.time()
            results.total_duration = end_time - start_time
            results.end_time = time.strftime('%Y-%m-%d %H:%M:%S')
            
            total_vulns = results.get_total_vulnerabilities()
            vuln_counts = results.get_vulnerabilities_by_severity()
            
            logger.info(f"Analysis complete: {len(results.file_results)} files analyzed, "
                       f"{total_vulns} vulnerabilities found")
            logger.info(f"Severity breakdown: {vuln_counts}")
            
            return results
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            raise
    
    def _discover_files(self, target_path: Path, language_filter: Optional[str] = None) -> List[Path]:
        """Discover files to analyze based on target path and filters."""
        files_to_analyze = []
        
        if target_path.is_file():
            # Single file analysis
            if self._should_analyze_file(target_path, language_filter):
                files_to_analyze.append(target_path)
        else:
            # Directory analysis
            files_to_analyze = self._scan_directory(target_path, language_filter)
        
        return files_to_analyze
    
    def _scan_directory(self, directory: Path, language_filter: Optional[str] = None) -> List[Path]:
        """Recursively scan directory for analyzable files."""
        files = []
        
        try:
            # Walk directory tree
            for root, dirs, filenames in os.walk(directory):
                # Filter out excluded directories
                dirs[:] = [d for d in dirs if not self._should_exclude_directory(Path(root) / d)]
                
                for filename in filenames:
                    file_path = Path(root) / filename
                    
                    if self._should_analyze_file(file_path, language_filter):
                        files.append(file_path)
            
            logger.debug(f"Scanned directory {directory}: found {len(files)} files")
            
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {str(e)}")
        
        return files
    
    def _should_analyze_file(self, file_path: Path, language_filter: Optional[str] = None) -> bool:
        """Determine if a file should be analyzed."""
        # Check if file should be excluded by configuration
        if self.config.should_exclude_file(file_path):
            return False
        
        # Check file size limits
        try:
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.config.get_max_file_size_mb():
                logger.debug(f"Skipping large file: {file_path} ({file_size_mb:.1f} MB)")
                return False
        except OSError:
            logger.debug(f"Could not get file size: {file_path}")
            return False
        
        # Check if we have an analyzer for this file
        analyzer = self.registry.get_analyzer_for_file(file_path)
        if not analyzer:
            return False
        
        # Check language filter
        if language_filter and analyzer.language_name != language_filter:
            return False
        
        return True
    
    def _should_exclude_directory(self, dir_path: Path) -> bool:
        """Check if a directory should be excluded from scanning."""
        return self.config.should_exclude_file(dir_path)
    
    def _analyze_files(self, files: List[Path]) -> List[FileAnalysisResult]:
        """Analyze multiple files in parallel."""
        results = []
        
        # Determine optimal number of worker threads
        max_workers = min(len(files), os.cpu_count() or 1, 8)  # Cap at 8 threads
        
        logger.debug(f"Starting parallel analysis with {max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit analysis tasks
            future_to_file = {
                executor.submit(self._analyze_single_file, file_path): file_path
                for file_path in files
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result(timeout=self.config.get_timeout_per_file())
                    if result:
                        results.append(result)
                        
                        # Log progress
                        vuln_count = len(result.vulnerabilities)
                        if vuln_count > 0:
                            logger.info(f"Found {vuln_count} issues in: {file_path}")
                        else:
                            logger.debug(f"No issues found in: {file_path}")
                            
                except Exception as e:
                    logger.error(f"Analysis failed for {file_path}: {str(e)}")
                    # Create error result
                    error_result = FileAnalysisResult(str(file_path), "unknown")
                    error_result.error = str(e)
                    results.append(error_result)
        
        return results
    
    def _analyze_single_file(self, file_path: Path) -> Optional[FileAnalysisResult]:
        """Analyze a single file for security vulnerabilities."""
        start_time = time.time()
        
        try:
            # Get appropriate analyzer
            analyzer = self.registry.get_analyzer_for_file(file_path)
            if not analyzer:
                logger.debug(f"No analyzer available for: {file_path}")
                return None
            
            logger.debug(f"Analyzing {file_path} with {analyzer.language_name} analyzer")
            
            # Perform analysis
            result = analyzer.analyze_file(file_path, self.config)
            
            # Set additional metadata
            result.analysis_duration = time.time() - start_time
            
            try:
                result.file_size = file_path.stat().st_size
            except OSError:
                result.file_size = 0
            
            # Filter vulnerabilities by severity threshold
            filtered_vulns = []
            for vuln in result.vulnerabilities:
                if self.config.meets_severity_threshold(vuln.severity):
                    filtered_vulns.append(vuln)
            
            result.vulnerabilities = filtered_vulns
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            # Return error result
            error_result = FileAnalysisResult(str(file_path), "unknown")
            error_result.error = str(e)
            error_result.analysis_duration = time.time() - start_time
            return error_result
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported programming languages."""
        return self.registry.get_supported_languages()
    
    def get_analyzer_info(self, language: str) -> Optional[dict]:
        """Get information about a specific language analyzer."""
        analyzer = self.registry.get_analyzer(language)
        if not analyzer:
            return None
        
        return {
            'language': analyzer.language_name,
            'file_extensions': analyzer.file_extensions,
            'supported_rules': analyzer.get_supported_rules(),
            'enabled': self.config.is_language_enabled(language)
        }
    
    def validate_configuration(self) -> Dict[str, bool]:
        """Validate the current configuration and analyzer setup."""
        validation_results = {
            'config_valid': True,
            'analyzers_valid': True,
            'languages_enabled': False
        }
        
        try:
            # Validate configuration
            self.config._validate_config()
        except Exception as e:
            logger.error(f"Configuration validation failed: {str(e)}")
            validation_results['config_valid'] = False
        
        # Validate analyzers
        analyzer_validation = self.registry.validate_analyzers()
        validation_results['analyzers_valid'] = all(analyzer_validation.values())
        
        # Check if any languages are enabled
        enabled_languages = [
            lang for lang in self.registry.get_supported_languages()
            if self.config.is_language_enabled(lang)
        ]
        validation_results['languages_enabled'] = len(enabled_languages) > 0
        
        return validation_results
    
    def get_analysis_statistics(self) -> dict:
        """Get statistics about the analyzer capabilities."""
        supported_languages = self.registry.get_supported_languages()
        enabled_languages = [
            lang for lang in supported_languages
            if self.config.is_language_enabled(lang)
        ]
        
        # Collect supported OWASP categories across all analyzers
        all_rules = set()
        for language in supported_languages:
            analyzer = self.registry.get_analyzer(language)
            if analyzer:
                all_rules.update(analyzer.get_supported_rules())
        
        extension_map = self.registry.get_file_extensions_map()
        
        return {
            'total_analyzers': len(supported_languages),
            'enabled_analyzers': len(enabled_languages),
            'supported_languages': supported_languages,
            'enabled_languages': enabled_languages,
            'supported_owasp_categories': sorted(list(all_rules)),
            'supported_extensions': sorted(list(extension_map.keys())),
            'min_severity': self.config.get_min_severity(),
            'include_tests': self.config.get_include_tests()
        }