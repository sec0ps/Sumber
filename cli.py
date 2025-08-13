#!/usr/bin/env python3
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

import argparse
import sys
import os
import logging
from pathlib import Path
from typing import List, Optional

# Import our core components (will be implemented in next sessions)
try:
    from core import SecurityAnalyzer
    from core import Config
    from reporter.html_reporter import HTMLReporter
except ImportError as e:
    print(f"Error importing core modules: {e}")
    print("Please ensure all modules are properly installed.")
    sys.exit(1)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def validate_target_path(path: str) -> Path:
    """Validate that the target path exists and is accessible."""
    target = Path(path)
    
    if not target.exists():
        raise argparse.ArgumentTypeError(f"Path does not exist: {path}")
    
    if not (target.is_file() or target.is_dir()):
        raise argparse.ArgumentTypeError(f"Path is not a file or directory: {path}")
    
    if not os.access(target, os.R_OK):
        raise argparse.ArgumentTypeError(f"Path is not readable: {path}")
    
    return target


def get_supported_languages() -> List[str]:
    """Return list of currently supported programming languages."""
    # This will be dynamic once we implement the registry
    return ['python']  # Starting with Python only


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog='security-analyzer',
        description='Static code analysis tool for OWASP Top 10 vulnerability detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single Python file
  python cli.py /path/to/file.py
  
  # Analyze entire directory with verbose output
  python cli.py /path/to/project --verbose
  
  # Analyze specific language with custom output location
  python cli.py /path/to/mixed-project --language python --output /tmp/report.html
  
  # Show detailed help for OWASP categories
  python cli.py --list-rules
        """
    )
    
    # Required arguments
    parser.add_argument(
        'target',
        type=validate_target_path,
        help='File or directory to analyze'
    )
    
    # Optional arguments
    parser.add_argument(
        '--language', '-l',
        choices=get_supported_languages(),
        help='Specific language to analyze (auto-detect if not specified)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='security_report.html',
        help='Output file path for HTML report (default: security_report.html)'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to custom configuration file (YAML format)'
    )
    
    parser.add_argument(
        '--severity',
        choices=['low', 'medium', 'high', 'critical'],
        help='Minimum severity level to report (default: medium)'
    )
    
    parser.add_argument(
        '--exclude',
        type=str,
        action='append',
        help='Exclude files/directories matching pattern (can be used multiple times)'
    )
    
    parser.add_argument(
        '--include-tests',
        action='store_true',
        help='Include test files in analysis (excluded by default)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress all output except errors'
    )
    
    # Information arguments
    parser.add_argument(
        '--list-rules',
        action='store_true',
        help='List all available OWASP Top 10 detection rules'
    )
    
    parser.add_argument(
        '--list-languages',
        action='store_true',
        help='List all supported programming languages'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Security Code Analyzer v1.0.0'
    )
    
    return parser


def list_rules() -> None:
    """Display available OWASP Top 10 rules."""
    print("OWASP Top 10 2021 - Supported Detection Rules:")
    print("=" * 50)
    
    rules = [
        ("A01", "Broken Access Control", "Authorization bypasses, privilege escalation"),
        ("A02", "Cryptographic Failures", "Weak encryption, exposed secrets"),
        ("A03", "Injection", "SQL, NoSQL, Command, LDAP injection"),
        ("A04", "Insecure Design", "Missing security controls, threat modeling gaps"),
        ("A05", "Security Misconfiguration", "Default configs, verbose errors"),
        ("A06", "Vulnerable Components", "Outdated dependencies, known CVEs"),
        ("A07", "Authentication Failures", "Weak passwords, session management"),
        ("A08", "Software Data Integrity", "Untrusted sources, missing integrity checks"),
        ("A09", "Security Logging Failures", "Insufficient logging, missing monitoring"),
        ("A10", "Server-Side Request Forgery", "SSRF vulnerabilities")
    ]
    
    for code, title, description in rules:
        print(f"{code}: {title}")
        print(f"    {description}")
        print()


def list_languages() -> None:
    """Display supported programming languages."""
    print("Supported Programming Languages:")
    print("=" * 35)
    
    languages = get_supported_languages()
    for lang in languages:
        print(f" {lang.capitalize()}")
    
    print(f"\nTotal: {len(languages)} language(s) supported")
    print("\nMore languages coming soon: PHP, Go, Perl, .NET, JavaScript")


def main() -> int:
    """Main entry point for the CLI application."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle information requests
    if args.list_rules:
        list_rules()
        return 0
    
    if args.list_languages:
        list_languages()
        return 0
    
    # Validate conflicting arguments
    if args.verbose and args.quiet:
        parser.error("--verbose and --quiet cannot be used together")
    
    # Setup logging
    if not args.quiet:
        setup_logging(args.verbose)
    
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        config = Config(args.config) if args.config else Config()
        
        # Override config with command line arguments
        if args.severity:
            config.set_min_severity(args.severity)
        
        if args.exclude:
            config.set_exclusions(args.exclude)
        
        config.set_include_tests(args.include_tests)
        
        # Initialize the security analyzer
        analyzer = SecurityAnalyzer(config)
        
        # Perform the analysis
        if not args.quiet:
            print(f"Starting security analysis of: {args.target}")
            if args.language:
                print(f"Language filter: {args.language}")
        
        results = analyzer.analyze(
            target_path=args.target,
            language_filter=args.language
        )
        
        # Generate HTML report
        reporter = HTMLReporter()
        report_path = reporter.generate_report(results, args.output)
        
        # Summary output
        if not args.quiet:
            total_issues = sum(len(file_results.vulnerabilities) 
                             for file_results in results.file_results)
            
            print(f"\nAnalysis complete!")
            print(f"Files analyzed: {len(results.file_results)}")
            print(f"Total vulnerabilities found: {total_issues}")
            print(f"Report generated: {report_path}")
            
            if total_issues > 0:
                print(f"\nSecurity issues detected. Review the HTML report for details.")
                return 1
            else:
                print(f"\nNo security vulnerabilities detected.")
        
        return 0
        
    except KeyboardInterrupt:
        if not args.quiet:
            print("\nAnalysis interrupted by user")
        return 130
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        if args.verbose:
            logger.exception("Detailed error information:")
        return 1


if __name__ == '__main__':
    sys.exit(main())