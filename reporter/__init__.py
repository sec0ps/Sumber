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

from .html_reporter import HTMLReporter

__all__ = ['HTMLReporter']



# Supported report formats
SUPPORTED_FORMATS = ['html']

def get_reporter(format_type: str = 'html'):
    """
    Factory function to get the appropriate reporter instance.
    
    Args:
        format_type (str): The desired report format ('html' currently supported)
        
    Returns:
        Reporter instance for the specified format
        
    Raises:
        ValueError: If the format_type is not supported
    """
    if format_type.lower() == 'html':
        return HTMLReporter()
    else:
        raise ValueError(f"Unsupported report format: {format_type}. "
                        f"Supported formats: {', '.join(SUPPORTED_FORMATS)}")