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
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from jinja2 import Environment, BaseLoader
import json

class HTMLReporter:
    """
    Generates HTML security reports from analysis results.
    
    Features:
    - OWASP Top 10 categorization
    - Severity-based color coding
    - Interactive vulnerability details
    - Summary statistics and charts
    - Code snippet highlighting
    """
    
    def __init__(self):
        self.template = self._get_html_template()
        
    def generate_report(self, analysis_results, output_path: str) -> str:
        """
        Generate HTML report from analysis results.
        
        Args:
            analysis_results: Results object from SecurityAnalyzer
            output_path (str): Path where HTML report should be saved
            
        Returns:
            str: Path to the generated HTML report
            
        Raises:
            IOError: If unable to write to output path
        """
        try:
            # Prepare data for template
            report_data = self._prepare_report_data(analysis_results)
            
            # Render HTML content
            html_content = self.template.render(**report_data)
            
            # Write to file
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            return str(output_file.resolve())
            
        except Exception as e:
            raise IOError(f"Failed to generate HTML report: {str(e)}")

    def _prepare_report_data(self, analysis_results) -> Dict[str, Any]:
        """Prepare data structure for HTML template rendering with enhanced OWASP data."""
        
        # Extract vulnerability statistics
        stats = self._calculate_statistics(analysis_results)
        
        # Group vulnerabilities by OWASP category
        owasp_groups = self._group_by_owasp_category(analysis_results)
        
        # Prepare file-level results
        file_results = self._prepare_file_results(analysis_results)
        
        # Calculate additional metrics
        total_files = len(analysis_results.file_results) if hasattr(analysis_results, 'file_results') else 0
        files_with_issues = stats.get('files_with_issues', 0)
        analysis_duration = getattr(analysis_results, 'total_duration', 0)
        
        # Get top CWE IDs for summary
        top_cwe_ids = sorted(stats.get('top_cwe_ids', {}).items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'report_title': 'Security Code Analysis Report',
            'generated_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'analysis_summary': {
                'total_vulnerabilities': stats['total_vulnerabilities'],
                'critical': stats['critical'],
                'high': stats['high'],
                'medium': stats['medium'],
                'low': stats['low'],
                'by_owasp': stats['by_owasp'],
                'top_cwe_ids': top_cwe_ids,
                'files_with_issues': files_with_issues,
                'analysis_duration': round(analysis_duration, 2)
            },
            'owasp_categories': owasp_groups,
            'file_results': file_results,
            'total_files': total_files,
            'scan_target': getattr(analysis_results, 'target_path', 'Unknown'),
            'start_time': getattr(analysis_results, 'start_time', 'Unknown'),
            'end_time': getattr(analysis_results, 'end_time', 'Unknown'),
            'analyzer_config': getattr(analysis_results, 'analyzer_config', {})
        }
    
    def _calculate_statistics(self, analysis_results) -> Dict[str, Any]:
        """Calculate summary statistics for the report."""
        stats = {
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_owasp': {},
            'top_cwe_ids': {},
            'files_with_issues': 0
        }
        
        if hasattr(analysis_results, 'file_results'):
            for file_result in analysis_results.file_results:
                if hasattr(file_result, 'vulnerabilities') and file_result.vulnerabilities:
                    stats['files_with_issues'] += 1
                    
                    for vuln in file_result.vulnerabilities:
                        stats['total_vulnerabilities'] += 1
                        
                        # Count by severity
                        severity = getattr(vuln, 'severity', 'medium').lower()
                        if severity in stats:
                            stats[severity] += 1
                        
                        # Count by OWASP category
                        owasp_category = getattr(vuln, 'owasp_category', 'GEN')
                        if ':' in owasp_category:
                            owasp_category = owasp_category.split(':')[0].strip()
                        stats['by_owasp'][owasp_category] = stats['by_owasp'].get(owasp_category, 0) + 1
                        
                        # Count CWE IDs
                        cwe_ids = getattr(vuln, 'cwe_ids', [])
                        for cwe_id in cwe_ids:
                            stats['top_cwe_ids'][cwe_id] = stats['top_cwe_ids'].get(cwe_id, 0) + 1
        
        return stats

    def _group_by_owasp_category(self, analysis_results) -> Dict[str, List]:
        """Group vulnerabilities by OWASP Top 10 categories."""
        owasp_groups = {}
        
        # OWASP Top 10 2021 categories + General Security
        owasp_categories = {
            'A01': 'Broken Access Control',
            'A02': 'Cryptographic Failures',
            'A03': 'Injection',
            'A04': 'Insecure Design',
            'A05': 'Security Misconfiguration',
            'A06': 'Vulnerable and Outdated Components',
            'A07': 'Identification and Authentication Failures',
            'A08': 'Software and Data Integrity Failures',
            'A09': 'Security Logging and Monitoring Failures',
            'A10': 'Server-Side Request Forgery',
            'GEN': 'General Security Issues'
        }
        
        # Initialize categories
        for owasp_id, title in owasp_categories.items():
            owasp_groups[owasp_id] = {
                'title': f"{owasp_id}: {title}" if owasp_id != 'GEN' else title,
                'vulnerabilities': [],
                'count': 0
            }
        
        # Group vulnerabilities by OWASP category
        if hasattr(analysis_results, 'file_results'):
            for file_result in analysis_results.file_results:
                if hasattr(file_result, 'vulnerabilities'):
                    for vuln in file_result.vulnerabilities:
                        # Get OWASP category (extract just the category code, e.g., 'A01' from 'A01: Broken Access Control')
                        owasp_category = getattr(vuln, 'owasp_category', 'GEN')
                        if ':' in owasp_category:
                            owasp_category = owasp_category.split(':')[0].strip()
                        
                        if owasp_category in owasp_groups:
                            owasp_groups[owasp_category]['vulnerabilities'].append(vuln)
                            owasp_groups[owasp_category]['count'] += 1
                        else:
                            # Fallback to General Security for unknown categories
                            owasp_groups['GEN']['vulnerabilities'].append(vuln)
                            owasp_groups['GEN']['count'] += 1
        
        return owasp_groups
    
    def _prepare_file_results(self, analysis_results) -> List[Dict]:
        """Prepare file-level results for template with enhanced vulnerability data."""
        file_results = []
        
        if hasattr(analysis_results, 'file_results'):
            for file_result in analysis_results.file_results:
                # Prepare enhanced vulnerability data
                enhanced_vulnerabilities = []
                vulnerabilities = getattr(file_result, 'vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    # Convert vulnerability to dict and ensure all fields are present
                    vuln_dict = vuln.to_dict() if hasattr(vuln, 'to_dict') else {
                        'title': getattr(vuln, 'title', 'Security Issue'),
                        'description': getattr(vuln, 'description', 'No description available'),
                        'severity': getattr(vuln, 'severity', 'medium'),
                        'owasp_category': getattr(vuln, 'owasp_category', 'GEN'),
                        'owasp_category_name': getattr(vuln, 'owasp_category_name', 'General Security Issues'),
                        'line_number': getattr(vuln, 'line_number', 'Unknown'),
                        'column_number': getattr(vuln, 'column_number', 0),
                        'code_snippet': getattr(vuln, 'code_snippet', ''),
                        'highlighted_code': getattr(vuln, 'highlighted_code', ''),
                        'filename': getattr(vuln, 'filename', 'Unknown'),
                        'confidence': getattr(vuln, 'confidence', 'medium'),
                        'cwe_ids': getattr(vuln, 'cwe_ids', []),
                        'primary_remediation': getattr(vuln, 'primary_remediation', ''),
                        'alternative_remediation': getattr(vuln, 'alternative_remediation', ''),
                        'references': getattr(vuln, 'references', []),
                        'tags': getattr(vuln, 'tags', []),
                        'pattern_id': getattr(vuln, 'pattern_id', '')
                    }
                    enhanced_vulnerabilities.append(vuln_dict)
                
                file_data = {
                    'filename': getattr(file_result, 'filename', 'Unknown'),
                    'language': getattr(file_result, 'language', 'Unknown'),
                    'vulnerabilities': enhanced_vulnerabilities,
                    'vulnerability_count': len(enhanced_vulnerabilities),
                    'lines_of_code': getattr(file_result, 'lines_of_code', 0),
                    'file_size': getattr(file_result, 'file_size', 0),
                    'analysis_duration': getattr(file_result, 'analysis_duration', 0),
                    'error': getattr(file_result, 'error', None)
                }
                file_results.append(file_data)
        
        return file_results

    def _get_html_template(self) -> Any:
        """Get the HTML template for report generation."""
        
        template_content = """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ report_title }}</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f5f5f5;
            }
            
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 2rem 0;
                text-align: center;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            
            .header h1 {
                font-size: 2.5rem;
                margin-bottom: 0.5rem;
            }
            
            .header .subtitle {
                opacity: 0.9;
                font-size: 1.1rem;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 2rem;
            }
            
            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1.5rem;
                margin: 2rem 0;
            }
            
            .summary-card {
                background: white;
                padding: 1.5rem;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.08);
                text-align: center;
                border-left: 4px solid #667eea;
            }
            
            .summary-card h3 {
                font-size: 2rem;
                margin-bottom: 0.5rem;
                color: #667eea;
            }
            
            .summary-card p {
                color: #666;
                font-weight: 500;
            }
            
            .severity-critical { border-left-color: #e74c3c; }
            .severity-critical h3 { color: #e74c3c; }
            
            .severity-high { border-left-color: #f39c12; }
            .severity-high h3 { color: #f39c12; }
            
            .severity-medium { border-left-color: #f1c40f; }
            .severity-medium h3 { color: #f1c40f; }
            
            .severity-low { border-left-color: #27ae60; }
            .severity-low h3 { color: #27ae60; }
            
            .section {
                background: white;
                margin: 2rem 0;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.08);
                overflow: hidden;
            }
            
            .section-header {
                background: #f8f9fa;
                padding: 1.5rem;
                border-bottom: 1px solid #e9ecef;
            }
            
            .section-header h2 {
                color: #495057;
                font-size: 1.5rem;
            }
            
            .section-content {
                padding: 1.5rem;
            }
            
            .owasp-category {
                margin-bottom: 2rem;
                border: 1px solid #e9ecef;
                border-radius: 8px;
                overflow: hidden;
            }
            
            .owasp-header {
                background: #667eea;
                color: white;
                padding: 1rem;
                cursor: pointer;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .owasp-header:hover {
                background: #5a67d8;
            }
            
            .owasp-content {
                display: none;
                padding: 1rem;
            }
            
            .owasp-content.active {
                display: block;
            }
            
            .vulnerability {
                background: #f8f9fa;
                border-left: 4px solid #dee2e6;
                margin: 1rem 0;
                padding: 1rem;
                border-radius: 0 8px 8px 0;
            }
            
            .vulnerability.critical { border-left-color: #e74c3c; }
            .vulnerability.high { border-left-color: #f39c12; }
            .vulnerability.medium { border-left-color: #f1c40f; }
            .vulnerability.low { border-left-color: #27ae60; }
            
            .vulnerability h4 {
                color: #495057;
                margin-bottom: 0.5rem;
            }
            
            .vulnerability-meta {
                display: flex;
                gap: 1rem;
                margin: 0.5rem 0;
                font-size: 0.9rem;
                flex-wrap: wrap;
            }
            
            .severity-badge {
                padding: 0.2rem 0.5rem;
                border-radius: 12px;
                font-weight: 600;
                text-transform: uppercase;
                font-size: 0.7rem;
            }
            
            .badge-critical { background: #e74c3c; color: white; }
            .badge-high { background: #f39c12; color: white; }
            .badge-medium { background: #f1c40f; color: #333; }
            .badge-low { background: #27ae60; color: white; }
            
            .cwe-badge {
                padding: 0.2rem 0.5rem;
                border-radius: 8px;
                background: #6c757d;
                color: white;
                font-size: 0.7rem;
                font-weight: 500;
            }
            
            .code-snippet {
                background: #2d3748;
                color: #e2e8f0;
                padding: 1rem;
                border-radius: 6px;
                font-family: 'Monaco', 'Consolas', monospace;
                font-size: 0.9rem;
                overflow-x: auto;
                margin: 1rem 0;
            }
            
            .vulnerability-highlight {
                background-color: #ff6b6b;
                color: white;
                padding: 2px 4px;
                border-radius: 3px;
                font-weight: bold;
            }
            
            .remediation-section {
                margin-top: 1rem;
                border-top: 1px solid #e9ecef;
                padding-top: 1rem;
            }
            
            .remediation-item {
                margin-bottom: 0.8rem;
                padding: 0.5rem;
                border-radius: 4px;
            }
            
            .primary-remediation {
                background: #d4edda;
                border-left: 3px solid #28a745;
            }
            
            .alternative-remediation {
                background: #fff3cd;
                border-left: 3px solid #ffc107;
            }
            
            .remediation-item h5 {
                font-size: 0.9rem;
                margin-bottom: 0.3rem;
                color: #495057;
            }
            
            .references {
                margin-top: 1rem;
                font-size: 0.9rem;
            }
            
            .references a {
                color: #667eea;
                text-decoration: none;
                margin-right: 1rem;
            }
            
            .references a:hover {
                text-decoration: underline;
            }
            
            .file-results {
                margin-top: 2rem;
            }
            
            .file-item {
                background: white;
                border: 1px solid #e9ecef;
                border-radius: 8px;
                margin: 1rem 0;
                overflow: hidden;
            }
            
            .file-header {
                background: #f8f9fa;
                padding: 1rem;
                border-bottom: 1px solid #e9ecef;
                display: flex;
                justify-content: space-between;
                align-items: center;
                cursor: pointer;
            }
            
            .file-header:hover {
                background: #e9ecef;
            }
            
            .file-content {
                display: none;
                padding: 1rem;
            }
            
            .file-content.active {
                display: block;
            }
            
            .footer {
                text-align: center;
                padding: 2rem;
                color: #666;
                border-top: 1px solid #e9ecef;
                margin-top: 3rem;
                background: white;
            }
            
            .footer a {
                color: #667eea;
                text-decoration: none;
                font-weight: 500;
            }
            
            .footer a:hover {
                text-decoration: underline;
            }
            
            .footer .copyright {
                margin-top: 0.5rem;
                font-size: 0.9rem;
            }
            
            @media (max-width: 768px) {
                .container {
                    padding: 1rem;
                }
                
                .summary-grid {
                    grid-template-columns: 1fr;
                }
                
                .vulnerability-meta {
                    flex-direction: column;
                    gap: 0.5rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Sumber Security Source Code Analysis Report</h1>
            <div class="subtitle">Generated on {{ generated_at }}</div>
            <div class="subtitle">Target: {{ scan_target }}</div>
        </div>
    
        <div class="container">
            <!-- Summary Statistics -->
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>{{ total_files }}</h3>
                    <p>Files Analyzed</p>
                </div>
                <div class="summary-card">
                    <h3>{{ analysis_summary.total_vulnerabilities }}</h3>
                    <p>Total Issues</p>
                </div>
                <div class="summary-card severity-critical">
                    <h3>{{ analysis_summary.critical }}</h3>
                    <p>Critical</p>
                </div>
                <div class="summary-card severity-high">
                    <h3>{{ analysis_summary.high }}</h3>
                    <p>High</p>
                </div>
                <div class="summary-card severity-medium">
                    <h3>{{ analysis_summary.medium }}</h3>
                    <p>Medium</p>
                </div>
                <div class="summary-card severity-low">
                    <h3>{{ analysis_summary.low }}</h3>
                    <p>Low</p>
                </div>
            </div>
    
            <!-- OWASP Categories -->
            <div class="section">
                <div class="section-header">
                    <h2>OWASP Top 10 Categories</h2>
                </div>
                <div class="section-content">
                    {% for owasp_id, category in owasp_categories.items() %}
                    {% if category.count > 0 %}
                    <div class="owasp-category">
                        <div class="owasp-header" onclick="toggleOwasp('{{ owasp_id }}')">
                            <span>{{ category.title }}</span>
                            <span>{{ category.count }} issues</span>
                        </div>
                        <div class="owasp-content" id="owasp-{{ owasp_id }}">
                            {% for vuln in category.vulnerabilities %}
                            <div class="vulnerability {{ vuln.severity|default('medium') }}">
                                <h4>{{ vuln.title|default('Security Issue') }}</h4>
                                <div class="vulnerability-meta">
                                    <span class="severity-badge badge-{{ vuln.severity|default('medium') }}">
                                        {{ vuln.severity|default('medium') }}
                                    </span>
                                    <span>Line {{ vuln.line_number|default('Unknown') }}</span>
                                    <span>{{ vuln.filename|default('Unknown file') }}</span>
                                    {% if vuln.cwe_ids %}
                                        {% for cwe_id in vuln.cwe_ids %}
                                        <span class="cwe-badge">CWE-{{ cwe_id }}</span>
                                        {% endfor %}
                                    {% endif %}
                                </div>
                                <p>{{ vuln.description|default('No description available') }}</p>
                                
                                {% if vuln.highlighted_code %}
                                <div class="code-snippet">{{ vuln.highlighted_code|safe }}</div>
                                {% elif vuln.code_snippet %}
                                <div class="code-snippet">{{ vuln.code_snippet }}</div>
                                {% endif %}
                                
                                {% if vuln.primary_remediation or vuln.alternative_remediation %}
                                <div class="remediation-section">
                                    {% if vuln.primary_remediation %}
                                    <div class="remediation-item primary-remediation">
                                        <h5>Recommended Solution:</h5>
                                        <p>{{ vuln.primary_remediation }}</p>
                                    </div>
                                    {% endif %}
                                    {% if vuln.alternative_remediation %}
                                    <div class="remediation-item alternative-remediation">
                                        <h5>Alternative Approach:</h5>
                                        <p>{{ vuln.alternative_remediation }}</p>
                                    </div>
                                    {% endif %}
                                </div>
                                {% endif %}
                                
                                {% if vuln.references %}
                                <div class="references">
                                    <strong>References:</strong>
                                    {% for ref in vuln.references %}
                                    <a href="{{ ref }}" target="_blank">{{ ref }}</a>
                                    {% endfor %}
                                </div>
                                {% endif %}
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                    {% endfor %}
                </div>
            </div>
    
            <!-- File Results -->
            <div class="section">
                <div class="section-header">
                    <h2>File Analysis Results</h2>
                </div>
                <div class="section-content">
                    {% for file in file_results %}
                    <div class="file-item">
                        <div class="file-header" onclick="toggleFile('{{ loop.index }}')">
                            <span>{{ file.filename }} ({{ file.language }})</span>
                            <span>{{ file.vulnerability_count }} issues</span>
                        </div>
                        <div class="file-content" id="file-{{ loop.index }}">
                            {% if file.vulnerabilities %}
                                {% for vuln in file.vulnerabilities %}
                                <div class="vulnerability {{ vuln.severity|default('medium') }}">
                                    <h4>{{ vuln.title|default('Security Issue') }}</h4>
                                    <div class="vulnerability-meta">
                                        <span class="severity-badge badge-{{ vuln.severity|default('medium') }}">
                                            {{ vuln.severity|default('medium') }}
                                        </span>
                                        <span>Line {{ vuln.line_number|default('Unknown') }}</span>
                                        {% if vuln.cwe_ids %}
                                            {% for cwe_id in vuln.cwe_ids %}
                                            <span class="cwe-badge">CWE-{{ cwe_id }}</span>
                                            {% endfor %}
                                        {% endif %}
                                    </div>
                                    <p>{{ vuln.description|default('No description available') }}</p>
                                    
                                    {% if vuln.highlighted_code %}
                                    <div class="code-snippet">{{ vuln.highlighted_code|safe }}</div>
                                    {% elif vuln.code_snippet %}
                                    <div class="code-snippet">{{ vuln.code_snippet }}</div>
                                    {% endif %}
                                    
                                    {% if vuln.primary_remediation or vuln.alternative_remediation %}
                                    <div class="remediation-section">
                                        {% if vuln.primary_remediation %}
                                        <div class="remediation-item primary-remediation">
                                            <h5>Recommended Solution:</h5>
                                            <p>{{ vuln.primary_remediation }}</p>
                                        </div>
                                        {% endif %}
                                        {% if vuln.alternative_remediation %}
                                        <div class="remediation-item alternative-remediation">
                                            <h5>Alternative Approach:</h5>
                                            <p>{{ vuln.alternative_remediation }}</p>
                                        </div>
                                        {% endif %}
                                    </div>
                                    {% endif %}
                                    
                                    {% if vuln.references %}
                                    <div class="references">
                                        <strong>References:</strong>
                                        {% for ref in vuln.references %}
                                        <a href="{{ ref }}" target="_blank">{{ ref }}</a>
                                        {% endfor %}
                                    </div>
                                    {% endif %}
                                </div>
                                {% endfor %}
                            {% else %}
                                <p>No security issues found in this file.</p>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    
        <div class="footer">
            <p>Generated by <strong>Sumber Security Source Code Analyzer</strong></p>
            <p>Report generated on {{ generated_at }}</p>
            <div class="copyright">
                <p>Copyright &copy; 2025 <a href="https://www.redcellsecurity.org" target="_blank" onclick="window.open(this.href, '_blank'); return false;">Red Cell Security, LLC</a></p>
            </div>
        </div>
    
        <script>
            function toggleOwasp(owaspId) {
                const content = document.getElementById('owasp-' + owaspId);
                content.classList.toggle('active');
            }
            
            function toggleFile(fileIndex) {
                const content = document.getElementById('file-' + fileIndex);
                content.classList.toggle('active');
            }
            
            // Auto-expand categories with vulnerabilities
            document.addEventListener('DOMContentLoaded', function() {
                const owaspContents = document.querySelectorAll('.owasp-content');
                owaspContents.forEach(function(content) {
                    const vulns = content.querySelectorAll('.vulnerability');
                    if (vulns.length > 0) {
                        content.classList.add('active');
                    }
                });
            });
        </script>
    </body>
    </html>"""
        
        # Create Jinja2 environment with string template
        env = Environment(loader=BaseLoader())
        return env.from_string(template_content)