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

import re
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from enum import Enum

# OWASP Top 10 2021 Categories
OWASP_CATEGORIES = {
    'A01': {
        'name': 'Broken Access Control',
        'description': 'Restrictions on what authenticated users are allowed to do are often not properly enforced',
        'risk_factors': ['Authorization bypass', 'Privilege escalation', 'Direct object references'],
        'impact': 'High - attackers can act as users or administrators, or gain unauthorized access to data'
    },
    'A02': {
        'name': 'Cryptographic Failures',
        'description': 'Failures related to cryptography which often leads to sensitive data exposure',
        'risk_factors': ['Weak encryption', 'Hardcoded secrets', 'Improper key management'],
        'impact': 'High - sensitive data exposure, identity theft, financial fraud'
    },
    'A03': {
        'name': 'Injection',
        'description': 'Injection flaws occur when untrusted data is sent to an interpreter',
        'risk_factors': ['SQL injection', 'Command injection', 'Cross-site scripting'],
        'impact': 'Critical - data loss, corruption, unauthorized access, complete system compromise'
    },
    'A04': {
        'name': 'Insecure Design',
        'description': 'Missing or ineffective control design',
        'risk_factors': ['Missing security controls', 'Business logic flaws', 'Insecure algorithms'],
        'impact': 'Variable - depends on protection needs of application and data'
    },
    'A05': {
        'name': 'Security Misconfiguration',
        'description': 'Security misconfiguration is commonly a result of insecure default configurations',
        'risk_factors': ['Debug mode enabled', 'Default credentials', 'Unnecessary features'],
        'impact': 'Medium - unauthorized access to system data or functionality'
    },
    'A06': {
        'name': 'Vulnerable and Outdated Components',
        'description': 'Components with known vulnerabilities',
        'risk_factors': ['Outdated dependencies', 'Unpatched software', 'Insecure configurations'],
        'impact': 'Variable - ranges from minimal to complete host takeover'
    },
    'A07': {
        'name': 'Identification and Authentication Failures',
        'description': 'Authentication and session management implemented incorrectly',
        'risk_factors': ['Weak passwords', 'Session management flaws', 'Credential stuffing'],
        'impact': 'High - compromise of user accounts, identity theft'
    },
    'A08': {
        'name': 'Software and Data Integrity Failures',
        'description': 'Code and infrastructure that does not protect against integrity violations',
        'risk_factors': ['Insecure deserialization', 'Supply chain attacks', 'Code integrity'],
        'impact': 'High - unauthorized code execution, data corruption'
    },
    'A09': {
        'name': 'Security Logging and Monitoring Failures',
        'description': 'Insufficient logging and monitoring',
        'risk_factors': ['Missing security logging', 'Log injection', 'Sensitive data in logs'],
        'impact': 'Medium - delayed attack detection, forensic difficulties'
    },
    'A10': {
        'name': 'Server-Side Request Forgery',
        'description': 'Web application fetching a remote resource without validating the URL',
        'risk_factors': ['Unvalidated URLs', 'Internal network access', 'DNS rebinding'],
        'impact': 'High - internal network scanning, sensitive data exposure'
    },
    'GEN': {
        'name': 'General Security Issues',
        'description': 'Security issues not covered by OWASP Top 10',
        'risk_factors': ['Code quality', 'Best practices', 'Defensive programming'],
        'impact': 'Variable - depends on specific issue'
    }
}

# Severity Levels
SEVERITY_LEVELS = {
    'critical': {
        'score': 4,
        'description': 'Critical security vulnerability requiring immediate attention',
        'response_time': '24 hours',
        'business_impact': 'High'
    },
    'high': {
        'score': 3,
        'description': 'High-risk vulnerability that should be addressed promptly',
        'response_time': '72 hours',
        'business_impact': 'Medium-High'
    },
    'medium': {
        'score': 2,
        'description': 'Medium-risk vulnerability that should be reviewed',
        'response_time': '1 week',
        'business_impact': 'Medium'
    },
    'low': {
        'score': 1,
        'description': 'Low-risk issue or potential security improvement',
        'response_time': '1 month',
        'business_impact': 'Low'
    }
}

@dataclass
class VulnerabilityPattern:
    """
    Defines a specific vulnerability pattern within an OWASP category.
    """
    pattern_id: str
    name: str
    description: str
    severity: str
    confidence: str
    owasp_category: str
    cwe_ids: List[int]
    regex_patterns: List[str]
    examples: List[str]
    primary_remediation: str
    alternative_remediation: str
    references: List[str]
    languages: Set[str]
    tags: Set[str]

class OWASPRuleSet:
    """
    Complete set of OWASP Top 10 2021 vulnerability patterns.
    
    Provides structured access to vulnerability patterns, detection rules,
    and remediation guidance for each OWASP category.
    """
    
    def __init__(self):
        self.patterns: Dict[str, VulnerabilityPattern] = {}
        self.patterns_by_category: Dict[str, List[VulnerabilityPattern]] = {}
        self.patterns_by_language: Dict[str, List[VulnerabilityPattern]] = {}
        
        self._initialize_patterns()
    
    def _initialize_patterns(self) -> None:
        """Initialize all OWASP vulnerability patterns."""
        
        # A01: Broken Access Control
        self._add_access_control_patterns()
        
        # A02: Cryptographic Failures
        self._add_cryptographic_patterns()
        
        # A03: Injection
        self._add_injection_patterns()
        
        # A04: Insecure Design
        self._add_insecure_design_patterns()
        
        # A05: Security Misconfiguration
        self._add_misconfiguration_patterns()
        
        # A06: Vulnerable Components
        self._add_vulnerable_component_patterns()
        
        # A07: Authentication Failures
        self._add_authentication_patterns()
        
        # A08: Integrity Failures
        self._add_integrity_patterns()
        
        # A09: Logging Failures
        self._add_logging_patterns()
        
        # A10: SSRF
        self._add_ssrf_patterns()
    
    def _add_pattern(self, pattern: VulnerabilityPattern) -> None:
        """Add a vulnerability pattern to the rule set."""
        self.patterns[pattern.pattern_id] = pattern
        
        # Index by category
        if pattern.owasp_category not in self.patterns_by_category:
            self.patterns_by_category[pattern.owasp_category] = []
        self.patterns_by_category[pattern.owasp_category].append(pattern)
        
        # Index by language
        for language in pattern.languages:
            if language not in self.patterns_by_language:
                self.patterns_by_language[language] = []
            self.patterns_by_language[language].append(pattern)
    
    def _add_access_control_patterns(self) -> None:
        """Add A01: Broken Access Control patterns."""
        
        # Direct Object Reference
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A01_001",
            name="Insecure Direct Object Reference",
            description="Direct access to objects without proper authorization checks allows attackers to manipulate object references to access unauthorized data or functionality. This occurs when applications use user-supplied input to directly access objects (files, database records, URLs) without validating the user's permission to access that specific object. Attackers can modify parameters in URLs, forms, or API calls to access other users' data, system files, or administrative functions. The business impact includes unauthorized data access, privacy violations leading to regulatory fines (GDPR, CCPA), data manipulation or deletion, privilege escalation to administrative functions, and potential system compromise through access to configuration files or sensitive system data.",
            severity="high",
            confidence="medium",
            owasp_category="A01",
            cwe_ids=[22, 285, 639],
            regex_patterns=[
                r'open\s*\(\s*["\']?[^"\']*\+[^"\']*["\']?\s*\)',
                r'file\s*\(\s*["\']?[^"\']*\+[^"\']*["\']?\s*\)',
                r'\/[^\/\s]*\{[^}]*\}[^\/\s]*\/.*\.(txt|log|conf|xml)',
            ],
            examples=[
                "open('/var/log/' + user_input + '.log')",
                "file_path = '/data/' + request.GET['file']",
                "config_file = f'/etc/{filename}.conf'"
            ],
            primary_remediation="Implement indirect object references using mapping tables or UUIDs. Replace direct file access like 'open(\"/data/\" + user_file)' with a mapping system: create a secure mapping table that maps user-accessible tokens to actual file paths, validate user permissions against the requested resource before granting access, use UUIDs or sequential IDs that don't reveal system structure. Implement proper access control checks: verify user authentication and authorization for each resource request, use role-based access control (RBAC) with granular permissions, maintain audit logs of all resource access attempts. For file operations, use absolute path validation with os.path.realpath() and ensure paths remain within allowed directories using path traversal protection.",
            alternative_remediation="If direct object references cannot be eliminated due to legacy system constraints, implement robust validation and access controls: 1) Path canonicalization using os.path.realpath() to resolve symbolic links and relative paths, then verify the resolved path starts with an allowed base directory, 2) Input validation with strict whitelisting: allow only alphanumeric characters and specific safe symbols, reject any input containing '../', absolute paths, or null bytes, 3) Implement file access chroot jails or containers to limit file system access, 4) Use operating system-level permissions with dedicated service accounts having minimal required file access, 5) Implement comprehensive logging and monitoring of all file access attempts with alerting on suspicious patterns. This approach should be temporary while implementing proper indirect reference architecture.",
            references=[
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
            ],
            languages={"python", "php", "javascript", "java"},
            tags={"path_traversal", "file_access", "authorization"}
        ))
        
        # Missing Authorization
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A01_002",
            name="Missing Function Level Authorization",
            description="Functions accessible without proper authorization checks allow attackers to access administrative or sensitive functionality intended for privileged users. This vulnerability occurs when applications fail to verify user permissions at the function or endpoint level, relying only on client-side restrictions or 'security through obscurity'. Attackers can directly call administrative functions, access sensitive API endpoints, or manipulate URLs to reach unauthorized functionality. The impact includes unauthorized administrative access, data manipulation or deletion, user account compromise, system configuration changes, and potential complete application takeover. This can result in data breaches, service disruption, financial losses, and regulatory compliance violations.",
            severity="high",
            confidence="low",
            owasp_category="A01",
            cwe_ids=[285, 862],
            regex_patterns=[
                r'@app\.route\([^)]*\)\s*\n\s*def\s+\w+\([^)]*\):\s*\n(?!\s*@)',
                r'def\s+(admin|delete|modify|update)\w*\([^)]*\):\s*\n(?!\s*@\w*auth)',
                r'function\s+(admin|delete|modify|update)\w*\([^)]*\)\s*{(?!.*auth)',
            ],
            examples=[
                "@app.route('/admin/delete')\ndef delete_user():",
                "def admin_panel(): # Missing authorization check",
                "function deleteAllUsers() { // No auth check"
            ],
            primary_remediation="Implement comprehensive role-based access control (RBAC) with function-level authorization decorators. For Flask applications, create authorization decorators: '@require_role(\"admin\")' or '@require_permission(\"user.delete\")' that verify user authentication and role/permission before function execution. Use framework-specific middleware: Django's @permission_required, Spring Security's @PreAuthorize, or custom JWT validation middleware. Implement centralized authorization logic: create an authorization service that checks user roles/permissions against requested resources, maintain a permission matrix mapping roles to allowed functions, use session management with secure token validation and expiration. Apply authorization checks at multiple layers: controller/route level, service layer, and data access layer for defense in depth.",
            alternative_remediation="If comprehensive RBAC implementation is not immediately feasible, implement manual authorization checks as a temporary measure: 1) Add explicit authorization validation at the beginning of each sensitive function using 'if not user.has_permission(\"admin\") or not user.is_authenticated(): return unauthorized_response()', 2) Implement session validation middleware that checks authentication status and user roles on every request to sensitive endpoints, 3) Use HTTP status code 403 (Forbidden) for authorization failures and 401 (Unauthorized) for authentication failures, 4) Implement request logging and monitoring to track access attempts to sensitive functions, 5) Apply IP-based restrictions for administrative functions where possible, 6) Use temporary access tokens with short expiration times for sensitive operations. Gradually migrate to a proper RBAC system while maintaining these manual checks.",
            references=[
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                "https://cwe.mitre.org/data/definitions/862.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java"},
            tags={"authorization", "function_level", "access_control"}
        ))
    
    def _add_cryptographic_patterns(self) -> None:
        """Add A02: Cryptographic Failures patterns."""

        # Hardcoded Secrets
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A02_001",
            name="Hardcoded Secrets",
            description="Secrets, keys, or passwords hardcoded in source code create critical security vulnerabilities as they are accessible to anyone with code access. This includes API keys, database passwords, encryption keys, JWT secrets, and service credentials embedded directly in application code. The risk is amplified because source code is often stored in version control systems, shared among developers, deployed to multiple environments, and potentially exposed through repository breaches or insider threats. Attackers gaining access to these secrets can authenticate as the application, access backend services, decrypt sensitive data, compromise connected systems, and potentially gain persistent access to infrastructure. The business impact includes data breaches, unauthorized service usage leading to financial costs, regulatory compliance violations, loss of customer trust, and potential legal liability.",
            severity="critical",
            confidence="medium",
            owasp_category="A02",
            cwe_ids=[798, 321, 256],
            regex_patterns=[
                r'(?i)(api[_-]?key|secret|password|pwd|token)\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
                r'(?i)AKIA[0-9A-Z]{16}',  # AWS Access Key
                r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                r'(?i)(mysql|postgres|mongodb)://[^:\s]+:[^@\s]+@',
                r'eyJ[a-zA-Z0-9+/=]+\.eyJ[a-zA-Z0-9+/=]+\.[a-zA-Z0-9+/=]+',  # JWT
            ],
            examples=[
                "API_KEY = 'sk-1234567890abcdef'",
                "password = 'hardcoded_password_123'",
                "connection_string = 'mysql://user:pass@localhost/db'"
            ],
            primary_remediation="Implement external secret management systems for production environments. Use cloud-native solutions like AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault to store and rotate secrets automatically. Configure applications to retrieve secrets at runtime using environment variables: replace 'API_KEY = \"sk-abc123\"' with 'API_KEY = os.getenv(\"API_KEY\")' and set environment variables through deployment pipelines. For Kubernetes, use Secret objects and service account tokens. Implement secret rotation policies with automatic key rotation every 30-90 days. Use encrypted configuration files with runtime decryption for secrets that cannot use external management. Apply principle of least privilege with secrets scoped to specific services and environments. Implement audit logging for all secret access and usage.",
            alternative_remediation="If external secret management systems are not available, implement secure configuration management practices: 1) Use environment-specific configuration files stored outside the application directory and excluded from version control via .gitignore, 2) Encrypt configuration files using tools like ansible-vault or git-crypt with keys managed separately from the codebase, 3) Implement configuration injection during deployment using CI/CD pipeline variables that pull secrets from secure storage, 4) Use application startup scripts that read encrypted configuration and decrypt secrets into memory only, never writing to disk, 5) Implement configuration validation to ensure secrets are loaded correctly and fail securely if secrets are missing, 6) Regularly audit and rotate secrets manually with documented procedures. Gradually migrate to automated secret management solutions.",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java", "go", "csharp"},
            tags={"secrets", "credentials", "hardcoded"}
        ))
        
        # Weak Cryptography
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A02_002",
            name="Weak Cryptographic Algorithms",
            description="Use of weak or deprecated cryptographic algorithms creates vulnerabilities that attackers can exploit using modern computational power and known cryptographic attacks. Weak algorithms like MD5, SHA1, DES, and RC4 have known vulnerabilities including collision attacks, preimage attacks, and brute force susceptibility. Predictable random number generators compromise session tokens, password salts, and cryptographic keys. The risk increases over time as computational power grows and new attack methods are discovered. Successful exploitation can lead to password cracking, session hijacking, data decryption, digital signature forgery, and authentication bypass. The business impact includes data breaches exposing sensitive customer information, regulatory compliance violations (PCI DSS, HIPAA), loss of data integrity, and potential legal liability from inadequate data protection.",
            severity="high",
            confidence="high",
            owasp_category="A02",
            cwe_ids=[327, 328, 916],
            regex_patterns=[
                r'(?i)hashlib\.(md5|sha1)\(',
                r'(?i)(des|3des|rc4|md4|md5|sha1)[\s\(]',
                r'(?i)Cipher\.(DES|RC4|ARC4)',
                r'(?i)(MD5|SHA1)\.Create\(\)',
                r'(?i)random\.(random|randint|choice)\(',
            ],
            examples=[
                "hashlib.md5(password.encode()).hexdigest()",
                "random.randint(1, 1000000)  # For session token",
                "Cipher.DES.new(key, DES.MODE_ECB)"
            ],
            primary_remediation="Replace weak algorithms with cryptographically secure alternatives and implement proper key management. For hashing: replace MD5/SHA1 with SHA-256 or SHA-3, use bcrypt, scrypt, or Argon2 for password hashing with appropriate cost factors (bcrypt rounds ≥12, scrypt N≥32768). For encryption: replace DES/3DES with AES-256 in GCM or CBC mode with proper IV generation, ensure keys are generated using cryptographically secure random number generators. For random number generation: replace Python's random module with secrets module for cryptographic purposes: 'secrets.token_urlsafe(32)' for tokens, 'secrets.SystemRandom()' for random integers. Implement proper key derivation using PBKDF2, scrypt, or Argon2 with unique salts. Use established cryptographic libraries (cryptography, PyNaCl) rather than implementing custom crypto.",
            alternative_remediation="If immediate algorithm replacement is not feasible due to system dependencies, implement additional security layers while planning migration: 1) Add multiple rounds of hashing for weak algorithms (e.g., SHA1(SHA1(password + salt)) though not recommended long-term), 2) Implement key stretching techniques to increase computational cost for attackers, 3) Use longer keys and salts to increase attack complexity (minimum 128-bit random salts), 4) Implement additional authentication factors (2FA/MFA) to reduce reliance on password security alone, 5) Monitor for signs of compromise through unusual authentication patterns or failed login attempts, 6) Implement network-level protections (TLS 1.3, certificate pinning) to protect data in transit, 7) Plan and execute gradual migration to strong algorithms with dual-algorithm support during transition periods.",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cwe.mitre.org/data/definitions/327.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java", "csharp"},
            tags={"cryptography", "weak_algorithms", "hashing"}
        ))
    
    def _add_injection_patterns(self) -> None:
        """Add A03: Injection patterns."""
        
        # SQL Injection
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A03_001",
            name="SQL Injection",
            description="SQL queries constructed using string concatenation or formatting allow attackers to inject malicious SQL commands. This occurs when user input is directly embedded into SQL queries without proper sanitization. Attackers can exploit this to bypass authentication, extract sensitive data, modify database records, execute administrative operations, or in some cases achieve remote code execution. The impact ranges from data theft and privacy breaches to complete database compromise, potentially affecting business operations, regulatory compliance (GDPR, HIPAA), and customer trust. Advanced attacks can include time-based blind SQL injection for data exfiltration, union-based attacks for data extraction, and stacked queries for multiple statement execution.",
            severity="critical",
            confidence="high",
            owasp_category="A03",
            cwe_ids=[89, 564],
            regex_patterns=[
                r'(?i)(select|insert|update|delete)\s+.*\+.*\s*(from|into|set|where)',
                r'(?i)execute\s*\(\s*["\'][^"\']*\+[^"\']*["\']',
                r'(?i)query\s*\(\s*["\'][^"\']*\%s[^"\']*["\']',
                r'(?i)(select|insert|update|delete).*\{[^}]*\}',
                r'(?i)cursor\.execute\s*\([^)]*\+[^)]*\)',
            ],
            examples=[
                "query = \"SELECT * FROM users WHERE id = \" + user_id",
                "cursor.execute(\"SELECT * FROM table WHERE name = '%s'\" % name)",
                "db.execute(f\"INSERT INTO logs VALUES ('{user_input}')\")"
            ],
            primary_remediation="Implement parameterized queries (prepared statements) that separate SQL logic from data. Replace vulnerable code like 'cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)' with 'cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))'. For Python: use psycopg2's parameter substitution, SQLAlchemy's text() with bound parameters, or Django's ORM. Configure database connections with least privilege principles - create dedicated application users with minimal required permissions (SELECT, INSERT, UPDATE only on specific tables). Implement connection pooling with proper timeout settings. Use stored procedures where complex logic is required, ensuring they also use parameterized inputs. Enable database query logging and monitoring for suspicious patterns.",
            alternative_remediation="If parameterized queries cannot be immediately implemented due to legacy system constraints, implement a multi-layered defense: 1) Input validation using strict whitelisting (e.g., alphanumeric only for usernames, regex patterns for expected formats), 2) SQL injection-specific escaping using database-provided functions (e.g., mysql_real_escape_string() for MySQL, though not recommended as primary defense), 3) Implement Web Application Firewall (WAF) rules to detect and block common SQL injection patterns, 4) Use database query monitoring and anomaly detection to identify suspicious queries, 5) Apply principle of least privilege at database level with read-only users for SELECT operations where possible, 6) Implement input length restrictions and character filtering to reduce attack surface. This approach should be temporary while migrating to parameterized queries.",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            languages={"python", "php", "javascript", "java", "csharp"},
            tags={"sql_injection", "database", "injection"}
        ))
        
        # Command Injection
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A03_002",
            name="Command Injection",
            description="System command execution with user-controlled input allows attackers to execute arbitrary operating system commands on the server. This vulnerability occurs when applications pass user input to system shell commands without proper validation or escaping. Attackers can chain multiple commands using shell metacharacters (;, &&, ||, |) to execute additional commands beyond the intended functionality. The impact is severe: attackers can read sensitive files (/etc/passwd, configuration files), modify system settings, install malware, create backdoors, access other systems on the network, or completely compromise the server. This can lead to data breaches, service disruption, lateral movement in network infrastructure, and potential regulatory violations. Remote code execution can also enable cryptocurrency mining, botnet participation, or use of the server for additional attacks.",
            severity="critical",
            confidence="high",
            owasp_category="A03",
            cwe_ids=[78, 77],
            regex_patterns=[
                r'(?i)(os\.system|subprocess\.(call|run|Popen))\s*\([^)]*\+[^)]*\)',
                r'(?i)(exec|eval|system)\s*\([^)]*\+[^)]*\)',
                r'(?i)shell=True.*\+',
                r'(?i)(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\([^)]*\+[^)]*\)',
            ],
            examples=[
                "os.system('ls ' + user_input)",
                "subprocess.call('ping ' + host, shell=True)",
                "eval('calculate(' + user_formula + ')')"
            ],
            primary_remediation="Replace shell command execution with subprocess module using argument arrays. Change 'os.system(\"ping \" + host)' to 'subprocess.run([\"ping\", \"-c\", \"1\", host], capture_output=True, timeout=30)'. Never use shell=True with user input. For file operations, use Python's built-in libraries (pathlib, shutil) instead of shell commands. Implement input validation with strict whitelisting: define allowed characters (alphanumeric, specific symbols), maximum length limits, and expected patterns using regex. Create a whitelist of allowed commands/operations rather than trying to blacklist dangerous ones. Use process isolation: run commands in restricted environments (chroot, containers, separate user accounts with minimal privileges). Set resource limits (CPU, memory, execution time) using subprocess timeout parameters and system-level controls (ulimit, cgroups).",
            alternative_remediation="If shell commands with user input cannot be avoided due to system requirements, implement defense in depth: 1) Input sanitization using shlex.quote() to escape shell metacharacters for any user input passed to shell commands, 2) Implement command whitelisting - maintain a predefined list of allowed commands and reject any others, 3) Use parameterized execution where possible (e.g., subprocess with argument lists instead of shell strings), 4) Apply input validation with strict character filtering: remove or reject input containing shell metacharacters (;, &, |, $, `, \\, !, <, >), 5) Run commands with restricted user accounts having minimal system privileges (not root), 6) Implement comprehensive logging and monitoring of all system command executions with alerting on suspicious patterns, 7) Use application sandboxing or containerization to limit the impact of successful command injection. Plan migration to eliminate shell command usage.",
            references=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://cwe.mitre.org/data/definitions/78.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
            ],
            languages={"python", "php", "javascript", "java"},
            tags={"command_injection", "system_calls", "injection"}
        ))
    
    def _add_insecure_design_patterns(self) -> None:
        """Add A04: Insecure Design patterns."""
        
        # Missing Rate Limiting
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A04_001",
            name="Missing Rate Limiting",
            description="Absence of rate limiting on sensitive operations allows attackers to perform automated attacks at scale. This enables brute force attacks against authentication systems, credential stuffing attacks using compromised password lists, account enumeration to discover valid usernames, denial of service through resource exhaustion, and abuse of expensive operations (password resets, SMS sending, API calls) leading to financial costs. The business impact includes increased infrastructure costs, service degradation affecting legitimate users, successful account compromises leading to data breaches, potential regulatory violations from inadequate access controls, and reputation damage from security incidents. Automated attacks can also bypass traditional security monitoring if not properly rate limited.",
            severity="medium",
            confidence="low",
            owasp_category="A04",
            cwe_ids=[770, 799],
            regex_patterns=[
                r'@app\.route\([^)]*\)\s*\n\s*def\s+(login|register|reset_password|send_email)',
                r'def\s+(login|authenticate|send_sms|verify)\w*\([^)]*\):\s*\n(?!.*rate_limit)',
                r'function\s+(login|register|forgot)\w*\([^)]*\)\s*{(?!.*rate.*limit)',
            ],
            examples=[
                "@app.route('/login', methods=['POST'])\ndef login():",
                "def send_password_reset_email(email):",
                "function authenticateUser(username, password) {"
            ],
            primary_remediation="Implement sophisticated rate limiting using Redis-based solutions with sliding window algorithms. Use tools like Flask-Limiter for Python applications with configurations like '@limiter.limit(\"5 per minute\")' for login attempts, '@limiter.limit(\"3 per hour\")' for password resets. Implement progressive delays: increase delay time with each failed attempt (exponential backoff). Use multiple rate limiting dimensions: per-IP address, per-user account, per-session, and global rate limits. Implement CAPTCHA challenges after threshold violations to distinguish human users from automated attacks. Use distributed rate limiting for multi-server deployments with shared state in Redis or database. Monitor and alert on rate limit violations for security incident detection. Implement whitelist mechanisms for trusted IP addresses or authenticated users with higher limits.",
            alternative_remediation="If advanced rate limiting infrastructure is not available, implement basic protection mechanisms: 1) In-memory rate tracking using dictionaries or simple caches with IP addresses as keys and attempt counts/timestamps as values, 2) Implement account lockout policies: lock accounts for 15-30 minutes after 5 failed login attempts, gradually increase lockout duration for repeated violations, 3) Add simple CAPTCHA or challenge-response mechanisms after 3 failed attempts, 4) Implement basic IP-based blocking using fail2ban or similar tools at the network level, 5) Add artificial delays to authentication responses (minimum 1-2 seconds) to slow down brute force attacks, 6) Use session-based tracking to limit attempts per session in addition to IP-based limits, 7) Implement basic monitoring and alerting for unusual authentication patterns. Plan upgrade to proper distributed rate limiting solutions.",
            references=[
                "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                "https://cwe.mitre.org/data/definitions/770.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java"},
            tags={"rate_limiting", "authentication", "design"}
        ))
    
    def _add_misconfiguration_patterns(self) -> None:
        """Add A05: Security Misconfiguration patterns."""
        
        # Debug Mode Enabled
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A05_001",
            name="Debug Mode Enabled",
            description="Debug mode enabled in production environments exposes sensitive application internals to potential attackers. Debug mode typically reveals detailed error messages including stack traces, source code snippets, database connection strings, internal file paths, and environment variables. This information disclosure helps attackers understand application architecture, identify additional vulnerabilities, and plan more targeted attacks. Debug endpoints may also provide administrative interfaces, code execution capabilities, or bypass normal security controls. The business impact includes information disclosure that aids reconnaissance for further attacks, potential exposure of credentials or sensitive configuration data, increased attack surface through debug endpoints, and potential regulatory compliance violations from inadequate data protection measures.",
            severity="high",
            confidence="high",
            owasp_category="A05",
            cwe_ids=[489, 489],
            regex_patterns=[
                r'(?i)DEBUG\s*=\s*True',
                r'(?i)app\.debug\s*=\s*True',
                r'(?i)app\.run\([^)]*debug\s*=\s*True',
                r'(?i)development\s*=\s*true',
                r'(?i)console\.log\s*\(',
            ],
            examples=[
                "DEBUG = True",
                "app.debug = True",
                "app.run(debug=True, host='0.0.0.0')"
            ],
            primary_remediation="Implement environment-based configuration management to automatically control debug settings based on deployment environment. Use environment variables: replace 'DEBUG = True' with 'DEBUG = os.getenv(\"DEBUG\", \"False\").lower() == \"true\"' and set environment variables through secure deployment pipelines. For Flask applications, use different configuration classes for development, staging, and production with debug automatically disabled in production. Implement configuration validation during application startup to verify production settings are correct and fail startup if debug mode is enabled in production. Use CI/CD pipeline checks to prevent deployment with debug enabled. Implement centralized configuration management using tools like Consul, etcd, or cloud-native configuration services. Set up monitoring and alerting to detect if debug mode is accidentally enabled in production environments.",
            alternative_remediation="If automated environment-based configuration is not available, implement manual safeguards and deployment procedures: 1) Create explicit production deployment checklists that include verifying debug mode is disabled, environment-specific configuration files are used, and verbose error reporting is turned off, 2) Implement code review processes that specifically check for debug settings in production deployment code, 3) Use deployment scripts that explicitly set debug=False during production deployments, 4) Implement application health checks that verify configuration settings and alert if debug mode is detected in production, 5) Use separate configuration files for each environment (development.config, production.config) and ensure only production configs are deployed to production systems, 6) Implement custom error handlers that provide generic error messages to users while logging detailed errors securely for developers. Gradually implement automated configuration management.",
            references=[
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                "https://cwe.mitre.org/data/definitions/489.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java"},
            tags={"debug_mode", "configuration", "production"}
        ))
    
    def _add_vulnerable_component_patterns(self) -> None:
        """Add A06: Vulnerable Components patterns."""
        
        # Outdated Dependencies
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A06_001",
            name="Potentially Vulnerable Dependencies",
            description="Dependencies with known vulnerabilities create significant security risks as attackers actively exploit public vulnerability databases to target applications using outdated components. Vulnerable dependencies can contain security flaws ranging from remote code execution and SQL injection to authentication bypasses and data exposure. The risk is amplified because dependencies often have deep dependency trees, making vulnerability tracking complex. Attackers use automated tools to scan for known vulnerable versions, making exploitation highly scalable. The business impact includes potential data breaches through dependency vulnerabilities, compliance violations from using components with known security issues, increased attack surface from multiple vulnerable components, legal liability from failing to maintain secure software, and operational disruption from emergency patching requirements.",
            severity="medium",
            confidence="low",
            owasp_category="A06",
            cwe_ids=[1104, 937],
            regex_patterns=[
                r'(?i)django\s*[<>=]*\s*[12]\.',
                r'(?i)flask\s*[<>=]*\s*0\.',
                r'(?i)requests\s*[<>=]*\s*2\.[0-5]\.',
                r'(?i)jquery\s*[<>=]*\s*[12]\.',
                r'(?i)spring.*[<>=]*\s*[34]\.',
            ],
            examples=[
                "Django==1.11.29",
                "Flask==0.12.4",
                "requests==2.5.3"
            ],
            primary_remediation="Implement automated dependency scanning and management in CI/CD pipelines using tools like Dependabot, Snyk, or OWASP Dependency-Check. Configure automated pull requests for security updates with staging environment testing before production deployment. Use dependency management tools: pip-audit for Python, npm audit for Node.js, or language-specific security scanners. Implement Software Bill of Materials (SBOM) generation to track all components and their versions. Set up vulnerability monitoring with automated alerts for newly discovered CVEs affecting used components. Use dependency pinning with regular updates rather than wildcard versioning. Implement security-focused dependency review processes that evaluate new dependencies for security track record, maintenance status, and alternatives. Establish maximum age policies for dependencies (e.g., no dependencies older than 12 months without security review).",
            alternative_remediation="If automated dependency scanning tools are not available, implement manual dependency management processes: 1) Maintain detailed inventory of all direct and transitive dependencies with versions in spreadsheets or documentation, 2) Subscribe to security mailing lists and RSS feeds for used frameworks and libraries to receive vulnerability notifications, 3) Implement quarterly dependency review cycles where all dependencies are checked against public vulnerability databases (CVE, NVD), 4) Use virtual environments or containerization to isolate dependencies and simplify testing of updates, 5) Implement staged update testing: test dependency updates in development, then staging, before production deployment, 6) Create emergency patching procedures for critical security updates with expedited testing and deployment processes, 7) Implement network-level protections (WAF, network segmentation) to reduce exposure of vulnerable components. Plan migration to automated dependency management tools.",
            references=[
                "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                "https://cwe.mitre.org/data/definitions/1104.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java"},
            tags={"dependencies", "outdated", "vulnerabilities"}
        ))
    
    def _add_authentication_patterns(self) -> None:
        """Add A07: Authentication Failures patterns."""
        
        # Weak Authentication
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A07_001",
            name="Weak Authentication Implementation",
            description="Weak or bypassed authentication mechanisms allow attackers to gain unauthorized access to user accounts and sensitive application functionality. This includes hardcoded credentials, weak password policies, insufficient account lockout mechanisms, predictable password reset processes, and session management vulnerabilities. Weak authentication enables credential stuffing attacks using breached password databases, brute force attacks against user accounts, account takeover through session hijacking, and privilege escalation through authentication bypasses. The business impact includes unauthorized access to user data and administrative functions, regulatory compliance violations (PCI DSS, HIPAA) from inadequate access controls, financial losses from account takeovers, reputation damage from data breaches, and potential legal liability from insufficient user data protection.",
            severity="high",
            confidence="medium",
            owasp_category="A07",
            cwe_ids=[287, 306, 620],
            regex_patterns=[
                r'(?i)if\s+password\s*==\s*["\'][^"\']*["\']',
                r'(?i)user\s*==\s*["\']admin["\']',
                r'(?i)password\s*in\s*\[["\'][^"\']*["\']',
                r'(?i)auth\s*=\s*(True|False)',
                r'(?i)session\[\s*["\']user["\']?\s*\]\s*=',
            ],
            examples=[
                "if password == 'admin123':",
                "if user == 'admin' and password == 'password':",
                "session['authenticated'] = True"
            ],
            primary_remediation="Implement robust authentication using established security frameworks and best practices. Use secure password hashing with bcrypt, scrypt, or Argon2 with appropriate cost factors (bcrypt rounds ≥12). Replace hardcoded credential checks with proper user authentication systems: implement user registration and login systems with encrypted password storage, multi-factor authentication (TOTP, SMS, hardware tokens), and secure session management with cryptographically secure session tokens. Implement proper session lifecycle management: generate new session IDs after authentication, set appropriate session timeouts, implement secure session invalidation on logout. Use OAuth 2.0 or SAML for third-party authentication where appropriate. Implement account lockout policies with progressive delays and CAPTCHA challenges after failed attempts.",
            alternative_remediation="If comprehensive authentication systems cannot be immediately implemented, strengthen existing authentication with incremental improvements: 1) Replace hardcoded passwords with environment variables or encrypted configuration files, increase password complexity requirements to include minimum 12 characters with mixed case, numbers, and symbols, 2) Implement basic account lockout after 5 failed attempts with 15-minute lockout periods, 3) Add password strength validation on the client and server side with real-time feedback, 4) Implement basic session security: use HTTPOnly and Secure flags on session cookies, implement session timeout after 30 minutes of inactivity, regenerate session IDs after login, 5) Add basic audit logging for all authentication attempts with alerting on suspicious patterns, 6) Implement password change requirements with validation that new passwords differ from previous passwords. Plan migration to proper authentication frameworks.",
            references=[
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "https://cwe.mitre.org/data/definitions/287.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java"},
            tags={"authentication", "weak_auth", "session"}
        ))
    
    def _add_integrity_patterns(self) -> None:
        """Add A08: Integrity Failures patterns."""
        
        # Insecure Deserialization
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A08_001",
            name="Insecure Deserialization",
            description="Unsafe deserialization of untrusted data allows attackers to execute arbitrary code, manipulate application logic, or gain unauthorized access through crafted serialized objects. This vulnerability is particularly dangerous because serialization formats like pickle, yaml.load(), and others can execute code during the deserialization process. Attackers can craft malicious serialized payloads that execute system commands, modify application state, access sensitive data, or establish persistent backdoors. The vulnerability is often exploitable remotely and can lead to complete system compromise. The business impact includes remote code execution leading to full server compromise, data breaches through unauthorized access to application data, service disruption through malicious payload execution, potential lateral movement within network infrastructure, and significant incident response costs from complete system compromise.",
            severity="critical",
            confidence="high",
            owasp_category="A08",
            cwe_ids=[502, 915],
            regex_patterns=[
                r'(?i)pickle\.(loads?|load)\s*\(',
                r'(?i)yaml\.load\s*\(',
                r'(?i)eval\s*\(',
                r'(?i)exec\s*\(',
                r'(?i)unserialize\s*\(',
                r'(?i)JSON\.parse\s*\([^)]*user',
            ],
            examples=[
                "pickle.loads(user_data)",
                "yaml.load(config_string)",
                "eval(user_expression)"
            ],
            primary_remediation="Replace unsafe deserialization with secure alternatives and implement strict input validation. Replace 'pickle.loads()' with 'json.loads()' for simple data structures, use 'yaml.safe_load()' instead of 'yaml.load()' for YAML parsing, replace 'eval()' with 'ast.literal_eval()' for safe expression evaluation. Implement data integrity checks using digital signatures or HMAC validation before deserialization to ensure data hasn't been tampered with. Use allowlist-based deserialization where only specific, safe object types are permitted. Implement deserialization in sandboxed environments with restricted permissions and network access. For complex objects, use schema validation libraries to verify structure and content before processing. Consider using safer serialization formats like Protocol Buffers or MessagePack with strict schemas.",
            alternative_remediation="If unsafe deserialization cannot be immediately eliminated due to legacy system requirements, implement defense-in-depth measures: 1) Implement strict input validation with allowlisting of permitted data types and structures, rejecting any unexpected object types or properties, 2) Use digital signatures (HMAC-SHA256) to verify data integrity and authenticity before deserialization, ensuring only trusted sources can provide serialized data, 3) Run deserialization processes in isolated environments (containers, chroot jails) with minimal system privileges and no network access, 4) Implement comprehensive monitoring and logging of all deserialization activities with alerting on suspicious patterns or failures, 5) Use application-level firewalls to filter and validate serialized data before it reaches the application, 6) Implement timeout and resource limits for deserialization processes to prevent resource exhaustion attacks. Plan migration to safe serialization alternatives.",
            references=[
                "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                "https://cwe.mitre.org/data/definitions/502.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java"},
            tags={"deserialization", "pickle", "unsafe_eval"}
        ))
    
    def _add_logging_patterns(self) -> None:
        """Add A09: Logging Failures patterns."""
        
        # Sensitive Data in Logs
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A09_001",
            name="Sensitive Data in Logs",
            description="Logging sensitive information creates data exposure risks through log files, centralized logging systems, and log analysis tools. Sensitive data in logs can include passwords, API keys, personal information (PII), financial data, session tokens, and authentication credentials. This information becomes accessible to system administrators, developers, security personnel, and potentially attackers who gain access to log files or logging infrastructure. Log files are often stored for extended periods, backed up to multiple locations, and may have less stringent access controls than application databases. The business impact includes regulatory compliance violations (GDPR, PCI DSS, HIPAA) from improper handling of sensitive data, data breaches through log file exposure, privacy violations leading to legal liability, increased attack surface through credential exposure in logs, and forensic complications from corrupted or tampered log data.",
            severity="medium",
            confidence="medium",
            owasp_category="A09",
            cwe_ids=[532, 117],
            regex_patterns=[
                r'(?i)log[^(]*\([^)]*(?:password|token|secret|key|ssn|credit)[^)]*\)',
                r'(?i)print\s*\([^)]*(?:password|token|secret|key)[^)]*\)',
                r'(?i)console\.log\([^)]*(?:password|token|secret)[^)]*\)',
                r'(?i)logger\.[^(]*\([^)]*(?:password|token|secret)[^)]*\)',
            ],
            examples=[
                "logger.info(f'Login attempt with password: {password}')",
                "print(f'API response: {api_key}')",
                "console.log('User token:', user_token)"
            ],
            primary_remediation="Implement log sanitization frameworks and structured logging with automatic sensitive data filtering. Use logging libraries with built-in data sanitization (e.g., Python's structlog with processors that mask sensitive fields). Create logging utility functions that automatically filter sensitive data: implement regex-based filtering for common sensitive patterns (credit cards, SSNs, passwords), use allowlist approaches where only specific safe fields are logged. Implement structured logging with field-level controls where sensitive fields are automatically excluded or masked. Use centralized logging configuration that applies sanitization rules consistently across the application. Implement log level management to ensure sensitive data is only logged at appropriate levels (never in production INFO/ERROR logs). Create developer training and code review guidelines for secure logging practices.",
            alternative_remediation="If automated log sanitization is not available, implement manual logging security practices and procedures: 1) Create and enforce coding standards that prohibit logging of sensitive data types, with specific guidelines for developers on what data should never be logged, 2) Implement manual code review processes specifically focused on logging statements to identify potential sensitive data exposure, 3) Use log preprocessing scripts that scan log files for sensitive patterns and mask or remove them before storage or transmission, 4) Implement field-level masking in logging statements: replace 'logger.info(f\"User {username} logged in with password {password}\")' with 'logger.info(f\"User {username} logged in successfully\")', 5) Create separate debug logging that only activates in development environments and is automatically disabled in production, 6) Implement log access controls and monitoring to track who accesses log files containing potentially sensitive information. Plan implementation of automated sanitization solutions.",
            references=[
                "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                "https://cwe.mitre.org/data/definitions/532.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java"},
            tags={"logging", "sensitive_data", "information_disclosure"}
        ))
    
    def _add_ssrf_patterns(self) -> None:
        """Add A10: SSRF patterns."""
        
        # Server-Side Request Forgery
        self._add_pattern(VulnerabilityPattern(
            pattern_id="A10_001",
            name="Server-Side Request Forgery",
            description="Server-Side Request Forgery (SSRF) allows attackers to make HTTP requests from the server to arbitrary destinations, potentially accessing internal systems not directly accessible from the internet. Attackers can exploit SSRF to scan internal networks, access cloud metadata services (AWS, Azure, GCP), interact with internal APIs and services, bypass firewall restrictions, and potentially gain access to sensitive information or perform actions on behalf of the server. This vulnerability is particularly dangerous in cloud environments where metadata services provide access to credentials and configuration data. The business impact includes unauthorized access to internal systems and data, exposure of cloud credentials through metadata service access, potential lateral movement within internal networks, data exfiltration from internal systems, and service disruption through attacks on internal infrastructure.",
            severity="high",
            confidence="medium",
            owasp_category="A10",
            cwe_ids=[918, 79],
            regex_patterns=[
                r'(?i)requests\.(get|post|put|delete|patch)\s*\([^)]*\+[^)]*\)',
                r'(?i)urllib\.request\.urlopen\s*\([^)]*\+[^)]*\)',
                r'(?i)fetch\s*\([^)]*\+[^)]*\)',
                r'(?i)http[s]?://.*\{[^}]*\}',
                r'(?i)(curl|wget)\s+.*\$\{?[^}]*\}?',
            ],
            examples=[
                "requests.get('http://api.example.com/' + user_url)",
                "urllib.request.urlopen(base_url + user_path)",
                "fetch('http://internal/' + request.query.endpoint)"
            ],
            primary_remediation="Implement strict URL validation and network-level controls to prevent SSRF attacks. Create URL allowlists with specific permitted domains and protocols: implement domain validation that only allows requests to predefined trusted hosts, use URL parsing libraries to validate and normalize URLs before making requests. Implement network segmentation: place application servers in DMZ with restricted outbound access, use firewall rules to block access to internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8), block access to cloud metadata endpoints (169.254.169.254). Use proxy servers for outbound requests with centralized logging and filtering. Implement DNS controls to prevent DNS rebinding attacks. Use dedicated service accounts with minimal privileges for external API access.",
            alternative_remediation="If comprehensive URL validation and network controls are not immediately feasible, implement layered protection measures: 1) Implement basic hostname and IP validation: reject requests to private IP ranges, localhost, and cloud metadata endpoints (169.254.169.254), 2) Use URL parsing to validate scheme, hostname, and port before making requests, rejecting file://, ftp://, and other non-HTTP protocols, 3) Implement request timeout and size limits to prevent resource exhaustion and limit data exfiltration, 4) Use HTTP client libraries with disabled redirect following to prevent redirect-based SSRF attacks, 5) Implement request logging and monitoring to detect suspicious outbound request patterns, 6) Use application-level firewalls or proxies to filter outbound requests and block suspicious destinations, 7) Implement user input validation to restrict URL parameters to expected formats and reject URLs with suspicious patterns. Plan implementation of proper network segmentation and URL validation.",
            references=[
                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                "https://cwe.mitre.org/data/definitions/918.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
            ],
            languages={"python", "javascript", "php", "java"},
            tags={"ssrf", "http_requests", "url_validation"}
        ))
    
    def get_pattern(self, pattern_id: str) -> Optional[VulnerabilityPattern]:
        """Get a specific vulnerability pattern by ID."""
        return self.patterns.get(pattern_id)
    
    def get_patterns_by_category(self, category: str) -> List[VulnerabilityPattern]:
        """Get all patterns for a specific OWASP category."""
        return self.patterns_by_category.get(category, [])
    
    def get_patterns_by_language(self, language: str) -> List[VulnerabilityPattern]:
        """Get all patterns applicable to a specific language."""
        return self.patterns_by_language.get(language, [])
    
    def get_all_patterns(self) -> List[VulnerabilityPattern]:
        """Get all vulnerability patterns."""
        return list(self.patterns.values())
    
    def search_patterns(self, query: str, field: str = "name") -> List[VulnerabilityPattern]:
        """Search patterns by name, description, or tags."""
        results = []
        query_lower = query.lower()
        
        for pattern in self.patterns.values():
            if field == "name" and query_lower in pattern.name.lower():
                results.append(pattern)
            elif field == "description" and query_lower in pattern.description.lower():
                results.append(pattern)
            elif field == "tags" and any(query_lower in tag for tag in pattern.tags):
                results.append(pattern)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the rule set."""
        total_patterns = len(self.patterns)
        
        severity_counts = {}
        for severity in SEVERITY_LEVELS.keys():
            severity_counts[severity] = len([p for p in self.patterns.values() if p.severity == severity])
        
        category_counts = {cat: len(patterns) for cat, patterns in self.patterns_by_category.items()}
        language_counts = {lang: len(patterns) for lang, patterns in self.patterns_by_language.items()}
        
        return {
            'total_patterns': total_patterns,
            'patterns_by_severity': severity_counts,
            'patterns_by_category': category_counts,
            'patterns_by_language': language_counts,
            'categories': list(OWASP_CATEGORIES.keys()),
            'supported_languages': list(self.patterns_by_language.keys())
        }

# Global rule set instance
_global_ruleset = None

def get_owasp_ruleset() -> OWASPRuleSet:
    """Get the global OWASP rule set instance."""
    global _global_ruleset
    if _global_ruleset is None:
        _global_ruleset = OWASPRuleSet()
    return _global_ruleset

def get_owasp_rule_by_id(pattern_id: str) -> Optional[VulnerabilityPattern]:
    """Get a specific OWASP rule by ID."""
    return get_owasp_ruleset().get_pattern(pattern_id)

def get_rules_by_category(category: str) -> List[VulnerabilityPattern]:
    """Get all rules for a specific OWASP category."""
    return get_owasp_ruleset().get_patterns_by_category(category)

def get_all_owasp_rules() -> List[VulnerabilityPattern]:
    """Get all OWASP vulnerability patterns."""
    return get_owasp_ruleset().get_all_patterns()

def get_rules_by_language(language: str) -> List[VulnerabilityPattern]:
    """Get all rules applicable to a specific programming language."""
    return get_owasp_ruleset().get_patterns_by_language(language)