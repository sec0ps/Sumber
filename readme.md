# Sumber Security Source Code Analyzer

**Static Application Security Testing (SAST) tool for identifying OWASP Top 10 vulnerabilities in source code.**

---

## Overview

Sumber is a static application security testing tool that performs deep source code analysis to identify security vulnerabilities aligned with the OWASP Top 10 2021. Built with a modular architecture, it provides detailed vulnerability reports with actionable remediation guidance.

**Current Language Support:** Python (with extensible framework for additional languages)

**Planned Language Expansion:** JavaScript, PHP, C/C++, Go, Java, C#/.NET, Ruby, Rust, TypeScript, Kotlin, Swift, Perl, PowerShell

### Key Features

- **OWASP Top 10 2021 Coverage** - Detection of injection flaws, authentication issues, cryptographic failures, and more
- **AST-Based Analysis** - Deep Abstract Syntax Tree parsing for accurate vulnerability detection with Python focus
- **Professional Reporting** - Rich HTML reports with code highlighting, CWE mappings, and detailed remediation guidance
- **Configurable Rules** - Extensible rule engine with severity classification and confidence scoring
- **Multi-Language Architecture** - Modular framework designed for easy language expansion
- **Performance Optimized** - Parallel processing with configurable timeouts and resource limits

---

## Quick Start

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/redcellsecurity/sumber.git
cd sumber
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run your first scan:**
```bash
python cli.py /path/to/your/project
```

### Basic Usage

```bash
# Analyze a single Python file
python cli.py myapp.py

# Analyze entire Python project directory
python cli.py /path/to/project

# Generate report with custom output location
python cli.py /path/to/project --output /path/to/security_report.html

# Filter by severity level
python cli.py /path/to/project --severity high

# Include test files in analysis
python cli.py /path/to/project --include-tests

# Exclude specific patterns
python cli.py /path/to/project --exclude "*.test.py" --exclude "temp/*"
```

---

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `target` | File or directory to analyze | `python cli.py /app` |
| `--language, -l` | Specific language to analyze | `--language python` |
| `--output, -o` | Output file path for HTML report | `--output report.html` |
| `--config, -c` | Path to custom configuration file | `--config myconfig.json` |
| `--severity` | Minimum severity level to report | `--severity high` |
| `--exclude` | Exclude files/directories (can be used multiple times) | `--exclude "test_*"` |
| `--include-tests` | Include test files in analysis | `--include-tests` |
| `--verbose, -v` | Enable verbose output | `--verbose` |
| `--quiet, -q` | Suppress all output except errors | `--quiet` |
| `--list-rules` | List all available detection rules | `--list-rules` |
| `--list-languages` | List supported programming languages | `--list-languages` |

---

## Supported Vulnerabilities

Sumber detects vulnerabilities across all OWASP Top 10 2021 categories:

### A01 - Broken Access Control
- Insecure Direct Object Reference
- Missing Function Level Authorization
- Path Traversal vulnerabilities

### A02 - Cryptographic Failures
- Hardcoded secrets and API keys
- Weak cryptographic algorithms (MD5, SHA1, DES)
- Insecure random number generation

### A03 - Injection
- SQL Injection via string concatenation
- Command Injection through system calls
- Code injection through eval/exec

### A04 - Insecure Design
- Missing rate limiting on sensitive operations
- Insufficient business logic validation

### A05 - Security Misconfiguration
- Debug mode enabled in production
- Verbose error reporting
- Insecure default configurations

### A06 - Vulnerable and Outdated Components
- Outdated dependency detection
- Known vulnerable library versions

### A07 - Identification and Authentication Failures
- Weak authentication implementations
- Hardcoded credentials
- Insecure session management

### A08 - Software and Data Integrity Failures
- Insecure deserialization (pickle, yaml.load)
- Dynamic code execution vulnerabilities

### A09 - Security Logging and Monitoring Failures
- Sensitive data in log files
- Information disclosure through error messages

### A10 - Server-Side Request Forgery (SSRF)
- HTTP requests to user-controlled URLs
- Internal network access vulnerabilities

---

## Report Features

Sumber generates HTML reports with:

- **Executive Summary** - High-level vulnerability statistics and trends
- **OWASP Category Breakdown** - Issues organized by security category
- **Code Context** - Highlighted vulnerable code snippets with surrounding context
- **Dual Remediation Guidance** - Primary recommended fixes and alternative approaches
- **CWE Mappings** - Industry-standard Common Weakness Enumeration references
- **Severity Classification** - Critical, High, Medium, Low risk levels
- **Technical References** - Links to OWASP guidelines and security resources

---

## ⚙️ Configuration

Sumber works out-of-the-box with sensible defaults for Python code analysis:

```python
{
    'analysis': {
        'min_severity': 'medium',
        'include_tests': False,
        'max_file_size_mb': 10,
        'timeout_per_file_seconds': 30
    },
    'exclusions': {
        'patterns': [
            '*.pyc', '__pycache__/*', '.git/*', 
            'venv/*', 'node_modules/*', 'dist/*'
        ]
    }
}
```

Configuration can be customized through command-line options for immediate use.

---

### Language Roadmap

**Currently Supported:**
- **Python** - Complete OWASP Top 10 coverage with AST analysis

**Planned Language Support:**
- **JavaScript/TypeScript** - Node.js and browser-side vulnerability detection
- **PHP** - Web application security analysis
- **C/C++** - Memory safety and buffer overflow detection
- **Go** - Concurrent programming and API security analysis
- **Java** - Enterprise application security scanning
- **C#/.NET** - Microsoft stack security analysis
- **Ruby** - Rails and web application security
- **Rust** - Memory safety validation (though Rust prevents many issues by design)
- **Kotlin** - Android and JVM security analysis
- **Swift** - iOS application security scanning
- **Perl** - Legacy system and script analysis
- **PowerShell** - Windows automation and administration script security

### Extensibility

The modular architecture allows easy extension:

- **New Languages**: Add analyzers in `language_modules/`
- **Custom Rules**: Extend `rules/` with domain-specific patterns
- **Output Formats**: Add new reporters (JSON, XML, SARIF)
- **Integrations**: Hook into CI/CD pipelines and SIEM systems

---

## Development

### Adding New Rules

1. **Create rule class** extending `BaseSecurityRule`:

```python
class CustomRule(ASTSecurityRule):
    def __init__(self):
        super().__init__(
            rule_id="CUSTOM_001",
            title="Custom Security Issue",
            description="Detailed vulnerability description",
            severity=Severity.HIGH,
            owasp_category=RuleCategory.A03_INJECTION
        )
    
    def check_ast(self, tree, content, file_path):
        # Implement detection logic
        return matches
```

2. **Register rule** in language analyzer:

```python
def _initialize_rules(self):
    self.add_rule(CustomRule())
```

### Testing

```bash
# Run test suite
pytest tests/

# Run with coverage
pytest --cov=. tests/

# Test specific functionality
pytest tests/test_sql_injection.py -v
```

---

## Integration

### CI/CD Pipeline Integration

**GitHub Actions:**
```yaml
- name: Security Code Analysis
  run: |
    python cli.py . --output security_report.html --severity high
    # Fail build if critical issues found
    if grep -q "Critical" security_report.html; then exit 1; fi
```

**Jenkins:**
```groovy
stage('Security Scan') {
    steps {
        sh 'python cli.py . --output security_report.html'
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: '.',
            reportFiles: 'security_report.html',
            reportName: 'Security Analysis Report'
        ])
    }
}
```

### IDE Integration

Most IDEs can run Sumber as an external tool for Python projects:

**VS Code** - Add to `.vscode/tasks.json`:
```json
{
    "label": "Sumber Security Scan",
    "type": "shell",
    "command": "python",
    "args": ["cli.py", "${workspaceFolder}"],
    "group": "build"
}
```

---

## 📈 Performance

### Benchmarks

| Project Size | Python Files | Analysis Time | Memory Usage |
|--------------|--------------|---------------|--------------|
| Small (1K LOC) | 10-50 | 2-5 seconds | 50MB |
| Medium (10K LOC) | 100-500 | 30-60 seconds | 200MB |
| Large (100K LOC) | 1000+ | 5-15 minutes | 500MB |

### Optimization Tips

- Use `--exclude` patterns to skip non-essential files
- Set appropriate `--severity` levels for faster scanning
- Configure `max_file_size_mb` to skip large generated files
- Use parallel processing (automatic with multi-core systems)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🏢 About Red Cell Security

Sumber is developed and maintained by [Red Cell Security, LLC](https://www.redcellsecurity.org), a cybersecurity consultancy specializing in application security, penetration testing, and security tool development.

### Contact

- **Website**: [www.redcellsecurity.org](https://www.redcellsecurity.org)
- **Email**: keith@redcellsecurity.org
- **Author**: Keith Pachulski


---

*"Security through transparency and continuous improvement"* - Red Cell Security
