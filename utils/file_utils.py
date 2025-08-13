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
import hashlib
import mimetypes
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Union, Any
import chardet
import re

logger = logging.getLogger(__name__)

class FileManager:
    """
    Secure file management utilities for the analyzer.
    
    Provides safe file operations with built-in security checks,
    encoding detection, and error handling.
    """
    
    # Common text file extensions
    TEXT_EXTENSIONS = {
        '.py', '.pyw', '.php', '.js', '.jsx', '.ts', '.tsx',
        '.java', '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
        '.cs', '.go', '.rs', '.rb', '.pl', '.pm', '.sh',
        '.bash', '.zsh', '.fish', '.ps1', '.sql', '.html',
        '.htm', '.xml', '.json', '.yaml', '.yml', '.toml',
        '.ini', '.cfg', '.conf', '.txt', '.md', '.rst'
    }
    
    # Binary file extensions to avoid
    BINARY_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib', '.bin', '.obj',
        '.pyc', '.pyo', '.class', '.jar', '.war', '.ear',
        '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
        '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wmv',
        '.ttf', '.otf', '.woff', '.woff2'
    }
    
    # Maximum file size for text detection (10MB)
    MAX_TEXT_DETECTION_SIZE = 10 * 1024 * 1024
    
    def __init__(self, max_file_size: int = 50 * 1024 * 1024):
        """
        Initialize FileManager.
        
        Args:
            max_file_size (int): Maximum file size to process in bytes
        """
        self.max_file_size = max_file_size
    
    def is_safe_to_read(self, file_path: Path) -> bool:
        """
        Check if a file is safe to read.
        
        Args:
            file_path (Path): Path to the file
            
        Returns:
            bool: True if file is safe to read
        """
        try:
            if not file_path.exists() or not file_path.is_file():
                return False
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                logger.debug(f"File too large: {file_path} ({file_size} bytes)")
                return False
            
            # Check if it's a text file
            if not is_text_file(file_path):
                logger.debug(f"Not a text file: {file_path}")
                return False
            
            # Check read permissions
            if not os.access(file_path, os.R_OK):
                logger.debug(f"No read permission: {file_path}")
                return False
            
            return True
            
        except Exception as e:
            logger.debug(f"Error checking file safety {file_path}: {str(e)}")
            return False


def is_text_file(file_path: Path) -> bool:
    """
    Determine if a file is a text file.
    
    Args:
        file_path (Path): Path to the file
        
    Returns:
        bool: True if file appears to be text
    """
    try:
        # Check extension first (fast check)
        ext = file_path.suffix.lower()
        
        if ext in FileManager.BINARY_EXTENSIONS:
            return False
        
        if ext in FileManager.TEXT_EXTENSIONS:
            return True
        
        # For unknown extensions, sample the file content
        return _is_text_by_content(file_path)
        
    except Exception as e:
        logger.debug(f"Error determining if text file {file_path}: {str(e)}")
        return False


def _is_text_by_content(file_path: Path, sample_size: int = 8192) -> bool:
    """
    Determine if file is text by examining content.
    
    Args:
        file_path (Path): Path to the file
        sample_size (int): Number of bytes to sample
        
    Returns:
        bool: True if content appears to be text
    """
    try:
        # Don't sample very large files
        file_size = file_path.stat().st_size
        if file_size > FileManager.MAX_TEXT_DETECTION_SIZE:
            return False
        
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
        
        if not sample:
            return True  # Empty files are considered text
        
        # Check for null bytes (strong indicator of binary)
        if b'\x00' in sample:
            return False
        
        # Try to decode as text
        try:
            sample.decode('utf-8')
            return True
        except UnicodeDecodeError:
            pass
        
        # Try with encoding detection
        detected = chardet.detect(sample)
        if detected and detected.get('confidence', 0) > 0.7:
            try:
                sample.decode(detected['encoding'])
                return True
            except (UnicodeDecodeError, LookupError):
                pass
        
        # Check for high percentage of printable characters
        printable_chars = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
        text_ratio = printable_chars / len(sample)
        
        return text_ratio > 0.75
        
    except Exception as e:
        logger.debug(f"Error sampling file content {file_path}: {str(e)}")
        return False


def get_file_language(file_path: Path) -> Optional[str]:
    """
    Determine the programming language of a file.
    
    Args:
        file_path (Path): Path to the file
        
    Returns:
        str: Language name or None if unknown
    """
    ext = file_path.suffix.lower()
    
    # Common language mappings
    language_map = {
        '.py': 'python',
        '.pyw': 'python',
        '.php': 'php',
        '.php3': 'php',
        '.php4': 'php',
        '.php5': 'php',
        '.phtml': 'php',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.h': 'c',
        '.hpp': 'cpp',
        '.cs': 'csharp',
        '.go': 'go',
        '.rs': 'rust',
        '.rb': 'ruby',
        '.pl': 'perl',
        '.pm': 'perl',
        '.sh': 'shell',
        '.bash': 'shell',
        '.zsh': 'shell',
        '.fish': 'shell',
        '.ps1': 'powershell',
        '.sql': 'sql'
    }
    
    return language_map.get(ext)


def safe_read_file(file_path: Path, encoding: Optional[str] = None, max_size: Optional[int] = None) -> Optional[str]:
    """
    Safely read a text file with encoding detection.
    
    Args:
        file_path (Path): Path to the file
        encoding (str, optional): Specific encoding to use
        max_size (int, optional): Maximum file size to read
        
    Returns:
        str: File content or None if read failed
    """
    try:
        file_size = file_path.stat().st_size
        
        # Check file size limit
        if max_size and file_size > max_size:
            logger.warning(f"File too large to read: {file_path} ({file_size} bytes)")
            return None
        
        # Read with specified encoding
        if encoding:
            try:
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    return f.read()
            except (UnicodeDecodeError, LookupError) as e:
                logger.debug(f"Failed to read with encoding {encoding}: {file_path}")
        
        # Try UTF-8 first
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            pass
        
        # Detect encoding
        with open(file_path, 'rb') as f:
            raw_data = f.read()
        
        detected = chardet.detect(raw_data)
        if detected and detected.get('confidence', 0) > 0.6:
            try:
                return raw_data.decode(detected['encoding'], errors='replace')
            except (UnicodeDecodeError, LookupError):
                pass
        
        # Fallback to latin-1 (can decode any byte sequence)
        return raw_data.decode('latin-1', errors='replace')
        
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None


def calculate_file_hash(file_path: Path, algorithm: str = 'sha256') -> Optional[str]:
    """
    Calculate hash of a file.
    
    Args:
        file_path (Path): Path to the file
        algorithm (str): Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        str: Hex digest of file hash or None if failed
    """
    try:
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
        
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {str(e)}")
        return None


def get_file_info(file_path: Path) -> Dict[str, Any]:
    """
    Get comprehensive information about a file.
    
    Args:
        file_path (Path): Path to the file
        
    Returns:
        dict: File information dictionary
    """
    info = {
        'path': str(file_path),
        'name': file_path.name,
        'extension': file_path.suffix.lower(),
        'language': None,
        'size': 0,
        'lines': 0,
        'is_text': False,
        'encoding': None,
        'hash': None,
        'mime_type': None,
        'error': None
    }
    
    try:
        if not file_path.exists():
            info['error'] = 'File does not exist'
            return info
        
        if not file_path.is_file():
            info['error'] = 'Not a regular file'
            return info
        
        # Basic file stats
        stat = file_path.stat()
        info['size'] = stat.st_size
        
        # Check if it's a text file
        info['is_text'] = is_text_file(file_path)
        
        if info['is_text']:
            # Language detection
            info['language'] = get_file_language(file_path)
            
            # Line count
            info['lines'] = count_lines_of_code(file_path)
            
            # Encoding detection
            info['encoding'] = _detect_encoding(file_path)
            
            # File hash
            info['hash'] = calculate_file_hash(file_path)
        
        # MIME type
        mime_type, _ = mimetypes.guess_type(str(file_path))
        info['mime_type'] = mime_type
        
    except Exception as e:
        info['error'] = str(e)
        logger.error(f"Error getting file info for {file_path}: {str(e)}")
    
    return info


def _detect_encoding(file_path: Path) -> Optional[str]:
    """
    Detect file encoding.
    
    Args:
        file_path (Path): Path to the file
        
    Returns:
        str: Detected encoding or None
    """
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(8192)  # Sample first 8KB
        
        detected = chardet.detect(raw_data)
        if detected and detected.get('confidence', 0) > 0.7:
            return detected['encoding']
        
        return None
        
    except Exception:
        return None


def normalize_path(path: Union[str, Path]) -> Path:
    """
    Normalize and resolve a file path securely.
    
    Args:
        path (Union[str, Path]): Path to normalize
        
    Returns:
        Path: Normalized path object
    """
    try:
        path_obj = Path(path)
        return path_obj.resolve()
    except Exception as e:
        logger.error(f"Error normalizing path {path}: {str(e)}")
        return Path(path)


def is_safe_path(path: Path, base_path: Optional[Path] = None) -> bool:
    """
    Check if a path is safe (no directory traversal).
    
    Args:
        path (Path): Path to check
        base_path (Path, optional): Base path to restrict to
        
    Returns:
        bool: True if path is safe
    """
    try:
        normalized = normalize_path(path)
        
        if base_path:
            base_normalized = normalize_path(base_path)
            try:
                normalized.relative_to(base_normalized)
            except ValueError:
                return False  # Path is outside base directory
        
        # Check for suspicious path components
        parts = normalized.parts
        for part in parts:
            if part in ('..', '.'):
                return False
            if part.startswith('.') and len(part) > 1:
                # Allow hidden files but be cautious
                continue
        
        return True
        
    except Exception as e:
        logger.error(f"Error checking path safety {path}: {str(e)}")
        return False


def extract_code_snippet(file_path: Path, line_number: int, context_lines: int = 3) -> Optional[Dict[str, Any]]:
    """
    Extract a code snippet around a specific line.
    
    Args:
        file_path (Path): Path to the source file
        line_number (int): Target line number (1-based)
        context_lines (int): Number of context lines before and after
        
    Returns:
        dict: Code snippet information or None if failed
    """
    try:
        content = safe_read_file(file_path)
        if not content:
            return None
        
        lines = content.splitlines()
        
        if line_number < 1 or line_number > len(lines):
            return None
        
        # Calculate snippet range (0-based indexing)
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)
        
        snippet_lines = []
        for i in range(start_line, end_line):
            snippet_lines.append({
                'line_number': i + 1,
                'content': lines[i],
                'is_target': i + 1 == line_number
            })
        
        return {
            'file_path': str(file_path),
            'target_line': line_number,
            'start_line': start_line + 1,
            'end_line': end_line,
            'lines': snippet_lines,
            'language': get_file_language(file_path)
        }
        
    except Exception as e:
        logger.error(f"Error extracting code snippet from {file_path}:{line_number}: {str(e)}")
        return None


def count_lines_of_code(file_path: Path) -> int:
    """
    Count lines of code in a file (excluding empty lines and comments).
    
    Args:
        file_path (Path): Path to the file
        
    Returns:
        int: Number of lines of code
    """
    try:
        content = safe_read_file(file_path)
        if not content:
            return 0
        
        lines = content.splitlines()
        language = get_file_language(file_path)
        
        loc = 0
        in_multiline_comment = False
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Language-specific comment handling
            if language == 'python':
                # Handle Python comments and docstrings
                if line.startswith('#'):
                    continue
                if '"""' in line or "'''" in line:
                    # Simple docstring detection (not perfect but good enough)
                    if line.count('"""') % 2 == 1 or line.count("'''") % 2 == 1:
                        in_multiline_comment = not in_multiline_comment
                    if in_multiline_comment or line.strip() in ('"""', "'''"):
                        continue
                if in_multiline_comment:
                    continue
            
            elif language in ('javascript', 'java', 'c', 'cpp', 'csharp', 'go'):
                # Handle C-style comments
                if line.startswith('//'):
                    continue
                if '/*' in line:
                    in_multiline_comment = True
                if '*/' in line:
                    in_multiline_comment = False
                    continue
                if in_multiline_comment:
                    continue
            
            elif language == 'shell':
                # Handle shell comments
                if line.startswith('#'):
                    continue
            
            # If we get here, it's a line of code
            loc += 1
        
        return loc
        
    except Exception as e:
        logger.error(f"Error counting lines of code in {file_path}: {str(e)}")
        return 0