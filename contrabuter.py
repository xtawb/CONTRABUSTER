#!/usr/bin/env python3
"""
                                                                                         
                                                                                         
▄█████ ▄████▄ ███  ██ ██████ █████▄  ▄████▄ █████▄ ██  ██ ▄█████ ██████ ██████ █████▄    
██     ██  ██ ██ ▀▄██   ██   ██▄▄██▄ ██▄▄██ ██▄▄██ ██  ██ ▀▀▀▄▄▄   ██   ██▄▄   ██▄▄██▄   
▀█████ ▀████▀ ██   ██   ██   ██   ██ ██  ██ ██▄▄█▀ ▀████▀ █████▀   ██   ██▄▄▄▄ ██   ██   
                                                                                         
                        Advanced Container Intelligence Scanner
"""

__version__ = "1.0.2"
__author__ = "xtawb"
__contact__ = "https://linktr.ee/xtawb"

import argparse
import asyncio
import aiohttp
import aiofiles
import re
import json
import hashlib
import math
import base64
import mimetypes
import time
import signal
import sys
import os
import tempfile
import shutil
import subprocess
import platform
from typing import Dict, List, Tuple, Optional, Set, Any
from urllib.parse import urlparse, urljoin, quote
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from datetime import datetime
import logging
from concurrent.futures import ThreadPoolExecutor
import zlib
from html import escape
import urllib.request
import urllib.error

try:
    import entropy
    ENTROPY_AVAILABLE = True
except ImportError:
    ENTROPY_AVAILABLE = False

# =======================
# Color System
# =======================

class Colors:
    """Professional color system for CLI output"""
    
    # Severity Colors
    CRITICAL = "\033[38;5;196m"      # Bright Red
    HIGH = "\033[38;5;202m"          # Orange Red
    MEDIUM = "\033[38;5;226m"        # Bright Yellow
    LOW = "\033[38;5;82m"            # Bright Green
    INFO = "\033[38;5;39m"           # Bright Blue
    
    # Status Colors
    SUCCESS = "\033[38;5;46m"        # Bright Green
    WARNING = "\033[38;5;220m"       # Gold
    ERROR = "\033[38;5;196m"         # Bright Red
    DEBUG = "\033[38;5;99m"          # Purple
    
    # UI Colors
    BANNER = "\033[38;5;51m"         # Cyan
    HEADER = "\033[38;5;75m"         # Light Blue
    ACCENT = "\033[38;5;214m"        # Orange
    TEXT = "\033[38;5;250m"          # Light Gray
    MUTED = "\033[38;5;244m"         # Gray
    
    # Reset
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    @staticmethod
    def colorize(text: str, color_code: str) -> str:
        """Apply color to text"""
        return f"{color_code}{text}{Colors.RESET}"
    
    @staticmethod
    def severity_color(severity: str) -> str:
        """Get color for severity level"""
        colors = {
            "CRITICAL": Colors.CRITICAL,
            "HIGH": Colors.HIGH,
            "MEDIUM": Colors.MEDIUM,
            "LOW": Colors.LOW,
            "INFORMATIONAL": Colors.INFO
        }
        return colors.get(severity.upper(), Colors.TEXT)

# =======================
# Self-Update System
# =======================

class UpdateManager:
    """Automatic update system for CONTRABUSTER"""
    
    # Official repository information
    REPO_URL = "https://api.github.com/repos/xtawb/CONTRABUSTER/releases/latest"
    RAW_BASE = "https://raw.githubusercontent.com/xtawb/CONTRABUSTER/main/"
    
    @staticmethod
    def check_for_updates(current_version: str) -> Optional[Dict]:
        """Check for available updates"""
        try:
            headers = {
                'User-Agent': 'CONTRABUSTER-Scanner',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            req = urllib.request.Request(UpdateManager.REPO_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                latest_version = data.get('tag_name', '').lstrip('v')
                if not latest_version:
                    return None
                
                # Compare versions
                if UpdateManager._compare_versions(current_version, latest_version) < 0:
                    return {
                        'latest_version': latest_version,
                        'current_version': current_version,
                        'changelog': data.get('body', ''),
                        'release_url': data.get('html_url', ''),
                        'assets': data.get('assets', []),
                        'published_at': data.get('published_at', '')
                    }
            
            return None
            
        except Exception as e:
            logging.debug(f"Update check failed: {e}")
            return None
    
    @staticmethod
    def _compare_versions(v1: str, v2: str) -> int:
        """Compare version strings"""
        def parse_version(v):
            return [int(x) for x in v.split('.')]
        
        try:
            v1_parts = parse_version(v1)
            v2_parts = parse_version(v2)
            
            for i in range(max(len(v1_parts), len(v2_parts))):
                v1_part = v1_parts[i] if i < len(v1_parts) else 0
                v2_part = v2_parts[i] if i < len(v2_parts) else 0
                
                if v1_part < v2_part:
                    return -1
                elif v1_part > v2_part:
                    return 1
            
            return 0
        except:
            return 0
    
    @staticmethod
    def download_update(update_info: Dict) -> bool:
        """Download and apply update"""
        try:
            print(f"\n{Colors.colorize('[UPDATE]', Colors.ACCENT)} Downloading version {update_info['latest_version']}...")
            
            # Get the main script URL
            script_url = f"{UpdateManager.RAW_BASE}contrabuster.py"
            
            # Download the new version
            response = urllib.request.urlopen(script_url, timeout=30)
            new_content = response.read().decode('utf-8')
            
            # Verify it's a valid CONTRABUSTER script
            if "CONTRABUSTER" not in new_content:
                print(f"{Colors.colorize('[ERROR]', Colors.ERROR)} Downloaded file is not valid")
                return False
            
            # Create backup
            current_file = __file__
            backup_file = f"{current_file}.backup"
            shutil.copy2(current_file, backup_file)
            
            # Write new version
            with open(current_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            # Verify the new version
            new_version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', new_content)
            if new_version_match and new_version_match.group(1) == update_info['latest_version']:
                print(f"{Colors.colorize('[SUCCESS]', Colors.SUCCESS)} Updated to version {update_info['latest_version']}")
                
                # Make executable on Unix systems
                if platform.system() != 'Windows':
                    os.chmod(current_file, 0o755)
                
                return True
            else:
                # Restore backup
                shutil.copy2(backup_file, current_file)
                print(f"{Colors.colorize('[ERROR]', Colors.ERROR)} Update verification failed, restored backup")
                return False
                
        except Exception as e:
            print(f"{Colors.colorize('[ERROR]', Colors.ERROR)} Update failed: {e}")
            return False

# =======================
# Branding System
# =======================

class Branding:
    """CONTRABUSTER branding and identity system"""
    
    @staticmethod
    def print_banner():
        """Display CONTRABUSTER banner"""
        banner = rf"""
{Colors.BANNER}{Colors.BOLD}
   _____ ____  _   _ _______ _____            ____  _    _  _____ _______ ______ _____  
  / ____/ __ \| \ | |__   __|  __ \     /\   |  _ \| |  | |/ ____|__   __|  ____|  __ \ 
 | |   | |  | |  \| |  | |  | |__) |   /  \  | |_) | |  | | (___    | |  | |__  | |__) |
 | |   | |  | | . ` |  | |  |  _  /   / /\ \ |  _ <| |  | |\___ \   | |  |  __| |  _  / 
 | |___| |__| | |\  |  | |  | | \ \  / ____ \| |_) | |__| |____) |  | |  | |____| | \ \ 
  \_____\____/|_| \_|  |_|  |_|  \_\/_/    \_\____/ \____/|_____/   |_|  |______|_|  \_\
{Colors.RESET}
{Colors.ACCENT}{Colors.BOLD}                    Advanced Container Intelligence Scanner{Colors.RESET}
{Colors.MUTED}{Colors.BOLD}                              Professional Edition{Colors.RESET}
"""
        print(banner)
    
    @staticmethod
    def print_developer_info():
        """Display developer information"""
        info = f"""
{Colors.HEADER}{Colors.BOLD}Developer:{Colors.RESET} {Colors.TEXT}xtawb{Colors.RESET}
{Colors.HEADER}{Colors.BOLD}Contact:{Colors.RESET}  {Colors.TEXT}https://linktr.ee/xtawb{Colors.RESET}
{Colors.HEADER}{Colors.BOLD}Version:{Colors.RESET}  {Colors.TEXT}{__version__}{Colors.RESET}
"""
        print(info)
    
    @staticmethod
    def print_disclaimer():
        """Display security disclaimer"""
        disclaimer = f"""
{Colors.WARNING}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}
{Colors.WARNING}{Colors.BOLD}║                       SECURITY NOTICE                        ║{Colors.RESET}
{Colors.WARNING}{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
{Colors.WARNING}This tool is for authorized security testing only.{Colors.RESET}
{Colors.WARNING}Unauthorized use against systems you don't own is illegal.{Colors.RESET}
{Colors.WARNING}You are responsible for your own actions.{Colors.RESET}
"""
        print(disclaimer)

# =======================
# Data Models
# =======================

class Severity(Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class FileType(Enum):
    JAVASCRIPT = "JavaScript"
    JSON = "JSON"
    CONFIG = "Configuration"
    ENVIRONMENT = "Environment"
    BINARY = "Binary"
    MEDIA = "Media"
    DOCUMENT = "Document"
    ARCHIVE = "Archive"
    OTHER = "Other"

@dataclass
class Finding:
    file_url: str
    file_name: str
    file_type: FileType
    rule_name: str
    description: str
    severity: Severity
    match: str
    context: Optional[str] = None
    line_number: Optional[int] = None
    exploitability: str = ""
    recommendation: str = ""
    confidence: float = 0.0

@dataclass
class JSFeature:
    file_url: str
    feature_type: str
    value: str
    context: str
    line_number: int
    severity: Severity

@dataclass
class ScanStats:
    total_files: int = 0
    scanned_files: int = 0
    findings: List[Finding] = field(default_factory=list)
    js_features: List[JSFeature] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    errors: List[str] = field(default_factory=list)

# =======================
# Configuration
# =======================

class Config:
    # Performance
    MAX_CONCURRENT_REQUESTS = 10
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 3
    RETRY_DELAY = 1
    
    # Security
    RATE_LIMIT_DELAY = 0.1
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    
    # Analysis
    MIN_ENTROPY_THRESHOLD = 4.5
    MAX_CONTEXT_LINES = 3
    
    # Ignore patterns
    IGNORE_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
        '.mp4', '.mp3', '.avi', '.mov', '.wav',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.ttf', '.woff', '.woff2', '.eot'
    }
    
    IGNORE_PATHS = {
        '__MACOSX', '.git', '.svn', '.DS_Store',
        'node_modules', 'bower_components', 'vendor'
    }

# =======================
# Secret Pattern Database
# =======================

class SecretPatterns:
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> List[Dict]:
        """Load comprehensive secret patterns with metadata"""
        return [
            # Cloud Providers
            {
                "name": "AWS_ACCESS_KEY",
                "pattern": r"(?i)(?:aws|amazon)[^a-z0-9]*?(?:access[^a-z0-9]*?key|key[^a-z0-9]*?id)[^a-z0-9]*?['\"]?[=:\s]*['\"]?(AKIA[0-9A-Z]{16,})['\"]?",
                "description": "AWS Access Key ID",
                "severity": Severity.CRITICAL,
                "provider": "AWS",
                "validation": self._validate_aws_key
            },
            {
                "name": "AWS_SECRET_KEY",
                "pattern": r"(?i)(?:aws|amazon)[^a-z0-9]*?(?:secret|private)[^a-z0-9]*?(?:access)?[^a-z0-9]*?key[^a-z0-9]*?['\"]?[=:\s]*['\"]?([A-Za-z0-9/+]{40})['\"]?",
                "description": "AWS Secret Access Key",
                "severity": Severity.CRITICAL,
                "provider": "AWS"
            },
            {
                "name": "GCP_API_KEY",
                "pattern": r"AIza[0-9A-Za-z\-_]{35}",
                "description": "Google Cloud Platform API Key",
                "severity": Severity.HIGH,
                "provider": "GCP"
            },
            {
                "name": "GCP_SERVICE_ACCOUNT",
                "pattern": r'"type":\s*"service_account".{0,2000}?"private_key":\s*"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----"',
                "description": "Google Service Account Private Key",
                "severity": Severity.CRITICAL,
                "provider": "GCP"
            },
            {
                "name": "AZURE_STORAGE_KEY",
                "pattern": r"(?i)DefaultEndpointsProtocol.+AccountKey[=:\s]+([A-Za-z0-9+/=]{88,})",
                "description": "Azure Storage Account Key",
                "severity": Severity.HIGH,
                "provider": "Azure"
            },
            
            # Authentication & Tokens
            {
                "name": "JWT_TOKEN",
                "pattern": r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*\b",
                "description": "JSON Web Token",
                "severity": Severity.MEDIUM,
                "context_required": ["authorization", "token", "jwt"]
            },
            {
                "name": "BEARER_TOKEN",
                "pattern": r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)",
                "description": "Bearer Authentication Token",
                "severity": Severity.MEDIUM
            },
            {
                "name": "OAUTH_TOKEN",
                "pattern": r"(?i)oauth[^a-z0-9]*?(?:token|secret)[^a-z0-9]*?['\"]?[=:\s]*['\"]?([A-Za-z0-9\-_=]{20,})['\"]?",
                "description": "OAuth Token/Secret",
                "severity": Severity.HIGH
            },
            {
                "name": "SESSION_TOKEN",
                "pattern": r"(?i)(?:session|auth)[^a-z0-9]*?(?:token|cookie)[^a-z0-9]*?['\"]?[=:\s]*['\"]?([A-Za-z0-9%=]{20,})['\"]?",
                "description": "Session/Authorization Token",
                "severity": Severity.MEDIUM
            },
            
            # Database & Services
            {
                "name": "DATABASE_URL",
                "pattern": r"(?i)(?:mysql|postgres|mongodb|redis|memcached)://[^'\"]+",
                "description": "Database Connection String",
                "severity": Severity.HIGH
            },
            {
                "name": "MONGODB_URI",
                "pattern": r"mongodb(?:\+srv)?://[^'\"]+",
                "description": "MongoDB Connection URI",
                "severity": Severity.HIGH
            },
            {
                "name": "REDIS_URL",
                "pattern": r"redis://[^'\"]+",
                "description": "Redis Connection URL",
                "severity": Severity.MEDIUM
            },
            
            # Payment Processors
            {
                "name": "STRIPE_SECRET_KEY",
                "pattern": r"(?i)(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}",
                "description": "Stripe Secret Key",
                "severity": Severity.CRITICAL,
                "provider": "Stripe"
            },
            {
                "name": "STRIPE_PUBLISHABLE_KEY",
                "pattern": r"(?i)pk_(live|test)_[0-9a-zA-Z]{24,}",
                "description": "Stripe Publishable Key",
                "severity": Severity.LOW,
                "provider": "Stripe"
            },
            {
                "name": "PAYPAL_TOKEN",
                "pattern": r"access_token\\$\\(production|sandbox)\\[0-9a-z]{16}\\$[0-9a-f]{32}",
                "description": "PayPal Access Token",
                "severity": Severity.HIGH,
                "provider": "PayPal"
            },
            
            # Communication Services
            {
                "name": "SLACK_TOKEN",
                "pattern": r"(xox[abpors]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
                "description": "Slack API Token",
                "severity": Severity.HIGH,
                "provider": "Slack"
            },
            {
                "name": "SLACK_WEBHOOK",
                "pattern": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
                "description": "Slack Incoming Webhook",
                "severity": Severity.MEDIUM,
                "provider": "Slack"
            },
            {
                "name": "DISCORD_TOKEN",
                "pattern": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
                "description": "Discord Bot Token",
                "severity": Severity.HIGH,
                "provider": "Discord"
            },
            {
                "name": "DISCORD_WEBHOOK",
                "pattern": r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
                "description": "Discord Webhook URL",
                "severity": Severity.MEDIUM,
                "provider": "Discord"
            },
            {
                "name": "TELEGRAM_BOT_TOKEN",
                "pattern": r"\d{8,10}:[A-Za-z0-9_-]{35}",
                "description": "Telegram Bot Token",
                "severity": Severity.HIGH,
                "provider": "Telegram"
            },
            
            # CI/CD & Version Control
            {
                "name": "GITHUB_TOKEN",
                "pattern": r"(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})",
                "description": "GitHub Personal Access Token",
                "severity": Severity.CRITICAL,
                "provider": "GitHub"
            },
            {
                "name": "GITLAB_TOKEN",
                "pattern": r"glpat-[A-Za-z0-9_-]{20}",
                "description": "GitLab Personal Access Token",
                "severity": Severity.CRITICAL,
                "provider": "GitLab"
            },
            {
                "name": "JENKINS_TOKEN",
                "pattern": r"[A-Za-z0-9]{32}",
                "description": "Jenkins API Token",
                "severity": Severity.HIGH,
                "context_required": ["jenkins"],
                "provider": "Jenkins"
            },
            
            # Social Media & APIs
            {
                "name": "FACEBOOK_TOKEN",
                "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
                "description": "Facebook Access Token",
                "severity": Severity.HIGH,
                "provider": "Facebook"
            },
            {
                "name": "TWITTER_TOKEN",
                "pattern": r"[tT][wW][iI][tT][tT][eE][rR][^a-z0-9]*?['\"]?[=:\s]*['\"]?([A-Za-z0-9]{25,})['\"]?",
                "description": "Twitter API Token",
                "severity": Severity.HIGH,
                "provider": "Twitter"
            },
            
            # Generic Patterns
            {
                "name": "PRIVATE_KEY",
                "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
                "description": "Private Key File",
                "severity": Severity.CRITICAL
            },
            {
                "name": "SSH_PRIVATE_KEY",
                "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
                "description": "SSH Private Key",
                "severity": Severity.CRITICAL
            },
            {
                "name": "API_KEY",
                "pattern": r"(?i)(?:api[^a-z0-9]*?(?:key|token)|apikey)[^a-z0-9]*?['\"]?[=:\s]*['\"]?([A-Za-z0-9\-_=]{20,})['\"]?",
                "description": "Generic API Key",
                "severity": Severity.MEDIUM
            },
            {
                "name": "PASSWORD",
                "pattern": r"(?i)(?:password|passwd|pwd)[^a-z0-9]*?['\"]?[=:\s]*['\"]?([^'\"\s]{6,})['\"]?",
                "description": "Password in Plaintext",
                "severity": Severity.HIGH,
                "validation": self._validate_password
            }
        ]
    
    def _validate_aws_key(self, match: str) -> bool:
        """Validate AWS Key format"""
        if not match.startswith('AKIA'):
            return False
        # Add more validation if needed
        return True
    
    def _validate_password(self, match: str) -> bool:
        """Validate if match looks like a real password"""
        # Exclude common false positives
        false_positives = {'password', 'passwd', 'pwd', 'null', 'undefined', 'true', 'false'}
        if match.lower() in false_positives:
            return False
        return len(match) >= 8

# =======================
# Advanced JS Analysis
# =======================

class JSAnalyzer:
    """Advanced JavaScript analysis engine"""
    
    def __init__(self):
        self.endpoint_patterns = [
            (r"(?i)(?:fetch|axios|ajax|request|http\.(?:get|post|put|delete))\(['\"]([^'\"]+)['\"]", "HTTP Request"),
            (r"(?i)\.(?:get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]", "HTTP Method"),
            (r"url\s*[:=]\s*['\"]([^'\"]+)['\"]", "URL Assignment"),
            (r"href\s*=\s*['\"]([^'\"]+)['\"]", "Hyperlink"),
            (r"src\s*=\s*['\"]([^'\"]+)['\"]", "Source URL"),
            (r"window\.location\s*[.=]\s*['\"]([^'\"]+)['\"]", "Window Location")
        ]
        
        self.api_patterns = [
            (r"/api/v[0-9]+/[^'\"]+", "API Endpoint"),
            (r"(?i)graphql", "GraphQL Endpoint"),
            (r"(?i)rest", "REST API"),
            (r"(?i)websocket", "WebSocket Endpoint"),
            (r"wss?://[^'\"]+", "WebSocket URL")
        ]
        
        self.auth_patterns = [
            (r"(?i)admin|administrator", "Admin Reference"),
            (r"(?i)role\s*[=:]\s*['\"]?(admin|superadmin|root)['\"]?", "Admin Role"),
            (r"(?i)permission\s*[=:]\s*['\"]?([^'\"]+)['\"]?", "Permission Level"),
            (r"(?i)isAdmin|isAuthenticated", "Auth Check"),
            (r"(?i)token|session|cookie", "Auth Mechanism")
        ]
        
        self.idor_patterns = [
            (r"(?i)user[_-]?id\s*[=:]\s*['\"]?([0-9]+)['\"]?", "User ID"),
            (r"(?i)id\s*[=:]\s*['\"]?([0-9]+)['\"]?", "Numeric ID"),
            (r"(?i)uuid\s*[=:]\s*['\"]?([a-f0-9-]+)['\"]?", "UUID"),
            (r"\/[0-9]+\/", "ID in URL Pattern")
        ]
        
        self.config_patterns = [
            (r"(?i)debug\s*[=:]\s*(true|false)", "Debug Mode"),
            (r"(?i)environment\s*[=:]\s*['\"]?(development|staging|production)['\"]?", "Environment"),
            (r"(?i)feature[_-]?flag", "Feature Flag"),
            (r"(?i)config|configuration", "Configuration Object")
        ]
    
    def analyze(self, content: str, file_url: str) -> List[JSFeature]:
        """Analyze JavaScript content for interesting features"""
        features = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Extract endpoints
            for pattern, feature_type in self.endpoint_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    if match.groups():
                        features.append(JSFeature(
                            file_url=file_url,
                            feature_type=f"Endpoint/{feature_type}",
                            value=match.group(1),
                            context=line.strip(),
                            line_number=line_num,
                            severity=Severity.INFORMATIONAL
                        ))
            
            # Extract API patterns
            for pattern, feature_type in self.api_patterns:
                if re.search(pattern, line):
                    features.append(JSFeature(
                        file_url=file_url,
                        feature_type=f"API/{feature_type}",
                        value=re.search(pattern, line).group(),
                        context=line.strip(),
                        line_number=line_num,
                        severity=Severity.LOW
                    ))
            
            # Extract authentication patterns
            for pattern, feature_type in self.auth_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    if match.groups():
                        features.append(JSFeature(
                            file_url=file_url,
                            feature_type=f"Auth/{feature_type}",
                            value=match.group(1) if match.groups() else match.group(),
                            context=line.strip(),
                            line_number=line_num,
                            severity=Severity.MEDIUM
                        ))
            
            # Extract IDOR candidates
            for pattern, feature_type in self.idor_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    if match.groups():
                        features.append(JSFeature(
                            file_url=file_url,
                            feature_type=f"IDOR/{feature_type}",
                            value=match.group(1),
                            context=line.strip(),
                            line_number=line_num,
                            severity=Severity.MEDIUM
                        ))
            
            # Extract configuration
            for pattern, feature_type in self.config_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    if match.groups():
                        features.append(JSFeature(
                            file_url=file_url,
                            feature_type=f"Config/{feature_type}",
                            value=match.group(1),
                            context=line.strip(),
                            line_number=line_num,
                            severity=Severity.LOW
                        ))
        
        return features

# =======================
# File Discovery Engine
# =======================

class DiscoveryEngine:
    """Advanced file discovery engine with recursion"""
    
    def __init__(self, base_url: str, ignore_extensions: Set[str] = None):
        self.base_url = base_url.rstrip('/') + '/'
        self.ignore_extensions = ignore_extensions or set()
        self.discovered_files = set()
        self.session = None
    
    async def discover(self, session) -> List[str]:
        """Discover all files recursively"""
        self.session = session
        await self._discover_directory(self.base_url)
        return list(self.discovered_files)
    
    async def _discover_directory(self, url: str, depth: int = 0, max_depth: int = 10):
        """Recursively discover files in directory"""
        if depth > max_depth:
            return
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)) as response:
                if response.status != 200:
                    return
                
                html = await response.text()
                
                # Extract files and directories
                files, directories = self._parse_directory_listing(html, url)
                
                # Process files
                for file in files:
                    file_url = urljoin(url, file)
                    if self._should_process_file(file_url):
                        self.discovered_files.add(file_url)
                
                # Recursively process directories
                for directory in directories:
                    dir_url = urljoin(url, directory) + '/'
                    await self._discover_directory(dir_url, depth + 1, max_depth)
        
        except Exception as e:
            logging.debug(f"Error discovering directory {url}: {e}")
    
    def _parse_directory_listing(self, html: str, base_url: str) -> Tuple[List[str], List[str]]:
        """Parse Apache/Nginx directory listing"""
        files = []
        directories = []
        
        # Common directory listing patterns
        patterns = [
            r'<a href="([^?"][^"]*)">[^<]*</a>',
            r'href=["\']([^"\']*?)["\']',
            r'<td><a href="([^"]+)">'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                # Skip parent directory links and empty links
                if match in ['../', './', '', '#']:
                    continue
                
                # Remove query parameters and fragments
                clean_match = match.split('?')[0].split('#')[0]
                
                # Skip ignored paths
                if any(ignored in clean_match for ignored in Config.IGNORE_PATHS):
                    continue
                
                # Determine if it's a directory or file
                if clean_match.endswith('/'):
                    directories.append(clean_match)
                else:
                    files.append(clean_match)
        
        return files, directories
    
    def _should_process_file(self, file_url: str) -> bool:
        """Check if file should be processed based on extension and size"""
        # Check extension
        path = urlparse(file_url).path.lower()
        ext = Path(path).suffix
        
        if ext in self.ignore_extensions:
            return False
        
        # Check against default ignore extensions
        if ext in Config.IGNORE_EXTENSIONS:
            return False
        
        return True

# =======================
# Secret Detection Engine
# =======================

class SecretDetector:
    """Advanced secret detection with entropy and context awareness"""
    
    def __init__(self):
        self.patterns = SecretPatterns()
        self.js_analyzer = JSAnalyzer()
    
    async def analyze_file(self, content: str, file_url: str, file_type: FileType) -> Tuple[List[Finding], List[JSFeature]]:
        """Analyze file content for secrets and interesting features"""
        findings = []
        js_features = []
        
        # Analyze for secrets
        findings.extend(self._analyze_secrets(content, file_url, file_type))
        
        # Analyze JavaScript files specifically
        if file_type == FileType.JAVASCRIPT:
            js_features.extend(self.js_analyzer.analyze(content, file_url))
            
            # Additional JS-specific secret patterns
            findings.extend(self._analyze_js_specific(content, file_url))
        
        # Analyze config files
        elif file_type in [FileType.CONFIG, FileType.ENVIRONMENT, FileType.JSON]:
            findings.extend(self._analyze_config_files(content, file_url))
        
        return findings, js_features
    
    def _analyze_secrets(self, content: str, file_url: str, file_type: FileType) -> List[Finding]:
        """Analyze content for secrets using patterns and entropy"""
        findings = []
        
        for rule in self.patterns.patterns:
            matches = re.finditer(rule["pattern"], content, re.IGNORECASE)
            
            for match in matches:
                matched_text = match.group(1) if match.groups() else match.group()
                
                # Skip empty matches
                if not matched_text or len(matched_text.strip()) < 8:
                    continue
                
                # Apply validation if available
                if "validation" in rule and callable(rule["validation"]):
                    if not rule["validation"](matched_text):
                        continue
                
                # Check context requirements
                if rule.get("context_required"):
                    if not self._check_context(content, match.start(), match.end(), rule["context_required"]):
                        continue
                
                # Calculate entropy for high-entropy strings
                if self._calculate_entropy(matched_text) > Config.MIN_ENTROPY_THRESHOLD:
                    # Adjust severity based on entropy
                    severity = rule["severity"]
                    if self._calculate_entropy(matched_text) > 5.0:
                        if severity == Severity.MEDIUM:
                            severity = Severity.HIGH
                        elif severity == Severity.HIGH:
                            severity = Severity.CRITICAL
                
                # Get context lines
                context = self._get_context_lines(content, match.start(), match.end())
                
                # Create finding
                finding = Finding(
                    file_url=file_url,
                    file_name=Path(urlparse(file_url).path).name,
                    file_type=file_type,
                    rule_name=rule["name"],
                    description=rule["description"],
                    severity=rule["severity"],
                    match=matched_text[:100] + "..." if len(matched_text) > 100 else matched_text,
                    context=context,
                    line_number=self._get_line_number(content, match.start()),
                    exploitability=self._get_exploitability(rule["severity"]),
                    recommendation=self._get_recommendation(rule["name"]),
                    confidence=self._calculate_confidence(matched_text, rule)
                )
                
                findings.append(finding)
        
        return findings
    
    def _analyze_js_specific(self, content: str, file_url: str) -> List[Finding]:
        """JavaScript-specific analysis"""
        findings = []
        
        # Find hardcoded credentials in JS
        js_patterns = [
            (r"const\s+(\w+)\s*=\s*['\"]([A-Za-z0-9+/=]{20,})['\"]", "Hardcoded Secret"),
            (r"let\s+(\w+)\s*=\s*['\"]([A-Za-z0-9+/=]{20,})['\"]", "Hardcoded Secret"),
            (r"var\s+(\w+)\s*=\s*['\"]([A-Za-z0-9+/=]{20,})['\"]", "Hardcoded Secret"),
            (r"process\.env\.([A-Z_]+)", "Environment Variable Reference")
        ]
        
        for pattern, description in js_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                if match.groups():
                    findings.append(Finding(
                        file_url=file_url,
                        file_name=Path(urlparse(file_url).path).name,
                        file_type=FileType.JAVASCRIPT,
                        rule_name="JS_HARDCODED_SECRET",
                        description=description,
                        severity=Severity.MEDIUM,
                        match=match.group(2) if len(match.groups()) > 1 else match.group(1),
                        context=match.group(),
                        exploitability="Medium",
                        recommendation="Move secrets to environment variables or secure storage"
                    ))
        
        return findings
    
    def _analyze_config_files(self, content: str, file_url: str) -> List[Finding]:
        """Analyze configuration files"""
        findings = []
        
        try:
            if file_url.endswith('.json'):
                config = json.loads(content)
                findings.extend(self._analyze_json_config(config, file_url))
            elif file_url.endswith('.env') or '.env.' in file_url:
                findings.extend(self._analyze_env_file(content, file_url))
        except:
            pass
        
        return findings
    
    def _analyze_json_config(self, config: dict, file_url: str) -> List[Finding]:
        """Recursively analyze JSON configuration"""
        findings = []
        
        def traverse(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    traverse(value, new_path)
            elif isinstance(obj, (list, tuple)):
                for i, item in enumerate(obj):
                    traverse(item, f"{path}[{i}]")
            elif isinstance(obj, str):
                # Check if string looks like a secret
                if self._calculate_entropy(obj) > Config.MIN_ENTROPY_THRESHOLD and len(obj) > 12:
                    # Check common secret field names
                    secret_fields = ['key', 'token', 'secret', 'password', 'passwd', 'pwd']
                    if any(secret in path.lower() for secret in secret_fields):
                        findings.append(Finding(
                            file_url=file_url,
                            file_name=Path(urlparse(file_url).path).name,
                            file_type=FileType.JSON,
                            rule_name="CONFIG_SECRET",
                            description="Potential secret in configuration",
                            severity=Severity.MEDIUM,
                            match=obj[:50] + "..." if len(obj) > 50 else obj,
                            context=f"{path}: {obj[:100]}",
                            exploitability="Medium",
                            recommendation="Use secure configuration management"
                        ))
        
        traverse(config)
        return findings
    
    def _analyze_env_file(self, content: str, file_url: str) -> List[Finding]:
        """Analyze .env files"""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Check if it's a potential secret
                if self._calculate_entropy(value) > Config.MIN_ENTROPY_THRESHOLD and len(value) > 8:
                    secret_keys = ['KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'PWD', 'PASS']
                    if any(secret in key.upper() for secret in secret_keys):
                        findings.append(Finding(
                            file_url=file_url,
                            file_name=Path(urlparse(file_url).path).name,
                            file_type=FileType.ENVIRONMENT,
                            rule_name="ENV_SECRET",
                            description="Potential secret in environment file",
                            severity=Severity.HIGH,
                            match=f"{key}={value[:50]}..." if len(value) > 50 else f"{key}={value}",
                            context=line,
                            line_number=line_num,
                            exploitability="High",
                            recommendation="Use environment variables securely and avoid committing .env files"
                        ))
        
        return findings
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not ENTROPY_AVAILABLE:
            # Simple entropy calculation
            if not string:
                return 0.0
            entropy = 0.0
            for char in set(string):
                p = string.count(char) / len(string)
                entropy -= p * math.log2(p)
            return entropy
        
        return entropy.shannon_entropy(string)
    
    def _check_context(self, content: str, start: int, end: int, required_words: List[str]) -> bool:
        """Check if required context words are near the match"""
        context_start = max(0, start - 100)
        context_end = min(len(content), end + 100)
        context = content[context_start:context_end].lower()
        
        return any(word.lower() in context for word in required_words)
    
    def _get_context_lines(self, content: str, start: int, end: int) -> str:
        """Get context lines around the match"""
        lines = content.split('\n')
        current_pos = 0
        
        for line_num, line in enumerate(lines):
            line_end = current_pos + len(line) + 1
            if start >= current_pos and start < line_end:
                context_start = max(0, line_num - Config.MAX_CONTEXT_LINES)
                context_end = min(len(lines), line_num + Config.MAX_CONTEXT_LINES + 1)
                context_lines = lines[context_start:context_end]
                return '\n'.join(context_lines)
            current_pos = line_end
        
        return ""
    
    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number from position"""
        return content[:position].count('\n') + 1
    
    def _get_exploitability(self, severity: Severity) -> str:
        """Determine exploitability based on severity"""
        if severity == Severity.CRITICAL:
            return "High - Immediate exploitation possible"
        elif severity == Severity.HIGH:
            return "High - Direct impact if exploited"
        elif severity == Severity.MEDIUM:
            return "Medium - Requires additional steps"
        elif severity == Severity.LOW:
            return "Low - Limited impact"
        else:
            return "Information only"
    
    def _get_recommendation(self, rule_name: str) -> str:
        """Get recommendation based on rule"""
        recommendations = {
            "AWS_ACCESS_KEY": "Immediately rotate AWS keys and audit usage",
            "AWS_SECRET_KEY": "Immediately rotate AWS keys and audit usage",
            "GCP_API_KEY": "Restrict API key usage and rotate if exposed",
            "PRIVATE_KEY": "Immediately revoke and regenerate private key",
            "PASSWORD": "Change password immediately and enable 2FA",
            "DATABASE_URL": "Rotate database credentials and restrict access",
            "JWT_TOKEN": "Token should be invalidated and regenerated",
            "API_KEY": "Revoke and regenerate API key with minimal permissions"
        }
        
        return recommendations.get(rule_name, "Review and secure the exposed credential")
    
    def _calculate_confidence(self, match: str, rule: dict) -> float:
        """Calculate confidence score for a finding"""
        confidence = 0.5  # Base confidence
        
        # Length-based confidence
        if len(match) > 20:
            confidence += 0.2
        
        # Entropy-based confidence
        entropy = self._calculate_entropy(match)
        if entropy > 4.5:
            confidence += 0.2
        
        # Provider-specific patterns increase confidence
        if "provider" in rule:
            confidence += 0.1
        
        return min(confidence, 1.0)

# =======================
# File Type Classifier
# =======================

class FileClassifier:
    """Classify files by type and determine if they should be analyzed"""
    
    @staticmethod
    def classify(file_url: str) -> FileType:
        """Classify file by URL/extension"""
        path = urlparse(file_url).path.lower()
        
        if path.endswith('.js'):
            return FileType.JAVASCRIPT
        elif path.endswith('.json'):
            return FileType.JSON
        elif any(path.endswith(ext) for ext in ['.yml', '.yaml', '.xml', '.ini', '.conf', '.cfg', '.config']):
            return FileType.CONFIG
        elif any(path.endswith(ext) for ext in ['.env', '.properties']):
            return FileType.ENVIRONMENT
        elif any(path.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3', '.avi']):
            return FileType.MEDIA
        elif any(path.endswith(ext) for ext in ['.exe', '.dll', '.so', '.dylib']):
            return FileType.BINARY
        elif any(path.endswith(ext) for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx']):
            return FileType.DOCUMENT
        elif any(path.endswith(ext) for ext in ['.zip', '.tar', '.gz', '.rar']):
            return FileType.ARCHIVE
        else:
            return FileType.OTHER
    
    @staticmethod
    def should_analyze(file_type: FileType) -> bool:
        """Determine if file type should be analyzed"""
        analyzable_types = [
            FileType.JAVASCRIPT,
            FileType.JSON,
            FileType.CONFIG,
            FileType.ENVIRONMENT,
            FileType.OTHER  # We'll analyze other text files
        ]
        return file_type in analyzable_types

# =======================
# Impact Assessment Engine
# =======================

class ImpactEngine:
    """Assess impact and severity of findings"""
    
    @staticmethod
    def assess_finding(finding: Finding) -> Finding:
        """Assess and possibly adjust finding severity based on context"""
        
        # Adjust severity based on file type and location
        if finding.file_type == FileType.JAVASCRIPT:
            # Secrets in JS are more severe
            if finding.severity == Severity.MEDIUM:
                finding.severity = Severity.HIGH
            elif finding.severity == Severity.LOW:
                finding.severity = Severity.MEDIUM
        
        # Adjust based on file name
        sensitive_files = ['config', 'secret', 'password', 'key', 'token', 'env']
        if any(sensitive in finding.file_name.lower() for sensitive in sensitive_files):
            if finding.severity.value in ['Low', 'Informational']:
                finding.severity = Severity.MEDIUM
        
        # Update exploitability based on adjusted severity
        finding.exploitability = ImpactEngine._get_exploitability(finding.severity)
        
        return finding
    
    @staticmethod
    def _get_exploitability(severity: Severity) -> str:
        """Get detailed exploitability description"""
        descriptions = {
            Severity.CRITICAL: "High - Direct impact, immediate action required",
            Severity.HIGH: "High - Significant business impact if exploited",
            Severity.MEDIUM: "Medium - Requires specific conditions or additional access",
            Severity.LOW: "Low - Limited scope or requires privileged access",
            Severity.INFORMATIONAL: "Information only - No direct exploitation path"
        }
        return descriptions.get(severity, "Unknown")
    
    @staticmethod
    def generate_attack_scenarios(findings: List[Finding], js_features: List[JSFeature]) -> List[Dict]:
        """Generate potential attack scenarios from findings"""
        scenarios = []
        
        # Group by file and type
        file_findings = {}
        for finding in findings:
            if finding.file_url not in file_findings:
                file_findings[finding.file_url] = []
            file_findings[finding.file_url].append(finding)
        
        # Look for credential reuse scenarios
        aws_keys = [f for f in findings if "AWS" in f.rule_name]
        if len(aws_keys) >= 2:
            scenarios.append({
                "title": "AWS Credential Chain Compromise",
                "description": "Multiple AWS credentials found, potentially allowing full account takeover",
                "severity": Severity.CRITICAL,
                "steps": [
                    "1. Use access key for initial access",
                    "2. Use secret key for full AWS API access",
                    "3. Escalate privileges using discovered keys",
                    "4. Access sensitive data and resources"
                ],
                "findings": [f.file_name for f in aws_keys]
            })
        
        # Database credential scenarios
        db_creds = [f for f in findings if "DATABASE" in f.rule_name]
        if db_creds:
            scenarios.append({
                "title": "Database Credential Exposure",
                "description": "Direct database access credentials discovered",
                "severity": Severity.HIGH,
                "steps": [
                    "1. Connect to database using exposed credentials",
                    "2. Extract sensitive data",
                    "3. Perform database manipulation",
                    "4. Potentially escalate to server access"
                ],
                "findings": [f.file_name for f in db_creds]
            })
        
        # API endpoint + credential scenarios
        api_endpoints = [f for f in js_features if "API" in f.feature_type]
        api_keys = [f for f in findings if "API_KEY" in f.rule_name]
        
        if api_endpoints and api_keys:
            scenarios.append({
                "title": "API Credential Compromise",
                "description": "API endpoints discovered with corresponding API keys",
                "severity": Severity.HIGH,
                "steps": [
                    "1. Identify API endpoint structure",
                    "2. Use discovered API keys for authentication",
                    "3. Access restricted API endpoints",
                    "4. Perform unauthorized operations"
                ],
                "findings": [f.file_name for f in api_keys]
            })
        
        return scenarios

# =======================
# Enhanced CLI Interface
# =======================

class CLIInterface:
    """Enhanced CLI interface with professional colors"""
    
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.console_width = 80
        self.scan_start_time = None
        
    def print_banner(self):
        """Print application banner"""
        if self.quiet:
            return
        
        Branding.print_banner()
        Branding.print_developer_info()
        Branding.print_disclaimer()
    
    def print_status(self, current_file: str, scanned: int, total: int, findings_count: int):
        """Print current scan status with colored progress bar"""
        if self.quiet:
            return
        
        elapsed = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        # Clear line
        print(f"\r{' ' * self.console_width}", end='\r')
        
        # File info
        file_display = current_file[:40] + "..." if len(current_file) > 40 else current_file
        print(f"{Colors.INFO}Current:{Colors.RESET} {Colors.TEXT}{file_display}{Colors.RESET} ", end='')
        
        # Progress bar
        progress_width = 30
        percent = scanned / total if total > 0 else 0
        filled = int(progress_width * percent)
        
        # Color progress bar based on completion
        if percent < 0.3:
            bar_color = Colors.WARNING
        elif percent < 0.7:
            bar_color = Colors.ACCENT
        else:
            bar_color = Colors.SUCCESS
        
        bar = bar_color + "[" + "=" * filled + " " * (progress_width - filled) + "]" + Colors.RESET
        
        print(f"{Colors.INFO}Progress:{Colors.RESET} {bar} {Colors.TEXT}{scanned}/{total}{Colors.RESET} ", end='')
        
        # Stats
        findings_color = Colors.HIGH if findings_count > 0 else Colors.TEXT
        print(f"{Colors.INFO}Findings:{Colors.RESET} {findings_color}{findings_count}{Colors.RESET} ", end='')
        
        # Time
        time_color = Colors.WARNING if elapsed > 30 else Colors.TEXT
        print(f"{Colors.INFO}Time:{Colors.RESET} {time_color}{elapsed:.1f}s{Colors.RESET}", end='\r')
        
        sys.stdout.flush()
    
    def print_update_notification(self, update_info: Dict):
        """Display update notification"""
        print(f"\n{Colors.ACCENT}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.ACCENT}{Colors.BOLD}║                    UPDATE AVAILABLE                          ║{Colors.RESET}")
        print(f"{Colors.ACCENT}{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        print(f"\n{Colors.HEADER}Current Version:{Colors.RESET} {Colors.TEXT}{update_info['current_version']}{Colors.RESET}")
        print(f"{Colors.HEADER}Latest Version:{Colors.RESET}  {Colors.SUCCESS}{update_info['latest_version']}{Colors.RESET}")
        print(f"{Colors.HEADER}Released:{Colors.RESET}        {Colors.TEXT}{update_info['published_at'][:10]}{Colors.RESET}")
        
        if update_info.get('changelog'):
            print(f"\n{Colors.HEADER}What's New:{Colors.RESET}")
            changelog_lines = update_info['changelog'].split('\n')
            for line in changelog_lines[:10]:  # Show first 10 lines
                if line.strip():
                    print(f"  {Colors.TEXT}• {line.strip()}{Colors.RESET}")
        
        print(f"\n{Colors.HEADER}Release URL:{Colors.RESET} {Colors.TEXT}{update_info['release_url']}{Colors.RESET}")
    
    def print_summary(self, stats: ScanStats, attack_scenarios: List[Dict]):
        """Print scan summary with colored statistics"""
        if self.quiet:
            return
        
        elapsed = time.time() - stats.start_time
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.HEADER}{Colors.BOLD}║                         SCAN SUMMARY                         ║{Colors.RESET}")
        print(f"{Colors.HEADER}{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        print(f"\n{Colors.INFO}Files Discovered:{Colors.RESET} {Colors.TEXT}{stats.total_files}{Colors.RESET}")
        print(f"{Colors.INFO}Files Scanned:{Colors.RESET}    {Colors.TEXT}{stats.scanned_files}{Colors.RESET}")
        print(f"{Colors.INFO}Scan Duration:{Colors.RESET}    {Colors.TEXT}{elapsed:.2f} seconds{Colors.RESET}")
        
        # Findings breakdown
        critical = len([f for f in stats.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in stats.findings if f.severity == Severity.HIGH])
        medium = len([f for f in stats.findings if f.severity == Severity.MEDIUM])
        low = len([f for f in stats.findings if f.severity == Severity.LOW])
        info = len([f for f in stats.findings if f.severity == Severity.INFORMATIONAL])
        
        print(f"\n{Colors.INFO}Findings Breakdown:{Colors.RESET}")
        print(f"  {Colors.severity_color('CRITICAL')}Critical:{Colors.RESET} {Colors.TEXT}{critical}{Colors.RESET}")
        print(f"  {Colors.severity_color('HIGH')}High:{Colors.RESET}       {Colors.TEXT}{high}{Colors.RESET}")
        print(f"  {Colors.severity_color('MEDIUM')}Medium:{Colors.RESET}     {Colors.TEXT}{medium}{Colors.RESET}")
        print(f"  {Colors.severity_color('LOW')}Low:{Colors.RESET}        {Colors.TEXT}{low}{Colors.RESET}")
        print(f"  {Colors.severity_color('INFORMATIONAL')}Informational:{Colors.RESET} {Colors.TEXT}{info}{Colors.RESET}")
        
        if stats.errors:
            print(f"\n{Colors.WARNING}Errors Encountered:{Colors.RESET} {Colors.TEXT}{len(stats.errors)}{Colors.RESET}")
            if self.verbose:
                for error in stats.errors[:3]:
                    print(f"  {Colors.MUTED}• {error}{Colors.RESET}")
        
        if attack_scenarios:
            self._print_attack_scenarios(attack_scenarios)
    
    def _print_attack_scenarios(self, scenarios: List[Dict]):
        """Print attack scenarios"""
        print(f"\n{Colors.ACCENT}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.ACCENT}{Colors.BOLD}║                 ATTACK SCENARIOS                              ║{Colors.RESET}")
        print(f"{Colors.ACCENT}{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        for i, scenario in enumerate(scenarios, 1):
            severity_color = Colors.severity_color(scenario['severity'].value)
            print(f"\n{Colors.HEADER}{i}. {scenario['title']}{Colors.RESET} [{severity_color}{scenario['severity'].value}{Colors.RESET}]")
            print(f"   {Colors.TEXT}{scenario['description']}{Colors.RESET}")
            print(f"   {Colors.INFO}Steps:{Colors.RESET}")
            for step in scenario['steps']:
                print(f"     {Colors.TEXT}{step}{Colors.RESET}")
            print(f"   {Colors.MUTED}Files: {', '.join(scenario['findings'][:3])}{'...' if len(scenario['findings']) > 3 else ''}{Colors.RESET}")
    
    def print_findings_table(self, findings: List[Finding]):
        """Print findings in a formatted, colored table"""
        if self.quiet or not findings:
            return
        
        # Group by severity
        severity_groups = {}
        for finding in findings:
            if finding.severity not in severity_groups:
                severity_groups[finding.severity] = []
            severity_groups[finding.severity].append(finding)
        
        # Print by severity (Critical first)
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]:
            if severity in severity_groups:
                severity_color = Colors.severity_color(severity.value)
                
                print(f"\n{severity_color}{'═' * 60}{Colors.RESET}")
                print(f"{severity_color}{severity.value.upper()} SEVERITY FINDINGS ({len(severity_groups[severity])}){Colors.RESET}")
                print(f"{severity_color}{'═' * 60}{Colors.RESET}")
                
                for finding in severity_groups[severity]:
                    self._print_finding(finding)
    
    def _print_finding(self, finding: Finding):
        """Print individual finding with colored severity"""
        severity_color = Colors.severity_color(finding.severity.value)
        
        print(f"\n{Colors.ACCENT}[+]{Colors.RESET} {Colors.HEADER}File:{Colors.RESET} {Colors.TEXT}{finding.file_name}{Colors.RESET}")
        print(f"    {Colors.INFO}Type:{Colors.RESET} {Colors.TEXT}{finding.rule_name}{Colors.RESET}")
        print(f"    {Colors.INFO}Description:{Colors.RESET} {Colors.TEXT}{finding.description}{Colors.RESET}")
        print(f"    {Colors.INFO}Severity:{Colors.RESET} {severity_color}{finding.severity.value}{Colors.RESET}")
        print(f"    {Colors.INFO}Confidence:{Colors.RESET} {Colors.TEXT}{finding.confidence:.1%}{Colors.RESET}")
        print(f"    {Colors.INFO}Exploitability:{Colors.RESET} {Colors.TEXT}{finding.exploitability}{Colors.RESET}")
        print(f"    {Colors.INFO}Match:{Colors.RESET} {Colors.TEXT}{finding.match}{Colors.RESET}")
        print(f"    {Colors.INFO}Recommendation:{Colors.RESET} {Colors.TEXT}{finding.recommendation}{Colors.RESET}")
        
        if finding.context and self.verbose:
            print(f"    {Colors.INFO}Context:{Colors.RESET}")
            for line in finding.context.split('\n'):
                print(f"      {Colors.MUTED}{line}{Colors.RESET}")
        
        print(f"    {Colors.MUTED}{'─' * 40}{Colors.RESET}")

# =======================
# Report Generator
# =======================

class ReportGenerator:
    """Generate reports in multiple formats"""
    
    @staticmethod
    def generate_json_report(stats: ScanStats, attack_scenarios: List[Dict]) -> str:
        """Generate JSON report"""
        report = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "tool": "CONTRABUSTER - Advanced Container Intelligence Scanner",
                "version": __version__,
                "developer": __author__,
                "contact": __contact__
            },
            "statistics": {
                "total_files": stats.total_files,
                "scanned_files": stats.scanned_files,
                "findings_count": len(stats.findings),
                "critical_findings": len([f for f in stats.findings if f.severity == Severity.CRITICAL]),
                "high_findings": len([f for f in stats.findings if f.severity == Severity.HIGH]),
                "medium_findings": len([f for f in stats.findings if f.severity == Severity.MEDIUM]),
                "low_findings": len([f for f in stats.findings if f.severity == Severity.LOW]),
                "informational_findings": len([f for f in stats.findings if f.severity == Severity.INFORMATIONAL]),
                "js_features": len(stats.js_features),
                "scan_duration": time.time() - stats.start_time,
                "errors_count": len(stats.errors)
            },
            "findings": [
                {
                    "file_url": f.file_url,
                    "file_name": f.file_name,
                    "file_type": f.file_type.value,
                    "rule_name": f.rule_name,
                    "description": f.description,
                    "severity": f.severity.value,
                    "match": f.match,
                    "context": f.context,
                    "line_number": f.line_number,
                    "exploitability": f.exploitability,
                    "recommendation": f.recommendation,
                    "confidence": f.confidence
                }
                for f in stats.findings
            ],
            "js_features": [
                {
                    "file_url": f.file_url,
                    "feature_type": f.feature_type,
                    "value": f.value,
                    "context": f.context,
                    "line_number": f.line_number,
                    "severity": f.severity.value
                }
                for f in stats.js_features
            ],
            "attack_scenarios": attack_scenarios,
            "errors": stats.errors
        }
        
        return json.dumps(report, indent=2, default=str)
    
    @staticmethod
    def generate_html_report(stats: ScanStats, attack_scenarios: List[Dict]) -> str:
        """Generate HTML report with severity colors"""
        # Generate severity color CSS based on our color system
        severity_colors = {
            "CRITICAL": "#FF0000",  # Red
            "HIGH": "#FF6600",      # Orange
            "MEDIUM": "#FFCC00",    # Yellow
            "LOW": "#00CC00",       # Green
            "INFORMATIONAL": "#0066CC"  # Blue
        }
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CONTRABUSTER Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }}
        .stat-card.critical {{ border-color: {severity_colors["CRITICAL"]}; }}
        .stat-card.high {{ border-color: {severity_colors["HIGH"]}; }}
        .stat-card.medium {{ border-color: {severity_colors["MEDIUM"]}; }}
        .stat-card.low {{ border-color: {severity_colors["LOW"]}; }}
        .finding {{
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            transition: transform 0.2s;
        }}
        .finding:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .finding.critical {{ border-left: 4px solid {severity_colors["CRITICAL"]}; }}
        .finding.high {{ border-left: 4px solid {severity_colors["HIGH"]}; }}
        .finding.medium {{ border-left: 4px solid {severity_colors["MEDIUM"]}; }}
        .finding.low {{ border-left: 4px solid {severity_colors["LOW"]}; }}
        .finding.info {{ border-left: 4px solid {severity_colors["INFORMATIONAL"]}; }}
        .severity {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .severity-critical {{ background: {severity_colors["CRITICAL"]}; color: white; }}
        .severity-high {{ background: {severity_colors["HIGH"]}; color: white; }}
        .severity-medium {{ background: {severity_colors["MEDIUM"]}; color: #333; }}
        .severity-low {{ background: {severity_colors["LOW"]}; color: white; }}
        .severity-info {{ background: {severity_colors["INFORMATIONAL"]}; color: white; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        pre {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
        }}
        .scenario {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #9b59b6;
        }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 20px;
        }}
        .disclaimer {{
            background: #fff3cd;
            border: 1px solid #ffecb5;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>CONTRABUSTER</h1>
            <p>Advanced Container Intelligence Scanner</p>
            <p><small>Version: {__version__} | Developer: {__author__}</small></p>
        </div>
        
        <div class="disclaimer">
            <strong>Security Notice:</strong> This report is for authorized security testing only. 
            Unauthorized use against systems you don't own is illegal.
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary-stats">
            <div class="stat-card">
                <h3>Total Files</h3>
                <p style="font-size: 2em; font-weight: bold;">{stats.total_files}</p>
            </div>
            <div class="stat-card">
                <h3>Files Scanned</h3>
                <p style="font-size: 2em; font-weight: bold;">{stats.scanned_files}</p>
            </div>
            <div class="stat-card critical">
                <h3>Critical Findings</h3>
                <p style="font-size: 2em; font-weight: bold;">{len([f for f in stats.findings if f.severity == Severity.CRITICAL])}</p>
            </div>
            <div class="stat-card high">
                <h3>High Findings</h3>
                <p style="font-size: 2em; font-weight: bold;">{len([f for f in stats.findings if f.severity == Severity.HIGH])}</p>
            </div>
        </div>
        
        <h2>Findings</h2>
        """
        
        # Group findings by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
        
        for severity in severity_order:
            severity_findings = [f for f in stats.findings if f.severity == severity]
            if severity_findings:
                severity_class = severity.value.lower()
                html += f"""
                <h3>{severity.value} Findings ({len(severity_findings)})</h3>
                """
                
                for finding in severity_findings:
                    html += f"""
                    <div class="finding {severity_class}">
                        <h4>{escape(finding.file_name)}</h4>
                        <p><strong>Rule:</strong> {escape(finding.rule_name)}</p>
                        <p><strong>Description:</strong> {escape(finding.description)}</p>
                        <p><strong>Severity:</strong> <span class="severity severity-{severity_class}">{severity.value}</span></p>
                        <p><strong>Confidence:</strong> {finding.confidence:.1%}</p>
                        <p><strong>Exploitability:</strong> {escape(finding.exploitability)}</p>
                        <p><strong>Recommendation:</strong> {escape(finding.recommendation)}</p>
                        <p><strong>Match:</strong> <code>{escape(finding.match)}</code></p>
                        """
                    
                    if finding.context:
                        html += f"""
                        <p><strong>Context:</strong></p>
                        <pre>{escape(finding.context)}</pre>
                        """
                    
                    html += f"""
                        <p><small>File: <a href="{escape(finding.file_url)}" target="_blank">{escape(finding.file_url)}</a></small></p>
                    </div>
                    """
        
        # Attack scenarios
        if attack_scenarios:
            html += """
            <h2>Potential Attack Scenarios</h2>
            """
            
            for scenario in attack_scenarios:
                html += f"""
                <div class="scenario">
                    <h3>{escape(scenario['title'])}</h3>
                    <p><strong>Severity:</strong> <span class="severity severity-{scenario['severity'].value.lower()}">{scenario['severity'].value}</span></p>
                    <p>{escape(scenario['description'])}</p>
                    <h4>Attack Steps:</h4>
                    <ol>
                """
                
                for step in scenario['steps']:
                    html += f"<li>{escape(step)}</li>"
                
                html += """
                    </ol>
                </div>
                """
        
        # JavaScript features
        if stats.js_features:
            html += """
            <h2>JavaScript Features Discovered</h2>
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for feature in stats.js_features:
                html += f"""
                <tr>
                    <td>{escape(Path(urlparse(feature.file_url).path).name)}</td>
                    <td>{escape(feature.feature_type)}</td>
                    <td><code>{escape(feature.value[:50])}{'...' if len(feature.value) > 50 else ''}</code></td>
                    <td><span class="severity severity-{feature.severity.value.lower()}">{feature.severity.value}</span></td>
                </tr>
                """
            
            html += """
                </tbody>
            </table>
            """
        
        html += f"""
        <footer>
            <p>Report generated by CONTRABUSTER v{__version__}</p>
            <p>Developer: {__author__} | Contact: {__contact__}</p>
            <p>For authorized security testing only. Unauthorized use is prohibited.</p>
        </footer>
    </div>
</body>
</html>
        """
        
        return html

# =======================
# Main Scanner Class
# =======================

class AdvancedContainerScanner:
    """Main scanner class orchestrating all components"""
    
    def __init__(self, args):
        self.args = args
        self.cli = CLIInterface(verbose=args.verbose, quiet=args.quiet)
        self.stats = ScanStats()
        self.secret_detector = SecretDetector()
        self.file_classifier = FileClassifier()
        self.impact_engine = ImpactEngine()
        
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG if args.debug else logging.ERROR,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    async def scan(self):
        """Main scan method"""
        try:
            # Print banner
            self.cli.print_banner()
            
            # Create HTTP session with limits
            connector = aiohttp.TCPConnector(limit=Config.MAX_CONCURRENT_REQUESTS)
            timeout = aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Step 1: Discover files
                self.cli.scan_start_time = time.time()
                print(f"{Colors.INFO}[*]{Colors.RESET} Discovering files...")
                
                ignore_extensions = set(self.args.ignore_extensions.split(',')) if self.args.ignore_extensions else set()
                discovery = DiscoveryEngine(self.args.url, ignore_extensions)
                files = await discovery.discover(session)
                
                self.stats.total_files = len(files)
                print(f"{Colors.SUCCESS}[+]{Colors.RESET} Discovered {len(files)} files")
                
                # Step 2: Process files
                print(f"{Colors.INFO}[*]{Colors.RESET} Analyzing files...")
                
                semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_REQUESTS)
                
                tasks = []
                for file_url in files:
                    task = asyncio.create_task(self._process_file(session, semaphore, file_url))
                    tasks.append(task)
                
                # Process results as they complete
                for task in asyncio.as_completed(tasks):
                    await task
                
                # Step 3: Post-process findings
                print(f"{Colors.INFO}[*]{Colors.RESET} Assessing findings...")
                self._post_process_findings()
                
                # Step 4: Generate attack scenarios
                attack_scenarios = self.impact_engine.generate_attack_scenarios(
                    self.stats.findings, self.stats.js_features
                )
                
                # Step 5: Print results
                self.cli.print_summary(self.stats, attack_scenarios)
                self.cli.print_findings_table(self.stats.findings)
                
                # Step 6: Generate reports
                if self.args.output:
                    self._generate_reports(attack_scenarios)
                
                return self.stats
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!]{Colors.RESET} Scan interrupted by user")
            return self.stats
        except Exception as e:
            print(f"\n{Colors.ERROR}[!]{Colors.RESET} Critical error: {e}")
            if self.args.debug:
                import traceback
                traceback.print_exc()
            return self.stats
    
    async def _process_file(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, file_url: str):
        """Process individual file"""
        async with semaphore:
            try:
                # Get file content
                async with session.get(file_url, timeout=aiohttp.ClientTimeout(total=Config.REQUEST_TIMEOUT)) as response:
                    if response.status != 200:
                        return
                    
                    # Check content type
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Skip binary files unless forced
                    if 'text' not in content_type and 'json' not in content_type and 'javascript' not in content_type:
                        if not self.args.force:
                            return
                    
                    # Check file size
                    content_length = response.headers.get('content-length')
                    if content_length and int(content_length) > Config.MAX_FILE_SIZE:
                        return
                    
                    content = await response.text()
                    
                    # Classify file
                    file_type = self.file_classifier.classify(file_url)
                    
                    # Skip if file type shouldn't be analyzed
                    if not self.file_classifier.should_analyze(file_type):
                        return
                    
                    # Analyze file
                    findings, js_features = await self.secret_detector.analyze_file(
                        content, file_url, file_type
                    )
                    
                    # Update stats
                    self.stats.scanned_files += 1
                    self.stats.findings.extend(findings)
                    self.stats.js_features.extend(js_features)
                    
                    # Update UI
                    self.cli.print_status(
                        file_url,
                        self.stats.scanned_files,
                        self.stats.total_files,
                        len(self.stats.findings)
                    )
                    
                    # Rate limiting
                    await asyncio.sleep(Config.RATE_LIMIT_DELAY)
                    
            except asyncio.TimeoutError:
                self.stats.errors.append(f"Timeout processing {file_url}")
            except Exception as e:
                self.stats.errors.append(f"Error processing {file_url}: {str(e)}")
    
    def _post_process_findings(self):
        """Post-process findings with impact assessment"""
        processed_findings = []
        for finding in self.stats.findings:
            # Assess impact
            assessed_finding = self.impact_engine.assess_finding(finding)
            processed_findings.append(assessed_finding)
        
        self.stats.findings = processed_findings
        
        # Sort findings by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, 
                         Severity.LOW: 3, Severity.INFORMATIONAL: 4}
        self.stats.findings.sort(key=lambda x: severity_order[x.severity])
    
    def _generate_reports(self, attack_scenarios: List[Dict]):
        """Generate output reports"""
        try:
            output_path = Path(self.args.output)
            
            # JSON report
            json_report = ReportGenerator.generate_json_report(self.stats, attack_scenarios)
            json_path = output_path.with_suffix('.json')
            json_path.write_text(json_report, encoding='utf-8')
            print(f"{Colors.SUCCESS}[+]{Colors.RESET} JSON report saved to: {json_path}")
            
            # HTML report
            html_report = ReportGenerator.generate_html_report(self.stats, attack_scenarios)
            html_path = output_path.with_suffix('.html')
            html_path.write_text(html_report, encoding='utf-8')
            print(f"{Colors.SUCCESS}[+]{Colors.RESET} HTML report saved to: {html_path}")
            
            # CLI report
            if not self.args.quiet:
                cli_path = output_path.with_suffix('.txt')
                with open(cli_path, 'w', encoding='utf-8') as f:
                    f.write("CONTRABUSTER - Advanced Container Intelligence Scanner\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                    f.write(f"Version: {__version__}\n")
                    f.write(f"Developer: {__author__}\n\n")
                    
                    for finding in self.stats.findings:
                        f.write(f"[{finding.severity.value}] {finding.file_name}\n")
                        f.write(f"  Rule: {finding.rule_name}\n")
                        f.write(f"  Description: {finding.description}\n")
                        f.write(f"  Match: {finding.match}\n")
                        f.write(f"  URL: {finding.file_url}\n")
                        f.write(f"  Recommendation: {finding.recommendation}\n")
                        f.write("-" * 40 + "\n")
                
                print(f"{Colors.SUCCESS}[+]{Colors.RESET} CLI report saved to: {cli_path}")
                
        except Exception as e:
            print(f"{Colors.ERROR}[!]{Colors.RESET} Error generating reports: {e}")

# =======================
# Argument Parser
# =======================

def parse_args():
    """Parse command line arguments with update options"""
    parser = argparse.ArgumentParser(
        description=f"{Colors.BANNER}CONTRABUSTER{Colors.RESET} - Advanced Container Intelligence Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.ACCENT}Examples:{Colors.RESET}
  {Colors.TEXT}%(prog)s -u https://example.com/assets/{Colors.RESET}
  {Colors.TEXT}%(prog)s -u https://s3.amazonaws.com/bucket/ -t 20 -o results{Colors.RESET}
  {Colors.TEXT}%(prog)s -u https://cdn.example.com/ --extensions js,json,env --verbose{Colors.RESET}
  {Colors.TEXT}%(prog)s --no-update -u https://example.com/files/ --quiet{Colors.RESET}
        """
    )
    
    # Required arguments
    parser.add_argument("-u", "--url", required=True,
                       help="URL of public container or directory listing")
    
    # Update options
    parser.add_argument("--no-update", action="store_true",
                       help="Disable automatic update check")
    parser.add_argument("--check-update", action="store_true",
                       help="Check for updates without scanning")
    parser.add_argument("--force-update", action="store_true",
                       help="Force update to latest version")
    
    # Scan configuration
    parser.add_argument("-e", "--extensions",
                       default="js,json,txt,env,config,yml,yaml,xml,ini,conf",
                       help="Comma-separated list of file extensions to scan")
    parser.add_argument("--ignore-extensions",
                       help="Comma-separated list of extensions to ignore")
    parser.add_argument("--ignore-paths",
                       help="Comma-separated list of paths to ignore")
    parser.add_argument("-t", "--threads", type=int, default=Config.MAX_CONCURRENT_REQUESTS,
                       help=f"Number of concurrent threads (default: {Config.MAX_CONCURRENT_REQUESTS})")
    parser.add_argument("--max-depth", type=int, default=10,
                       help="Maximum recursion depth (default: 10)")
    parser.add_argument("--max-size", type=int, default=Config.MAX_FILE_SIZE,
                       help=f"Maximum file size to scan in bytes (default: {Config.MAX_FILE_SIZE})")
    
    # Output options
    parser.add_argument("-o", "--output",
                       help="Output base name for reports (generates JSON, HTML, and TXT)")
    parser.add_argument("--json-only", action="store_true",
                       help="Output only JSON report")
    parser.add_argument("--html-only", action="store_true",
                       help="Output only HTML report")
    
    # Mode selection
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Quiet mode - minimal output")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose mode - show detailed information")
    parser.add_argument("-d", "--debug", action="store_true",
                       help="Debug mode - show debug information")
    parser.add_argument("--force", action="store_true",
                       help="Force scan of non-text files")
    
    # Filtering
    parser.add_argument("--min-severity", default="LOW",
                       choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                       help="Minimum severity to report (default: LOW)")
    parser.add_argument("--filter", action="append",
                       help="Filter findings by keyword (can be used multiple times)")
    
    return parser.parse_args()

def handle_update_flow(args) -> bool:
    """Handle update checking and execution"""
    # Force update mode
    if args.force_update:
        print(f"{Colors.ACCENT}Force update requested...{Colors.RESET}")
        update_info = UpdateManager.check_for_updates(__version__)
        if not update_info:
            print(f"{Colors.INFO}Already running latest version {__version__}{Colors.RESET}")
            return False
        
        if UpdateManager.download_update(update_info):
            print(f"\n{Colors.SUCCESS}Update completed. Please restart CONTRABUSTER.{Colors.RESET}")
            return True
        return False
    
    # Check update only mode
    if args.check_update:
        update_info = UpdateManager.check_for_updates(__version__)
        if update_info:
            cli = CLIInterface()
            cli.print_update_notification(update_info)
            
            choice = input(f"\n{Colors.ACCENT}Update now? (y/N): {Colors.RESET}").strip().lower()
            if choice == 'y':
                if UpdateManager.download_update(update_info):
                    print(f"\n{Colors.SUCCESS}Update completed. Please restart CONTRABUSTER.{Colors.RESET}")
                    return True
        else:
            print(f"{Colors.INFO}No updates available. Current version: {__version__}{Colors.RESET}")
        return False
    
    # Normal scan mode with update check
    if not args.no_update:
        update_info = UpdateManager.check_for_updates(__version__)
        if update_info:
            cli = CLIInterface(verbose=args.verbose, quiet=args.quiet)
            cli.print_update_notification(update_info)
            
            choice = input(f"\n{Colors.ACCENT}Update now? (y/N): {Colors.RESET}").strip().lower()
            if choice == 'y':
                if UpdateManager.download_update(update_info):
                    print(f"\n{Colors.SUCCESS}Update completed. Please restart CONTRABUSTER.{Colors.RESET}")
                    return True
    
    return False

# =======================
# Main Entry Point
# =======================

def main():
    """Main entry point"""
    try:
        # Parse arguments
        args = parse_args()
        
        # Handle updates
        if handle_update_flow(args):
            return
        
        # Update config based on arguments
        if args.threads:
            Config.MAX_CONCURRENT_REQUESTS = args.threads
        if args.max_size:
            Config.MAX_FILE_SIZE = args.max_size
        
        # Create and run scanner
        scanner = AdvancedContainerScanner(args)
        
        # Setup signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print(f"\n{Colors.WARNING}Shutting down gracefully...{Colors.RESET}")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Run scan
        asyncio.run(scanner.scan())
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Scan interrupted{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.ERROR}Fatal error: {e}{Colors.RESET}")
        if args and args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
