#!/usr/bin/env python3
"""
PKiller Universal v4.0 - Complete Auto Protection Remover
Fully automated APK protection remover for Termux
Detects and removes: PairIP, License checks, Signature verification, Root detection, etc.

Usage:
  python3 pkiller_v4.py <input.apk> [-o output.apk]

Features:
- Auto detect ALL protection methods
- Remove PairIP completely
- Remove license checks
- Bypass signature verification
- Remove root/emulator detection
- Auto sign and optimize APK
- Backup system
- Progress tracking

Requirements (Termux):
  pkg install apktool openjdk-17 wget zip
  pip install termcolor rich

Author: PKiller Team
Version: 4.0
"""

import os
import sys
import re
import json
import time
import shutil
import hashlib
import zipfile
import argparse
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from termcolor import colored, cprint

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ==================== CONFIGURATION ====================
VERSION = "4.0"
APP_NAME = "PKiller Universal"

# Tool paths for Termux
TERMUX_PREFIX = "/data/data/com.termux/files/usr"
APKTOOL = shutil.which("apktool") or "apktool"
JAVA = shutil.which("java") or "java"
KEYTOOL = shutil.which("keytool") or "keytool"
ZIPALIGN = shutil.which("zipalign") or f"{TERMUX_PREFIX}/bin/zipalign"
ZIP = shutil.which("zip") or "zip"

# ==================== DETECTION PATTERNS ====================

# Comprehensive protection detection patterns
PROTECTION_PATTERNS = {
    # PairIP specific patterns
    "PAIRIP": [
        r'pairip', r'pair\.ip', r'pair_ip', r'com\.pairip', r'com/pairip',
        r'pairip\.', r'PairIP', r'PAIRIP', r'PairipProtection',
        r'PairIpChecker', r'PairIpValidator', r'PairIpSecurity',
        r'Lcom/pairip', r'pairipclient', r'pairipserver'
    ],
    
    # License verification patterns
    "LICENSE": [
        r'license', r'licence', r'islicensed', r'checklicense', 
        r'verifylicense', r'validatelicense', r'licensecheck',
        r'licensevalidator', r'licenseverifier', r'licensemanager',
        r'LicenseChecker', r'LicenseValidator', r'LVL',
        r'com\.android\.vending\.licensing',
        r'GoogleLicenseVerification', r'PlayStoreLicense'
    ],
    
    # Signature verification patterns
    "SIGNATURE": [
        r'signature', r'getsignature', r'checksignature', r'verifysignature',
        r'getsignatures', r'packageinfo', r'getpackageinfo',
        r'PackageManager', r'pm\.getPackageInfo', r'pm\.getSignatures',
        r'MessageDigest', r'digest', r'md5', r'sha1', r'sha256',
        r'certificate', r'checkValidity', r'X\.509'
    ],
    
    # Root/Emulator detection
    "ROOT_DETECTION": [
        r'root', r'isrooted', r'checkroot', r'roote?ddevice',
        r'su\.', r'Superuser', r'SuperSU', r'Magisk',
        r'/system/bin/su', r'/system/xbin/su', r'/sbin/su',
        r'build\.tags', r'test-keys', r'debuggable',
        r'ro\.debuggable', r'ro\.secure', r'ro\.build\.type',
        r'emulator', r'isemulator', r'bluestacks', r'genymotion',
        r'qemu', r'goldfish'
    ],
    
    # Debug detection
    "DEBUG_DETECTION": [
        r'isdebuggerconnected', r'isdebuggingenabled',
        r'debug', r'checkdebug', r'debuggable',
        r'Build\.DEBUG', r'android:debuggable',
        r'Debug\.isDebuggerConnected'
    ],
    
    # Installer verification
    "INSTALLER_CHECK": [
        r'getinstallerpackagename', r'getinstaller',
        r'installer', r'packagemanager',
        r'com\.android\.vending', r'com\.google\.android\.finsky',
        r'playstore', r'play store', r'google play'
    ],
    
    # Time/Date validation
    "TIME_VALIDATION": [
        r'checkvalidity', r'checkexpiry', r'isexpired',
        r'validuntil', r'validfrom', r'timecheck',
        r'datecheck', r'System\.currentTimeMillis',
        r'Calendar\.getInstance', r'new Date\(\)'
    ],
    
    # Package tampering check
    "TAMPER_CHECK": [
        r'checktamper', r'istampered', r'apktamper',
        r'checksum', r'hash', r'integrity',
        r'verifyapk', r'checkapk', r'validateapk'
    ],
    
    # Emulator/Runtime detection
    "RUNTIME_DETECTION": [
        r'Runtime\.exec', r'Runtime\.getRuntime',
        r'exec\s*\(', r'processbuilder',
        r'which su', r'busybox', r'xposed',
        r'luckypatcher', r'gameguardian'
    ],
    
    # General protection keywords
    "PROTECTION": [
        r'protection', r'security', r'checker', r'validator',
        r'verifier', r'guard', r'shield', r'defender',
        r'antitamper', r'anti\-debug', r'anti\-root',
        r'obfuscation', r'encrypt', r'decrypt',
        r'securestorage', r'keystore', r'keymanager'
    ],
    
    # Network/Server validation
    "SERVER_VALIDATION": [
        r'validatewithserver', r'servercheck',
        r'apivalidation', r'webservice',
        r'httppost', r'httpget', r'okhttp',
        r'retrofit', r'volley', r'socket'
    ],
    
    # Resource/Asset protection
    "RESOURCE_PROTECTION": [
        r'\.dat$', r'\.bin$', r'\.enc$', r'\.crypt$',
        r'assets/.*\.(dat|bin|enc|crypt|key)',
        r'raw/.*\.(dat|bin|enc|crypt|key)',
        r'res/.*\.(dat|bin|enc|crypt|key)'
    ]
}

# Suspicious file extensions to remove
SUSPICIOUS_EXTENSIONS = ['.dat', '.bin', '.enc', '.crypt', '.key', '.lic', '.cert']

# Suspicious directory names to check
SUSPICIOUS_DIRS = [
    'pairip', 'license', 'protection', 'security', 'checker',
    'validator', 'verifier', 'guard', 'shield', 'defender',
    'antitamper', 'antidebug', 'antiroot', 'signature',
    'rootcheck', 'emulator', 'debug', 'server', 'api'
]

# ==================== LOGGER CLASS ====================

class Logger:
    """Enhanced logging with colors and progress tracking"""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
    
    def print_banner(self):
        """Print PKiller banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════╗
║                PKiller Universal v{VERSION}                 ║
║           Complete Auto Protection Remover                ║
║                 Termux Optimized Edition                  ║
╚══════════════════════════════════════════════════════════╝
        """
        cprint(banner, "cyan", attrs=["bold"])
    
    def info(self, msg):
        if self.console:
            self.console.print(f"[cyan][INFO][/cyan] {msg}")
        else:
            cprint(f"[INFO] {msg}", "cyan")
    
    def success(self, msg):
        if self.console:
            self.console.print(f"[green][✓][/green] {msg}")
        else:
            cprint(f"[✓] {msg}", "green")
    
    def warning(self, msg):
        if self.console:
            self.console.print(f"[yellow][!][/yellow] {msg}")
        else:
            cprint(f"[!] {msg}", "yellow")
    
    def error(self, msg):
        if self.console:
            self.console.print(f"[red][✗][/red] {msg}")
        else:
            cprint(f"[✗] {msg}", "red")
    
    def progress(self, task_id, description, current, total):
        """Show progress bar"""
        if self.console:
            if not hasattr(self, '_progress'):
                self._progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    console=self.console
                )
                self._progress.start()
                self._task = self._progress.add_task(description, total=total)
            
            self._progress.update(self._task, completed=current)
        else:
            percent = (current / total) * 100
            sys.stdout.write(f"\r[🔄] {description}: {current}/{total} ({percent:.1f}%)")
            sys.stdout.flush()
    
    def finish_progress(self):
        """Finish progress display"""
        if self.console and hasattr(self, '_progress'):
            self._progress.stop()
        else:
            sys.stdout.write("\n")
            sys.stdout.flush()
    
    def print_summary(self, stats):
        """Print summary table"""
        if self.console:
            table = Table(title="Processing Summary", show_header=True, header_style="bold magenta")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            for key, value in stats.items():
                table.add_row(key.replace('_', ' ').title(), str(value))
            
            self.console.print(table)
        else:
            cprint("\n" + "="*60, "cyan")
            cprint("PROCESSING SUMMARY", "cyan", attrs=["bold"])
            cprint("="*60, "cyan")
            for key, value in stats.items():
                cprint(f"{key.replace('_', ' ').title():<25}: {value}", "yellow")
            cprint("="*60, "cyan")

# ==================== UTILITY FUNCTIONS ====================

logger = Logger()

def run_command(cmd, timeout=300, capture=False, cwd=None):
    """Run shell command with timeout"""
    try:
        if capture:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                shell=False,
                cwd=cwd
            )
            return result.returncode == 0, result.stdout, result.stderr
        else:
            result = subprocess.run(
                cmd,
                timeout=timeout,
                shell=False,
                cwd=cwd
            )
            return result.returncode == 0, "", ""
    except subprocess.TimeoutExpired:
        return False, "", f"Command timeout after {timeout}s"
    except Exception as e:
        return False, "", str(e)

def check_dependencies():
    """Check if all required tools are available"""
    logger.info("Checking dependencies...")
    
    tools = {
        "apktool": APKTOOL,
        "java": JAVA,
        "keytool": KEYTOOL,
        "zip": ZIP,
    }
    
    missing = []
    for tool, path in tools.items():
        if shutil.which(tool):
            logger.success(f"{tool}: Found")
        else:
            logger.error(f"{tool}: Not found")
            missing.append(tool)
    
    if missing:
        logger.warning("Some tools are missing")
        install_cmd = "pkg install " + " ".join(missing)
        logger.info(f"Install with: {install_cmd}")
        return False
    
    # Check Python modules
    try:
        import termcolor
        logger.success("termcolor: Available")
    except ImportError:
        logger.warning("termcolor not installed")
        logger.info("Install with: pip install termcolor")
    
    if not RICH_AVAILABLE:
        logger.warning("rich module not available (optional)")
        logger.info("Install with: pip install rich (for better UI)")
    
    return True

def get_file_hash(filepath):
    """Calculate SHA256 hash of file"""
    hash_sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def create_backup(original_file, backup_dir="pkiller_backups"):
    """Create backup of original APK"""
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{Path(original_file).stem}_{timestamp}.apk"
    backup_path = os.path.join(backup_dir, backup_name)
    
    shutil.copy2(original_file, backup_path)
    logger.success(f"Backup created: {backup_path}")
    return backup_path

def extract_apk_info(apk_path):
    """Extract basic APK info"""
    try:
        import zipfile
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            # Try to read AndroidManifest (simplified)
            for file_name in zip_ref.namelist():
                if 'AndroidManifest.xml' in file_name:
                    # Just note that it exists
                    break
            
        file_size = os.path.getsize(apk_path) / (1024 * 1024)  # MB
        return {
            "name": Path(apk_path).name,
            "size_mb": round(file_size, 2),
            "hash": get_file_hash(apk_path)[:16],
            "timestamp": datetime.fromtimestamp(os.path.getmtime(apk_path)).strftime("%Y-%m-%d %H:%M:%S")
        }
    except:
        return {"name": Path(apk_path).name, "size_mb": "Unknown"}

# ==================== PROTECTION DETECTOR ====================

class ProtectionDetector:
    """Detect various protection mechanisms in APK"""
    
    def __init__(self, decoded_dir):
        self.decoded_dir = decoded_dir
        self.detections = {}
        self.files_to_patch = []
        self.files_to_remove = []
        
    def scan_directory(self, directory, file_extension=None):
        """Scan directory for files"""
        files = []
        for root, dirs, filenames in os.walk(directory):
            for filename in filenames:
                if file_extension and not filename.endswith(file_extension):
                    continue
                files.append(os.path.join(root, filename))
        return files
    
    def detect_in_file(self, filepath):
        """Detect protections in a single file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            content_lower = content.lower()
            detections = []
            
            # Check each protection type
            for protection_type, patterns in PROTECTION_PATTERNS.items():
                for pattern in patterns:
                    pattern_lower = pattern.lower()
                    if re.search(pattern_lower, content_lower, re.IGNORECASE):
                        detections.append(protection_type)
                        break
            
            # Check file name
            filename = os.path.basename(filepath).lower()
            for dir_name in SUSPICIOUS_DIRS:
                if dir_name in filename:
                    detections.append(f"SUSPICIOUS_FILENAME_{dir_name.upper()}")
            
            # Check file extension
            file_ext = Path(filepath).suffix.lower()
            if file_ext in SUSPICIOUS_EXTENSIONS:
                detections.append(f"SUSPICIOUS_EXTENSION{file_ext.upper()}")
            
            # Check directory path
            filepath_lower = filepath.lower()
            for dir_name in SUSPICIOUS_DIRS:
                if dir_name in filepath_lower:
                    detections.append(f"SUSPICIOUS_PATH_{dir_name.upper()}")
            
            return list(set(detections))  # Remove duplicates
            
        except Exception as e:
            logger.warning(f"Error reading {filepath}: {e}")
            return []
    
    def detect_in_smali(self):
        """Detect protections in smali files"""
        logger.info("Scanning smali files for protections...")
        smali_files = self.scan_directory(self.decoded_dir, '.smali')
        
        detected_files = 0
        for i, smali_file in enumerate(smali_files):
            logger.progress("scan_smali", "Scanning smali files", i+1, len(smali_files))
            
            detections = self.detect_in_file(smali_file)
            if detections:
                detected_files += 1
                self.files_to_patch.append({
                    "file": smali_file,
                    "detections": detections,
                    "type": "smali"
                })
                
                # Add to detections dictionary
                for detection in detections:
                    if detection not in self.detections:
                        self.detections[detection] = []
                    self.detections[detection].append(smali_file)
        
        logger.finish_progress()
        logger.success(f"Found protections in {detected_files} smali files")
        return detected_files > 0
    
    def detect_in_xml(self):
        """Detect protections in XML files"""
        logger.info("Scanning XML files for protections...")
        
        xml_files = []
        for root, dirs, files in os.walk(self.decoded_dir):
            for file in files:
                if file.endswith('.xml'):
                    xml_files.append(os.path.join(root, file))
        
        detected_files = 0
        for i, xml_file in enumerate(xml_files):
            logger.progress("scan_xml", "Scanning XML files", i+1, len(xml_files))
            
            detections = self.detect_in_file(xml_file)
            if detections:
                detected_files += 1
                self.files_to_patch.append({
                    "file": xml_file,
                    "detections": detections,
                    "type": "xml"
                })
        
        logger.finish_progress()
        if detected_files > 0:
            logger.success(f"Found protections in {detected_files} XML files")
        return detected_files > 0
    
    def detect_suspicious_files(self):
        """Detect and mark suspicious files for removal"""
        logger.info("Looking for suspicious files...")
        
        # Check for suspicious directories
        for root, dirs, files in os.walk(self.decoded_dir):
            for dir_name in dirs:
                dir_lower = dir_name.lower()
                for suspicious in SUSPICIOUS_DIRS:
                    if suspicious in dir_lower:
                        dir_path = os.path.join(root, dir_name)
                        self.files_to_remove.append({
                            "path": dir_path,
                            "reason": f"Suspicious directory name: {dir_name}",
                            "type": "directory"
                        })
        
        # Check for suspicious files
        for root, dirs, files in os.walk(self.decoded_dir):
            for file_name in files:
                file_lower = file_name.lower()
                file_path = os.path.join(root, file_name)
                
                # Check extensions
                file_ext = Path(file_name).suffix.lower()
                if file_ext in SUSPICIOUS_EXTENSIONS:
                    self.files_to_remove.append({
                        "path": file_path,
                        "reason": f"Suspicious extension: {file_ext}",
                        "type": "file"
                    })
                    continue
                
                # Check file names
                for suspicious in SUSPICIOUS_DIRS:
                    if suspicious in file_lower:
                        self.files_to_remove.append({
                            "path": file_path,
                            "reason": f"Suspicious file name: {file_name}",
                            "type": "file"
                        })
                        break
        
        if self.files_to_remove:
            logger.success(f"Found {len(self.files_to_remove)} suspicious items to remove")
        else:
            logger.info("No suspicious files found")
        
        return len(self.files_to_remove) > 0
    
    def detect_in_libs(self):
        """Detect protection libraries"""
        logger.info("Checking native libraries...")
        
        lib_dir = os.path.join(self.decoded_dir, "lib")
        if not os.path.exists(lib_dir):
            logger.info("No lib directory found")
            return False
        
        suspicious_libs = []
        for arch in os.listdir(lib_dir):
            arch_dir = os.path.join(lib_dir, arch)
            if os.path.isdir(arch_dir):
                for lib_file in os.listdir(arch_dir):
                    lib_path = os.path.join(arch_dir, lib_file)
                    lib_name = lib_file.lower()
                    
                    # Check for protection library names
                    suspicious_keywords = ['pairip', 'license', 'protection', 'security', 
                                         'checker', 'validator', 'guard', 'shield']
                    
                    if any(keyword in lib_name for keyword in suspicious_keywords):
                        suspicious_libs.append({
                            "path": lib_path,
                            "reason": f"Protection library: {lib_file}",
                            "type": "library"
                        })
        
        if suspicious_libs:
            self.files_to_remove.extend(suspicious_libs)
            logger.success(f"Found {len(suspicious_libs)} suspicious libraries")
        
        return len(suspicious_libs) > 0
    
    def run_detection(self):
        """Run all detection methods"""
        logger.info("Starting comprehensive protection detection...")
        
        self.detect_in_smali()
        self.detect_in_xml()
        self.detect_suspicious_files()
        self.detect_in_libs()
        
        # Summary
        total_detections = sum(len(files) for files in self.detections.values())
        logger.success(f"Total protection detections: {total_detections}")
        
        if self.detections:
            logger.info("Detection summary:")
            for protection_type, files in self.detections.items():
                logger.info(f"  {protection_type}: {len(files)} files")
        
        return total_detections > 0

# ==================== PROTECTION REMOVER ====================

class ProtectionRemover:
    """Remove detected protections from APK"""
    
    def __init__(self, decoded_dir, detector):
        self.decoded_dir = decoded_dir
        self.detector = detector
        self.patch_stats = {
            "files_patched": 0,
            "methods_patched": 0,
            "files_removed": 0,
            "directories_removed": 0
        }
    
    def get_return_type_stub(self, return_type):
        """Get appropriate stub based on return type"""
        stubs = {
            # void
            'V': '''
    .locals 0
    return-void''',
            
            # boolean
            'Z': '''
    .locals 1
    const/4 v0, 0x1
    return v0''',
            
            # int, short, byte, char
            'I': '''
    .locals 1
    const/4 v0, 0x1
    return v0''',
            'S': '''
    .locals 1
    const/4 v0, 0x1
    return v0''',
            'B': '''
    .locals 1
    const/4 v0, 0x1
    return v0''',
            'C': '''
    .locals 1
    const/4 v0, 0x1
    return v0''',
            
            # long
            'J': '''
    .locals 2
    const-wide/16 v0, 0x1
    return-wide v0''',
            
            # float
            'F': '''
    .locals 1
    const/high16 v0, 0x3f800000    # 1.0f
    return v0''',
            
            # double
            'D': '''
    .locals 2
    const-wide/high16 v0, 0x3ff0000000000000L    # 1.0
    return-wide v0''',
            
            # String
            'Ljava/lang/String;': '''
    .locals 1
    const-string v0, "patched"
    return-object v0''',
            
            # Boolean object
            'Ljava/lang/Boolean;': '''
    .locals 2
    const/4 v0, 0x1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v0
    return-object v0''',
            
            # Integer object
            'Ljava/lang/Integer;': '''
    .locals 2
    const/4 v0, 0x1
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;
    move-result-object v0
    return-object v0''',
            
            # Object (default)
            'Ljava/lang/Object;': '''
    .locals 1
    const/4 v0, 0x0
    return-object v0''',
        }
        
        # Default stub for unknown types
        default_stub = '''
    .locals 1
    const/4 v0, 0x0
    return-object v0'''
        
        return stubs.get(return_type, default_stub)
    
    def extract_return_type(self, method_signature):
        """Extract return type from method signature"""
        # Pattern: )ReturnType
        match = re.search(r'\)([^;\s]+)', method_signature)
        if match:
            return match.group(1)
        return None
    
    def patch_smali_method(self, method_content):
        """Patch a single smali method"""
        lines = method_content.strip().split('\n')
        if not lines:
            return method_content, False
        
        signature_line = lines[0]
        return_type = self.extract_return_type(signature_line)
        
        if not return_type:
            return method_content, False
        
        # Create new method with stub
        stub = self.get_return_type_stub(return_type)
        
        # Check if .locals already exists
        has_locals = False
        for line in lines:
            if '.locals' in line:
                has_locals = True
                break
        
        # Build new method
        new_method_lines = [signature_line]
        
        if not has_locals:
            # Add minimal locals declaration
            new_method_lines.append('    .locals 1')
        
        new_method_lines.append(stub)
        new_method_lines.append('.end method')
        
        self.patch_stats["methods_patched"] += 1
        return '\n'.join(new_method_lines), True
    
    def patch_smali_file(self, filepath):
        """Patch all methods in a smali file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            
            # Find and patch all methods
            method_pattern = r'(\.method[\s\S]*?\.end method)'
            methods = re.findall(method_pattern, content, re.DOTALL)
            
            if not methods:
                return False, 0
            
            patched_count = 0
            for method in methods:
                patched_method, was_patched = self.patch_smali_method(method)
                if was_patched:
                    content = content.replace(method, patched_method)
                    patched_count += 1
            
            # Save if changes were made
            if content != original_content and patched_count > 0:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                self.patch_stats["files_patched"] += 1
                return True, patched_count
            
            return False, 0
            
        except Exception as e:
            logger.warning(f"Error patching {filepath}: {e}")
            return False, 0
    
    def patch_xml_file(self, filepath):
        """Patch XML file (AndroidManifest.xml)"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            
            # Remove debuggable restriction
            content = re.sub(r'android:debuggable=["\']false["\']', 
                           'android:debuggable="true"', content)
            
            # Remove backup restriction
            content = re.sub(r'android:allowBackup=["\']false["\']', 
                           'android:allowBackup="true"', content)
            
            # Remove any install restrictions
            content = re.sub(r'android:installLocation=["\'].*?["\']', '', content)
            
            # Remove any protection-related permissions
            protection_permissions = [
                r'android\.permission\.CHECK_LICENSE',
                r'android\.permission\.VERIFY_LICENSE',
                r'com\.android\.vending\.CHECK_LICENSE'
            ]
            
            for perm in protection_permissions:
                content = re.sub(f'<uses-permission.*?{perm}.*?/>', '', content, 
                               flags=re.DOTALL | re.IGNORECASE)
            
            if content != original_content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error patching XML {filepath}: {e}")
            return False
    
    def remove_files(self):
        """Remove detected suspicious files and directories"""
        removed_count = 0
        dir_removed_count = 0
        
        for item in self.detector.files_to_remove:
            try:
                if item["type"] == "directory" and os.path.exists(item["path"]):
                    shutil.rmtree(item["path"])
                    dir_removed_count += 1
                    logger.info(f"Removed directory: {item['path']}")
                
                elif item["type"] in ["file", "library"] and os.path.exists(item["path"]):
                    os.remove(item["path"])
                    removed_count += 1
                    logger.info(f"Removed file: {item['path']}")
                    
                    # Also remove empty parent directories
                    parent_dir = os.path.dirname(item["path"])
                    if os.path.exists(parent_dir) and not os.listdir(parent_dir):
                        os.rmdir(parent_dir)
                        
            except Exception as e:
                logger.warning(f"Failed to remove {item['path']}: {e}")
        
        self.patch_stats["files_removed"] = removed_count
        self.patch_stats["directories_removed"] = dir_removed_count
        
        if removed_count > 0 or dir_removed_count > 0:
            logger.success(f"Removed {removed_count} files and {dir_removed_count} directories")
        
        return removed_count > 0 or dir_removed_count > 0
    
    def run_removal(self):
        """Run all removal operations"""
        logger.info("Starting protection removal...")
        
        # Remove suspicious files first
        self.remove_files()
        
        # Patch smali files
        smali_patches = 0
        smali_files = [f for f in self.detector.files_to_patch if f["type"] == "smali"]
        
        if smali_files:
            logger.info(f"Patching {len(smali_files)} smali files...")
            for i, file_info in enumerate(smali_files):
                logger.progress("patch_smali", "Patching smali files", i+1, len(smali_files))
                patched, count = self.patch_smali_file(file_info["file"])
                if patched:
                    smali_patches += count
            
            logger.finish_progress()
        
        # Patch XML files
        xml_files = [f for f in self.detector.files_to_patch if f["type"] == "xml"]
        xml_patches = 0
        
        if xml_files:
            logger.info(f"Patching {len(xml_files)} XML files...")
            for xml_info in xml_files:
                if self.patch_xml_file(xml_info["file"]):
                    xml_patches += 1
        
        # Summary
        total_patches = self.patch_stats["methods_patched"] + xml_patches
        logger.success(f"Patched {self.patch_stats['methods_patched']} methods and {xml_patches} XML files")
        
        return total_patches > 0

# ==================== APK PROCESSOR ====================

class APKProcessor:
    """Main APK processing class"""
    
    def __init__(self, apk_path, output_name=None):
        self.apk_path = apk_path
        self.apk_name = Path(apk_path).stem
        self.output_name = output_name or f"{self.apk_name}_patched"
        self.output_dir = f"{self.apk_name}_output"
        
        self.decoded_dir = os.path.join(self.output_dir, "decoded")
        self.backup_dir = os.path.join(self.output_dir, "backup")
        
        self.stats = {
            "original_apk": self.apk_name,
            "original_size_mb": 0,
            "start_time": time.time(),
            "detections": {},
            "patches_applied": 0,
            "files_removed": 0
        }
    
    def decode_apk(self):
        """Decode APK using apktool"""
        logger.info(f"Decoding APK: {self.apk_name}")
        
        # Clean up previous decode if exists
        if os.path.exists(self.decoded_dir):
            shutil.rmtree(self.decoded_dir)
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Decode command
        cmd = [APKTOOL, "d", self.apk_path, "-o", self.decoded_dir, "-f", "-s"]
        success, stdout, stderr = run_command(cmd, timeout=600)
        
        if success:
            logger.success("APK decoded successfully")
            
            # Create backup of decoded files
            if os.path.exists(self.backup_dir):
                shutil.rmtree(self.backup_dir)
            shutil.copytree(self.decoded_dir, self.backup_dir)
            logger.success(f"Backup saved to: {self.backup_dir}")
            
            return True
        else:
            logger.error(f"Failed to decode APK: {stderr[:500]}")
            return False
    
    def build_apk(self):
        """Build APK from decoded directory"""
        output_apk = os.path.join(self.output_dir, f"{self.output_name}.apk")
        
        logger.info(f"Building APK: {output_apk}")
        
        cmd = [APKTOOL, "b", self.decoded_dir, "-o", output_apk, "-f"]
        success, stdout, stderr = run_command(cmd, timeout=600)
        
        if success:
            logger.success(f"APK built successfully: {output_apk}")
            return True, output_apk
        else:
            logger.error(f"Failed to build APK: {stderr[:500]}")
            return False, None
    
    def sign_apk(self, apk_path):
        """Sign APK with debug key"""
        logger.info("Signing APK...")
        
        signed_apk = apk_path.replace('.apk', '_signed.apk')
        
        # Create debug keystore if not exists
        keystore_path = os.path.join(self.output_dir, "debug.keystore")
        if not os.path.exists(keystore_path):
            logger.info("Creating debug keystore...")
            cmd = [
                KEYTOOL, "-genkey", "-v",
                "-keystore", keystore_path,
                "-alias", "androiddebugkey",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-storepass", "android",
                "-keypass", "android",
                "-dname", "CN=Android Debug,O=Android,C=US"
            ]
            success, _, _ = run_command(cmd)
            if not success:
                logger.warning("Failed to create keystore")
        
        # Try multiple signing methods
        
        # Method 1: apksigner
        apksigner_path = shutil.which("apksigner")
        if apksigner_path and os.path.exists(keystore_path):
            cmd = [
                apksigner_path, "sign",
                "--ks", keystore_path,
                "--ks-key-alias", "androiddebugkey",
                "--ks-pass", "pass:android",
                "--key-pass", "pass:android",
                "--out", signed_apk,
                apk_path
            ]
            success, stdout, stderr = run_command(cmd)
            if success:
                logger.success("APK signed with apksigner")
                return signed_apk
        
        # Method 2: jarsigner (fallback)
        jarsigner_path = shutil.which("jarsigner")
        if jarsigner_path and os.path.exists(keystore_path):
            cmd = [
                jarsigner_path,
                "-verbose",
                "-keystore", keystore_path,
                "-storepass", "android",
                "-keypass", "android",
                "-sigalg", "SHA1withRSA",
                "-digestalg", "SHA1",
                signed_apk,
                "androiddebugkey"
            ]
            # First copy APK
            shutil.copy2(apk_path, signed_apk)
            success, stdout, stderr = run_command(cmd)
            if success:
                logger.success("APK signed with jarsigner")
                return signed_apk
        
        # Method 3: Just copy (last resort)
        logger.warning("Using unsigned APK (signing failed)")
        shutil.copy2(apk_path, signed_apk)
        return signed_apk
    
    def zipalign_apk(self, apk_path):
        """Zipalign APK for optimization"""
        if not shutil.which("zipalign"):
            logger.warning("zipalign not found, skipping optimization")
            return apk_path
        
        aligned_path = apk_path.replace('.apk', '_aligned.apk')
        
        cmd = [ZIPALIGN, "-v", "4", apk_path, aligned_path]
        success, stdout, stderr = run_command(cmd)
        
        if success:
            # Replace with aligned version
            os.remove(apk_path)
            shutil.move(aligned_path, apk_path)
            logger.success("APK optimized with zipalign")
        else:
            logger.warning(f"Zipalign failed: {stderr[:200]}")
        
        return apk_path
    
    def cleanup(self, keep_decoded=False):
        """Cleanup temporary files"""
        if not keep_decoded:
            try:
                shutil.rmtree(self.decoded_dir)
                logger.info("Cleaned up decoded files")
            except:
                pass
    
    def process(self, keep_decoded=False):
        """Main processing function"""
        logger.print_banner()
        
        # Step 1: Get original APK info
        original_info = extract_apk_info(self.apk_path)
        self.stats["original_size_mb"] = original_info["size_mb"]
        logger.info(f"Processing: {original_info['name']} ({original_info['size_mb']} MB)")
        
        # Step 2: Create backup
        backup_path = create_backup(self.apk_path)
        self.stats["backup_path"] = backup_path
        
        # Step 3: Decode APK
        if not self.decode_apk():
            return False
        
        # Step 4: Detect protections
        detector = ProtectionDetector(self.decoded_dir)
        has_protections = detector.run_detection()
        
        if not has_protections:
            logger.warning("No protections detected!")
            answer = input("Continue anyway? (y/N): ").lower()
            if answer != 'y':
                return False
        
        # Step 5: Remove protections
        remover = ProtectionRemover(self.decoded_dir, detector)
        remover.run_removal()
        
        # Update stats
        self.stats.update(remover.patch_stats)
        self.stats["detections"] = {k: len(v) for k, v in detector.detections.items()}
        
        # Step 6: Build APK
        build_success, built_apk = self.build_apk()
        if not build_success:
            return False
        
        # Step 7: Optimize and sign
        optimized_apk = self.zipalign_apk(built_apk)
        final_apk = self.sign_apk(optimized_apk)
        
        # Step 8: Final info
        if os.path.exists(final_apk):
            final_size = os.path.getsize(final_apk) / (1024 * 1024)
            self.stats["final_apk"] = os.path.basename(final_apk)
            self.stats["final_size_mb"] = round(final_size, 2)
            self.stats["processing_time"] = round(time.time() - self.stats["start_time"], 2)
            
            logger.success(f"\n✅ Processing complete!")
            logger.success(f"📦 Final APK: {self.stats['final_apk']}")
            logger.success(f"📊 Final size: {self.stats['final_size_mb']} MB")
            logger.success(f"⏱ Time taken: {self.stats['processing_time']} seconds")
            
            # Show installation command
            install_cmd = f"adb install -r {final_apk}"
            logger.info(f"Install command: {install_cmd}")
        
        # Step 9: Cleanup
        self.cleanup(keep_decoded)
        
        # Step 10: Save report
        self.save_report()
        
        # Step 11: Show summary
        logger.print_summary(self.stats)
        
        return True
    
    def save_report(self):
        """Save processing report"""
        report_path = os.path.join(self.output_dir, "processing_report.json")
        
        report = {
            "tool": APP_NAME,
            "version": VERSION,
            "timestamp": datetime.now().isoformat(),
            "stats": self.stats,
            "original_hash": get_file_hash(self.apk_path),
            "final_hash": get_file_hash(self.stats.get("final_apk", "")) 
                        if "final_apk" in self.stats and os.path.exists(
                            os.path.join(self.output_dir, self.stats["final_apk"])
                        ) else ""
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.success(f"Report saved: {report_path}")
        
        # Also save a simple text summary
        text_report = os.path.join(self.output_dir, "summary.txt")
        with open(text_report, 'w', encoding='utf-8') as f:
            f.write(f"PKiller Universal v{VERSION} - Processing Report\n")
            f.write("="*50 + "\n\n")
            f.write(f"Original APK: {self.stats['original_apk']}\n")
            f.write(f"Original Size: {self.stats['original_size_mb']} MB\n")
            f.write(f"Final APK: {self.stats.get('final_apk', 'N/A')}\n")
            f.write(f"Final Size: {self.stats.get('final_size_mb', 'N/A')} MB\n")
            f.write(f"Time: {self.stats.get('processing_time', 'N/A')} seconds\n\n")
            
            f.write("Protections Removed:\n")
            for prot_type, count in self.stats.get("detections", {}).items():
                f.write(f"  {prot_type}: {count} files\n")
            
            f.write(f"\nFiles Patched: {self.stats.get('files_patched', 0)}\n")
            f.write(f"Methods Patched: {self.stats.get('methods_patched', 0)}\n")
            f.write(f"Files Removed: {self.stats.get('files_removed', 0)}\n")
            f.write(f"Directories Removed: {self.stats.get('directories_removed', 0)}\n")

# ==================== MAIN FUNCTION ====================

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description=f'{APP_NAME} v{VERSION} - Complete Auto Protection Remover',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  {sys.argv[0]} app.apk                     # Auto patch app.apk
  {sys.argv[0]} app.apk -o patched_app      # Specify output name
  {sys.argv[0]} app.apk --keep              # Keep decoded files
  {sys.argv[0]} --help                      # Show this help

Requirements (Termux):
  pkg install apktool openjdk-17 wget zip
  pip install termcolor

Advanced features with:
  pip install rich

Disclaimer: For educational and testing purposes only.
Use only on apps you own or have permission to modify.
        '''
    )
    
    parser.add_argument('apk_path', nargs='?', help='Input APK file')
    parser.add_argument('-o', '--output', help='Output APK name (without .apk)')
    parser.add_argument('--keep', action='store_true', help='Keep decoded files for debugging')
    parser.add_argument('--version', action='version', version=f'{APP_NAME} v{VERSION}')
    
    args = parser.parse_args()
    
    # Show help if no arguments
    if not args.apk_path:
        parser.print_help()
        return
    
    # Check if file exists
    if not os.path.exists(args.apk_path):
        logger.error(f"File not found: {args.apk_path}")
        sys.exit(1)
    
    # Check if it's an APK
    if not args.apk_path.lower().endswith('.apk'):
        logger.warning(f"File doesn't have .apk extension: {args.apk_path}")
        answer = input("Continue anyway? (y/N): ").lower()
        if answer != 'y':
            sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        logger.warning("Some dependencies may be missing")
        answer = input("Continue anyway? (y/N): ").lower()
        if answer != 'y':
            sys.exit(1)
    
    try:
        # Process APK
        processor = APKProcessor(args.apk_path, args.output)
        success = processor.process(keep_decoded=args.keep)
        
        if success:
            logger.success("\n🎉 Processing completed successfully!")
            logger.success("Check the output directory for your patched APK.")
            sys.exit(0)
        else:
            logger.error("\n❌ Processing failed!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.error("\n\nProcess interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
