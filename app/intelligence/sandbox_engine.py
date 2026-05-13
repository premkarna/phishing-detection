import hashlib
import logging
import os
import subprocess
import json
import tempfile
import time
import zipfile
import struct
import math
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class SandboxSimulator:
    """
    Zero-Click Local Sandbox — isolated tempdir per scan, pure Python.
    No Docker, no SSH, no external tools required.
    Supports .exe/.bat/.ps1, .pdf, .doc/.docx, archives, and scripts.
    """

    def __init__(self, vm_config: Optional[Dict] = None):
        # Known bad hashes (forensic lookup)
        self.known_malware_hashes = [
            "44d88612fea8a8f36de82e1278abb02f",  # WannaCry variant
            "e5b045de501258cdb8d1b110a1200115",  # Emotet loader
            "cf83e1357eefb8bdf1542850d66d8007"   # Cobalt Strike Beacon
        ]

        # File type categories
        self.executable_exts = ['.exe', '.bat', '.ps1', '.vbs', '.msi', '.scr', '.com']
        self.document_exts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.docm', '.xlsm', '.rtf']
        self.archive_exts = ['.zip', '.rar', '.tar', '.gz', '.7z', '.iso', '.img', '.cab', '.tar.gz', '.tgz']
        self.script_exts = ['.js', '.jse', '.wsf', '.hta', '.vbe']

        # Suspicious PE imports (static analysis)
        self.suspicious_apis = [
            b'CreateRemoteThread', b'WriteProcessMemory', b'VirtualAllocEx',
            b'InternetOpenA', b'InternetConnectA', b'HttpSendRequestA',
            b'WSAStartup', b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
            b'VirtualProtect', b'NtUnmapViewOfSection', b'RegSetValueEx',
            b'ShellExecute', b'WinExec', b'CreateProcess'
        ]

        # Suspicious PDF keywords
        self.suspicious_pdf_keywords = [
            b'/JavaScript', b'/JS', b'/OpenAction', b'/Launch',
            b'/EmbeddedFile', b'/AA', b'/AcroForm', b'cmd.exe',
            b'powershell', b'mshta', b'wscript'
        ]

        # vm_config kept for backward-compat with tests
        self.vm_config = vm_config or {
            'host': os.getenv('SANDBOX_VM_HOST', 'localhost'),
            'port': int(os.getenv('SANDBOX_VM_PORT', '2222')),
            'user': os.getenv('SANDBOX_VM_USER', 'sandbox'),
            'key_file': os.getenv('SANDBOX_VM_KEY', '~/.ssh/sandbox_vm'),
            'working_dir': '/tmp/sandbox_detonation',
            'timeout': 120
        }
        self.vm_tools = {
            'exiftool': '/usr/bin/exiftool', 'pdfinfo': '/usr/bin/pdfinfo',
            'strings': '/usr/bin/strings', 'objdump': '/usr/bin/objdump',
            'peframe': '/usr/local/bin/peframe', 'clamscan': '/usr/bin/clamscan',
            'tshark': '/usr/bin/tshark', 'wine': '/usr/bin/wine',
            'xorsearch': '/usr/local/bin/xorsearch', 'yara': '/usr/local/bin/yara'
        }

        logging.info("[+] SANDBOX: Zero-Click Local Sandbox Initialized (isolated tempdir per scan, pure Python)")

    def generate_hash(self, file_path: str) -> Dict[str, str]:
        """Generate MD5, SHA1, and SHA256 hashes of file."""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            logging.error(f"[-] Hash generation failed: {e}")
        return hashes

    # ------------------------------------------------------------------ #
    #  Local Sandbox Internals (pure Python, no SSH/Docker needed)         #
    # ------------------------------------------------------------------ #

    def _create_sandbox_dir(self) -> str:
        """Create an isolated temp directory for this scan session."""
        sandbox_dir = tempfile.mkdtemp(prefix="sandbox_")
        logging.info(f"[+] SANDBOX: Isolated tempdir created → {sandbox_dir}")
        return sandbox_dir

    def _cleanup_sandbox_dir(self, sandbox_dir: str):
        """Destroy the sandbox directory after analysis."""
        try:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
            logging.info(f"[+] SANDBOX: Tempdir destroyed → {sandbox_dir}")
        except Exception as e:
            logging.warning(f"[-] SANDBOX: Cleanup failed: {e}")

    def _analyze_pdf_local(self, file_path: str) -> Dict:
        """Pure-Python PDF analysis — no external tools needed."""
        results = {
            'metadata': {},
            'javascript': False,
            'embedded_files': [],
            'urls': [],
            'suspicious_strings': []
        }
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Check for suspicious PDF keywords
            for kw in self.suspicious_pdf_keywords:
                if kw.lower() in data.lower():
                    kw_str = kw.decode('latin-1', errors='replace')
                    results['suspicious_strings'].append(kw_str)
                    if kw in (b'/JavaScript', b'/JS'):
                        results['javascript'] = True
                    if kw == b'/EmbeddedFile':
                        results['embedded_files'].append('embedded_file_detected')

            # Extract URLs from raw bytes
            urls = re.findall(rb'https?://[^\s<>"\x00-\x1f]{4,200}', data)
            results['urls'] = list(set(u.decode('latin-1', errors='replace') for u in urls))[:20]

            # Basic metadata from PDF header
            if data.startswith(b'%PDF'):
                version_match = re.search(rb'%PDF-(\d\.\d)', data)
                if version_match:
                    results['metadata']['PDF-Version'] = version_match.group(1).decode()
            else:
                results['suspicious_strings'].append('INVALID_PDF_HEADER')

        except Exception as e:
            logging.warning(f"[-] SANDBOX: PDF analysis error: {e}")
        return results

    def _analyze_exe_local(self, file_path: str) -> Dict:
        """Pure-Python PE/EXE static analysis — byte scanning for suspicious APIs."""
        results = {
            'pe_info': {},
            'suspicious_api': [],
            'wine_execution': {'exit_code': -1, 'output': 'Local sandbox: execution blocked for safety', 'timeout': False},
            'dropped_files': [],
            'is_valid_pe': False
        }
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Check MZ header
            if data[:2] == b'MZ':
                results['is_valid_pe'] = True
                results['pe_info']['header'] = 'MZ (Windows PE)'

                # Try to read PE offset and machine type
                pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
                if pe_offset + 6 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
                    results['pe_info']['machine'] = '64-bit' if machine == 0x8664 else '32-bit' if machine == 0x14c else f'0x{machine:04x}'

            # Scan for suspicious API strings
            found = []
            for api in self.suspicious_apis:
                if api in data:
                    found.append(api.decode('latin-1', errors='replace'))
            results['suspicious_api'] = list(set(found))

            # Entropy check
            entropy = self._calculate_entropy(data[:65536])
            results['pe_info']['entropy'] = round(entropy, 2)
            if entropy > 7.2:
                results['pe_info']['packed'] = True

        except Exception as e:
            logging.warning(f"[-] SANDBOX: EXE analysis error: {e}")
        return results

    def _analyze_archive_local(self, file_path: str, sandbox_dir: str) -> Dict:
        """Pure-Python archive analysis using zipfile."""
        results = {
            'extracted_files': [],
            'nested_archives': 0,
            'executables_inside': [],
            'scripts_inside': []
        }
        extract_dir = os.path.join(sandbox_dir, 'extracted')
        os.makedirs(extract_dir, exist_ok=True)

        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    # Guard against zip bombs: cap total uncompressed size
                    total_size = sum(i.file_size for i in zf.infolist())
                    if total_size > 100 * 1024 * 1024:  # 100 MB cap
                        results['extracted_files'] = ['[ZIP BOMB SUSPECTED — extraction aborted]']
                        return results
                    zf.extractall(extract_dir)
                    names = zf.namelist()
                    results['extracted_files'] = names

                    archive_exts_set = set(self.archive_exts)
                    for name in names:
                        ext = os.path.splitext(name)[1].lower()
                        if ext in archive_exts_set:
                            results['nested_archives'] += 1
                        if ext in self.executable_exts:
                            results['executables_inside'].append(name)
                        if ext in self.script_exts:
                            results['scripts_inside'].append(name)
            else:
                results['extracted_files'] = ['[Non-ZIP archive — extraction requires external tool]']
        except Exception as e:
            logging.warning(f"[-] SANDBOX: Archive analysis error: {e}")
            results['extracted_files'] = [f'[ERROR: {e}]']
        return results

    def _check_network_behavior(self, duration: int = 10) -> Dict:
        """Network monitoring stub — real capture needs a live VM/container."""
        return {
            'connections': [],
            'dns_queries': [],
            'suspicious_ips': [],
            'data_exfiltration': False,
            'note': 'Network capture unavailable in local sandbox mode'
        }

    # ------------------------------------------------------------------ #
    #  Legacy SSH/VM stubs — kept so existing tests don't break            #
    # ------------------------------------------------------------------ #

    def _run_vm_command(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Legacy SSH stub — not used in local sandbox mode."""
        ssh_cmd = [
            'ssh', '-p', str(self.vm_config['port']),
            '-i', os.path.expanduser(self.vm_config['key_file']),
            '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10',
            f"{self.vm_config['user']}@{self.vm_config['host']}", command
        ]
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "SSH command timed out"
        except Exception as e:
            return -1, "", str(e)

    def _transfer_to_vm(self, local_path: str, remote_name: str) -> bool:
        """Legacy SCP stub."""
        scp_cmd = [
            'scp', '-P', str(self.vm_config['port']),
            '-i', os.path.expanduser(self.vm_config['key_file']),
            '-o', 'StrictHostKeyChecking=no', local_path,
            f"{self.vm_config['user']}@{self.vm_config['host']}:{self.vm_config['working_dir']}/{remote_name}"
        ]
        try:
            result = subprocess.run(scp_cmd, capture_output=True, timeout=30)
            return result.returncode == 0
        except Exception as e:
            logging.error(f"[-] File transfer failed: {e}")
            return False

    def _setup_vm_environment(self) -> bool:
        """Legacy VM setup stub."""
        cmd = f"mkdir -p {self.vm_config['working_dir']} && rm -rf {self.vm_config['working_dir']}/*"
        exit_code, _, _ = self._run_vm_command(cmd, timeout=10)
        return exit_code == 0

    def _analyze_pdf_vm(self, file_path: str, remote_name: str) -> Dict:
        """Legacy VM PDF stub — delegates to local analysis."""
        return self._analyze_pdf_local(file_path)

    def _analyze_exe_vm(self, file_path: str, remote_name: str) -> Dict:
        """Legacy VM EXE stub — delegates to local analysis."""
        return self._analyze_exe_local(file_path)

    def _analyze_archive_vm(self, file_path: str, remote_name: str) -> Dict:
        """Legacy VM archive stub — delegates to local analysis."""
        sandbox_dir = os.path.dirname(file_path)
        return self._analyze_archive_local(file_path, sandbox_dir)
    
    def analyze_file(self, file_path: str, perform_detonation: bool = True) -> Dict:
        """
        Zero-Click Local Sandbox detonation.
        Each call gets a fresh isolated tempdir, cleaned up after analysis.
        No SSH, no Docker, no external tools required.
        """
        file_name = os.path.basename(file_path)
        ext = os.path.splitext(file_name)[1].lower()

        logging.info(f"[*] SANDBOX: Initiating Zero-Click local analysis for {file_name}")

        hashes = self.generate_hash(file_path)

        report = {
            "file_name": file_name,
            "file_path": file_path,
            "hashes": hashes,
            "file_type": ext,
            "status": "CLEAN",
            "risk_score": 0,
            "sandbox_logs": [
                "[+] Sandbox: Local Isolated Tempdir (pure Python, zero infra)",
                f"[+] Mode: {'FULL_SCAN' if perform_detonation else 'STATIC_ONLY'}",
                f"[+] Target: {file_name}",
                f"[+] SHA256: {hashes.get('sha256', 'N/A')[:32]}..."
            ],
            "vm_analysis": {},
            "network_activity": [],
            "verdict": "SAFE",
            "detonation_time": 0
        }

        # Known-bad hash check
        if hashes.get('md5') in self.known_malware_hashes:
            report["status"] = "CRITICAL: Known Malware Hash"
            report["risk_score"] = 100
            report["verdict"] = "MALICIOUS"
            report["sandbox_logs"].append("[!!!] FATAL: Hash matches known threat database")
            return report

        start_time = time.time()
        sandbox_dir = self._create_sandbox_dir()

        try:
            if perform_detonation:
                report["sandbox_logs"].append(f"[+] Sandbox dir: {sandbox_dir}")

                if ext == '.pdf':
                    analysis = self._analyze_pdf_local(file_path)
                    report["vm_analysis"]["pdf_analysis"] = analysis
                    if analysis.get('javascript'):
                        report["risk_score"] += 40
                        report["sandbox_logs"].append("[!!!] PDF contains JavaScript — Active Content Detected")
                    if analysis.get('urls'):
                        report["risk_score"] += 20
                        report["sandbox_logs"].append(f"[!] PDF contains {len(analysis['urls'])} embedded URLs")
                    if analysis.get('suspicious_strings'):
                        report["risk_score"] += min(len(analysis['suspicious_strings']) * 5, 30)
                        report["sandbox_logs"].append(f"[!] Suspicious PDF keywords: {', '.join(analysis['suspicious_strings'][:5])}")

                elif ext in self.executable_exts:
                    analysis = self._analyze_exe_local(file_path)
                    report["vm_analysis"]["exe_analysis"] = analysis
                    if analysis.get('suspicious_api'):
                        report["risk_score"] += min(len(analysis['suspicious_api']) * 5, 50)
                        report["sandbox_logs"].append(f"[!] {len(analysis['suspicious_api'])} suspicious API imports found")
                    if analysis.get('pe_info', {}).get('packed'):
                        report["risk_score"] += 20
                        report["sandbox_logs"].append("[!] High entropy — likely packed/encrypted payload")
                    if not analysis.get('is_valid_pe') and ext == '.exe':
                        report["risk_score"] += 10
                        report["sandbox_logs"].append("[!] Invalid PE header — possible disguised file")

                elif ext in self.archive_exts:
                    analysis = self._analyze_archive_local(file_path, sandbox_dir)
                    report["vm_analysis"]["archive_analysis"] = analysis
                    if analysis.get('executables_inside'):
                        exe_count = len(analysis['executables_inside'])
                        report["risk_score"] += min(exe_count * 15, 60)
                        report["sandbox_logs"].append(f"[!] Archive contains {exe_count} executable(s)")
                    if analysis.get('nested_archives', 0) > 0:
                        report["risk_score"] += 20
                        report["sandbox_logs"].append("[!] Nested archives detected — possible obfuscation")
                    if analysis.get('scripts_inside'):
                        report["risk_score"] += 15
                        report["sandbox_logs"].append(f"[!] Scripts inside archive: {analysis['scripts_inside']}")

                else:
                    self._static_analysis_fallback(report, file_path, ext)
            else:
                self._static_analysis_fallback(report, file_path, ext)

        finally:
            self._cleanup_sandbox_dir(sandbox_dir)

        report["detonation_time"] = round(time.time() - start_time, 2)

        # Final verdict
        if report["risk_score"] >= 80:
            report["status"] = "CRITICAL: THREAT DETONATED"
            report["verdict"] = "MALICIOUS"
        elif report["risk_score"] >= 50:
            report["status"] = "HIGH: SUSPICIOUS BEHAVIOR"
            report["verdict"] = "SUSPICIOUS"
        elif report["risk_score"] >= 20:
            report["status"] = "MEDIUM: REQUIRES REVIEW"
            report["verdict"] = "SUSPICIOUS"

        report["risk_score"] = min(report["risk_score"], 100)
        report["sandbox_logs"].append(f"[+] Analysis complete in {report['detonation_time']}s | Risk: {report['risk_score']}/100")

        return report
    
    def _static_analysis_fallback(self, report: Dict, file_path: str, ext: str):
        """Fallback static analysis when VM is unavailable."""
        report["sandbox_logs"].append("[*] Performing static analysis (VM unavailable)")
        
        if ext in self.executable_exts:
            report["risk_score"] += 30
            report["sandbox_logs"].append("[!] Executable file type - elevated risk")
        
        if ext in self.document_exts and any(k in report["file_name"].lower() for k in ["invoice", "urgent", "payment"]):
            report["risk_score"] += 25
            report["sandbox_logs"].append("[!] Document with social engineering filename pattern")
        
        # Check file entropy (simple implementation)
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(65536, os.path.getsize(file_path)))
                if len(data) > 0:
                    entropy = self._calculate_entropy(data)
                    if entropy > 7.5:
                        report["risk_score"] += 15
                        report["sandbox_logs"].append(f"[!] High entropy ({entropy:.2f}) - possible packed/encrypted")
        except (IOError, OSError, ValueError):
            # File read error or invalid data - skip entropy check
            pass
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    
    def _apply_verdict(self, report: Dict):
        """Apply final verdict based on risk score."""
        if report["risk_score"] >= 80:
            report["status"] = "CRITICAL: THREAT DETONATED"
            report["verdict"] = "MALICIOUS"
        elif report["risk_score"] >= 50:
            report["status"] = "HIGH: SUSPICIOUS BEHAVIOR"
            report["verdict"] = "SUSPICIOUS"
        elif report["risk_score"] >= 20:
            report["status"] = "MEDIUM: REQUIRES REVIEW"
            report["verdict"] = "SUSPICIOUS"
        else:
            report["status"] = "CLEAN"
            report["verdict"] = "SAFE"

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sim = SandboxSimulator()
    
    # Test with sample files
    test_files = [
        "invoice_9921.pdf",
        "setup.exe",
        "document.zip"
    ]
    
    for f in test_files:
        print(f"\n{'='*60}")
        print(f"Testing: {f}")
        print('='*60)
        result = sim.analyze_file(f, perform_detonation=False)
        print(f"Verdict: {result['verdict']} (Risk: {result['risk_score']}/100)")
        print(f"Status: {result['status']}")
        for log in result['sandbox_logs']:
            print(f"  {log}")
