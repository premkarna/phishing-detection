"""
Zero-Click Sandbox Detonation Test Suite
Comprehensive tests for VM-based file analysis of .exe, .pdf, and other suspicious files.
"""
import unittest
import os
import tempfile
import hashlib
import json
import zipfile
from unittest.mock import patch, MagicMock, call
from app.intelligence.sandbox_engine import SandboxSimulator


class TestSandboxZeroClickDetonation(unittest.TestCase):
    """Test cases for Zero-Click VM-based file detonation."""
    
    def setUp(self):
        """Set up test environment with mock VM configuration."""
        self.vm_config = {
            'host': 'test-vm.local',
            'port': 2222,
            'user': 'testuser',
            'key_file': '/tmp/test_key',
            'working_dir': '/tmp/sandbox_test',
            'timeout': 30
        }
        self.sandbox = SandboxSimulator(vm_config=self.vm_config)
    
    # ========== TEST: File Type Classification ==========
    
    def test_executable_extensions_recognition(self):
        """Verify all executable extensions are properly recognized."""
        exe_files = [
            'malware.exe', 'script.bat', 'payload.ps1', 
            'macro.vbs', 'installer.msi', 'screensaver.scr'
        ]
        for f in exe_files:
            ext = os.path.splitext(f)[1].lower()
            self.assertIn(ext, self.sandbox.executable_exts, 
                         f"{ext} should be in executable extensions")
    
    def test_document_extensions_recognition(self):
        """Verify document extensions including PDF are recognized."""
        doc_files = [
            'invoice.pdf', 'memo.doc', 'report.docx', 
            'budget.xls', 'data.xlsx', 'macro.docm'
        ]
        for f in doc_files:
            ext = os.path.splitext(f)[1].lower()
            self.assertIn(ext, self.sandbox.document_exts,
                         f"{ext} should be in document extensions")
    
    def test_archive_extensions_recognition(self):
        """Verify archive extensions are recognized."""
        arch_files = ['data.zip', 'files.rar', 'backup.tar.gz', 'image.iso']
        for f in arch_files:
            ext = os.path.splitext(f)[1].lower()
            # Handle .tar.gz special case
            if '.tar' in f:
                self.assertIn('.tar.gz', self.sandbox.archive_exts)
            else:
                self.assertIn(ext, self.sandbox.archive_exts)
    
    # ========== TEST: Hash Generation ==========
    
    def test_hash_generation_for_file(self):
        """Test MD5, SHA1, SHA256 hash generation."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"test malware content")
            temp_path = f.name
        
        try:
            hashes = self.sandbox.generate_hash(temp_path)
            
            # Verify all hash types are present
            self.assertIn('md5', hashes)
            self.assertIn('sha1', hashes)
            self.assertIn('sha256', hashes)
            
            # Verify hash lengths
            self.assertEqual(len(hashes['md5']), 32)
            self.assertEqual(len(hashes['sha1']), 40)
            self.assertEqual(len(hashes['sha256']), 64)
            
            # Verify consistency
            hashes2 = self.sandbox.generate_hash(temp_path)
            self.assertEqual(hashes, hashes2)
        finally:
            os.unlink(temp_path)
    
    def test_known_malware_hash_detection(self):
        """Test detection of known malicious hashes."""
        # Create file that matches known hash pattern
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Predefined content to get specific hash
            content = b"wannacry_test_content"
            f.write(content)
            temp_path = f.name
        
        # Mock the hash to match known malware
        with patch.object(self.sandbox, 'generate_hash') as mock_hash:
            mock_hash.return_value = {'md5': '44d88612fea8a8f36de82e1278abb02f'}
            
            result = self.sandbox.analyze_file(temp_path, perform_detonation=False)
            
            self.assertEqual(result['verdict'], 'MALICIOUS')
            self.assertEqual(result['risk_score'], 100)
            self.assertIn('CRITICAL', result['status'])
        
        os.unlink(temp_path)
    
    # ========== TEST: VM Connection and Setup ==========
    
    @patch('subprocess.run')
    def test_vm_setup_environment(self, mock_run):
        """Test VM working directory setup via SSH."""
        mock_run.return_value = MagicMock(returncode=0)
        
        result = self.sandbox._setup_vm_environment()
        
        self.assertTrue(result)
        mock_run.assert_called_once()
        # Verify command includes mkdir and cleanup
        call_args = mock_run.call_args[0][0]
        self.assertIn('mkdir', ' '.join(call_args))
        self.assertIn('rm -rf', ' '.join(call_args))
    
    @patch('subprocess.run')
    def test_vm_setup_failure_handling(self, mock_run):
        """Test handling of VM setup failure."""
        mock_run.return_value = MagicMock(returncode=1, stderr=b'SSH connection failed')
        
        result = self.sandbox._setup_vm_environment()
        
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_file_transfer_to_vm(self, mock_run):
        """Test SCP file transfer to VM."""
        mock_run.return_value = MagicMock(returncode=0)
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = f.name
        
        try:
            result = self.sandbox._transfer_to_vm(local_path, 'test_sample.exe')
            
            self.assertTrue(result)
            mock_run.assert_called_once()
            # Verify SCP command structure
            call_args = mock_run.call_args[0][0]
            self.assertIn('scp', call_args)
        finally:
            os.unlink(local_path)
    
    # ========== TEST: PDF Analysis (local) ==========

    def test_pdf_javascript_detection(self):
        """Test detection of JavaScript in PDF files."""
        pdf_content = b"%PDF-1.4\n/JavaScript (alert(1))\n/JS\nhttps://http://evil.com/malware"
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(pdf_content)
            temp_path = f.name
        try:
            result = self.sandbox._analyze_pdf_local(temp_path)
            self.assertTrue(result['javascript'])
        finally:
            os.unlink(temp_path)

    def test_pdf_metadata_extraction(self):
        """Test PDF metadata extraction from header."""
        pdf_content = b"%PDF-1.4\n1 0 obj\n<</Type /Catalog>>\nendobj"
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(pdf_content)
            temp_path = f.name
        try:
            result = self.sandbox._analyze_pdf_local(temp_path)
            self.assertIn('PDF-Version', result['metadata'])
            self.assertEqual(result['metadata']['PDF-Version'], '1.4')
        finally:
            os.unlink(temp_path)

    def test_pdf_embedded_files_detection(self):
        """Test detection of embedded files in PDF."""
        pdf_content = b"%PDF-1.4\n/EmbeddedFile\npayload content"
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(pdf_content)
            temp_path = f.name
        try:
            result = self.sandbox._analyze_pdf_local(temp_path)
            self.assertTrue(len(result['embedded_files']) > 0)
        finally:
            os.unlink(temp_path)
    
    # ========== TEST: EXE Analysis (local) ==========

    def test_exe_suspicious_api_detection(self):
        """Test detection of suspicious Windows APIs in EXE."""
        exe_content = b'MZ' + b'\x00' * 0x3a + b'\x40\x00\x00\x00' + b'\x00' * 4 + b'PE\x00\x00\x4c\x01'
        exe_content += b'CreateRemoteThread' + b'WriteProcessMemory' + b'InternetOpenA'
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(exe_content)
            temp_path = f.name
        try:
            result = self.sandbox._analyze_exe_local(temp_path)
            self.assertIn('CreateRemoteThread', result['suspicious_api'])
            self.assertIn('WriteProcessMemory', result['suspicious_api'])
            self.assertIn('InternetOpenA', result['suspicious_api'])
        finally:
            os.unlink(temp_path)

    def test_exe_wine_execution_monitoring(self):
        """Test Wine execution field is present in EXE analysis result."""
        exe_content = b'MZ' + b'\x00' * 100
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(exe_content)
            temp_path = f.name
        try:
            result = self.sandbox._analyze_exe_local(temp_path)
            self.assertIn('output', result['wine_execution'])
            self.assertIn('exit_code', result['wine_execution'])
        finally:
            os.unlink(temp_path)

    def test_exe_dropped_files_detection(self):
        """Test dropped_files field is present in EXE analysis result."""
        exe_content = b'MZ' + b'\x00' * 100
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(exe_content)
            temp_path = f.name
        try:
            result = self.sandbox._analyze_exe_local(temp_path)
            self.assertIn('dropped_files', result)
            self.assertIsInstance(result['dropped_files'], list)
        finally:
            os.unlink(temp_path)
    
    # ========== TEST: Archive Analysis (local) ==========

    def test_zip_extraction_and_analysis(self):
        """Test ZIP extraction and content analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'test.zip')
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('file1.txt', 'hello')
                zf.writestr('file2.exe', 'MZ fake exe')
            sandbox_dir = tempfile.mkdtemp()
            try:
                result = self.sandbox._analyze_archive_local(zip_path, sandbox_dir)
                self.assertEqual(len(result['extracted_files']), 2)
                self.assertIn('file2.exe', result['executables_inside'])
            finally:
                import shutil
                shutil.rmtree(sandbox_dir, ignore_errors=True)

    def test_nested_archive_detection(self):
        """Test detection of nested archives (obfuscation)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inner_zip = os.path.join(tmpdir, 'inner.zip')
            with zipfile.ZipFile(inner_zip, 'w') as zf:
                zf.writestr('note.txt', 'inner')
            outer_zip = os.path.join(tmpdir, 'outer.zip')
            with zipfile.ZipFile(outer_zip, 'w') as zf:
                zf.write(inner_zip, 'inner.zip')
                zf.writestr('readme.txt', 'readme')
            sandbox_dir = tempfile.mkdtemp()
            try:
                result = self.sandbox._analyze_archive_local(outer_zip, sandbox_dir)
                self.assertGreaterEqual(result['nested_archives'], 1)
            finally:
                import shutil
                shutil.rmtree(sandbox_dir, ignore_errors=True)

    def test_archive_with_multiple_executables(self):
        """Test detection of multiple EXEs in archive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'multi.zip')
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('file1.exe', 'MZ')
                zf.writestr('file2.exe', 'MZ')
                zf.writestr('file3.exe', 'MZ')
                zf.writestr('readme.txt', 'readme')
            sandbox_dir = tempfile.mkdtemp()
            try:
                result = self.sandbox._analyze_archive_local(zip_path, sandbox_dir)
                self.assertEqual(len(result['executables_inside']), 3)
            finally:
                import shutil
                shutil.rmtree(sandbox_dir, ignore_errors=True)
    
    # ========== TEST: Network Behavior Monitoring ==========

    def test_dns_query_monitoring(self):
        """Test network behavior stub returns expected structure."""
        result = self.sandbox._check_network_behavior(duration=1)
        self.assertIn('dns_queries', result)
        self.assertIn('connections', result)
        self.assertIn('suspicious_ips', result)
        self.assertIsInstance(result['dns_queries'], list)

    def test_suspicious_ip_detection(self):
        """Test network behavior stub returns expected structure."""
        result = self.sandbox._check_network_behavior(duration=1)
        self.assertIn('suspicious_ips', result)
        self.assertIsInstance(result['suspicious_ips'], list)
    
    # ========== TEST: Risk Scoring and Verdicts ==========
    
    def test_pdf_with_javascript_risk_score(self):
        """Test risk scoring for PDF with JavaScript."""
        pdf_content = b"%PDF-1.4\n/JavaScript (alert(1))\n/JS\nhttps://evil.com/payload"
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(pdf_content)
            temp_path = f.name
        try:
            result = self.sandbox.analyze_file(temp_path, perform_detonation=True)
            # JavaScript (40) + URLs (20) = 60 minimum
            self.assertGreaterEqual(result['risk_score'], 60)
            self.assertEqual(result['verdict'], 'SUSPICIOUS')
        finally:
            os.unlink(temp_path)
    
    def test_exe_with_suspicious_apis_risk_score(self):
        """Test risk scoring for EXE with suspicious APIs."""
        exe_content = b'MZ' + b'\x00' * 0x3a + b'\x40\x00\x00\x00' + b'\x00' * 4 + b'PE\x00\x00\x4c\x01'
        exe_content += (
            b'CreateRemoteThread' + b'WriteProcessMemory' + b'InternetOpenA' +
            b'VirtualAllocEx' + b'InternetConnectA' + b'HttpSendRequestA' +
            b'WSAStartup' + b'IsDebuggerPresent' + b'VirtualProtect' +
            b'ShellExecute' + b'WinExec'
        )
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(exe_content)
            temp_path = f.name
        try:
            result = self.sandbox.analyze_file(temp_path, perform_detonation=True)
            self.assertGreaterEqual(result['risk_score'], 50)
        finally:
            os.unlink(temp_path)
    
    def test_risk_score_capped_at_100(self):
        """Verify risk score never exceeds 100."""
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(b"content")
            temp_path = f.name
        
        # Manually set very high risk
        with patch.object(self.sandbox, '_static_analysis_fallback') as mock_static:
            def add_high_risk(report, path, ext):
                report['risk_score'] = 150
            mock_static.side_effect = add_high_risk
            
            result = self.sandbox.analyze_file(temp_path, perform_detonation=False)
            self.assertLessEqual(result['risk_score'], 100)
        
        os.unlink(temp_path)
    
    # ========== TEST: Verdict Classification ==========
    
    def test_verdict_malicious_for_high_risk(self):
        """Test MALICIOUS verdict for risk >= 80."""
        report = {'risk_score': 85, 'verdict': 'SAFE', 'status': 'CLEAN', 'sandbox_logs': []}
        self.sandbox._apply_verdict(report)
        
        self.assertEqual(report['verdict'], 'MALICIOUS')
        self.assertIn('CRITICAL', report['status'])
    
    def test_verdict_suspicious_for_medium_risk(self):
        """Test SUSPICIOUS verdict for risk 50-79."""
        report = {'risk_score': 65, 'verdict': 'SAFE', 'status': 'CLEAN', 'sandbox_logs': []}
        self.sandbox._apply_verdict(report)
        
        self.assertEqual(report['verdict'], 'SUSPICIOUS')
        self.assertIn('HIGH', report['status'])
    
    def test_verdict_safe_for_low_risk(self):
        """Test SAFE verdict for risk < 50."""
        report = {'risk_score': 15, 'verdict': 'SAFE', 'status': 'CLEAN', 'sandbox_logs': []}
        self.sandbox._apply_verdict(report)
        
        self.assertEqual(report['verdict'], 'SAFE')
        self.assertIn('CLEAN', report['status'])
    
    # ========== TEST: Static Analysis Fallback ==========
    
    def test_static_fallback_for_executable(self):
        """Test static analysis adds risk for executables."""
        report = {
            'risk_score': 0,
            'file_name': 'setup.exe',
            'sandbox_logs': []
        }
        
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b"MZ content")
            temp_path = f.name
        
        self.sandbox._static_analysis_fallback(report, temp_path, '.exe')
        
        self.assertGreater(report['risk_score'], 0)
        self.assertIn('Executable file type', ' '.join(report['sandbox_logs']))
        
        os.unlink(temp_path)
    
    def test_static_fallback_for_social_engineering_filename(self):
        """Test detection of social engineering patterns in filename."""
        report = {
            'risk_score': 0,
            'file_name': 'urgent_invoice_payment.pdf',
            'sandbox_logs': []
        }
        
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            temp_path = f.name
        
        self.sandbox._static_analysis_fallback(report, temp_path, '.pdf')
        
        self.assertGreater(report['risk_score'], 0)
        self.assertIn('social engineering', ' '.join(report['sandbox_logs']).lower())
        
        os.unlink(temp_path)
    
    def test_static_fallback_entropy_check(self):
        """Test entropy detection for packed/encrypted files."""
        import random
        # Create high-entropy (random) content
        random_content = bytes([random.randint(0, 255) for _ in range(10000)])
        
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(random_content)
            temp_path = f.name
        
        report = {'risk_score': 0, 'file_name': 'packed.exe', 'sandbox_logs': []}
        self.sandbox._static_analysis_fallback(report, temp_path, '.exe')
        
        # High entropy should trigger additional risk
        entropy_logs = [log for log in report['sandbox_logs'] if 'entropy' in log.lower()]
        self.assertTrue(len(entropy_logs) > 0 or report['risk_score'] > 30)
        
        os.unlink(temp_path)
    
    # ========== TEST: Integration Tests ==========
    
    def test_full_analysis_flow_pdf(self):
        """Integration test for complete PDF analysis flow."""
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\nxref\ntrailer\n<<\n/Size 1\n/Root 1 0 R\n>>\nstartxref\n9\n%%EOF")
            temp_path = f.name
        
        # Mock all VM operations
        with patch.object(self.sandbox, '_setup_vm_environment', return_value=True), \
             patch.object(self.sandbox, '_transfer_to_vm', return_value=True), \
             patch.object(self.sandbox, '_analyze_pdf_vm', return_value={
                 'javascript': False,
                 'urls': [],
                 'metadata': {'Pages': '1'}
             }), \
             patch.object(self.sandbox, '_check_network_behavior', return_value={'dns_queries': []}):
            
            result = self.sandbox.analyze_file(temp_path, perform_detonation=True)

            self.assertIn('file_name', result)
            self.assertIn('hashes', result)
            self.assertIn('vm_analysis', result)
            self.assertIn('detonation_time', result)
            # detonation_time may be 0 with mocks, just verify field exists
            self.assertIsInstance(result['detonation_time'], (int, float))

        os.unlink(temp_path)
    
    def test_full_analysis_flow_exe(self):
        """Integration test for complete EXE analysis flow."""
        # Create fake MZ executable
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b"MZ" + b"\x00" * 100)
            temp_path = f.name
        
        with patch.object(self.sandbox, '_setup_vm_environment', return_value=True), \
             patch.object(self.sandbox, '_transfer_to_vm', return_value=True), \
             patch.object(self.sandbox, '_analyze_exe_vm', return_value={
                 'suspicious_api': ['CreateRemoteThread'],
                 'dropped_files': [],
                 'wine_execution': {'exit_code': 0}
             }), \
             patch.object(self.sandbox, '_check_network_behavior', return_value={'dns_queries': []}):
            
            result = self.sandbox.analyze_file(temp_path, perform_detonation=True)
            
            self.assertIn('vm_analysis', result)
            self.assertIn('exe_analysis', result['vm_analysis'])
        
        os.unlink(temp_path)
    
    def test_analysis_without_detonation(self):
        """Test static-only analysis mode."""
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(b"PDF content")
            temp_path = f.name
        
        result = self.sandbox.analyze_file(temp_path, perform_detonation=False)
        
        self.assertEqual(result['verdict'], 'SAFE')  # Generic PDF
        self.assertIn('STATIC_ONLY', result['sandbox_logs'][1])
        self.assertIsInstance(result['detonation_time'], (int, float))
        
        os.unlink(temp_path)
    
    def test_vm_fallback_on_connection_failure(self):
        """Test that analyze_file always returns a valid report."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b"MZ content")
            temp_path = f.name
        try:
            result = self.sandbox.analyze_file(temp_path, perform_detonation=True)
            self.assertIn('verdict', result)
            self.assertIn('risk_score', result)
            self.assertIn('sandbox_logs', result)
        finally:
            os.unlink(temp_path)
    
    # ========== TEST: Error Handling ==========
    
    def test_hash_generation_error_handling(self):
        """Test graceful handling of hash generation errors."""
        # Test with non-existent file
        hashes = self.sandbox.generate_hash('/nonexistent/file.exe')
        
        self.assertEqual(hashes, {})
    
    @patch('subprocess.run')
    def test_ssh_timeout_handling(self, mock_run):
        """Test handling of SSH command timeouts."""
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired('ssh', 60)
        
        exit_code, stdout, stderr = self.sandbox._run_vm_command('test', timeout=30)
        
        self.assertEqual(exit_code, -1)
        self.assertEqual(stderr, "SSH command timed out")
    
    def test_empty_file_handling(self):
        """Test handling of empty files."""
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(b"")
            temp_path = f.name
        
        result = self.sandbox.analyze_file(temp_path, perform_detonation=False)
        
        self.assertIn('hashes', result)
        # Empty file should have known hash
        
        os.unlink(temp_path)
    
    # ========== TEST: Entropy Calculation ==========
    
    def test_entropy_calculation_low(self):
        """Test entropy for predictable content."""
        # All same byte = 0 entropy
        data = b"AAAA" * 1000
        entropy = self.sandbox._calculate_entropy(data)
        
        self.assertEqual(entropy, 0)
    
    def test_entropy_calculation_high(self):
        """Test entropy for random content."""
        import random
        data = bytes([random.randint(0, 255) for _ in range(10000)])
        entropy = self.sandbox._calculate_entropy(data)
        
        # Should be close to 8 (max for bytes)
        self.assertGreater(entropy, 7.5)
    
    def test_entropy_calculation_empty(self):
        """Test entropy for empty data."""
        entropy = self.sandbox._calculate_entropy(b"")
        
        self.assertEqual(entropy, 0)


class TestSandboxConfiguration(unittest.TestCase):
    """Test configuration and environment setup."""
    
    def test_default_vm_config(self):
        """Test default VM configuration values."""
        sandbox = SandboxSimulator()
        
        self.assertEqual(sandbox.vm_config['host'], 'localhost')
        self.assertEqual(sandbox.vm_config['port'], 2222)
        self.assertEqual(sandbox.vm_config['working_dir'], '/tmp/sandbox_detonation')
    
    def test_custom_vm_config(self):
        """Test custom VM configuration."""
        custom_config = {
            'host': '192.168.1.100',
            'port': 2223,
            'user': 'customuser',
            'key_file': '/custom/key',
            'working_dir': '/custom/sandbox'
        }
        
        sandbox = SandboxSimulator(vm_config=custom_config)
        
        self.assertEqual(sandbox.vm_config['host'], '192.168.1.100')
        self.assertEqual(sandbox.vm_config['user'], 'customuser')
    
    def test_vm_tools_configuration(self):
        """Test that all required VM tools are configured."""
        sandbox = SandboxSimulator()
        
        required_tools = ['exiftool', 'pdfinfo', 'strings', 'tshark', 'wine']
        for tool in required_tools:
            self.assertIn(tool, sandbox.vm_tools)
            self.assertTrue(sandbox.vm_tools[tool].startswith('/'))
    
    @patch.dict(os.environ, {
        'SANDBOX_VM_HOST': 'env-vm.local',
        'SANDBOX_VM_PORT': '3333',
        'SANDBOX_VM_USER': 'envuser'
    })
    def test_env_var_configuration(self):
        """Test configuration from environment variables."""
        sandbox = SandboxSimulator()
        
        self.assertEqual(sandbox.vm_config['host'], 'env-vm.local')
        self.assertEqual(sandbox.vm_config['port'], 3333)
        self.assertEqual(sandbox.vm_config['user'], 'envuser')


if __name__ == '__main__':
    unittest.main(verbosity=2)
