"""
Unit tests for logging configuration
-----------------------------------
Tests for logging setup, security event logging, and performance logging.
"""

import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

from config import ServerConfig
from logging_config import (
    SecurityEventLogger, PerformanceLogger, setup_logging,
    get_request_logger, log_system_info
)


class TestSecurityEventLogger:
    """Test cases for SecurityEventLogger"""
    
    def test_security_logger_initialization(self, test_config):
        """Test security logger initialization"""
        logger = SecurityEventLogger(test_config)
        
        assert logger.config == test_config
        assert logger.logger.name == 'security'
        assert logger.logger.level == logging.INFO
        assert not logger.logger.propagate
    
    def test_log_auth_attempt_success(self, test_config, tmp_path):
        """Test logging successful authentication attempt"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)
        
        logger.log_auth_attempt('testuser', True, '127.0.0.1', 'Test Browser')
        
        # Check that log file was created and contains expected data
        security_log = tmp_path / 'security.log'
        assert security_log.exists()
        
        log_content = security_log.read_text()
        log_data = json.loads(log_content.strip())
        
        assert log_data['event_type'] == 'authentication'
        assert log_data['username'] == 'testuser'
        assert log_data['success'] is True
        assert log_data['ip_address'] == '127.0.0.1'
        assert log_data['user_agent'] == 'Test Browser'
    
    def test_log_auth_attempt_failure(self, test_config, tmp_path):
        """Test logging failed authentication attempt"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)
        
        logger.log_auth_attempt('baduser', False, '192.168.1.100', 'Evil Browser')
        
        security_log = tmp_path / 'security.log'
        log_content = security_log.read_text()
        log_data = json.loads(log_content.strip())
        
        assert log_data['success'] is False
        assert log_data['username'] == 'baduser'
    
    def test_log_file_access(self, test_config, tmp_path):
        """Test logging file access attempts"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)
        
        logger.log_file_access('/test/video.mp4', '127.0.0.1', True, 'testuser')
        
        security_log = tmp_path / 'security.log'
        log_content = security_log.read_text()
        log_data = json.loads(log_content.strip())
        
        assert log_data['event_type'] == 'file_access'
        assert log_data['file_path'] == '/test/video.mp4'
        assert log_data['success'] is True
        assert log_data['user'] == 'testuser'
    
    def test_log_security_violation(self, test_config, tmp_path):
        """Test logging security violations"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)
        
        logger.log_security_violation('path_traversal', 'Attempted ../../../etc/passwd', '10.0.0.1')
        
        security_log = tmp_path / 'security.log'
        log_content = security_log.read_text()
        log_data = json.loads(log_content.strip())
        
        assert log_data['event_type'] == 'security_violation'
        assert log_data['violation_type'] == 'path_traversal'
        assert log_data['details'] == 'Attempted ../../../etc/passwd'
        assert log_data['ip_address'] == '10.0.0.1'
    
    def test_log_rate_limit_exceeded(self, test_config, tmp_path):
        """Test logging rate limit violations"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)
        
        logger.log_rate_limit_exceeded('192.168.1.50', '/stream/video.mp4')
        
        security_log = tmp_path / 'security.log'
        log_content = security_log.read_text()
        log_data = json.loads(log_content.strip())
        
        assert log_data['event_type'] == 'rate_limit_exceeded'
        assert log_data['ip_address'] == '192.168.1.50'
        assert log_data['endpoint'] == '/stream/video.mp4'


class TestPerformanceLogger:
    """Test cases for PerformanceLogger"""
    
    def test_performance_logger_initialization(self, test_config):
        """Test performance logger initialization"""
        logger = PerformanceLogger(test_config)
        
        assert logger.config == test_config
        assert logger.logger.name == 'performance'
        assert logger.logger.level == logging.INFO
        assert not logger.logger.propagate
    
    def test_log_request_duration(self, test_config, tmp_path):
        """Test logging request duration metrics"""
        test_config.log_directory = str(tmp_path)
        logger = PerformanceLogger(test_config)
        
        logger.log_request_duration('/stream/video.mp4', 0.250, 200)
        
        perf_log = tmp_path / 'performance.log'
        assert perf_log.exists()
        
        log_content = perf_log.read_text()
        log_data = json.loads(log_content.strip())
        
        assert log_data['type'] == 'request_duration'
        assert log_data['endpoint'] == '/stream/video.mp4'
        assert log_data['duration_ms'] == 250.0
        assert log_data['status_code'] == 200
    
    def test_log_file_serve_time(self, test_config, tmp_path):
        """Test logging file serving performance"""
        test_config.log_directory = str(tmp_path)
        logger = PerformanceLogger(test_config)
        
        # 10MB file served in 2 seconds = 5 MB/s
        logger.log_file_serve_time('/test/video.mp4', 10485760, 2.0)
        
        perf_log = tmp_path / 'performance.log'
        log_content = perf_log.read_text()
        log_data = json.loads(log_content.strip())
        
        assert log_data['type'] == 'file_serve'
        assert log_data['file_path'] == '/test/video.mp4'
        assert log_data['file_size_bytes'] == 10485760
        assert log_data['duration_ms'] == 2000.0
        assert log_data['throughput_mbps'] == 5.0
    
    def test_zero_duration_throughput(self, test_config, tmp_path):
        """Test throughput calculation with zero duration"""
        test_config.log_directory = str(tmp_path)
        logger = PerformanceLogger(test_config)
        
        logger.log_file_serve_time('/test/video.mp4', 1024, 0.0)
        
        perf_log = tmp_path / 'performance.log'
        log_content = perf_log.read_text()
        log_data = json.loads(log_content.strip())
        
        assert log_data['throughput_mbps'] == 0


class TestLoggingSetup:
    """Test cases for logging setup function"""
    
    def test_setup_logging_creates_loggers(self, test_config, tmp_path):
        """Test that setup_logging creates all required loggers"""
        test_config.log_directory = str(tmp_path)
        
        components = setup_logging(test_config)
        
        assert 'root_logger' in components
        assert 'security_logger' in components
        assert 'performance_logger' in components
        assert 'console_handler' in components
        assert 'file_handler' in components
        assert 'error_handler' in components
        
        # Check that log files are created
        assert (tmp_path / 'app.log').exists()
        assert (tmp_path / 'error.log').exists()
        assert (tmp_path / 'security.log').exists()
        assert (tmp_path / 'performance.log').exists()
    
    def test_setup_logging_log_levels(self, test_config, tmp_path):
        """Test logging levels are set correctly"""
        test_config.log_directory = str(tmp_path)
        test_config.log_level = 'DEBUG'
        
        components = setup_logging(test_config)
        root_logger = components['root_logger']
        
        assert root_logger.level == logging.DEBUG
        
        # Error handler should only log errors and above
        error_handler = components['error_handler']
        assert error_handler.level == logging.ERROR
    
    def test_setup_logging_production_mode(self, test_config, tmp_path):
        """Test logging setup in production mode"""
        test_config.log_directory = str(tmp_path)
        
        with patch.object(test_config, 'is_production', return_value=True):
            components = setup_logging(test_config)
            
            flask_logger = logging.getLogger('werkzeug')
            assert flask_logger.level == logging.WARNING
    
    def test_setup_logging_development_mode(self, test_config, tmp_path):
        """Test logging setup in development mode"""
        test_config.log_directory = str(tmp_path)
        
        with patch.object(test_config, 'is_production', return_value=False):
            components = setup_logging(test_config)
            
            flask_logger = logging.getLogger('werkzeug')
            assert flask_logger.level == logging.INFO
    
    @patch('logging_config.structlog')
    def test_structlog_configuration(self, mock_structlog, test_config, tmp_path):
        """Test structlog configuration"""
        test_config.log_directory = str(tmp_path)
        
        setup_logging(test_config)
        
        mock_structlog.configure.assert_called_once()
        call_args = mock_structlog.configure.call_args
        
        assert 'processors' in call_args.kwargs
        assert 'logger_factory' in call_args.kwargs
        assert 'cache_logger_on_first_use' in call_args.kwargs
        assert call_args.kwargs['cache_logger_on_first_use'] is True


class TestUtilityFunctions:
    """Test cases for utility functions"""
    
    def test_get_request_logger(self):
        """Test get_request_logger function"""
        logger = get_request_logger('test_handler')
        
        assert logger.name == 'request.test_handler'
        assert isinstance(logger, logging.Logger)
    
    @patch('logging_config.platform')
    @patch('logging_config.psutil')
    def test_log_system_info(self, mock_psutil, mock_platform, test_config, tmp_path):
        """Test system information logging"""
        test_config.log_directory = str(tmp_path)
        
        # Mock system information
        mock_platform.platform.return_value = 'Test Platform'
        mock_platform.python_version.return_value = '3.9.0'
        mock_psutil.cpu_count.return_value = 8
        mock_psutil.virtual_memory.return_value.total = 16 * 1024**3  # 16GB
        mock_psutil.disk_usage.return_value.free = 500 * 1024**3  # 500GB
        
        setup_logging(test_config)  # Initialize logging first
        log_system_info(test_config)
        
        # Verify that system logger was called
        mock_platform.platform.assert_called_once()
        mock_psutil.cpu_count.assert_called_once()


class TestLoggingRotation:
    """Test cases for log file rotation"""
    
    def test_log_rotation_configuration(self, test_config, tmp_path):
        """Test log rotation configuration"""
        test_config.log_directory = str(tmp_path)
        test_config.log_max_bytes = 1024
        test_config.log_backup_count = 3
        
        components = setup_logging(test_config)
        file_handler = components['file_handler']
        
        assert hasattr(file_handler, 'maxBytes')
        assert file_handler.maxBytes == 1024
        assert hasattr(file_handler, 'backupCount')
        assert file_handler.backupCount == 3
    
    def test_security_log_rotation(self, test_config, tmp_path):
        """Test security log rotation"""
        test_config.log_directory = str(tmp_path)
        test_config.log_max_bytes = 100  # Very small for testing
        
        logger = SecurityEventLogger(test_config)
        
        # Generate enough log entries to trigger rotation
        for i in range(50):
            logger.log_auth_attempt(f'user{i}', True, '127.0.0.1', 'Test Browser')
        
        # Check that log files exist (rotation might create backup files)
        log_files = list(tmp_path.glob('security.log*'))
        assert len(log_files) >= 1


@pytest.mark.timeout(5)
class TestLoggingPerformance:
    """Performance tests for logging system"""
    
    def test_logging_performance(self, test_config, tmp_path):
        """Test logging performance under load"""
        import time
        
        test_config.log_directory = str(tmp_path)
        components = setup_logging(test_config)
        logger = components['security_logger']
        
        start_time = time.time()
        
        # Log 1000 events
        for i in range(1000):
            logger.log_auth_attempt(f'user{i}', i % 2 == 0, '127.0.0.1', 'Test Browser')
        
        end_time = time.time()
        
        # Should complete in reasonable time
        assert end_time - start_time < 2.0
    
    def test_concurrent_logging(self, test_config, tmp_path):
        """Test concurrent logging safety"""
        import threading
        import time
        
        test_config.log_directory = str(tmp_path)
        components = setup_logging(test_config)
        security_logger = components['security_logger']
        perf_logger = components['performance_logger']
        
        def log_security_events():
            for i in range(100):
                security_logger.log_auth_attempt(f'user{i}', True, '127.0.0.1')
                time.sleep(0.001)
        
        def log_performance_events():
            for i in range(100):
                perf_logger.log_request_duration(f'/endpoint{i}', 0.1, 200)
                time.sleep(0.001)
        
        # Start multiple threads
        threads = [
            threading.Thread(target=log_security_events),
            threading.Thread(target=log_performance_events),
            threading.Thread(target=log_security_events),
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join(timeout=5.0)  # 5 second timeout
        
        # Verify log files were created and contain data
        security_log = tmp_path / 'security.log'
        performance_log = tmp_path / 'performance.log'
        
        assert security_log.exists()
        assert performance_log.exists()
        assert security_log.stat().st_size > 0
        assert performance_log.stat().st_size > 0


class TestLoggingErrorHandling:
    """Test error handling in logging system"""
    
    def test_logging_with_permission_error(self, test_config):
        """Test logging behavior when log directory is not writable"""
        test_config.log_directory = '/root/logs'  # Typically not writable
        
        # Should not raise exception, but might not create files
        try:
            setup_logging(test_config)
        except PermissionError:
            pytest.skip("Permission error expected in restricted environment")
    
    def test_invalid_log_level(self, test_config, tmp_path):
        """Test handling of invalid log levels"""
        test_config.log_directory = str(tmp_path)
        test_config.log_level = 'INVALID_LEVEL'
        
        # Should default to INFO level without raising exception
        components = setup_logging(test_config)
        root_logger = components['root_logger']
        
        # Should fall back to INFO level
        assert root_logger.level in [logging.INFO, logging.NOTSET]
    
    def test_logging_with_special_characters(self, test_config, tmp_path):
        """Test logging with special characters and unicode"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)
        
        # Test with unicode characters
        logger.log_auth_attempt('用户', True, '127.0.0.1', 'Browser with 特殊字符')
        
        # Test with special characters that might break JSON
        logger.log_security_violation('xss', '<script>alert("test")</script>', '127.0.0.1')
        
        # Verify log file was created and is readable
        security_log = tmp_path / 'security.log'
        assert security_log.exists()
        
        # Should be valid JSON
        log_content = security_log.read_text(encoding='utf-8')
        lines = log_content.strip().split('\n')
        for line in lines:
            if line:
                json.loads(line)  # Should not raise exception
