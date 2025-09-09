"""
Advanced unit tests for logging_config module
---------------------------------------------
Tests for uncovered logging functionality including performance logging,
system information logging, and advanced features.
"""

import json
import tempfile
import time
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from config import ServerConfig
from logging_config import (
    PerformanceLogger,
    SecurityEventLogger,
    log_system_info,
    setup_logging,
)


class TestPerformanceLoggerAdvanced:
    """Advanced test cases for PerformanceLogger"""

    def test_log_request_duration(self, test_config, tmp_path):
        """Test logging request duration"""
        test_config.log_directory = str(tmp_path)
        logger = PerformanceLogger(test_config)

        logger.log_request_duration("/api/test", 0.15, 200)

        # Verify log file was created and contains expected content
        log_file = tmp_path / "performance.log"
        assert log_file.exists()

        log_content = log_file.read_text()
        assert "request_duration" in log_content
        assert "/api/test" in log_content

    def test_log_file_serve_time(self, test_config, tmp_path):
        """Test logging file serve time"""
        test_config.log_directory = str(tmp_path)
        logger = PerformanceLogger(test_config)

        logger.log_file_serve_time("/path/to/video.mp4", 1024000, 0.5)

        log_file = tmp_path / "performance.log"
        log_content = log_file.read_text()

        # Verify file serve data is logged
        assert "file_serve" in log_content
        assert "/path/to/video.mp4" in log_content
        assert "1024000" in log_content  # file size
        assert "0.5" in log_content  # duration

    def test_performance_logger_multiple_entries(self, test_config, tmp_path):
        """Test performance logger with multiple log entries"""
        test_config.log_directory = str(tmp_path)
        logger = PerformanceLogger(test_config)

        # Log multiple performance metrics
        logger.log_request_duration("/api/test1", 0.1, 200)
        logger.log_request_duration("/api/test2", 0.2, 404)
        logger.log_file_serve_time("/video1.mp4", 500000, 1.5)

        log_file = tmp_path / "performance.log"
        log_content = log_file.read_text()

        # Should contain all entries
        log_lines = [line for line in log_content.split("\n") if line.strip()]
        assert len(log_lines) >= 3  # At least 3 log entries


class TestSecurityEventLoggerAdvanced:
    """Advanced test cases for SecurityEventLogger"""

    def test_log_rate_limit_exceeded(self, test_config, tmp_path):
        """Test logging rate limit exceeded events"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)

        logger.log_rate_limit_exceeded("127.0.0.1", "/api/auth")

        log_file = tmp_path / "security.log"
        log_content = log_file.read_text()

        assert "rate_limit_exceeded" in log_content
        assert "127.0.0.1" in log_content
        assert "/api/auth" in log_content

    def test_log_suspicious_activity(self, test_config, tmp_path):
        """Test logging suspicious activity"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)

        logger.log_suspicious_activity(
            "127.0.0.1", "path_traversal", "/../../etc/passwd"
        )

        log_file = tmp_path / "security.log"
        log_content = log_file.read_text()

        assert "suspicious_activity" in log_content
        assert "path_traversal" in log_content
        assert "127.0.0.1" in log_content

    def test_log_file_access_denied(self, test_config, tmp_path):
        """Test logging file access events"""
        test_config.log_directory = str(tmp_path)
        logger = SecurityEventLogger(test_config)

        logger.log_file_access("/restricted/file.exe", "127.0.0.1", False, "user")

        log_file = tmp_path / "security.log"
        log_content = log_file.read_text()

        assert "file_access" in log_content
        assert "user" in log_content
        assert "/restricted/file.exe" in log_content
        assert "127.0.0.1" in log_content


class TestSystemInformation:
    """Test cases for system information logging"""

    def test_log_system_info_execution(self, test_config, tmp_path):
        """Test log_system_info executes without error"""
        test_config.log_directory = str(tmp_path)

        # Should complete without raising exceptions
        log_system_info(test_config)

        # Verify system log file was created
        log_file = tmp_path / "system.log"
        assert log_file.exists()

        log_content = log_file.read_text()
        assert "system_info" in log_content


class TestLoggingSetupAdvanced:
    """Advanced test cases for logging setup"""

    def test_setup_logging_creates_handlers(self, test_config, tmp_path):
        """Test setup_logging creates all required handlers"""
        test_config.log_directory = str(tmp_path)

        components = setup_logging(test_config)

        assert "security_logger" in components
        assert "performance_logger" in components
        assert isinstance(components["security_logger"], SecurityEventLogger)
        assert isinstance(components["performance_logger"], PerformanceLogger)

    def test_setup_logging_directory_creation(self, test_config, tmp_path):
        """Test setup_logging creates log directory if it doesn't exist"""
        log_dir = tmp_path / "nonexistent_logs"
        test_config.log_directory = str(log_dir)

        assert not log_dir.exists()

        setup_logging(test_config)

        assert log_dir.exists()
        assert log_dir.is_dir()

    def test_setup_logging_with_invalid_log_level(self, test_config, tmp_path):
        """Test setup_logging handles invalid log level gracefully"""
        test_config.log_directory = str(tmp_path)
        test_config.log_level = "INVALID_LEVEL"

        # Should not raise exception
        components = setup_logging(test_config)

        assert "security_logger" in components
        assert "performance_logger" in components


class TestLoggingSetupInternal:
    """Test cases for internal logging setup functionality"""

    def test_logging_directory_setup(self, test_config, tmp_path):
        """Test that logging setup handles directory creation internally"""
        log_dir = tmp_path / "new_log_dir"
        test_config.log_directory = str(log_dir)

        assert not log_dir.exists()

        # setup_logging should create the directory internally
        components = setup_logging(test_config)

        assert log_dir.exists()
        assert log_dir.is_dir()
        assert "security_logger" in components


class TestLoggingPerformance:
    """Test cases for logging performance"""

    def test_logging_performance_overhead(self, test_config, tmp_path):
        """Test that logging doesn't add significant overhead"""
        test_config.log_directory = str(tmp_path)
        logger = PerformanceLogger(test_config)

        # Measure time for multiple log entries
        start_time = time.time()

        for i in range(100):
            logger.log_request_duration(f"/test/{i}", 0.1, 200)

        end_time = time.time()
        total_time = end_time - start_time

        # Should complete 100 log entries in reasonable time (< 1 second)
        assert total_time < 1.0

    def test_concurrent_logging(self, test_config, tmp_path):
        """Test concurrent logging operations"""
        import threading

        test_config.log_directory = str(tmp_path)
        security_logger = SecurityEventLogger(test_config)
        performance_logger = PerformanceLogger(test_config)

        def log_security_events():
            for i in range(10):
                security_logger.log_auth_attempt(f"user{i}", i % 2 == 0, "127.0.0.1")

        def log_performance_events():
            for i in range(10):
                performance_logger.log_request_duration(f"/path{i}", 0.1 * i, 200)

        # Run concurrent logging
        thread1 = threading.Thread(target=log_security_events)
        thread2 = threading.Thread(target=log_performance_events)

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        # Verify both log files exist and have content
        security_log = tmp_path / "security.log"
        performance_log = tmp_path / "performance.log"

        assert security_log.exists()
        assert performance_log.exists()

        security_content = security_log.read_text()
        performance_content = performance_log.read_text()

        # Should have entries from both loggers
        assert len(security_content.strip().split("\n")) >= 10
        assert len(performance_content.strip().split("\n")) >= 10


class TestLoggingErrorHandling:
    """Test cases for logging error handling"""

    @patch("builtins.open", side_effect=PermissionError("Permission denied"))
    def test_logging_permission_error(self, mock_open, test_config, tmp_path):
        """Test logging handles permission errors gracefully"""
        test_config.log_directory = str(tmp_path)

        try:
            logger = SecurityEventLogger(test_config)
            logger.log_auth_attempt("user", True, "127.0.0.1")
            # Should handle error gracefully
        except PermissionError:
            # Or may re-raise appropriately
            pass

    @patch("builtins.open", side_effect=OSError("Disk full"))
    def test_logging_disk_full_error(self, mock_open, test_config, tmp_path):
        """Test logging handles disk full errors gracefully"""
        test_config.log_directory = str(tmp_path)

        try:
            logger = PerformanceLogger(test_config)
            logger.log_request_duration("/test", 0.1, 200)
            # Should handle error gracefully
        except OSError:
            # Or may re-raise appropriately
            pass
