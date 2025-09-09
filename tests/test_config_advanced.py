"""
Advanced unit tests for config module
-------------------------------------
Tests for uncovered configuration functionality including environment
file creation, validation edge cases, and advanced configuration options.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from config import ServerConfig, _get_default_video_directory, create_sample_env_file


class TestConfigValidationAdvanced:
    """Advanced test cases for configuration validation"""

    def test_config_with_all_environment_variables(self):
        """Test configuration with all possible environment variables set"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_HOST": "0.0.0.0",
                "VIDEO_SERVER_PORT": "8080",
                "VIDEO_SERVER_DEBUG": "true",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash_value",
                "VIDEO_SERVER_SECRET_KEY": "custom_secret_key",
                "VIDEO_SERVER_SESSION_TIMEOUT": "7200",
                "VIDEO_SERVER_MAX_UPLOAD_SIZE": "1073741824",
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": "mp4,avi,mkv,mov",
                "VIDEO_SERVER_RATE_LIMIT_PER_MINUTE": "120",
                "VIDEO_SERVER_SESSION_COOKIE_SECURE": "true",
                "VIDEO_SERVER_SESSION_COOKIE_HTTPONLY": "true",
                "VIDEO_SERVER_SESSION_COOKIE_SAMESITE": "Strict",
                "VIDEO_SERVER_LOG_LEVEL": "DEBUG",
                "VIDEO_SERVER_LOG_DIRECTORY": f"{temp_dir}/logs",
                "VIDEO_SERVER_LOG_MAX_BYTES": "52428800",
                "VIDEO_SERVER_LOG_BACKUP_COUNT": "10",
                "VIDEO_SERVER_SERVER_THREADS": "16",
                "VIDEO_SERVER_DATABASE_URL": "sqlite:///test.db",
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                # Verify all values were loaded correctly
                assert config.host == "0.0.0.0"
                assert config.port == 8080
                assert config.debug is True
                assert config.video_directory == temp_dir
                assert config.password_hash == "test_hash_value"
                assert config.secret_key == "custom_secret_key"
                assert config.session_timeout_minutes == 7200
                assert config.max_upload_size == 1073741824
                assert config.allowed_extensions == ["mp4", "avi", "mkv", "mov"]
                assert config.rate_limit_per_minute == 120
                assert config.session_cookie_secure is True
                assert config.session_cookie_httponly is True
                assert config.session_cookie_samesite == "Strict"
                assert config.log_level == "DEBUG"
                assert config.log_directory == f"{temp_dir}/logs"
                assert config.log_max_bytes == 52428800
                assert config.log_backup_count == 10
                assert config.server_threads == 16
                assert config.database_url == "sqlite:///test.db"

    def test_config_boolean_parsing_variations(self):
        """Test various boolean value parsing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            boolean_values = [
                ("true", True),
                ("True", True),
                ("TRUE", True),
                ("yes", True),
                ("1", True),
                ("false", False),
                ("False", False),
                ("FALSE", False),
                ("no", False),
                ("0", False),
                ("", False),
                ("invalid", False),
            ]

            for str_value, expected in boolean_values:
                env_vars = {
                    "VIDEO_SERVER_DEBUG": str_value,
                    "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                }

                with patch.dict(os.environ, env_vars):
                    config = ServerConfig()
                    assert config.debug == expected, f"Failed for value: {str_value}"

    def test_config_integer_parsing_edge_cases(self):
        """Test integer parsing with edge cases"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test maximum port value
            env_vars = {
                "VIDEO_SERVER_PORT": "65535",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()
                assert config.port == 65535

            # Test minimum port value
            env_vars["VIDEO_SERVER_PORT"] = "1"
            with patch.dict(os.environ, env_vars):
                config = ServerConfig()
                assert config.port == 1

    def test_config_list_parsing(self):
        """Test parsing of comma-separated list values"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": "mp4, avi , mkv,mov,  webm  ",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                # Should parse and clean whitespace
                assert config.allowed_extensions == ["mp4", "avi", "mkv", "mov", "webm"]

    def test_config_empty_list_parsing(self):
        """Test parsing of empty list values"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": "",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                # Empty string should result in empty list
                assert config.allowed_extensions == []


class TestConfigSecurityFeatures:
    """Test cases for configuration security features"""

    def test_config_excludes_sensitive_data_from_dict(self):
        """Test that sensitive data is excluded from config dict representation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_PASSWORD_HASH": "super_secret_hash",
                "VIDEO_SERVER_SECRET_KEY": "super_secret_key",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()
                config_dict = config.to_dict()

                # Sensitive fields should be excluded
                assert "password_hash" not in config_dict
                assert "secret_key" not in config_dict

                # Non-sensitive fields should be present
                assert "host" in config_dict
                assert "port" in config_dict
                assert "debug" in config_dict

    def test_config_excludes_sensitive_data_from_string(self):
        """Test that sensitive data is excluded from string representation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_PASSWORD_HASH": "super_secret_hash",
                "VIDEO_SERVER_SECRET_KEY": "super_secret_key",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()
                config_str = str(config)

                # Sensitive values should not appear in string
                assert "super_secret_hash" not in config_str
                assert "super_secret_key" not in config_str

                # Should still show field names but not values
                assert "password_hash" in config_str
                assert "secret_key" in config_str


class TestCreateSampleEnvFile:
    """Test cases for create_sample_env_file function"""

    def test_create_sample_env_file_creates_file(self, tmp_path):
        """Test that create_sample_env_file creates .env file"""
        env_file = tmp_path / ".env"

        with patch("config.Path.cwd", return_value=tmp_path):
            create_sample_env_file()

        assert env_file.exists()

    def test_create_sample_env_file_content(self, tmp_path):
        """Test content of created .env file"""
        env_file = tmp_path / ".env"

        with patch("config.Path.cwd", return_value=tmp_path):
            create_sample_env_file()

        content = env_file.read_text()

        # Should contain all configuration variables
        expected_vars = [
            "VIDEO_SERVER_HOST",
            "VIDEO_SERVER_PORT",
            "VIDEO_SERVER_DEBUG",
            "VIDEO_SERVER_DIRECTORY",
            "VIDEO_SERVER_PASSWORD_HASH",
            "VIDEO_SERVER_SECRET_KEY",
            "VIDEO_SERVER_SESSION_TIMEOUT",
            "VIDEO_SERVER_MAX_UPLOAD_SIZE",
            "VIDEO_SERVER_ALLOWED_EXTENSIONS",
            "VIDEO_SERVER_RATE_LIMIT_PER_MINUTE",
        ]

        for var in expected_vars:
            assert var in content

        # Should contain comments/documentation
        assert "#" in content  # Comments should be present

    def test_create_sample_env_file_overwrites_existing(self, tmp_path):
        """Test that create_sample_env_file overwrites existing .env file"""
        env_file = tmp_path / ".env"
        env_file.write_text("OLD_CONTENT=value")

        with patch("config.Path.cwd", return_value=tmp_path):
            create_sample_env_file()

        content = env_file.read_text()
        assert "OLD_CONTENT" not in content
        assert "VIDEO_SERVER_HOST" in content


class TestDefaultVideoDirectory:
    """Test cases for _get_default_video_directory function"""

    def test_get_default_video_directory_success(self):
        """Test _get_default_video_directory when Path.home() succeeds"""
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path("/home/user")

            result = _get_default_video_directory()

            assert result == "/home/user/Videos"

    def test_get_default_video_directory_runtime_error(self):
        """Test _get_default_video_directory when Path.home() raises RuntimeError"""
        with patch(
            "pathlib.Path.home", side_effect=RuntimeError("Cannot determine home")
        ):
            result = _get_default_video_directory()

            assert result == "./videos"

    def test_get_default_video_directory_other_exception(self):
        """Test _get_default_video_directory when Path.home() raises other exception"""
        with patch("pathlib.Path.home", side_effect=OSError("Permission denied")):
            result = _get_default_video_directory()

            assert result == "./videos"


class TestConfigDatabaseUrl:
    """Test cases for database URL configuration"""

    def test_config_database_url_sqlite(self):
        """Test configuration with SQLite database URL"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_DATABASE_URL": "sqlite:///app.db",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.database_url == "sqlite:///app.db"

    def test_config_database_url_postgresql(self):
        """Test configuration with PostgreSQL database URL"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_DATABASE_URL": "postgresql://user:pass@localhost/dbname",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.database_url == "postgresql://user:pass@localhost/dbname"

    def test_config_database_url_none(self):
        """Test configuration with no database URL (default None)"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.database_url is None


class TestConfigLogConfiguration:
    """Test cases for logging-related configuration"""

    def test_config_log_directory_creation(self):
        """Test that log directory path is properly configured"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = f"{temp_dir}/custom_logs"
            env_vars = {
                "VIDEO_SERVER_LOG_DIRECTORY": log_dir,
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.log_directory == log_dir

    def test_config_log_rotation_settings(self):
        """Test log rotation configuration settings"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_LOG_MAX_BYTES": "104857600",  # 100MB
                "VIDEO_SERVER_LOG_BACKUP_COUNT": "5",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.log_max_bytes == 104857600
                assert config.log_backup_count == 5


class TestConfigSessionSettings:
    """Test cases for session-related configuration"""

    def test_config_session_cookie_settings(self):
        """Test session cookie configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_SESSION_COOKIE_SECURE": "true",
                "VIDEO_SERVER_SESSION_COOKIE_HTTPONLY": "false",
                "VIDEO_SERVER_SESSION_COOKIE_SAMESITE": "Lax",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.session_cookie_secure is True
                assert config.session_cookie_httponly is False
                assert config.session_cookie_samesite == "Lax"

    def test_config_session_timeout(self):
        """Test session timeout configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_SESSION_TIMEOUT": "1800",  # 30 minutes
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.session_timeout_minutes == 1800


class TestConfigPerformanceSettings:
    """Test cases for performance-related configuration"""

    def test_config_server_threads(self):
        """Test server thread configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_SERVER_THREADS": "32",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.server_threads == 32

    def test_config_max_upload_size(self):
        """Test maximum upload size configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "VIDEO_SERVER_MAX_UPLOAD_SIZE": "2147483648",  # 2GB
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": temp_dir,
            }

            with patch.dict(os.environ, env_vars):
                config = ServerConfig()

                assert config.max_upload_size == 2147483648
