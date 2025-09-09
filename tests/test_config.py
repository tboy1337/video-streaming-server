"""
Unit tests for configuration management
--------------------------------------
Tests for ServerConfig class and environment variable handling.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from config import ServerConfig, create_sample_env_file, load_config


class TestServerConfig:
    """Test cases for ServerConfig class"""

    def test_default_values(self):
        """Test default configuration values"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            config = ServerConfig()

        assert config.host == "0.0.0.0"
        assert config.port == 5000
        assert config.debug is False
        assert config.threads == 6
        assert config.username == "tboy1337"
        assert config.session_timeout == 3600
        assert ".mp4" in config.allowed_extensions
        assert config.rate_limit_enabled is True
        assert config.rate_limit_per_minute == 60

    def test_environment_variable_override(self):
        """Test environment variable overrides"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_HOST": "192.168.1.100",
                "VIDEO_SERVER_PORT": "8080",
                "VIDEO_SERVER_DEBUG": "true",
                "VIDEO_SERVER_THREADS": "12",
                "VIDEO_SERVER_USERNAME": "customuser",
                "VIDEO_SERVER_SESSION_TIMEOUT": "7200",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            config = ServerConfig()

            assert config.host == "192.168.1.100"
            assert config.port == 8080
            assert config.debug is True
            assert config.threads == 12
            assert config.username == "customuser"
            assert config.session_timeout == 7200

    def test_invalid_port_validation(self):
        """Test port validation"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PORT": "99999",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
                ServerConfig()

    def test_invalid_thread_count(self):
        """Test thread count validation"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_THREADS": "0",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            with pytest.raises(ValueError, match="Thread count must be at least 1"):
                ServerConfig()

    def test_missing_password_hash(self):
        """Test missing password hash validation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ, {"VIDEO_SERVER_DIRECTORY": temp_dir}, clear=True
            ):
                with pytest.raises(ValueError, match="PASSWORD_HASH must be set"):
                    ServerConfig()

    def test_invalid_video_directory(self):
        """Test invalid video directory validation"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_DIRECTORY": "/nonexistent/directory",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
            },
        ):
            with pytest.raises(ValueError, match="Video directory does not exist"):
                ServerConfig()

    def test_log_directory_creation(self):
        """Test log directory creation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"

            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_LOG_DIR": str(log_dir),
                    "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                    "VIDEO_SERVER_DIRECTORY": str(Path.home()),
                },
            ):
                config = ServerConfig()
                assert log_dir.exists()
                assert log_dir.is_dir()

    def test_production_detection(self):
        """Test production environment detection"""
        with patch.dict(os.environ, {"FLASK_ENV": "production"}):
            config = ServerConfig(
                password_hash="test_hash", video_directory=str(Path.home())
            )
            assert config.is_production() is True

        with patch.dict(os.environ, {"FLASK_ENV": "development"}):
            config = ServerConfig(
                password_hash="test_hash", video_directory=str(Path.home())
            )
            assert config.is_production() is False

    def test_to_dict_excludes_sensitive_data(self):
        """Test that to_dict excludes sensitive information"""
        config = ServerConfig(
            password_hash="secret_hash",
            secret_key="secret_key",
            video_directory=str(Path.home()),
        )

        config_dict = config.to_dict()

        assert "password_hash" not in config_dict
        assert "secret_key" not in config_dict
        assert config_dict["username"] == config.username
        assert config_dict["host"] == config.host

    def test_database_url_handling(self):
        """Test database URL configuration"""
        with patch.dict(
            os.environ, {"DATABASE_URL": "postgresql://test:test@localhost/testdb"}
        ):
            config = ServerConfig(
                password_hash="test_hash", video_directory=str(Path.home())
            )
            assert (
                config.get_database_url() == "postgresql://test:test@localhost/testdb"
            )

        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfig(
                password_hash="test_hash", video_directory=str(Path.home())
            )
            assert config.get_database_url() is None


class TestConfigLoading:
    """Test cases for configuration loading functions"""

    def test_load_config(self):
        """Test config loading function"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_HOST": "testhost",
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            config = load_config()
            assert isinstance(config, ServerConfig)
            assert config.host == "testhost"

    def test_create_sample_env_file(self, tmp_path):
        """Test sample .env file creation"""
        with patch("config.Path") as mock_path:
            mock_env_file = tmp_path / ".env.example"
            mock_path.return_value = mock_env_file

            create_sample_env_file()

            assert mock_env_file.exists()
            content = mock_env_file.read_text()
            assert "VIDEO_SERVER_HOST" in content
            assert "VIDEO_SERVER_PASSWORD_HASH" in content
            assert "tboy1337" in content

    @patch("config.load_dotenv")
    def test_dotenv_loading(self, mock_load_dotenv, tmp_path):
        """Test .env file loading"""
        # Create a test .env file
        env_file = tmp_path / ".env"
        env_file.write_text("VIDEO_SERVER_HOST=dotenv_host\n")

        with patch("config.Path") as mock_path:
            mock_path.return_value = env_file
            mock_path.return_value.exists.return_value = True

            load_config()
            mock_load_dotenv.assert_called_once_with(env_file)

    def test_missing_dotenv_graceful_failure(self):
        """Test graceful handling when dotenv is not available"""
        with patch("config.load_dotenv", side_effect=ImportError):
            # Should not raise exception
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                    "VIDEO_SERVER_DIRECTORY": str(Path.home()),
                },
            ):
                config = load_config()
                assert isinstance(config, ServerConfig)


class TestSecurityHeaders:
    """Test cases for security headers configuration"""

    def test_default_security_headers(self):
        """Test default security headers"""
        config = ServerConfig(
            password_hash="test_hash", video_directory=str(Path.home())
        )

        headers = config.security_headers

        assert "X-Content-Type-Options" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in headers
        assert headers["X-Frame-Options"] == "SAMEORIGIN"
        assert "Strict-Transport-Security" in headers
        assert "Content-Security-Policy" in headers
        assert "Referrer-Policy" in headers

    def test_content_security_policy(self):
        """Test Content Security Policy configuration"""
        config = ServerConfig(
            password_hash="test_hash", video_directory=str(Path.home())
        )

        csp = config.security_headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "media-src 'self'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp


@pytest.mark.timeout(10)
class TestConfigPerformance:
    """Performance tests for configuration loading"""

    def test_config_loading_performance(self):
        """Test that config loading is fast"""
        import time

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            start_time = time.time()
            for _ in range(100):
                ServerConfig()
            end_time = time.time()

            # Should complete 100 config loads in under 1 second
            assert end_time - start_time < 1.0

    def test_config_validation_performance(self):
        """Test configuration validation performance"""
        import time

        config = ServerConfig(
            password_hash="test_hash", video_directory=str(Path.home())
        )

        start_time = time.time()
        for _ in range(1000):
            config.validate_config()
        end_time = time.time()

        # Validation should be very fast
        assert end_time - start_time < 0.5
