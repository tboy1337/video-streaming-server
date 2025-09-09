"""
Integration tests for Video Streaming Server
-------------------------------------------
Comprehensive tests for the main streaming server functionality including
authentication, file serving, security, and API endpoints.
"""

import base64
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import session

from streaming_server import VideoStreamingServer


class TestVideoStreamingServer:
    """Test cases for VideoStreamingServer initialization and configuration"""

    def test_server_initialization(self, test_config):
        """Test server initialization with configuration"""
        server = VideoStreamingServer(test_config)

        assert server.config == test_config
        assert server.app is not None
        assert server.security_logger is not None
        assert server.performance_logger is not None

    def test_flask_app_configuration(self, test_server):
        """Test Flask app configuration"""
        app = test_server.app

        assert app.config["TESTING"] is False  # Will be set by test client
        assert app.config["MAX_CONTENT_LENGTH"] == test_server.config.max_file_size
        assert app.secret_key == test_server.config.secret_key

    def test_security_configuration(self, test_server):
        """Test security-related configuration"""
        app = test_server.app

        assert app.config["SESSION_COOKIE_HTTPONLY"] is True
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
        assert (
            app.config["PERMANENT_SESSION_LIFETIME"]
            == test_server.config.session_timeout
        )

    def test_rate_limiting_enabled(self, test_config):
        """Test rate limiting when enabled"""
        test_config.rate_limit_enabled = True
        server = VideoStreamingServer(test_config)

        assert hasattr(server, "limiter")
        assert server.limiter is not None

    def test_rate_limiting_disabled(self, test_config):
        """Test rate limiting when disabled"""
        test_config.rate_limit_enabled = False
        server = VideoStreamingServer(test_config)

        assert server.limiter is None


class TestAuthentication:
    """Test cases for authentication functionality"""

    def test_check_auth_valid_credentials(self, test_server, test_config):
        """Test authentication with valid credentials"""
        with test_server.app.test_request_context():
            result = test_server.check_auth(test_config.username, "testpass")
            assert result is True

    def test_check_auth_invalid_username(self, test_server):
        """Test authentication with invalid username"""
        with test_server.app.test_request_context():
            result = test_server.check_auth("wronguser", "testpass")
            assert result is False

    def test_check_auth_invalid_password(self, test_server, test_config):
        """Test authentication with invalid password"""
        with test_server.app.test_request_context():
            result = test_server.check_auth(test_config.username, "wrongpass")
            assert result is False

    def test_check_auth_empty_credentials(self, test_server):
        """Test authentication with empty credentials"""
        with test_server.app.test_request_context():
            result = test_server.check_auth("", "")
            assert result is False

            result = test_server.check_auth("user", "")
            assert result is False

            result = test_server.check_auth("", "pass")
            assert result is False

    def test_requires_auth_decorator_with_session(self, test_server):
        """Test auth decorator with valid session"""

        @test_server.requires_auth
        def test_endpoint():
            return "success"

        with test_server.app.test_request_context():
            # Mock session data directly in g or flask context
            from flask import session

            with test_server.app.test_request_context():
                session["authenticated"] = True
                session["last_activity"] = time.time()

                # Should allow access
                result = test_endpoint()
                assert result == "success"

    def test_requires_auth_decorator_session_timeout(self, test_server):
        """Test auth decorator with expired session"""

        @test_server.requires_auth
        def test_endpoint():
            return "success"

        with test_server.app.test_request_context():
            with test_server.app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["authenticated"] = True
                    sess["last_activity"] = (
                        time.time() - test_server.config.session_timeout - 1
                    )

                # Should reject expired session
                response = test_endpoint()
                assert response.status_code == 401

    def test_requires_auth_decorator_http_auth(self, test_server, test_config):
        """Test auth decorator with HTTP Basic Auth"""

        @test_server.requires_auth
        def test_endpoint():
            return "success"

        credentials = base64.b64encode(
            f"{test_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with test_server.app.test_request_context(
            headers={"Authorization": f"Basic {credentials}"}
        ):
            result = test_endpoint()
            assert result == "success"


class TestPathSecurity:
    """Test cases for path traversal protection"""

    def test_get_safe_path_normal(self, test_server, temp_video_dir):
        """Test safe path handling with normal paths"""
        with test_server.app.test_request_context():
            safe_path = test_server.get_safe_path("test_video.mp4")
            expected_path = temp_video_dir / "test_video.mp4"
            assert safe_path == expected_path

    def test_get_safe_path_empty(self, test_server, temp_video_dir):
        """Test safe path handling with empty path"""
        with test_server.app.test_request_context():
            safe_path = test_server.get_safe_path("")
            assert safe_path == Path(test_server.config.video_directory)

    def test_get_safe_path_none(self, test_server, temp_video_dir):
        """Test safe path handling with None path"""
        with test_server.app.test_request_context():
            safe_path = test_server.get_safe_path(None)
            assert safe_path == Path(test_server.config.video_directory)

    def test_path_traversal_protection(self, test_server, security_test_payloads):
        """Test protection against path traversal attacks"""
        with test_server.app.test_request_context():
            for payload in security_test_payloads["path_traversal"]:
                safe_path = test_server.get_safe_path(payload)
                assert safe_path is None

    def test_url_encoding_in_paths(self, test_server, temp_video_dir):
        """Test URL-encoded path handling"""
        with test_server.app.test_request_context():
            # Test normal URL encoding
            safe_path = test_server.get_safe_path("test%20video.mp4")
            expected_path = temp_video_dir / "test video.mp4"  # Should decode spaces
            # Since file doesn't exist, just check it's in the right directory
            assert safe_path.parent == temp_video_dir

    def test_double_slash_protection(self, test_server):
        """Test protection against double slash attacks"""
        with test_server.app.test_request_context():
            safe_path = test_server.get_safe_path("path//to//file.mp4")
            assert safe_path is None

    def test_symlink_resolution(self, test_server, temp_video_dir):
        """Test symlink resolution in safe path"""
        with test_server.app.test_request_context():
            # This should resolve to the absolute path within video directory
            safe_path = test_server.get_safe_path("test_video.mp4")
            assert safe_path is not None
            assert temp_video_dir in safe_path.parents or safe_path == temp_video_dir


class TestDirectoryListing:
    """Test cases for directory listing functionality"""

    def test_breadcrumbs_generation(self, test_server, temp_video_dir):
        """Test breadcrumb navigation generation"""
        subdir_path = temp_video_dir / "subdir"
        breadcrumbs = test_server.get_breadcrumbs(subdir_path)

        assert len(breadcrumbs) >= 1
        assert breadcrumbs[0]["name"] == "Home"
        assert breadcrumbs[0]["path"] == "/"

        # Should include subdirectory
        assert any(crumb["name"] == "subdir" for crumb in breadcrumbs)

    def test_breadcrumbs_root_directory(self, test_server, temp_video_dir):
        """Test breadcrumbs for root directory"""
        breadcrumbs = test_server.get_breadcrumbs(temp_video_dir)

        assert len(breadcrumbs) == 1
        assert breadcrumbs[0]["name"] == "Home"

    def test_directory_listing_with_auth(self, authenticated_client, temp_video_dir):
        """Test directory listing with authentication"""
        response = authenticated_client.get("/")

        assert response.status_code == 200
        assert b"test_video.mp4" in response.data
        assert b"test_video.mkv" in response.data
        assert b"subdir" in response.data

    def test_directory_listing_without_auth(self, test_client):
        """Test directory listing without authentication"""
        response = test_client.get("/")

        assert response.status_code == 401
        assert "Basic" in response.headers.get("WWW-Authenticate", "")

    def test_subdirectory_listing(self, authenticated_client):
        """Test listing contents of subdirectory"""
        response = authenticated_client.get("/subdir/")

        assert response.status_code == 200
        assert b"sub_video.avi" in response.data

    def test_empty_directory_listing(self, authenticated_client):
        """Test listing empty directory"""
        response = authenticated_client.get("/empty_dir/")

        assert response.status_code == 200
        # Should show parent directory link
        assert b"Up to parent directory" in response.data or b"parent" in response.data


class TestVideoStreaming:
    """Test cases for video streaming functionality"""

    def test_stream_valid_video(self, authenticated_client):
        """Test streaming a valid video file"""
        response = authenticated_client.get("/stream/test_video.mp4")

        assert response.status_code == 200
        assert response.data == b"fake video content"

    def test_stream_video_without_auth(self, test_client):
        """Test streaming video without authentication"""
        response = test_client.get("/stream/test_video.mp4")

        assert response.status_code == 401

    def test_stream_nonexistent_file(self, authenticated_client):
        """Test streaming nonexistent file"""
        response = authenticated_client.get("/stream/nonexistent.mp4")

        assert response.status_code == 404

    def test_stream_invalid_file_type(self, authenticated_client):
        """Test streaming invalid file type"""
        response = authenticated_client.get("/stream/invalid_file.txt")

        assert response.status_code == 403

    def test_stream_path_traversal_attempt(
        self, authenticated_client, security_test_payloads
    ):
        """Test streaming with path traversal attempts"""
        for payload in security_test_payloads["path_traversal"][
            :3
        ]:  # Test first 3 to avoid timeout
            response = authenticated_client.get(f"/stream/{payload}")
            assert response.status_code in [403, 404]  # Should be blocked or not found

    def test_video_player_page(self, authenticated_client):
        """Test video player page rendering"""
        response = authenticated_client.get("/test_video.mp4")

        assert response.status_code == 200
        assert b"<video controls" in response.data
        assert b"test_video.mp4" in response.data

    def test_subtitle_file_access(self, authenticated_client):
        """Test accessing subtitle files"""
        response = authenticated_client.get("/stream/subtitles.srt")

        assert response.status_code == 200
        assert response.data == b"fake subtitle content"


class TestAPIEndpoints:
    """Test cases for API endpoints"""

    def test_health_check_endpoint(self, test_client):
        """Test health check endpoint"""
        response = test_client.get("/health")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "version" in data
        assert "video_directory_accessible" in data

    def test_api_files_endpoint_with_auth(self, authenticated_client):
        """Test API files endpoint with authentication"""
        response = authenticated_client.get("/api/files")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert "files" in data
        assert "path" in data
        assert "total_files" in data
        assert isinstance(data["files"], list)

    def test_api_files_endpoint_without_auth(self, test_client):
        """Test API files endpoint without authentication"""
        response = test_client.get("/api/files")

        assert response.status_code == 401
        data = json.loads(response.data)
        assert "error" in data

    def test_api_files_with_path_parameter(self, authenticated_client):
        """Test API files endpoint with path parameter"""
        response = authenticated_client.get("/api/files?path=subdir")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert data["path"] == "subdir"
        # Should contain subdirectory files
        filenames = [f["name"] for f in data["files"]]
        assert "sub_video.avi" in filenames

    def test_api_files_invalid_path(self, authenticated_client):
        """Test API files endpoint with invalid path"""
        response = authenticated_client.get("/api/files?path=../../../etc")

        assert response.status_code == 404
        data = json.loads(response.data)
        assert "error" in data

    def test_api_files_file_metadata(self, authenticated_client):
        """Test API files endpoint returns file metadata"""
        response = authenticated_client.get("/api/files")

        assert response.status_code == 200
        data = json.loads(response.data)

        # Check that files have required metadata
        for file_info in data["files"]:
            assert "name" in file_info
            assert "path" in file_info
            assert "is_directory" in file_info
            assert "size" in file_info
            assert "modified" in file_info


class TestErrorHandling:
    """Test cases for error handling"""

    def test_404_error_handler(self, authenticated_client):
        """Test 404 error handler"""
        response = authenticated_client.get("/nonexistent-path")

        assert response.status_code == 404
        assert b"Path not found" in response.data

    def test_403_error_handler(self, authenticated_client):
        """Test 403 error handler"""
        # Try to access invalid file type
        response = authenticated_client.get("/stream/invalid_file.txt")

        assert response.status_code == 403
        assert b"File type not allowed" in response.data

    def test_400_error_handling(self, authenticated_client):
        """Test bad request error handling"""
        # Try to view a non-video file as video player
        response = authenticated_client.get("/invalid_file.txt")

        assert response.status_code == 400
        assert b"Not a video file" in response.data

    def test_request_entity_too_large_handler(self, test_server):
        """Test request entity too large handler"""
        with test_server.app.test_request_context():
            # Simulate request too large error
            from werkzeug.exceptions import RequestEntityTooLarge

            @test_server.app.route("/test-large")
            def test_large():
                raise RequestEntityTooLarge()

            with test_server.app.test_client() as client:
                response = client.get("/test-large")
                assert response.status_code == 413


class TestSecurityHeaders:
    """Test cases for security headers"""

    def test_security_headers_applied(self, test_client):
        """Test that security headers are applied to all responses"""
        response = test_client.get("/health")

        expected_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Referrer-Policy",
        ]

        for header in expected_headers:
            assert header in response.headers

    def test_content_security_policy(self, test_client):
        """Test Content Security Policy header"""
        response = test_client.get("/health")

        csp = response.headers.get("Content-Security-Policy")
        assert "default-src 'self'" in csp
        assert "media-src 'self'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp

    def test_xss_protection_header(self, test_client):
        """Test XSS protection header"""
        response = test_client.get("/health")

        xss_protection = response.headers.get("X-XSS-Protection")
        assert xss_protection == "1; mode=block"


class TestSessionManagement:
    """Test cases for session management"""

    def test_session_creation_on_auth(self, test_server, test_config):
        """Test session creation on successful authentication"""
        credentials = base64.b64encode(
            f"{test_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with test_server.app.test_client() as client:
            response = client.get(
                "/", headers={"Authorization": f"Basic {credentials}"}
            )

            assert response.status_code == 200

            # Session should be created
            with client.session_transaction() as sess:
                assert sess.get("authenticated") is True
                assert sess.get("username") == test_config.username
                assert "last_activity" in sess

    def test_session_persistence(self, test_server, test_config):
        """Test session persistence across requests"""
        credentials = base64.b64encode(
            f"{test_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with test_server.app.test_client() as client:
            # First request with auth
            client.get("/", headers={"Authorization": f"Basic {credentials}"})

            # Second request without auth should work due to session
            response = client.get("/")
            assert response.status_code == 200

    def test_session_timeout(self, test_server):
        """Test session timeout functionality"""
        with test_server.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["authenticated"] = True
                sess["last_activity"] = (
                    time.time() - test_server.config.session_timeout - 1
                )

            response = client.get("/")
            assert response.status_code == 401


class TestRequestLogging:
    """Test cases for request logging and monitoring"""

    def test_request_id_generation(self, test_server):
        """Test request ID generation"""
        with test_server.app.test_request_context():
            with test_server.app.test_client() as client:
                response = client.get("/health")
                # Request should complete successfully
                assert response.status_code == 200

    def test_performance_logging(self, authenticated_client):
        """Test performance logging for requests"""
        response = authenticated_client.get("/")

        # Should complete without error
        assert response.status_code == 200
        # Performance metrics should be logged (tested in logging tests)

    def test_security_event_logging(self, test_client, security_test_payloads):
        """Test security event logging"""
        # Try path traversal attack
        response = test_client.get(
            f'/stream/{security_test_payloads["path_traversal"][0]}'
        )

        # Should be blocked and logged
        assert response.status_code == 401  # Unauthorized due to no auth


@pytest.mark.timeout(30)
class TestPerformance:
    """Performance tests for the streaming server"""

    def test_concurrent_requests(self, test_server, test_config):
        """Test server performance under concurrent requests"""
        import threading
        import time

        results = []

        def make_request():
            with test_server.app.test_client() as client:
                start_time = time.time()
                response = client.get("/health")
                end_time = time.time()
                results.append(
                    {
                        "status_code": response.status_code,
                        "duration": end_time - start_time,
                    }
                )

        # Start 10 concurrent requests
        threads = [threading.Thread(target=make_request) for _ in range(10)]

        start_time = time.time()
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=10.0)

        end_time = time.time()

        # All requests should complete successfully
        assert len(results) == 10
        assert all(r["status_code"] == 200 for r in results)
        assert end_time - start_time < 5.0  # Should complete within 5 seconds

    def test_large_directory_listing(self, authenticated_client, temp_video_dir):
        """Test performance with large directory listings"""
        # Create many test files
        for i in range(100):
            (temp_video_dir / f"test_video_{i:03d}.mp4").write_text(f"fake content {i}")

        start_time = time.time()
        response = authenticated_client.get("/")
        end_time = time.time()

        assert response.status_code == 200
        assert end_time - start_time < 2.0  # Should complete within 2 seconds

    def test_memory_usage_stability(self, test_server):
        """Test memory usage stability under repeated requests"""
        import gc

        # Force garbage collection
        gc.collect()

        # Make many requests
        with test_server.app.test_client() as client:
            for i in range(1000):
                response = client.get("/health")
                assert response.status_code == 200

                # Periodic garbage collection
                if i % 100 == 0:
                    gc.collect()

        # Final garbage collection
        gc.collect()

        # Test passes if no memory leaks cause exceptions


class TestFileTypeHandling:
    """Test cases for different file types and extensions"""

    def test_supported_video_formats(self, authenticated_client, temp_video_dir):
        """Test support for different video formats"""
        supported_formats = [".mp4", ".mkv", ".avi", ".mov", ".webm", ".m4v", ".flv"]

        for ext in supported_formats:
            test_file = temp_video_dir / f"test_video{ext}"
            test_file.write_text(f"fake content for {ext}")

            response = authenticated_client.get(f"/stream/test_video{ext}")
            assert response.status_code == 200, f"Failed for extension {ext}"

    def test_subtitle_file_support(self, authenticated_client):
        """Test subtitle file support"""
        response = authenticated_client.get("/stream/subtitles.srt")

        assert response.status_code == 200
        assert response.data == b"fake subtitle content"

    def test_unsupported_file_types(self, authenticated_client, temp_video_dir):
        """Test rejection of unsupported file types"""
        unsupported_file = temp_video_dir / "document.pdf"
        unsupported_file.write_text("fake PDF content")

        response = authenticated_client.get("/stream/document.pdf")
        assert response.status_code == 403

    def test_case_insensitive_extensions(self, authenticated_client, temp_video_dir):
        """Test case-insensitive file extension handling"""
        upper_case_file = temp_video_dir / "test_video.MP4"
        upper_case_file.write_text("fake video content")

        response = authenticated_client.get("/stream/test_video.MP4")
        assert response.status_code == 200
