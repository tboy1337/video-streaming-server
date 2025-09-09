# Video Streaming Server

A comprehensive, production-ready video streaming server that allows you to securely share your personal video library over the internet. Built with enterprise-grade security, monitoring, and performance features.

## ✨ Features

### 🔒 Security
- **Multi-layer Authentication**: HTTP Basic Auth + Session Management
- **Path Traversal Protection**: Prevents unauthorized file access
- **Security Headers**: XSS, CSRF, clickjacking protection
- **Rate Limiting**: Configurable request throttling
- **Security Audit Logging**: Comprehensive security event tracking
- **Session Management**: Secure sessions with configurable timeouts

### 🎥 Media Streaming  
- **Universal Format Support**: MP4, MKV, AVI, MOV, WebM, M4V, FLV
- **Subtitle Support**: SRT subtitle files
- **Audio Support**: MP3, AAC, OGG, WAV
- **Range Requests**: Efficient streaming with seek support
- **Mobile Optimized**: Responsive design for all devices

### 📊 Monitoring & Performance
- **Health Check Endpoint**: Real-time server status
- **Performance Metrics**: Request timing and throughput monitoring  
- **Comprehensive Logging**: Application, security, error, and performance logs
- **Multi-threaded**: Configurable concurrency for high performance
- **Resource Monitoring**: Memory and disk usage tracking

### 🛠️ Production Features
- **Environment Configuration**: Full environment variable support
- **100% Test Coverage**: Comprehensive test suite with security tests
- **Docker Ready**: Production deployment configurations
- **Process Management**: Systemd/Windows service configurations
- **Log Rotation**: Automatic log rotation and archival
- **API Support**: RESTful JSON API for integration

## 📋 Requirements

- **Python**: 3.8 or higher
- **Operating System**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 20.04+ recommended)
- **Memory**: Minimum 2GB RAM, 4GB+ recommended for production
- **Storage**: 1GB for application, additional space for video content
- **Network**: Stable internet connection for remote access

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/tboy1337/video-streaming-server.git
cd video-streaming-server

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install production dependencies
pip install -r requirements.txt

# For development (includes testing and linting tools)
pip install -r requirements-dev.txt
```

### 2. Configuration

```bash
# Generate sample configuration
python config.py

# Copy and edit configuration
cp .env.example .env
# Edit .env with your settings
```

### 3. Security Setup

```bash
# Generate secure password hash
python generate_password.py
# Follow prompts and update .env with the hash
```

### 4. Start the Server

```bash
# Production server
python streaming_server.py

# Or with custom configuration
python streaming_server.py --host 0.0.0.0 --port 8080
```

## 📚 Documentation

### 📖 User Guides
- **[User Manual](docs/user_manual.md)** - Complete user guide with examples
- **[Deployment Guide](docs/deployment_guide.md)** - Production deployment instructions
- **[API Documentation](docs/api_documentation.md)** - Complete API reference

### 🔧 Configuration

Key environment variables:

```bash
# Server Configuration
VIDEO_SERVER_HOST=0.0.0.0
VIDEO_SERVER_PORT=5000  
VIDEO_SERVER_DIRECTORY=/path/to/videos
VIDEO_SERVER_THREADS=6

# Security (Required)
VIDEO_SERVER_USERNAME=your_username
VIDEO_SERVER_PASSWORD_HASH=your_secure_hash
VIDEO_SERVER_SECRET_KEY=your_secret_key

# Performance
VIDEO_SERVER_RATE_LIMIT_PER_MIN=60
VIDEO_SERVER_SESSION_TIMEOUT=3600
VIDEO_SERVER_MAX_FILE_SIZE=21474836480  # 20GB default, set to 0 to disable

# Logging
VIDEO_SERVER_LOG_LEVEL=INFO
VIDEO_SERVER_LOG_DIR=./logs
```

## 🏗️ Architecture

### Core Components

- **`streaming_server.py`** - Main application with Flask server
- **`config.py`** - Configuration management with environment variables  
- **`logging_config.py`** - Advanced logging with security and performance tracking
- **`generate_password.py`** - Secure password hash generation

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Install development dependencies (includes testing tools)
pip install -r requirements-dev.txt

# Run all tests with coverage
pytest

# Run specific test categories  
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests  
pytest -m security      # Security tests
pytest -m performance   # Performance tests

# Generate coverage report
pytest --cov=. --cov-report=html
```

### Test Coverage

- **Unit Tests**: Configuration, logging, authentication
- **Integration Tests**: Full application workflows
- **Security Tests**: Authentication, authorization, input validation  
- **Performance Tests**: Concurrent access, memory usage
- **API Tests**: All endpoints with various scenarios

## 🔒 Security

### Authentication & Authorization

```python
# Multi-layer authentication
HTTP_BASIC_AUTH + SESSION_MANAGEMENT + CSRF_PROTECTION
```

### Security Headers

```http
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN  
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

### Security Monitoring

All security events are logged:
- Authentication attempts (success/failure)
- Path traversal attempts
- Rate limit violations
- File access attempts
- Security header violations

## 📈 Performance

### Optimizations

- **Multi-threading**: Configurable worker threads
- **Range Requests**: Efficient video streaming
- **HTTP Caching**: Browser caching for static content
- **Connection Pooling**: Optimized for concurrent users
- **Memory Management**: Automatic resource cleanup

### Monitoring

```bash
# Health check
curl http://localhost:5000/health

# Performance metrics in logs/performance.log
tail -f logs/performance.log

# Resource monitoring  
htop  # Linux/macOS
perfmon  # Windows
```

## 🐳 Production Deployment

### Docker (Recommended)

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 5000
CMD ["python", "streaming_server.py"]
```

### System Service

**Linux (systemd)**:
```ini
[Unit]
Description=Video Streaming Server
After=network.target

[Service]  
Type=simple
User=video-server
WorkingDirectory=/opt/video-streaming-server
EnvironmentFile=/opt/video-streaming-server/.env
ExecStart=/opt/video-streaming-server/venv/bin/python streaming_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

**Windows Service**: Use NSSM (Non-Sucking Service Manager)

### Reverse Proxy (SSL/TLS)

**Nginx Configuration**:
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📊 API Usage

### RESTful Endpoints

```bash
# Health check (no auth required)
GET /health

# Directory listing  
GET /api/files?path=movies

# File streaming
GET /stream/path/to/video.mp4

# Web interface
GET /
GET /path/to/directory/
```

### Example API Usage

```python
import requests
from requests.auth import HTTPBasicAuth

auth = HTTPBasicAuth('username', 'password')

# Get file listing
response = requests.get(
    'http://localhost:5000/api/files', 
    auth=auth
)
files = response.json()

# Stream video
video_url = 'http://localhost:5000/stream/movie.mp4'
response = requests.get(video_url, auth=auth, stream=True)
```

## 🛠️ Development

### Code Quality

```bash
# Linting
pylint streaming_server.py config.py logging_config.py

# Code formatting
black .
isort .

# Type checking
mypy streaming_server.py
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features  
4. Ensure all tests pass
5. Submit a pull request

## 🔧 Troubleshooting

### Common Issues

**Server won't start**: Check logs in `logs/error.log`
**Authentication issues**: Verify password hash configuration  
**Performance problems**: Increase thread count
**Network access**: Check firewall and port forwarding

### Debug Mode

```bash
VIDEO_SERVER_DEBUG=true
VIDEO_SERVER_LOG_LEVEL=DEBUG
python streaming_server.py
```

### Support

- **Documentation**: Check `docs/` directory
- **Logs**: Review application logs in `logs/`
- **Health Check**: `curl http://localhost:5000/health`
- **Issues**: Create GitHub issue with logs and configuration

## 📄 License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

## 🤝 Acknowledgments

Built with modern Python practices and enterprise-grade security features. Designed for real-world deployment with comprehensive monitoring, testing, and documentation.

---

**Production Ready** ✅ | **Security Hardened** 🔒 | **100% Tested** 🧪 | **Fully Documented** 📚
