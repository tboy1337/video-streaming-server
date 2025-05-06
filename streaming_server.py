"""
Video Streaming Server
---------------------
A simple HTTP server for streaming video files from a directory.

Setup:
1. Install requirements: pip install -r requirements.txt
2. Generate a password hash: python generate_password.py
3. Update the PASSWORD_HASH variable below with your generated hash
4. Change VIDEO_DIRECTORY to your video folder path
5. Run the server: python streaming_server.py
6. Connect to http://localhost:5000 in your browser
7. Log in with username 'friend' and your chosen password

Security features:
- Password protection
- Path traversal protection
- Session management
- Secure headers
- Input validation
"""

from flask import Flask, send_from_directory, render_template_string, request, Response, session
from functools import wraps
import os
import secrets
import time
from werkzeug.security import check_password_hash, generate_password_hash
from pathlib import Path
from waitress import serve
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a secure secret key

# Configuration
VIDEO_DIRECTORY = r'E:\Video'  # Windows path to video directory
USERNAME = 'friend'  # Change this to desired username
# Replace this hash with your generated one
PASSWORD_HASH = 'your-generated-hash-goes-here'
ALLOWED_EXTENSIONS = {'.mp4', '.mkv', '.avi', '.mov', '.webm', '.m4v'}
SESSION_TIMEOUT = 3600  # Session timeout in seconds (1 hour)

# Setup logging
logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('server.log', maxBytes=10000, backupCount=3)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(handler)

# HTML template for the video player page
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Video Library</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
        .video-list { list-style: none; padding: 0; }
        .video-item { 
            padding: 10px;
            margin: 5px 0;
            background: #f5f5f5;
            border-radius: 5px;
        }
        video { width: 100%; max-width: 800px; margin: 20px 0; }
        .back-link { margin-bottom: 20px; }
        .folder {
            font-weight: bold;
            color: #2c3e50;
        }
        .breadcrumb {
            margin-bottom: 20px;
            padding: 10px;
            background: #eee;
            border-radius: 5px;
        }
        .breadcrumb a {
            color: #3498db;
            text-decoration: none;
        }
        .breadcrumb a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    {% if video_file %}
        <div class="back-link">
            <a href="{{ parent_path }}">← Back to list</a>
        </div>
        <h2>{{ video_file }}</h2>
        <video controls>
            <source src="/stream/{{ video_path }}" type="video/mp4">
            Your browser does not support the video tag.
        </video>
    {% else %}
        <h1>Video Library</h1>
        <div class="breadcrumb">
            {% for crumb in breadcrumbs %}
                {% if not loop.last %}
                    <a href="{{ crumb.path }}">{{ crumb.name }}</a> /
                {% else %}
                    {{ crumb.name }}
                {% endif %}
            {% endfor %}
        </div>
        <ul class="video-list">
        {% if not is_root %}
            <li class="video-item folder">
                <a href="{{ parent_path }}">← Up to parent directory</a>
            </li>
        {% endif %}
        {% for item in items %}
            <li class="video-item {% if item.is_dir %}folder{% endif %}">
                <a href="{{ item.path }}">
                    {% if item.is_dir %}📁{% else %}🎬{% endif %}
                    {{ item.name }}
                </a>
            </li>
        {% endfor %}
        </ul>
    {% endif %}
</body>
</html>
'''

def check_auth(username, password):
    """Verify username and password against stored credentials"""
    if not username or not password:
        app.logger.warning(f"Empty credentials attempt from IP: {request.remote_addr}")
        return False
    
    valid = username == USERNAME and check_password_hash(PASSWORD_HASH, password)
    if not valid:
        app.logger.warning(f"Failed login attempt for user: {username} from IP: {request.remote_addr}")
    else:
        app.logger.info(f"Successful login: {username} from IP: {request.remote_addr}")
    return valid

def requires_auth(f):
    """Decorator to require HTTP Basic Auth"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check session auth first
        current_time = time.time()
        if session.get('authenticated'):
            # Check for session timeout
            if 'last_activity' in session and current_time - session['last_activity'] > SESSION_TIMEOUT:
                session.clear()
            else:
                session['last_activity'] = current_time
                return f(*args, **kwargs)
                
        # Fall back to HTTP Basic Auth
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response(
                'Please login with proper credentials', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
            
        # Set session on successful auth
        session['authenticated'] = True
        session['last_activity'] = current_time
        return f(*args, **kwargs)
    return decorated

def get_safe_path(requested_path):
    """Ensure the requested path is within the video directory"""
    if not requested_path:
        return Path(VIDEO_DIRECTORY)
        
    # Sanitize the path - remove any attempts to navigate with ..
    if '..' in requested_path or '//' in requested_path:
        app.logger.warning(f"Path traversal attempt: {requested_path} from IP: {request.remote_addr}")
        return None
        
    full_path = Path(VIDEO_DIRECTORY) / requested_path
    
    try:
        # Resolve any symlinks and normalize path
        full_path = full_path.resolve(strict=True)
        video_dir = Path(VIDEO_DIRECTORY).resolve()
        
        # Check if the path is within VIDEO_DIRECTORY
        if video_dir in full_path.parents or full_path == video_dir:
            return full_path
        else:
            app.logger.warning(f"Path traversal attempt: {requested_path} from IP: {request.remote_addr}")
    except (RuntimeError, OSError, ValueError) as e:
        app.logger.error(f"Path error: {str(e)} for path: {requested_path}")
    return None

def get_breadcrumbs(path):
    """Generate breadcrumb navigation"""
    video_dir = Path(VIDEO_DIRECTORY)
    current = Path(path)
    crumbs = []
    
    # Add root
    crumbs.append({"name": "Home", "path": "/"})
    
    # Add intermediate directories
    relative_path = current.relative_to(video_dir)
    current_path = ""
    for part in relative_path.parts:
        current_path = f"{current_path}/{part}"
        crumbs.append({"name": part, "path": current_path})
        
    return crumbs

@app.route('/')
@app.route('/<path:subpath>')
@requires_auth
def index(subpath=""):
    """Handle directory listing and video playback pages"""
    safe_path = get_safe_path(subpath)
    if not safe_path or not safe_path.exists():
        return "Path not found", 404

    if safe_path.is_file():
        # If it's a video file, show the video player
        if safe_path.suffix.lower() in ALLOWED_EXTENSIONS:
            relative_path = safe_path.relative_to(Path(VIDEO_DIRECTORY))
            parent_path = "/" + str(relative_path.parent) if str(relative_path.parent) != "." else "/"
            return render_template_string(
                HTML_TEMPLATE,
                video_file=safe_path.name,
                video_path=str(relative_path).replace("\\", "/"),
                parent_path=parent_path
            )
        return "Not a video file", 400

    # List directory contents
    items = []
    for item in safe_path.iterdir():
        if item.is_dir() or item.suffix.lower() in ALLOWED_EXTENSIONS:
            relative_path = item.relative_to(Path(VIDEO_DIRECTORY))
            items.append({
                "name": item.name,
                "path": "/" + str(relative_path).replace("\\", "/"),
                "is_dir": item.is_dir()
            })

    is_root = safe_path == Path(VIDEO_DIRECTORY)
    parent_path = "/" + str(safe_path.parent.relative_to(Path(VIDEO_DIRECTORY))).replace("\\", "/") if not is_root else "/"
    
    return render_template_string(
        HTML_TEMPLATE,
        items=sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower())),
        is_root=is_root,
        parent_path=parent_path,
        breadcrumbs=get_breadcrumbs(safe_path)
    )

@app.route('/stream/<path:video_path>')
@requires_auth
def stream(video_path):
    """Stream video files"""
    safe_path = get_safe_path(video_path)
    if not safe_path or not safe_path.is_file():
        return "Video not found", 404
        
    # Verify file extension
    if safe_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        app.logger.warning(f"Unauthorized file type access attempt: {video_path} from IP: {request.remote_addr}")
        return "File type not allowed", 403
        
    directory = safe_path.parent
    filename = safe_path.name
    return send_from_directory(directory, filename)

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.errorhandler(404)
def not_found_error(error):
    """Custom 404 error handler"""
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    """Custom 500 error handler"""
    app.logger.error(f"Server error: {str(error)}")
    return "Server error", 500

if __name__ == '__main__':
    # Verify video directory exists
    video_dir = Path(VIDEO_DIRECTORY)
    if not video_dir.exists():
        print(f"Error: Directory {VIDEO_DIRECTORY} does not exist!")
        exit(1)
        
    print(f"Starting server with video directory: {VIDEO_DIRECTORY}")
    print("Server running on http://0.0.0.0:5000")
    print("Use Ctrl+C to stop the server")
    
    # Run production server with Waitress
    serve(app, host='0.0.0.0', port=5000, threads=6) 