# Python Video Streaming Server

A simple web-based video streaming server that allows you to share your video library with friends over the internet. Features include:
- Password protection with secure session management
- Directory browsing with breadcrumb navigation
- Video streaming with controls
- Support for MP4, MKV, AVI, MOV, WebM, M4V, FLV files and SRT subtitles
- Mobile-friendly interface
- Enhanced security against common web attacks

## Requirements

- Python 3.7 or higher
- Windows computer with a stable internet connection
- Port forwarding capability on your router

## Installation

1. Install required Python packages:
```bash
pip install -r requirements.txt
```

2. Generate a password hash:
```bash
python generate_password.py
```
   - This will generate a secure password hash for authentication
   - You can either create your own password or let the script generate a strong one for you
   - Save the password for login and copy the hash for configuration

3. Edit the configuration in `streaming_server.py`:
   - Set your video directory path:
```python
VIDEO_DIRECTORY = r'E:\Video'  # Change this to your video folder path
```
   - Replace the password hash:
```python
PASSWORD_HASH = 'your-generated-hash-goes-here'  # Paste your generated hash here
```
   - Optionally, change the username (default is 'friend'):
```python
USERNAME = 'friend'  # Change this to your preferred username
```

4. Start the server:
```bash
python streaming_server.py
```
   - You should see "Server running on http://0.0.0.0:5000"

## Accessing the Server

1. **Local Access**:
   - Open your browser and visit: `http://localhost:5000`
   - Log in with the username (default: 'friend') and your chosen password

2. **Remote Access** (requires port forwarding):
   - Set up port forwarding on your router to forward port 5000 to your computer
   - Find your public IP address at [whatismyip.com](https://www.whatismyip.com)
   - Share your public IP and port with friends: `http://your-public-ip:5000`
   - They will also need the login credentials

## Port Forwarding Setup

1. Find your computer's local IP address:
   - Open Command Prompt and type `ipconfig`
   - Look for "IPv4 Address" (usually starts with 192.168 or 10.0)

2. Set up port forwarding on your router:
   - Log into your router's admin interface
   - Find the port forwarding section (often under Advanced Settings)
   - Add a new port forwarding rule:
     - External Port: 5000
     - Internal Port: 5000
     - Internal IP: Your computer's local IP address
     - Protocol: TCP
     - Save the changes

## Security Features

This server includes several security features:

1. **Authentication**:
   - Password-based authentication with secure hashing
   - Session management for seamless browsing
   - Session timeout after period of inactivity

2. **Path Protection**:
   - Path traversal prevention
   - Directory restriction to configured video folder only
   - File type validation for streaming

3. **Web Security**:
   - Security headers to prevent XSS, clickjacking, and MIME sniffing
   - Input validation and sanitization
   - Secure session cookies

4. **Monitoring**:
   - Logging of authentication attempts
   - Security event tracking
   - Error handling with appropriate information disclosure

## Supported Video Formats

The server supports the following video formats:
- MP4 (.mp4)
- MKV (.mkv)
- AVI (.avi)
- MOV (.mov)
- WebM (.webm)
- M4V (.m4v)
- FLV (.flv)
- SRT (.srt) subtitle files

To add support for additional formats, update the `ALLOWED_EXTENSIONS` set in the configuration.

## Troubleshooting

1. **Server won't start**:
   - Verify Python 3.7+ is installed: `python --version`
   - Check if all dependencies are installed: `pip install -r requirements.txt`
   - Ensure the video directory path exists and is accessible

2. **Can't access locally**:
   - Verify the server is running (check command prompt)
   - Try using `http://127.0.0.1:5000` instead of localhost
   - Check if another service is using port 5000

3. **Authentication issues**:
   - Verify you're using the correct username and password
   - Regenerate the password hash if needed
   - Check for proper hash configuration in the script

4. **Videos won't play**:
   - Verify the browser supports the video format
   - Check if the video file isn't corrupted
   - For H.265/HEVC videos, use Chrome or Edge

5. **Remote access issues**:
   - Verify port forwarding is set up correctly
   - Check if your public IP has changed
   - Ensure your computer's firewall allows incoming connections on port 5000

## Customization

The server can be customized in several ways:

1. **Change the port number**:
```python
serve(app, host='0.0.0.0', port=YOUR_PORT, threads=6)
```
   - Remember to update port forwarding rules accordingly

2. **Adjust session timeout** (default is 1 hour):
```python
SESSION_TIMEOUT = 3600  # Time in seconds
```

3. **Modify thread count** for better performance:
```python
serve(app, host='0.0.0.0', port=5000, threads=12)
```

4. **Change the video file extensions**:
```python
ALLOWED_EXTENSIONS = {'.mp4', '.mkv', '.avi', '.mov', '.webm', '.m4v', '.flv', '.srt'}
```

## Stopping the Server

Press `Ctrl+C` in the Command Prompt window to stop the server.

## Security Best Practices

1. Keep your password secure and don't share it widely
2. Regularly update Python and the installed packages
3. Consider using a non-standard port instead of 5000
4. Keep your computer's firewall enabled
5. Do not expose the server to the internet if it contains sensitive content
