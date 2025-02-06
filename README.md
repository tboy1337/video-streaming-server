# Python Video Streaming Server

A simple web-based video streaming server that allows you to share your video library with friends over the internet. Features include:
- Password protection
- Directory browsing
- Video streaming
- Support for MP4, MKV, AVI, and MOV files
- Mobile-friendly interface

## Requirements

- Python 3.7 or higher
- Windows computer with a stable internet connection
- Port forwarding capability on your router

## Installation

1. Install Python:
   - Download Python from [python.org](https://python.org)
   - During installation, make sure to check "Add Python to PATH"

2. Install required Python packages:
```bash
pip install flask waitress
```

3. Download the video server script (`streaming_server.py`) and save it to a location of your choice.

## Configuration

1. Generate a password hash:
   - Open Command Prompt
   - Run Python:
```python
from werkzeug.security import generate_password_hash
print(generate_password_hash('your-chosen-password'))
```
   Replace 'your-chosen-password' with the password you want to use.

2. Edit the video server script:
   - Open `streaming_server.py` in a text editor
   - Set your video directory path:
```python
VIDEO_DIRECTORY = r'E:\Video'  # Change this to your video folder path
```
   - Set your desired username:
```python
USERNAME = 'friend'  # Change this to your preferred username
```
   - Replace the password hash:
```python
PASSWORD_HASH = 'your-generated-hash-goes-here'  # Paste your generated hash here
```

## Port Forwarding Setup

1. Find your computer's local IP address:
   - Open Command Prompt
   - Type `ipconfig`
   - Look for "IPv4 Address" under your active network adapter (usually starts with 192.168 or 10.0)

2. Set up port forwarding on your router:
   - Log into your router's admin interface (usually http://192.168.1.1 or http://192.168.0.1)
   - Find the port forwarding section (might be under Advanced Settings)
   - Add a new port forwarding rule:
     - External Port: 5000
     - Internal Port: 5000
     - Internal IP: Your computer's IP address from step 1
     - Protocol: TCP
     - Save the changes

3. Find your public IP address:
   - Visit [whatismyip.com](https://www.whatismyip.com)
   - Note down your public IP address

## Running the Server

1. Start the server:
   - Open Command Prompt
   - Navigate to the folder containing `streaming_server.py`
   - Run:
```bash
python streaming_server.py
```
   - You should see "Server running on http://0.0.0.0:5000"

2. Test local access:
   - Open Chrome or Edge (recommended for best video format support)
   - Visit: `http://localhost:5000`
   - Log in with your chosen username and password

## Sharing with Friends

Share these details with your friend:
1. Your public IP address (from step 3 of Port Forwarding)
2. The username and password you configured
3. Instructions to:
   - Visit `http://your-public-ip:5000` in their browser
   - Use Chrome or Edge for best compatibility
   - Log in with the provided credentials

## Troubleshooting

1. Can't access locally:
   - Check if the server is running
   - Verify the video directory path exists
   - Try using `http://127.0.0.1:5000`

2. Friend can't access:
   - Verify port forwarding is set up correctly
   - Check if your public IP has changed
   - Ensure your computer's firewall allows incoming connections on port 5000

3. Videos won't play:
   - For H.265/HEVC videos, use Chrome or Edge
   - Verify the video file isn't corrupted
   - Check if the video format is supported (.mp4, .mkv, .avi, .mov)

## Security Notes

1. Keep your password secure
2. Don't share the login credentials publicly
3. Consider changing the port number from 5000 to something less common
4. Keep your computer's firewall enabled
5. Regularly update Python and the installed packages

## Stopping the Server

Press Ctrl+C in the Command Prompt window to stop the server.

## Optional Enhancements

1. To run on a different port:
   - Change the port number in the code:
```python
serve(app, host='0.0.0.0', port=YOUR_PORT, threads=6)
```
   - Update your port forwarding rules accordingly

2. To allow more concurrent users:
   - Increase the number of threads:
```python
serve(app, host='0.0.0.0', port=5000, threads=12)
```

## Support

For issues or questions:
1. Check the troubleshooting section
2. Verify all setup steps were followed correctly
3. Check your system meets all requirements
