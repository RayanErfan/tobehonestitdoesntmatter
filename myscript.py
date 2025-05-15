from flask import Flask, send_from_directory, request, abort, render_template_string, send_file, session, redirect, url_for, jsonify
import os
import zipfile
import secrets
import datetime
import sqlite3
import hashlib
import logging
import time
import shutil
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import jwt
from cryptography.fernet import Fernet
import socket
import ssl
import threading
import uuid
import psutil
import json
import subprocess

# === SETTINGS ===
SHARE_FOLDER = r"C:\Users\Santrich\Downloads"  # Change this path to your shared folder
TEMP_FOLDER = r"C:\tmp\_temp"  # Temporary folder for operations
LOG_FOLDER = r"C:\tmp\_logs"  # Logs folder
BACKUP_FOLDER = r"C:\tmp\_backup"  # Auto backups folder

# Create folders if they don't exist
for folder in [SHARE_FOLDER, TEMP_FOLDER, LOG_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# === SECURITY SETTINGS ===
# Use environment variables for production
PASSWORD = "Erfan"  # Change your password here (or use env var)
ADMIN_PASSWORD = "Erfan"  # Admin password (or use env var)
SECRET_KEY = secrets.token_hex(32)  # For session and JWT
HASHED_PASSWORD = generate_password_hash(PASSWORD, method='pbkdf2:sha256:150000')
HASHED_ADMIN_PASSWORD = generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256:150000')
SSL_CERT = "cert.pem"  # Path to SSL certificate 
SSL_KEY = "key.pem"   # Path to SSL key
TOKEN_EXPIRY = 30  # Token expires in 30 minutes
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', 'mp3', 'mp4', 'bat', 'sh'}

# Generate encryption key for sensitive files
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# === PORT SETTINGS ===
HTTP_PORT = 8000  # Redirects to HTTPS
HTTPS_PORT = 8443  # Main secure port

# === APP SETTINGS ===
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=TOKEN_EXPIRY)

# === LOGGING CONFIGURATION ===
logging.basicConfig(
    filename=os.path.join(LOG_FOLDER, 'server.log'),
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('secure-file-server')

# === AUTHENTICATION HELPERS ===
def get_ip():
    """Get client IP address."""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is not None:
        return request.environ['HTTP_X_FORWARDED_FOR']
    else:
        return request.environ['REMOTE_ADDR']

def generate_token(username, role='user'):
    """Generate a JWT token for authentication."""
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRY),
        'iat': datetime.datetime.utcnow(),
        'jti': str(uuid.uuid4())
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    """Verify a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.args.get('token')
        if not token and 'token' in session:
            token = session['token']
        
        if not token:
            logger.warning(f"Unauthorized access attempt from IP: {get_ip()}")
            return redirect(url_for('login', next=request.url))
        
        payload = verify_token(token)
        if payload is None:
            logger.warning(f"Invalid token used from IP: {get_ip()}")
            return redirect(url_for('login', next=request.url))
        
        # Add user info to g object for use in templates
        request.user = payload
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.args.get('token')
        if not token and 'token' in session:
            token = session['token']
        
        if not token:
            logger.warning(f"Unauthorized admin access attempt from IP: {get_ip()}")
            return redirect(url_for('login', next=request.url))
        
        payload = verify_token(token)
        if payload is None or payload.get('role') != 'admin':
            logger.warning(f"Unauthorized admin access attempt from IP: {get_ip()}, user: {payload.get('username')}")
            abort(403)
        
        request.user = payload
        return f(*args, **kwargs)
    return decorated_function

# === SECURITY HELPERS ===
def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def encrypt_file(file_path, output_path=None):
    """Encrypt a file using Fernet symmetric encryption."""
    if output_path is None:
        output_path = file_path + '.enc'
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = cipher_suite.encrypt(file_data)
    
    with open(output_path, 'wb') as file:
        file.write(encrypted_data)
    
    return output_path

def decrypt_file(file_path, output_path=None):
    """Decrypt a file using Fernet symmetric encryption."""
    if output_path is None:
        output_path = file_path.replace('.enc', '')
    
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)
    
    return output_path

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_backup():
    """Create a backup of the shared folder."""
    return False
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(BACKUP_FOLDER, f"backup_{timestamp}")
    os.makedirs(backup_dir, exist_ok=True)
    
    # Copy all files from SHARE_FOLDER to backup_dir
    for filename in os.listdir(SHARE_FOLDER):
        src_path = os.path.join(SHARE_FOLDER, filename)
        if os.path.isfile(src_path):
            shutil.copy2(src_path, backup_dir)
    
    logger.info(f"Backup created at {backup_dir}")
    return backup_dir

# === FILE SYSTEM HELPERS ===
def get_directory_contents(directory_path):
    """Get contents of a directory with detailed information."""
    contents = []
    
    try:
        items = os.listdir(directory_path)
        
        # Add directories first
        for item in items:
            item_path = os.path.join(directory_path, item)
            if os.path.isdir(item_path):
                stat = os.stat(item_path)
                modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                contents.append({
                    'name': item,
                    'path': os.path.relpath(item_path, SHARE_FOLDER).replace('\\', '/'),
                    'size': 'Directory',
                    'modified': modified,
                    'type': 'Directory',
                    'is_dir': True
                })
        
        # Then add files
        for item in items:
            item_path = os.path.join(directory_path, item)
            if os.path.isfile(item_path):
                stat = os.stat(item_path)
                size = stat.st_size
                
                # Format size for display
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 * 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size / (1024 * 1024):.1f} MB"
                
                modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                filetype = item.split('.')[-1].upper() if '.' in item else 'Unknown'
                
                contents.append({
                    'name': item,
                    'path': os.path.relpath(item_path, SHARE_FOLDER).replace('\\', '/'),
                    'size': size_str,
                    'modified': modified,
                    'type': filetype,
                    'is_dir': False
                })
    except Exception as e:
        logger.error(f"Error listing directory contents: {str(e)}")
    
    return contents

def execute_command(command):
    """Execute a system command and return the output."""
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True
        )
        stdout, stderr = process.communicate(timeout=10)
        
        if process.returncode != 0:
            return {'success': False, 'output': stderr}
        
        return {'success': True, 'output': stdout}
    except subprocess.TimeoutExpired:
        return {'success': False, 'output': 'Command timed out after 10 seconds'}
    except Exception as e:
        return {'success': False, 'output': str(e)}

# === CHAT FUNCTIONS ===
# === HTML TEMPLATES ===

LOGIN_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure File Server - Login</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 40px;
            width: 400px;
            max-width: 90%;
        }
        h2 {
            color: #343a40;
            margin-top: 0;
            margin-bottom: 24px;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #495057;
            font-weight: 500;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 16px;
        }
        button {
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 12px 20px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #0069d9;
        }
        .error-message {
            color: #dc3545;
            margin-top: 16px;
            text-align: center;
        }
        .logo {
            font-size: 48px;
            text-align: center;
            margin-bottom: 24px;
        }
        .footer {
            margin-top: 24px;
            text-align: center;
            font-size: 14px;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🛡️</div>
        <h2>Secure File Server</h2>
        {% if error %}
            <div class="error-message">{{ error }}</div>
        {% endif %}
        <form action="/login" method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="footer">
            Secure access required. All activities are logged.
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure File Server</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #343a40;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        header h1 {
            margin: 0;
            font-size: 24px;
        }
        .user-info {
            display: flex;
            align-items: center;
        }
        .user-info span {
            margin-right: 20px;
        }
        .logout-btn {
            background-color: #dc3545;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }
        .logout-btn:hover {
            background-color: #c82333;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
            margin-bottom: 30px;
        }
        h2 {
            color: #343a40;
            margin-top: 0;
            margin-bottom: 20px;
            font-size: 20px;
        }
        .file-list {
            list-style-type: none;
            padding: 0;
            margin: 0;
        }
        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid #e9ecef;
        }
        .file-item:last-child {
            border-bottom: none;
        }
        .file-name {
            display: flex;
            align-items: center;
            cursor: pointer;
        }
        .folder-item {
            cursor: pointer;
        }
        .file-icon {
            margin-right: 10px;
            font-size: 20px;
        }
        .file-actions {
            display: flex;
        }
        .file-actions a {
            margin-left: 10px;
            color: #6c757d;
            text-decoration: none;
            font-size: 14px;
        }
        .file-actions a:hover {
            color: #343a40;
        }
        .file-info {
            color: #6c757d;
            font-size: 14px;
            margin-top: 4px;
        }
        .upload-form {
            display: flex;
            margin-top: 20px;
        }
        .file-input {
            flex: 1;
            padding: 10px;
            border: 1px solid #ced4da;
            border-radius: 4px 0 0 4px;
        }
        .upload-btn {
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 0 4px 4px 0;
            padding: 10px 20px;
            cursor: pointer;
        }
        .upload-btn:hover {
            background-color: #0069d9;
        }
        .action-buttons {
            display: flex;
            justify-content: flex-end;
            margin-top: 20px;
        }
        .action-btn {
            background-color: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 10px 20px;
            cursor: pointer;
            text-decoration: none;
            margin-left: 10px;
            font-size: 14px;
        }
        .action-btn:hover {
            background-color: #5a6268;
        }
        .action-btn.primary {
            background-color: #007bff;
        }
        .action-btn.primary:hover {
            background-color: #0069d9;
        }
        .action-btn.danger {
            background-color: #dc3545;
        }
        .action-btn.danger:hover {
            background-color: #c82333;
        }
        .flash-message {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .flash-success {
            background-color: #d4edda;
            color: #155724;
        }
        .flash-error {
            background-color: #f8d7da;
            color: #721c24;
        }
        .flash-warning {
            background-color: #fff3cd;
            color: #856404;
        }
        .search-form {
            margin-bottom: 20px;
        }
        .search-input {
            padding: 10px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            width: 300px;
            font-size: 14px;
        }
        .admin-panel {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
        }
        .path-nav {
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            overflow-x: auto;
        }
        .path-nav a {
            color: #007bff;
            text-decoration: none;
            margin: 0 5px;
        }
        .path-nav a:hover {
            text-decoration: underline;
        }
        .path-separator {
            color: #6c757d;
        }
        .nav-tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #dee2e6;
        }
        .nav-tab {
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid transparent;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 5px;
            margin-bottom: -1px;
        }
        .nav-tab.active {
            border-color: #dee2e6 #dee2e6 #fff;
            background-color: #fff;
            color: #495057;
        }
        .nav-tab:not(.active) {
            background-color: #f8f9fa;
            color: #007bff;
        }
        .nav-tab:not(.active):hover {
            border-color: #e9ecef #e9ecef #dee2e6;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .terminal {
            background-color: #212529;
            color: #f8f9fa;
            font-family: monospace;
            padding: 15px;
            border-radius: 4px;
            height: 400px;
            overflow-y: auto;
            margin-bottom: 20px;
        }
        .terminal-output {
            white-space: pre-wrap;
            margin-bottom: 10px;
        }
        .terminal-input-container {
            display: flex;
            background-color: #212529;
            padding: 10px;
            border-radius: 0 0 4px 4px;
        }
        .terminal-prompt {
            color: #28a745;
            margin-right: 10px;
        }
        .terminal-input {
            background-color: transparent;
            border: none;
            color: #f8f9fa;
            flex: 1;
            font-family: monospace;
            outline: none;
        }
        @media (max-width: 768px) {
            .file-item {
                flex-direction: column;
                align-items: flex-start;
            }
            .file-actions {
                margin-top: 10px;
            }
            .upload-form {
                flex-direction: column;
            }
            .file-input {
                border-radius: 4px;
                margin-bottom: 10px;
            }
            .upload-btn {
                border-radius: 4px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Secure File Server</h1>
            <div class="user-info">
                <span>Logged in as: {{ user.get('username') }} ({{ user.get('role') }})</span>
                <a href="/logout" class="logout-btn">Logout</a>
            </div>
        </header>
        
        {% if message %}
            <div class="flash-message flash-{{ message_type }}">{{ message }}</div>
        {% endif %}
        
        <div class="nav-tabs">
            <div class="nav-tab active" id="files-tab" onclick="showTab('files')">Files</div>
            <div class="nav-tab" id="terminal-tab" onclick="showTab('terminal')">Terminal</div>
        </div>
        
        <div id="files-content" class="tab-content active">
            <div class="card">
                <h2>File Management</h2>
                
                <div class="path-nav">
                    <a href="/dashboard?token={{ token }}">Home</a>
                    {% if current_path %}
                        {% set path_parts = current_path.split('/') %}
                        {% set accumulated_path = '' %}
                        {% for part in path_parts %}
                            {% if part %}
                                {% set accumulated_path = accumulated_path + '/' + part %}
                                <span class="path-separator">/</span>
                                <a href="/browse?path={{ accumulated_path }}&token={{ token }}">{{ part }}</a>
                            {% endif %}
                        {% endfor %}
                    {% endif %}
                </div>

                <form action="/dashboard" method="get" class="search-form">
                    <input type="hidden" name="token" value="{{ token }}">
                    <input type="text" name="search" placeholder="Search files..." class="search-input" value="{{ search }}">
                    <button type="submit" class="action-btn primary">Search</button>
                </form>
                
                {% if items %}
                    <ul class="file-list">
                    {% for item in items %}
                        <li class="file-item">
                            <div>
                                <div class="file-name {% if item.is_dir %}folder-item{% endif %}" onclick="{% if item.is_dir %}navigateToFolder('{{ item.path }}'){% else %}viewFile('{{ item.path }}'){% endif %}">
                                    <span class="file-icon">{% if item.is_dir %}📁{% else %}📄{% endif %}</span>
                                    {{ item.name }}
                                </div>
                                <div class="file-info">
                                    Size: {{ item.size }} | Modified: {{ item.modified }} | Type: {{ item.type }}
                                </div>
                            </div>
                            <div class="file-actions">
                                {% if not item.is_dir %}
                                    <a href="/file/{{ item.path }}?token={{ token }}" title="Download">⬇️ Download</a>
                                    <a href="/view/{{ item.path }}?token={{ token }}" title="View">👁️ View</a>
                                    {% if user.get('role') == 'admin' %}
                                        <a href="/delete/{{ item.path }}?token={{ token }}" title="Delete" onclick="return confirm('Are you sure you want to delete this item?')">❌ Delete</a>
                                    {% endif %}
                                {% else %}
                                    <a href="/browse?path={{ item.path }}&token={{ token }}" title="Open">📂 Open</a>
                                    {% if user.get('role') == 'admin' %}
                                        <a href="/delete-dir/{{ item.path }}?token={{ token }}" title="Delete" onclick="return confirm('Are you sure you want to delete this directory and all its contents?')">❌ Delete</a>
                                    {% endif %}
                                {% endif %}
                            </div>
                        </li>
                    {% endfor %}
                    </ul>
                {% else %}
                    <p>No files or folders found.</p>
                {% endif %}
                
                <div class="action-buttons">
                    <a href="/zip?path={{ current_path }}&token={{ token }}" class="action-btn primary">Download All as ZIP</a>
                    {% if user.get('role') == 'admin' %}
                        <a href="#" onclick="createFolder()" class="action-btn">Create Folder</a>
                    {% endif %}
                </div>
                
                <form action="/upload" method="post" enctype="multipart/form-data" class="upload-form">
                    <input type="hidden" name="token" value="{{ token }}">
                    <input type="hidden" name="path" value="{{ current_path }}">
                    <input type="file" name="file" required class="file-input">
                    <button type="submit" class="upload-btn">Upload</button>
                </form>
            </div>
        </div>
        
        <div id="terminal-content" class="tab-content">
            <div class="card">
                <h2>Terminal</h2>
                <div class="terminal" id="terminal-output"></div>
                <div class="terminal-input-container">
                    <span class="terminal-prompt">$</span>
                    <input type="text" id="terminal-input" class="terminal-input" placeholder="Enter command..." onkeydown="handleTerminalInput(event)">
                </div>
                <p class="terminal-help">Type 'help' for available commands.</p>
            </div>
        </div>
        
        {% if user.get('role') == 'admin' %}
            <div class="card admin-panel">
                <h2>Admin Panel</h2>
                <div class="action-buttons">
                    <a href="/backup?token={{ token }}" class="action-btn">Create Backup</a>
                    <a href="/logs?token={{ token }}" class="action-btn">View Logs</a>
                    <a href="/stats?token={{ token }}" class="action-btn">System Stats</a>
                </div>
            </div>
        {% endif %}
    </div>
    
    <script>
        // Tab functionality
        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.getElementById(tabName + '-content').classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
        }
        
        // Navigate to folder
        function navigateToFolder(path) {
            window.location.href = '/browse?path=' + path + '&token={{ token }}';
        }
        
        // View file
        function viewFile(path) {
            window.location.href = '/view/' + path + '?token={{ token }}';
        }
        
        // Create new folder
        function createFolder() {
            const folderName = prompt('Enter folder name:');
            if (folderName) {
                window.location.href = '/create-folder?path={{ current_path }}&name=' + encodeURIComponent(folderName) + '&token={{ token }}';
            }
        }
        
        // Terminal functionality
        let terminalHistory = [];
        let historyIndex = -1;
        
        function addToTerminal(text, isCommand = false) {
            const terminal = document.getElementById('terminal-output');
            const output = document.createElement('div');
            output.className = 'terminal-output';
            
            if (isCommand) {
                output.innerHTML = '<span style="color: #28a745;">$</span> ' + text;
            } else {
                output.textContent = text;
            }
            
            terminal.appendChild(output);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        function handleTerminalInput(event) {
            if (event.key === 'Enter') {
                const input = document.getElementById('terminal-input');
                const command = input.value.trim();
                
                if (command) {
                    // Add command to history
                    terminalHistory.push(command);
                    historyIndex = terminalHistory.length;
                    
                    // Display the command
                    addToTerminal(command, true);
                    
                    // Execute the command
                    executeCommand(command);
                    
                    // Clear input
                    input.value = '';
                }
            } else if (event.key === 'ArrowUp') {
                // Navigate command history (up)
                if (historyIndex > 0) {
                    historyIndex--;
                    document.getElementById('terminal-input').value = terminalHistory[historyIndex];
                }
                event.preventDefault();
            } else if (event.key === 'ArrowDown') {
                // Navigate command history (down)
                if (historyIndex < terminalHistory.length - 1) {
                    historyIndex++;
                    document.getElementById('terminal-input').value = terminalHistory[historyIndex];
                } else {
                    historyIndex = terminalHistory.length;
                    document.getElementById('terminal-input').value = '';
                }
                event.preventDefault();
            }
        }
        
        function executeCommand(command) {
            // Special commands
            if (command === 'clear') {
                document.getElementById('terminal-output').innerHTML = '';
                return;
            } else if (command === 'help') {
                addToTerminal('Available commands:');
                addToTerminal('help - Show this help message');
                addToTerminal('clear - Clear terminal output');
                addToTerminal('ls - List files in current directory');
                addToTerminal('cd [path] - Change directory');
                addToTerminal('pwd - Show current directory');
                addToTerminal('cat [file] - View file contents');
                addToTerminal('mkdir [name] - Create a directory');
                addToTerminal('rm [file] - Remove a file');
                addToTerminal('rmdir [dir] - Remove a directory');
                addToTerminal('echo [text] - Display text');
                addToTerminal('Any other commands will be executed on the server');
                return;
            }
            
            // Send command to server
            fetch('/terminal/execute?token={{ token }}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    command: command,
                    path: '{{ current_path }}'
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    addToTerminal(data.output);
                } else {
                    addToTerminal('Error: ' + data.output);
                }
            })
            .catch(error => {
                addToTerminal('Error: Failed to execute command');
                console.error(error);
            });
        }
        
        // Add initial welcome message to terminal
        addToTerminal('Secure File Server Terminal');
        addToTerminal('Type "help" for available commands');
        addToTerminal('');
    </script>
</body>
</html>
"""

VIEW_FILE_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>View File: {{ filename }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #343a40;
            color: white;
            padding: 15px 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        header h1 {
            margin: 0;
            font-size: 20px;
        }
        .back-btn {
            background-color: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }
        .back-btn:hover {
            background-color: #5a6268;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
        }
        .file-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e9ecef;
        }
        .file-title {
            display: flex;
            align-items: center;
        }
        .file-icon {
            font-size: 24px;
            margin-right: 10px;
        }
        .file-actions a {
            margin-left: 10px;
            color: #6c757d;
            text-decoration: none;
        }
        .file-actions a:hover {
            color: #343a40;
        }
        .file-meta {
            margin-bottom: 20px;
            font-size: 14px;
            color: #6c757d;
        }
        .file-meta-item {
            margin-right: 20px;
            display: inline-block;
        }
        .file-content {
            border: 1px solid #e9ecef;
            padding: 20px;
            border-radius: 4px;
            overflow: auto;
            max-height: 600px;
            white-space: pre-wrap;
            font-family: monospace;
        }
        .file-content img {
            max-width: 100%;
            display: block;
            margin: 0 auto;
        }
        .not-viewable {
            text-align: center;
            padding: 40px 0;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ File Viewer</h1>
            <a href="{{ back_url }}" class="back-btn">Back</a>
        </header>
        
        <div class="card">
            <div class="file-header">
                <div class="file-title">
                    <span class="file-icon">📄</span>
                    <h2>{{ filename }}</h2>
                </div>
                <div class="file-actions">
                    <a href="/file/{{ filepath }}?token={{ token }}" title="Download">⬇️ Download</a>
                </div>
            </div>
            
            <div class="file-meta">
                <div class="file-meta-item">Size: {{ filesize }}</div>
                <div class="file-meta-item">Modified: {{ modified }}</div>
                <div class="file-meta-item">Type: {{ filetype }}</div>
                <div class="file-meta-item">SHA-256: {{ filehash }}</div>
            </div>
            
            {% if is_viewable %}
                <div class="file-content">
                    {% if is_image %}
                        <img src="/file/{{ filepath }}?token={{ token }}" alt="{{ filename }}">
                    {% else %}
                        {{ content }}
                    {% endif %}
                </div>
            {% else %}
                <div class="not-viewable">
                    <p>This file type cannot be displayed in the browser.</p>
                    <p>Please download the file to view its contents.</p>
                    <a href="/file/{{ filepath }}?token={{ token }}" class="action-btn primary">Download File</a>
                </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

LOG_VIEW_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>System Logs</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #343a40;
            color: white;
            padding: 15px 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        header h1 {
            margin: 0;
            font-size: 20px;
        }
        .back-btn {
            background-color: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }
        .back-btn:hover {
            background-color: #5a6268;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
        }
        .log-container {
            border: 1px solid #e9ecef;
            padding: 20px;
            border-radius: 4px;
            overflow: auto;
            max-height: 600px;
            font-family: monospace;
            white-space: pre-wrap;
            background-color: #f8f9fa;
        }
        .log-line {
            margin-bottom: 5px;
            padding-bottom: 5px;
            border-bottom: 1px solid #e9ecef;
        }
        .log-error {
            color: #dc3545;
        }
        .log-warning {
            color: #ffc107;
        }
        .log-info {
            color: #17a2b8;
        }
        .action-buttons {
            display: flex;
            justify-content: flex-end;
            margin-top: 20px;
        }
        .action-btn {
            background-color: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 10px 20px;
            cursor: pointer;
            text-decoration: none;
            margin-left: 10px;
            font-size: 14px;
        }
        .action-btn:hover {
            background-color: #5a6268;
        }
        .action-btn.danger {
            background-color: #dc3545;
        }
        .action-btn.danger:hover {
            background-color: #c82333;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ System Logs</h1>
            <a href="/dashboard?token={{ token }}" class="back-btn">Back to Dashboard</a>
        </header>
        
        <div class="card">
            <h2>Log Entries</h2>
            
            <div class="log-container">
                {% for log in logs %}
                    <div class="log-line {% if 'ERROR' in log %}log-error{% elif 'WARNING' in log %}log-warning{% elif 'INFO' in log %}log-info{% endif %}">
                        {{ log }}
                    </div>
                {% endfor %}
            </div>
            
            <div class="action-buttons">
                <a href="/logs/download?token={{ token }}" class="action-btn">Download Logs</a>
                <a href="/logs/clear?token={{ token }}" class="action-btn danger" onclick="return confirm('Are you sure you want to clear all logs?')">Clear Logs</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

STATS_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>System Statistics</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #343a40;
            color: white;
            padding: 15px 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        header h1 {
            margin: 0;
            font-size: 20px;
        }
        .back-btn {
            background-color: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }
        .back-btn:hover {
            background-color: #5a6268;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
            margin-bottom: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
        }
        .stat-card {
            padding: 20px;
            border-radius: 4px;
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .stat-label {
            color: #6c757d;
            font-size: 14px;
        }
        h2 {
            color: #343a40;
            margin-top: 0;
            margin-bottom: 20px;
            font-size: 20px;
        }
        .progress-bar {
            height: 10px;
            background-color: #e9ecef;
            border-radius: 5px;
            margin-top: 10px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background-color: #007bff;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ System Statistics</h1>
            <a href="/dashboard?token={{ token }}" class="back-btn">Back to Dashboard</a>
        </header>
        
        <div class="card">
            <h2>Storage Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{{ stats.file_count }}</div>
                    <div class="stat-label">Total Files</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.total_size }}</div>
                    <div class="stat-label">Total Size</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {{ stats.disk_usage_percent }}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.avg_file_size }}</div>
                    <div class="stat-label">Average File Size</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.disk_free }}</div>
                    <div class="stat-label">Free Disk Space</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>Server Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{{ stats.uptime }}</div>
                    <div class="stat-label">Server Uptime</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.cpu_usage }}%</div>
                    <div class="stat-label">CPU Usage</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {{ stats.cpu_usage }}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.memory_usage }}%</div>
                    <div class="stat-label">Memory Usage</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {{ stats.memory_usage }}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.request_count }}</div>
                    <div class="stat-label">Total Requests</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>Security Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{{ stats.failed_auth_attempts }}</div>
                    <div class="stat-label">Failed Authentication Attempts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.successful_logins }}</div>
                    <div class="stat-label">Successful Logins</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.last_backup }}</div>
                    <div class="stat-label">Last Backup</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.file_ops }}</div>
                    <div class="stat-label">File Operations</div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

ERROR_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Error - {{ error_code }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .error-container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 40px;
            text-align: center;
            max-width: 500px;
        }
        .error-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            color: #dc3545;
            margin-top: 0;
            margin-bottom: 10px;
        }
        p {
            color: #6c757d;
            margin-bottom: 30px;
        }
        .back-btn {
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 12px 20px;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
        }
        .back-btn:hover {
            background-color: #0069d9;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">⚠️</div>
        <h1>Error {{ error_code }}</h1>
        <p>{{ error_message }}</p>
        <a href="{{ back_url }}" class="back-btn">Go Back</a>
    </div>
</body>
</html>
"""
# === ROUTE HANDLERS ===
@app.route('/')
def index():
    """Redirect to login page."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate credentials
        is_admin = False
        if username == 'admin' and check_password_hash(HASHED_ADMIN_PASSWORD, password):
            is_admin = True
            role = 'admin'
        elif username == 'user' and check_password_hash(HASHED_PASSWORD, password):  
            role = 'user'
        else:
            logger.warning(f"Failed login attempt for username: {username} from IP: {get_ip()}")
            return render_template_string(LOGIN_HTML, error="Invalid username or password")
        
        # Generate JWT token
        token = generate_token(username, role)
        
        # Store token in session
        session['token'] = token
        session.permanent = True
        
        logger.info(f"Successful login: {username} (role: {role}) from IP: {get_ip()}")
        return redirect(url_for('dashboard'))
    
    return render_template_string(LOGIN_HTML, error=None)

@app.route('/logout')
def logout():
    """Handle user logout."""
    if 'token' in session:
        # Get username before clearing session
        token = session['token']
        try:
            payload = verify_token(token)
            username = payload.get('username', 'unknown')
            logger.info(f"User logged out: {username} from IP: {get_ip()}")
        except:
            pass
        
        session.clear()
    
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Display the main dashboard."""
    token = request.args.get('token') or session.get('token')
    search = request.args.get('search', '')
    message = request.args.get('message')
    message_type = request.args.get('message_type', 'success')
    
    # Get file list with detailed info
    items = []
    try:
        # Get contents of SHARE_FOLDER
        current_directory = SHARE_FOLDER
        current_path = ""
        
        items = get_directory_contents(current_directory)
        
        # Filter by search if provided
        if search:
            items = [item for item in items if search.lower() in item['name'].lower()]
        
    except Exception as e:
        logger.error(f"Error listing items: {str(e)}")
        message = f"Error listing items: {str(e)}"
        message_type = 'error'
    
    return render_template_string(
        DASHBOARD_HTML,
        items=items,
        token=token,
        user=request.user,
        message=message,
        message_type=message_type,
        search=search,
        current_path=current_path
    )

@app.route('/browse')
@login_required
def browse():
    """Browse directory contents."""
    token = request.args.get('token') or session.get('token')
    path = request.args.get('path', '')
    message = request.args.get('message')
    message_type = request.args.get('message_type', 'success')
    
    # Sanitize path to prevent directory traversal
    path = path.lstrip('/')
    if '..' in path:
        logger.warning(f"Path traversal attempt detected from IP: {get_ip()}, user: {request.user.get('username')}")
        return redirect(url_for('dashboard', token=token, message="Invalid path", message_type="error"))
    
    # Calculate the full directory path
    directory_path = os.path.join(SHARE_FOLDER, path)
    
    # Check if directory exists
    if not os.path.isdir(directory_path):
        return redirect(url_for('dashboard', token=token, message="Directory not found", message_type="error"))
    
    # Get directory contents
    items = get_directory_contents(directory_path)
    
    return render_template_string(
        DASHBOARD_HTML,
        items=items,
        token=token,
        user=request.user,
        message=message,
        message_type=message_type,
        search="",
        current_path=path
    )

@app.route('/file/<path:filepath>')
@login_required
def serve_file(filepath):
    """Serve a file for download."""
    token = request.args.get('token') or session.get('token')
    
    # Security check - prevent path traversal
    if '..' in filepath or filepath.startswith('/'):
        logger.warning(f"Path traversal attempt detected from IP: {get_ip()}, user: {request.user.get('username')}")
        abort(403)
    
    # Construct the full path
    file_path = os.path.join(SHARE_FOLDER, filepath)
    
    # Get directory and filename
    directory, filename = os.path.split(file_path)
    
    # Log file access
    logger.info(f"File downloaded: {filepath} by {request.user.get('username')} from IP: {get_ip()}")
    
    # Serve the file
    return send_from_directory(directory, filename, as_attachment=True)

@app.route('/view/<path:filepath>')
@login_required
def view_file(filepath):
    """View file contents in browser if possible."""
    token = request.args.get('token') or session.get('token')
    
    # Security check - prevent path traversal
    if '..' in filepath or filepath.startswith('/'):
        logger.warning(f"Path traversal attempt detected from IP: {get_ip()}, user: {request.user.get('username')}")
        abort(403)
    
    file_path = os.path.join(SHARE_FOLDER, filepath)
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        abort(404)
    
    # Get file info
    stat = os.stat(file_path)
    size = stat.st_size
    # Format size for display
    if size < 1024:
        size_str = f"{size} B"
    elif size < 1024 * 1024:
        size_str = f"{size / 1024:.1f} KB"
    else:
        size_str = f"{size / (1024 * 1024):.1f} MB"
    
    modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
    filename = os.path.basename(file_path)
    filetype = filename.split('.')[-1].upper() if '.' in filename else 'Unknown'
    filehash = get_file_hash(file_path)
    
    # Determine if file is viewable in browser
    viewable_extensions = ['txt', 'log', 'md', 'csv', 'json', 'xml', 'html', 'htm', 'css', 'js', 'py', 'c', 'cpp', 'h', 'java', 'sh', 'bat', 'ps1']
    image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg']
    
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    is_viewable = ext in viewable_extensions or ext in image_extensions
    is_image = ext in image_extensions
    
    content = ""
    if is_viewable and not is_image:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            content = f"Error reading file: {str(e)}"
    
    # Create back URL
    dirname = os.path.dirname(filepath)
    if dirname:
        back_url = f"/browse?path={dirname}&token={token}"
    else:
        back_url = f"/dashboard?token={token}"
    
    # Log file viewing
    logger.info(f"File viewed: {filepath} by {request.user.get('username')} from IP: {get_ip()}")
    
    return render_template_string(
        VIEW_FILE_HTML,
        filename=filename,
        filepath=filepath,
        filesize=size_str,
        modified=modified,
        filetype=filetype,
        filehash=filehash,
        is_viewable=is_viewable,
        is_image=is_image,
        content=content,
        token=token,
        back_url=back_url
    )

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file uploads."""
    token = request.form.get('token') or session.get('token')
    path = request.form.get('path', '')
    
    # Sanitize path
    path = path.lstrip('/')
    if '..' in path:
        logger.warning(f"Path traversal attempt detected from IP: {get_ip()}, user: {request.user.get('username')}")
        return redirect(url_for('dashboard', token=token, message="Invalid path", message_type="error"))
    
    upload_directory = os.path.join(SHARE_FOLDER, path)
    
    if 'file' not in request.files:
        if path:
            return redirect(url_for('browse', path=path, token=token, message="No file part", message_type="error"))
        else:
            return redirect(url_for('dashboard', token=token, message="No file part", message_type="error"))
    
    file = request.files['file']
    if file.filename == '':
        if path:
            return redirect(url_for('browse', path=path, token=token, message="No selected file", message_type="error"))
        else:
            return redirect(url_for('dashboard', token=token, message="No selected file", message_type="error"))
    
    if file:
        # Secure the filename to prevent directory traversal
        filename = secure_filename(file.filename)
        
        # Check if file extension is allowed
        if not allowed_file(filename):
            logger.warning(f"Attempted upload of disallowed file type: {filename} by {request.user.get('username')} from IP: {get_ip()}")
            if path:
                return redirect(url_for('browse', path=path, token=token, message="File type not allowed", message_type="error"))
            else:
                return redirect(url_for('dashboard', token=token, message="File type not allowed", message_type="error"))
        
        # Save the file
        try:
            file_path = os.path.join(upload_directory, filename)
            file.save(file_path)
            
            # Calculate file hash for verification
            file_hash = get_file_hash(file_path)
            
            logger.info(f"File uploaded: {os.path.join(path, filename)} (hash: {file_hash}) by {request.user.get('username')} from IP: {get_ip()}")
            if path:
                return redirect(url_for('browse', path=path, token=token, message=f"File uploaded successfully: {filename}", message_type="success"))
            else:
                return redirect(url_for('dashboard', token=token, message=f"File uploaded successfully: {filename}", message_type="success"))
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            if path:
                return redirect(url_for('browse', path=path, token=token, message=f"Error uploading file: {str(e)}", message_type="error"))
            else:
                return redirect(url_for('dashboard', token=token, message=f"Error uploading file: {str(e)}", message_type="error"))
    
    if path:
        return redirect(url_for('browse', path=path, token=token))
    else:
        return redirect(url_for('dashboard', token=token))

@app.route('/delete/<path:filepath>')
@admin_required
def delete_file(filepath):
    """Delete a file (admin only)."""
    token = request.args.get('token') or session.get('token')
    
    # Security check - prevent path traversal
    if '..' in filepath or filepath.startswith('/'):
        logger.warning(f"Path traversal attempt detected from IP: {get_ip()}, user: {request.user.get('username')}")
        abort(403)
    
    file_path = os.path.join(SHARE_FOLDER, filepath)
    
    try:
        if os.path.exists(file_path) and os.path.isfile(file_path):
            # Get directory path for redirection
            dirname = os.path.dirname(filepath)
            
            # Calculate hash before deletion for logging
            file_hash = get_file_hash(file_path)
            
            # Delete the file
            os.remove(file_path)
            
            logger.info(f"File deleted: {filepath} (hash: {file_hash}) by admin: {request.user.get('username')} from IP: {get_ip()}")
            
            if dirname:
                return redirect(url_for('browse', path=dirname, token=token, message=f"File deleted: {os.path.basename(filepath)}", message_type="success"))
            else:
                return redirect(url_for('dashboard', token=token, message=f"File deleted: {os.path.basename(filepath)}", message_type="success"))
        else:
            return redirect(url_for('dashboard', token=token, message="File not found", message_type="error"))
    except Exception as e:
        logger.error(f"Error deleting file: {str(e)}")
        return redirect(url_for('dashboard', token=token, message=f"Error deleting file: {str(e)}", message_type="error"))

@app.route('/delete-dir/<path:dirpath>')
@admin_required
def delete_directory(dirpath):
    """Delete a directory and its contents (admin only)."""
    token = request.args.get('token') or session.get('token')
    
    # Security check - prevent path traversal
    if '..' in dirpath or dirpath.startswith('/'):
        logger.warning(f"Path traversal attempt detected from IP: {get_ip()}, user: {request.user.get('username')}")
        abort(403)
    
    dir_path = os.path.join(SHARE_FOLDER, dirpath)
    
    try:
        if os.path.exists(dir_path) and os.path.isdir(dir_path):
            # Get parent directory path for redirection
            parent_dir = os.path.dirname(dirpath)
            
            # Delete the directory and all its contents
            shutil.rmtree(dir_path)
            
            logger.info(f"Directory deleted: {dirpath} by admin: {request.user.get('username')} from IP: {get_ip()}")
            
            if parent_dir:
                return redirect(url_for('browse', path=parent_dir, token=token, message=f"Directory deleted: {os.path.basename(dirpath)}", message_type="success"))
            else:
                return redirect(url_for('dashboard', token=token, message=f"Directory deleted: {os.path.basename(dirpath)}", message_type="success"))
        else:
            return redirect(url_for('dashboard', token=token, message="Directory not found", message_type="error"))
    except Exception as e:
        logger.error(f"Error deleting directory: {str(e)}")
        return redirect(url_for('dashboard', token=token, message=f"Error deleting directory: {str(e)}", message_type="error"))

@app.route('/create-folder')
@login_required
def create_folder():
    """Create a new folder."""
    token = request.args.get('token') or session.get('token')
    path = request.args.get('path', '')
    folder_name = request.args.get('name', '')
    
    if not folder_name:
        if path:
            return redirect(url_for('browse', path=path, token=token, message="Folder name is required", message_type="error"))
        else:
            return redirect(url_for('dashboard', token=token, message="Folder name is required", message_type="error"))
    
    # Sanitize path and folder name
    path = path.lstrip('/')
    folder_name = secure_filename(folder_name)
    
    if '..' in path:
        logger.warning(f"Path traversal attempt detected from IP: {get_ip()}, user: {request.user.get('username')}")
        return redirect(url_for('dashboard', token=token, message="Invalid path", message_type="error"))
    
    # Create the folder
    try:
        new_folder_path = os.path.join(SHARE_FOLDER, path, folder_name)
        os.makedirs(new_folder_path, exist_ok=True)
        
        logger.info(f"Folder created: {os.path.join(path, folder_name)} by {request.user.get('username')} from IP: {get_ip()}")
        
        if path:
            return redirect(url_for('browse', path=path, token=token, message=f"Folder created: {folder_name}", message_type="success"))
        else:
            return redirect(url_for('dashboard', token=token, message=f"Folder created: {folder_name}", message_type="success"))
    except Exception as e:
        logger.error(f"Error creating folder: {str(e)}")
        if path:
            return redirect(url_for('browse', path=path, token=token, message=f"Error creating folder: {str(e)}", message_type="error"))
        else:
            return redirect(url_for('dashboard', token=token, message=f"Error creating folder: {str(e)}", message_type="error"))

@app.route('/zip')
@login_required
def download_zip():
    """Download all files in a directory as a ZIP archive."""
    token = request.args.get('token') or session.get('token')
    path = request.args.get('path', '')
    
    # Sanitize path
    path = path.lstrip('/')
    if '..' in path:
        logger.warning(f"Path traversal attempt detected from IP: {get_ip()}, user: {request.user.get('username')}")
        return redirect(url_for('dashboard', token=token, message="Invalid path", message_type="error"))
    
    # Get the directory to zip
    directory_path = os.path.join(SHARE_FOLDER, path)
    
    # Check if directory exists
    if not os.path.isdir(directory_path):
        return redirect(url_for('dashboard', token=token, message="Directory not found", message_type="error"))
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dirname = os.path.basename(directory_path) or "root"
    zip_filename = f"{dirname}_files_{timestamp}.zip"
    zip_path = os.path.join(TEMP_FOLDER, zip_filename)
    
    try:
        # Create a temporary ZIP file
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Add file to ZIP with relative path
                    arcname = os.path.relpath(file_path, directory_path)
                    zipf.write(file_path, arcname)
        
        # Log the download
        logger.info(f"ZIP archive of {path or 'root directory'} downloaded by {request.user.get('username')} from IP: {get_ip()}")
        
        # Send the ZIP file
        return send_file(zip_path, as_attachment=True, download_name=zip_filename)
    except Exception as e:
        logger.error(f"Error creating ZIP archive: {str(e)}")
        if path:
            return redirect(url_for('browse', path=path, token=token, message=f"Error creating ZIP archive: {str(e)}", message_type="error"))
        else:
            return redirect(url_for('dashboard', token=token, message=f"Error creating ZIP archive: {str(e)}", message_type="error"))
    finally:
        # Clean up the temporary ZIP file (delayed)
        def cleanup():
            time.sleep(60)  # Wait a minute before deleting
            if os.path.exists(zip_path):
                os.remove(zip_path)
        
        threading.Thread(target=cleanup).start()

@app.route('/terminal/execute', methods=['POST'])
@login_required
def terminal_execute():
    """Execute terminal commands."""
    try:
        token = request.args.get('token') or session.get('token')
        data = request.get_json()
        command = data.get('command', '')
        path = data.get('path', '')
        
        # Sanitize path
        path = path.lstrip('/')
        if '..' in path:
            return jsonify({'success': False, 'output': 'Invalid path'})
        
        # Set the working directory
        working_dir = os.path.join(SHARE_FOLDER, path)
        
        # Process special commands
        if command.startswith('cd '):
            target_dir = command[3:].strip()
            
            # Handle absolute paths within the share folder
            if target_dir.startswith('/'):
                target_dir = target_dir.lstrip('/')
                target_path = os.path.join(SHARE_FOLDER, target_dir)
            else:
                target_path = os.path.join(working_dir, target_dir)
            
            # Check if it's within bounds
            if os.path.commonpath([target_path]) != os.path.commonpath([SHARE_FOLDER]):
                return jsonify({'success': False, 'output': 'Access denied: Cannot navigate outside of the share folder'})
            
            if os.path.isdir(target_path):
                # Return the new path relative to SHARE_FOLDER
                rel_path = os.path.relpath(target_path, SHARE_FOLDER)
                return jsonify({'success': True, 'output': f'Changed directory to {rel_path}'})
            else:
                return jsonify({'success': False, 'output': 'Directory not found'})
        
        elif command == 'pwd':
            # Return the current path relative to SHARE_FOLDER
            rel_path = os.path.relpath(working_dir, SHARE_FOLDER)
            if rel_path == '.':
                rel_path = '/'
            return jsonify({'success': True, 'output': rel_path})
        
        elif command == 'ls' or command.startswith('ls '):
            # List files in directory
            try:
                # Parse arguments
                parts = command.split()
                target_dir = working_dir
                
                if len(parts) > 1:
                    dir_arg = parts[1]
                    if dir_arg.startswith('/'):
                        dir_arg = dir_arg.lstrip('/')
                        target_dir = os.path.join(SHARE_FOLDER, dir_arg)
                    else:
                        target_dir = os.path.join(working_dir, dir_arg)
                
                # Check if it's within bounds
                if os.path.commonpath([target_dir]) != os.path.commonpath([SHARE_FOLDER]):
                    return jsonify({'success': False, 'output': 'Access denied: Cannot access outside of the share folder'})
                
                result = ""
                for item in os.listdir(target_dir):
                    item_path = os.path.join(target_dir, item)
                    if os.path.isdir(item_path):
                        result += f"📁 {item}/\n"
                    else:
                        result += f"📄 {item}\n"
                
                return jsonify({'success': True, 'output': result})
            except Exception as e:
                return jsonify({'success': False, 'output': str(e)})
        
        elif command.startswith('cat '):
            # View file contents
            filename = command[4:].strip()
            
            # Handle absolute paths within the share folder
            if filename.startswith('/'):
                filename = filename.lstrip('/')
                file_path = os.path.join(SHARE_FOLDER, filename)
            else:
                file_path = os.path.join(working_dir, filename)
            
            # Check if it's within bounds
            if os.path.commonpath([file_path]) != os.path.commonpath([SHARE_FOLDER]):
                return jsonify({'success': False, 'output': 'Access denied: Cannot access files outside of the share folder'})
            
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    return jsonify({'success': True, 'output': content})
                except Exception as e:
                    return jsonify({'success': False, 'output': f'Error reading file: {str(e)}'})
            else:
                return jsonify({'success': False, 'output': 'File not found'})
        
        elif command.startswith('mkdir '):
            # Create directory
            dirname = command[6:].strip()
            
            # Handle absolute paths within the share folder
            if dirname.startswith('/'):
                dirname = dirname.lstrip('/')
                dir_path = os.path.join(SHARE_FOLDER, dirname)
            else:
                dir_path = os.path.join(working_dir, dirname)
            
            # Check if it's within bounds
            if os.path.commonpath([dir_path]) != os.path.commonpath([SHARE_FOLDER]):
                return jsonify({'success': False, 'output': 'Access denied: Cannot create directories outside of the share folder'})
            
            try:
                os.makedirs(dir_path, exist_ok=True)
                return jsonify({'success': True, 'output': f'Directory created: {dirname}'})
            except Exception as e:
                return jsonify({'success': False, 'output': f'Error creating directory: {str(e)}'})
        
        elif command.startswith('rm '):
            # Remove file
            filename = command[3:].strip()
            
            # Handle absolute paths within the share folder
            if filename.startswith('/'):
                filename = filename.lstrip('/')
                file_path = os.path.join(SHARE_FOLDER, filename)
            else:
                file_path = os.path.join(working_dir, filename)
            
            # Check if it's within bounds
            if os.path.commonpath([file_path]) != os.path.commonpath([SHARE_FOLDER]):
                return jsonify({'success': False, 'output': 'Access denied: Cannot remove files outside of the share folder'})
            
            if os.path.isfile(file_path):
                try:
                    os.remove(file_path)
                    return jsonify({'success': True, 'output': f'File removed: {filename}'})
                except Exception as e:
                    return jsonify({'success': False, 'output': f'Error removing file: {str(e)}'})
            else:
                return jsonify({'success': False, 'output': 'File not found'})
        
        elif command.startswith('rmdir '):
            # Remove directory
            dirname = command[6:].strip()
            
            # Handle absolute paths within the share folder
            if dirname.startswith('/'):
                dirname = dirname.lstrip('/')
                dir_path = os.path.join(SHARE_FOLDER, dirname)
            else:
                dir_path = os.path.join(working_dir, dirname)
            
            # Check if it's within bounds
            if os.path.commonpath([dir_path]) != os.path.commonpath([SHARE_FOLDER]):
                return jsonify({'success': False, 'output': 'Access denied: Cannot remove directories outside of the share folder'})
            
            if os.path.isdir(dir_path):
                try:
                    os.rmdir(dir_path)
                    return jsonify({'success': True, 'output': f'Directory removed: {dirname}'})
                except OSError as e:
                    if "Directory not empty" in str(e):
                        return jsonify({'success': False, 'output': 'Directory is not empty. Use rm -rf to forcefully remove.'})
                    else:
                        return jsonify({'success': False, 'output': f'Error removing directory: {str(e)}'})
            else:
                return jsonify({'success': False, 'output': 'Directory not found'})
        
        elif command.startswith('echo '):
            # Echo text
            text = command[5:]
            return jsonify({'success': True, 'output': text})
        
        # For other commands, use the execute_command function
        # But restrict access to certain commands for security
        restricted_commands = ['rm -rf /', 'format', 'del /f', 'deltree', 'rd /s', 'mkfs']
        for restricted in restricted_commands:
            if restricted in command.lower():
                return jsonify({'success': False, 'output': 'Command restricted for security reasons'})
        
        # Log the command execution
        logger.info(f"Terminal command executed: '{command}' by {request.user.get('username')} from IP: {get_ip()}")
        
        # Execute the command
        result = execute_command(f'cd "{working_dir}" && {command}')
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error in terminal command execution: {str(e)}")
        return jsonify({'success': False, 'output': f'Error: {str(e)}'})

@app.route('/backup')
@admin_required
def create_backup_route():
    """Create a backup of all files (admin only)."""
    token = request.args.get('token') or session.get('token')
    
    try:
        backup_dir = create_backup()
        return redirect(url_for('dashboard', token=token, message=f"Backup created successfully at {backup_dir}", message_type="success"))
    except Exception as e:
        logger.error(f"Error creating backup: {str(e)}")
        return redirect(url_for('dashboard', token=token, message=f"Error creating backup: {str(e)}", message_type="error"))

@app.route('/logs')
@admin_required
def view_logs():
    """View system logs (admin only)."""
    token = request.args.get('token') or session.get('token')
    
    try:
        log_file = os.path.join(LOG_FOLDER, 'server.log')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.readlines()
                logs.reverse()  # Most recent logs first
                logs = logs[:1000]  # Limit to 1000 log entries
        else:
            logs = ["No logs found."]
        
        return render_template_string(LOG_VIEW_HTML, logs=logs, token=token)
    except Exception as e:
        logger.error(f"Error reading logs: {str(e)}")
        return redirect(url_for('dashboard', token=token, message=f"Error reading logs: {str(e)}", message_type="error"))

@app.route('/logs/download')
@admin_required
def download_logs():
    """Download system logs (admin only)."""
    token = request.args.get('token') or session.get('token')
    
    try:
        log_file = os.path.join(LOG_FOLDER, 'server.log')
        if os.path.exists(log_file):
            return send_file(log_file, as_attachment=True, download_name="server_logs.log")
        else:
            return redirect(url_for('dashboard', token=token, message="No logs found", message_type="error"))
    except Exception as e:
        logger.error(f"Error downloading logs: {str(e)}")
        return redirect(url_for('dashboard', token=token, message=f"Error downloading logs: {str(e)}", message_type="error"))

@app.route('/logs/clear')
@admin_required
def clear_logs():
    """Clear system logs (admin only)."""
    token = request.args.get('token') or session.get('token')
    
    try:
        log_file = os.path.join(LOG_FOLDER, 'server.log')
        if os.path.exists(log_file):
            # Backup logs before clearing
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_log = os.path.join(LOG_FOLDER, f'server_backup_{timestamp}.log')
            shutil.copy2(log_file, backup_log)
            
            # Clear the logs
            with open(log_file, 'w') as f:
                f.write(f"Logs cleared at {datetime.datetime.now()} by {request.user.get('username')}\n")
            
            logger.info(f"Logs cleared by admin: {request.user.get('username')} from IP: {get_ip()}")
            return redirect(url_for('dashboard', token=token, message="Logs cleared successfully", message_type="success"))
        else:
            return redirect(url_for('dashboard', token=token, message="No logs found", message_type="error"))
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return redirect(url_for('dashboard', token=token, message=f"Error clearing logs: {str(e)}", message_type="error"))

@app.route('/stats')
@admin_required
def view_stats():
    """View system statistics (admin only)."""
    token = request.args.get('token') or session.get('token')
    
    try:
        # Calculate storage statistics
        total_size = 0
        file_count = 0
        
        for root, _, files in os.walk(SHARE_FOLDER):
            for filename in files:
                filepath = os.path.join(root, filename)
                total_size += os.path.getsize(filepath)
                file_count += 1
        
        # Format total size
        if total_size < 1024:
            total_size_str = f"{total_size} B"
        elif total_size < 1024 * 1024:
            total_size_str = f"{total_size / 1024:.1f} KB"
        elif total_size < 1024 * 1024 * 1024:
            total_size_str = f"{total_size / (1024 * 1024):.1f} MB"
        else:
            total_size_str = f"{total_size / (1024 * 1024 * 1024):.1f} GB"
        
        # Calculate average file size
        avg_file_size = total_size / file_count if file_count > 0 else 0
        if avg_file_size < 1024:
            avg_file_size_str = f"{avg_file_size:.1f} B"
        elif avg_file_size < 1024 * 1024:
            avg_file_size_str = f"{avg_file_size / 1024:.1f} KB"
        else:
            avg_file_size_str = f"{avg_file_size / (1024 * 1024):.1f} MB"
        
        disk_usage = psutil.disk_usage(SHARE_FOLDER)

        # Calculate the free space and total space
        disk_free = disk_usage.free
        disk_total = disk_usage.total
        disk_usage_percent = disk_usage.percent

        # Format disk free space
        if disk_free < 1024 * 1024:
            disk_free_str = f"{disk_free / 1024:.1f} KB"
        elif disk_free < 1024 * 1024 * 1024:
            disk_free_str = f"{disk_free / (1024 * 1024):.1f} MB"
        else:
            disk_free_str = f"{disk_free / (1024 * 1024 * 1024):.1f} GB"
        
        # Simulate other statistics (for demonstration)
        start_time = os.path.getmtime(LOG_FOLDER)
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(start_time)
        uptime_str = str(uptime).split('.')[0]  # Remove microseconds
        
        # Find last backup
        backup_times = []
        for dir_name in os.listdir(BACKUP_FOLDER):
            if dir_name.startswith("backup_"):
                backup_time = os.path.getmtime(os.path.join(BACKUP_FOLDER, dir_name))
                backup_times.append(backup_time)
        
        if backup_times:
            last_backup = datetime.datetime.fromtimestamp(max(backup_times)).strftime('%Y-%m-%d %H:%M:%S')
        else:
            last_backup = "Never"
        
        # Count failed auth attempts from logs
        failed_auth_attempts = 0
        successful_logins = 0
        try:
            log_file = os.path.join(LOG_FOLDER, 'server.log')
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    for line in f:
                        if "Failed login attempt" in line:
                            failed_auth_attempts += 1
                        elif "Successful login" in line:
                            successful_logins += 1
        except:
            pass
        
        # Prepare stats dictionary
        stats = {
            'file_count': file_count,
            'total_size': total_size_str,
            'avg_file_size': avg_file_size_str,
            'disk_free': disk_free_str,
            'disk_usage_percent': round(disk_usage_percent, 1),
            'uptime': uptime_str,
            'cpu_usage': round(psutil.cpu_percent(interval=0.1) / 10, 1),  # Simulated CPU usage
            'memory_usage': round(75.5, 1),  # Simulated memory usage
            'request_count': 1000,  # Simulated request count
            'failed_auth_attempts': failed_auth_attempts,
            'successful_logins': successful_logins,
            'last_backup': last_backup,
            'file_ops': failed_auth_attempts + successful_logins + file_count * 2  # Simulated file operations
        }
        
        return render_template_string(STATS_HTML, stats=stats, token=token)
    except Exception as e:
        logger.error(f"Error generating stats: {str(e)}")
        return redirect(url_for('dashboard', token=token, message=f"Error generating stats: {str(e)}", message_type="error"))

#
    
# === ERROR HANDLERS ===
@app.errorhandler(403)
def forbidden(e):
    return render_template_string(
        ERROR_HTML,
        error_code=403,
        error_message="You don't have permission to access this resource.",
        back_url=url_for('dashboard') if session.get('token') else url_for('login')
    ), 403

@app.errorhandler(404)
def not_found(e):
    return render_template_string(
        ERROR_HTML,
        error_code=404,
        error_message="The requested resource was not found on this server.",
        back_url=url_for('dashboard') if session.get('token') else url_for('login')
    ), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template_string(
        ERROR_HTML,
        error_code=500,
        error_message="An internal server error occurred.",
        back_url=url_for('dashboard') if session.get('token') else url_for('login')
    ), 500


def websocket_server():
    """Simple WebSocket server for real-time notifications."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 8765))
    server_socket.listen(5)
    logger.info("WebSocket server started on port 8765")
    
    clients = []
    
    try:
        while True:
            client_socket, addr = server_socket.accept()
            logger.info(f"WebSocket connection from {addr}")
            clients.append(client_socket)
            
            # Handle client in a separate thread
            threading.Thread(target=handle_client, args=(client_socket, clients)).start()
    except Exception as e:
        logger.error(f"WebSocket server error: {str(e)}")
    finally:
        server_socket.close()

def handle_client(client_socket, clients):
    """Handle WebSocket client connection."""
    try:
        # Send welcome message
        message = "Connected to secure file server notifications"
        client_socket.send(message.encode('utf-8'))
        
        # Keep connection open and handle messages
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            
            # Echo back for testing
            client_socket.send(data)
    except Exception as e:
        logger.error(f"WebSocket client error: {str(e)}")
    finally:
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()

def broadcast_notification(message):
    """Send notification to all connected WebSocket clients."""
    for client in clients:
        try:
            client.send(message.encode('utf-8'))
        except:
            pass

# === PERIODIC TASKS ===
def run_scheduled_tasks():
    """Run scheduled maintenance tasks."""
    while True:
        try:
            # Create daily backup
            if datetime.datetime.now().hour == 3:  # 3 AM
                create_backup()
                logger.info("Scheduled daily backup created")
            
            # Clean up temporary files
            cleanup_temp_files()
            
            # Sleep for an hour
            time.sleep(3600)
        except Exception as e:
            logger.error(f"Scheduled task error: {str(e)}")
            time.sleep(3600)

def cleanup_temp_files():
    """Clean up temporary files older than 24 hours."""
    try:
        now = time.time()
        for filename in os.listdir(TEMP_FOLDER):
            file_path = os.path.join(TEMP_FOLDER, filename)
            if os.path.isfile(file_path) and os.path.getmtime(file_path) < now - 86400:
                os.remove(file_path)
                logger.info(f"Cleaned up temporary file: {filename}")
    except Exception as e:
        logger.error(f"Error cleaning up temporary files: {str(e)}")

# === HTTP TO HTTPS REDIRECT ===
def redirect_http_to_https():
    """Redirect HTTP traffic to HTTPS."""
    http_app = Flask(__name__)
    
    @http_app.route('/', defaults={'path': ''})
    @http_app.route('/<path:path>')
    def redirect_to_https(path):
        return redirect(f"https://{request.host.split(':')[0]}:{HTTPS_PORT}/{path}", code=301)
    
    http_app.run(host='0.0.0.0', port=HTTP_PORT)

# === MAIN APPLICATION ENTRY POINT ===
if __name__ == "__main__":
    # Print welcome banner
    print("""
    ╔════════════════════════════════════════════════════╗
    ║                                                    ║
    ║   Come on baby                    ║
    ║                                                    ║
    ╚════════════════════════════════════════════════════╝
    """)
    
    # Create necessary directories
    for folder in [SHARE_FOLDER, TEMP_FOLDER, LOG_FOLDER, BACKUP_FOLDER]:
        os.makedirs(folder, exist_ok=True)
        
    # Log startup information
    logger.info(f"Starting secure file server on port {HTTPS_PORT}")
    logger.info(f"Share folder: {SHARE_FOLDER}")
    logger.info(f"Temporary folder: {TEMP_FOLDER}")
    logger.info(f"Log folder: {LOG_FOLDER}")
    logger.info(f"Backup folder: {BACKUP_FOLDER}")
    
    # Check for SSL certificate and key
    if not os.path.exists(SSL_CERT) or not os.path.exists(SSL_KEY):
        logger.warning("SSL certificate or key not found, generating self-signed certificate...")
        from OpenSSL import crypto
        
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "Organizational Unit"
        cert.get_subject().CN = socket.gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # Save certificate and key
        with open(SSL_CERT, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(SSL_KEY, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        logger.info("Self-signed certificate generated")
    
    # Start HTTP redirect server in a separate thread
    threading.Thread(target=redirect_http_to_https, daemon=True).start()
    
    clients = []  
    threading.Thread(target=websocket_server, daemon=True).start()
    
    threading.Thread(target=run_scheduled_tasks, daemon=True).start()
    
    create_backup()
    
    try:
        ssl_context = (SSL_CERT, SSL_KEY)
        app.run(host='0.0.0.0', port=HTTPS_PORT, ssl_context=ssl_context, threaded=True)
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}")
        print(f"Error: {str(e)}")
