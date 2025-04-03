#!/usr/bin/env python3

import os
import sys
import json
import argparse
import subprocess
import shutil
import time
import random
import string
import socket
import requests
from pathlib import Path

class TrackerDeployer:
    def __init__(self, args):
        self.args = args
        self.config = {}
        self.project_dir = ""
        self.script_dir = ""
        self.templates_dir = ""
        self.engagement_name = args.engagement_name or self.generate_engagement_name()
        
    def generate_engagement_name(self):
        """Generate a random engagement name if not provided"""
        prefix = "track"
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{prefix}-{suffix}"
        
    def create_directory_structure(self):
        """Create the necessary directory structure"""
        print(f"[+] Creating directory structure for engagement: {self.engagement_name}")
        
        # Create base directories
        self.project_dir = os.path.expanduser(f"~/trackers/{self.engagement_name}")
        self.script_dir = f"{self.project_dir}/Tools"
        self.templates_dir = f"{self.project_dir}/templates"
        
        # Create all directories
        for directory in [self.project_dir, self.script_dir, f"{self.project_dir}/logs", 
                         f"{self.project_dir}/certs", self.templates_dir]:
            os.makedirs(directory, exist_ok=True)
            
        print(f"[+] Created directory structure at {self.project_dir}")
        return True
        
    def copy_scripts(self):
        """Copy all necessary scripts to the project directory"""
        print("[+] Copying tracking scripts to project directory")
        
        # Define source and destination paths
        src_dir = os.path.dirname(os.path.abspath(__file__))
        tools_src = os.path.join(src_dir, "Tools")
        
        # Copy all tools
        try:
            for item in os.listdir(tools_src):
                s = os.path.join(tools_src, item)
                d = os.path.join(self.script_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)
            
            # Make scripts executable
            subprocess.run(["chmod", "+x", f"{self.script_dir}/capture-server.py"])
            subprocess.run(["chmod", "+x", f"{self.script_dir}/log_cleanup.py"])
            subprocess.run(["chmod", "+x", f"{self.script_dir}/setup.sh"])
            
            print("[+] Scripts copied successfully")
            return True
        except Exception as e:
            print(f"[!] Error copying scripts: {e}")
            return False
    
    def generate_config(self):
        """Generate configuration file based on user inputs"""
        print("[+] Generating configuration file")
        
        # Load template config
        template_path = os.path.join(self.script_dir, "template-config.yaml")
        try:
            with open(template_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            print(f"[!] Error loading template config: {e}")
            return False
        
        # Update config with user inputs
        self.config["engagement"]["name"] = self.engagement_name
        self.config["server"]["domain"] = self.args.domain
        self.config["server"]["email"] = self.args.email
        self.config["server"]["working_dir"] = os.path.expanduser(f"~/trackers/{self.engagement_name}")
        self.config["server"]["log_dir"] = os.path.expanduser(f"~/trackers/{self.engagement_name}/logs")
        self.config["ipinfo"]["token"] = self.args.ipinfo_token
        self.config["paths"]["project_dir_base"] = os.path.expanduser("~/trackers/")
        
        # Write the config file
        config_path = os.path.join(self.project_dir, "config.json")
        try:
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"[+] Configuration saved to {config_path}")
            return True
        except Exception as e:
            print(f"[!] Error saving configuration: {e}")
            return False
    
    def setup_tracking_page(self):
        """Set up the tracking page based on the specified option"""
        print("[+] Setting up tracking page")
        
        if self.args.clone_url:
            print(f"[+] Cloning tracking page from {self.args.clone_url}")
            clone_script = os.path.join(self.script_dir, "site-cloner/sitecloner.py")
            clone_cmd = [
                "python3", clone_script,
                self.args.clone_url,
                self.project_dir,
                "--debug"
            ]
            
            try:
                subprocess.run(clone_cmd, check=True)
                print("[+] Site cloned successfully")
                return True
            except subprocess.CalledProcessError as e:
                print(f"[!] Error cloning site: {e}")
                return False
        elif self.args.template:
            print(f"[+] Using template: {self.args.template}")
            # TODO: Implement template selection
            print("[!] Template selection not yet implemented")
            return False
        else:
            # Create a basic tracking page
            index_path = os.path.join(self.project_dir, "index.html")
            with open(index_path, 'w') as f:
                f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Tracking Page</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div id="content">
        <p>Tracking page active.</p>
    </div>
    <script>
        // Basic tracking script
        document.addEventListener('DOMContentLoaded', function() {
            fetch('/log', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    userAgent: navigator.userAgent,
                    cookies: document.cookie,
                    screenResolution: `${window.screen.width}x${window.screen.height}`,
                    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    referrer: document.referrer
                })
            })
            .then(response => console.log('Tracking data sent'))
            .catch(error => console.error('Error sending tracking data:', error));
        });
    </script>
</body>
</html>''')
            print(f"[+] Created basic tracking page at {index_path}")
            return True
    
    def install_dependencies(self):
        """Install all required dependencies"""
        print("[+] Installing dependencies")
        
        # Install system packages
        system_packages = [
            "python3-pip", "python3-venv", "certbot", "python3-certbot",
            "chromium-browser", "chromium-driver"
        ]
        
        try:
            subprocess.run(["sudo", "apt-get", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "-y"] + system_packages, check=True)
            
            # Install Python packages
            requirements_path = os.path.join(self.script_dir, "requirements.txt")
            subprocess.run(["pip3", "install", "-r", requirements_path], check=True)
            
            # Install site-cloner requirements
            sitecloner_req_path = os.path.join(self.script_dir, "site-cloner/requirements.txt")
            subprocess.run(["pip3", "install", "-r", sitecloner_req_path], check=True)
            
            print("[+] Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Error installing dependencies: {e}")
            return False
    
    def setup_ssl(self):
        """Set up SSL certificates using Let's Encrypt or create self-signed for IP-only"""
        if self.args.ip_only:
            return self.setup_self_signed_ssl()
            
        if not self.args.setup_ssl:
            print("[*] Skipping SSL setup")
            return True
            
        print("[+] Setting up SSL certificates using Let's Encrypt")
        
        try:
            certbot_cmd = [
                "sudo", "certbot", "certonly", "--standalone",
                "--non-interactive", "--agree-tos",
                "-m", self.args.email,
                "-d", self.args.domain
            ]
            
            subprocess.run(certbot_cmd, check=True)
            print("[+] SSL certificates obtained successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Error obtaining SSL certificates: {e}")
            return False
            
    def setup_self_signed_ssl(self):
        """Create self-signed SSL certificates for IP-only mode"""
        print("[+] Creating self-signed SSL certificates for IP-only mode")
        
        cert_dir = os.path.join(self.project_dir, "certs")
        os.makedirs(cert_dir, exist_ok=True)
        
        key_path = os.path.join(cert_dir, "server.key")
        cert_path = os.path.join(cert_dir, "server.crt")
        
        try:
            # Generate private key
            subprocess.run([
                "openssl", "genrsa", 
                "-out", key_path, 
                "2048"
            ], check=True)
            
            # Generate self-signed certificate (valid for 1 year)
            subprocess.run([
                "openssl", "req", 
                "-new", 
                "-key", key_path, 
                "-out", os.path.join(cert_dir, "server.csr"),
                "-subj", f"/CN=TrackServer/O=Security/C=US"
            ], check=True)
            
            subprocess.run([
                "openssl", "x509", 
                "-req", 
                "-days", "365", 
                "-in", os.path.join(cert_dir, "server.csr"), 
                "-signkey", key_path, 
                "-out", cert_path
            ], check=True)
            
            # Set permissions
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o600)
            
            # Update config to use these certificates
            self.config["server"]["ssl_cert"]["cert_dir"] = cert_dir
            self.config["server"]["ssl_cert"]["cert_file"] = "server.crt"
            self.config["server"]["ssl_cert"]["key_file"] = "server.key"
            
            if self.generate_config():
                print("[+] Self-signed SSL certificates created successfully")
                return True
            else:
                print("[!] Failed to update configuration with self-signed certificate paths")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"[!] Error creating self-signed certificates: {e}")
            return False
    
    def create_systemd_service(self):
        """Create and enable a systemd service for the capture server"""
        print("[+] Creating systemd service")
        
        service_name = f"tracker-{self.engagement_name}.service"
        service_path = f"/etc/systemd/system/{service_name}"
        
        service_content = f'''[Unit]
Description=Tracking Server for {self.engagement_name}
After=network.target

[Service]
ExecStart=/usr/bin/python3 {self.script_dir}/capture-server.py
WorkingDirectory={self.project_dir}
StandardOutput=journal
StandardError=journal
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
'''
        
        try:
            with open("/tmp/tracker-service", 'w') as f:
                f.write(service_content)
                
            subprocess.run(["sudo", "mv", "/tmp/tracker-service", service_path], check=True)
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(["sudo", "systemctl", "enable", service_name], check=True)
            subprocess.run(["sudo", "systemctl", "start", service_name], check=True)
            
            print(f"[+] Service '{service_name}' created and started")
            return True
        except Exception as e:
            print(f"[!] Error creating systemd service: {e}")
            return False
    
    def setup_cron_jobs(self):
        """Set up cron jobs for log rotation and cleanup"""
        print("[+] Setting up cron jobs for log maintenance")
        
        cron_job = f"0 0 * * * /usr/bin/python3 {self.script_dir}/log_cleanup.py > {self.project_dir}/logs/cron.log 2>&1\n"
        
        try:
            # Write to temporary file and then use crontab
            with open("/tmp/tracker-cron", 'w') as f:
                # Get existing crontab
                try:
                    existing_cron = subprocess.check_output(["crontab", "-l"]).decode()
                    f.write(existing_cron)
                except subprocess.CalledProcessError:
                    # No existing crontab
                    pass
                
                # Add our cron job
                f.write(cron_job)
            
            # Install new crontab
            subprocess.run(["crontab", "/tmp/tracker-cron"], check=True)
            print("[+] Cron job installed successfully")
            return True
        except Exception as e:
            print(f"[!] Error setting up cron job: {e}")
            return False
    
    def create_tracking_pixel(self):
        """Create a tracking pixel for email tracking"""
        if not self.args.create_pixel:
            print("[*] Skipping tracking pixel creation")
            return True
            
        print("[+] Creating tracking pixel")
        
        pixel_dir = os.path.join(self.project_dir, "pixel")
        os.makedirs(pixel_dir, exist_ok=True)
        
        # Generate HTML sample
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Email Tracking Pixel</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>Email Tracking Pixel</h1>
    <p>Use the following HTML in your emails:</p>
    <pre>&lt;img src="https://{self.args.domain}/track-open?email=target@example.com" width="1" height="1" alt="" style="display:none;"&gt;</pre>
    <p>Replace target@example.com with the recipient's email or any identifier.</p>
</body>
</html>'''
        
        with open(os.path.join(pixel_dir, "index.html"), 'w') as f:
            f.write(html_content)
            
        print(f"[+] Tracking pixel documentation created at {pixel_dir}/index.html")
        return True
    
    def print_summary(self):
        """Print a summary of the deployment"""
        print("\n" + "="*50)
        print(f"TRACKER DEPLOYMENT SUMMARY: {self.engagement_name}")
        print("="*50)
        print(f"• Deployment Directory: {self.project_dir}")
        
        # Get server address based on deployment mode
        if self.args.ip_only:
            server_ip = self.get_server_ip()
            print(f"• Server IP: {server_ip}")
            protocol = "http"
            if self.args.setup_ssl or hasattr(self, 'config') and self.config.get("server", {}).get("ssl_cert"):
                protocol = "https"
            server_address = server_ip
            print(f"• Mode: IP-based (No domain)")
        else:
            protocol = "https" if self.args.setup_ssl else "http"
            server_address = self.args.domain
            print(f"• Domain: {self.args.domain}")
            
        if self.args.email:
            print(f"• Admin Email: {self.args.email}")
            
        print(f"• Tracking Server URL: {protocol}://{server_address}")
        
        if self.args.create_pixel:
            print(f"• Email Tracking Pixel: {protocol}://{server_address}/track-open?email=TARGET_EMAIL")
            
        print(f"• Log Directory: {self.project_dir}/logs")
        
        print("\nTo view logs:")
        print(f"  tail -f {self.project_dir}/logs/server.log")
        
        if not self.args.no_service:
            print("\nTo check service status:")
            print(f"  systemctl status tracker-{self.engagement_name}")
            print("\nTo stop the service:")
            print(f"  sudo systemctl stop tracker-{self.engagement_name}")
        else:
            print("\nQuick deployment mode: Server running in current terminal.")
            print("Press Ctrl+C to stop the server if running.")
            print("\nTo start the server manually:")
            print(f"  python3 {self.script_dir}/capture-server.py --config {self.project_dir}/config.json")
            
        print("="*50)
        
    def get_server_ip(self):
        """Get the server's public IP address"""
        try:
            # Try multiple IP detection services
            services = [
                "https://api.ipify.org",
                "https://ifconfig.me/ip",
                "https://ip.42.pl/raw"
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        print(f"[+] Detected server IP: {ip}")
                        return ip
                except Exception:
                    continue
                    
            # Fall back to hostname if API services fail
            ip = socket.gethostbyname(socket.gethostname())
            print(f"[+] Using hostname-derived IP: {ip}")
            return ip
            
        except Exception as e:
            print(f"[!] Error detecting server IP: {e}")
            print("[!] Please manually specify your server IP in the configuration")
            return "127.0.0.1"  # Fallback

    def run_quick_deploy(self):
        """Run a simplified deployment for quick/temporary usage"""
        print("[+] Running quick deployment...")
        
        # Minimal steps needed for quick deployment
        quick_steps = [
            self.create_directory_structure,
            self.copy_scripts,
            self.generate_config,
        ]
        
        # Add SSL setup if needed (self-signed for IP-only)
        if self.args.ip_only or self.args.setup_ssl:
            quick_steps.append(self.setup_ssl)
        
        # Create a basic tracking page if not cloning
        if not self.args.clone_url:
            quick_steps.append(self.setup_tracking_page)
        
        success = True
        for step in quick_steps:
            if not step():
                success = False
                print(f"[!] Quick deployment step failed: {step.__name__}")
                if self.args.abort_on_error:
                    return False
        
        if not success:
            print("[!] Quick deployment completed with errors")
            return False
            
        # Start the server directly if --no-service is specified
        if self.args.no_service:
            print("\n[+] Starting tracker server directly...")
            server_script = os.path.join(self.script_dir, "capture-server.py")
            print(f"\n[+] To track emails, use: http://{self.config['server']['domain'] or self.get_server_ip()}/track-open?email=TARGET_EMAIL")
            print(f"[+] Press Ctrl+C to stop the server\n")
            
            try:
                # Run the server directly
                cmd = [
                    "python3",
                    server_script,
                    "--config", os.path.join(self.project_dir, "config.json"),
                ]
                
                if self.args.minimal:
                    cmd.append("--minimal")
                    
                os.execvp("python3", cmd)  # Replace current process with the server
                
            except Exception as e:
                print(f"[!] Error starting server: {e}")
                return False
                
        self.print_summary()
        return True
            
    def deploy(self):
        """Run the complete deployment process"""
        # Handle IP-only mode
        if self.args.ip_only:
            print("[+] Running IP-based deployment (no domain required)")
            server_ip = self.get_server_ip()
            
            # Update config with IP instead of domain if in IP-only mode
            if not self.args.domain:
                self.args.domain = server_ip
                
        # Quick deployment mode
        if self.args.quick_deploy:
            return self.run_quick_deploy()
            
        # Regular full deployment
        steps = [
            self.create_directory_structure,
            self.copy_scripts,
            self.generate_config,
            self.install_dependencies,
            self.setup_tracking_page,
            self.setup_ssl,
        ]
        
        # Add systemd service unless --no-service is specified
        if not self.args.no_service:
            steps.append(self.create_systemd_service)
            steps.append(self.setup_cron_jobs)
            
        if self.args.create_pixel:
            steps.append(self.create_tracking_pixel)
        
        success = True
        for step in steps:
            if not step():
                success = False
                if self.args.abort_on_error:
                    print("[!] Deployment aborted due to error")
                    return False
        
        if success:
            self.print_summary()
            return True
        else:
            print("[!] Deployment completed with errors")
            return False


def parse_arguments():
    parser = argparse.ArgumentParser(description="Deploy a tracking server for red team operations")
    
    # Domain/IP Group - make domain conditionally required unless ip-only is specified
    domain_group = parser.add_argument_group('Domain Configuration')
    domain_group.add_argument("--domain", help="Domain name for the tracking server")
    domain_group.add_argument("--ip-only", action="store_true", help="Use server IP directly (no domain needed)")
    
    # Email is needed for Let's Encrypt but not for ip-only
    parser.add_argument("--email", help="Admin email for Let's Encrypt certificates")
    
    # Quick deployment options
    quick_deploy = parser.add_argument_group('Quick Deployment Options')
    quick_deploy.add_argument("--quick-deploy", action="store_true", help="Quick deployment mode")
    quick_deploy.add_argument("--no-service", action="store_true", help="Don't create a system service")
    quick_deploy.add_argument("--minimal", action="store_true", help="Deploy minimal tracking features")
    quick_deploy.add_argument("--port", type=int, default=443, help="Port for the tracker server (default: 443)")
    
    # Standard optional arguments
    parser.add_argument("--engagement-name", help="Name for this tracking engagement (random if not specified)")
    parser.add_argument("--ipinfo-token", help="IPinfo API token for geolocation data")
    parser.add_argument("--clone-url", help="URL to clone for the tracking page")
    parser.add_argument("--template", help="Template to use for the tracking page")
    parser.add_argument("--setup-ssl", action="store_true", help="Set up SSL certificates using Let's Encrypt")
    parser.add_argument("--create-pixel", action="store_true", help="Create a tracking pixel for email tracking")
    parser.add_argument("--abort-on-error", action="store_true", help="Abort deployment on any error")
    
    args = parser.parse_args()
    
    # Validation logic for required arguments
    if not args.ip_only and not args.domain:
        parser.error("Either --domain or --ip-only is required")
    
    if args.setup_ssl and not args.email:
        parser.error("--email is required when using --setup-ssl")
    
    if not args.ip_only and not args.email:
        parser.error("--email is required unless using --ip-only")
    
    return args


if __name__ == "__main__":
    args = parse_arguments()
    deployer = TrackerDeployer(args)
    success = deployer.deploy()
    sys.exit(0 if success else 1)