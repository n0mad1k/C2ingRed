#!/usr/bin/env python3

import os
import json
import sys
import logging
import ipaddress
import string
from pathlib import Path

class TrackerConfig:
    """Enhanced configuration manager for tracker deployments"""
    
    def __init__(self, config_path=None):
        self.logger = self._setup_logger()
        self.config_path = config_path
        self.config = {
            "engagement": {
                "name": ""
            },
            "server": {
                "port": 443,
                "working_dir": "",
                "log_dir": "",
                "domain": "",
                "email": "",
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
                "project_dir_base": "",
                "script_dir": "Tools/",
                "index_file": "index.html",
                "requirements_file": "requirements.txt",
                "capture_server_script": "capture-server.py",
                "log_cleanup_script": "log_cleanup.py",
                "specific_logs": [
                    "log.txt",
                    "email_open_log.txt"
                ]
            },
            "tracking": {
                "email_pixel": True,
                "form_capture": True,
                "browser_data": True,
                "detailed_logging": True
            },
            "integration": {
                "c2_server": "",
                "notification_webhook": "",
                "enable_notifications": False
            }
        }
        
        if config_path and os.path.exists(config_path):
            self.load_config()
    
    def _setup_logger(self):
        """Set up a logger for the config module"""
        logger = logging.getLogger("TrackerConfig")
        logger.setLevel(logging.INFO)
        
        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        ch.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(ch)
        
        return logger
    
    def load_config(self):
        """Load configuration from a file"""
        try:
            with open(self.config_path, 'r') as f:
                loaded_config = json.load(f)
                # Update our config with the loaded values
                self._update_nested_dict(self.config, loaded_config)
                self.logger.info(f"Configuration loaded from {self.config_path}")
                return True
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in configuration file: {e}")
            return False
    
    def _update_nested_dict(self, d, u):
        """Recursively update a nested dictionary"""
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._update_nested_dict(d[k], v)
            else:
                d[k] = v
    
    def save_config(self, path=None):
        """Save configuration to a file"""
        save_path = path or self.config_path
        if not save_path:
            self.logger.error("No configuration path specified")
            return False
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, 'w') as f:
                json.dump(self.config, f, indent=2)
                
            self.logger.info(f"Configuration saved to {save_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return False
    
    def validate(self):
        """Validate the configuration"""
        errors = []
        warnings = []
        
        # Check required fields
        required_fields = {
            "engagement.name": "Engagement name",
            "server.domain": "Server domain",
            "server.email": "Admin email",
            "server.working_dir": "Working directory",
            "server.log_dir": "Log directory"
        }
        
        for field, description in required_fields.items():
            value = self.get_nested(field)
            if not value:
                errors.append(f"Missing required field: {description} ({field})")
        
        # Validate domain format
        if self.config["server"]["domain"]:
            if not self._is_valid_domain(self.config["server"]["domain"]):
                errors.append(f"Invalid domain format: {self.config['server']['domain']}")
        
        # Validate email format
        if self.config["server"]["email"]:
            if not self._is_valid_email(self.config["server"]["email"]):
                errors.append(f"Invalid email format: {self.config['server']['email']}")
        
        # Validate directories
        if self.config["server"]["working_dir"]:
            working_dir = os.path.expanduser(self.config["server"]["working_dir"])
            if not os.path.exists(working_dir):
                warnings.append(f"Working directory does not exist: {working_dir}")
        
        # Validate IPInfo token if tracking is enabled
        if self.config["tracking"]["detailed_logging"] and not self.config["ipinfo"]["token"]:
            warnings.append("IPInfo token not set, geolocation data will be limited")
        
        # Print validation results
        for error in errors:
            self.logger.error(f"Validation error: {error}")
        
        for warning in warnings:
            self.logger.warning(f"Validation warning: {warning}")
        
        is_valid = len(errors) == 0
        if is_valid:
            self.logger.info("Configuration validated successfully")
        
        return is_valid
    
    def get_nested(self, path):
        """Get a nested configuration value using dot notation"""
        keys = path.split('.')
        value = self.config
        for key in keys:
            if key in value:
                value = value[key]
            else:
                return None
        return value
    
    def set_nested(self, path, value):
        """Set a nested configuration value using dot notation"""
        keys = path.split('.')
        d = self.config
        for key in keys[:-1]:
            if key not in d:
                d[key] = {}
            d = d[key]
        d[keys[-1]] = value
    
    def _is_valid_domain(self, domain):
        """Check if a domain name is valid"""
        if not domain:
            return False
        
        # Simple domain validation
        allowed = string.ascii_letters + string.digits + '.-'
        if not all(c in allowed for c in domain):
            return False
        
        # Check if domain has at least one dot and no consecutive dots
        if '.' not in domain or '..' in domain:
            return False
        
        # Check if domain ends with a valid TLD (simplistic approach)
        parts = domain.split('.')
        if len(parts[-1]) < 2:
            return False
        
        return True
    
    def _is_valid_email(self, email):
        """Check if an email address is valid"""
        if not email:
            return False
        
        # Basic email validation
        if '@' not in email:
            return False
        
        username, domain = email.split('@', 1)
        if not username or not domain:
            return False
        
        return self._is_valid_domain(domain)
    
    def generate_sample_config(self, output_path):
        """Generate a sample configuration file"""
        sample_config = {
            "engagement": {
                "name": "demo-engagement"
            },
            "server": {
                "port": 443,
                "working_dir": "~/trackers/demo-engagement",
                "log_dir": "~/trackers/demo-engagement/logs",
                "domain": "tracker.example.com",
                "email": "admin@example.com",
                "ssl_cert": {
                    "cert_dir": "/etc/letsencrypt/live/",
                    "cert_file": "fullchain.pem",
                    "key_file": "privkey.pem"
                }
            },
            "ipinfo": {
                "token": "your-ipinfo-token-here"
            },
            "cleanup": {
                "retention_days": 7
            },
            "paths": {
                "project_dir_base": "~/trackers/",
                "script_dir": "Tools/",
                "index_file": "index.html",
                "requirements_file": "requirements.txt",
                "capture_server_script": "capture-server.py",
                "log_cleanup_script": "log_cleanup.py",
                "specific_logs": [
                    "log.txt",
                    "email_open_log.txt"
                ]
            },
            "tracking": {
                "email_pixel": True,
                "form_capture": True,
                "browser_data": True,
                "detailed_logging": True
            },
            "integration": {
                "c2_server": "https://c2.example.com",
                "notification_webhook": "https://webhook.example.com/notify",
                "enable_notifications": False
            }
        }
        
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(sample_config, f, indent=2)
            self.logger.info(f"Sample configuration generated at {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error generating sample configuration: {e}")
            return False

def main():
    """Command-line interface for the config module"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Tracker configuration manager")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate a configuration file")
    validate_parser.add_argument("config_path", help="Path to the configuration file")
    
    # Generate command
    generate_parser = subparsers.add_parser("generate", help="Generate a sample configuration file")
    generate_parser.add_argument("output_path", help="Path for the output configuration file")
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update a configuration file")
    update_parser.add_argument("config_path", help="Path to the configuration file")
    update_parser.add_argument("--set", nargs=2, action="append", metavar=("KEY", "VALUE"),
                             help="Set a configuration value (can be used multiple times)")
    
    args = parser.parse_args()
    
    if args.command == "validate":
        config = TrackerConfig(args.config_path)
        if config.validate():
            print("Configuration is valid.")
            return 0
        else:
            print("Configuration is invalid. See errors above.")
            return 1
    
    elif args.command == "generate":
        config = TrackerConfig()
        if config.generate_sample_config(args.output_path):
            print(f"Sample configuration generated at {args.output_path}")
            return 0
        else:
            print("Failed to generate sample configuration.")
            return 1
    
    elif args.command == "update":
        config = TrackerConfig(args.config_path)
        if not os.path.exists(args.config_path):
            print(f"Configuration file not found: {args.config_path}")
            return 1
        
        if args.set:
            for key, value in args.set:
                # Handle different value types
                if value.lower() == "true":
                    value = True
                elif value.lower() == "false":
                    value = False
                elif value.isdigit():
                    value = int(value)
                config.set_nested(key, value)
            
            if config.save_config():
                print(f"Configuration updated at {args.config_path}")
                return 0
            else:
                print("Failed to update configuration.")
                return 1
        else:
            print("No updates specified.")
            return 0
    
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())