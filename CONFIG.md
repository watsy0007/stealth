# Stealth Configuration Guide

Stealth supports two configuration methods:

1. **YAML Configuration** (Recommended) - Structured, easy to read and maintain
2. **Environment Variables** (Legacy) - Backward compatible, works in all environments

## YAML Configuration

### Quick Start

1. **Copy the example configuration:**
   ```bash
   cp config/stealth.yml.example config/stealth.yml
   ```

2. **Edit the configuration:**
   ```bash
   vim config/stealth.yml
   ```

3. **Run Stealth:**
   ```bash
   mix run --no-halt
   # or
   _build/prod/rel/stealth/bin/stealth start
   ```

### YAML Configuration File Location

Stealth looks for configuration files in this order:

1. Path specified by `CONFIG_FILE` environment variable
2. `config/stealth.yml` in the project root
3. Falls back to environment variables if no YAML file found

**Example:**
```bash
# Use custom config file location
export CONFIG_FILE=/etc/stealth/my-config.yml
./bin/stealth start
```

### YAML Configuration Format

```yaml
# Shadowsocks Configuration
shadowsocks:
  enabled: true                    # Enable/disable Shadowsocks
  port: 8088                       # TCP port
  password: "your-secure-password" # Shared secret
  method: "aes_256_gcm"           # Encryption: aes_128_gcm | aes_256_gcm

  websocket:
    enabled: true                  # Enable WebSocket transport
    port: 8089                     # WebSocket port

# Trojan Configuration
trojan:
  enabled: false                   # Enable/disable Trojan
  port: 443                        # SSL/TLS port
  password: "your-secure-password" # Shared secret
  mask_host: "www.bing.com"       # Fallback server for masquerading
  mask_port: 443                   # Fallback server port

  # Optional: SSL certificate paths
  certfile: "/path/to/cert.pem"   # SSL certificate file
  keyfile: "/path/to/key.pem"     # SSL private key file
```

### Configuration Examples

#### Example 1: Shadowsocks Only (Simple Setup)

```yaml
shadowsocks:
  enabled: true
  port: 8088
  password: "my-strong-password-123"
  method: "aes_256_gcm"
  websocket:
    enabled: true
    port: 8089

trojan:
  enabled: false
```

#### Example 2: Trojan Only (HTTPS Disguise)

```yaml
shadowsocks:
  enabled: false

trojan:
  enabled: true
  port: 443
  password: "trojan-secure-password"
  mask_host: "www.google.com"
  mask_port: 443
  certfile: "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
  keyfile: "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
```

#### Example 3: Both Protocols Enabled

```yaml
shadowsocks:
  enabled: true
  port: 8088
  password: "shadowsocks-password"
  method: "aes_256_gcm"
  websocket:
    enabled: true
    port: 8089

trojan:
  enabled: true
  port: 443
  password: "trojan-password"
  mask_host: "www.cloudflare.com"
  mask_port: 443
  certfile: "/etc/ssl/certs/server.crt"
  keyfile: "/etc/ssl/private/server.key"
```

## Environment Variable Configuration

For backward compatibility and container deployments, Stealth still supports environment variables.

**Note:** If a YAML configuration file exists, it takes precedence over environment variables.

### Shadowsocks Environment Variables

```bash
ENABLE_SS=1                      # Enable Shadowsocks (default: 1)
SS_PORT=8088                     # TCP port (default: 8088)
SS_PASSWORD=hello-world          # Shared password (default: hello-world)
SS_METHOD=aes_256_gcm           # Encryption method (default: aes_256_gcm)
SS_WS_ENABLED=1                 # Enable WebSocket (default: 1)
SS_WS_PORT=8089                 # WebSocket port (default: 8089)
```

### Trojan Environment Variables

```bash
ENABLE_TROJAN=0                 # Enable Trojan (default: 0)
TROJAN_PORT=443                 # SSL port (default: 443)
TROJAN_PASSWORD=hello-world     # Shared password (default: hello-world)
TROJAN_MASK_HOST=               # Fallback server host (default: empty)
TROJAN_MASK_PORT=443            # Fallback server port (default: 443)
```

### Using Environment Variables

```bash
# Set environment variables
export SS_PORT=9088
export SS_PASSWORD="my-secure-password"
export SS_METHOD=aes_128_gcm

# Run Stealth
mix run --no-halt
```

## Docker Configuration

### Using YAML Configuration with Docker

**Method 1: Mount config file**
```bash
docker run -d \
  -v /path/to/stealth.yml:/app/config/stealth.yml:ro \
  -p 8088:8088 \
  -p 8089:8089 \
  watsy0007/stealth:latest
```

**Method 2: Use CONFIG_FILE environment variable**
```bash
docker run -d \
  -e CONFIG_FILE=/etc/stealth/custom.yml \
  -v /path/to/custom.yml:/etc/stealth/custom.yml:ro \
  -p 8088:8088 \
  watsy0007/stealth:latest
```

### Using Environment Variables with Docker

```bash
docker run -d \
  -e SS_PORT=8088 \
  -e SS_PASSWORD=my-secure-password \
  -e SS_METHOD=aes_256_gcm \
  -p 8088:8088 \
  -p 8089:8089 \
  watsy0007/stealth:latest
```

### Docker Compose Example

**Using YAML Configuration:**
```yaml
version: '3.8'

services:
  stealth:
    image: watsy0007/stealth:latest
    volumes:
      - ./stealth.yml:/app/config/stealth.yml:ro
    ports:
      - "8088:8088"
      - "8089:8089"
    restart: unless-stopped
```

**Using Environment Variables:**
```yaml
version: '3.8'

services:
  stealth:
    image: watsy0007/stealth:latest
    environment:
      - SS_PORT=8088
      - SS_PASSWORD=my-secure-password
      - SS_METHOD=aes_256_gcm
      - SS_WS_ENABLED=1
      - SS_WS_PORT=8089
    ports:
      - "8088:8088"
      - "8089:8089"
    restart: unless-stopped
```

## Configuration Priority

The configuration loading priority (highest to lowest):

1. **YAML Configuration File** - If exists at `CONFIG_FILE` or `config/stealth.yml`
2. **Environment Variables** - If no YAML file found
3. **Default Values** - Built-in defaults

## Encryption Methods

Stealth supports the following encryption methods:

- `aes_128_gcm` - AES-128 with Galois/Counter Mode (faster, lower CPU usage)
- `aes_256_gcm` - AES-256 with Galois/Counter Mode (stronger, recommended)

## Security Best Practices

### 1. Strong Passwords

❌ **Bad:**
```yaml
password: "123456"
password: "password"
password: "hello-world"
```

✅ **Good:**
```yaml
password: "Kx9$mP2#vL8@nQ5!zR7^wT4&yU6*"
```

Generate secure passwords:
```bash
# Generate 32-character password
openssl rand -base64 24
```

### 2. Use Different Passwords

Use different passwords for Shadowsocks and Trojan:

```yaml
shadowsocks:
  password: "shadowsocks-unique-password-abc123"

trojan:
  password: "trojan-different-password-xyz789"
```

### 3. SSL/TLS Certificates for Trojan

For production Trojan deployments, use valid SSL certificates:

```bash
# Install certbot
sudo apt-get install certbot

# Get Let's Encrypt certificate
sudo certbot certonly --standalone -d yourdomain.com

# Configure in stealth.yml
trojan:
  certfile: "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
  keyfile: "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
```

### 4. File Permissions

Protect your configuration files:

```bash
# Set restrictive permissions
chmod 600 config/stealth.yml

# Verify permissions
ls -l config/stealth.yml
# Should show: -rw------- (read/write for owner only)
```

## Troubleshooting

### Configuration Not Loading

**Check 1: File exists**
```bash
ls -l config/stealth.yml
```

**Check 2: Valid YAML syntax**
```bash
# Install yamllint
pip install yamllint

# Validate YAML
yamllint config/stealth.yml
```

**Check 3: Check logs**
```bash
# Look for configuration loading messages
grep -i "config" /path/to/stealth.log
```

### Port Already in Use

```bash
# Check what's using the port
sudo lsof -i :8088

# Kill the process or change port in config
```

### SSL Certificate Errors (Trojan)

```bash
# Verify certificate files exist
ls -l /path/to/cert.pem
ls -l /path/to/key.pem

# Check certificate validity
openssl x509 -in /path/to/cert.pem -text -noout

# Verify private key matches certificate
openssl x509 -noout -modulus -in /path/to/cert.pem | openssl md5
openssl rsa -noout -modulus -in /path/to/key.pem | openssl md5
# Both should output the same hash
```

## Migration from Environment Variables to YAML

**Step 1: Export current configuration**
```bash
# If using environment variables, create YAML from them
cat > config/stealth.yml << EOF
shadowsocks:
  enabled: ${ENABLE_SS:-true}
  port: ${SS_PORT:-8088}
  password: "${SS_PASSWORD:-hello-world}"
  method: "${SS_METHOD:-aes_256_gcm}"
  websocket:
    enabled: ${SS_WS_ENABLED:-true}
    port: ${SS_WS_PORT:-8089}

trojan:
  enabled: ${ENABLE_TROJAN:-false}
  port: ${TROJAN_PORT:-443}
  password: "${TROJAN_PASSWORD:-hello-world}"
  mask_host: "${TROJAN_MASK_HOST:-}"
  mask_port: ${TROJAN_MASK_PORT:-443}
EOF
```

**Step 2: Test the new configuration**
```bash
# Verify the YAML is valid
mix run -e "IO.inspect(Application.get_all_env(:stealth))"
```

**Step 3: Remove environment variables**
```bash
# After confirming YAML works, remove env vars from your startup scripts
unset ENABLE_SS SS_PORT SS_PASSWORD SS_METHOD
unset ENABLE_TROJAN TROJAN_PORT TROJAN_PASSWORD
```

## Advanced Usage

### Multiple Configurations

Run multiple instances with different configs:

```bash
# Instance 1: Shadowsocks on port 8088
CONFIG_FILE=config/shadowsocks.yml ./bin/stealth start

# Instance 2: Trojan on port 443
CONFIG_FILE=config/trojan.yml ./bin/stealth start
```

### Dynamic Configuration Reloading

Currently, Stealth requires restart to apply configuration changes:

```bash
# After editing config/stealth.yml
./bin/stealth restart
```

## Support

For issues and questions:
- GitHub Issues: https://github.com/watsy0007/stealth/issues
- Documentation: See CLAUDE.md for detailed architecture information

---

**Last Updated:** 2026-01-04
**Version:** 0.9.5
