# CLAUDE.md - AI Assistant Guide for Stealth

> Last updated: 2026-01-02
> Version: 0.9.5

## Project Overview

**Stealth** is a SOCKS5 proxy server written in Elixir that implements multiple encrypted proxy protocols to tunnel network traffic securely. The server acts as a transparent network gateway that:

- Accepts encrypted client connections
- Decrypts and parses SOCKS5 proxy requests
- Resolves domain names with intelligent caching
- Establishes connections to target servers
- Proxies bidirectional traffic with encryption
- Supports multiple protocols: **Shadowsocks** (TCP + WebSocket) and **Trojan** (SSL/TLS)

## Codebase Architecture

### Directory Structure

```
/home/user/stealth/
├── lib/stealth/
│   ├── stealth.ex              # Root module (minimal)
│   ├── application.ex          # OTP application supervisor
│   ├── conn.ex                 # SOCKS5 parsing & TCP utilities
│   ├── dns_cache.ex            # DNS caching with 120s TTL
│   └── protocol/
│       ├── shadowsocks/
│       │   ├── protocol.ex     # Protocol parsing utilities
│       │   ├── cipher.ex       # AES-GCM encryption/decryption
│       │   ├── hkdf.ex         # HKDF key derivation (RFC 5869)
│       │   ├── worker.ex       # TCP connection handler
│       │   ├── router.ex       # WebSocket HTTP endpoint router
│       │   └── ws_handler.ex   # WebSocket message handler
│       └── trojan/
│           ├── protocol.ex     # Protocol parsing & auth
│           ├── worker.ex       # SSL connection handler
│           └── cert_helper.ex  # SSL certificate management
├── config/
│   ├── config.exs              # Build-time defaults
│   ├── runtime.exs             # Runtime env vars (MAIN CONFIG)
│   ├── dev.exs                 # Development overrides
│   ├── test.exs                # Test environment
│   └── prod.exs                # Production settings
├── test/                       # ExUnit tests
├── mix.exs                     # Mix project configuration
├── Dockerfile                  # Multi-stage production build
└── .github/workflows/hub.yml   # CI/CD for Docker Hub
```

### Core Modules & Responsibilities

| Module | File | Responsibility |
|--------|------|----------------|
| `Stealth.Application` | `application.ex:1` | Supervisor setup; conditionally starts Shadowsocks TCP worker, WebSocket server, and/or Trojan SSL server based on config |
| `Stealth.Conn` | `conn.ex:1` | SOCKS5 request parsing (IPv4/IPv6/hostname), DNS resolution, private IP filtering (prod only), TCP connection management with retry logic |
| `Stealth.DNSCache` | `dns_cache.ex:1` | In-memory DNS caching using Cachex; 120-second TTL to prevent DNS storms |
| `Stealth.Protocol.Shadowsocks.Worker` | `protocol/shadowsocks/worker.ex:1` | Accepts TCP connections, handles AEAD encryption/decryption handshake, manages bidirectional proxy via recursive receive loop |
| `Stealth.Protocol.Shadowsocks.Cipher` | `protocol/shadowsocks/cipher.ex:1` | AEAD cipher state machine; manages nonce counter and encoder/decoder contexts for AES-128-GCM and AES-256-GCM |
| `Stealth.Protocol.Shadowsocks.HKDF` | `protocol/shadowsocks/hkdf.ex:1` | RFC 5869 HMAC-based key derivation; derives sub-keys from password and salt |
| `Stealth.Protocol.Shadowsocks.Router` | `protocol/shadowsocks/router.ex:1` | Plug-based HTTP router; handles WebSocket upgrade on `/shadowsocks` and `/ss` paths |
| `Stealth.Protocol.Shadowsocks.WSHandler` | `protocol/shadowsocks/ws_handler.ex:1` | WebSock behavior implementation; manages WebSocket lifecycle and binary message routing |
| `Stealth.Protocol.Trojan.Worker` | `protocol/trojan/worker.ex:1` | ThousandIsland handler; parses Trojan protocol, validates SHA-224 password, manages bidirectional proxy with fallback |
| `Stealth.Protocol.Trojan.Protocol` | `protocol/trojan/protocol.ex:1` | Protocol parser for Trojan requests; validates SHA-224 password hash and extracts SOCKS5 address |
| `Stealth.Protocol.Trojan.CertHelper` | `protocol/trojan/cert_helper.ex:1` | Generates self-signed SSL certificates using OpenSSL for testing/development |

## Supported Protocols

### Shadowsocks (TCP + WebSocket)

- **Encryption**: AES-128-GCM and AES-256-GCM AEAD ciphers
- **Authentication**: Pre-shared key (password)
- **Transport modes**:
  - **TCP** (port 8088 default): Direct SOCKS5 proxying over encrypted TCP
  - **WebSocket** (port 8089 default): Protocol wrapped in WebSocket frames for firewall traversal
- **Key Features**:
  - Stream-based encryption with per-packet authentication tags
  - Automatic IV generation and salt derivation using HKDF
  - Chunked encoding for large payloads (16KB max chunk size)
  - Stateful nonce counter prevents replay attacks

**Request Flow**:
1. Client connects → Server sends IV
2. Client sends: `IV + encrypted(SOCKS5 request + payload)`
3. Server decrypts, resolves DNS, connects to target
4. Bidirectional encrypted proxy loop

### Trojan (SSL/TLS)

- **Transport**: TLS 1.2+ with certificate-based encryption
- **Authentication**: SHA-224 hashed password
- **Port**: 443 (default, appears as HTTPS traffic)
- **Masking**: Supports forwarding invalid requests to fallback HTTP server
- **Key Features**:
  - Bidirectional proxy with Task-based async handling
  - Fallback mechanism for non-Trojan traffic (appears as normal HTTPS)
  - Configurable certificate files

**Request Flow**:
1. Client connects via SSL/TLS
2. Client sends: `SHA224(password) + CRLF + SOCKS5 request`
3. Server validates password hash
4. Server connects to target or fallback server
5. Two async tasks handle bidirectional proxying

## Configuration

### Environment Variables (runtime.exs)

**Shadowsocks Configuration**:
```bash
ENABLE_SS=1                    # Enable Shadowsocks (default: enabled)
SS_PORT=8088                   # TCP listen port
SS_PASSWORD=hello-world        # Shared secret
SS_METHOD=aes_256_gcm          # Cipher: aes_128_gcm | aes_256_gcm
SS_WS_PORT=8089                # WebSocket port
SS_WS_ENABLED=1                # Enable WebSocket endpoint (0 to disable)
```

**Trojan Configuration**:
```bash
ENABLE_TROJAN=0                # Enable Trojan (default: disabled)
TROJAN_PORT=443                # SSL listen port
TROJAN_PASSWORD=hello-world    # Shared secret
TROJAN_MASK_HOST=              # Fallback HTTP server host (e.g., example.com)
TROJAN_MASK_PORT=443           # Fallback HTTP server port
```

**Configuration Priority**:
1. `config/runtime.exs` - Environment variables (highest priority)
2. `config/{env}.exs` - Environment-specific overrides
3. `config/config.exs` - Build-time defaults (lowest priority)

## Development Workflow

### Setup

```bash
# Install dependencies
mix deps.get

# Format code (follows .formatter.exs)
mix format

# Run tests
mix test              # Alias: mix test --no-start
mix test --no-start   # Tests don't start the application

# Build production release
mix release           # Alias: mix release --overwrite
```

### Docker Deployment

```bash
# Build Docker image
docker build -t stealth:latest .

# Run with environment variables
docker run -e SS_PASSWORD=mysecret -p 8088:8088 stealth:latest

# Multi-stage build details:
# - Builder: elixir:1.19.4-otp-28-slim (compile)
# - Runtime: Minimal Elixir release
# - Entry: /app/bin/stealth start
```

### CI/CD Pipeline

**GitHub Actions** (`.github/workflows/hub.yml`):
- Triggers on version tags (`v*`)
- Builds multi-platform Docker images (QEMU)
- Pushes to Docker Hub: `watsy0007/stealth:$TAG`

## Coding Conventions

### Elixir Style Guidelines

1. **Module Organization**:
   - Use `@moduledoc` and `@doc` for documentation
   - Group related functions together
   - Use `alias` for module references
   - Define module attributes at the top

2. **Pattern Matching**:
   - Prefer pattern matching over conditionals
   - Use `with` for sequential operations with early exit
   - Binary pattern matching for protocol parsing:
     ```elixir
     <<1, addr::bytes-4, port::16, payload::bytes>> -> ...
     ```

3. **Error Handling**:
   - Return `{:ok, result}` or `{:error, reason}` tuples
   - Use `with` for chaining operations:
     ```elixir
     with {:ok, req} <- parse_socks5_request(data),
          {:ok, req} <- resolve_remote_address(req),
          {:ok, req} <- filter_forbidden_addresses(req) do
       # success path
     end
     ```

4. **Logging**:
   - Use `Logger.debug/1` for connection details
   - Use `Logger.error/1` for errors
   - Include relevant context (IP, port, reason)

5. **Code Formatting**:
   - Always run `mix format` before committing
   - Configured inputs: `{mix,.formatter}.exs`, `{config,lib,test}/**/*.{ex,exs}`

### Module Patterns

**TCP Connection Pattern** (`conn.ex:100`):
```elixir
def tcp_connect_remote(req), do: tcp_connect_remote(req, @socket_option, @tcp_retry)

def tcp_connect_remote(%{ip: r, port: port} = req, opts, retry) when retry > 1 do
  case :gen_tcp.connect(r, port, opts) do
    {:ok, client} -> {:ok, req |> Map.put(:remote, client)}
    {:error, _} ->
      Logger.debug("retrying! #{inspect(r)}:#{port}")
      :timer.sleep(10)
      tcp_connect_remote(req, port, opts, retry - 1)
  end
end
```

**Compile-Time Environment Switching** (`conn.ex:73`):
```elixir
if Mix.env() == :prod do
  def filter_forbidden_addresses(%{ip: ip} = req) do
    # Production: Block private IPs
  end
else
  def filter_forbidden_addresses(req), do: {:ok, req}
end
```

## Testing

### Test Structure

```
test/
├── test_helper.exs
├── stealth_test.exs
└── stealth/protocol/
    ├── shadowsocks/
    │   ├── ciper_test.exs        # Cipher encode/decode, stream ops
    │   └── ws_handler_test.exs   # WebSocket lifecycle
    └── trojan/
        ├── protocol_test.exs      # Protocol parsing
        └── worker_test.exs        # SSL connection acceptance
```

### Testing Conventions

1. **Test Organization**:
   - Use `describe` blocks for grouping related tests
   - Use `async: true` when tests are independent
   - Use setup callbacks for common initialization

2. **Running Tests**:
   ```bash
   mix test --no-start    # Run all tests without starting app
   mix test path/to/test  # Run specific test file
   ```

3. **Test Patterns**:
   ```elixir
   defmodule Stealth.Protocol.Shadowsocks.CipherTest do
     use ExUnit.Case, async: true

     describe "encode/decode" do
       test "encrypts and decrypts data" do
         # Test implementation
       end
     end
   end
   ```

## Security Considerations

### Private IP Filtering (Production Only)

**Location**: `conn.ex:73-86`

In production (`Mix.env() == :prod`), the following addresses are blocked:
- `192.168.x.x` - Private networks
- `10.x.x.x` - Private networks
- `127.0.0.x` - Localhost
- `0.x.x.x` - Invalid addresses
- `172.16-31.x.x` - Private networks

**Development/Test**: All addresses allowed for testing

### Encryption & Authentication

1. **AEAD Authentication**: All Shadowsocks data includes authentication tags
2. **Per-Connection Nonces**: Incremented nonce prevents replay attacks
3. **No Hardcoded Secrets**: All passwords via environment variables
4. **SSL/TLS**: Trojan uses proper certificate-based encryption

### Socket Configuration

**Default Socket Options** (`conn.ex:6-15`):
```elixir
@socket_option [
  :binary,
  active: :once,      # Flow control
  nodelay: true,      # Disable Nagle's algorithm
  keepalive: true,    # TCP keepalive
  packet: 0,          # Raw binary mode
  sndbuf: 2_097_152,  # 2MB send buffer
  recbuf: 2_097_152,  # 2MB receive buffer
  reuseaddr: true     # Allow port reuse
]
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `thousand_island` | ~1.3 | Barebone TCP/SSL server framework (Trojan) |
| `bandit` | ~1.10 | HTTP/WebSocket server (Shadowsocks WebSocket) |
| `websock_adapter` | ~0.5 | WebSocket upgrade handler for Bandit |
| `plug` | ~1.14 | HTTP routing (Shadowsocks WebSocket router) |
| `cachex` | ~4.0 | Distributed cache (DNS caching with TTL) |

**Built-in OTP Apps**:
- `:crypto` - AES-GCM, SHA-224, HMAC, MD5 hashing
- `:logger` - Structured logging

## Common Tasks for AI Assistants

### Adding a New Protocol

1. Create new directory: `lib/stealth/protocol/{protocol_name}/`
2. Implement required modules:
   - `protocol.ex` - Request/response parsing
   - `worker.ex` - Connection handler (ThousandIsland or custom)
   - Additional helpers as needed
3. Update `application.ex` to conditionally start the protocol
4. Add configuration to `config/runtime.exs`
5. Add tests in `test/stealth/protocol/{protocol_name}/`

### Modifying Cipher Support

**Location**: `lib/stealth/protocol/shadowsocks/cipher.ex`

1. Add new cipher method to pattern matches
2. Update key size derivation
3. Add tests for new cipher method
4. Update configuration documentation

### Debugging Connection Issues

1. **Check logs**: Look for `Logger.debug` messages with IP/port info
2. **Verify configuration**: Check `config/runtime.exs` environment variables
3. **Test DNS resolution**: Check `dns_cache.ex` for cached entries
4. **Inspect SOCKS5 parsing**: Add debug logs in `conn.ex:20-37`
5. **Monitor encryption**: Check cipher state in worker modules

### Performance Optimization

**Key Areas**:
- DNS caching TTL (`dns_cache.ex:1` - currently 120s)
- Socket buffer sizes (`conn.ex:12-13` - currently 2MB)
- TCP retry count (`conn.ex:18` - currently 2)
- Chunk size for encryption (`cipher.ex` - currently 16KB)

## Git Workflow

### Branch Strategy

- **Main branch**: Stable releases
- **Feature branches**: `feat/description`
- **Current branch**: `claude/add-claude-documentation-5irY4`

### Commit Conventions

- Use clear, descriptive commit messages
- Recent examples:
  - `bump version & websocket support`
  - `feat: support trojan`
  - `bump cachex version`

### Making Changes

```bash
# Ensure you're on the correct branch
git checkout claude/add-claude-documentation-5irY4

# Make changes, format code
mix format

# Run tests
mix test

# Commit changes
git add .
git commit -m "feat: descriptive message"

# Push to remote
git push -u origin claude/add-claude-documentation-5irY4
```

## Troubleshooting

### Common Issues

1. **Port already in use**:
   - Change port via environment variables
   - Check for other running instances

2. **DNS resolution failures**:
   - Verify network connectivity
   - Check DNS cache in `dns_cache.ex`

3. **Encryption errors**:
   - Verify password matches between client/server
   - Check cipher method configuration

4. **SSL certificate issues** (Trojan):
   - Use `CertHelper` to generate test certificates
   - Verify certificate paths in configuration

### Debug Commands

```bash
# Interactive Elixir shell with app
iex -S mix

# Check running processes
:observer.start()

# Enable debug logging
Logger.configure(level: :debug)
```

## Key Files Reference

- **Main entry point**: `lib/stealth/application.ex:1`
- **SOCKS5 parsing**: `lib/stealth/conn.ex:20`
- **DNS caching**: `lib/stealth/dns_cache.ex:1`
- **Shadowsocks TCP**: `lib/stealth/protocol/shadowsocks/worker.ex:1`
- **Shadowsocks WebSocket**: `lib/stealth/protocol/shadowsocks/ws_handler.ex:1`
- **Trojan handler**: `lib/stealth/protocol/trojan/worker.ex:1`
- **Configuration**: `config/runtime.exs:1`
- **Build config**: `mix.exs:1`
- **Docker build**: `Dockerfile:1`
- **CI/CD**: `.github/workflows/hub.yml:1`

## Additional Resources

- **Elixir Version**: 1.17+
- **OTP Version**: 28+ (per Dockerfile)
- **Current Version**: 0.9.5
- **Repository**: https://github.com/watsy0007/stealth (inferred from Docker Hub namespace)

---

**Last Updated**: 2026-01-02
**Maintainer**: watsy0007
**Purpose**: AI assistant guidance for understanding and modifying the Stealth proxy server codebase
