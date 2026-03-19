# Challenge 14 Writeup

**Challenge Name:** challenge14
**Author:** SalaryThief
**Category:** Reverse Engineering / Web
**Description:** "Last time, someone said my license activation program so easy to crack it. So, I enhanced it in this time."

## Initial Analysis

The challenge provided a directory `License_v2` containing a Windows executable `QtLicense.exe` (a Qt 5 application) and several DLLs.

Running `file` on the binary confirmed it was a 64-bit PE executable:
```bash
$ file License_v2/QtLicense.exe
License_v2/QtLicense.exe: PE32+ executable (GUI) x86-64, for MS Windows
```

## Static Analysis

We performed strings analysis on the binary to identify interesting artifacts.

```bash
strings -e l License_v2/QtLicense.exe | grep -i "http"
```

This revealed a URL pointing to `https://chal.polyuctf.com:11337`.

Further inspection of strings near network functionality revealed several interesting JSON keys:
- `license_key`
- `server_time`
- `is_4dm1n_m0de`

The presence of `is_4dm1n_m0de` immediately suggested a potential bypass mechanism in the verification logic.

## Network Protocol Analysis

We observed the application communicating with two endpoints:
1. `GET /time` - Retrieves the current server time.
2. `POST /license/verify` - Submits the license key for verification.

The `/time` endpoint returns a JSON object:
```json
{"server_time": "2026-03-07T12:07:35.141494+00:00"}
```

## Exploitation

The application logic likely constructs a JSON payload to send to `/license/verify`. We hypothesized that the server-side code checks the `is_4dm1n_m0de` parameter. If set to `true`, it might bypass the standard license validation.

We manually constructed a `curl` request to test this hypothesis.

### Step 1: Get Valid Server Time
The server likely validates the timestamp to prevent replay attacks or ensure freshness.

```bash
curl -k https://chal.polyuctf.com:11337/time
```

### Step 2: Send Malicious Payload
We crafted a POST request including the hidden admin parameter:

```bash
curl -k -X POST -H "Content-Type: application/json" \
     -d '{"license_key": "test", "server_time": "2026-03-07T12:07:35.141494+00:00", "is_4dm1n_m0de": true}' \
     https://chal.polyuctf.com:11337/license/verify
```

*Note: The `server_time` must be current.*

## Result

The server responded with the flag:

```json
{
  "ok": true,
  "status": "valid_admin",
  "message": "Admin mode active: License key accepted. \r\n Here is your flag: PUCTF26{y0u_hv_4ct1v4t3d_w1th0ut_4_k3y_a9f3c4b1e7d28f5096bc1a4e3d5f8c72}"
}
```

## Flag

`PUCTF26{y0u_hv_4ct1v4t3d_w1th0ut_4_k3y_a9f3c4b1e7d28f5096bc1a4e3d5f8c72}`
