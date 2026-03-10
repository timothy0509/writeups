# Play with Dinosaur I — Writeup

## Overview

- **Category:** rev
- **Given target (example port):** `nc chal.polyuctf.com 11338`
- **Real target:** HTTPS API used by a Unity IL2CPP Android APK
- **Goal:** recover both encrypted flag scenes and extract the flags from them

The challenge ships `dinosaur.zip`, which contains an Android APK. The advertised `nc` port is misleading: it is actually an HTTPS service backing the game.

## Files / target

Important local files:

- `dinosaur.apk`
- `apk/lib/arm64-v8a/libil2cpp.so`
- `cpp2il_fake/Game_Data/il2cpp_data/Metadata/global-metadata.dat`
- `tools/bin/il2cppdumper/dump.cs`
- `extracted/assets/flag_scene.enc`
- `extracted/assets/flag_scene_uat.enc`

Binary type:

```bash
file "dinosaur.apk" "apk/lib/arm64-v8a/libil2cpp.so"
```

Result:

- APK: Android package
- `libil2cpp.so`: **ELF 64-bit LSB shared object, ARM aarch64**, stripped

## Step 1: identify the real service

The README says:

```text
nc chal.polyuctf.com 11338
```

But the port is HTTPS, not plain TCP. Useful recon:

```bash
curl -k https://chal.polyuctf.com:11338/openapi.json
```

That exposes a FastAPI spec for the backend. The important endpoints are:

- `/secret`
- `/config/encrypt`
- `/uat/secret`
- `/uat/config/encrypt`

These are the four endpoints that matter for the solve.

## Step 2: reverse the Unity IL2CPP app

The APK is a Unity IL2CPP build, so the main reversing targets are:

- `libil2cpp.so`
- `global-metadata.dat`

I used the already dumped IL2CPP output in this folder. The key strings/classes are visible in:

```bash
grep -nE 'Encrypter|UIButtonScript|LoadGameSceneProperly|AES_KEY|AES_INIT_VECTOR|config/encrypt|/secret' \
  "metadata_strings.txt" \
  "tools/bin/il2cppdumper/dump.cs"
```

Important static findings:

- `Encrypter`
- `EncrypterSettings`
- `UIButtonScript`
- `LoadGameSceneProperly`
- `SecretResponse`
- `EncryptSettingsResponse`
- embedded URLs for prod and UAT

Relevant dump excerpt from `tools/bin/il2cppdumper/dump.cs`:

```csharp
public class Encrypter
{
    public const string AES_INIT_VECTOR = "J8nX3cP0vL5sQ2mT7kR9zH1dG6yU4wBa";
    public const string AES_KEY = "h4Qv9mZ2sT7kN8pL3xYc6D1wR5bG0uVa";
    private const int BlockSize = 256;
    private const int KeySize = 256;
    public static byte[] Decrypt(byte[] binData, string aesInitVector = "", string aesKey = "") { }
}

private sealed class UIButtonScript.<LoadGameSceneProperly>d__9
{
    private string <aes_key>5__2;
    private string <aes_iv>5__3;
    private UnityWebRequest <secretReq>5__4;
    private UnityWebRequest <request>5__5;
    private AsyncOperation <op>5__6;
    private UnityWebRequest <encryptReq>5__7;
}
```

This tells us where the check/decryption logic lives:

- **API/decryption flow:** `UIButtonScript.LoadGameSceneProperly` at **RVA `0x1AB6BE8`**
- **decrypt helper:** `Encrypter.Decrypt` at **RVA `0x1AB4904`**

## Step 3: discover the exact secret transformation

The app first requests `/secret`, then transforms the returned string before calling `/config/encrypt`.

Live secrets:

```text
/secret      -> BoD87jPZcWHshnnc9k3SHwg5IlfrG4dVeeakjIIYRWYMmbGL
/uat/secret  -> mQ7xZp4Rt9Ls2Vn8Yc6Hd3BaWf1JuKgTeR5vNk2Lm8Qa3Zp7
```

Directly sending the full secret fails with `401 Unauthorized`.

The exact transform from `UIButtonScript.LoadGameSceneProperly` is:

```python
secret[:24]
```

So the accepted values are:

```text
prod: BoD87jPZcWHshnnc9k3SHwg5
uat : mQ7xZp4Rt9Ls2Vn8Yc6Hd3Ba
```

Replayable proof:

```bash
curl -sk 'https://chal.polyuctf.com:11338/config/encrypt?secret=BoD87jPZcWHshnnc9k3SHwg5'
curl -sk 'https://chal.polyuctf.com:11338/uat/config/encrypt?secret=mQ7xZp4Rt9Ls2Vn8Yc6Hd3Ba'
```

Returned values:

```text
prod aes_key = zGtJuYfWaB3dH6cK8nV2sL4rZ9qPm7Tx
prod aes_iv  = kJhGfDcBaH8nY4wU6sR2kZ7tV3mQx9Lp

uat aes_key  = FuJ5gByW1kZ8dH4cR6mT9sL2aQ7pXn3V
uat aes_iv   = uB5GaF1WjZ6dH4cY8pN2sR7xQ3mLv9Kt
```

Note: the UAT endpoint responded with HTML-wrapped JSON, but the two values above are the ones needed.

## Step 4: reconstruct the decryption algorithm

`Encrypter` uses **Rijndael-256-CBC**, not normal AES-128 block mode.

Important detail from reversing the decryption logic:

- block size = **256 bits**
- key size = **256 bits**
- the backend-returned strings are **not** used directly

Exact transformation used to decrypt the scene bundles:

```python
rijndael_key = aes_iv[::-1].encode()
rijndael_iv  = aes_key[::-1].encode()
```

So it is:

- **swap** returned `aes_key` and `aes_iv`
- then **reverse** each string

In words:

- reversed remote **IV** becomes the Rijndael **key**
- reversed remote **key** becomes the Rijndael **IV**

## Step 5: decrypt `flag_scene.enc` and `flag_scene_uat.enc`

Replayable Python snippet:

```python
from pathlib import Path
from py3rijndael import RijndaelCbc, ZeroPadding

def dec_file(src, dst, aes_key, aes_iv):
    key = aes_iv[::-1].encode()
    iv = aes_key[::-1].encode()
    cipher = RijndaelCbc(key=key, iv=iv, padding=ZeroPadding(32), block_size=32)
    pt = cipher.decrypt(Path(src).read_bytes())
    Path(dst).write_bytes(pt)

dec_file(
    'extracted/assets/flag_scene.enc',
    'flag_scene.dec',
    'zGtJuYfWaB3dH6cK8nV2sL4rZ9qPm7Tx',
    'kJhGfDcBaH8nY4wU6sR2kZ7tV3mQx9Lp',
)

dec_file(
    'extracted/assets/flag_scene_uat.enc',
    'flag_scene_uat.dec',
    'FuJ5gByW1kZ8dH4cR6mT9sL2aQ7pXn3V',
    'uB5GaF1WjZ6dH4cY8pN2sR7xQ3mLv9Kt',
)
```

Verification:

```bash
python3 - <<'PY'
from pathlib import Path
for p in ['flag_scene.dec', 'flag_scene_uat.dec']:
    print(p, Path(p).read_bytes()[:8])
PY
```

Expected output starts with:

```text
UnityFS
```

That confirms the decryption is correct.

## Step 6: extract the Unity bundles

Once decrypted, both files are valid Unity asset bundles.

Quick inspection:

```bash
PYTHONPATH="pydeps" python3 - <<'PY'
import UnityPy
for path in ['flag_scene.dec','flag_scene_uat.dec']:
    env = UnityPy.load(path)
    print('FILE', path)
    for obj in env.objects:
        data = obj.read()
        print(obj.type.name, repr(getattr(data, 'm_Name', '')))
PY
```

Important objects recovered:

- `AssetBundle 'flag_scene'`
- `Texture2D 'flag'`
- `Sprite 'flag'`
- `AssetBundle 'flag_scene_uat'`
- `Texture2D 'flag_uat'`
- `Sprite 'flag_uat'`

Minimal extraction script:

```python
import UnityPy

for src in ['flag_scene.dec', 'flag_scene_uat.dec']:
    env = UnityPy.load(src)
    for obj in env.objects:
        if obj.type.name == 'Texture2D':
            tex = obj.read()
            tex.image.save(f"{tex.m_Name}.png")
```

This yields the flag images (`flag.png` / `flag_uat.png`).

## Final flags

### Prod flag for part I

```text
PUCTF26{y0u_f0und_d1n0s4ur_4nd_f147_7c2f9a4e1d6b83f0a5c7e2d91b4f6a08}
```

### UAT flag for part II

```text
PUCTF26{y0U_h4v3_fu11y_kn0w_th15_g4m3_d4a1b9e76f3c82a5b0e7d19c4f2a6b38}
```

## Full reproduction in one place

```bash
# 1) get the transformed secrets
curl -sk https://chal.polyuctf.com:11338/secret
curl -sk https://chal.polyuctf.com:11338/uat/secret

# 2) use secret[:24]
curl -sk 'https://chal.polyuctf.com:11338/config/encrypt?secret=BoD87jPZcWHshnnc9k3SHwg5'
curl -sk 'https://chal.polyuctf.com:11338/uat/config/encrypt?secret=mQ7xZp4Rt9Ls2Vn8Yc6Hd3Ba'

# 3) decrypt the bundles with Rijndael-256-CBC using swapped+reversed values
# 4) verify decrypted files start with UnityFS
# 5) extract Texture2D from the bundles and read the flags from the images
```

## Notes / lessons learned

- A fake `nc` target may still hide a web API.
- For Unity IL2CPP challenges, string metadata plus IL2CPP dumps usually reveal the whole control flow quickly.
- "AES" labels in app code are not always standard AES; here the app used **Rijndael with 256-bit blocks**.
- When returned crypto parameters do not work directly, check for extra app-side transforms like truncation, swapping, and reversing.
