# Secure Shield - Automatic Threat Cleanup

## Overview

Secure Shield now includes **automatic threat remediation** that can quarantine infected files, repair compromised WordPress core files, and sanitize database entries containing malicious code.

---

## 🛡️ Cleanup Modes

The plugin offers **3 cleanup modes** to match your security requirements:

### 1. **Disabled** (Manual Review Only)
```php
update_option('secure_shield_cleanup_mode', 'disabled');
```
- ❌ No automatic cleanup
- ✅ Threats are detected and logged only
- ✅ Admin must manually review and clean threats
- **Use When**: You want complete control and manual review

### 2. **Critical Only** (Default - Recommended)
```php
update_option('secure_shield_cleanup_mode', 'critical_only');
```
- ✅ Automatically quarantines files with **critical** threats
- ✅ Automatically sanitizes database entries with **critical** threats
- ✅ Automatically repairs compromised WordPress core files
- ⚠️ Warning-level threats are logged but not cleaned
- **Use When**: You want automatic protection for serious threats only

### 3. **Aggressive** (Maximum Protection)
```php
update_option('secure_shield_cleanup_mode', 'aggressive');
```
- ✅ Quarantines ALL detected infected files (critical + warnings)
- ✅ Sanitizes ALL malicious database entries (critical + warnings)
- ✅ Automatically repairs WordPress core files
- ⚠️ May have false positives
- **Use When**: Maximum security is critical, slight risk of false positives acceptable

---

## 📁 File Remediation

### Quarantine Process

When an infected file is detected:

1. **Copy to Quarantine**: File is copied to `/wp-content/secure-shield-quarantine/`
2. **Secure Quarantine**: Protected `.htaccess` prevents execution
3. **Delete Original**: Infected file is removed from original location
4. **Timestamped Backup**: Filename includes timestamp: `infected-file.php-1234567890.infected`
5. **Logged**: Action is logged with full details

### Quarantine Directory Security

The quarantine directory is automatically protected:

```apache
# /wp-content/secure-shield-quarantine/.htaccess
Order deny,allow
Deny from all
<Files *>
ForceType application/octet-stream
Header set Content-Disposition attachment
</Files>
```

- ✅ All HTTP access denied
- ✅ Files cannot be executed
- ✅ Files force download if accessed
- ✅ Complete isolation from website

### WordPress Core File Repair

For WordPress core files (`wp-admin/`, `wp-includes/`, root PHP files):

1. **Detection**: Checksum mismatch detected
2. **Source Verification**: Downloads clean copy from:
   - `https://raw.githubusercontent.com/WordPress/WordPress/{version}/`
   - `https://core.svn.wordpress.org/tags/{version}/`
3. **Replacement**: Infected file replaced with clean version
4. **Verification**: New checksum verified
5. **Logged**: Repair action logged

**Note**: Core file repair requires `secure_shield_auto_repair` setting enabled.

### Plugin/Theme File Handling

For infected plugin or theme files:

- **Action**: Quarantined (not repaired)
- **Reason**: No trusted source for verification
- **Recommendation**: Reinstall plugin/theme from wordpress.org
- **Backup**: Original file preserved in quarantine for investigation

---

## 🗄️ Database Remediation

### Sanitization Process

When malicious code is found in database:

1. **Backup**: Original content backed up to post/comment meta
2. **Sanitize**: Malicious content removed/replaced
3. **Logged**: Action logged with backup meta key
4. **Recoverable**: Original content can be restored from backup

### Supported Database Tables

| Table | Field | Backup Location | Protection |
|-------|-------|-----------------|------------|
| **wp_posts** | `post_content` | Post meta `_secure_shield_backup_{timestamp}` | Content replaced with notice |
| **wp_comments** | `comment_content` | Comment meta `secure_shield_backup_{timestamp}` | Content replaced with notice |
| **wp_postmeta** | `meta_value` | New meta `_secure_shield_backup_meta_{timestamp}` | Infected meta deleted |
| **wp_options** | `option_value` | New option `secure_shield_backup_option_{timestamp}` | Infected option deleted |

### Protected Options

These WordPress core options **cannot be auto-cleaned**:

- `siteurl`
- `home`
- `blogname`
- `admin_email`
- `users_can_register`

If malicious code is detected in these, manual review is required.

### Database Recovery

To restore sanitized content:

```php
// Restore a post
$post_id = 123;
$backup_key = '_secure_shield_backup_1234567890';
$original_content = get_post_meta($post_id, $backup_key, true);
wp_update_post(array(
    'ID' => $post_id,
    'post_content' => $original_content
));
```

```php
// Restore a comment
$comment_id = 456;
$backup_key = 'secure_shield_backup_1234567890';
$original_content = get_comment_meta($comment_id, $backup_key, true);
wp_update_comment(array(
    'comment_ID' => $comment_id,
    'comment_content' => $original_content
));
```

---

## ⚙️ Configuration

### Enable Automatic Cleanup

Via WordPress admin or programmatically:

```php
// Enable critical threats auto-cleanup (default)
update_option('secure_shield_cleanup_mode', 'critical_only');

// Enable auto-repair for WordPress core files
update_option('secure_shield_auto_repair', '1');
```

### Disable Automatic Cleanup

```php
// Disable all automatic cleanup
update_option('secure_shield_cleanup_mode', 'disabled');
```

### Check Current Settings

```php
$settings = new Secure_Shield_Settings($logger);
$mode = $settings->get_cleanup_mode(); // disabled, critical_only, or aggressive
$auto_repair = $settings->is_auto_repair_enabled(); // true or false

echo "Cleanup Mode: " . $mode . "\n";
echo "Auto-Repair: " . ($auto_repair ? 'Enabled' : 'Disabled');
```

---

## 📊 Remediation Results

After each scan, remediation results are included in scan results:

```php
$results = array(
    'scan_type' => 'deep',
    'critical' => array(...), // Detected threats
    'remediation' => array(
        'files_quarantined' => array(
            'wp-content/plugins/suspicious-plugin/malware.php',
            'wp-content/themes/compromised/backdoor.php'
        ),
        'files_repaired' => array(
            'wp-admin/admin.php',
            'wp-includes/functions.php'
        ),
        'database_sanitized' => array(
            'posts:123',
            'comments:456',
            'postmeta:789'
        ),
        'errors' => array(
            'Failed to quarantine file.php: Permission denied'
        )
    )
);
```

---

## 🔍 Viewing Remediation Logs

All remediation actions are logged:

```php
// View logs
$logs = get_option('secure_shield_logs', array());
foreach ($logs as $log) {
    echo sprintf(
        "[%s] %s: %s\n",
        $log['time'],
        $log['level'],
        $log['message']
    );
}
```

Example log entries:

```
[2024-11-04 10:30:15] critical: Quarantined and removed: wp-content/plugins/bad-plugin/shell.php
[2024-11-04 10:30:16] critical: Repaired core file wp-admin/admin.php from GitHub
[2024-11-04 10:30:17] critical: Sanitized post ID 123 (backup: _secure_shield_backup_1730718617)
[2024-11-04 10:30:18] critical: Automatic remediation: 5 files quarantined, 2 files repaired, 3 database entries sanitized.
```

---

## 🚨 What Gets Cleaned Automatically?

### Critical Threats (Always in "Critical Only" and "Aggressive" modes)

**Files:**
- Web shells (C99, R57, WSO, B374K)
- Eval/exec/system code execution
- Base64/gzinflate obfuscated malware
- Socket-based reverse shells
- Known ransomware patterns
- Cryptominer scripts

**Database:**
- Eval() in post content
- Base64-encoded payloads
- JavaScript cookie stealers
- SQL injection attempts
- Command execution code

### Warning-Level Threats (Only in "Aggressive" mode)

**Files:**
- Suspicious file operations
- Unprotected AJAX endpoints
- Inline event handlers
- Remote file inclusions
- Deprecated functions

**Database:**
- XSS patterns
- Suspicious iframes
- External scripts
- Cookie access code

---

## ⚠️ Important Notes

### Backup Before Enabling

**CRITICAL**: Always backup your site before enabling automatic cleanup:

```bash
# Create full backup
wp db export backup-$(date +%Y%m%d).sql --allow-root
tar -czf backup-files-$(date +%Y%m%d).tar.gz wp-content/
```

### False Positives

Some legitimate code may trigger signatures:

- **Developer tools** using eval() for debugging
- **Legitimate plugins** with obfuscated code (ion cube, etc.)
- **Analytics scripts** accessing cookies
- **Security plugins** with signature databases

**Solution**: Review quarantined files before cleanup or use "disabled" mode.

### Performance Impact

- **Disabled**: Zero impact
- **Critical Only**: <1% impact (checks severity only)
- **Aggressive**: ~2-5% impact (checks all threats)

---

## 📋 Best Practices

### 1. **Start with "Critical Only"** (Default)
```php
update_option('secure_shield_cleanup_mode', 'critical_only');
```
- Balances automation with safety
- Minimizes false positives
- Handles serious threats automatically

### 2. **Monitor First Week**
- Review logs daily for first 7 days
- Check quarantine directory for false positives
- Verify legitimate files not removed

### 3. **Whitelist Known Good Code**
```php
// Example: Whitelist specific files from scanning
add_filter('secure_shield_scan_exclude', function($excluded) {
    $excluded[] = 'wp-content/plugins/legitimate-tool/obfuscated.php';
    return $excluded;
});
```

### 4. **Regular Quarantine Review**
```bash
# List quarantined files
ls -lh /path/to/wp-content/secure-shield-quarantine/

# Review file contents
cat /path/to/wp-content/secure-shield-quarantine/suspicious_file.php-1234567890.infected
```

### 5. **Automated Backups**
- Use Google Cloud Storage for automated daily backups
- Retain 30+ days of backups
- Test restoration process monthly

---

## 🔧 Troubleshooting

### "Permission Denied" Errors

```bash
# Fix quarantine directory permissions
chmod 700 /path/to/wp-content/secure-shield-quarantine/
chown www-data:www-data /path/to/wp-content/secure-shield-quarantine/
```

### "Core File Repair Failed"

Check connectivity to WordPress.org:

```bash
curl -I https://core.svn.wordpress.org/
curl -I https://raw.githubusercontent.com/WordPress/
```

### Too Many False Positives

Switch to manual mode:

```php
update_option('secure_shield_cleanup_mode', 'disabled');
```

Then review and manually clean threats.

### Restore Quarantined File

```bash
# Copy back from quarantine
cp /wp-content/secure-shield-quarantine/file.php-timestamp.infected /original/location/file.php
```

---

## 📞 Emergency Procedures

### If Site Breaks After Cleanup

1. **Disable automatic cleanup immediately**:
```php
update_option('secure_shield_cleanup_mode', 'disabled');
```

2. **Check recent logs** for what was cleaned:
```bash
wp option get secure_shield_logs --allow-root --format=json | jq '.[-10:]'
```

3. **Restore from quarantine** if needed:
```bash
cd /path/to/wp-content/secure-shield-quarantine/
ls -lt | head -10  # Most recent quarantined files
```

4. **Restore database backups** if needed:
```php
// List backups
global $wpdb;
$backups = $wpdb->get_results("
    SELECT post_id, meta_key, meta_value
    FROM {$wpdb->postmeta}
    WHERE meta_key LIKE '_secure_shield_backup_%'
    ORDER BY meta_id DESC
    LIMIT 10
");
```

---

## 🎯 Summary

| Feature | Description | Safety Level |
|---------|-------------|--------------|
| **File Quarantine** | Isolates infected files | ✅ High - Files preserved in quarantine |
| **Core File Repair** | Replaces with clean WordPress files | ✅ High - Downloads from official sources |
| **Database Sanitization** | Removes malicious database content | ⚠️ Medium - Backups created first |
| **Automatic Mode** | Runs during scheduled scans | ✅ Safe with "critical_only" mode |
| **Manual Mode** | Detect only, no cleanup | ✅ Highest - Full control |

---

**Recommendation**: Use **"critical_only"** mode (default) with **auto-repair enabled** for best balance of security and safety.

