# Secure Shield - Google Cloud Deployment Guide

## Cloud Optimizations

This WordPress security plugin has been optimized for Google Cloud infrastructure with enhanced scalability and comprehensive threat intelligence.

---

## 🚀 Cloud Performance Features

### 1. **No Resource Limitations**
- **File Scanning**: Increased from 10MB to **100MB** default limit
- **Database Scanning**: Unlimited rows by default (was 1,000 row limit)
- **Chunked File Reading**: Efficiently processes files >10MB without memory issues
- **Configurable Limits**: Use WordPress filters to adjust as needed

### 2. **Custom Configuration via Filters**

```php
// Increase max file scan size to 500MB
add_filter('secure_shield_max_file_size', function() {
    return 524288000; // 500MB in bytes
});

// Limit database scanning to 5,000 rows (for faster scans)
add_filter('secure_shield_db_scan_limit', function() {
    return 5000; // 0 = unlimited (default)
});
```

---

## 📡 Automatic Threat Intelligence Sources

The plugin automatically updates from **14 threat intelligence feeds** twice daily:

### Core Sources (Original)
1. **YARA Malware Index** - GitHub malware signatures
2. **Emerging Threats** - Compromised IP blocklist
3. **ThreatFox** (abuse.ch) - Malware indicators (optional)
4. **CIRCL CVE Database** - Latest CVE vulnerabilities
5. **NVD** - National Vulnerability Database (requires API key)
6. **OSV.dev** - Open Source Vulnerability database
7. **WPScan** - WordPress-specific vulnerabilities (requires token)

### New Cloud-Enhanced Sources (Enabled by Default)
8. **MalwareBazaar** (abuse.ch) - Recent malware samples & hashes
   - 100 most recent malware samples
   - File hashes (SHA256) and filenames

9. **URLhaus** (abuse.ch) - Malicious URLs and domains
   - 500 most recent malicious URLs
   - Extracts and blocks malicious domains

10. **Feodo Tracker** (abuse.ch) - Botnet C2 servers
    - Command & Control server IPs
    - Real-time botnet infrastructure

11. **SSL Blacklist** (abuse.ch) - Malicious SSL certificates
    - SSL-based malware C2 servers
    - Certificate fingerprints

12. **PhishTank** - Verified phishing URLs
    - 1,000+ active phishing domains
    - Community-verified threats

13. **AlienVault OTX** - Open Threat Exchange
    - Malicious IP reputation data
    - Reliability scoring

14. **Malware Domain List** - Known malicious domains
    - Comprehensive domain blacklist
    - Hosts file format

---

## 🎛️ Configuration Options

### Enable/Disable Threat Feeds

All feeds are **enabled by default**. Disable any via WordPress admin or programmatically:

```php
// Disable specific feeds (add to wp-config.php or theme functions.php)
update_option('secure_shield_malwarebazaar_enabled', '0');
update_option('secure_shield_urlhaus_enabled', '0');
update_option('secure_shield_feodotracker_enabled', '0');
update_option('secure_shield_sslbl_enabled', '0');
update_option('secure_shield_phishtank_enabled', '0');
update_option('secure_shield_alienvault_enabled', '0');
update_option('secure_shield_malwaredomain_enabled', '0');
```

### Signature Update Schedule

By default, signatures update **twice daily**. Modify the schedule:

```php
// Update signatures every hour
add_filter('cron_schedules', function($schedules) {
    $schedules['secure_shield_hourly'] = array(
        'interval' => 3600,
        'display' => 'Every Hour'
    );
    return $schedules;
});

// Clear existing schedule and reschedule
wp_clear_scheduled_hook('secure_shield_update_signatures');
wp_schedule_event(time(), 'secure_shield_hourly', 'secure_shield_update_signatures');
```

---

## 📊 Signature Statistics

After cloud optimization, the plugin loads:

| Category | Count | Source |
|----------|-------|--------|
| **Built-in Patterns** | 80+ | Default signatures |
| **YARA Rules** | Variable | GitHub repository |
| **Malware Samples** | 100+ | MalwareBazaar |
| **Malicious Domains** | 1,500+ | URLhaus, PhishTank, Malware Domain List |
| **Botnet IPs** | 500+ | Feodo Tracker |
| **Malicious IPs** | 1,000+ | AlienVault OTX, SSL Blacklist |
| **CVEs** | Variable | CIRCL, NVD |
| **WordPress Vulnerabilities** | Variable | WPScan |

**Total Signatures**: Typically **3,000-10,000+ indicators** updated twice daily.

---

## 🔧 Google Cloud Infrastructure Recommendations

### Compute Engine Configuration

```bash
# Recommended VM specs for high-traffic sites
Machine Type: n2-standard-2 or higher
- vCPUs: 2+
- Memory: 8GB+
- Disk: 50GB SSD persistent disk

# For very large sites
Machine Type: n2-standard-4
- vCPUs: 4
- Memory: 16GB
- Disk: 100GB SSD
```

### PHP Configuration (php.ini)

```ini
# Optimize for cloud scanning
memory_limit = 512M
max_execution_time = 300
post_max_size = 128M
upload_max_filesize = 128M

# For very large installations
memory_limit = 1G
max_execution_time = 600
```

### MySQL/Cloud SQL Optimization

```sql
-- Optimize database for fast scanning
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
SET GLOBAL query_cache_size = 268435456; -- 256MB
SET GLOBAL max_allowed_packet = 67108864; -- 64MB
```

---

## 🔐 Security Enhancements

### Malware Detection Coverage

- **Web Shells**: C99, R57, WSO, B374K, FilesMan
- **Cryptominers**: CoinHive, CryptoLoot, WebMinePool, Minero
- **Command Execution**: exec, shell_exec, system, proc_open, popen
- **Obfuscation**: base64_decode, gzinflate, str_rot13, eval
- **SQL Injection**: UNION SELECT, benchmark, sleep, hex patterns
- **XSS Attacks**: Cookie stealing, event handlers, script injection
- **Ransomware**: File encryption indicators, ransom messages
- **Reverse Shells**: Socket connections, process pipes
- **File Operations**: Remote file inclusion, suspicious writes
- **Phishing**: Domain verification, URL analysis
- **Botnet C2**: Known command & control servers

### Firewall Protection

- **50+ blocked file extensions**
- **40+ malicious user agent patterns**
- **Double extension detection**
- **Null byte injection prevention**
- **Content-based upload scanning**
- **IP validation and sanitization**
- **CSRF protection**
- **XML-RPC attack prevention**

---

## 📈 Performance Monitoring

### Check Signature Count

```php
$signatures = get_option('secure_shield_signatures');
$count = is_array($signatures) ? count($signatures) : 0;
echo "Loaded signatures: " . $count;
```

### Last Update Time

```php
$last_update = get_option('secure_shield_signatures_updated');
echo "Last updated: " . date('Y-m-d H:i:s', $last_update);
```

### View Logs

Navigate to: **WordPress Admin → Secure Shield → Logs**

---

## 🔄 Manual Signature Update

Trigger manual update via WP-CLI:

```bash
# SSH into your Google Cloud VM
gcloud compute ssh your-instance-name

# Update signatures manually
wp cron event run secure_shield_update_signatures --allow-root

# View update logs
wp option get secure_shield_logs --allow-root --format=json
```

---

## 🛡️ API Keys (Optional but Recommended)

### National Vulnerability Database (NVD)
Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key

```php
update_option('secure_shield_nvd_api_key', 'your-nvd-api-key-here');
```

### WPScan Token
Get a free token at: https://wpscan.com/api

```php
update_option('secure_shield_wpscan_token', 'your-wpscan-token-here');
```

### Benefits:
- Higher rate limits
- Priority access to vulnerability data
- WordPress plugin/theme-specific CVEs

---

## 📋 Deployment Checklist

- [ ] Deploy to Google Cloud Compute Engine or App Engine
- [ ] Set PHP memory_limit to 512M or higher
- [ ] Enable PHP OPcache for performance
- [ ] Configure Cloud SQL or MySQL with adequate resources
- [ ] Set up Cloud Monitoring for scan alerts
- [ ] Configure automated backups via Cloud Storage
- [ ] Add NVD API key for enhanced CVE data
- [ ] Add WPScan token for WordPress vulnerabilities
- [ ] Test signature updates: `wp cron event run secure_shield_update_signatures`
- [ ] Run initial deep scan
- [ ] Set up Cloud Logging for security events
- [ ] Configure Cloudflare (optional) for IP blocking

---

## 🚨 Troubleshooting

### Signatures Not Updating

```bash
# Check WordPress cron
wp cron event list --allow-root | grep secure_shield

# Force update
wp cron event run secure_shield_update_signatures --allow-root
```

### Memory Issues During Scan

```php
// Temporarily increase limit for scans only
add_filter('secure_shield_max_file_size', function() {
    return 52428800; // Reduce to 50MB
});
```

### Database Scan Too Slow

```php
// Limit database scan to recent rows
add_filter('secure_shield_db_scan_limit', function() {
    return 1000; // Only scan last 1,000 rows
});
```

---

## 📞 Support

For issues or questions:
- Check logs: **WP Admin → Secure Shield → Logs**
- Enable WordPress debug: `define('WP_DEBUG', true);`
- Check Cloud Logging: `gcloud logging read "resource.type=gce_instance"`

---

## 🔖 Version Information

- **Plugin Version**: 1.0.0
- **Optimized For**: Google Cloud Platform
- **PHP Requirements**: 7.0+
- **WordPress Requirements**: 5.0+
- **Database**: MySQL 5.6+ or Cloud SQL

---

**Last Updated**: 2024
**Maintained By**: Security Team
