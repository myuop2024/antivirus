# Secure Shield Security Suite

Secure Shield is an advanced WordPress security plugin that delivers comprehensive protection through malware scanning, vulnerability hardening, automated backups, and real-time threat intelligence synchronization.

## Features

- **Multi-mode Malware Scanner**: Deep, quick, and core integrity scans across the entire WordPress installation (files and database) using continuously updated open-source signatures.
- **Automated Remediation**: Quarantine suspicious files, sanitize database payloads, and notify administrators when critical issues are detected.
- **Application Firewall**: Real-time request inspection, proactive IP blocking, configurable security headers, and Cloudflare integration for instant network-level enforcement.
- **Permission Auditing**: Routine validation of sensitive file and directory permissions with actionable recommendations.
- **Threat Intelligence Sync**: Twice-daily ingestion of open-source threat feeds (YARA, Emerging Threats, AbuseCH ThreatFox, CIRCL CVEs) plus optional NVD, OSV.dev, and WPScan enrichment with configurable API credentials.
- **Integrity Monitoring & Auto Repair**: WordPress core checksums verified against wordpress.org with optional trusted auto-repair sourcing for tampered files.
- **Backups and Restore**: One-click file system backup, secure quarantine directory handling, and restoration workflow.
- **REST API & Automation**: REST endpoints for programmatic scans and status retrieval, plus granular logging for observability.
- **Polished Admin Experience**: Responsive dashboard, live scan status, curated alerts, and Cloudflare credential management.

## Installation

1. Copy the `secure-shield` directory into your WordPress installation's `wp-content/plugins/` folder.
2. Activate **Secure Shield Security Suite** from the WordPress Plugins screen.
3. Visit **Secure Shield → Dashboard** to run your first scan, review system health, and configure threat intelligence sources and Cloudflare integration.

## Threat Intelligence Providers

- **WPScan API Token (optional)** – Enables detailed advisories for installed core, plugins, and themes.
- **NVD API Key (optional)** – Raises rate limits when fetching the latest CVEs from the National Vulnerability Database.
- **OSV.dev Toggle** – Pulls open-source vulnerability advisories for the WordPress ecosystem.
- **AbuseCH ThreatFox Toggle** – Streams malware signatures and indicators of compromise.
- **Core Auto-Repair Toggle** – Automatically attempts to restore tampered WordPress core files from trusted upstream sources.

## Cloudflare Integration

Provide your Cloudflare email, API token, and zone ID under the Cloudflare Integration panel. Secure Shield will automatically propagate firewall blocks to Cloudflare when malicious activity is detected.

## Backups

Backups are stored in `wp-content/uploads/secure-shield-backups`. The plugin automatically excludes backup and quarantine directories from new archives to prevent nested backups.

## Cron Schedules

- Threat intelligence updates run twice daily.
- Deep scans run every six hours by default (adjustable via WP-Cron filters).
- Hourly maintenance refreshes permissions and blocklists.

## Support

Secure Shield leverages best practices from open-source security research but should complement, not replace, defense-in-depth strategies such as WAFs, timely updates, and least-privilege access controls.
