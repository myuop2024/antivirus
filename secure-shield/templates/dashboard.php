<?php
/**
 * Dashboard template.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap secure-shield">
    <h1 class="secure-shield__title"><?php esc_html_e( 'Secure Shield Security Suite', 'secure-shield' ); ?></h1>

    <?php if ( isset( $_GET['message'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
        <div class="notice notice-success is-dismissible">
            <p>
                <?php
                $message = sanitize_text_field( wp_unslash( $_GET['message'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $messages = array(
                    'scan_complete'   => __( 'Scan completed successfully.', 'secure-shield' ),
                    'backup_success'  => __( 'Backup created successfully.', 'secure-shield' ),
                    'backup_failed'   => __( 'Backup failed. Check logs for details.', 'secure-shield' ),
                    'restore_success' => __( 'Restore completed successfully.', 'secure-shield' ),
                    'restore_failed'  => __( 'Restore failed. Check logs for details.', 'secure-shield' ),
                );
                echo esc_html( $messages[ $message ] ?? __( 'Action completed.', 'secure-shield' ) );
                ?>
            </p>
        </div>
    <?php endif; ?>

    <div class="secure-shield__grid">
        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Run Scan', 'secure-shield' ); ?></h2>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <?php wp_nonce_field( 'secure_shield_scan' ); ?>
                <input type="hidden" name="action" value="secure_shield_scan" />
                <label for="scan_type"><?php esc_html_e( 'Scan Type', 'secure-shield' ); ?></label>
                <select name="scan_type" id="scan_type" class="secure-shield__select">
                    <option value="quick"><?php esc_html_e( 'Quick Scan', 'secure-shield' ); ?></option>
                    <option value="core"><?php esc_html_e( 'Core Integrity Scan', 'secure-shield' ); ?></option>
                    <option value="deep"><?php esc_html_e( 'Deep Scan', 'secure-shield' ); ?></option>
                </select>
                <button type="submit" class="button button-primary button-hero">
                    <span class="dashicons dashicons-shield"></span>
                    <?php esc_html_e( 'Start Scan', 'secure-shield' ); ?>
                </button>
            </form>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Latest Scan Results', 'secure-shield' ); ?></h2>
            <?php if ( empty( $results ) ) : ?>
                <p><?php esc_html_e( 'No scans have been run yet.', 'secure-shield' ); ?></p>
            <?php else : ?>
                <p><strong><?php esc_html_e( 'Type:', 'secure-shield' ); ?></strong> <?php echo esc_html( ucfirst( $results['scan_type'] ?? '' ) ); ?></p>
                <p><strong><?php esc_html_e( 'Start:', 'secure-shield' ); ?></strong> <?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $results['start'] ?? time() ) ); ?></p>
                <p><strong><?php esc_html_e( 'End:', 'secure-shield' ); ?></strong> <?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $results['end'] ?? time() ) ); ?></p>
                <p><strong><?php esc_html_e( 'Signatures Loaded:', 'secure-shield' ); ?></strong> <?php echo esc_html( number_format_i18n( count( (array) $signatures ) ) ); ?></p>
                <h3><?php esc_html_e( 'Critical Issues', 'secure-shield' ); ?></h3>
                <?php if ( empty( $results['critical'] ) ) : ?>
                    <p class="secure-shield__status--success"><?php esc_html_e( 'No critical issues found!', 'secure-shield' ); ?></p>
                <?php else : ?>
                    <ul class="secure-shield__list secure-shield__list--danger">
                        <?php foreach ( $results['critical'] as $location => $description ) : ?>
                            <li>
                                <strong><?php echo esc_html( $location ); ?></strong> — <?php echo esc_html( $description ); ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Integrity Watch', 'secure-shield' ); ?></h2>
            <?php $integrity = $results['integrity']['core'] ?? array(); ?>
            <?php if ( empty( $integrity ) ) : ?>
                <p class="secure-shield__status--success"><?php esc_html_e( 'Core checksums are verified against wordpress.org.', 'secure-shield' ); ?></p>
            <?php else : ?>
                <ul class="secure-shield__list secure-shield__list--warning">
                    <?php foreach ( $integrity as $file => $message ) : ?>
                        <li><strong><?php echo esc_html( $file ); ?></strong> — <?php echo esc_html( $message ); ?></li>
                    <?php endforeach; ?>
                </ul>
                <?php if ( $settings->is_auto_repair_enabled() ) : ?>
                    <p><?php esc_html_e( 'Auto-repair attempted to restore mismatched files using trusted sources.', 'secure-shield' ); ?></p>
                <?php else : ?>
                    <p><?php esc_html_e( 'Enable auto-repair below to automatically fetch pristine core files when tampering is detected.', 'secure-shield' ); ?></p>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'File Permission Audit', 'secure-shield' ); ?></h2>
            <?php if ( empty( $permissions ) ) : ?>
                <p class="secure-shield__status--success"><?php esc_html_e( 'Permissions look good!', 'secure-shield' ); ?></p>
            <?php else : ?>
                <ul class="secure-shield__list secure-shield__list--warning">
                    <?php foreach ( $permissions as $path => $issue ) : ?>
                        <li><strong><?php echo esc_html( $path ); ?></strong> — <?php echo esc_html( $issue ); ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Firewall Blocklist', 'secure-shield' ); ?></h2>
            <?php if ( empty( $blocklist ) ) : ?>
                <p><?php esc_html_e( 'No IPs currently blocked.', 'secure-shield' ); ?></p>
            <?php else : ?>
                <ul class="secure-shield__list">
                    <?php foreach ( $blocklist as $ip => $details ) : ?>
                        <li>
                            <strong><?php echo esc_html( $ip ); ?></strong>
                            <span><?php echo esc_html( $details['reason'] ); ?></span>
                            <span><?php echo esc_html( date_i18n( get_option( 'date_format' ), $details['time'] ) ); ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Backups', 'secure-shield' ); ?></h2>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <?php wp_nonce_field( 'secure_shield_backup' ); ?>
                <input type="hidden" name="action" value="secure_shield_backup" />
                <button type="submit" class="button button-secondary secure-shield__button-block">
                    <span class="dashicons dashicons-database"></span>
                    <?php esc_html_e( 'Create Backup', 'secure-shield' ); ?>
                </button>
            </form>

            <?php if ( ! empty( $backups ) ) : ?>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="secure-shield__restore-form">
                    <?php wp_nonce_field( 'secure_shield_restore' ); ?>
                    <input type="hidden" name="action" value="secure_shield_restore" />
                    <label for="backup_file"><?php esc_html_e( 'Restore from backup', 'secure-shield' ); ?></label>
                    <select name="backup_file" id="backup_file" class="secure-shield__select">
                        <?php foreach ( $backups as $backup_file ) : ?>
                            <option value="<?php echo esc_attr( $backup_file ); ?>"><?php echo esc_html( basename( $backup_file ) ); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <button type="submit" class="button button-warning secure-shield__button-block">
                        <span class="dashicons dashicons-update"></span>
                        <?php esc_html_e( 'Restore Backup', 'secure-shield' ); ?>
                    </button>
                </form>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card secure-shield__card--wide">
            <h2><?php esc_html_e( 'Threat Intelligence & Integrations', 'secure-shield' ); ?></h2>
            <p><?php esc_html_e( 'Secure Shield synchronizes with open-source vulnerability databases and Cloudflare. Provide API keys and toggle feeds to tune protection.', 'secure-shield' ); ?></p>
            <p><strong><?php esc_html_e( 'Last Signature Update:', 'secure-shield' ); ?></strong> <?php echo esc_html( $last_update ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last_update ) : __( 'Pending', 'secure-shield' ) ); ?></p>
            <form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
                <?php
                settings_fields( 'secure_shield' );
                do_settings_sections( 'secure_shield' );
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="secure_shield_wpscan_token"><?php esc_html_e( 'WPScan API Token', 'secure-shield' ); ?></label></th>
                        <td>
                            <input type="text" name="secure_shield_wpscan_token" id="secure_shield_wpscan_token" value="<?php echo esc_attr( get_option( 'secure_shield_wpscan_token', '' ) ); ?>" class="regular-text" />
                            <p class="description"><?php esc_html_e( 'Optional. Enables real-time ingestion of WordPress core, plugin, and theme advisories.', 'secure-shield' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_nvd_api_key"><?php esc_html_e( 'NVD API Key', 'secure-shield' ); ?></label></th>
                        <td>
                            <input type="text" name="secure_shield_nvd_api_key" id="secure_shield_nvd_api_key" value="<?php echo esc_attr( get_option( 'secure_shield_nvd_api_key', '' ) ); ?>" class="regular-text" />
                            <p class="description"><?php esc_html_e( 'Optional. Improve National Vulnerability Database sync reliability and rate limits.', 'secure-shield' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable OSV.dev Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_osv_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_osv_enabled" value="1" <?php checked( true, $settings->is_osv_enabled() ); ?> /> <?php esc_html_e( 'Pull advisories for the WordPress ecosystem from OSV.dev.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable ThreatFox Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_threatfox_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_threatfox_enabled" value="1" <?php checked( true, $settings->is_threatfox_enabled() ); ?> /> <?php esc_html_e( 'Continuously ingest AbuseCH ThreatFox malware signatures.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable MalwareBazaar Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_malwarebazaar_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_malwarebazaar_enabled" value="1" <?php checked( true, $settings->is_malwarebazaar_enabled() ); ?> /> <?php esc_html_e( 'Sync malware hashes from AbuseCH MalwareBazaar database.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable URLhaus Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_urlhaus_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_urlhaus_enabled" value="1" <?php checked( true, $settings->is_urlhaus_enabled() ); ?> /> <?php esc_html_e( 'Block malicious URLs from AbuseCH URLhaus feed.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Feodo Tracker Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_feodotracker_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_feodotracker_enabled" value="1" <?php checked( true, $settings->is_feodotracker_enabled() ); ?> /> <?php esc_html_e( 'Track botnet C&C servers from AbuseCH Feodo Tracker.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable SSL Blacklist Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_sslbl_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_sslbl_enabled" value="1" <?php checked( true, $settings->is_sslbl_enabled() ); ?> /> <?php esc_html_e( 'Block malicious SSL certificates from AbuseCH SSLBL.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable PhishTank Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_phishtank_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_phishtank_enabled" value="1" <?php checked( true, $settings->is_phishtank_enabled() ); ?> /> <?php esc_html_e( 'Detect phishing URLs from PhishTank database.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable AlienVault OTX Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_alienvault_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_alienvault_enabled" value="1" <?php checked( true, $settings->is_alienvault_enabled() ); ?> /> <?php esc_html_e( 'Community-driven threat intelligence from AlienVault OTX.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Malware Domain List Feed', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_malwaredomain_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_malwaredomain_enabled" value="1" <?php checked( true, $settings->is_malwaredomain_enabled() ); ?> /> <?php esc_html_e( 'Block known malware-hosting domains.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Core Auto-Repair', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_auto_repair" value="0" />
                            <label><input type="checkbox" name="secure_shield_auto_repair" value="1" <?php checked( true, $settings->is_auto_repair_enabled() ); ?> /> <?php esc_html_e( 'Automatically fetch pristine WordPress core files when tampering is detected.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_cleanup_mode"><?php esc_html_e( 'Automatic Cleanup Mode', 'secure-shield' ); ?></label></th>
                        <td>
                            <select name="secure_shield_cleanup_mode" id="secure_shield_cleanup_mode" class="regular-text">
                                <option value="disabled" <?php selected( $settings->get_cleanup_mode(), 'disabled' ); ?>><?php esc_html_e( 'Disabled (Manual Review Only)', 'secure-shield' ); ?></option>
                                <option value="critical_only" <?php selected( $settings->get_cleanup_mode(), 'critical_only' ); ?>><?php esc_html_e( 'Critical Only (Recommended)', 'secure-shield' ); ?></option>
                                <option value="aggressive" <?php selected( $settings->get_cleanup_mode(), 'aggressive' ); ?>><?php esc_html_e( 'Aggressive (Maximum Protection)', 'secure-shield' ); ?></option>
                            </select>
                            <p class="description"><?php esc_html_e( 'Controls automatic threat remediation. Critical Only mode quarantines only critical threats, Aggressive mode handles all threats automatically.', 'secure-shield' ); ?></p>
                        </td>
                    </tr>
                </table>
                <?php submit_button( __( 'Save Settings', 'secure-shield' ) ); ?>
            </form>
        </div>

        <div class="secure-shield__card secure-shield__card--wide">
            <h2><?php esc_html_e( 'AI-Powered Threat Analysis', 'secure-shield' ); ?></h2>
            <p><?php esc_html_e( 'Enhance malware detection with DeepSeek V3.1 AI analysis via OpenRouter. The AI can analyze suspicious code, suggest repairs, learn from patterns, and verify false positives.', 'secure-shield' ); ?></p>
            <form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
                <?php
                settings_fields( 'secure_shield' );
                do_settings_sections( 'secure_shield' );
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable AI Analysis', 'secure-shield' ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_ai_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_ai_enabled" id="secure_shield_ai_enabled" value="1" <?php checked( true, $settings->is_ai_enabled() ); ?> /> <?php esc_html_e( 'Use AI to analyze threats, generate repairs, and reduce false positives.', 'secure-shield' ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_deepseek_api_key"><?php esc_html_e( 'OpenRouter API Key', 'secure-shield' ); ?></label></th>
                        <td>
                            <input type="password" name="secure_shield_deepseek_api_key" id="secure_shield_deepseek_api_key" value="<?php echo esc_attr( get_option( 'secure_shield_deepseek_api_key', '' ) ); ?>" class="regular-text" autocomplete="off" />
                            <p class="description">
                                <?php esc_html_e( 'Get your API key from', 'secure-shield' ); ?> <a href="https://openrouter.ai/keys" target="_blank">OpenRouter</a>.
                                <?php esc_html_e( 'Model: deepseek/deepseek-chat-v3.1:free', 'secure-shield' ); ?>
                            </p>
                            <button type="button" id="test-ai-connection" class="button button-secondary" style="margin-top: 10px;">
                                <span class="dashicons dashicons-cloud"></span>
                                <?php esc_html_e( 'Test Connection', 'secure-shield' ); ?>
                            </button>
                            <span id="ai-test-result" style="margin-left: 10px;"></span>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'AI Capabilities', 'secure-shield' ); ?></th>
                        <td>
                            <ul style="list-style: disc; margin-left: 20px;">
                                <li><?php esc_html_e( 'Threat Analysis: Analyze suspicious code with confidence scoring', 'secure-shield' ); ?></li>
                                <li><?php esc_html_e( 'Code Repair: Generate safe versions of infected files', 'secure-shield' ); ?></li>
                                <li><?php esc_html_e( 'Pattern Learning: Extract malware signatures from samples', 'secure-shield' ); ?></li>
                                <li><?php esc_html_e( 'False Positive Detection: Verify legitimate code flagged by signatures', 'secure-shield' ); ?></li>
                            </ul>
                        </td>
                    </tr>
                </table>
                <?php submit_button( __( 'Save AI Settings', 'secure-shield' ) ); ?>
            </form>
        </div>

        <div class="secure-shield__card secure-shield__card--wide">
            <h2><?php esc_html_e( 'Cloudflare Integration', 'secure-shield' ); ?></h2>
            <p><?php esc_html_e( 'Automatically block malicious IPs at the edge using Cloudflare Firewall Rules.', 'secure-shield' ); ?></p>
            <form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
                <?php
                settings_fields( 'secure_shield' );
                do_settings_sections( 'secure_shield' );
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="secure_shield_cloudflare_email"><?php esc_html_e( 'Cloudflare Email', 'secure-shield' ); ?></label></th>
                        <td><input type="email" name="secure_shield_cloudflare_email" id="secure_shield_cloudflare_email" value="<?php echo esc_attr( get_option( 'secure_shield_cloudflare_email', '' ) ); ?>" class="regular-text" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_cloudflare_token"><?php esc_html_e( 'Cloudflare API Token', 'secure-shield' ); ?></label></th>
                        <td><input type="text" name="secure_shield_cloudflare_token" id="secure_shield_cloudflare_token" value="<?php echo esc_attr( get_option( 'secure_shield_cloudflare_token', '' ) ); ?>" class="regular-text" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_cloudflare_zone"><?php esc_html_e( 'Cloudflare Zone ID', 'secure-shield' ); ?></label></th>
                        <td><input type="text" name="secure_shield_cloudflare_zone" id="secure_shield_cloudflare_zone" value="<?php echo esc_attr( get_option( 'secure_shield_cloudflare_zone', '' ) ); ?>" class="regular-text" /></td>
                    </tr>
                </table>
                <?php submit_button( __( 'Save Cloudflare Settings', 'secure-shield' ) ); ?>
            </form>
        </div>
    </div>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
    $('#test-ai-connection').on('click', function(e) {
        e.preventDefault();
        var $button = $(this);
        var $result = $('#ai-test-result');
        var apiKey = $('#secure_shield_deepseek_api_key').val();

        if (!apiKey) {
            $result.html('<span style="color: #dc3232;"><?php esc_html_e( 'Please enter an API key first.', 'secure-shield' ); ?></span>');
            return;
        }

        $button.prop('disabled', true);
        $result.html('<span style="color: #999;"><?php esc_html_e( 'Testing connection...', 'secure-shield' ); ?></span>');

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'secure_shield_test_ai',
                nonce: '<?php echo esc_js( wp_create_nonce( 'secure_shield_test_ai' ) ); ?>'
            },
            success: function(response) {
                if (response.success) {
                    $result.html('<span style="color: #46b450;"><span class="dashicons dashicons-yes"></span> ' + response.data.message + '</span>');
                } else {
                    $result.html('<span style="color: #dc3232;"><span class="dashicons dashicons-no"></span> ' + response.data.message + '</span>');
                }
            },
            error: function() {
                $result.html('<span style="color: #dc3232;"><?php esc_html_e( 'Connection test failed. Check your network.', 'secure-shield' ); ?></span>');
            },
            complete: function() {
                $button.prop('disabled', false);
            }
        });
    });
});
</script>
