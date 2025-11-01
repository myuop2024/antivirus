<?php
/**
 * Dashboard template.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap secure-shield bison-security">
    <h1 class="secure-shield__title"><?php esc_html_e( 'BISON Security Suite Command Center', SECURE_SHIELD_TEXT_DOMAIN ); ?></h1>

    <div class="secure-shield__hero">
        <div class="secure-shield__hero-panel">
            <h2><?php esc_html_e( 'Live Defense Snapshot', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <ul>
                <li>
                    <span class="status-pill js-realtime-pill <?php echo $settings->is_realtime_updates_enabled() ? 'status-pill--ok' : 'status-pill--warn'; ?>"
                        data-label-on="<?php echo esc_attr( __( 'Realtime Feeds Online', SECURE_SHIELD_TEXT_DOMAIN ) ); ?>"
                        data-label-off="<?php echo esc_attr( __( 'Realtime Feeds Paused', SECURE_SHIELD_TEXT_DOMAIN ) ); ?>">
                        <?php echo $settings->is_realtime_updates_enabled() ? esc_html__( 'Realtime Feeds Online', SECURE_SHIELD_TEXT_DOMAIN ) : esc_html__( 'Realtime Feeds Paused', SECURE_SHIELD_TEXT_DOMAIN ); ?>
                    </span>
                </li>
                <li>
                    <strong><?php esc_html_e( 'Threat Signatures Loaded', SECURE_SHIELD_TEXT_DOMAIN ); ?>:</strong>
                    <?php echo esc_html( number_format_i18n( count( (array) $signatures ) ) ); ?>
                </li>
                <li>
                    <strong><?php esc_html_e( 'Last Sync', SECURE_SHIELD_TEXT_DOMAIN ); ?>:</strong>
                    <?php echo esc_html( $last_update ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last_update ) : __( 'Pending', SECURE_SHIELD_TEXT_DOMAIN ) ); ?>
                </li>
            </ul>
        </div>
        <div class="secure-shield__hero-panel secure-shield__hero-panel--right">
            <h2><?php esc_html_e( 'Adaptive Co-Pilot', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <p><?php esc_html_e( 'Connect Gemini and Hugging Face models to receive guided fixes, permission hardening steps, and safe clean-up routines.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
            <div class="secure-shield__integration-pills">
                <span class="status-pill js-ai-pill <?php echo $settings->get_gemini_api_key() ? 'status-pill--ok' : 'status-pill--idle'; ?>"
                    data-target="#secure_shield_gemini_api_key"
                    data-label-on="<?php echo esc_attr( __( 'Gemini Connected', SECURE_SHIELD_TEXT_DOMAIN ) ); ?>"
                    data-label-off="<?php echo esc_attr( __( 'Gemini Pending', SECURE_SHIELD_TEXT_DOMAIN ) ); ?>">
                    <?php echo $settings->get_gemini_api_key() ? esc_html__( 'Gemini Connected', SECURE_SHIELD_TEXT_DOMAIN ) : esc_html__( 'Gemini Pending', SECURE_SHIELD_TEXT_DOMAIN ); ?>
                </span>
                <span class="status-pill js-ai-pill <?php echo $settings->get_hf_api_key() ? 'status-pill--ok' : 'status-pill--idle'; ?>"
                    data-target="#secure_shield_hf_api_key"
                    data-label-on="<?php echo esc_attr( __( 'Hugging Face Connected', SECURE_SHIELD_TEXT_DOMAIN ) ); ?>"
                    data-label-off="<?php echo esc_attr( __( 'Hugging Face Pending', SECURE_SHIELD_TEXT_DOMAIN ) ); ?>">
                    <?php echo $settings->get_hf_api_key() ? esc_html__( 'Hugging Face Connected', SECURE_SHIELD_TEXT_DOMAIN ) : esc_html__( 'Hugging Face Pending', SECURE_SHIELD_TEXT_DOMAIN ); ?>
                </span>
                <span class="status-pill <?php echo ! empty( $blocklist ) ? 'status-pill--ok' : 'status-pill--idle'; ?>"><?php esc_html_e( 'Firewall Active', SECURE_SHIELD_TEXT_DOMAIN ); ?></span>
            </div>
        </div>
    </div>

    <?php if ( isset( $_GET['message'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
        <div class="notice notice-success is-dismissible">
            <p>
                <?php
                $message = sanitize_text_field( wp_unslash( $_GET['message'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $messages = array(
                    'scan_complete'   => __( 'Scan completed successfully.', SECURE_SHIELD_TEXT_DOMAIN ),
                    'backup_success'  => __( 'Backup created successfully.', SECURE_SHIELD_TEXT_DOMAIN ),
                    'backup_failed'   => __( 'Backup failed. Check logs for details.', SECURE_SHIELD_TEXT_DOMAIN ),
                    'restore_success' => __( 'Restore completed successfully.', SECURE_SHIELD_TEXT_DOMAIN ),
                    'restore_failed'  => __( 'Restore failed. Check logs for details.', SECURE_SHIELD_TEXT_DOMAIN ),
                );
                echo esc_html( $messages[ $message ] ?? __( 'Action completed.', SECURE_SHIELD_TEXT_DOMAIN ) );
                ?>
            </p>
        </div>
    <?php endif; ?>

    <div class="secure-shield__grid">
        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Run Scan', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <?php wp_nonce_field( 'secure_shield_scan' ); ?>
                <input type="hidden" name="action" value="secure_shield_scan" />
                <label for="scan_type"><?php esc_html_e( 'Scan Type', SECURE_SHIELD_TEXT_DOMAIN ); ?></label>
                <select name="scan_type" id="scan_type" class="secure-shield__select">
                    <option value="quick"><?php esc_html_e( 'Quick Scan', SECURE_SHIELD_TEXT_DOMAIN ); ?></option>
                    <option value="core"><?php esc_html_e( 'Core Integrity Scan', SECURE_SHIELD_TEXT_DOMAIN ); ?></option>
                    <option value="deep"><?php esc_html_e( 'Deep Scan', SECURE_SHIELD_TEXT_DOMAIN ); ?></option>
                </select>
                <button type="submit" class="button button-primary button-hero">
                    <span class="dashicons dashicons-shield"></span>
                    <?php esc_html_e( 'Start Scan', SECURE_SHIELD_TEXT_DOMAIN ); ?>
                </button>
            </form>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Latest Scan Results', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <?php if ( empty( $results ) ) : ?>
                <p><?php esc_html_e( 'No scans have been run yet.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
            <?php else : ?>
                <p><strong><?php esc_html_e( 'Type:', SECURE_SHIELD_TEXT_DOMAIN ); ?></strong> <?php echo esc_html( ucfirst( $results['scan_type'] ?? '' ) ); ?></p>
                <p><strong><?php esc_html_e( 'Start:', SECURE_SHIELD_TEXT_DOMAIN ); ?></strong> <?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $results['start'] ?? time() ) ); ?></p>
                <p><strong><?php esc_html_e( 'End:', SECURE_SHIELD_TEXT_DOMAIN ); ?></strong> <?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $results['end'] ?? time() ) ); ?></p>
                <p><strong><?php esc_html_e( 'Signatures Loaded:', SECURE_SHIELD_TEXT_DOMAIN ); ?></strong> <?php echo esc_html( number_format_i18n( count( (array) $signatures ) ) ); ?></p>
                <h3><?php esc_html_e( 'Critical Issues', SECURE_SHIELD_TEXT_DOMAIN ); ?></h3>
                <?php if ( empty( $results['critical'] ) ) : ?>
                    <p class="secure-shield__status--success"><?php esc_html_e( 'No critical issues found!', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                <?php else : ?>
                    <ul class="secure-shield__list secure-shield__list--danger">
                        <?php foreach ( $results['critical'] as $location => $description ) : ?>
                            <li>
                                <strong><?php echo esc_html( $location ); ?></strong> — <?php echo esc_html( $description ); ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                    <?php if ( ! empty( $results['ai_guidance'] ) ) : ?>
                        <div class="secure-shield__ai-panel">
                            <h3><?php esc_html_e( 'AI Remediation Guidance', SECURE_SHIELD_TEXT_DOMAIN ); ?></h3>
                            <?php foreach ( $results['ai_guidance'] as $file => $advice ) : ?>
                                <div class="secure-shield__ai-entry">
                                    <h4><?php echo esc_html( $file ); ?></h4>
                                    <?php foreach ( $advice as $source => $message ) : ?>
                                        <details>
                                            <summary><?php echo esc_html( ucfirst( $source ) ); ?></summary>
                                            <p><?php echo nl2br( esc_html( $message ) ); ?></p>
                                        </details>
                                    <?php endforeach; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Integrity Watch', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <?php $integrity = $results['integrity']['core'] ?? array(); ?>
            <?php if ( empty( $integrity ) ) : ?>
                <p class="secure-shield__status--success"><?php esc_html_e( 'Core checksums are verified against wordpress.org.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
            <?php else : ?>
                <ul class="secure-shield__list secure-shield__list--warning">
                    <?php foreach ( $integrity as $file => $message ) : ?>
                        <li><strong><?php echo esc_html( $file ); ?></strong> — <?php echo esc_html( $message ); ?></li>
                    <?php endforeach; ?>
                </ul>
                <?php if ( $settings->is_auto_repair_enabled() ) : ?>
                    <p><?php esc_html_e( 'Auto-repair attempted to restore mismatched files using trusted sources.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                <?php else : ?>
                    <p><?php esc_html_e( 'Enable auto-repair below to automatically fetch pristine core files when tampering is detected.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'File Permission Audit', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <?php if ( empty( $permissions ) ) : ?>
                <p class="secure-shield__status--success"><?php esc_html_e( 'Permissions look good!', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
            <?php else : ?>
                <ul class="secure-shield__list secure-shield__list--warning">
                    <?php foreach ( $permissions as $path => $issue ) : ?>
                        <li><strong><?php echo esc_html( $path ); ?></strong> — <?php echo esc_html( $issue ); ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Firewall Blocklist', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <?php if ( empty( $blocklist ) ) : ?>
                <p><?php esc_html_e( 'No IPs currently blocked.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
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
            <h2><?php esc_html_e( 'Backups', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <?php wp_nonce_field( 'secure_shield_backup' ); ?>
                <input type="hidden" name="action" value="secure_shield_backup" />
                <button type="submit" class="button button-secondary secure-shield__button-block">
                    <span class="dashicons dashicons-database"></span>
                    <?php esc_html_e( 'Create Backup', SECURE_SHIELD_TEXT_DOMAIN ); ?>
                </button>
            </form>

            <?php if ( ! empty( $backups ) ) : ?>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="secure-shield__restore-form">
                    <?php wp_nonce_field( 'secure_shield_restore' ); ?>
                    <input type="hidden" name="action" value="secure_shield_restore" />
                    <label for="backup_file"><?php esc_html_e( 'Restore from backup', SECURE_SHIELD_TEXT_DOMAIN ); ?></label>
                    <select name="backup_file" id="backup_file" class="secure-shield__select">
                        <?php foreach ( $backups as $backup_file ) : ?>
                            <option value="<?php echo esc_attr( $backup_file ); ?>"><?php echo esc_html( basename( $backup_file ) ); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <button type="submit" class="button button-warning secure-shield__button-block">
                        <span class="dashicons dashicons-update"></span>
                        <?php esc_html_e( 'Restore Backup', SECURE_SHIELD_TEXT_DOMAIN ); ?>
                    </button>
                </form>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card">
            <h2><?php esc_html_e( 'Theme Onboarding Scans', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <?php if ( empty( $theme_scans ) ) : ?>
                <p><?php esc_html_e( 'No recently installed themes have been scanned yet.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
            <?php else : ?>
                <table class="secure-shield__table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'Theme', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                            <th><?php esc_html_e( 'Scanned', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                            <th><?php esc_html_e( 'Critical Files', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                            <th><?php esc_html_e( 'AI Insights', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $theme_scans as $theme_slug => $scan_meta ) : ?>
                            <tr>
                                <td><?php echo esc_html( $theme_slug ); ?></td>
                                <td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $scan_meta['time'] ?? time() ) ); ?></td>
                                <td>
                                    <?php if ( empty( $scan_meta['critical'] ) ) : ?>
                                        <span class="status-pill status-pill--ok"><?php esc_html_e( 'Clean', SECURE_SHIELD_TEXT_DOMAIN ); ?></span>
                                    <?php else : ?>
                                        <ul>
                                            <?php foreach ( $scan_meta['critical'] as $file => $desc ) : ?>
                                                <li><?php echo esc_html( $file ); ?></li>
                                            <?php endforeach; ?>
                                        </ul>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ( empty( $scan_meta['ai_guidance'] ) ) : ?>
                                        <span class="status-pill status-pill--idle"><?php esc_html_e( 'No prompts yet', SECURE_SHIELD_TEXT_DOMAIN ); ?></span>
                                    <?php else : ?>
                                        <?php foreach ( $scan_meta['ai_guidance'] as $file => $guidance ) : ?>
                                            <details>
                                                <summary><?php echo esc_html( $file ); ?></summary>
                                                <?php foreach ( $guidance as $provider => $summary ) : ?>
                                                    <p><strong><?php echo esc_html( ucfirst( $provider ) ); ?>:</strong> <?php echo esc_html( wp_trim_words( $summary, 40 ) ); ?></p>
                                                <?php endforeach; ?>
                                            </details>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <div class="secure-shield__card secure-shield__card--wide">
            <h2><?php esc_html_e( 'Threat Intelligence & Integrations', SECURE_SHIELD_TEXT_DOMAIN ); ?></h2>
            <p><?php esc_html_e( 'BISON Security Suite synchronizes with open-source vulnerability databases and Cloudflare while keeping AI co-pilots ready for remediation.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
            <p><strong><?php esc_html_e( 'Last Signature Update:', SECURE_SHIELD_TEXT_DOMAIN ); ?></strong> <?php echo esc_html( $last_update ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last_update ) : __( 'Pending', SECURE_SHIELD_TEXT_DOMAIN ) ); ?></p>
            <form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
                <?php
                settings_fields( 'secure_shield' );
                do_settings_sections( 'secure_shield' );
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Real-time Feed Polling', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_realtime_updates" value="0" />
                            <label><input type="checkbox" name="secure_shield_realtime_updates" value="1" <?php checked( true, $settings->is_realtime_updates_enabled() ); ?> /> <?php esc_html_e( 'Refresh intelligence feeds every five minutes for rapid containment.', SECURE_SHIELD_TEXT_DOMAIN ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_wpscan_token"><?php esc_html_e( 'WPScan API Token', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td>
                            <input type="text" name="secure_shield_wpscan_token" id="secure_shield_wpscan_token" value="<?php echo esc_attr( $settings->get_wpscan_token() ); ?>" class="regular-text" />
                            <p class="description"><?php esc_html_e( 'Optional. Enables real-time ingestion of WordPress core, plugin, and theme advisories.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_nvd_api_key"><?php esc_html_e( 'NVD API Key', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td>
                            <input type="text" name="secure_shield_nvd_api_key" id="secure_shield_nvd_api_key" value="<?php echo esc_attr( $settings->get_nvd_api_key() ); ?>" class="regular-text" />
                            <p class="description"><?php esc_html_e( 'Optional. Improve National Vulnerability Database sync reliability and rate limits.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable OSV.dev Feed', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_osv_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_osv_enabled" value="1" <?php checked( true, $settings->is_osv_enabled() ); ?> /> <?php esc_html_e( 'Pull advisories for the WordPress ecosystem from OSV.dev.', SECURE_SHIELD_TEXT_DOMAIN ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable ThreatFox Feed', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_threatfox_enabled" value="0" />
                            <label><input type="checkbox" name="secure_shield_threatfox_enabled" value="1" <?php checked( true, $settings->is_threatfox_enabled() ); ?> /> <?php esc_html_e( 'Continuously ingest AbuseCH ThreatFox malware signatures.', SECURE_SHIELD_TEXT_DOMAIN ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Enable Core Auto-Repair', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                        <td>
                            <input type="hidden" name="secure_shield_auto_repair" value="0" />
                            <label><input type="checkbox" name="secure_shield_auto_repair" value="1" <?php checked( true, $settings->is_auto_repair_enabled() ); ?> /> <?php esc_html_e( 'Automatically fetch pristine WordPress core files when tampering is detected.', SECURE_SHIELD_TEXT_DOMAIN ); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_gemini_api_key"><?php esc_html_e( 'Gemini API Key', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td>
                            <input type="text" name="secure_shield_gemini_api_key" id="secure_shield_gemini_api_key" value="<?php echo esc_attr( $settings->get_gemini_api_key() ); ?>" class="regular-text" />
                            <p class="description"><?php esc_html_e( 'Required for real-time remediation guidance via Google Gemini.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_gemini_model"><?php esc_html_e( 'Gemini Model', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td>
                            <input type="text" name="secure_shield_gemini_model" id="secure_shield_gemini_model" value="<?php echo esc_attr( $settings->get_gemini_model() ); ?>" class="regular-text" />
                            <p class="description"><?php esc_html_e( 'Default is models/gemini-pro. Override to track the latest release.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_hf_api_key"><?php esc_html_e( 'Hugging Face API Key', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td>
                            <input type="text" name="secure_shield_hf_api_key" id="secure_shield_hf_api_key" value="<?php echo esc_attr( $settings->get_hf_api_key() ); ?>" class="regular-text" />
                            <p class="description"><?php esc_html_e( 'Use a free inference token to unlock open-source malware triage models.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_hf_model"><?php esc_html_e( 'Hugging Face Model', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td>
                            <input type="text" name="secure_shield_hf_model" id="secure_shield_hf_model" value="<?php echo esc_attr( $settings->get_hf_model() ); ?>" class="regular-text" />
                            <p class="description"><?php esc_html_e( 'Provide any compatible text-generation model slug. BISON suggests the openai-community/gpt2 baseline.', SECURE_SHIELD_TEXT_DOMAIN ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_cloudflare_email"><?php esc_html_e( 'Cloudflare Email', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td><input type="email" name="secure_shield_cloudflare_email" id="secure_shield_cloudflare_email" value="<?php echo esc_attr( get_option( 'secure_shield_cloudflare_email', '' ) ); ?>" class="regular-text" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_cloudflare_token"><?php esc_html_e( 'Cloudflare API Token', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td><input type="text" name="secure_shield_cloudflare_token" id="secure_shield_cloudflare_token" value="<?php echo esc_attr( $settings->get_secret_option( 'secure_shield_cloudflare_token' ) ); ?>" class="regular-text" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="secure_shield_cloudflare_zone"><?php esc_html_e( 'Cloudflare Zone ID', SECURE_SHIELD_TEXT_DOMAIN ); ?></label></th>
                        <td><input type="text" name="secure_shield_cloudflare_zone" id="secure_shield_cloudflare_zone" value="<?php echo esc_attr( get_option( 'secure_shield_cloudflare_zone', '' ) ); ?>" class="regular-text" /></td>
                    </tr>
                </table>
                <?php submit_button( __( 'Save Settings', SECURE_SHIELD_TEXT_DOMAIN ) ); ?>
            </form>
        </div>
    </div>
</div>
