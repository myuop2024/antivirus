<?php
/**
 * Handles malware signatures and threat intelligence feeds.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Signature_Manager {

    const OPTION_SIGNATURES = 'secure_shield_signatures';
    const OPTION_LAST_UPDATE = 'secure_shield_signatures_updated';

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Settings handler.
     *
     * @var Secure_Shield_Settings
     */
    protected $settings;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger   $logger   Logger instance.
     * @param Secure_Shield_Settings $settings Settings handler.
     */
    public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Settings $settings ) {
        $this->logger   = $logger;
        $this->settings = $settings;
    }

    /**
     * Register update scheduling.
     */
    public function register() {
        add_action( 'secure_shield_update_signatures', array( $this, 'update_signatures' ) );
        add_action( 'secure_shield_realtime_update', array( $this, 'update_signatures_if_needed' ) );
        add_action( 'update_option_secure_shield_realtime_updates', array( $this, 'handle_realtime_toggle' ), 10, 2 );

        if ( ! wp_next_scheduled( 'secure_shield_update_signatures' ) ) {
            wp_schedule_event( time(), 'twicedaily', 'secure_shield_update_signatures' );
        }

        $this->maybe_schedule_realtime();
    }

    /**
     * Get stored signatures.
     *
     * @return array
     */
    public function get_signatures() {
        $signatures = get_option( self::OPTION_SIGNATURES, array() );

        if ( empty( $signatures ) ) {
            $signatures = $this->default_signatures();
            update_option( self::OPTION_SIGNATURES, $signatures, false );
        }

        return $signatures;
    }

    /**
     * Default signature patterns using open source intel.
     *
     * @return array
     */
    protected function default_signatures() {
        return array(
            'base64_decode(' => __( 'Obfuscated payload via base64_decode', SECURE_SHIELD_TEXT_DOMAIN ),
            'gzinflate('      => __( 'Compressed malware payload', SECURE_SHIELD_TEXT_DOMAIN ),
            'shell_exec('     => __( 'Potential command execution', SECURE_SHIELD_TEXT_DOMAIN ),
            'passthru('       => __( 'Potential command execution', SECURE_SHIELD_TEXT_DOMAIN ),
            'preg_replace("/.*e"' => __( 'Deprecated preg_replace /e misuse', SECURE_SHIELD_TEXT_DOMAIN ),
            'wp_ajax_nopriv_' => __( 'Unprotected AJAX endpoint', SECURE_SHIELD_TEXT_DOMAIN ),
            'document.cookie' => __( 'Potential cross-site scripting', SECURE_SHIELD_TEXT_DOMAIN ),
            'onerror='        => __( 'Inline event handler suspicious', SECURE_SHIELD_TEXT_DOMAIN ),
            'eval('           => __( 'Dynamic code execution', SECURE_SHIELD_TEXT_DOMAIN ),
        );
    }

    /**
     * Update signatures from external feeds.
     */
    public function update_signatures() {
        $signatures = $this->default_signatures();

        $this->ingest_text_feeds( $signatures );
        $this->ingest_cve_feed( $signatures );
        $this->ingest_nvd_feed( $signatures );
        $this->ingest_osv_feed( $signatures );
        $this->ingest_wpscan_feed( $signatures );

        update_option( self::OPTION_SIGNATURES, $signatures, false );
        update_option( self::OPTION_LAST_UPDATE, current_time( 'timestamp' ), false );
        do_action( 'secure_shield/log', __( 'Threat intelligence feeds updated.', SECURE_SHIELD_TEXT_DOMAIN ) );
    }

    /**
     * Update signatures if the previous refresh is stale.
     */
    public function update_signatures_if_needed() {
        if ( ! $this->settings->is_realtime_updates_enabled() ) {
            return;
        }

        $last_update = (int) get_option( self::OPTION_LAST_UPDATE, 0 );
        $now         = current_time( 'timestamp' );
        if ( ( $now - $last_update ) < 300 ) {
            return;
        }

        $this->update_signatures();
    }

    /**
     * Handle realtime toggle updates from settings.
     *
     * @param string $old_value Previous value.
     * @param string $value     New value.
     */
    public function handle_realtime_toggle( $old_value, $value ) {
        unset( $old_value );

        if ( '1' === $value ) {
            $this->maybe_schedule_realtime();
            $this->update_signatures_if_needed();
        } else {
            wp_clear_scheduled_hook( 'secure_shield_realtime_update' );
        }
    }

    /**
     * Ensure realtime update scheduling aligns with configuration.
     */
    protected function maybe_schedule_realtime() {
        if ( $this->settings->is_realtime_updates_enabled() ) {
            if ( ! wp_next_scheduled( 'secure_shield_realtime_update' ) ) {
                wp_schedule_event( time(), 'secure_shield_5m', 'secure_shield_realtime_update' );
            }
        } else {
            wp_clear_scheduled_hook( 'secure_shield_realtime_update' );
        }
    }

    /**
     * Ingest plain-text indicator feeds.
     *
     * @param array $signatures Reference to signature array.
     */
    protected function ingest_text_feeds( array &$signatures ) {
        $feeds = array(
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/malware_index.yar',
            'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        );

        if ( $this->settings->is_threatfox_enabled() ) {
            $feeds[] = 'https://threatfox.abuse.ch/downloads/malware_signatures.csv';
        }

        foreach ( $feeds as $feed ) {
            $response = wp_remote_get( $feed, array( 'timeout' => 20 ) );
            if ( is_wp_error( $response ) ) {
                do_action( 'secure_shield/log', sprintf( 'Failed to fetch feed %s: %s', $feed, $response->get_error_message() ), 'warning' );
                continue;
            }

            $body = wp_remote_retrieve_body( $response );
            if ( empty( $body ) ) {
                continue;
            }

            $lines = preg_split( '/\r?\n/', $body );
            foreach ( $lines as $line ) {
                $line = trim( $line );
                if ( empty( $line ) || strpos( $line, '#' ) === 0 ) {
                    continue;
                }
                $signatures[ $line ] = __( 'Threat intelligence feed match', SECURE_SHIELD_TEXT_DOMAIN );
            }
        }
    }

    /**
     * Ingest the latest CVEs from CIRCL.
     *
     * @param array $signatures Reference to signature array.
     */
    protected function ingest_cve_feed( array &$signatures ) {
        $response = wp_remote_get( 'https://cve.circl.lu/api/last', array( 'timeout' => 20 ) );
        if ( is_wp_error( $response ) ) {
            do_action( 'secure_shield/log', sprintf( 'Failed to fetch CIRCL feed: %s', $response->get_error_message() ), 'warning' );
            return;
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $data ) ) {
            return;
        }

        foreach ( $data as $entry ) {
            if ( empty( $entry['id'] ) || empty( $entry['summary'] ) ) {
                continue;
            }

            $signatures[ sanitize_text_field( $entry['id'] ) ] = sanitize_text_field( $entry['summary'] );
        }
    }

    /**
     * Ingest NVD CVE data when an API key is available.
     *
     * @param array $signatures Reference to signature array.
     */
    protected function ingest_nvd_feed( array &$signatures ) {
        $api_key = $this->settings->get_nvd_api_key();
        if ( empty( $api_key ) ) {
            return;
        }

        $params = array(
            'lastModStartDate' => gmdate( 'Y-m-d\TH:i:s\Z', strtotime( '-7 days' ) ),
            'lastModEndDate'   => gmdate( 'Y-m-d\TH:i:s\Z' ),
            'keywordSearch'    => 'wordpress',
        );

        $response = wp_remote_get(
            add_query_arg( $params, 'https://services.nvd.nist.gov/rest/json/cves/2.0' ),
            array(
                'timeout' => 20,
                'headers' => array(
                    'apiKey'    => $api_key,
                    'X-Api-Key' => $api_key,
                ),
            )
        );

        if ( is_wp_error( $response ) ) {
            do_action( 'secure_shield/log', sprintf( 'Failed to fetch NVD feed: %s', $response->get_error_message() ), 'warning' );
            return;
        }

        $payload = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $payload['vulnerabilities'] ) || ! is_array( $payload['vulnerabilities'] ) ) {
            return;
        }

        foreach ( $payload['vulnerabilities'] as $item ) {
            if ( empty( $item['cve']['id'] ) ) {
                continue;
            }
            $description = '';
            if ( ! empty( $item['cve']['descriptions'] ) && is_array( $item['cve']['descriptions'] ) ) {
                $description = $item['cve']['descriptions'][0]['value'] ?? '';
            }
            $signatures[ sanitize_text_field( $item['cve']['id'] ) ] = sanitize_text_field( $description ?: __( 'NVD reported vulnerability', SECURE_SHIELD_TEXT_DOMAIN ) );
        }
    }

    /**
     * Ingest vulnerabilities from OSV.dev when enabled.
     *
     * @param array $signatures Reference to signature array.
     */
    protected function ingest_osv_feed( array &$signatures ) {
        if ( ! $this->settings->is_osv_enabled() ) {
            return;
        }

        $response = wp_remote_post(
            'https://api.osv.dev/v1/query',
            array(
                'timeout' => 20,
                'headers' => array( 'Content-Type' => 'application/json' ),
                'body'    => wp_json_encode(
                    array(
                        'package' => array(
                            'ecosystem' => 'WordPress',
                            'name'      => 'wordpress',
                        ),
                    )
                ),
            )
        );

        if ( is_wp_error( $response ) ) {
            do_action( 'secure_shield/log', sprintf( 'Failed to fetch OSV feed: %s', $response->get_error_message() ), 'warning' );
            return;
        }

        $payload = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $payload['vulns'] ) || ! is_array( $payload['vulns'] ) ) {
            return;
        }

        foreach ( $payload['vulns'] as $vuln ) {
            if ( empty( $vuln['id'] ) ) {
                continue;
            }

            $summary = $vuln['summary'] ?? ( $vuln['details'] ?? __( 'Open source vulnerability advisory', SECURE_SHIELD_TEXT_DOMAIN ) );
            $signatures[ sanitize_text_field( $vuln['id'] ) ] = sanitize_text_field( $summary );
        }
    }

    /**
     * Ingest WordPress-specific vulnerabilities from WPScan when configured.
     *
     * @param array $signatures Reference to signature array.
     */
    protected function ingest_wpscan_feed( array &$signatures ) {
        $token = $this->settings->get_wpscan_token();
        if ( empty( $token ) ) {
            return;
        }

        $headers = array(
            'Authorization' => 'Token token=' . $token,
        );

        $version = get_bloginfo( 'version' );
        $core    = wp_remote_get( "https://wpscan.com/api/v3/wordpresses/{$version}", array( 'timeout' => 20, 'headers' => $headers ) );
        $this->parse_wpscan_payload( $core, $signatures, 'WordPress Core' );

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins = array_keys( (array) get_plugins() );
        foreach ( $plugins as $plugin_file ) {
            $slug = dirname( $plugin_file );
            if ( '.' === $slug || empty( $slug ) ) {
                $slug = basename( $plugin_file, '.php' );
            }
            $slug     = sanitize_title( $slug );
            $response = wp_remote_get( "https://wpscan.com/api/v3/plugins/{$slug}", array( 'timeout' => 20, 'headers' => $headers ) );
            $this->parse_wpscan_payload( $response, $signatures, sprintf( __( 'Plugin: %s', SECURE_SHIELD_TEXT_DOMAIN ), $slug ) );
        }

        $theme = wp_get_theme();
        if ( $theme && $theme->exists() ) {
            $slug     = sanitize_title( $theme->get_stylesheet() );
            $response = wp_remote_get( "https://wpscan.com/api/v3/themes/{$slug}", array( 'timeout' => 20, 'headers' => $headers ) );
            $this->parse_wpscan_payload( $response, $signatures, sprintf( __( 'Theme: %s', SECURE_SHIELD_TEXT_DOMAIN ), $slug ) );
        }
    }

    /**
     * Parse the WPScan API payload and append to signatures.
     *
     * @param array|WP_Error $response   WP HTTP response.
     * @param array          $signatures Signatures reference.
     * @param string         $context    Context label.
     */
    protected function parse_wpscan_payload( $response, array &$signatures, $context ) {
        if ( is_wp_error( $response ) ) {
            do_action( 'secure_shield/log', sprintf( 'Failed to fetch WPScan feed for %s: %s', $context, $response->get_error_message() ), 'warning' );
            return;
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( 200 !== $code ) {
            return;
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $data['vulnerabilities'] ) || ! is_array( $data['vulnerabilities'] ) ) {
            return;
        }

        foreach ( $data['vulnerabilities'] as $vulnerability ) {
            if ( empty( $vulnerability['title'] ) ) {
                continue;
            }

            $key = sprintf( '%s — %s', $context, sanitize_text_field( $vulnerability['title'] ) );
            $description = $vulnerability['description'] ?? ( $vulnerability['references']['url'][0] ?? '' );
            $signatures[ $key ] = sanitize_text_field( $description ?: __( 'WPScan reported vulnerability', SECURE_SHIELD_TEXT_DOMAIN ) );
        }
    }
}
