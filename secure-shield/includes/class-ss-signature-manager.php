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

        if ( ! wp_next_scheduled( 'secure_shield_update_signatures' ) ) {
            wp_schedule_event( time(), 'twicedaily', 'secure_shield_update_signatures' );
        }
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
            // Basic obfuscation and execution
            'base64_decode('                                   => __( 'Obfuscated payload via base64_decode', 'secure-shield' ),
            'gzinflate('                                       => __( 'Compressed malware payload', 'secure-shield' ),
            'gzuncompress('                                    => __( 'Compressed malware payload', 'secure-shield' ),
            'str_rot13('                                       => __( 'ROT13 obfuscated code', 'secure-shield' ),
            'convert_uudecode('                                => __( 'UUencoded payload', 'secure-shield' ),
            'eval('                                            => __( 'Dynamic code execution', 'secure-shield' ),
            'assert('                                          => __( 'Code execution via assert', 'secure-shield' ),
            'preg_replace_callback('                           => __( 'Potential callback execution', 'secure-shield' ),
            'regex:/preg_replace\s*\(\s*[\'\"][^\'\"]+\/e[\'\"]/i' => __( 'Deprecated preg_replace /e misuse', 'secure-shield' ),
            'create_function('                                 => __( 'Deprecated dynamic function creation', 'secure-shield' ),

            // Command execution
            'shell_exec('                                      => __( 'Shell command execution', 'secure-shield' ),
            'exec('                                            => __( 'Command execution', 'secure-shield' ),
            'passthru('                                        => __( 'Command execution passthru', 'secure-shield' ),
            'system('                                          => __( 'System command execution', 'secure-shield' ),
            'proc_open('                                       => __( 'Process execution', 'secure-shield' ),
            'popen('                                           => __( 'Pipe command execution', 'secure-shield' ),
            'pcntl_exec('                                      => __( 'Process control execution', 'secure-shield' ),
            '`'                                                => __( 'Backtick command execution', 'secure-shield' ),

            // File operations (malicious)
            'file_put_contents('                               => __( 'File writing operation', 'secure-shield' ),
            'fwrite('                                          => __( 'File write operation', 'secure-shield' ),
            'fputs('                                           => __( 'File output operation', 'secure-shield' ),
            'file_get_contents("http'                          => __( 'Remote file inclusion attempt', 'secure-shield' ),
            'curl_exec('                                       => __( 'Remote content fetch', 'secure-shield' ),
            'fsockopen('                                       => __( 'Socket connection', 'secure-shield' ),
            'pfsockopen('                                      => __( 'Persistent socket connection', 'secure-shield' ),
            'stream_socket_client('                            => __( 'Stream socket connection', 'secure-shield' ),

            // Database operations (suspicious)
            'mysql_query('                                     => __( 'Deprecated MySQL query', 'secure-shield' ),
            'mysqli_query('                                    => __( 'Direct database query', 'secure-shield' ),
            'mysql_connect('                                   => __( 'Deprecated MySQL connection', 'secure-shield' ),
            'mysqli_multi_query('                              => __( 'Multiple SQL queries', 'secure-shield' ),

            // Known web shell signatures
            'c99shell'                                         => __( 'C99 web shell detected', 'secure-shield' ),
            'r57shell'                                         => __( 'R57 web shell detected', 'secure-shield' ),
            'wso shell'                                        => __( 'WSO web shell detected', 'secure-shield' ),
            'b374k'                                            => __( 'B374K web shell detected', 'secure-shield' ),
            'regex:/\$_(GET|POST|REQUEST)\[.*\]\s*\(\s*\$_(GET|POST|REQUEST)/i' => __( 'Variable function execution pattern', 'secure-shield' ),
            'FilesMan'                                         => __( 'FilesMan web shell component', 'secure-shield' ),
            'Remoteshell'                                      => __( 'Remote shell indicator', 'secure-shield' ),
            'regex:/function\s+wso_/i'                         => __( 'WSO shell function pattern', 'secure-shield' ),

            // WordPress-specific threats
            'wp_ajax_nopriv_'                                  => __( 'Unprotected AJAX endpoint', 'secure-shield' ),
            'add_action(\'wp_head\','                          => __( 'Potential header injection', 'secure-shield' ),
            'regex:/add_action\s*\(\s*[\'"]wp_footer[\'"]\s*,\s*[\'"](?!wp_)/i' => __( 'Suspicious footer hook', 'secure-shield' ),
            'regex:/wp_remote_(get|post)\s*\([^)]*base64/i'   => __( 'WordPress HTTP with base64', 'secure-shield' ),
            'regex:/\$wpdb->query\s*\(\s*\$_(GET|POST|REQUEST)/i' => __( 'SQL injection via WordPress DB', 'secure-shield' ),

            // Crypto miners
            'coinhive'                                         => __( 'CoinHive cryptominer', 'secure-shield' ),
            'crypto-loot'                                      => __( 'CryptoLoot miner', 'secure-shield' ),
            'webminepool'                                      => __( 'WebMinePool cryptominer', 'secure-shield' ),
            'minero.cc'                                        => __( 'Minero cryptominer', 'secure-shield' ),
            'regex:/new\s+Worker\s*\(\s*[\'"].*cryptonight/i' => __( 'Cryptonight web miner', 'secure-shield' ),
            'regex:/\.mine\s*\(\s*[\'"][a-zA-Z0-9]{40,}/i'    => __( 'Cryptocurrency mining script', 'secure-shield' ),

            // Backdoors and malicious redirects
            'regex:/@include\s+[\'"]http/i'                   => __( 'Remote file inclusion', 'secure-shield' ),
            'regex:/@require\s+[\'"]http/i'                   => __( 'Remote file requirement', 'secure-shield' ),
            'regex:/header\s*\(\s*[\'"]location.*\$_(GET|POST|REQUEST)/i' => __( 'Redirect injection', 'secure-shield' ),
            'regex:/meta\s+http-equiv.*refresh.*\$_(GET|POST)/i' => __( 'Meta refresh injection', 'secure-shield' ),
            'regex:/\$_COOKIE\[[\'\"][^\'"]+[\'\"]\]\s*\(/i'  => __( 'Cookie-based code execution', 'secure-shield' ),
            'regex:/\$_(SERVER|ENV)\[[\'\"]HTTP_.*[\'\"]\]\s*\(/i' => __( 'Header-based code execution', 'secure-shield' ),

            // SQL injection patterns
            'regex:/union\s+select/i'                          => __( 'SQL UNION injection', 'secure-shield' ),
            'regex:/concat\s*\(.*char\s*\(/i'                 => __( 'SQL concat injection', 'secure-shield' ),
            'regex:/0x[0-9a-f]{8,}/i'                         => __( 'Hexadecimal SQL injection', 'secure-shield' ),
            'regex:/benchmark\s*\(\s*\d+/i'                   => __( 'SQL benchmark attack', 'secure-shield' ),
            'regex:/sleep\s*\(\s*\d+/i'                       => __( 'SQL time-based injection', 'secure-shield' ),

            // XSS patterns
            'document.cookie'                                  => __( 'Cookie stealing attempt', 'secure-shield' ),
            'onerror='                                         => __( 'Inline onerror event handler', 'secure-shield' ),
            'onload='                                          => __( 'Inline onload event handler', 'secure-shield' ),
            'javascript:'                                      => __( 'JavaScript protocol handler', 'secure-shield' ),
            'regex:/<script[^>]*src\s*=\s*[\'"]http[^\'\"]+[\'\"]/i' => __( 'External script injection', 'secure-shield' ),
            'regex:/<iframe[^>]*src\s*=\s*[\'"]http/i'        => __( 'Iframe injection', 'secure-shield' ),

            // Ransomware indicators
            'regex:/\.(encrypted|locked|crypto|crypted|EnCiPhErEd)/i' => __( 'Ransomware file extension', 'secure-shield' ),
            'regex:/your\s+files?\s+(have\s+been\s+)?encrypted/i' => __( 'Ransomware message', 'secure-shield' ),
            'regex:/pay.*bitcoin/i'                           => __( 'Ransomware payment demand', 'secure-shield' ),

            // Information disclosure
            'phpinfo()'                                        => __( 'PHP information disclosure', 'secure-shield' ),
            'php_uname('                                       => __( 'System information disclosure', 'secure-shield' ),
            'getmyuid('                                        => __( 'UID disclosure', 'secure-shield' ),
            'getmypid('                                        => __( 'Process ID disclosure', 'secure-shield' ),
            'regex:/var_dump\s*\(\s*\$_(SERVER|POST|GET|COOKIE)/i' => __( 'Sensitive variable dump', 'secure-shield' ),

            // Serialization exploits
            'unserialize('                                     => __( 'Unsafe deserialization', 'secure-shield' ),
            'regex:/unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i' => __( 'User input deserialization', 'secure-shield' ),

            // Malicious constants and variables
            'regex:/\$GLOBALS\[[\'\"]_+[A-Z0-9]+_+[\'\"]\]/i' => __( 'Obfuscated global variable', 'secure-shield' ),
            'regex:/\${[\'"]\w+[\'"]}/'                       => __( 'Variable variable pattern', 'secure-shield' ),
            'regex:/\$\{[\s]*[\'"]/i'                         => __( 'Complex variable syntax', 'secure-shield' ),

            // Reverse shells
            'regex:/socket_create.*socket_connect/is'         => __( 'Socket-based reverse shell', 'secure-shield' ),
            'regex:/proc_open.*descriptorspec/i'              => __( 'Process-based reverse shell', 'secure-shield' ),
            'regex:/fsockopen.*\/bin\/(bash|sh)/i'            => __( 'Shell reverse connection', 'secure-shield' ),
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
        do_action( 'secure_shield/log', __( 'Threat intelligence feeds updated.', 'secure-shield' ) );
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
                $signatures[ $line ] = __( 'Threat intelligence feed match', 'secure-shield' );
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
            $signatures[ sanitize_text_field( $item['cve']['id'] ) ] = sanitize_text_field( $description ?: __( 'NVD reported vulnerability', 'secure-shield' ) );
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

            $summary = $vuln['summary'] ?? ( $vuln['details'] ?? __( 'Open source vulnerability advisory', 'secure-shield' ) );
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
            $this->parse_wpscan_payload( $response, $signatures, sprintf( __( 'Plugin: %s', 'secure-shield' ), $slug ) );
        }

        $theme = wp_get_theme();
        if ( $theme && $theme->exists() ) {
            $slug     = sanitize_title( $theme->get_stylesheet() );
            $response = wp_remote_get( "https://wpscan.com/api/v3/themes/{$slug}", array( 'timeout' => 20, 'headers' => $headers ) );
            $this->parse_wpscan_payload( $response, $signatures, sprintf( __( 'Theme: %s', 'secure-shield' ), $slug ) );
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
            $signatures[ $key ] = sanitize_text_field( $description ?: __( 'WPScan reported vulnerability', 'secure-shield' ) );
        }
    }
}
