<?php
/**
 * Application firewall and bot mitigation.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Firewall {

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Signature manager instance.
     *
     * @var Secure_Shield_Signature_Manager
     */
    protected $signatures;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger           $logger     Logger instance.
     * @param Secure_Shield_Signature_Manager $signatures Signature manager instance.
     */
    public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Signature_Manager $signatures ) {
        $this->logger     = $logger;
        $this->signatures = $signatures;
    }

    /**
     * Register firewall hooks.
     */
    public function register() {
        add_action( 'init', array( $this, 'apply_security_headers' ) );
        add_action( 'init', array( $this, 'enforce_origin_policies' ), 1 );
        add_action( 'plugins_loaded', array( $this, 'monitor_requests' ), 1 );
        add_action( 'template_redirect', array( $this, 'prevent_author_enumeration' ), 0 );
        add_filter( 'rest_pre_dispatch', array( $this, 'scrutinize_rest_requests' ), 10, 3 );
        add_filter( 'wp_handle_upload_prefilter', array( $this, 'inspect_uploads' ) );
        add_action( 'xmlrpc_call', array( $this, 'guard_xmlrpc_call' ) );
    }

    /**
     * Apply HTTP security headers.
     */
    public function apply_security_headers() {
        if ( headers_sent() ) {
            return;
        }

        header( 'X-Frame-Options: SAMEORIGIN' );
        header( 'X-Content-Type-Options: nosniff' );
        header( 'Referrer-Policy: strict-origin-when-cross-origin' );
        header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
        header( "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https:; object-src 'none'; frame-ancestors 'self'" );
    }

    /**
     * Monitor requests for suspicious patterns.
     */
    public function monitor_requests() {
        if ( is_admin() && ! wp_doing_ajax() ) {
            return;
        }

        $ip         = $this->get_ip_address();
        $uri        = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        $method     = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';

        if ( $this->is_denied_user_agent( $user_agent ) ) {
            $this->block_ip( $ip, sprintf( 'Denied user agent detected: %s', $user_agent ) );
            wp_die( esc_html__( 'Request blocked by Secure Shield.', 'secure-shield' ), esc_html__( 'Blocked', 'secure-shield' ), 403 );
        }

        $payload_parts = array(
            'uri'      => $uri,
            'query'    => wp_unslash( $_GET ),
            'post'     => wp_unslash( $_POST ),
            'cookies'  => wp_unslash( $_COOKIE ),
            'raw_body' => file_get_contents( 'php://input' ),
        );

        $payload = wp_json_encode( $payload_parts );
        $this->inspect_with_signatures( $payload, $ip );

        if ( empty( $user_agent ) || strlen( $user_agent ) < 5 ) {
            do_action( 'secure_shield/log', sprintf( 'Request allowed with short/empty user agent from %s', $ip ), 'notice' );
        }

        if ( 'POST' === $method && $this->looks_like_csrf_probe( $payload_parts ) ) {
            $this->block_ip( $ip, 'Potential CSRF probe detected.' );
            wp_die( esc_html__( 'Request blocked by Secure Shield.', 'secure-shield' ), esc_html__( 'Blocked', 'secure-shield' ), 403 );
        }
    }

    /**
     * Enforce strict origin policies for state-changing requests.
     */
    public function enforce_origin_policies() {
        if ( empty( $_SERVER['REQUEST_METHOD'] ) ) {
            return;
        }

        $method = strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) );
        if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) ) {
            return;
        }

        if ( wp_doing_cron() || defined( 'XMLRPC_REQUEST' ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
            return;
        }

        $origin  = isset( $_SERVER['HTTP_ORIGIN'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_ORIGIN'] ) ) : '';
        $referer = isset( $_SERVER['HTTP_REFERER'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
        $host    = wp_parse_url( home_url(), PHP_URL_HOST );

        $has_origin_header = ! empty( $origin ) || ! empty( $referer );

        $valid = false;
        foreach ( array( $origin, $referer ) as $header ) {
            if ( empty( $header ) ) {
                continue;
            }

            $header_host = wp_parse_url( $header, PHP_URL_HOST );
            if ( ! empty( $header_host ) && $header_host === $host ) {
                $valid = true;
                break;
            }
        }

        if ( ! $has_origin_header && ! is_user_logged_in() ) {
            do_action( 'secure_shield/log', 'State-changing request allowed without Origin/Referer headers.', 'notice' );
            return;
        }

        if ( $has_origin_header && ! $valid && ! is_user_logged_in() ) {
            $ip = $this->get_ip_address();
            $this->block_ip( $ip, 'State-changing request without trusted origin headers.' );
            wp_die( esc_html__( 'Request blocked by Secure Shield.', 'secure-shield' ), esc_html__( 'Blocked', 'secure-shield' ), 403 );
        }
    }

    /**
     * Prevent public author enumeration via ?author= queries.
     */
    public function prevent_author_enumeration() {
        if ( is_admin() ) {
            return;
        }

        $author = get_query_var( 'author' );
        if ( ! empty( $author ) && is_numeric( $author ) && ! is_user_logged_in() ) {
            $ip = $this->get_ip_address();
            $this->block_ip( $ip, 'Author enumeration attempt blocked.' );
            wp_die( esc_html__( 'Request blocked by Secure Shield.', 'secure-shield' ), esc_html__( 'Blocked', 'secure-shield' ), 403 );
        }
    }

    /**
     * Scrutinize REST API requests and prevent sensitive enumeration.
     *
     * @param mixed           $result  Response to replace.
     * @param WP_REST_Server  $server  Server instance.
     * @param WP_REST_Request $request Incoming request.
     *
     * @return mixed
     */
    public function scrutinize_rest_requests( $result, $server, $request ) {
        if ( ! ( $request instanceof WP_REST_Request ) ) {
            return $result;
        }

        $route  = $request->get_route();
        $method = $request->get_method();
        $ip     = $this->get_ip_address();

        if ( 'GET' === $method && preg_match( '#/wp/v2/users#', $route ) && ! current_user_can( 'list_users' ) ) {
            $this->block_ip( $ip, 'REST API user enumeration blocked.' );
            return new WP_Error( 'secure_shield_rest_blocked', __( 'User enumeration blocked by Secure Shield.', 'secure-shield' ), array( 'status' => 403 ) );
        }

        $payload = wp_json_encode( array(
            'route'   => $route,
            'params'  => $request->get_params(),
            'headers' => $request->get_headers(),
            'body'    => $request->get_body(),
        ) );

        if ( $this->inspect_with_signatures( $payload, $ip, false ) ) {
            return new WP_Error( 'secure_shield_rest_blocked', __( 'REST API payload blocked by Secure Shield.', 'secure-shield' ), array( 'status' => 403 ) );
        }

        return $result;
    }

    /**
     * Inspect upload files and stop malicious extensions.
     *
     * @param array $file Uploaded file array.
     *
     * @return array|WP_Error
     */
    public function inspect_uploads( $file ) {
        if ( empty( $file['name'] ) ) {
            return $file;
        }

        $filename = $file['name'];
        $extension = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

        // Comprehensive list of dangerous extensions
        $blocked = array(
            // PHP variants
            'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'phar',
            // Perl/CGI
            'cgi', 'pl', 'plx',
            // Python
            'py', 'pyc', 'pyo',
            // Shell scripts
            'sh', 'bash', 'zsh', 'ksh', 'command',
            // Executables
            'exe', 'com', 'bat', 'cmd', 'scr', 'vbs', 'vbe', 'ws', 'wsf',
            // ASP/ASPX
            'asp', 'aspx', 'cer', 'asa', 'asax',
            // JSP
            'jsp', 'jspx',
            // SSI
            'shtml', 'shtm', 'stm',
            // Other dangerous
            'dll', 'so', 'htaccess', 'htpasswd', 'ini', 'config',
        );

        if ( in_array( $extension, $blocked, true ) ) {
            $ip = $this->get_ip_address();
            $this->block_ip( $ip, sprintf( 'Upload blocked for dangerous extension: %s', $extension ) );
            return new WP_Error( 'secure_shield_upload_blocked', __( 'This file type is not allowed for security reasons.', 'secure-shield' ) );
        }

        // Check for double extensions (e.g., file.php.jpg)
        if ( preg_match( '/\.(php|phtml|pl|py|cgi|asp|jsp|sh|exe)\./i', $filename ) ) {
            $ip = $this->get_ip_address();
            $this->block_ip( $ip, sprintf( 'Upload blocked for double extension: %s', $filename ) );
            return new WP_Error( 'secure_shield_upload_blocked', __( 'Files with double extensions are not allowed.', 'secure-shield' ) );
        }

        // Check for null byte injection
        if ( strpos( $filename, "\0" ) !== false ) {
            $ip = $this->get_ip_address();
            $this->block_ip( $ip, 'Upload blocked for null byte in filename' );
            return new WP_Error( 'secure_shield_upload_blocked', __( 'Invalid filename detected.', 'secure-shield' ) );
        }

        // If tmp_name exists, scan the actual file content for PHP tags
        if ( ! empty( $file['tmp_name'] ) && file_exists( $file['tmp_name'] ) ) {
            $content = @file_get_contents( $file['tmp_name'], false, null, 0, 1024 ); // Read first 1KB
            if ( false !== $content ) {
                // Check for PHP opening tags in non-PHP files
                if ( ! in_array( $extension, array( 'php', 'phtml' ), true ) && preg_match( '/<\?php/i', $content ) ) {
                    $ip = $this->get_ip_address();
                    $this->block_ip( $ip, sprintf( 'Upload blocked: PHP code in %s file', $extension ) );
                    return new WP_Error( 'secure_shield_upload_blocked', __( 'File contains suspicious content.', 'secure-shield' ) );
                }
            }
        }

        return $file;
    }

    /**
     * Guard XML-RPC calls against brute-force and pingback abuse.
     *
     * @param string $method XML-RPC method name.
     */
    public function guard_xmlrpc_call( $method ) {
        $ip = $this->get_ip_address();

        if ( in_array( $method, array( 'pingback.ping', 'pingback.extensions.getPingbacks' ), true ) ) {
            $this->block_ip( $ip, sprintf( 'Blocked XML-RPC method: %s', $method ) );
            wp_die( esc_html__( 'XML-RPC method blocked by Secure Shield.', 'secure-shield' ), esc_html__( 'Blocked', 'secure-shield' ), 403 );
        }
    }

    /**
     * Inspect payload against signature intelligence.
     *
     * @param string $payload Encoded payload to scan.
     * @param string $ip      Client IP.
     * @param bool   $terminate Whether to terminate execution when a signature hits.
     *
     * @return bool True when a match was found.
     */
    protected function inspect_with_signatures( $payload, $ip, $terminate = true ) {
        $signatures = $this->signatures->get_signatures();

        foreach ( $signatures as $signature => $description ) {
            $description = sanitize_text_field( $description );

            if ( 0 === strpos( $signature, 'regex:' ) ) {
                $pattern = substr( $signature, 6 );
                if ( @preg_match( $pattern, '' ) === false ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                    continue;
                }

                if ( preg_match( $pattern, $payload ) ) {
                    $this->block_ip( $ip, sprintf( 'Request matched signature: %s', $description ) );
                    if ( $terminate ) {
                        wp_die( esc_html__( 'Request blocked by Secure Shield.', 'secure-shield' ), esc_html__( 'Blocked', 'secure-shield' ), 403 );
                    }
                    return true;
                }
                continue;
            }

            if ( false !== stripos( $payload, $signature ) ) {
                $this->block_ip( $ip, sprintf( 'Request matched signature: %s', $description ) );
                if ( $terminate ) {
                    wp_die( esc_html__( 'Request blocked by Secure Shield.', 'secure-shield' ), esc_html__( 'Blocked', 'secure-shield' ), 403 );
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Identify CSRF probes with suspicious parameters.
     *
     * @param array $payload_parts Request components.
     *
     * @return bool
     */
    protected function looks_like_csrf_probe( $payload_parts ) {
        $suspicious_keys = array( '_method', '__construct', 'GLOBALS', '_config' );

        foreach ( $suspicious_keys as $key ) {
            if ( isset( $payload_parts['post'][ $key ] ) || isset( $payload_parts['query'][ $key ] ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the user agent is denylisted.
     *
     * @param string $user_agent User agent string.
     *
     * @return bool
     */
    protected function is_denied_user_agent( $user_agent ) {
        if ( empty( $user_agent ) ) {
            return false;
        }

        $denylist = array(
            // Scanners and penetration testing tools
            '#(sqlmap|nikto|acunetix|wpscan|nmap|masscan|zmap)#i',
            '#(nessus|openvas|metasploit|burpsuite|vega|w3af)#i',
            '#(havij|pangolin|webscarab|paros|grabber)#i',
            '#(dirbuster|dirb|gobuster|wfuzz|ffuf)#i',

            // Bots and crawlers (malicious)
            '#(semrush|ahrefs|mj12|majestic|blexbot|dotbot)#i',
            '#(serpstat|linkdex|80legs|spbot|rogerbot)#i',

            // Scripting and automated tools
            '#curl/[0-9]#i',
            '#wget#i',
            '#python-requests#i',
            '#libwww-perl#i',
            '#java/[0-9]#i',
            '#go-http-client#i',
            '#ruby#i',
            '#perl#i',

            // Download managers and scrapers
            '#(httrack|harvest|extract|grab|siphon)#i',
            '#(teleport|webcopier|webcapture|webripper)#i',

            // Known malicious
            '#(backdoor|shell|exploit|payload|virus)#i',
            '#(injection|joomla|wordpress)scan#i',
        );

        foreach ( $denylist as $pattern ) {
            if ( preg_match( $pattern, $user_agent ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get visitor IP address with proper sanitization.
     *
     * @return string
     */
    protected function get_ip_address() {
        $keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' );
        foreach ( $keys as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                $value = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
                // Handle comma-separated IPs (from proxy chains)
                $ips = array_map( 'trim', explode( ',', $value ) );
                foreach ( $ips as $ip ) {
                    // Validate IP address format
                    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
                        return $ip;
                    }
                    // If strict validation fails, accept any valid IP format
                    if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                        return $ip;
                    }
                }
            }
        }
        return '0.0.0.0';
    }

    /**
     * Block malicious IP in transient blocklist.
     *
     * @param string $ip IP address.
     * @param string $reason Reason message.
     */
    protected function block_ip( $ip, $reason ) {
        $ip        = sanitize_text_field( $ip );
        $blocklist = get_site_transient( 'secure_shield_blocklist' );
        if ( ! is_array( $blocklist ) ) {
            $blocklist = array();
        }

        $blocklist[ $ip ] = array(
            'reason' => sanitize_text_field( $reason ),
            'time'   => current_time( 'timestamp' ),
        );
        set_site_transient( 'secure_shield_blocklist', $blocklist, DAY_IN_SECONDS * 7 );
        do_action( 'secure_shield/log', sprintf( 'Blocked IP %s: %s', $ip, $reason ), 'warning' );
        do_action( 'secure_shield/firewall_block', $ip, $reason );
    }

    /**
     * Retrieve blocklist.
     *
     * @return array
     */
    public function get_blocklist() {
        return get_site_transient( 'secure_shield_blocklist' );
    }
}
