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
     * Signature manager for threat indicators.
     *
     * @var Secure_Shield_Signature_Manager
     */
    protected $signatures;

    /**
     * Rate limiting windows and thresholds.
     *
     * @var array
     */
    protected $rate_limits = array();

    /**
     * Cached fragments taken from signature feeds for request inspection.
     *
     * @var array|null
     */
    protected $request_signature_fragments = null;

    /**
     * Known malicious or scanning user agents to block outright.
     *
     * @var array
     */
    protected $denylisted_agents = array(
        'acunetix',
        'netsparker',
        'sqlmap',
        'nikto',
        'wpscan',
        'fimap',
        'masscan',
        'nessus',
        'python-requests',
        'curl/',
    );

    /**
     * Disallowed file extensions for uploads.
     *
     * @var array
     */
    protected $restricted_extensions = array( 'php', 'phtml', 'php5', 'php7', 'phar', 'sh', 'bash', 'exe', 'bat', 'cmd', 'pl' );

    /**
     * Maximum failed login attempts before blocking an IP.
     */
    const LOGIN_FAILURE_LIMIT = 5;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger            $logger     Logger instance.
     * @param Secure_Shield_Signature_Manager $signatures Signature manager.
     */
    public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Signature_Manager $signatures ) {
        $this->logger      = $logger;
        $this->signatures  = $signatures;
        $this->rate_limits = array(
            'general' => array(
                'max'    => 120,
                'window' => MINUTE_IN_SECONDS,
            ),
            'rest'    => array(
                'max'    => 60,
                'window' => MINUTE_IN_SECONDS,
            ),
            'xmlrpc'  => array(
                'max'    => 20,
                'window' => HOUR_IN_SECONDS,
            ),
        );
    }

    /**
     * Register firewall hooks.
     */
    public function register() {
        add_action( 'init', array( $this, 'apply_security_headers' ) );
        add_action( 'plugins_loaded', array( $this, 'monitor_requests' ) );
        add_filter( 'rest_authentication_errors', array( $this, 'throttle_rest_requests' ) );
        add_filter( 'rest_pre_dispatch', array( $this, 'inspect_rest_request' ), 10, 3 );
        add_action( 'wp_login_failed', array( $this, 'track_login_failure' ) );
        add_action( 'wp_login', array( $this, 'reset_login_failure' ) );
        add_action( 'template_redirect', array( $this, 'prevent_author_enumeration' ) );
        add_filter( 'wp_handle_upload_prefilter', array( $this, 'inspect_upload' ) );
        add_action( 'xmlrpc_call', array( $this, 'inspect_xmlrpc_call' ) );
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
        header( 'X-XSS-Protection: 1; mode=block' );
        header( 'Referrer-Policy: strict-origin-when-cross-origin' );
        header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
        header( 'Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://www.google.com https://www.gstatic.com; object-src \'none\'; frame-ancestors \'self\'' );
    }

    /**
     * Monitor requests for suspicious patterns.
     */
    public function monitor_requests() {
        $ip         = $this->get_ip_address();
        $uri        = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        $method     = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';

        $blocklist = $this->get_blocklist();
        if ( isset( $blocklist[ $ip ] ) ) {
            $this->terminate_request( $ip, 'IP already present on blocklist.', 403 );
        }

        if ( ! $this->enforce_general_rate_limit( $ip ) ) {
            $this->terminate_request( $ip, 'Exceeded global rate limit.', 429 );
        }

        if ( ! $this->is_user_agent_allowed( $user_agent ) ) {
            $this->terminate_request( $ip, 'User agent denied by firewall.', 403 );
        }

        $payload_sources = array(
            $uri,
            wp_unslash( $_GET ),
            wp_unslash( $_POST ),
            wp_unslash( $_COOKIE ),
            $this->get_raw_input(),
        );

        if ( $this->payload_matches_signature( $payload_sources ) ) {
            $this->terminate_request( $ip, 'Payload matched firewall pattern.', 403 );
        }

        if ( ! $this->validate_sensitive_endpoints( $uri, $method, $ip ) ) {
            return;
        }

        $this->enforce_origin_policy( $ip, $method );
    }

    /**
     * Enforce REST API specific throttling.
     *
     * @param WP_Error|null|bool $result Existing auth error.
     *
     * @return WP_Error|null|bool
     */
    public function throttle_rest_requests( $result ) {
        if ( is_wp_error( $result ) ) {
            return $result;
        }

        $rate_result = $this->enforce_rate_limit( $this->get_ip_address(), 'rest' );
        if ( ! $rate_result ) {
            return new WP_Error( 'secure_shield_rest_rate_limited', __( 'Too many REST API requests. Please slow down.', SECURE_SHIELD_TEXT_DOMAIN ), array( 'status' => 429 ) );
        }

        return $result;
    }

    /**
     * Inspect REST request payloads for malicious patterns.
     *
     * @param mixed           $result  Pre-dispatch result.
     * @param WP_REST_Server  $server  REST server instance.
     * @param WP_REST_Request $request Current request.
     *
     * @return mixed
     */
    public function inspect_rest_request( $result, $server, $request ) {
        unset( $server );

        if ( is_wp_error( $result ) ) {
            return $result;
        }

        if ( ! $request instanceof WP_REST_Request ) {
            return $result;
        }

        $ip = $this->get_ip_address();

        if ( $this->is_user_enumeration_request( $request ) ) {
            $this->terminate_request( $ip, 'REST user enumeration attempt blocked.' );
        }

        $payload_sources = array(
            $request->get_route(),
            $request->get_body(),
            $request->get_params(),
            $request->get_json_params(),
        );

        if ( $this->payload_matches_signature( $payload_sources ) ) {
            $this->terminate_request( $ip, 'REST payload matched firewall pattern.' );
        }

        return $result;
    }

    /**
     * Track failed login attempts to mitigate brute force abuse.
     */
    public function track_login_failure() {
        $ip  = $this->get_ip_address();
        $key = $this->get_login_failure_key( $ip );

        $count = (int) get_transient( $key );
        $count++;
        set_transient( $key, $count, 15 * MINUTE_IN_SECONDS );

        if ( $count >= self::LOGIN_FAILURE_LIMIT ) {
            $this->block_ip( $ip, 'Exceeded failed login threshold.' );
        }
    }

    /**
     * Reset failed login counter on successful authentication.
     */
    public function reset_login_failure() {
        $ip = $this->get_ip_address();
        delete_transient( $this->get_login_failure_key( $ip ) );
    }

    /**
     * Get visitor IP address.
     *
     * @return string
     */
    protected function get_ip_address() {
        $keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );
        foreach ( $keys as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                $ip = explode( ',', $_SERVER[ $key ] );
                return trim( $ip[0] );
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
     * Immediately stop the request lifecycle with a specific HTTP response.
     *
     * @param string $ip     Visitor IP.
     * @param string $reason Reason for the termination.
     * @param int    $code   HTTP status code.
     */
    protected function terminate_request( $ip, $reason, $code = 403 ) {
        $this->block_ip( $ip, $reason );

        wp_die(
            esc_html__( 'Request blocked by BISON Security Suite.', SECURE_SHIELD_TEXT_DOMAIN ),
            esc_html__( 'Blocked', SECURE_SHIELD_TEXT_DOMAIN ),
            array( 'response' => $code )
        );
    }

    /**
     * Enforce general rate limiting.
     *
     * @param string $ip IP address.
     *
     * @return bool
     */
    protected function enforce_general_rate_limit( $ip ) {
        $allowed = $this->enforce_rate_limit( $ip, 'general' );
        if ( ! $allowed ) {
            $this->block_ip( $ip, 'Exceeded request rate limit.' );
        }

        return $allowed;
    }

    /**
     * Handle rate limiting logic for a given context.
     *
     * @param string $ip      IP address.
     * @param string $context Context key.
     *
     * @return bool True when under limit, false otherwise.
     */
    protected function enforce_rate_limit( $ip, $context ) {
        if ( empty( $ip ) ) {
            return true;
        }

        $config = $this->rate_limits[ $context ] ?? null;
        if ( empty( $config ) ) {
            return true;
        }

        $key     = sprintf( 'secure_shield_rate_%s_%s', $context, md5( $ip ) );
        $counter = get_transient( $key );

        if ( ! is_array( $counter ) || empty( $counter['expires'] ) || time() > $counter['expires'] ) {
            $counter = array(
                'count'   => 0,
                'expires' => time() + (int) $config['window'],
            );
        }

        $counter['count']++;
        set_transient( $key, $counter, (int) $config['window'] );

        return (int) $counter['count'] <= (int) $config['max'];
    }

    /**
     * Build the transient key for failed logins.
     *
     * @param string $ip IP address.
     *
     * @return string
     */
    protected function get_login_failure_key( $ip ) {
        return 'secure_shield_login_' . md5( $ip );
    }

    /**
     * Determine whether a user enumeration attempt is being performed.
     *
     * @param WP_REST_Request $request Current REST request.
     *
     * @return bool
     */
    protected function is_user_enumeration_request( $request ) {
        if ( ! $request instanceof WP_REST_Request ) {
            return false;
        }

        $route = strtolower( (string) $request->get_route() );
        if ( false === strpos( $route, '/wp/v2/users' ) && false === strpos( $route, '/wp/v2/users/me' ) ) {
            return false;
        }

        if ( is_user_logged_in() && current_user_can( 'list_users' ) ) {
            return false;
        }

        return true;
    }

    /**
     * Prevent author enumeration through direct query parameters.
     */
    public function prevent_author_enumeration() {
        if ( is_admin() ) {
            return;
        }

        if ( isset( $_GET['author'] ) && ! current_user_can( 'list_users' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $this->terminate_request( $this->get_ip_address(), 'Author enumeration attempt detected.' );
        }

        if ( function_exists( 'is_author' ) && is_author() && ! current_user_can( 'list_users' ) ) {
            $this->terminate_request( $this->get_ip_address(), 'Blocked author archive enumeration.' );
        }
    }

    /**
     * Inspect file uploads and block dangerous extensions.
     *
     * @param array $file Upload details.
     *
     * @return array|WP_Error
     */
    public function inspect_upload( $file ) {
        if ( empty( $file['name'] ) ) {
            return $file;
        }

        $extension = strtolower( (string) pathinfo( $file['name'], PATHINFO_EXTENSION ) );
        if ( in_array( $extension, $this->restricted_extensions, true ) ) {
            $this->block_ip( $this->get_ip_address(), sprintf( 'Attempted upload of disallowed file type: %s', $extension ) );
            return new WP_Error( 'secure_shield_forbidden_upload', __( 'This file type is not allowed for security reasons.', SECURE_SHIELD_TEXT_DOMAIN ) );
        }

        if ( isset( $file['name'] ) && preg_match( '/\.(php|phtml)\.[^\.]+$/i', $file['name'] ) ) {
            $this->block_ip( $this->get_ip_address(), 'Attempted double extension upload.' );
            return new WP_Error( 'secure_shield_forbidden_upload', __( 'Executable files are not permitted.', SECURE_SHIELD_TEXT_DOMAIN ) );
        }

        return $file;
    }

    /**
     * Inspect XML-RPC calls for abusive behaviour.
     *
     * @param string $method XML-RPC method name.
     */
    public function inspect_xmlrpc_call( $method ) {
        $method = strtolower( (string) $method );

        if ( in_array( $method, array( 'pingback.ping', 'system.multicall' ), true ) ) {
            $this->terminate_request( $this->get_ip_address(), sprintf( 'Blocked XML-RPC method: %s', $method ) );
        }
    }

    /**
     * Validate whether a given user agent is allowed.
     *
     * @param string $user_agent Raw user agent string.
     *
     * @return bool
     */
    protected function is_user_agent_allowed( $user_agent ) {
        if ( empty( $user_agent ) || strlen( $user_agent ) < 5 ) {
            return false;
        }

        $agent = strtolower( $user_agent );
        foreach ( $this->denylisted_agents as $blocked_agent ) {
            if ( false !== strpos( $agent, $blocked_agent ) ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Ensure sensitive endpoints receive extra scrutiny.
     *
     * @param string $uri    Request URI.
     * @param string $method HTTP method.
     * @param string $ip     Visitor IP.
     *
     * @return bool
     */
    protected function validate_sensitive_endpoints( $uri, $method, $ip ) {
        $lower_uri = strtolower( $uri );

        if ( false !== strpos( $lower_uri, 'xmlrpc.php' ) ) {
            $xmlrpc_attempts = $this->enforce_rate_limit( $ip, 'xmlrpc' );
            if ( ! $xmlrpc_attempts ) {
                $this->terminate_request( $ip, 'XML-RPC abuse detected.', 429 );
                return false;
            }
        }

        if ( false !== strpos( $lower_uri, 'wp-json/wp/v2/users' ) && ! is_user_logged_in() ) {
            $this->terminate_request( $ip, 'REST user listing blocked.' );
            return false;
        }

        if ( in_array( strtoupper( $method ), array( 'PUT', 'DELETE', 'PATCH' ), true ) && empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
            $this->terminate_request( $ip, 'Privileged HTTP method without authorization.', 403 );
            return false;
        }

        return true;
    }

    /**
     * Enforce cross-origin policy for state-changing requests.
     *
     * @param string $ip     Visitor IP.
     * @param string $method HTTP method.
     */
    protected function enforce_origin_policy( $ip, $method ) {
        $method = strtoupper( $method );
        if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) ) {
            return;
        }

        $host     = wp_parse_url( home_url(), PHP_URL_HOST );
        $origin   = isset( $_SERVER['HTTP_ORIGIN'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_ORIGIN'] ) ) ) : '';
        $referer  = isset( $_SERVER['HTTP_REFERER'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) ) : '';
        $auth     = isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) ) : '';
        $nonce    = isset( $_REQUEST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $ajaxnonce = isset( $_REQUEST['_ajax_nonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_ajax_nonce'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $rest_nonce = isset( $_SERVER['HTTP_X_WP_NONCE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_WP_NONCE'] ) ) : '';

        $host = is_string( $host ) ? strtolower( $host ) : '';
        $is_same_origin = function( $value ) use ( $host ) {
            if ( empty( $value ) || empty( $host ) ) {
                return false;
            }
            $parsed = wp_parse_url( $value, PHP_URL_HOST );
            if ( empty( $parsed ) ) {
                return false;
            }
            return strtolower( $parsed ) === $host;
        };

        $has_nonce = ! empty( $nonce ) || ! empty( $ajaxnonce ) || ! empty( $rest_nonce );

        if ( empty( $auth ) && ! $has_nonce ) {
            if ( ! $is_same_origin( $origin ) && ! $is_same_origin( $referer ) ) {
                $this->terminate_request( $ip, 'Potential CSRF attempt detected.' );
            }
        }
    }

    /**
     * Determine if a payload matches known malicious patterns or signatures.
     *
     * @param mixed $sources Payload sources to inspect.
     *
     * @return bool
     */
    protected function payload_matches_signature( $sources ) {
        $payload = $this->stringify_payload( $sources );
        if ( '' === $payload ) {
            return false;
        }

        foreach ( $this->get_payload_patterns() as $pattern ) {
            if ( preg_match( $pattern, $payload ) ) {
                return true;
            }
        }

        foreach ( $this->get_signature_fragments() as $fragment ) {
            if ( false !== strpos( $payload, $fragment ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Convert mixed payload sources into a normalized string for inspection.
     *
     * @param mixed $sources Payload sources.
     *
     * @return string
     */
    protected function stringify_payload( $sources ) {
        if ( is_string( $sources ) ) {
            return strtolower( $sources );
        }

        if ( is_array( $sources ) ) {
            $buffer = '';
            foreach ( $sources as $source ) {
                $buffer .= ' ' . $this->stringify_payload( $source );
            }
            return trim( $buffer );
        }

        if ( is_object( $sources ) ) {
            return $this->stringify_payload( wp_json_encode( $sources ) );
        }

        if ( is_scalar( $sources ) ) {
            return strtolower( (string) $sources );
        }

        return '';
    }

    /**
     * Retrieve regex patterns for payload inspection.
     *
     * @return array
     */
    protected function get_payload_patterns() {
        return array(
            '/(<|%3C)script/i',
            '/(<|%3C)iframe/i',
            '/union(\s+|%20)select/i',
            '/select\s+.*from/i',
            '/insert\s+into/i',
            '/drop\s+table/i',
            '/sleep\s*\(/i',
            '/load_file\s*\(/i',
            '/outfile\s+/i',
            '/base64_decode\s*\(/i',
            '/eval\s*\(/i',
            '/assert\s*\(/i',
            '/shell_exec\s*\(/i',
            '/passthru\s*\(/i',
            '/0x[0-9a-f]{6,}/i',
            '/\.\.\//',
            '/\.\.\\/',
            '/php:\/\//i',
        );
    }

    /**
     * Retrieve signature fragments from the signature manager.
     *
     * @return array
     */
    protected function get_signature_fragments() {
        if ( null !== $this->request_signature_fragments ) {
            return $this->request_signature_fragments;
        }

        $this->request_signature_fragments = array();

        if ( ! $this->signatures instanceof Secure_Shield_Signature_Manager ) {
            return $this->request_signature_fragments;
        }

        $signatures = $this->signatures->get_signatures();
        if ( ! is_array( $signatures ) ) {
            return $this->request_signature_fragments;
        }

        foreach ( array_keys( $signatures ) as $indicator ) {
            $indicator = strtolower( trim( (string) $indicator ) );
            if ( strlen( $indicator ) < 8 ) {
                continue;
            }

            if ( strlen( $indicator ) > 120 ) {
                continue;
            }

            if ( preg_match( '/^[0-9\.]+$/', $indicator ) ) {
                continue;
            }

            if ( count( $this->request_signature_fragments ) >= 50 ) {
                break;
            }

            $this->request_signature_fragments[] = $indicator;
        }

        return $this->request_signature_fragments;
    }

    /**
     * Retrieve raw input stream for inspection.
     *
     * @return string
     */
    protected function get_raw_input() {
        static $raw = null;

        if ( null === $raw ) {
            $raw = file_get_contents( 'php://input' );
            if ( false === $raw ) {
                $raw = '';
            }
        }

        return $raw;
    }

    /**
     * Retrieve blocklist.
     *
     * @return array
     */
    public function get_blocklist() {
        return get_site_transient( 'secure_shield_blocklist' );
    }

    /**
     * Determine if the current visitor IP exists in the blocklist.
     *
     * @return bool
     */
    public function current_ip_is_blocked() {
        $ip        = $this->get_ip_address();
        $blocklist = $this->get_blocklist();

        return isset( $blocklist[ $ip ] );
    }
}
