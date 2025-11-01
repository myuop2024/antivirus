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
     * Constructor.
     *
     * @param Secure_Shield_Logger $logger Logger instance.
     */
    public function __construct( Secure_Shield_Logger $logger ) {
        $this->logger = $logger;
    }

    /**
     * Register firewall hooks.
     */
    public function register() {
        add_action( 'init', array( $this, 'apply_security_headers' ) );
        add_action( 'plugins_loaded', array( $this, 'monitor_requests' ) );
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
        header( 'Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://www.google.com https://www.gstatic.com; object-src \'none\'; frame-ancestors \'self\'' );
    }

    /**
     * Monitor requests for suspicious patterns.
     */
    public function monitor_requests() {
        $ip = $this->get_ip_address();
        $uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

        $patterns = array(
            '/(<|%3C)script/i',
            '/union(\s+)select/i',
            '/base64_decode\s*\(/i',
            '/eval\s*\(/i',
        );

        $payload = wp_json_encode( array( $uri, wp_unslash( $_REQUEST ) ) );
        foreach ( $patterns as $pattern ) {
            if ( preg_match( $pattern, $payload ) ) {
                $this->block_ip( $ip, 'Payload matched firewall pattern.' );
                wp_die( esc_html__( 'Request blocked by Secure Shield.', 'secure-shield' ), esc_html__( 'Blocked', 'secure-shield' ), 403 );
            }
        }

        if ( empty( $user_agent ) || strlen( $user_agent ) < 5 ) {
            $this->block_ip( $ip, 'Missing or empty user agent.' );
        }
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
     * Retrieve blocklist.
     *
     * @return array
     */
    public function get_blocklist() {
        return get_site_transient( 'secure_shield_blocklist' );
    }
}
