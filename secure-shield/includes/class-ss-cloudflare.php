<?php
/**
 * Integrates with Cloudflare for IP blocking and firewall events.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Cloudflare {

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Settings manager.
     *
     * @var Secure_Shield_Settings
     */
    protected $settings;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger  $logger   Logger instance.
     * @param Secure_Shield_Settings $settings Settings manager.
     */
    public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Settings $settings ) {
        $this->logger   = $logger;
        $this->settings = $settings;
    }

    /**
     * Register admin fields.
     */
    public function register() {
        add_action( 'admin_init', array( $this, 'register_settings' ) );
    }

    /**
     * Register Cloudflare configuration fields.
     */
    public function register_settings() {
        register_setting( 'secure_shield', 'secure_shield_cloudflare_email', array( 'sanitize_callback' => 'sanitize_email' ) );
        register_setting( 'secure_shield', 'secure_shield_cloudflare_token', array( $this, 'sanitize_token' ) );
        register_setting( 'secure_shield', 'secure_shield_cloudflare_zone', 'sanitize_text_field' );
    }

    /**
     * Block IP address via Cloudflare API.
     *
     * @param string $ip IP address.
     */
    public function block_ip( $ip ) {
        $email = get_option( 'secure_shield_cloudflare_email' );
        $token = $this->settings->get_secret_option( 'secure_shield_cloudflare_token' );
        $zone  = get_option( 'secure_shield_cloudflare_zone' );

        if ( empty( $email ) || empty( $token ) || empty( $zone ) ) {
            return;
        }

        $response = wp_remote_post(
            "https://api.cloudflare.com/client/v4/zones/{$zone}/firewall/access_rules/rules",
            array(
                'headers' => array(
                    'X-Auth-Email' => $email,
                    'X-Auth-Key'   => $token,
                    'Content-Type' => 'application/json',
                ),
                'body'    => wp_json_encode(
                    array(
                        'mode'    => 'block',
                        'configuration' => array(
                            'target' => 'ip',
                            'value'  => $ip,
                        ),
                        'notes'   => 'BISON Security Suite automated block',
                    )
                ),
                'timeout' => 15,
            )
        );

        if ( is_wp_error( $response ) ) {
            do_action( 'secure_shield/log', sprintf( 'Cloudflare block failed: %s', $response->get_error_message() ), 'warning' );
        } else {
            do_action( 'secure_shield/log', sprintf( 'Cloudflare block added for %s', $ip ) );
        }
    }

    /**
     * Sanitize Cloudflare token via shared encryption routine.
     *
     * @param string $value Raw token.
     *
     * @return string
     */
    public function sanitize_token( $value ) {
        return $this->settings->sanitize_secret( $value );
    }
}
