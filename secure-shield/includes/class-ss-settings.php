<?php
/**
 * Handles Secure Shield configuration options.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Settings {

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Option keys managed by the settings service.
     *
     * @var array
     */
    protected $options = array(
        'secure_shield_wpscan_token'          => '',
        'secure_shield_nvd_api_key'           => '',
        'secure_shield_osv_enabled'           => '1',
        'secure_shield_threatfox_enabled'     => '1',
        'secure_shield_auto_repair'           => '0',
        'secure_shield_malwarebazaar_enabled' => '1',
        'secure_shield_urlhaus_enabled'       => '1',
        'secure_shield_feodotracker_enabled'  => '1',
        'secure_shield_sslbl_enabled'         => '1',
        'secure_shield_phishtank_enabled'     => '1',
        'secure_shield_alienvault_enabled'    => '1',
        'secure_shield_malwaredomain_enabled' => '1',
        'secure_shield_cleanup_mode'          => 'critical_only', // disabled, critical_only, aggressive
    );

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger $logger Logger instance.
     */
    public function __construct( Secure_Shield_Logger $logger ) {
        $this->logger = $logger;
    }

    /**
     * Hook settings registration into WordPress.
     */
    public function register() {
        add_action( 'admin_init', array( $this, 'register_settings' ) );
    }

    /**
     * Register plugin settings for threat intelligence and automation.
     */
    public function register_settings() {
        register_setting( 'secure_shield', 'secure_shield_wpscan_token', 'sanitize_text_field' );
        register_setting( 'secure_shield', 'secure_shield_nvd_api_key', 'sanitize_text_field' );
        register_setting( 'secure_shield', 'secure_shield_osv_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_threatfox_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_auto_repair', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_malwarebazaar_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_urlhaus_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_feodotracker_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_sslbl_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_phishtank_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_alienvault_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_malwaredomain_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_cleanup_mode', array( $this, 'sanitize_cleanup_mode' ) );
    }

    /**
     * Sanitize boolean checkbox values.
     *
     * @param mixed $value Raw value.
     *
     * @return string
     */
    public function sanitize_bool( $value ) {
        return ( ! empty( $value ) && 'false' !== $value && '0' !== $value ) ? '1' : '0';
    }

    /**
     * Sanitize cleanup mode value.
     *
     * @param mixed $value Raw value.
     *
     * @return string
     */
    public function sanitize_cleanup_mode( $value ) {
        $valid_modes = array( 'disabled', 'critical_only', 'aggressive' );
        return in_array( $value, $valid_modes, true ) ? $value : 'critical_only';
    }

    /**
     * Retrieve a stored option with a default fallback.
     *
     * @param string $option Option key.
     * @param mixed  $default Default value.
     *
     * @return mixed
     */
    public function get_option( $option, $default = '' ) {
        if ( array_key_exists( $option, $this->options ) ) {
            $default = $this->options[ $option ];
        }

        return get_option( $option, $default );
    }

    /**
     * Retrieve the WPScan API token if configured.
     *
     * @return string
     */
    public function get_wpscan_token() {
        return trim( (string) $this->get_option( 'secure_shield_wpscan_token', '' ) );
    }

    /**
     * Retrieve the NVD API key if configured.
     *
     * @return string
     */
    public function get_nvd_api_key() {
        return trim( (string) $this->get_option( 'secure_shield_nvd_api_key', '' ) );
    }

    /**
     * Determine if OSV ingestion is enabled.
     *
     * @return bool
     */
    public function is_osv_enabled() {
        return '1' === $this->get_option( 'secure_shield_osv_enabled', '1' );
    }

    /**
     * Determine if ThreatFox feed ingestion is enabled.
     *
     * @return bool
     */
    public function is_threatfox_enabled() {
        return '1' === $this->get_option( 'secure_shield_threatfox_enabled', '1' );
    }

    /**
     * Check whether automatic repair is enabled.
     *
     * @return bool
     */
    public function is_auto_repair_enabled() {
        return '1' === $this->get_option( 'secure_shield_auto_repair', '0' );
    }

    /**
     * Check if MalwareBazaar feed is enabled.
     *
     * @return bool
     */
    public function is_malwarebazaar_enabled() {
        return '1' === $this->get_option( 'secure_shield_malwarebazaar_enabled', '1' );
    }

    /**
     * Check if URLhaus feed is enabled.
     *
     * @return bool
     */
    public function is_urlhaus_enabled() {
        return '1' === $this->get_option( 'secure_shield_urlhaus_enabled', '1' );
    }

    /**
     * Check if Feodo Tracker feed is enabled.
     *
     * @return bool
     */
    public function is_feodotracker_enabled() {
        return '1' === $this->get_option( 'secure_shield_feodotracker_enabled', '1' );
    }

    /**
     * Check if SSL Blacklist feed is enabled.
     *
     * @return bool
     */
    public function is_sslbl_enabled() {
        return '1' === $this->get_option( 'secure_shield_sslbl_enabled', '1' );
    }

    /**
     * Check if PhishTank feed is enabled.
     *
     * @return bool
     */
    public function is_phishtank_enabled() {
        return '1' === $this->get_option( 'secure_shield_phishtank_enabled', '1' );
    }

    /**
     * Check if AlienVault OTX feed is enabled.
     *
     * @return bool
     */
    public function is_alienvault_enabled() {
        return '1' === $this->get_option( 'secure_shield_alienvault_enabled', '1' );
    }

    /**
     * Check if Malware Domain List feed is enabled.
     *
     * @return bool
     */
    public function is_malwaredomain_enabled() {
        return '1' === $this->get_option( 'secure_shield_malwaredomain_enabled', '1' );
    }

    /**
     * Get the automatic cleanup mode.
     *
     * @return string disabled, critical_only, or aggressive
     */
    public function get_cleanup_mode() {
        return $this->get_option( 'secure_shield_cleanup_mode', 'critical_only' );
    }
}
