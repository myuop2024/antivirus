<?php
/**
 * Handles BISON Security Suite configuration options.
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
        'secure_shield_wpscan_token'       => '',
        'secure_shield_nvd_api_key'        => '',
        'secure_shield_osv_enabled'        => '1',
        'secure_shield_threatfox_enabled'  => '1',
        'secure_shield_auto_repair'        => '0',
        'secure_shield_realtime_updates'   => '1',
        'secure_shield_gemini_api_key'     => '',
        'secure_shield_gemini_model'       => 'models/gemini-pro',
        'secure_shield_hf_api_key'         => '',
        'secure_shield_hf_model'           => 'openai-community/gpt2',
    );

    /**
     * Options that should be stored encrypted at rest.
     *
     * @var array
     */
    protected $secret_options = array(
        'secure_shield_wpscan_token',
        'secure_shield_nvd_api_key',
        'secure_shield_gemini_api_key',
        'secure_shield_hf_api_key',
        'secure_shield_cloudflare_token',
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
        register_setting( 'secure_shield', 'secure_shield_wpscan_token', array( $this, 'sanitize_secret' ) );
        register_setting( 'secure_shield', 'secure_shield_nvd_api_key', array( $this, 'sanitize_secret' ) );
        register_setting( 'secure_shield', 'secure_shield_osv_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_threatfox_enabled', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_auto_repair', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_realtime_updates', array( $this, 'sanitize_bool' ) );
        register_setting( 'secure_shield', 'secure_shield_gemini_api_key', array( $this, 'sanitize_secret' ) );
        register_setting( 'secure_shield', 'secure_shield_gemini_model', 'sanitize_text_field' );
        register_setting( 'secure_shield', 'secure_shield_hf_api_key', array( $this, 'sanitize_secret' ) );
        register_setting( 'secure_shield', 'secure_shield_hf_model', 'sanitize_text_field' );
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

        $value = get_option( $option, $default );

        if ( in_array( $option, $this->secret_options, true ) ) {
            $value = $this->get_secret_option( $option, $value );
        }

        return $value;
    }

    /**
     * Retrieve the WPScan API token if configured.
     *
     * @return string
     */
    public function get_wpscan_token() {
        return trim( (string) $this->get_secret_option( 'secure_shield_wpscan_token' ) );
    }

    /**
     * Retrieve the NVD API key if configured.
     *
     * @return string
     */
    public function get_nvd_api_key() {
        return trim( (string) $this->get_secret_option( 'secure_shield_nvd_api_key' ) );
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
     * Determine if real-time threat updates are enabled.
     *
     * @return bool
     */
    public function is_realtime_updates_enabled() {
        return '1' === $this->get_option( 'secure_shield_realtime_updates', '1' );
    }

    /**
     * Retrieve Gemini API key.
     *
     * @return string
     */
    public function get_gemini_api_key() {
        return trim( (string) $this->get_secret_option( 'secure_shield_gemini_api_key' ) );
    }

    /**
     * Retrieve Gemini model identifier.
     *
     * @return string
     */
    public function get_gemini_model() {
        return trim( (string) $this->get_option( 'secure_shield_gemini_model', 'models/gemini-pro' ) );
    }

    /**
     * Retrieve Hugging Face API key.
     *
     * @return string
     */
    public function get_hf_api_key() {
        return trim( (string) $this->get_secret_option( 'secure_shield_hf_api_key' ) );
    }

    /**
     * Retrieve Hugging Face model identifier.
     *
     * @return string
     */
    public function get_hf_model() {
        return trim( (string) $this->get_option( 'secure_shield_hf_model', 'openai-community/gpt2' ) );
    }

    /**
     * Retrieve a decrypted secret option.
     *
     * @param string $option  Option name.
     * @param string $default Default value.
     *
     * @return string
     */
    public function get_secret_option( $option, $default = '' ) {
        $value = get_option( $option, $default );

        if ( empty( $value ) ) {
            return '';
        }

        $decrypted = $this->decrypt_secret( $value );

        if ( false === $decrypted ) {
            return trim( (string) $value );
        }

        return trim( (string) $decrypted );
    }

    /**
     * Sanitize and encrypt secrets before persisting.
     *
     * @param string $value Raw value.
     *
     * @return string
     */
    public function sanitize_secret( $value ) {
        $value = trim( (string) $value );

        if ( '' === $value ) {
            return '';
        }

        $value = sanitize_text_field( $value );
        $encrypted = $this->encrypt_secret( $value );

        if ( empty( $encrypted ) ) {
            do_action( 'secure_shield/log', __( 'Failed to encrypt secret option. Value discarded.', SECURE_SHIELD_TEXT_DOMAIN ), 'warning' );
            return '';
        }

        return $encrypted;
    }

    /**
     * Encrypt a secret using AES-256-CBC with the WordPress salt as key material.
     *
     * @param string $value Plain value.
     *
     * @return string
     */
    protected function encrypt_secret( $value ) {
        if ( ! function_exists( 'openssl_encrypt' ) ) {
            return $value;
        }

        $key = $this->get_encryption_key();
        if ( empty( $key ) ) {
            return '';
        }

        $iv = openssl_random_pseudo_bytes( 16 );
        if ( false === $iv ) {
            return '';
        }

        $cipher = openssl_encrypt( $value, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );

        if ( false === $cipher ) {
            return '';
        }

        return base64_encode( $iv . '::' . $cipher );
    }

    /**
     * Decrypt a stored secret value.
     *
     * @param string $value Stored value.
     *
     * @return string|false
     */
    protected function decrypt_secret( $value ) {
        if ( ! function_exists( 'openssl_decrypt' ) ) {
            return $value;
        }

        $decoded = base64_decode( (string) $value, true );
        if ( false === $decoded || false === strpos( $decoded, '::' ) ) {
            return false;
        }

        list( $iv, $cipher ) = explode( '::', $decoded, 2 );

        if ( empty( $iv ) || empty( $cipher ) ) {
            return false;
        }

        $key = $this->get_encryption_key();
        if ( empty( $key ) ) {
            return false;
        }

        $plain = openssl_decrypt( $cipher, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );

        if ( false === $plain ) {
            return false;
        }

        return $plain;
    }

    /**
     * Retrieve encryption key derived from WordPress salts.
     *
     * @return string
     */
    protected function get_encryption_key() {
        $salt = wp_salt( 'secure_shield_secret' );
        return hash( 'sha256', $salt, true );
    }
}
