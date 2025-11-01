<?php
/**
 * Automatic repair and hardening routines.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Remediator {

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
     * AI advisor.
     *
     * @var Secure_Shield_AI_Assistant|null
     */
    protected $ai;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger        $logger   Logger instance.
     * @param Secure_Shield_Settings      $settings Settings handler.
     * @param Secure_Shield_AI_Assistant $ai        AI advisor.
     */
    public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Settings $settings, ?Secure_Shield_AI_Assistant $ai = null ) {
        $this->logger   = $logger;
        $this->settings = $settings;
        $this->ai       = $ai;
    }

    /**
     * Register hooks.
     */
    public function register() {
        add_action( 'secure_shield/repair_core_file', array( $this, 'repair_core_file' ), 10, 1 );
        add_action( 'secure_shield/quarantine_file', array( $this, 'quarantine_file' ), 10, 1 );
    }

    /**
     * Attempt to repair a WordPress core file using trusted upstream sources.
     *
     * @param string $relative_path Relative path from the WordPress root.
     *
     * @return bool|WP_Error
     */
    public function repair_core_file( $relative_path ) {
        $relative_path = ltrim( $relative_path, '/' );
        $version       = get_bloginfo( 'version' );
        $candidates    = array(
            sprintf( 'https://raw.githubusercontent.com/WordPress/WordPress/%1$s/%2$s', $version, $relative_path ),
            sprintf( 'https://core.svn.wordpress.org/tags/%1$s/%2$s', $version, $relative_path ),
        );

        foreach ( $candidates as $candidate ) {
            $response = wp_remote_get( $candidate, array( 'timeout' => 20 ) );
            if ( is_wp_error( $response ) ) {
                do_action( 'secure_shield/log', sprintf( 'Auto-repair failed to fetch %1$s: %2$s', $candidate, $response->get_error_message() ), 'warning' );
                continue;
            }

            if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
                continue;
            }

            $contents = wp_remote_retrieve_body( $response );
            if ( empty( $contents ) ) {
                continue;
            }

            $destination = wp_normalize_path( ABSPATH . $relative_path );
            if ( ! wp_mkdir_p( dirname( $destination ) ) ) {
                return new WP_Error( 'repair_failed', __( 'Unable to create directories for repair.', SECURE_SHIELD_TEXT_DOMAIN ) );
            }

            if ( false === file_put_contents( $destination, $contents ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_ops_file_put_contents
                continue;
            }

            do_action( 'secure_shield/log', sprintf( 'Repaired core file %s from %s', $relative_path, $candidate ), 'warning' );
            return true;
        }

        return new WP_Error( 'repair_failed', __( 'Unable to download trusted source for repair.', SECURE_SHIELD_TEXT_DOMAIN ) );
    }

    /**
     * Dispatch a repair request if auto-repair is enabled.
     *
     * @param string $relative_path Relative path from ABSPATH.
     *
     * @return bool|WP_Error
     */
    public function maybe_repair_core_file( $relative_path ) {
        if ( ! $this->settings->is_auto_repair_enabled() ) {
            return new WP_Error( 'auto_repair_disabled', __( 'Auto repair is disabled.', SECURE_SHIELD_TEXT_DOMAIN ) );
        }

        return $this->repair_core_file( $relative_path );
    }

    /**
     * Quarantine a suspicious file by moving it to a secure location.
     *
     * @param string $relative_path Relative path from ABSPATH.
     *
     * @return array Details about the quarantined file.
     */
    public function quarantine_file( $relative_path ) {
        $relative_path = ltrim( $relative_path, '/' );
        $absolute      = wp_normalize_path( ABSPATH . $relative_path );

        if ( ! file_exists( $absolute ) ) {
            return array();
        }

        $quarantine_dir = $this->get_quarantine_dir();
        if ( ! wp_mkdir_p( $quarantine_dir ) ) {
            return array();
        }

        $timestamp   = time();
        $destination = wp_normalize_path( trailingslashit( $quarantine_dir ) . sanitize_file_name( basename( $relative_path ) ) . '-' . $timestamp );

        if ( ! @copy( $absolute, $destination ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_ops_copy
            return array();
        }

        $placeholder = "<?php\n// quarantined by BISON Security Suite\n";
        @rename( $absolute, $absolute . '.bison-quarantined' );
        file_put_contents( $absolute, $placeholder ); // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_ops_file_put_contents

        do_action( 'secure_shield/log', sprintf( 'Quarantined %s to %s', $relative_path, $destination ), 'critical' );

        return array(
            'source'      => $relative_path,
            'quarantine'  => $destination,
            'timestamp'   => $timestamp,
        );
    }

    /**
     * Quarantine multiple items.
     *
     * @param array $relative_paths List of relative paths.
     *
     * @return array
     */
    public function quarantine_items( array $relative_paths ) {
        $details = array();
        foreach ( $relative_paths as $path ) {
            $item = $this->quarantine_file( $path );
            if ( ! empty( $item ) ) {
                $details[] = $item;
            }
        }

        return $details;
    }

    /**
     * Generate AI remediation suggestions.
     *
     * @param string $file_path Absolute file path.
     * @param array  $context   Context array.
     *
     * @return array
     */
    public function generate_ai_guidance( $file_path, array $context = array() ) {
        if ( ! $this->ai ) {
            return array();
        }

        return $this->ai->generate_guidance( $file_path, $context );
    }

    /**
     * Retrieve quarantine directory path.
     *
     * @return string
     */
    protected function get_quarantine_dir() {
        return wp_normalize_path( WP_CONTENT_DIR . '/uploads/bison-security/quarantine' );
    }
}
