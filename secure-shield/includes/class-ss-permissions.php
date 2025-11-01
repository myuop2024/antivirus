<?php
/**
 * Validates file and directory permissions.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Permissions {

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
     * Register admin hooks.
     */
    public function register() {
        add_action( 'secure_shield_check_permissions', array( $this, 'check_permissions' ) );
    }

    /**
     * Assess critical directories for improper permissions.
     *
     * @return array
     */
    public function check_permissions() {
        $paths = array(
            ABSPATH              => '0755',
            ABSPATH . 'wp-admin' => '0755',
            ABSPATH . 'wp-includes' => '0755',
            WP_CONTENT_DIR       => '0755',
            WP_CONTENT_DIR . '/uploads' => '0755',
            WP_CONTENT_DIR . '/plugins' => '0755',
            WP_CONTENT_DIR . '/secure-shield-quarantine' => '0700',
            ABSPATH . 'wp-config.php' => '0640',
        );

        $issues = array();
        foreach ( $paths as $path => $recommended ) {
            if ( ! file_exists( $path ) ) {
                continue;
            }

            $perms = substr( sprintf( '%o', fileperms( $path ) ), -4 );
            if ( $perms !== $recommended ) {
                $issues[ wp_normalize_path( $path ) ] = sprintf(
                    __( 'Permission %1$s detected, recommend %2$s.', 'secure-shield' ),
                    $perms,
                    $recommended
                );
            }
        }

        if ( ! empty( $issues ) ) {
            do_action( 'secure_shield/log', __( 'Permission issues detected.', 'secure-shield' ), 'warning' );
        }

        return $issues;
    }
}
