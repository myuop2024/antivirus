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
     * Constructor.
     *
     * @param Secure_Shield_Logger   $logger    Logger instance.
     * @param Secure_Shield_Settings $settings  Settings handler.
     */
    public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Settings $settings ) {
        $this->logger   = $logger;
        $this->settings = $settings;
    }

    /**
     * Register hooks.
     */
    public function register() {
        add_action( 'secure_shield/repair_core_file', array( $this, 'repair_core_file' ), 10, 1 );
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
                return new WP_Error( 'repair_failed', __( 'Unable to create directories for repair.', 'secure-shield' ) );
            }

            if ( false === file_put_contents( $destination, $contents ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_ops_file_put_contents
                continue;
            }

            do_action( 'secure_shield/log', sprintf( 'Repaired core file %s from %s', $relative_path, $candidate ), 'warning' );
            return true;
        }

        return new WP_Error( 'repair_failed', __( 'Unable to download trusted source for repair.', 'secure-shield' ) );
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
            return new WP_Error( 'auto_repair_disabled', __( 'Auto repair is disabled.', 'secure-shield' ) );
        }

        return $this->repair_core_file( $relative_path );
    }

    /**
     * Quarantine an infected file by moving it to quarantine directory.
     *
     * @param string $file_path Absolute file path.
     *
     * @return bool|WP_Error
     */
    public function quarantine_file( $file_path ) {
        if ( ! file_exists( $file_path ) ) {
            return new WP_Error( 'file_not_found', __( 'File not found for quarantine.', 'secure-shield' ) );
        }

        $quarantine_dir = WP_CONTENT_DIR . '/secure-shield-quarantine';
        if ( ! wp_mkdir_p( $quarantine_dir ) ) {
            return new WP_Error( 'quarantine_dir_failed', __( 'Failed to create quarantine directory.', 'secure-shield' ) );
        }

        // Create .htaccess to prevent execution in quarantine
        $htaccess_file = $quarantine_dir . '/.htaccess';
        if ( ! file_exists( $htaccess_file ) ) {
            $htaccess_content = "# Secure Shield Quarantine - Deny all access\n";
            $htaccess_content .= "Order deny,allow\n";
            $htaccess_content .= "Deny from all\n";
            $htaccess_content .= "<Files *>\n";
            $htaccess_content .= "ForceType application/octet-stream\n";
            $htaccess_content .= "Header set Content-Disposition attachment\n";
            $htaccess_content .= "</Files>\n";
            @file_put_contents( $htaccess_file, $htaccess_content );
        }

        $relative_path = str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $file_path ) );
        $safe_name = sanitize_file_name( str_replace( '/', '_', $relative_path ) );
        $destination = wp_normalize_path( $quarantine_dir . '/' . $safe_name . '-' . time() . '.infected' );

        // Copy file to quarantine (preserve original for investigation)
        if ( @copy( $file_path, $destination ) ) {
            // Delete original infected file
            if ( @unlink( $file_path ) ) {
                do_action( 'secure_shield/log', sprintf( 'Quarantined and removed: %s', $relative_path ), 'critical' );
                return true;
            } else {
                do_action( 'secure_shield/log', sprintf( 'Quarantined but failed to remove: %s', $relative_path ), 'warning' );
                return new WP_Error( 'delete_failed', __( 'File quarantined but original could not be deleted.', 'secure-shield' ) );
            }
        }

        return new WP_Error( 'quarantine_failed', __( 'Failed to quarantine file.', 'secure-shield' ) );
    }

    /**
     * Sanitize database entry by removing malicious content.
     *
     * @param string $type Database type (posts, comments, postmeta, options).
     * @param int    $id   Entry ID.
     *
     * @return bool|WP_Error
     */
    public function sanitize_database_entry( $type, $id ) {
        global $wpdb;

        $id = absint( $id );
        if ( $id <= 0 ) {
            return new WP_Error( 'invalid_id', __( 'Invalid database entry ID.', 'secure-shield' ) );
        }

        switch ( $type ) {
            case 'posts':
                // Backup original content
                $post = get_post( $id );
                if ( ! $post ) {
                    return new WP_Error( 'post_not_found', __( 'Post not found.', 'secure-shield' ) );
                }

                $backup_meta_key = '_secure_shield_backup_' . time();
                update_post_meta( $id, $backup_meta_key, $post->post_content );

                // Sanitize post content
                $result = $wpdb->update(
                    $wpdb->posts,
                    array( 'post_content' => __( '[Content removed by Secure Shield - malicious code detected]', 'secure-shield' ) ),
                    array( 'ID' => $id ),
                    array( '%s' ),
                    array( '%d' )
                );

                if ( false !== $result ) {
                    do_action( 'secure_shield/log', sprintf( 'Sanitized post ID %d (backup: %s)', $id, $backup_meta_key ), 'critical' );
                    return true;
                }
                break;

            case 'comments':
                // Backup original content
                $comment = get_comment( $id );
                if ( ! $comment ) {
                    return new WP_Error( 'comment_not_found', __( 'Comment not found.', 'secure-shield' ) );
                }

                $backup_meta_key = 'secure_shield_backup_' . time();
                update_comment_meta( $id, $backup_meta_key, $comment->comment_content );

                $result = $wpdb->update(
                    $wpdb->comments,
                    array( 'comment_content' => __( '[Content removed by Secure Shield - malicious code detected]', 'secure-shield' ) ),
                    array( 'comment_ID' => $id ),
                    array( '%s' ),
                    array( '%d' )
                );

                if ( false !== $result ) {
                    do_action( 'secure_shield/log', sprintf( 'Sanitized comment ID %d (backup: %s)', $id, $backup_meta_key ), 'critical' );
                    return true;
                }
                break;

            case 'postmeta':
                // Get current meta
                $meta = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->postmeta} WHERE meta_id = %d", $id ) );
                if ( ! $meta ) {
                    return new WP_Error( 'meta_not_found', __( 'Post meta not found.', 'secure-shield' ) );
                }

                // Backup original
                $backup_meta_key = '_secure_shield_backup_meta_' . time();
                add_post_meta( $meta->post_id, $backup_meta_key, array(
                    'meta_key' => $meta->meta_key,
                    'meta_value' => $meta->meta_value,
                ) );

                // Delete infected meta
                $result = $wpdb->delete( $wpdb->postmeta, array( 'meta_id' => $id ), array( '%d' ) );

                if ( false !== $result ) {
                    do_action( 'secure_shield/log', sprintf( 'Deleted infected postmeta ID %d (backup: %s)', $id, $backup_meta_key ), 'critical' );
                    return true;
                }
                break;

            case 'options':
                // Get option
                $option = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->options} WHERE option_id = %d", $id ) );
                if ( ! $option ) {
                    return new WP_Error( 'option_not_found', __( 'Option not found.', 'secure-shield' ) );
                }

                // Don't delete core WordPress options
                $protected_options = array( 'siteurl', 'home', 'blogname', 'admin_email', 'users_can_register' );
                if ( in_array( $option->option_name, $protected_options, true ) ) {
                    return new WP_Error( 'protected_option', __( 'Cannot modify protected WordPress option.', 'secure-shield' ) );
                }

                // Backup original
                $backup_key = 'secure_shield_backup_option_' . time();
                add_option( $backup_key, array(
                    'option_name' => $option->option_name,
                    'option_value' => $option->option_value,
                ), '', 'no' );

                // Delete infected option
                $result = $wpdb->delete( $wpdb->options, array( 'option_id' => $id ), array( '%d' ) );

                if ( false !== $result ) {
                    do_action( 'secure_shield/log', sprintf( 'Deleted infected option ID %d (backup: %s)', $id, $backup_key ), 'critical' );
                    return true;
                }
                break;

            default:
                return new WP_Error( 'invalid_type', __( 'Invalid database type.', 'secure-shield' ) );
        }

        return new WP_Error( 'sanitize_failed', __( 'Failed to sanitize database entry.', 'secure-shield' ) );
    }

    /**
     * Automatically remediate threats based on settings.
     *
     * @param array $threats Array of detected threats.
     *
     * @return array Results of remediation actions.
     */
    public function auto_remediate_threats( $threats ) {
        $results = array(
            'files_quarantined' => array(),
            'files_repaired' => array(),
            'database_sanitized' => array(),
            'errors' => array(),
        );

        $cleanup_mode = $this->settings->get_cleanup_mode();

        if ( 'disabled' === $cleanup_mode ) {
            return $results;
        }

        // Process file threats
        if ( ! empty( $threats['files'] ) ) {
            foreach ( $threats['files'] as $file_path => $detections ) {
                $is_critical = false;
                foreach ( $detections as $detection ) {
                    if ( 'critical' === $detection['severity'] ) {
                        $is_critical = true;
                        break;
                    }
                }

                // Only auto-remediate critical threats
                if ( ! $is_critical && 'aggressive' !== $cleanup_mode ) {
                    continue;
                }

                // Check if it's a WordPress core file
                if ( $this->is_core_file( $file_path ) ) {
                    if ( $this->settings->is_auto_repair_enabled() ) {
                        $result = $this->repair_core_file( $file_path );
                        if ( ! is_wp_error( $result ) ) {
                            $results['files_repaired'][] = $file_path;
                        } else {
                            $results['errors'][] = sprintf( 'Failed to repair %s: %s', $file_path, $result->get_error_message() );
                        }
                    }
                } else {
                    // Quarantine non-core infected files
                    $full_path = wp_normalize_path( ABSPATH . ltrim( $file_path, '/' ) );
                    $result = $this->quarantine_file( $full_path );
                    if ( ! is_wp_error( $result ) ) {
                        $results['files_quarantined'][] = $file_path;
                    } else {
                        $results['errors'][] = sprintf( 'Failed to quarantine %s: %s', $file_path, $result->get_error_message() );
                    }
                }
            }
        }

        // Process database threats
        if ( ! empty( $threats['database'] ) ) {
            foreach ( $threats['database'] as $key => $detections ) {
                $is_critical = false;
                foreach ( $detections as $detection ) {
                    if ( 'critical' === $detection['severity'] ) {
                        $is_critical = true;
                        break;
                    }
                }

                // Only auto-remediate critical threats
                if ( ! $is_critical && 'aggressive' !== $cleanup_mode ) {
                    continue;
                }

                list( $type, $id ) = array_pad( explode( ':', $key ), 2, null );
                if ( $type && $id ) {
                    $result = $this->sanitize_database_entry( $type, $id );
                    if ( ! is_wp_error( $result ) ) {
                        $results['database_sanitized'][] = $key;
                    } else {
                        $results['errors'][] = sprintf( 'Failed to sanitize %s: %s', $key, $result->get_error_message() );
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Check if a file is a WordPress core file.
     *
     * @param string $relative_path Relative file path.
     *
     * @return bool
     */
    protected function is_core_file( $relative_path ) {
        $relative_path = ltrim( $relative_path, '/' );

        // WordPress core directories
        if ( preg_match( '#^wp-(admin|includes)/#', $relative_path ) ) {
            return true;
        }

        // WordPress root files
        $core_files = array( 'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php' );
        if ( in_array( $relative_path, $core_files, true ) ) {
            return true;
        }

        return false;
    }
}
