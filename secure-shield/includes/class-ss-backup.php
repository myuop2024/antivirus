<?php
/**
 * Backup and restore functionality.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Backup {

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
     * Register backup hooks.
     */
    public function register() {
        add_action( 'secure_shield_create_backup', array( $this, 'create_backup' ) );
    }

    /**
     * Create backup archive of WordPress files.
     *
     * @return string|WP_Error
     */
    public function create_backup() {
        if ( ! class_exists( 'ZipArchive' ) ) {
            return new WP_Error( 'missing_zip', __( 'ZipArchive is required for backups.', 'secure-shield' ) );
        }

        $uploads = wp_upload_dir();
        $backup_dir = trailingslashit( $uploads['basedir'] ) . 'secure-shield-backups';
        wp_mkdir_p( $backup_dir );

        $filename = $backup_dir . '/backup-' . date_i18n( 'Y-m-d-H-i-s' ) . '.zip';
        $zip      = new ZipArchive();

        if ( true !== $zip->open( $filename, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
            return new WP_Error( 'unable_to_create_backup', __( 'Unable to create backup archive.', 'secure-shield' ) );
        }

        $root     = realpath( ABSPATH );
        $skipDirs = array(
            trailingslashit( wp_normalize_path( $backup_dir ) ),
            trailingslashit( wp_normalize_path( WP_CONTENT_DIR . '/secure-shield-quarantine' ) ),
        );
        $iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, RecursiveDirectoryIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST );
        foreach ( $iterator as $item ) {
            $path = wp_normalize_path( $item->getRealPath() );
            $local_name = str_replace( wp_normalize_path( $root ) . '/', '', $path );
            foreach ( $skipDirs as $skip ) {
                if ( 0 === strpos( $path, $skip ) ) {
                    continue 2;
                }
            }
            if ( $item->isDir() ) {
                $zip->addEmptyDir( $local_name );
            } else {
                $zip->addFile( $path, $local_name );
            }
        }

        $zip->close();
        do_action( 'secure_shield/log', sprintf( 'Backup created at %s', $filename ), 'info' );

        return $filename;
    }

    /**
     * List available backups.
     *
     * @return array
     */
    public function list_backups() {
        $uploads = wp_upload_dir();
        $backup_dir = trailingslashit( $uploads['basedir'] ) . 'secure-shield-backups';
        if ( ! is_dir( $backup_dir ) ) {
            return array();
        }

        $files = glob( $backup_dir . '/*.zip' );
        rsort( $files );
        return $files;
    }

    /**
     * Restore backup archive.
     *
     * @param string $file Backup file path.
     *
     * @return bool|WP_Error
     */
    public function restore_backup( $file ) {
        $file = sanitize_text_field( $file );
        if ( ! file_exists( $file ) ) {
            return new WP_Error( 'missing_backup', __( 'Backup file not found.', 'secure-shield' ) );
        }

        if ( ! class_exists( 'ZipArchive' ) ) {
            return new WP_Error( 'missing_zip', __( 'ZipArchive is required for restore.', 'secure-shield' ) );
        }

        $zip = new ZipArchive();
        if ( true !== $zip->open( $file ) ) {
            return new WP_Error( 'unable_to_open', __( 'Unable to open backup archive.', 'secure-shield' ) );
        }

        $zip->extractTo( ABSPATH );
        $zip->close();

        do_action( 'secure_shield/log', sprintf( 'Backup restored from %s', $file ), 'warning' );
        return true;
    }
}
