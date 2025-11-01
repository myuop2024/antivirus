<?php
/**
 * Logging utility for Secure Shield.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Logger {

    const OPTION_LOGS = 'secure_shield_logs';

    /**
     * Register hooks.
     */
    public function register() {
        add_action( 'secure_shield/log', array( $this, 'log' ), 10, 2 );
    }

    /**
     * Append log message to option store.
     *
     * @param string $message Message to log.
     * @param string $level   Log level.
     */
    public function log( $message, $level = 'info' ) {
        $logs = get_option( self::OPTION_LOGS, array() );

        $logs[] = array(
            'time'    => current_time( 'timestamp' ),
            'message' => sanitize_text_field( $message ),
            'level'   => sanitize_text_field( $level ),
        );

        if ( count( $logs ) > 500 ) {
            $logs = array_slice( $logs, -200 );
        }

        update_option( self::OPTION_LOGS, $logs, false );
    }

    /**
     * Retrieve logs.
     *
     * @return array
     */
    public function get_logs() {
        return get_option( self::OPTION_LOGS, array() );
    }
}
