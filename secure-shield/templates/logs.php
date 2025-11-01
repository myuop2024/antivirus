<?php
/**
 * Logs template.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap secure-shield secure-shield--logs">
    <h1 class="secure-shield__title"><?php esc_html_e( 'BISON Security Suite Threat Logs', SECURE_SHIELD_TEXT_DOMAIN ); ?></h1>
    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th><?php esc_html_e( 'Time', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                <th><?php esc_html_e( 'Level', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
                <th><?php esc_html_e( 'Message', SECURE_SHIELD_TEXT_DOMAIN ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php if ( empty( $logs ) ) : ?>
                <tr>
                    <td colspan="3"><?php esc_html_e( 'No log entries yet.', SECURE_SHIELD_TEXT_DOMAIN ); ?></td>
                </tr>
            <?php else : ?>
                <?php foreach ( array_reverse( $logs ) as $entry ) : ?>
                    <tr>
                        <td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $entry['time'] ) ); ?></td>
                        <td><span class="secure-shield__badge secure-shield__badge--<?php echo esc_attr( $entry['level'] ); ?>"><?php echo esc_html( ucfirst( $entry['level'] ) ); ?></span></td>
                        <td><?php echo esc_html( $entry['message'] ); ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</div>
