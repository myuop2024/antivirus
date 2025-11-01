(function ($) {
    'use strict';

    $(document).ready(function () {
        const $status = $('<div class="secure-shield__live-status" />').appendTo('.secure-shield__card:first');

        $('.secure-shield form').on('submit', function () {
            if ($(this).find('input[name="action"]').val() === 'secure_shield_scan') {
                $status.text(secureShieldData.scanStatus).addClass('secure-shield__badge secure-shield__badge--info');
            }
        });

        if (typeof wp !== 'undefined' && wp.apiFetch) {
            $('.secure-shield__card:first').append('<button type="button" class="button secure-shield__button-block secure-shield__button-refresh"><span class="dashicons dashicons-update"></span> ' + secureShieldData.scanStatus + '</button>');

            $('.secure-shield__button-refresh').on('click', function () {
                const $button = $(this);
                $button.prop('disabled', true).addClass('is-busy');
                wp.apiFetch({
                    path: '/secure-shield/v1/results',
                    method: 'GET',
                    headers: {
                        'X-WP-Nonce': secureShieldData.nonce
                    }
                }).then(function (response) {
                    if (response && response.critical) {
                        $status.removeClass('secure-shield__badge--info').addClass('secure-shield__badge secure-shield__badge--' + (Object.keys(response.critical).length ? 'critical' : 'success'));
                        if (!Object.keys(response.critical).length) {
                            $status.text('No critical issues detected.');
                        } else {
                            $status.text('Critical issues detected: ' + Object.keys(response.critical).length);
                        }
                    }
                }).catch(function () {
                    $status.text('Unable to fetch latest results.').addClass('secure-shield__badge secure-shield__badge--warning');
                }).finally(function () {
                    $button.prop('disabled', false).removeClass('is-busy');
                });
            });
        }
    });
})(jQuery);
