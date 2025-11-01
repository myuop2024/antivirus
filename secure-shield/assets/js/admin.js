(function ($) {
    'use strict';

    $(document).ready(function () {
        const $status = $('<div class="secure-shield__live-status" />').appendTo('.secure-shield__card:first');
        const updateRealtimeBadge = function () {
            const $checkbox = $('#secure_shield_realtime_updates');
            const $badge = $('.js-realtime-pill');
            if (!$checkbox.length || !$badge.length) {
                return;
            }
            const enabled = $checkbox.is(':checked');
            $badge.toggleClass('status-pill--ok', enabled);
            $badge.toggleClass('status-pill--warn', !enabled);
            const label = enabled ? $badge.data('label-on') : $badge.data('label-off');
            $badge.text(label || (enabled ? secureShieldData.labels.realtimeOn : secureShieldData.labels.realtimeOff));
        };

        const updateAiPills = function () {
            $('.js-ai-pill').each(function () {
                const $pill = $(this);
                const selector = $pill.data('target');
                if (!selector) {
                    return;
                }
                const $input = $(selector);
                const hasKey = $input.length && $input.val().trim().length > 0;
                $pill.toggleClass('status-pill--ok', hasKey);
                $pill.toggleClass('status-pill--idle', !hasKey);
                const label = hasKey ? $pill.data('label-on') : $pill.data('label-off');
                $pill.text(label || (hasKey ? secureShieldData.labels.aiReady : secureShieldData.labels.aiWaiting));
            });
        };

        updateRealtimeBadge();
        updateAiPills();

        $('#secure_shield_realtime_updates').on('change', updateRealtimeBadge);
        $('#secure_shield_gemini_api_key, #secure_shield_hf_api_key').on('input blur', updateAiPills);

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
                        const count = Object.keys(response.critical).length;
                        $status.removeClass('secure-shield__badge--info').addClass('secure-shield__badge secure-shield__badge--' + (count ? 'critical' : 'info'));
                        $status.text(count ? ('Critical issues detected: ' + count) : 'No critical issues detected.');
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
