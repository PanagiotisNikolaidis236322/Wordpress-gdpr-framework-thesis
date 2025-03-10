<?php
if (!defined('ABSPATH')) exit;

// Ensure variables are defined with defaults
$periods = $periods ?? [];
$exemptions = $exemptions ?? [];
$last_cleanup = $last_cleanup ?? false;
$next_cleanup = $next_cleanup ?? false;
$stats = $stats ?? [];
?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    
    <div class="notice notice-info">
        <p><?php _e('Data retention policies automatically enforce GDPR Article 5 requirements by deleting or anonymizing personal data after specified time periods.', 'wp-gdpr-framework'); ?></p>
    </div>
    
    <!-- Status Summary -->
    <div class="gdpr-dashboard-grid">
        <div class="gdpr-dashboard-section">
            <h2><?php _e('Retention Status', 'wp-gdpr-framework'); ?></h2>
            
            <div class="stat-box">
                <span><?php _e('Last Cleanup', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value">
                    <?php 
                    if ($last_cleanup) {
                        echo esc_html(date_i18n(
                            get_option('date_format') . ' ' . get_option('time_format'),
                            strtotime($last_cleanup)
                        ));
                    } else {
                        _e('Never', 'wp-gdpr-framework');
                    }
                    ?>
                </span>
            </div>
            
            <div class="stat-box">
                <span><?php _e('Next Scheduled Cleanup', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value">
                    <?php 
                    if ($next_cleanup) {
                        echo esc_html(date_i18n(
                            get_option('date_format') . ' ' . get_option('time_format'),
                            $next_cleanup
                        ));
                    } else {
                        _e('Not scheduled', 'wp-gdpr-framework');
                    }
                    ?>
                </span>
            </div>
            
            <div>
                <button type="button" id="gdpr-manual-cleanup" class="button button-primary" 
                        data-nonce="<?php echo wp_create_nonce('gdpr_manual_cleanup'); ?>">
                    <?php _e('Run Manual Cleanup', 'wp-gdpr-framework'); ?>
                </button>
            </div>
        </div>
        
        <div class="gdpr-dashboard-section">
            <h2><?php _e('Data Overview', 'wp-gdpr-framework'); ?></h2>
            
            <?php foreach ($stats as $type => $counts): ?>
                <div class="stat-box">
                    <span><?php echo esc_html($periods[$type]['label'] ?? ucfirst(str_replace('_', ' ', $type))); ?></span>
                    <span class="stat-value">
                        <?php 
                        if (isset($counts['total']) && isset($counts['eligible'])) {
                            echo sprintf(
                                __('%d eligible / %d total', 'wp-gdpr-framework'),
                                $counts['eligible'],
                                $counts['total']
                            );
                        } else {
                            _e('N/A', 'wp-gdpr-framework');
                        }
                        ?>
                    </span>
                </div>
            <?php endforeach; ?>
            
            <?php if (empty($stats)): ?>
                <p><?php _e('No data statistics available.', 'wp-gdpr-framework'); ?></p>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- Retention Policies -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('Data Retention Policies', 'wp-gdpr-framework'); ?></h2>
        
        <?php if (!empty($periods)): ?>
            <table class="widefat">
                <thead>
                    <tr>
                        <th><?php _e('Data Type', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Retention Period', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Status', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Action', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Description', 'wp-gdpr-framework'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($periods as $key => $period): ?>
                        <tr>
                            <td><strong><?php echo esc_html($period['label']); ?></strong></td>
                            <td>
                                <?php 
                                echo esc_html(sprintf(
                                    _n('%d day', '%d days', $period['days'], 'wp-gdpr-framework'),
                                    $period['days']
                                ));
                                ?>
                            </td>
                            <td>
                                <?php if ($period['enabled']): ?>
                                    <span class="status-success"><?php _e('Enabled', 'wp-gdpr-framework'); ?></span>
                                <?php else: ?>
                                    <span class="status-failure"><?php _e('Disabled', 'wp-gdpr-framework'); ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php 
                                // Check if this type has a legal exemption
                                $exempted = false;
                                $exemption_days = 0;
                                
                                // Map data types to potential exemptions
                                $exemption_map = [
                                    'order_history' => 'financial_records',
                                    'user_financial_data' => 'financial_records',
                                    'health_data' => 'health_data',
                                    'legal_agreements' => 'legal_contracts'
                                ];
                                
                                if (isset($exemption_map[$key]) && isset($exemptions[$exemption_map[$key]])) {
                                    $exemption = $exemptions[$exemption_map[$key]];
                                    $exemption_days = $exemption['min_days'];
                                    $exempted = $exemption_days > $period['days'];
                                }
                                
                                if ($exempted): 
                                ?>
                                    <span class="status-warning"><?php _e('Legally exempted', 'wp-gdpr-framework'); ?></span>
                                <?php else: ?>
                                    <?php if ($period['enabled']): ?>
                                        <?php echo $key === 'comments' ? __('Anonymize', 'wp-gdpr-framework') : __('Delete', 'wp-gdpr-framework'); ?>
                                    <?php else: ?>
                                        <?php _e('No action', 'wp-gdpr-framework'); ?>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html($period['description']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <p>
                <a href="<?php echo esc_url(admin_url('admin.php?page=gdpr-framework-settings#retention')); ?>" class="button">
                    <?php _e('Edit Retention Policies', 'wp-gdpr-framework'); ?>
                </a>
            </p>
        <?php else: ?>
            <p><?php _e('No retention policies defined.', 'wp-gdpr-framework'); ?></p>
        <?php endif; ?>
    </div>
    
    <!-- Legal Exemptions -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('Legal Exemptions', 'wp-gdpr-framework'); ?></h2>
        
        <?php if (!empty($exemptions)): ?>
            <table class="widefat">
                <thead>
                    <tr>
                        <th><?php _e('Data Category', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Minimum Retention', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Reason', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Regulation', 'wp-gdpr-framework'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($exemptions as $key => $exemption): ?>
                        <tr>
                            <td><strong><?php echo esc_html($exemption['label']); ?></strong></td>
                            <td>
                                <?php 
                                echo esc_html(sprintf(
                                    _n('%d day', '%d days', $exemption['min_days'], 'wp-gdpr-framework'),
                                    $exemption['min_days']
                                ));
                                
                                if ($exemption['min_days'] >= 365) {
                                    $years = floor($exemption['min_days'] / 365);
                                    echo ' (' . sprintf(_n('%d year', '%d years', $years, 'wp-gdpr-framework'), $years) . ')';
                                }
                                ?>
                            </td>
                            <td><?php echo esc_html($exemption['reason']); ?></td>
                            <td><?php echo esc_html($exemption['regulation']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <p>
                <a href="<?php echo esc_url(admin_url('admin.php?page=gdpr-framework-settings#retention')); ?>" class="button">
                    <?php _e('Edit Legal Exemptions', 'wp-gdpr-framework'); ?>
                </a>
            </p>
        <?php else: ?>
            <p><?php _e('No legal exemptions defined.', 'wp-gdpr-framework'); ?></p>
        <?php endif; ?>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    $('#gdpr-manual-cleanup').on('click', function() {
        if (!confirm('<?php echo esc_js(__('Are you sure you want to run the data cleanup process? This will permanently delete or anonymize data according to your retention policies.', 'wp-gdpr-framework')); ?>')) {
            return;
        }
        
        var $button = $(this);
        $button.prop('disabled', true).text('<?php echo esc_js(__('Cleaning...', 'wp-gdpr-framework')); ?>');
        
        $.ajax({
            url: ajaxurl,
            method: 'POST',
            data: {
                action: 'gdpr_manual_cleanup',
                nonce: $button.data('nonce')
            },
            success: function(response) {
                if (response.success) {
                    alert('<?php echo esc_js(__('Data cleanup completed successfully.', 'wp-gdpr-framework')); ?>');
                    location.reload();
                } else {
                    alert(response.data.message || '<?php echo esc_js(__('An error occurred during cleanup.', 'wp-gdpr-framework')); ?>');
                    $button.prop('disabled', false).text('<?php echo esc_js(__('Run Manual Cleanup', 'wp-gdpr-framework')); ?>');
                }
            },
            error: function() {
                alert('<?php echo esc_js(__('An error occurred during cleanup.', 'wp-gdpr-framework')); ?>');
                $button.prop('disabled', false).text('<?php echo esc_js(__('Run Manual Cleanup', 'wp-gdpr-framework')); ?>');
            }
        });
    });
});
</script>