<!-- Database Partitioning Section -->
<div class="gdpr-dashboard-section">
    <h2><?php _e('Database Partitioning', 'wp-gdpr-framework'); ?></h2>
    
    <?php if (isset($partitioning) && !empty($partitioning_stats)): ?>
        <div class="partition-status">
            <div class="partition-stat-box">
                <span><?php _e('Partitioning', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value status-<?php echo $partitioning_stats['enabled'] ? 'success' : 'warning'; ?>">
                    <?php echo $partitioning_stats['enabled'] ? __('Enabled', 'wp-gdpr-framework') : __('Disabled', 'wp-gdpr-framework'); ?>
                </span>
            </div>
            
            <div class="partition-stat-box">
                <span><?php _e('Server Support', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value status-<?php echo $partitioning_stats['supported'] ? 'success' : 'failure'; ?>">
                    <?php echo $partitioning_stats['supported'] ? __('Available', 'wp-gdpr-framework') : __('Not Available', 'wp-gdpr-framework'); ?>
                </span>
            </div>
            
            <div class="partition-stat-box">
                <span><?php _e('Partitioned Tables', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value">
                    <?php echo esc_html($partitioning_stats['partitioned_count']); ?> / <?php echo esc_html(count($partitioning_stats['tables'])); ?>
                </span>
            </div>
            
            <div class="partition-stat-box">
                <span><?php _e('Total Rows', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value">
                    <?php echo esc_html(number_format($partitioning_stats['total_rows'])); ?>
                </span>
            </div>
        </div>
        
        <?php if (!empty($partitioning_stats['tables'])): ?>
            <h3><?php _e('Tables Eligible for Partitioning', 'wp-gdpr-framework'); ?></h3>
            <table class="widefat">
                <thead>
                    <tr>
                        <th><?php _e('Table', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Rows', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Partitioned', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Partitions', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Status', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Actions', 'wp-gdpr-framework'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($partitioning_stats['tables'] as $table_name => $table): ?>
                        <tr>
                            <td><?php echo esc_html($table['name']); ?></td>
                            <td><?php echo esc_html(number_format($table['rows'])); ?></td>
                            <td>
                                <span class="status-<?php echo $table['is_partitioned'] ? 'success' : 'warning'; ?>">
                                    <?php echo $table['is_partitioned'] ? __('Yes', 'wp-gdpr-framework') : __('No', 'wp-gdpr-framework'); ?>
                                </span>
                            </td>
                            <td><?php echo esc_html($table['partition_count']); ?></td>
                            <td>
                                <?php if ($table['needs_partitioning']): ?>
                                    <span class="status-warning">
                                        <?php _e('Needs Partitioning', 'wp-gdpr-framework'); ?>
                                    </span>
                                <?php elseif ($table['needs_maintenance']): ?>
                                    <span class="status-warning">
                                        <?php _e('Needs Maintenance', 'wp-gdpr-framework'); ?>
                                    </span>
                                <?php else: ?>
                                    <span class="status-success">
                                        <?php _e('OK', 'wp-gdpr-framework'); ?>
                                    </span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if (!$table['is_partitioned'] && $partitioning_stats['supported'] && $partitioning_stats['enabled']): ?>
                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;">
                                        <?php wp_nonce_field('gdpr_partition_table', 'partition_nonce'); ?>
                                        <input type="hidden" name="action" value="gdpr_partition_table">
                                        <input type="hidden" name="table" value="<?php echo esc_attr($table_name); ?>">
                                        <button type="submit" class="button button-small" <?php echo $table['rows'] < 1000 ? 'disabled' : ''; ?>>
                                            <?php _e('Partition', 'wp-gdpr-framework'); ?>
                                        </button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <p>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <?php wp_nonce_field('gdpr_analyze_tables', 'analyze_nonce'); ?>
                    <input type="hidden" name="action" value="gdpr_analyze_tables">
                    <button type="submit" class="button button-secondary">
                        <?php _e('Analyze Tables', 'wp-gdpr-framework'); ?>
                    </button>
                </form>
            </p>
        <?php endif; ?>
        
        <?php if (!$partitioning_stats['supported']): ?>
            <div class="notice notice-warning inline">
                <p>
                    <?php _e('Your database server does not support table partitioning. Upgrading to MySQL 5.7+ or MariaDB 10.3+ is recommended for large datasets.', 'wp-gdpr-framework'); ?>
                </p>
            </div>
        <?php endif; ?>
        
    <?php else: ?>
        <p><?php _e('Database partitioning component not available.', 'wp-gdpr-framework'); ?></p>
    <?php endif; ?>
</div>

<!-- Page Caching Status -->
<div class="gdpr-dashboard-section">
    <h2><?php _e('Page Caching', 'wp-gdpr-framework'); ?></h2>
    
    <?php if (isset($page_cache) && !empty($page_cache_stats)): ?>
        <div class="page-cache-info">
            <div class="cache-stat-box">
                <span><?php _e('Page Caching', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value status-<?php echo $page_cache_stats['enabled'] ? 'success' : 'warning'; ?>">
                    <?php echo $page_cache_stats['enabled'] ? __('Enabled', 'wp-gdpr-framework') : __('Disabled', 'wp-gdpr-framework'); ?>
                </span>
            </div>
            
            <div class="cache-stat-box">
                <span><?php _e('Cache Directory', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value">
                    <?php echo esc_html($page_cache_stats['cache_dir']); ?>
                </span>
            </div>
            
            <div class="cache-stat-box">
                <span><?php _e('Cached Files', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value">
                    <?php echo esc_html(number_format($page_cache_stats['cached_files'])); ?>
                </span>
            </div>
            
            <div class="cache-stat-box">
                <span><?php _e('Cache Size', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value">
                    <?php echo esc_html($page_cache_stats['cache_size']); ?>
                </span>
            </div>
            
            <div class="cache-stat-box">
                <span><?php _e('Cache Expiry', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value">
                    <?php echo esc_html($page_cache_stats['cache_expiry'] . ' ' . __('seconds', 'wp-gdpr-framework')); ?>
                </span>
            </div>
        </div>
        
        <?php if (!empty($page_cache_stats['detected_plugins'])): ?>
            <h3><?php _e('Detected Caching Plugins', 'wp-gdpr-framework'); ?></h3>
            <ul>
                <?php foreach ($page_cache_stats['detected_plugins'] as $plugin): ?>
                    <li><?php echo esc_html($plugin); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
        
        <?php if (!empty($page_cache_stats['exceptions'])): ?>
            <h3><?php _e('Cache Exceptions', 'wp-gdpr-framework'); ?></h3>
            <p><?php _e('The following pages are excluded from caching:', 'wp-gdpr-framework'); ?></p>
            <ul>
                <?php foreach ($page_cache_stats['exceptions'] as $exception): ?>
                    <?php if (!empty($exception)): ?>
                        <li><?php echo esc_html($exception); ?></li>
                    <?php endif; ?>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
        
        <p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <?php wp_nonce_field('gdpr_flush_cache', 'flush_cache_nonce'); ?>
                <input type="hidden" name="action" value="gdpr_flush_cache">
                <button type="submit" class="button button-secondary">
                    <?php _e('Flush Page Cache', 'wp-gdpr-framework'); ?>
                </button>
            </form>
        </p>
        
    <?php else: ?>
        <p><?php _e('Page caching component not available.', 'wp-gdpr-framework'); ?></p>
    <?php endif; ?>
</div>

<style>
    .partition-stat-box, .page-cache-stat-box {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px;
        border-bottom: 1px solid #f0f0f1;
    }
</style>