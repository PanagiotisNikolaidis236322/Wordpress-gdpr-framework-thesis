<?php
namespace GDPRFramework\Components;

/**
 * Database Partitioning Manager
 * 
 * Implements database partitioning for large datasets as specified in Appendix A
 * - Supports scaling MySQL/MariaDB operations
 * - Handles large audit logs through partitioning
 * - Implements sharding strategies for high-volume installations
 */
class DatabasePartitioning {
    private $db;
    private $settings;
    private $is_enabled = false;
    private $partition_threshold = 50000; // Row count threshold for partitioning
    private $max_partitions = 12; // Maximum number of partitions to create
    private $tables_eligible_for_partitioning = [
        'audit_log', 
        'user_consents', 
        'login_log'
    ];
    private $debug = false;

    public function __construct($database, $settings) {
        global $wpdb;
        
        $this->db = $database;
        $this->settings = $settings;
        $this->debug = defined('WP_DEBUG') && WP_DEBUG;
        
        // Check if partitioning is enabled
        $this->is_enabled = get_option('gdpr_enable_partitioning', 0);
        
        // Set thresholds from settings
        $this->partition_threshold = get_option('gdpr_partition_threshold', 50000);
        $this->max_partitions = get_option('gdpr_max_partitions', 12);
        
        // Register hooks
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('admin_post_gdpr_analyze_tables', [$this, 'handleAnalyzeTables']);
        add_action('admin_post_gdpr_partition_table', [$this, 'handlePartitionTable']);
        
        // Register maintenance task
        add_action('gdpr_monthly_maintenance', [$this, 'maintainPartitions']);
    }
    
    /**
     * Register partitioning settings
     */
    public function registerSettings() {
        register_setting('gdpr_framework_settings', 'gdpr_enable_partitioning', [
            'type' => 'boolean',
            'default' => 0,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_partition_threshold', [
            'type' => 'integer',
            'default' => 50000,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_max_partitions', [
            'type' => 'integer',
            'default' => 12,
            'sanitize_callback' => [$this, 'sanitizeMaxPartitions']
        ]);
        
        // Add settings section and fields
        add_settings_section(
            'gdpr_partitioning_section',
            __('Database Partitioning', 'wp-gdpr-framework'),
            [$this, 'renderPartitioningSection'],
            'gdpr_framework_settings'
        );
        
        add_settings_field(
            'gdpr_enable_partitioning',
            __('Enable Partitioning', 'wp-gdpr-framework'),
            [$this, 'renderEnablePartitioningField'],
            'gdpr_framework_settings',
            'gdpr_partitioning_section'
        );
        
        add_settings_field(
            'gdpr_partition_threshold',
            __('Partition Threshold', 'wp-gdpr-framework'),
            [$this, 'renderPartitionThresholdField'],
            'gdpr_framework_settings',
            'gdpr_partitioning_section'
        );
        
        add_settings_field(
            'gdpr_max_partitions',
            __('Maximum Partitions', 'wp-gdpr-framework'),
            [$this, 'renderMaxPartitionsField'],
            'gdpr_framework_settings',
            'gdpr_partitioning_section'
        );
    }
    
    /**
     * Render partitioning section description
     */
    public function renderPartitioningSection() {
        echo '<p>' . esc_html__('Configure database partitioning for large datasets.', 'wp-gdpr-framework') . '</p>';
        
        echo '<div class="notice notice-info inline">';
        echo '<p>' . esc_html__('Note: Database partitioning requires a MySQL/MariaDB server that supports partitioning.', 'wp-gdpr-framework') . '</p>';
        echo '</div>';
        
        // Show server support status
        if ($this->isPartitioningSupported()) {
            echo '<div class="notice notice-success inline">';
            echo '<p>' . esc_html__('Your database server supports partitioning!', 'wp-gdpr-framework') . '</p>';
            echo '</div>';
        } else {
            echo '<div class="notice notice-error inline">';
            echo '<p>' . esc_html__('Your database server does not support partitioning or it is not enabled.', 'wp-gdpr-framework') . '</p>';
            echo '</div>';
        }
    }
    
    /**
     * Render enable partitioning field
     */
    public function renderEnablePartitioningField() {
        $enabled = get_option('gdpr_enable_partitioning', 0);
        $disabled = !$this->isPartitioningSupported() ? 'disabled' : '';
        
        echo '<input type="checkbox" id="gdpr_enable_partitioning" name="gdpr_enable_partitioning" value="1" ' . 
             checked($enabled, 1, false) . ' ' . $disabled . '>';
             
        echo '<p class="description">' . 
             esc_html__('Enable database partitioning for improved performance with large datasets.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render partition threshold field
     */
    public function renderPartitionThresholdField() {
        $threshold = get_option('gdpr_partition_threshold', 50000);
        $disabled = !$this->isPartitioningSupported() ? 'disabled' : '';
        
        echo '<input type="number" id="gdpr_partition_threshold" name="gdpr_partition_threshold" value="' . 
             esc_attr($threshold) . '" min="10000" step="10000" class="medium-text" ' . $disabled . '>';
             
        echo '<p class="description">' . 
             esc_html__('Minimum number of rows before partitioning is applied to a table.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render max partitions field
     */
    public function renderMaxPartitionsField() {
        $max_partitions = get_option('gdpr_max_partitions', 12);
        $disabled = !$this->isPartitioningSupported() ? 'disabled' : '';
        
        echo '<input type="number" id="gdpr_max_partitions" name="gdpr_max_partitions" value="' . 
             esc_attr($max_partitions) . '" min="4" max="24" step="1" class="small-text" ' . $disabled . '>';
             
        echo '<p class="description">' . 
             esc_html__('Maximum number of partitions to create per table (4-24).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Sanitize max partitions setting
     */
    public function sanitizeMaxPartitions($value) {
        $value = absint($value);
        
        if ($value < 4) {
            return 4;
        }
        
        if ($value > 24) {
            return 24;
        }
        
        return $value;
    }
    
    /**
     * Check if partitioning is supported by the database server
     */
    public function isPartitioningSupported() {
        global $wpdb;
        
        // Check if the server supports partitioning
        $plugins = $wpdb->get_results("SHOW PLUGINS WHERE Name = 'partition' AND Status = 'ACTIVE'");
        
        return !empty($plugins);
    }
    
    /**
     * Get tables eligible for partitioning with their status
     */
    public function getEligibleTables() {
        global $wpdb;
        $prefix = $wpdb->prefix . 'gdpr_';
        $eligible_tables = [];
        
        foreach ($this->tables_eligible_for_partitioning as $table) {
            $table_name = $prefix . $table;
            
            // Check if table exists
            if (!$this->tableExists($table_name)) {
                continue;
            }
            
            // Get row count
            $row_count = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");
            
            // Check if table is already partitioned
            $is_partitioned = $this->isTablePartitioned($table_name);
            
            // Get partitions if applicable
            $partitions = $is_partitioned ? $this->getTablePartitions($table_name) : [];
            
            $eligible_tables[$table] = [
                'name' => $table_name,
                'rows' => $row_count,
                'is_partitioned' => $is_partitioned,
                'partitions' => $partitions,
                'partition_count' => count($partitions),
                'needs_partitioning' => !$is_partitioned && $row_count >= $this->partition_threshold,
                'needs_maintenance' => $is_partitioned && count($partitions) > $this->max_partitions
            ];
        }
        
        return $eligible_tables;
    }
    
    /**
     * Handle analyze tables action
     */
    public function handleAnalyzeTables() {
        // Verify nonce and permissions
        check_admin_referer('gdpr_analyze_tables', 'analyze_nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to perform this action.', 'wp-gdpr-framework'));
        }
        
        // Analyze tables
        $results = $this->analyzeTables();
        
        // Redirect back with results
        wp_redirect(add_query_arg(['page' => 'gdpr-framework-system', 'analyzed' => 1], admin_url('admin.php')));
        exit;
    }
    
    /**
     * Handle partition table action
     */
    public function handlePartitionTable() {
        // Verify nonce and permissions
        check_admin_referer('gdpr_partition_table', 'partition_nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to perform this action.', 'wp-gdpr-framework'));
        }
        
        // Get table to partition
        $table = isset($_POST['table']) ? sanitize_text_field($_POST['table']) : '';
        
        if (empty($table)) {
            wp_die(__('No table specified.', 'wp-gdpr-framework'));
        }
        
        // Partition table
        $result = $this->partitionTable($table);
        
        // Redirect back with results
        $status = $result ? 'success' : 'error';
        wp_redirect(add_query_arg(
            ['page' => 'gdpr-framework-system', 'partition_status' => $status, 'table' => $table], 
            admin_url('admin.php')
        ));
        exit;
    }
    
    /**
     * Check if a table exists
     */
    private function tableExists($table_name) {
        global $wpdb;
        
        return $wpdb->get_var(
            $wpdb->prepare("SHOW TABLES LIKE %s", $table_name)
        ) === $table_name;
    }
    
    /**
     * Check if a table is already partitioned
     */
    private function isTablePartitioned($table_name) {
        global $wpdb;
        
        // Get table status
        $result = $wpdb->get_row("SHOW TABLE STATUS LIKE '{$table_name}'");
        
        // Check Create_options for partitioning
        return $result && strpos($result->Create_options, 'partitioned') !== false;
    }
    
    /**
     * Get partitions for a table
     */
    private function getTablePartitions($table_name) {
        global $wpdb;
        
        // Get partitions
        $partitions = $wpdb->get_results("
            SELECT PARTITION_NAME, PARTITION_DESCRIPTION, PARTITION_METHOD, TABLE_ROWS
            FROM INFORMATION_SCHEMA.PARTITIONS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = '" . str_replace('`', '', $table_name) . "'
            AND PARTITION_NAME IS NOT NULL
            ORDER BY PARTITION_DESCRIPTION ASC
        ");
        
        return $partitions;
    }
    
    /**
     * Analyze tables for partitioning
     */
    public function analyzeTables() {
        global $wpdb;
        $prefix = $wpdb->prefix . 'gdpr_';
        $results = [];
        
        foreach ($this->tables_eligible_for_partitioning as $table) {
            $table_name = $prefix . $table;
            
            // Check if table exists
            if (!$this->tableExists($table_name)) {
                continue;
            }
            
            // Analyze table
            $wpdb->query("ANALYZE TABLE {$table_name}");
            
            // Get results
            $results[$table] = [
                'name' => $table_name,
                'analyzed' => true
            ];
        }
        
        return $results;
    }
    
    /**
     * Partition a table
     */
    public function partitionTable($table) {
        global $wpdb;
        $prefix = $wpdb->prefix . 'gdpr_';
        $table_name = $prefix . $table;
        
        // Check if table exists
        if (!$this->tableExists($table_name)) {
            error_log("GDPR Partitioning: Table {$table_name} does not exist");
            return false;
        }
        
        // Check if table is already partitioned
        if ($this->isTablePartitioned($table_name)) {
            error_log("GDPR Partitioning: Table {$table_name} is already partitioned");
            return false;
        }
        
        // Get table structure
        $table_structure = $wpdb->get_row("SHOW CREATE TABLE {$table_name}", ARRAY_A);
        
        if (!$table_structure || !isset($table_structure['Create Table'])) {
            error_log("GDPR Partitioning: Could not get table structure for {$table_name}");
            return false;
        }
        
        // Determine appropriate partitioning strategy
        $partition_strategy = $this->determinePartitionStrategy($table);
        
        // If no appropriate strategy, bail
        if (empty($partition_strategy)) {
            error_log("GDPR Partitioning: No appropriate partitioning strategy for {$table_name}");
            return false;
        }
        
        try {
            // Backup the table first
            $backup_result = $this->backupTable($table_name);
            
            if (!$backup_result) {
                error_log("GDPR Partitioning: Failed to backup table {$table_name}");
                return false;
            }
            
            // Apply partitioning based on strategy
            switch ($partition_strategy) {
                case 'RANGE_TIMESTAMP':
                    return $this->applyRangePartitioning($table_name, 'timestamp');
                    
                case 'RANGE_CREATED_AT':
                    return $this->applyRangePartitioning($table_name, 'created_at');
                    
                case 'HASH_ID':
                    return $this->applyHashPartitioning($table_name, 'id');
                    
                case 'HASH_USER_ID':
                    return $this->applyHashPartitioning($table_name, 'user_id');
                    
                default:
                    return false;
            }
            
        } catch (\Exception $e) {
            error_log("GDPR Partitioning Error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Determine the best partitioning strategy for a table
     */
    private function determinePartitionStrategy($table) {
        switch ($table) {
            case 'audit_log':
            case 'login_log':
                return 'RANGE_TIMESTAMP';
                
            case 'data_requests':
                return 'RANGE_CREATED_AT';
                
            case 'user_consents':
                // Determine if timestamp or hash is better based on table size
                $count = $this->getTableRowCount('gdpr_user_consents');
                return $count > 500000 ? 'HASH_USER_ID' : 'RANGE_TIMESTAMP';
                
            default:
                return 'HASH_ID'; // Fallback
        }
    }
    
    /**
     * Get row count for a table
     */
    private function getTableRowCount($table) {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}{$table}");
    }
    
    /**
     * Backup a table before partitioning
     */
    private function backupTable($table_name) {
        global $wpdb;
        
        // Create backup table
        $backup_table = $table_name . '_backup_' . time();
        
        $result = $wpdb->query("CREATE TABLE {$backup_table} LIKE {$table_name}");
        
        if ($result === false) {
            return false;
        }
        
        // Copy data
        $result = $wpdb->query("INSERT INTO {$backup_table} SELECT * FROM {$table_name}");
        
        return $result !== false;
    }
    
    /**
     * Apply range partitioning to a table
     */
    private function applyRangePartitioning($table_name, $timestamp_column) {
        global $wpdb;
        
        // Get earliest timestamp
        $earliest = $wpdb->get_var("SELECT MIN({$timestamp_column}) FROM {$table_name}");
        
        if (!$earliest) {
            // If no data, use current time minus 1 year
            $earliest = date('Y-m-d H:i:s', strtotime('-1 year'));
        }
        
        // Calculate partitioning intervals (monthly)
        $partition_count = min($this->max_partitions, 12); // At most 12 months
        $partitions = [];
        
        // Create partitioning SQL
        $timestamp = strtotime($earliest);
        $interval = '+1 month';
        
        // Add partitions for each month
        for ($i = 0; $i < $partition_count - 1; $i++) {
            $next_timestamp = strtotime($interval, $timestamp);
            $unix_timestamp = $next_timestamp;
            
            $partitions[] = "PARTITION p" . date('Ym', $timestamp) . 
                           " VALUES LESS THAN (" . $unix_timestamp . ")";
            
            $timestamp = $next_timestamp;
        }
        
        // Add max partition
        $partitions[] = "PARTITION pMaxValue VALUES LESS THAN MAXVALUE";
        
        // Build alter table statement
        $alter_sql = "ALTER TABLE {$table_name} 
                     PARTITION BY RANGE(UNIX_TIMESTAMP({$timestamp_column})) (
                     " . implode(",\n", $partitions) . "
                     )";
        
        // Execute the statement
        $result = $wpdb->query($alter_sql);
        
        if ($result === false) {
            error_log("GDPR Partitioning Error: " . $wpdb->last_error);
            return false;
        }
        
        return true;
    }
    
    /**
     * Apply hash partitioning to a table
     */
    private function applyHashPartitioning($table_name, $column) {
        global $wpdb;
        
        // Determine partition count (power of 2 for better distribution)
        $partition_count = pow(2, floor(log($this->max_partitions, 2)));
        
        // Build alter table statement
        $alter_sql = "ALTER TABLE {$table_name} 
                     PARTITION BY HASH({$column}) 
                     PARTITIONS {$partition_count}";
        
        // Execute the statement
        $result = $wpdb->query($alter_sql);
        
        if ($result === false) {
            error_log("GDPR Partitioning Error: " . $wpdb->last_error);
            return false;
        }
        
        return true;
    }
    
    /**
     * Maintain partitions (add/remove as needed)
     */
    public function maintainPartitions() {
        // Skip if partitioning is not enabled
        if (!$this->is_enabled || !$this->isPartitioningSupported()) {
            return;
        }
        
        $eligible_tables = $this->getEligibleTables();
        
        foreach ($eligible_tables as $table => $info) {
            // If table needs partitioning and is large enough
            if ($info['needs_partitioning'] && $info['rows'] >= $this->partition_threshold) {
                $this->partitionTable($table);
            }
            
            // If table is partitioned but needs maintenance
            if ($info['is_partitioned'] && $info['needs_maintenance']) {
                $this->reorganizePartitions($info['name']);
            }
        }
    }
    
    /**
     * Reorganize partitions for a table
     */
    private function reorganizePartitions($table_name) {
        global $wpdb;
        
        // Check if range or hash partitioning
        $partitions = $this->getTablePartitions($table_name);
        
        if (empty($partitions)) {
            return false;
        }
        
        $partition_method = $partitions[0]->PARTITION_METHOD ?? '';
        
        // Handle based on partition type
        if ($partition_method === 'RANGE') {
            return $this->reorganizeRangePartitions($table_name, $partitions);
        } elseif ($partition_method === 'HASH') {
            return $this->reorganizeHashPartitions($table_name, $partitions);
        }
        
        return false;
    }
    
    /**
     * Reorganize range partitions (drop old, add new)
     */
    private function reorganizeRangePartitions($table_name, $partitions) {
        global $wpdb;
        
        // Sort partitions by description (timestamp)
        usort($partitions, function($a, $b) {
            if ($a->PARTITION_NAME === 'pMaxValue') return 1;
            if ($b->PARTITION_NAME === 'pMaxValue') return -1;
            return $a->PARTITION_DESCRIPTION <=> $b->PARTITION_DESCRIPTION;
        });
        
        // If we have more partitions than max, drop oldest
        if (count($partitions) > $this->max_partitions) {
            // Keep the newest (max_partitions - 1) plus maxvalue
            $partitions_to_keep = array_slice($partitions, -(($this->max_partitions - 1) + 1));
            $partitions_to_drop = array_diff(array_column($partitions, 'PARTITION_NAME'), 
                                            array_column($partitions_to_keep, 'PARTITION_NAME'));
            
            // Drop oldest partitions
            foreach ($partitions_to_drop as $partition_name) {
                $sql = "ALTER TABLE {$table_name} DROP PARTITION {$partition_name}";
                $wpdb->query($sql);
            }
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Reorganize hash partitions (rebalance if needed)
     */
    private function reorganizeHashPartitions($table_name, $partitions) {
        global $wpdb;
        
        // For hash partitions, coalesce if we have too many
        if (count($partitions) > $this->max_partitions) {
            $target_count = pow(2, floor(log($this->max_partitions, 2)));
            
            $sql = "ALTER TABLE {$table_name} COALESCE PARTITION " . 
                  (count($partitions) - $target_count);
            
            $result = $wpdb->query($sql);
            
            return $result !== false;
        }
        
        return false;
    }
    
    /**
     * Get partitioning status and statistics
     */
    public function getPartitioningStats() {
        $eligible_tables = $this->getEligibleTables();
        $stats = [
            'enabled' => $this->is_enabled,
            'supported' => $this->isPartitioningSupported(),
            'tables' => $eligible_tables,
            'partitioned_count' => 0,
            'needs_partitioning' => 0,
            'needs_maintenance' => 0,
            'total_rows' => 0
        ];
        
        foreach ($eligible_tables as $table) {
            $stats['total_rows'] += $table['rows'];
            
            if ($table['is_partitioned']) {
                $stats['partitioned_count']++;
            }
            
            if ($table['needs_partitioning']) {
                $stats['needs_partitioning']++;
            }
            
            if ($table['needs_maintenance']) {
                $stats['needs_maintenance']++;
            }
        }
        
        return $stats;
    }
}