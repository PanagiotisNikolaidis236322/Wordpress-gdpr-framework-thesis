/**
     * Initialize remaining components immediately
     */
    private function initializeRemainingComponents() {
        try {
            // Basic components as before
            $basic_components = [
                'encryption' => '\GDPRFramework\Components\DataEncryptionManager',
                'consent' => '\GDPRFramework\Components\UserConsentManager',
                'access' => '\GDPRFramework\Components\AccessControlManager',
                'portability' => '\GDPRFramework\Components\DataPortabilityManager',
                'reports' => '\GDPRFramework\Components\ComplianceReportManager'
            ];
            
            // First wave of advanced components from Appendix A 
            $advanced_components = [
                'caching' => '\GDPRFramework\Components\CachingManager',
                'requirements' => '\GDPRFramework\Components\SystemRequirementsChecker',
                'api_security' => '\GDPRFramework\Components\APISecurity',
                'network' => '\GDPRFramework\Components\NetworkConfiguration'
            ];
            
            // New performance optimization components from Appendix A
            $performance_components = [
                'partitioning' => '\GDPRFramework\Components\DatabasePartitioning',
                'page_cache' => '\GDPRFramework\Components\PageCachingManager'
            ];
            
            // Combine all components
            $component_classes = array_merge($basic_components, $advanced_components, $performance_components);
            
            foreach ($component_classes as $key => $class) {
                if (!isset($this->components[$key])) {
                    try {
                        // Different components need different parameters
                        // First check if the class exists before attempting to instantiate
                        if (!class_exists($class)) {
                            error_log("GDPR Framework - Class not found: $class");
                            continue;
                        }
                        
                        switch ($key) {
                            case 'caching':
                            case 'requirements':
                            case 'network':
                                // These components only need settings
                                $this->components[$key] = new $class(
                                    $this->settings
                                );
                                break;
                                
                            case 'page_cache':
                                // Page cache needs settings and object cache
                                $this->components[$key] = new $class(
                                    $this->settings,
                                    $this->components['caching'] ?? null
                                );
                                break;
                                
                            default:
                                // Most components need both database and settings
                                $this->components[$key] = new $class(
                                    $this->database,
                                    $this->settings
                                );
                                break;
                        }
                    } catch (\Exception $e) {
                        error_log("GDPR Framework - Failed to initialize $key component: " . $e->getMessage());
                        // Continue with other components
                    }
                }
            }
    
            // Register cleanup task
            if (isset($this->components['audit'])) {
                add_action('gdpr_daily_cleanup', [$this->components['audit'], 'cleanupOldLogs']);
            }
            
            // Register database optimization task
            add_action('gdpr_weekly_maintenance', [$this->database, 'optimizeTables']);
            
            // Register database partitioning task
            if (isset($this->components['partitioning'])) {
                add_action('gdpr_monthly_maintenance', [$this->components['partitioning'], 'maintainPartitions']);
            }
            
            // Register page cache clearing task
            if (isset($this->components['page_cache'])) {
                add_action('gdpr_daily_cleanup', [$this->components['page_cache'], 'clearAllPageCache']);
            }
            
        } catch (\Exception $e) {
            error_log('GDPR Framework Component Init Error: ' . $e->getMessage());
            // Don't throw, just log and continue with what we have
        }
    }
    
    /**
     * Setup cleanup schedule
     */
    private function setupCleanupSchedule() {
        if (!wp_next_scheduled('gdpr_daily_cleanup')) {
            wp_schedule_event(time(), 'daily', 'gdpr_daily_cleanup');
        }
        
        // Add weekly maintenance tasks
        if (!wp_next_scheduled('gdpr_weekly_maintenance')) {
            wp_schedule_event(time(), 'weekly', 'gdpr_weekly_maintenance');
        }
        
        // Add monthly maintenance tasks
        if (!wp_next_scheduled('gdpr_monthly_maintenance')) {
            wp_schedule_event(time(), 'monthly', 'gdpr_monthly_maintenance');
        }

        add_action('gdpr_daily_cleanup', [$this, 'performCleanup']);
        add_action('gdpr_weekly_maintenance', [$this, 'performMaintenance']);
        add_action('gdpr_monthly_maintenance', [$this, 'performMonthlyMaintenance']);
    }
    
    /**
     * Perform monthly maintenance tasks
     */
    public function performMonthlyMaintenance() {
        try {
            // Partition database tables if needed
            if (isset($this->components['partitioning'])) {
                $this->components['partitioning']->maintainPartitions();
            }
            
            // Check and rotate encryption key if needed
            if (isset($this->components['encryption'])) {
                $auto_rotation = get_option('gdpr_auto_key_rotation', 0);
                
                if ($auto_rotation > 0) {
                    $last_rotation = get_option('gdpr_last_key_rotation', 0);
                    $days_since_rotation = floor((time() - $last_rotation) / DAY_IN_SECONDS);
                    
                    if ($days_since_rotation >= $auto_rotation) {
                        $this->components['encryption']->rotateKey();
                    }
                }
            }
            
            // Log maintenance activity
            if (isset($this->components['audit'])) {
                $this->components['audit']->log(
                    0,
                    'monthly_maintenance',
                    __('Monthly maintenance tasks completed', 'wp-gdpr-framework'),
                    'low'
                );
            }
            
            update_option('gdpr_last_monthly_maintenance', current_time('mysql'));
        } catch (\Exception $e) {
            error_log('GDPR Framework Monthly Maintenance Error: ' . $e->getMessage());
        }
    }
    
    /**
     * Render system status page
     */
    public function renderSystemStatus() {
        if (!isset($this->components['template'])) {
            echo '<div class="wrap"><h1>' . esc_html__('GDPR System Status', 'wp-gdpr-framework') . '</h1>';
            echo '<p>' . esc_html__('Template component not initialized.', 'wp-gdpr-framework') . '</p></div>';
            return;
        }
        
        $requirements_info = [];
        $requirements_summary = [];
        
        if (isset($this->components['requirements'])) {
            $requirements_info = $this->components['requirements']->checkAll();
            $requirements_summary = $this->components['requirements']->getSummary();
        }
        
        // Get database partitioning info
        $partitioning_stats = [];
        if (isset($this->components['partitioning'])) {
            $partitioning_stats = $this->components['partitioning']->getPartitioningStats();
        }
        
        // Get page caching info
        $page_cache_stats = [];
        if (isset($this->components['page_cache'])) {
            $page_cache_stats = $this->components['page_cache']->getCachingStats();
        }
        
        echo $this->components['template']->render('admin/system-status', [
            'requirements' => $this->components['requirements'] ?? null,
            'requirements_info' => $requirements_info,
            'requirements_summary' => $requirements_summary,
            'database_stats' => $this->database->getTableStatus(),
            'caching' => $this->components['caching'] ?? null,
            'network' => $this->components['network'] ?? null,
            'partitioning' => $this->components['partitioning'] ?? null,
            'partitioning_stats' => $partitioning_stats,
            'page_cache' => $this->components['page_cache'] ?? null,
            'page_cache_stats' => $page_cache_stats
        ]);
    }
    
    /**
     * Get cleanup status
     */
    public function getCleanupStatus() {
        $next_cleanup = wp_next_scheduled('gdpr_daily_cleanup');
        $next_maintenance = wp_next_scheduled('gdpr_weekly_maintenance');
        $next_monthly = wp_next_scheduled('gdpr_monthly_maintenance');
        
        return [
            'next_run' => $next_cleanup ? date_i18n(
                get_option('date_format') . ' ' . get_option('time_format'),
                $next_cleanup
            ) : __('Not scheduled', 'wp-gdpr-framework'),
            'last_run' => get_option('gdpr_last_cleanup', __('Never', 'wp-gdpr-framework')),
            'next_maintenance' => $next_maintenance ? date_i18n(
                get_option('date_format') . ' ' . get_option('time_format'),
                $next_maintenance
            ) : __('Not scheduled', 'wp-gdpr-framework'),
            'last_maintenance' => get_option('gdpr_last_maintenance', __('Never', 'wp-gdpr-framework')),
            'next_monthly_maintenance' => $next_monthly ? date_i18n(
                get_option('date_format') . ' ' . get_option('time_format'),
                $next_monthly
            ) : __('Not scheduled', 'wp-gdpr-framework'),
            'last_monthly_maintenance' => get_option('gdpr_last_monthly_maintenance', __('Never', 'wp-gdpr-framework'))
        ];
    }