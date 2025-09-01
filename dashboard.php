<?php
/**
 * Advanced Visitor Filtering System - Admin Dashboard
 * 
 * Provides real-time visualization of visitor data with threat matrix
 * and management capabilities.
 */

// Configuration
$config = [
    'log_file' => 'visitors.log',
    'allowed_countries' => ['US', 'DE', 'FR', 'MA']
];

// Handle log purging
if (isset($_POST['action']) && $_POST['action'] === 'purge_logs') {
    if (file_exists($config['log_file'])) {
        file_put_contents($config['log_file'], '');
    }
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
}

// Function to parse log file
function parseLogFile($logFile) {
    // Parse visitor logs
    $logs = [];
    $stats = [
        'total' => 0,
        'blocked' => 0,
        'clean' => 0,
        'countries' => [],
        'browsers' => [],
        'isps' => [],
        'flags' => []
    ];
    
    // No longer loading blocked IPs
    
    if (!file_exists($logFile)) {
        return ['logs' => [], 'stats' => $stats];
    }
    
    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $isHeader = true;
    
    foreach ($lines as $line) {
        // Skip header line
        if ($isHeader && strpos($line, '[TIMESTAMP]') !== false) {
            $isHeader = false;
            continue;
        }
        
        // Extract timestamp and data parts
        if (preg_match('/^\[(.*?)\] (.*)$/', $line, $matches)) {
            $timestamp = $matches[1];
            $data = explode(' | ', $matches[2]);
            
            // Check if we have enough data parts for the enhanced format
            if (count($data) >= 14) {
                $ip = $data[0] ?? 'unknown';
                $countryName = $data[1] ?? 'unknown';
                $countryCode = $data[2] ?? 'unknown';
                $city = $data[3] ?? 'unknown';
                $timezone = $data[4] ?? 'unknown';
                $status = $data[5] ?? 'unknown';
                $blockReason = $data[6] ?? 'none';
                $userAgent = $data[7] ?? 'unknown';
                $os = $data[8] ?? 'unknown';
                $browser = $data[9] ?? 'unknown';
                $version = $data[10] ?? 'unknown';
                $isp = $data[11] ?? 'unknown';
                $org = $data[12] ?? 'unknown';
                $flags = $data[13] ?? 'none';
                
                // Determine threat level
                $threatLevel = 'green'; // Default: clean
                
                if ($status === 'blocked' || strpos($flags, 'proxy:detected') !== false || 
                    strpos($flags, 'hosting:detected') !== false || 
                    strpos($flags, 'bot_signature') !== false || 
                    strpos($flags, 'suspicious_ua') !== false || 
                    strpos($flags, 'suspicious_isp') !== false) {
                    $threatLevel = 'red'; // High threat
                } elseif (strpos($flags, 'timezone_mismatch') !== false || 
                         strpos($flags, 'browser_inconsistency') !== false) {
                    $threatLevel = 'amber'; // Medium threat
                }
                
                // No longer checking for manually blocked IPs
                
                // Add to logs
                $logs[] = [
                    'time' => $timestamp, // This already contains the full timestamp format
                    'ip' => $ip,
                    'country_name' => $countryName,
                    'country' => $countryCode,
                    'city' => $city,
                    'timezone' => $timezone,
                    'status' => $status,
                    'block_reason' => $blockReason,
                    'user_agent' => $userAgent,
                    'os' => $os,
                    'browser' => $browser,
                    'version' => $version,
                    'isp' => $isp,
                    'org' => $org,
                    'flags' => $flags,
                    'threat_level' => $threatLevel
                ];
                
                // Update stats
                if (!isset($stats['countries'][$countryCode])) {
                    $stats['countries'][$countryCode] = 0;
                }
                $stats['countries'][$countryCode]++;
                
                if (!isset($stats['isps'][$isp])) {
                    $stats['isps'][$isp] = 0;
                }
                $stats['isps'][$isp]++;
                
                if (!isset($stats['browsers'][$browser])) {
                    $stats['browsers'][$browser] = 0;
                }
                $stats['browsers'][$browser]++;
                
                if (!isset($stats['os'][$os])) {
                    $stats['os'][$os] = 0;
                }
                $stats['os'][$os]++;
                
                if (!isset($stats['cities'][$city])) {
                    $stats['cities'][$city] = 0;
                }
                $stats['cities'][$city]++;
                
                if (!isset($stats['statuses'][$status])) {
                    $stats['statuses'][$status] = 0;
                }
                $stats['statuses'][$status]++;
                
                // Process detection flags
                $flagsArray = explode(',', $flags);
                foreach ($flagsArray as $flag) {
                    if (!empty($flag)) {
                        if (!isset($stats['flags'][$flag])) {
                            $stats['flags'][$flag] = 0;
                        }
                        $stats['flags'][$flag]++;
                    }
                }
            } else {
                // Handle legacy format (for backward compatibility)
                $ip = $data[0] ?? 'unknown';
                $countryCode = $data[1] ?? 'unknown';
                $proxy = $data[2] ?? 'unknown';
                $hosting = $data[3] ?? 'unknown';
                $isp = $data[4] ?? 'unknown';
                $uaHash = $data[5] ?? 'unknown';
                $flags = $data[6] ?? 'none';
                
                // Determine threat level
                $threatLevel = 'green'; // Default: clean
                
                if ($proxy === 'true' || $hosting === 'true' || 
                    strpos($flags, 'bot_signature') !== false || 
                    strpos($flags, 'suspicious_ua') !== false || 
                    strpos($flags, 'suspicious_isp') !== false) {
                    $threatLevel = 'red'; // High threat
                } elseif (strpos($flags, 'timezone_mismatch') !== false || 
                         strpos($flags, 'browser_inconsistency') !== false) {
                    $threatLevel = 'amber'; // Medium threat
                }
                
                // Add to logs with default values for new fields
                $logs[] = [
                    'time' => $timestamp,
                    'ip' => $ip,
                    'country_name' => $countryCode,
                    'country' => $countryCode,
                    'city' => 'unknown',
                    'timezone' => 'unknown',
                    'status' => $proxy === 'true' || $hosting === 'true' ? 'blocked' : 'clean',
                    'block_reason' => $proxy === 'true' ? 'proxy_detected' : ($hosting === 'true' ? 'hosting_detected' : 'none'),
                    'user_agent' => 'unknown',
                    'os' => 'unknown',
                    'browser' => 'unknown',
                    'version' => 'unknown',
                    'requests' => '1',
                    'isp' => $isp,
                    'org' => 'unknown',
                    'flags' => $flags,
                    'threat_level' => $threatLevel
                ];
                
                // Update stats
                if (!isset($stats['countries'][$countryCode])) {
                    $stats['countries'][$countryCode] = 0;
                }
                $stats['countries'][$countryCode]++;
                
                if (!isset($stats['isps'][$isp])) {
                    $stats['isps'][$isp] = 0;
                }
                $stats['isps'][$isp]++;
                
                // Process detection flags
                $flagsArray = explode(',', $flags);
                foreach ($flagsArray as $flag) {
                    if (!empty($flag)) {
                        if (!isset($stats['flags'][$flag])) {
                            $stats['flags'][$flag] = 0;
                        }
                        $stats['flags'][$flag]++;
                    }
                }
            }
        }
    }
    
    // Sort stats
    arsort($stats['countries']);
    arsort($stats['isps']);
    arsort($stats['flags']);
    arsort($stats['browsers']);
    
    // These arrays were removed during IP blocking removal
    // but we'll initialize them to prevent errors
    $stats['os'] = [];
    $stats['cities'] = [];
    $stats['statuses'] = [];
    
    return ['logs' => $logs, 'stats' => $stats];
}



// Process log data
$data = parseLogFile($config['log_file']);

// Reverse the log entries array to show newest entries first
$data['logs'] = array_reverse($data['logs']);
$log_entries = $data['logs'];

// Calculate statistics
$stats = [
    'total_visitors' => count($log_entries),
    'blocked_count' => 0,
    'suspicious_count' => 0,
    'clean_count' => 0,
    'countries' => [],
    'detection_flags' => [],
    'isps' => []
];

foreach ($log_entries as $entry) {
    // Count by threat level
    if (isset($entry['threat_level']) && $entry['threat_level'] === 'red') {
        $stats['blocked_count']++;
    } elseif (isset($entry['threat_level']) && $entry['threat_level'] === 'amber') {
        $stats['suspicious_count']++;
    } else {
        $stats['clean_count']++;
    }
    
    // Count by country
    $countryCode = isset($entry['country']) ? $entry['country'] : 'unknown';
    if (!isset($stats['countries'][$countryCode])) {
        $stats['countries'][$countryCode] = 0;
    }
    $stats['countries'][$countryCode]++;
    
    // Count by ISP
    $isp = isset($entry['isp']) ? $entry['isp'] : 'unknown';
    if (!isset($stats['isps'][$isp])) {
        $stats['isps'][$isp] = 0;
    }
    $stats['isps'][$isp]++;
    
    // Count detection flags
    $flagsStr = isset($entry['flags']) ? $entry['flags'] : '';
    $flags = !empty($flagsStr) ? explode(',', $flagsStr) : [];
    foreach ($flags as $flag) {
        if ($flag === 'none') continue;
        
        if (!isset($stats['detection_flags'][$flag])) {
            $stats['detection_flags'][$flag] = 0;
        }
        $stats['detection_flags'][$flag]++;
    }
}

// Sort countries by count
arsort($stats['countries']);

// Sort detection flags by count
arsort($stats['detection_flags']);
?>

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Visitor Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Threat level colors */
        .threat-red { background-color: rgba(255, 0, 0, 0.1); }
        .threat-amber { background-color: rgba(255, 191, 0, 0.1); }
        .threat-green { background-color: rgba(0, 255, 0, 0.1); }
        
        /* Table styling */
        .table-container {
            max-width: 100%;
            margin: 0 auto;
        }
        
        .table {
            table-layout: fixed;
            width: 100%;
            font-size: 0.85rem;
        }
        
        .table th {
            position: sticky;
            top: 0;
            background-color: #f8f9fa;
            z-index: 1;
            font-size: 0.9rem;
            padding: 8px 4px;
        }
        
        .table td {
            padding: 6px 4px;
            vertical-align: middle;
        }
        
        /* Column widths - optimized for no horizontal scroll */
        .col-time { width: 12%; /* Increased width for full timestamp */ }
        .col-ip { width: 8%; }
        .col-country { width: 10%; }
        .col-city { width: 7%; }
        .col-timezone { width: 7%; }
        .col-status { width: 5%; }
        .col-reason { width: 8%; }
        .col-os { width: 5%; }
        .col-browser { width: 8%; }
        .col-requests { width: 4%; }
        .col-isp { width: 8%; }
        .col-org { width: 8%; }
        .col-flags { width: 10%; }
        .col-actions { width: 5%; }
        
        /* Text truncation */
        .truncate {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            display: block;
        }
        
        /* Country flag styling */
        .country-flag {
            width: 16px;
            height: 12px;
            margin-right: 5px;
            vertical-align: middle;
        }
        
        /* Stats cards */
        .stats-card {
            height: 100%;
        }
        
        /* Action buttons */
        .btn-action {
            padding: 2px 5px;
            font-size: 0.7rem;
        }
        
        /* Tabs for better organization */
        .nav-tabs .nav-link {
            font-weight: 500;
        }
        
        .tab-content {
            border-left: 1px solid #dee2e6;
            border-right: 1px solid #dee2e6;
            border-bottom: 1px solid #dee2e6;
            padding: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mb-4">Advanced Visitor Filtering Dashboard</h1>
        
        <!-- Stats Overview -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stats-card">
                    <div class="stats-number"><?php echo $stats['total_visitors']; ?></div>
                    <div>Total Visitors</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card threat-red">
                    <div class="stats-number"><?php echo $stats['blocked_count']; ?></div>
                    <div>Blocked Visitors</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card threat-amber">
                    <div class="stats-number"><?php echo $stats['suspicious_count']; ?></div>
                    <div>Suspicious Visitors</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card threat-green">
                    <div class="stats-number"><?php echo $stats['clean_count']; ?></div>
                    <div>Clean Visitors</div>
                </div>
            </div>
        </div>
        
        <!-- Simplified Country, ISP and Flag Statistics -->
        <div class="row">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">Top Countries</div>
                    <div class="card-body">
                        <ul class="list-group">
                            <?php 
                            $count = 0;
                            foreach ($stats['countries'] as $country => $visits) {
                                if ($count++ < 5) {
                                    echo "<li class='list-group-item d-flex justify-content-between align-items-center'>";
                                    // Add country flag using free API
                                    if ($country !== 'unknown' && strlen($country) === 2) {
                                        echo "<span><img src='https://flagcdn.com/16x12/" . strtolower($country) . ".png' class='country-flag' alt='" . htmlspecialchars($country) . " flag'> ";
                                        echo htmlspecialchars($country);
                                        echo "</span>";
                                    } else {
                                        echo htmlspecialchars($country);
                                    }
                                    echo "<span class='badge bg-primary rounded-pill'>{$visits}</span>";
                                    echo "</li>";
                                }
                            }
                            if (empty($stats['countries'])) {
                                echo "<li class='list-group-item'>No country data available</li>";
                            }
                            ?>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">Top ISPs</div>
                    <div class="card-body">
                        <ul class="list-group">
                            <?php 
                            $count = 0;
                            foreach ($stats['isps'] as $isp => $visits) {
                                if ($count++ < 5) {
                                    echo "<li class='list-group-item d-flex justify-content-between align-items-center'>";
                                    echo htmlspecialchars($isp);
                                    echo "<span class='badge bg-primary rounded-pill'>{$visits}</span>";
                                    echo "</li>";
                                }
                            }
                            if (empty($stats['isps'])) {
                                echo "<li class='list-group-item'>No ISP data available</li>";
                            }
                            ?>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">Top Detection Flags</div>
                    <div class="card-body">
                        <ul class="list-group">
                            <?php 
                            $count = 0;
                            foreach (($data['stats']['flags'] ?? []) as $flag => $occurrences) {
                                if ($count++ < 5) {
                                    echo "<li class='list-group-item d-flex justify-content-between align-items-center'>";
                                    echo htmlspecialchars($flag);
                                    echo "<span class='badge bg-primary rounded-pill'>{$occurrences}</span>";
                                    echo "</li>";
                                }
                            }
                            if (empty($data['stats']['flags'] ?? [])) {
                                echo "<li class='list-group-item'>No detection flags recorded</li>";
                            }
                            ?>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Visitor Log Table -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span>Visitor Logs</span>
                <form method="post" id="purgeForm" class="d-inline">
                    <input type="hidden" name="action" value="purge_logs">
                    <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to purge all logs?');">Purge Logs</button>
                </form>
            </div>
            <div class="card-body table-container">
                <table class="table table-striped table-hover table-sm">
                    <thead>
                        <tr>
                            <th class="col-time">Time</th>
                            <th class="col-ip">IP</th>
                            <th class="col-country">Country</th>
                            <th class="col-city">City</th>
                            <th class="col-timezone">Timezone</th>
                            <th class="col-status">Status</th>
                            <th class="col-reason">Block Reason</th>
                            <th class="col-os">OS</th>
                            <th class="col-browser">Browser</th>
                            <th class="col-isp">ISP</th>
                            <th class="col-org">Organization</th>
                            <th class="col-actions">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($data['logs'] as $log): ?>
                            <tr class="threat-<?php echo $log['threat_level'] ?? 'green'; ?>">
                                <td><span class="truncate"><?php echo htmlspecialchars($log['time'] ?? ''); ?></span></td>
                                <td><span class="truncate"><?php echo htmlspecialchars($log['ip'] ?? ''); ?></span></td>
                                <td title="<?php echo htmlspecialchars($log['country_name'] ?? ''); ?>">
                                    <?php if (($log['country'] ?? '') !== 'unknown' && strlen($log['country'] ?? '') === 2): ?>
                                        <img src="https://flagcdn.com/16x12/<?php echo strtolower(htmlspecialchars($log['country'])); ?>.png" 
                                             class="country-flag" alt="<?php echo htmlspecialchars($log['country']); ?> flag">
                                    <?php endif; ?>
                                    <span class="truncate"><?php echo htmlspecialchars($log['country_name'] ?? ''); ?> (<?php echo htmlspecialchars($log['country'] ?? ''); ?>)</span>
                                </td>
                                <td><span class="truncate"><?php echo htmlspecialchars($log['city'] ?? ''); ?></span></td>
                                <td><span class="truncate"><?php echo htmlspecialchars($log['timezone'] ?? ''); ?></span></td>
                                <td>
                                    <span class="badge bg-<?php echo ($log['status'] ?? '') === 'clean' ? 'success' : 'danger'; ?>">
                                        <?php echo htmlspecialchars($log['status'] ?? 'unknown'); ?>
                                    </span>
                                </td>
                                <td><span class="truncate"><?php echo htmlspecialchars($log['block_reason'] ?? ''); ?></span></td>
                                <td><span class="truncate"><?php echo htmlspecialchars($log['os'] ?? ''); ?></span></td>
                                <td><span class="truncate"><?php echo htmlspecialchars($log['browser'] ?? ''); ?> <?php echo htmlspecialchars($log['version'] ?? ''); ?></span></td>
                                <td><span class="truncate" title="<?php echo htmlspecialchars($log['isp'] ?? ''); ?>"><?php echo htmlspecialchars($log['isp'] ?? ''); ?></span></td>
                                <td><span class="truncate" title="<?php echo htmlspecialchars($log['org'] ?? ''); ?>"><?php echo htmlspecialchars($log['org'] ?? ''); ?></span></td>
                                <td>
                                    <!-- Actions column - empty now that block/unblock functionality has been removed -->
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($data['logs'])): ?>
                            <tr>
                                <td colspan="13" class="text-center">No visitor logs available</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- Simple Purge Form -->
    <div class="text-center mt-4 mb-4">
        <form method="post" onsubmit="return confirm('Are you sure you want to purge all logs?')">
            <input type="hidden" name="action" value="purge_logs">
            <button type="submit" class="btn btn-danger">Purge All Logs</button>
        </form>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
