<?php
/**
 * ASWA_DVWA_XSS_SQLi_No_Email.php
 * ------------------------------------------------------------
 * Application-side security layer for an authorized DVWA lab.
 *
 * Purpose:
 *   - Detect and block reflected/stored XSS submission attempts.
 *   - Detect and block SQL Injection attempts.
 *   - Add a restrictive Content-Security-Policy to reduce execution
 *     of reflected or previously stored script payloads.
 *   - Write structured JSON-line logs.
 *
 * Recommended loading method:
 *   php.ini / Apache vhost / .htaccess:
 *   auto_prepend_file=/absolute/path/ASWA_DVWA_XSS_SQLi_No_Email.php
 *
 * Important:
 *   This file is a compensating protection layer. It does not replace:
 *   1) Prepared statements for SQL queries.
 *   2) Context-aware output encoding for XSS.
 *   3) Proper validation and authorization inside the application.
 *
 * Compatibility:
 *   Written without modern PHP-only syntax so it can run on older
 *   PHP versions commonly found in Metasploitable/DVWA labs.
 */

/* Prevent accidental double loading. */
if (defined('ASWA_AGENT_LOADED')) {
    return;
}
define('ASWA_AGENT_LOADED', true);

/* ============================================================
   1) Configuration
   ============================================================ */

/* block = log and return 403, log = log only */
$ASWA_MODE = 'block';

/* Protect only DVWA. Use '/' to protect the entire PHP site. */
$ASWA_SCOPE_PREFIX = '/dvwa';

/* Structured event log. */
$ASWA_LOG_FILE = '/tmp/dvwa_web_security.log';

/* Resource limits. */
$ASWA_MAX_VALUE_LENGTH = 16000;
$ASWA_MAX_RAW_BODY_LENGTH = 30000;
$ASWA_MAX_COMBINED_LENGTH = 50000;

/* Request sources to inspect. */
$ASWA_SCAN_COOKIES = true;
$ASWA_SCAN_HEADERS = true;
$ASWA_SCAN_RAW_BODY = true;

/* Detection thresholds. */
$ASWA_THRESHOLDS = array(
    'XSS' => 10,
    'SQL Injection' => 10
);

/*
 * CSP is important for stored XSS because the malicious value may have
 * been saved earlier and can be returned in a later, otherwise clean request.
 *
 * This strict policy blocks inline <script>, inline event handlers such as
 * onerror=, javascript: URLs, plugins, and framing by other origins.
 * Some intentionally vulnerable DVWA features or inline scripts may stop
 * working. Disable only while diagnosing compatibility issues.
 */
$ASWA_ENABLE_CSP = true;
$ASWA_CSP_POLICY = "default-src 'self'; " .
                   "script-src 'self'; " .
                   "object-src 'none'; " .
                   "base-uri 'self'; " .
                   "frame-ancestors 'self'; " .
                   "form-action 'self'; " .
                   "img-src 'self' data:; " .
                   "style-src 'self' 'unsafe-inline'; " .
                   "connect-src 'self'";

/* ============================================================
   2) Scope and request helpers
   ============================================================ */

function aswa_get_request_uri() {
    return isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
}

function aswa_is_in_scope($prefix) {
    $uri = aswa_get_request_uri();
    $path = parse_url($uri, PHP_URL_PATH);

    if ($path === false || $path === null) {
        $path = $uri;
    }

    if ($prefix === '' || $prefix === '/') {
        return true;
    }

    $prefix = rtrim($prefix, '/');

    return ($path === $prefix || strpos($path, $prefix . '/') === 0);
}

/* Do not run request blocking logic from CLI test commands. */
if (php_sapi_name() !== 'cli' && !aswa_is_in_scope($ASWA_SCOPE_PREFIX)) {
    return;
}

/* ============================================================
   3) Safe utility functions
   ============================================================ */

function aswa_safe_substr($value, $length) {
    if (is_array($value)) {
        $value = implode(' ', $value);
    }

    if (!is_string($value)) {
        $value = strval($value);
    }

    if (strlen($value) > $length) {
        return substr($value, 0, $length);
    }

    return $value;
}

function aswa_unicode_percent_callback($match) {
    $code = hexdec($match[1]);

    /* Convert only the ASCII range; replace other values safely. */
    if ($code >= 32 && $code <= 126) {
        return chr($code);
    }

    return ' ';
}

function aswa_flatten_input($name, $value, &$output, $max_length) {
    if (is_array($value)) {
        foreach ($value as $key => $child) {
            aswa_flatten_input($name . '[' . $key . ']', $child, $output, $max_length);
        }
        return;
    }

    $output[] = array(
        'name' => $name,
        'value' => aswa_safe_substr($value, $max_length)
    );
}

function aswa_collect_inputs($max_value_length, $max_raw_body_length, $max_combined_length) {
    global $ASWA_SCAN_COOKIES, $ASWA_SCAN_HEADERS, $ASWA_SCAN_RAW_BODY;

    $items = array();

    $items[] = array('name' => 'REQUEST_URI', 'value' => aswa_get_request_uri());

    if (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING'] !== '') {
        $items[] = array('name' => 'QUERY_STRING', 'value' => $_SERVER['QUERY_STRING']);
    }

    foreach ($_GET as $key => $value) {
        aswa_flatten_input('GET.' . $key, $value, $items, $max_value_length);
    }

    foreach ($_POST as $key => $value) {
        aswa_flatten_input('POST.' . $key, $value, $items, $max_value_length);
    }

    if ($ASWA_SCAN_COOKIES) {
        foreach ($_COOKIE as $key => $value) {
            aswa_flatten_input('COOKIE.' . $key, $value, $items, $max_value_length);
        }
    }

    if ($ASWA_SCAN_HEADERS) {
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0 || $key === 'CONTENT_TYPE') {
                aswa_flatten_input('HEADER.' . $key, $value, $items, $max_value_length);
            }
        }
    }

    if ($ASWA_SCAN_RAW_BODY) {
        $raw = @file_get_contents('php://input');

        if ($raw !== false && $raw !== '') {
            $items[] = array(
                'name' => 'RAW_BODY',
                'value' => aswa_safe_substr($raw, $max_raw_body_length)
            );
        }
    }

    /* Detect payloads split across multiple parameters. */
    $combined = '';
    foreach ($items as $item) {
        $combined .= ' ' . $item['value'];
        if (strlen($combined) >= $max_combined_length) {
            break;
        }
    }

    if ($combined !== '') {
        $items[] = array(
            'name' => 'COMBINED_REQUEST',
            'value' => aswa_safe_substr($combined, $max_combined_length)
        );
    }

    return $items;
}

/*
 * Canonicalization returns multiple normalized forms:
 *   text       : readable normalized value.
 *   sql_joined : SQL comments removed without spaces, catching comment-split SQL keywords.
 *   compact    : whitespace removed, catching simple split/spacing evasions.
 */
function aswa_canonicalize($value, $max_length) {
    $value = aswa_safe_substr($value, $max_length);

    for ($i = 0; $i < 4; $i++) {
        $previous = $value;
        $value = rawurldecode($value);
        $value = urldecode($value);
        $value = html_entity_decode($value, ENT_QUOTES, 'UTF-8');
        $value = preg_replace_callback('/%u([0-9a-fA-F]{4})/', 'aswa_unicode_percent_callback', $value);

        if ($value === $previous) {
            break;
        }
    }

    $value = str_replace("\0", ' ', $value);
    $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/', ' ', $value);
    $value = strtolower($value);

    /* Keep a copy where SQL block comments disappear without introducing gaps. */
    $sql_joined = preg_replace('/\/\*![0-9]*\s*(.*?)\*\//s', '$1', $value);
    $sql_joined = preg_replace('/\/\*.*?\*\//s', '', $sql_joined);

    /* Readable form uses spaces where comments existed. */
    $text = preg_replace('/\/\*![0-9]*\s*(.*?)\*\//s', ' $1 ', $value);
    $text = preg_replace('/\/\*.*?\*\//s', ' ', $text);
    $text = preg_replace('/\s+/', ' ', $text);
    $text = trim($text);

    $sql_joined = preg_replace('/\s+/', ' ', $sql_joined);
    $sql_joined = trim($sql_joined);

    $compact = preg_replace('/\s+/', '', $sql_joined);

    return array(
        'text' => $text,
        'sql_joined' => $sql_joined,
        'compact' => $compact
    );
}

function aswa_json_encode_safe($data) {
    if (function_exists('json_encode')) {
        return json_encode($data);
    }

    $parts = array();

    foreach ($data as $key => $value) {
        if (is_array($value)) {
            $value = implode('|', $value);
        }
        $parts[] = '"' . addslashes($key) . '":"' . addslashes(strval($value)) . '"';
    }

    return '{' . implode(',', $parts) . '}';
}

/* Safe output helper for use inside application templates. */
function aswa_escape_html($value) {
    return htmlspecialchars(strval($value), ENT_QUOTES, 'UTF-8');
}

/* ============================================================
   4) Security response headers
   ============================================================ */

function aswa_add_security_headers() {
    global $ASWA_ENABLE_CSP, $ASWA_CSP_POLICY;

    if (headers_sent()) {
        return;
    }

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

    if ($ASWA_ENABLE_CSP) {
        header('Content-Security-Policy: ' . $ASWA_CSP_POLICY);
    }

    /* Avoid advertising implementation details with a custom agent header. */
}

/* ============================================================
   5) Detection rules
   Each rule: label, regex, weight, normalized variant
   ============================================================ */

$ASWA_RULES = array(
    'XSS' => array(
        array('script element', '/<\s*\/?\s*script\b/i', 15, 'text'),
        array('inline event handler', '/\bon[a-z]{3,40}\s*=\s*/i', 12, 'text'),
        array('javascript URI scheme', '/(?:^|[\s\"\'=:])javascript\s*:/i', 13, 'text'),
        array('vbscript URI scheme', '/(?:^|[\s\"\'=:])vbscript\s*:/i', 13, 'text'),
        array('HTML data URI', '/data\s*:\s*text\/(?:html|javascript)/i', 12, 'text'),
        array('dangerous active HTML element', '/<\s*(?:iframe|object|embed|svg|math|base|meta)\b/i', 10, 'text'),
        array('image or media element with scriptable attributes', '/<\s*(?:img|video|audio|source|body)\b[^>]*(?:on[a-z]+\s*=|javascript\s*:)/i', 14, 'text'),
        array('srcdoc attribute', '/\bsrcdoc\s*=/i', 11, 'text'),
        array('browser execution primitive', '/\b(?:alert|confirm|prompt|eval|settimeout|setinterval|function)\s*\(/i', 7, 'text'),
        array('DOM cookie or location access', '/\b(?:document\s*\.\s*cookie|document\s*\.\s*domain|window\s*\.\s*location|location\s*=)/i', 9, 'text'),
        array('HTML tag encoded in request', '/(?:%3c|&#x?0*3c;?)/i', 7, 'text'),
        array('template-expression script pattern', '/(?:\{\{|\$\{).{0,80}(?:constructor|alert|document|window)/i', 7, 'text'),
        array('CSS script execution pattern', '/expression\s*\(|url\s*\(\s*[\"\']?javascript\s*:/i', 11, 'text')
    ),

    'SQL Injection' => array(
        array('UNION SELECT statement', '/\bunion\s+(?:all\s+)?select\b/i', 15, 'sql_joined'),
        array('comment-obfuscated UNION SELECT', '/union(?:all)?select/i', 15, 'compact'),
        array('quote followed by boolean operator', '/[\'\"]\s*(?:or|and)\s+(?:[\'\"]?[^\s\'\"]+[\'\"]?\s*=\s*[\'\"]?[^\s\'\"]+[\'\"]?|\d+\s*=\s*\d+)/i', 12, 'text'),
        array('tautology expression', '/\b(?:or|and)\b\s+(?:\d+\s*=\s*\d+|[\'\"][^\'\"]*[\'\"]\s*=\s*[\'\"][^\'\"]*[\'\"])/i', 10, 'text'),
        array('SELECT FROM statement', '/\bselect\b.{0,180}\bfrom\b/i', 10, 'sql_joined'),
        array('database metadata enumeration', '/\b(?:information_schema|mysql\s*\.\s*user|pg_catalog|sqlite_master)\b/i', 13, 'text'),
        array('time-based SQL injection', '/\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(?/i', 13, 'text'),
        array('error-based SQL injection', '/\b(?:updatexml|extractvalue|xmltype)\s*\(/i', 12, 'text'),
        array('database file or command function', '/\b(?:load_file|into\s+outfile|into\s+dumpfile|xp_cmdshell)\b/i', 14, 'text'),
        array('stacked SQL statement', '/;\s*(?:select|insert|update|delete|drop|alter|create|truncate|grant|revoke)\b/i', 13, 'text'),
        array('destructive SQL operation', '/\b(?:drop|alter|truncate)\s+(?:table|database|schema)\b/i', 13, 'text'),
        array('SQL comment after suspicious syntax', '/(?:[\'\"]|\b(?:union|select|or|and)\b).{0,100}(?:--\s|#)/i', 6, 'text'),
        array('SQL concatenation or enumeration function', '/\b(?:concat|group_concat|string_agg)\s*\(/i', 6, 'text'),
        array('hex or character obfuscation near SQL', '/\b(?:char|chr|unhex|hex)\s*\([^)]{1,100}\).{0,80}\b(?:union|select|or|and)\b/i', 8, 'text')
    )
);

function aswa_scan_value($normalized, $rules, $thresholds) {
    $best = null;

    foreach ($rules as $attack_type => $rule_list) {
        $score = 0;
        $matched = array();

        foreach ($rule_list as $rule) {
            $label = $rule[0];
            $pattern = $rule[1];
            $weight = $rule[2];
            $variant = $rule[3];

            $subject = isset($normalized[$variant]) ? $normalized[$variant] : $normalized['text'];
            $result = @preg_match($pattern, $subject);

            if ($result === 1) {
                $score += $weight;
                $matched[] = $label;
            }
        }

        if (count($matched) > 0) {
            $threshold = isset($thresholds[$attack_type]) ? $thresholds[$attack_type] : 10;

            if ($best === null || $score > $best['score']) {
                $best = array(
                    'attack_type' => $attack_type,
                    'score' => $score,
                    'threshold' => $threshold,
                    'matched' => $matched
                );
            }
        }
    }

    return $best;
}

/* ============================================================
   6) Logging and blocking
   ============================================================ */

function aswa_request_id() {
    if (function_exists('openssl_random_pseudo_bytes')) {
        $bytes = @openssl_random_pseudo_bytes(8);
        if ($bytes !== false) {
            return bin2hex($bytes);
        }
    }

    return substr(md5(uniqid('', true)), 0, 16);
}

function aswa_log_event($log_file, $request_id, $decision, $finding, $input_name, $sample) {
    $entry = array(
        'time_utc' => gmdate('Y-m-d\TH:i:s\Z'),
        'request_id' => $request_id,
        'decision' => $decision,
        'attack_type' => $finding['attack_type'],
        'score' => $finding['score'],
        'threshold' => $finding['threshold'],
        'source_ip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown',
        'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'unknown',
        'uri' => aswa_get_request_uri(),
        'input' => $input_name,
        'matched_rules' => implode(', ', $finding['matched']),
        'sample' => aswa_safe_substr($sample, 500),
        'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? aswa_safe_substr($_SERVER['HTTP_USER_AGENT'], 220) : ''
    );

    @file_put_contents(
        $log_file,
        aswa_json_encode_safe($entry) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

function aswa_block_request($request_id, $finding) {
    if (!headers_sent()) {
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/html; charset=UTF-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
    }

    $type = htmlspecialchars($finding['attack_type'], ENT_QUOTES, 'UTF-8');
    $rules = htmlspecialchars(implode(', ', $finding['matched']), ENT_QUOTES, 'UTF-8');
    $id = htmlspecialchars($request_id, ENT_QUOTES, 'UTF-8');
    $score = intval($finding['score']);

    echo '<!doctype html>';
    echo '<html><head><meta charset="UTF-8"><title>403 - Request Blocked</title>';
    echo '<style>';
    echo 'body{margin:0;background:#f3f5f7;font-family:Arial,sans-serif;color:#20252b;}';
    echo '.card{max-width:760px;margin:70px auto;background:#fff;padding:30px;border-left:7px solid #b00020;box-shadow:0 4px 18px rgba(0,0,0,.12);}';
    echo 'h1{margin-top:0;color:#b00020;}code{background:#eef0f2;padding:3px 7px;border-radius:4px;word-break:break-word;}';
    echo '</style></head><body><div class="card">';
    echo '<h1>403 - Request Blocked</h1>';
    echo '<p>The request was rejected before it reached the vulnerable application.</p>';
    echo '<p><strong>Detected category:</strong> ' . $type . '</p>';
    echo '<p><strong>Risk score:</strong> ' . $score . '</p>';
    echo '<p><strong>Matched rules:</strong> <code>' . $rules . '</code></p>';
    echo '<p><strong>Request ID:</strong> <code>' . $id . '</code></p>';
    echo '<p>This protection is intended for an authorized DVWA laboratory.</p>';
    echo '</div></body></html>';
    exit;
}

/* ============================================================
   7) Main execution
   ============================================================ */

if (php_sapi_name() !== 'cli') {
    aswa_add_security_headers();

    /* Improve session cookie defaults before the application starts a session. */
    @ini_set('session.cookie_httponly', '1');
    @ini_set('session.use_only_cookies', '1');

    $inputs = aswa_collect_inputs(
        $ASWA_MAX_VALUE_LENGTH,
        $ASWA_MAX_RAW_BODY_LENGTH,
        $ASWA_MAX_COMBINED_LENGTH
    );

    foreach ($inputs as $item) {
        $normalized = aswa_canonicalize($item['value'], $ASWA_MAX_VALUE_LENGTH);

        if ($normalized['text'] === '') {
            continue;
        }

        $finding = aswa_scan_value($normalized, $ASWA_RULES, $ASWA_THRESHOLDS);

        if ($finding !== null && $finding['score'] >= $finding['threshold']) {
            $request_id = aswa_request_id();
            $decision = ($ASWA_MODE === 'block') ? 'blocked' : 'logged_only';

            aswa_log_event(
                $ASWA_LOG_FILE,
                $request_id,
                $decision,
                $finding,
                $item['name'],
                $normalized['text']
            );

            if ($ASWA_MODE === 'block') {
                aswa_block_request($request_id, $finding);
            }
        }
    }
}

return;
?>
