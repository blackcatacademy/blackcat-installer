<?php

declare(strict_types=1);

/**
 * BlackCat Hosting Preflight (single-file, no Composer).
 *
 * Upload this file to the target hosting and open it in a browser to determine
 * whether a Stage 3 “kernel minimal bundle” install is feasible.
 *
 * SECURITY NOTE:
 * - This page reveals environment details (versions/extensions). Delete it after use.
 * - No user-controlled URLs are fetched (SSRF-safe by design).
 */

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
// Default CSP is script-less. `?probe=pathinfo` enables a minimal inline script to run same-origin fetches.
$probe = $_GET['probe'] ?? null;
$allowInlineScript = is_string($probe) && strtolower(trim($probe)) === 'pathinfo';
$csp = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
if ($allowInlineScript) {
    $csp .= "; script-src 'unsafe-inline'; connect-src 'self'";
}
header('Content-Security-Policy: ' . $csp);

/**
 * Kernel-minimal bundle currently depends on blackcat-config, which requires PHP 8.3+.
 * Keep this in sync with `blackcat-config/composer.json`.
 */
const BLACKCAT_PREFLIGHT_MIN_PHP = 80300; // 8.3.0

/**
 * The default chain used in the demo/docs is Edgen (chain_id=4207).
 * Keep this list small to avoid accidental rate limits.
 *
 * @var list<string>
 */
const BLACKCAT_PREFLIGHT_RPC_URLS = [
    'https://rpc.layeredge.io',
];

/**
 * @return array{policy:'strict'|'warn',value:string}
 */
function blackcat_preflight_policy(): array
{
    $raw = $_GET['policy'] ?? null;
    if (is_string($raw)) {
        $v = strtolower(trim($raw));
        if ($v === 'warn' || $v === 'dev') {
            return ['policy' => 'warn', 'value' => $v];
        }
        if ($v === 'strict' || $v === 'prod') {
            return ['policy' => 'strict', 'value' => $v];
        }
    }
    return ['policy' => 'strict', 'value' => 'strict'];
}

/**
 * @return 'pathinfo'|null
 */
function blackcat_preflight_probe(): ?string
{
    $raw = $_GET['probe'] ?? null;
    if (!is_string($raw)) {
        return null;
    }
    $v = strtolower(trim($raw));
    return $v === 'pathinfo' ? 'pathinfo' : null;
}

function blackcat_preflight_probe_deep(): bool
{
    $raw = $_GET['deep'] ?? null;
    if (!is_string($raw)) {
        return false;
    }
    $v = strtolower(trim($raw));
    return $v === '1' || $v === 'true' || $v === 'yes';
}

function blackcat_preflight_random_id(): string
{
    try {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes(8));
        }
    } catch (\Throwable $e) {
        // ignore
    }
    return substr(hash('sha256', (string) microtime(true) . '-' . (string) getmypid()), 0, 16);
}

/**
 * @return string
 */
function blackcat_preflight_script_dir_url_path(): string
{
    $script = $_SERVER['SCRIPT_NAME'] ?? null;
    if (!is_string($script) || $script === '' || str_contains($script, "\0")) {
        return '/';
    }

    $dir = str_replace('\\', '/', dirname($script));
    if ($dir === '.' || $dir === '') {
        return '/';
    }
    if ($dir[0] !== '/') {
        $dir = '/' . $dir;
    }
    return rtrim($dir, '/') . '/';
}

/**
 * @return string
 */
function blackcat_preflight_request_dir_url_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? null;
    if (!is_string($uri) || $uri === '' || str_contains($uri, "\0")) {
        return '/';
    }

    $path = parse_url($uri, PHP_URL_PATH);
    if (!is_string($path) || $path === '' || str_contains($path, "\0")) {
        return '/';
    }

    $dir = str_replace('\\', '/', dirname($path));
    if ($dir === '.' || $dir === '') {
        return '/';
    }
    if ($dir[0] !== '/') {
        $dir = '/' . $dir;
    }
    return rtrim($dir, '/') . '/';
}

/**
 * @return string
 */
function blackcat_preflight_request_url_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? null;
    if (!is_string($uri) || $uri === '' || str_contains($uri, "\0")) {
        return '/';
    }

    $path = parse_url($uri, PHP_URL_PATH);
    if (!is_string($path) || $path === '' || str_contains($path, "\0")) {
        return '/';
    }
    if ($path[0] !== '/') {
        $path = '/' . $path;
    }
    return $path;
}

/**
 * @return string|null
 */
function blackcat_preflight_request_origin(): ?string
{
    $host = $_SERVER['HTTP_HOST'] ?? null;
    if (!is_string($host) || $host === '' || str_contains($host, "\0")) {
        $host = $_SERVER['SERVER_NAME'] ?? null;
    }
    if (!is_string($host) || $host === '' || str_contains($host, "\0")) {
        return null;
    }
    // Allow host[:port] with sane characters only.
    if (!preg_match('/^[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?$/i', $host)) {
        return null;
    }

    $scheme = null;
    $https = $_SERVER['HTTPS'] ?? null;
    if (is_string($https) && $https !== '' && strtolower($https) !== 'off') {
        $scheme = 'https';
    }
    $requestScheme = $_SERVER['REQUEST_SCHEME'] ?? null;
    if ($scheme === null && is_string($requestScheme) && ($requestScheme === 'http' || $requestScheme === 'https')) {
        $scheme = $requestScheme;
    }
    if ($scheme === null) {
        $scheme = 'http';
    }

    return $scheme . '://' . $host;
}

/**
 * @param string $relative
 * @return string|null
 */
function blackcat_preflight_absolute_url(string $relative): ?string
{
    $origin = blackcat_preflight_request_origin();
    if ($origin === null) {
        return null;
    }
    if ($relative !== '' && $relative[0] === '?') {
        return $origin . blackcat_preflight_request_url_path() . $relative;
    }
    $dir = blackcat_preflight_request_dir_url_path();
    $rel = ltrim($relative, '/');
    return $origin . $dir . $rel;
}

/**
 * @return array{id:string, filename:string, file_path:string, url_path:string, expected:string, marker:string}
 */
function blackcat_preflight_prepare_pathinfo_probe(): array
{
    $id = blackcat_preflight_random_id();
    $filename = 'blackcat-pathinfo-probe.' . $id . '.txt';
    $filePath = __DIR__ . DIRECTORY_SEPARATOR . $filename;
    // Use a relative URL for probes: some hostings populate SCRIPT_NAME with a filesystem-like path.
    // The browser will resolve this relative to the currently opened preflight URL.
    $urlPath = $filename;
    $expected = 'BLACKCAT_PATHINFO_PROBE_' . $id;
    $marker = 'BLACKCAT_PATHINFO_PROBE_FILE_' . $id;

    // Avoid embedding the expected output string verbatim in the source file.
    $php = "<?php /* " . $marker . " */ echo 'BLACKCAT_PATHINFO_' . 'PROBE_' . '" . $id . "'; ?>\n";
    @file_put_contents($filePath, $php, LOCK_EX);

    return [
        'id' => $id,
        'filename' => $filename,
        'file_path' => $filePath,
        'url_path' => $urlPath,
        'expected' => $expected,
        'marker' => $marker,
    ];
}

/**
 * @return array{ok:bool, error?:string}
 */
function blackcat_preflight_cleanup_pathinfo_probe(): array
{
    $probe = blackcat_preflight_probe();
    if ($probe !== 'pathinfo') {
        return ['ok' => false, 'error' => 'probe not enabled'];
    }

    $token = $_GET['token'] ?? null;
    $file = $_GET['file'] ?? null;
    if (!is_string($token) || $token === '' || !preg_match('/^[a-f0-9]{16}$/', $token)) {
        return ['ok' => false, 'error' => 'invalid token'];
    }
    if (!is_string($file) || $file === '' || str_contains($file, "\0")) {
        return ['ok' => false, 'error' => 'invalid file'];
    }

    $expectedName = 'blackcat-pathinfo-probe.' . $token . '.txt';
    if (!hash_equals($expectedName, $file)) {
        return ['ok' => false, 'error' => 'file mismatch'];
    }

    $path = __DIR__ . DIRECTORY_SEPARATOR . $file;
    if (is_file($path)) {
        @unlink($path);
    }

    return ['ok' => true];
}

/**
 * @return array{ok:bool, code?:string, details?:string, hints?:list<string>}
 */
function blackcat_preflight_check_php_version(): array
{
    if (PHP_VERSION_ID < BLACKCAT_PREFLIGHT_MIN_PHP) {
        return [
            'ok' => false,
            'code' => 'php_version_too_low',
            'details' => 'Detected PHP ' . PHP_VERSION . '. Kernel-minimal bundle requires PHP 8.3+ (blackcat-config).',
            'hints' => [
                'Switch the hosting to PHP 8.3+ (often a control-panel setting).',
                'If the hosting cannot run PHP 8.3, use a different hosting/VPS for BlackCat.',
            ],
        ];
    }

    return [
        'ok' => true,
        'details' => 'PHP ' . PHP_VERSION,
    ];
}

/**
 * @return bool
 */
function blackcat_preflight_ini_flag(string $name): bool
{
    $raw = ini_get($name);
    if ($raw === false) {
        return false;
    }
    $value = strtolower(trim((string) $raw));
    if ($value === '' || $value === '0' || $value === 'off' || $value === 'false' || $value === 'no') {
        return false;
    }
    return true;
}

/**
 * @return list<string>
 */
function blackcat_preflight_disabled_functions(): array
{
    $raw = ini_get('disable_functions');
    if (!is_string($raw) || trim($raw) === '') {
        return [];
    }
    $parts = array_map('trim', explode(',', $raw));
    $out = [];
    foreach ($parts as $part) {
        if ($part !== '') {
            $out[] = strtolower($part);
        }
    }
    return array_values(array_unique($out));
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_required_extensions(): array
{
    $missing = [];
    foreach (['json', 'sodium', 'pdo'] as $ext) {
        if (!extension_loaded($ext)) {
            $missing[] = $ext;
        }
    }

    if ($missing !== []) {
        return [
            'ok' => false,
            'code' => 'missing_extensions',
            'details' => 'Missing required PHP extensions: ' . implode(', ', array_map(static fn (string $e): string => "ext-{$e}", $missing)),
            'hints' => [
                'Enable the missing extensions in your hosting control panel (or ask your provider).',
                'BlackCat crypto uses libsodium (ext-sodium) by default.',
            ],
        ];
    }

    return [
        'ok' => true,
        'details' => 'ext-json, ext-sodium, ext-pdo: OK',
    ];
}

/**
 * @return bool
 */
function blackcat_preflight_curl_supports_ssl(): bool
{
    if (!function_exists('curl_version')) {
        return false;
    }
    /** @var array<string,mixed> $v */
    $v = curl_version();
    $features = $v['features'] ?? 0;
    if (!is_int($features)) {
        return false;
    }
    return defined('CURL_VERSION_SSL') && (($features & CURL_VERSION_SSL) === CURL_VERSION_SSL);
}

/**
 * TLS verification is required for secure setup flows.
 *
 * Note: BlackCat crypto uses libsodium, but TLS/PKI verification is a separate concern.
 *
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_tls_verify_capability(): array
{
    $hasOpenssl = extension_loaded('openssl');
    $hasCurl = function_exists('curl_init') && blackcat_preflight_curl_supports_ssl();

    if ($hasOpenssl && $hasCurl) {
        return ['ok' => true, 'details' => 'TLS verification: OpenSSL + cURL(SSL) available'];
    }
    if ($hasOpenssl) {
        return ['ok' => true, 'details' => 'TLS verification: OpenSSL available'];
    }
    if ($hasCurl) {
        return ['ok' => true, 'details' => 'TLS verification: cURL(SSL) available'];
    }

    return [
        'ok' => false,
        'code' => 'tls_verify_unavailable',
        'details' => 'No server-side TLS verification capability detected (missing ext-openssl and cURL SSL support).',
        'hints' => [
            'Enable OpenSSL or cURL with SSL in your hosting (common names: ext-openssl, ext-curl).',
            'If your hosting cannot provide TLS verification, do not run the web setup there. Use the offline preparation flow and upload prepared artifacts via FTP.',
        ],
    ];
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_web3_transport_capability(): array
{
    $hasCurl = function_exists('curl_init') && blackcat_preflight_curl_supports_ssl();
    if ($hasCurl) {
        return [
            'ok' => true,
            'details' => 'Web3 transport: cURL(SSL) available',
        ];
    }

    $hasOpenssl = extension_loaded('openssl');
    $allowUrlFopen = blackcat_preflight_ini_flag('allow_url_fopen');
    if ($hasOpenssl && $allowUrlFopen) {
        return [
            'ok' => true,
            'details' => 'Web3 transport: HTTPS stream wrapper available (OpenSSL + allow_url_fopen)',
        ];
    }

    $hints = [];
    if (!$hasOpenssl) {
        $hints[] = 'Enable OpenSSL or enable cURL (with SSL).';
    }
    if (!$allowUrlFopen) {
        $hints[] = 'Enable allow_url_fopen or enable cURL (with SSL).';
    }

    return [
        'ok' => false,
        'code' => 'web3_transport_unavailable',
        'details' => 'Cannot establish an outbound HTTPS client for RPC (no cURL SSL; and HTTPS streams are unavailable).',
        'hints' => $hints !== [] ? $hints : ['Enable cURL(SSL) or OpenSSL + allow_url_fopen.'],
    ];
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_basic_hardening(): array
{
    $policy = blackcat_preflight_policy()['policy'];
    $fails = [];
    $warns = [];
    $info = [];

    if (blackcat_preflight_ini_flag('allow_url_include')) {
        $fails[] = 'allow_url_include is enabled (unsafe).';
    }

    $displayErrors = blackcat_preflight_ini_flag('display_errors');
    $displayStartupErrors = blackcat_preflight_ini_flag('display_startup_errors');
    if ($displayErrors || $displayStartupErrors) {
        // Best-effort: detect whether the runtime can override this (ini_set) like HttpKernel does.
        $canOverride = false;
        if (function_exists('ini_set')) {
            @ini_set('display_errors', '0');
            @ini_set('display_startup_errors', '0');
            $afterErrors = blackcat_preflight_ini_flag('display_errors');
            $afterStartup = blackcat_preflight_ini_flag('display_startup_errors');
            $canOverride = !$afterErrors && !$afterStartup;
        }

        if ($policy === 'strict' && !$canOverride) {
            $fails[] = 'display_errors/display_startup_errors is enabled (information disclosure).';
        } else {
            $warns[] = 'display_errors/display_startup_errors is enabled (information disclosure).'
                . ($canOverride ? ' Note: it appears overrideable at runtime (ini_set), but production should still disable it in hosting settings.' : '');
        }
    }

    $pharReadonly = ini_get('phar.readonly');
    if (is_string($pharReadonly) && trim($pharReadonly) !== '' && trim($pharReadonly) !== '1') {
        if ($policy === 'strict') {
            $fails[] = 'phar.readonly is disabled (PHAR deserialization risk).';
        } else {
            $warns[] = 'phar.readonly is disabled (PHAR deserialization risk).';
        }
    }

    if (blackcat_preflight_ini_flag('enable_dl')) {
        if ($policy === 'strict') {
            $fails[] = 'enable_dl is enabled (runtime extension loading increases attack surface).';
        } else {
            $warns[] = 'enable_dl is enabled (runtime extension loading increases attack surface).';
        }
    }

    $autoPrepend = ini_get('auto_prepend_file');
    if (is_string($autoPrepend) && trim($autoPrepend) !== '') {
        if ($policy === 'strict') {
            $fails[] = 'auto_prepend_file is set (hidden code injection risk).';
        } else {
            $warns[] = 'auto_prepend_file is set (hidden code injection risk).';
        }
    }

    $autoAppend = ini_get('auto_append_file');
    if (is_string($autoAppend) && trim($autoAppend) !== '') {
        if ($policy === 'strict') {
            $fails[] = 'auto_append_file is set (hidden code injection risk).';
        } else {
            $warns[] = 'auto_append_file is set (hidden code injection risk).';
        }
    }

    $cgiFixPathinfo = blackcat_preflight_ini_flag('cgi.fix_pathinfo');
    if ($cgiFixPathinfo && in_array(PHP_SAPI, ['fpm-fcgi', 'cgi', 'cgi-fcgi'], true)) {
        if ($policy === 'strict') {
            $fails[] = 'cgi.fix_pathinfo is enabled (risk in some FPM/CGI configurations; detected via ini_get). Optional: run ?probe=pathinfo (or &deep=1) for a best-effort black-box probe.';
        } else {
            $warns[] = 'cgi.fix_pathinfo is enabled (risk in some FPM/CGI configurations; detected via ini_get). Optional: run ?probe=pathinfo (or &deep=1) for a best-effort black-box probe.';
        }
    }

    $openBasedir = ini_get('open_basedir');
    if (!is_string($openBasedir) || trim($openBasedir) === '') {
        if ($policy === 'strict') {
            $fails[] = 'open_basedir is not set (required hardening control).';
        } else {
            $warns[] = 'open_basedir is not set (recommended hardening control).';
        }
    } else {
        $info[] = 'open_basedir is set. Ensure it includes your BlackCat bundle root (config.runtime.json + .blackcat) and any OS paths you use (/etc/blackcat, /var/lib/blackcat).';
    }

    $disabled = blackcat_preflight_disabled_functions();
    $dangerous = ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec'];
    $callable = [];
    foreach ($dangerous as $fn) {
        // If the function is disabled (disable_functions) or unavailable (extension not loaded),
        // function_exists() should be false. Treat "callable" as the real risk.
        if (function_exists($fn)) {
            $callable[] = $fn;
        }
    }

    if ($callable !== []) {
        $msg = 'Dangerous process-exec functions are callable: ' . implode(', ', $callable) . '. Disable them (recommended: disable_functions=' . implode(',', $dangerous) . ').';
        if ($policy === 'strict') {
            $fails[] = $msg;
        } else {
            $warns[] = $msg;
        }
    } elseif ($disabled === []) {
        // Informational only: some hostings may disable exec primitives at another layer.
        $info[] = 'disable_functions is empty, but no dangerous process-exec functions appear callable in this runtime.';
    }

    if ($fails !== []) {
        return [
            'ok' => false,
            'code' => 'php_ini_unsafe',
            'details' => implode(' ', $fails),
            'hints' => [
                'Harden php.ini (hosting settings) to remove the unsafe flags above.',
                'If you cannot change php.ini, strict TrustKernel will fail-closed on this hosting. Re-run with ?policy=warn to evaluate a non-strict deployment.',
            ],
        ];
    }

    if ($warns !== []) {
        return [
            'ok' => true,
            'code' => 'php_ini_warn',
            'details' => implode(' ', array_merge($warns, $info)),
            'hints' => [
                'Align php.ini with the TrustKernel policy you intend to run.',
                'If open_basedir is set, ensure the BlackCat bundle root is inside the allowed directories.',
            ],
        ];
    }

    if ($info !== []) {
        return [
            'ok' => true,
            'code' => 'php_ini_info',
            'details' => implode(' ', $info),
            'hints' => [
                'Ensure the BlackCat bundle root is inside open_basedir.',
            ],
        ];
    }

    return [
        'ok' => true,
        'details' => 'php.ini hardening: OK',
    ];
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_write_access(): array
{
    $dir = __DIR__;
    $probeName = '.blackcat_preflight_' . blackcat_preflight_random_id() . '.tmp';
    $probePath = $dir . DIRECTORY_SEPARATOR . $probeName;
    $ok = @file_put_contents($probePath, "blackcat_preflight\n");
    if ($ok === false) {
        return [
            'ok' => false,
            'code' => 'write_blocked',
            'details' => 'PHP cannot write files in this directory.',
            'hints' => [
                'Ensure the hosting allows PHP file writes for BlackCat state/config.',
                'If you uploaded this file into a read-only directory, move it to a writable location and re-run.',
                'The Stage 3 bundle writes state/config in the bundle root; ensure that directory is writable too.',
            ],
        ];
    }

    @unlink($probePath);
    return [
        'ok' => true,
        'details' => 'Write access: OK (temporary probe file created and removed)',
    ];
}

/**
 * @return array{ok:bool, details?:string, code?:string, hints?:list<string>}
 */
function blackcat_preflight_check_outbound_rpc(): array
{
    $payload = '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}';
    $timeoutSec = 4;

    foreach (BLACKCAT_PREFLIGHT_RPC_URLS as $url) {
        $url = trim($url);
        if ($url === '') {
            continue;
        }

        $err = null;
        $status = null;
        $body = null;

        if (function_exists('curl_init') && blackcat_preflight_curl_supports_ssl()) {
            /** @var \CurlHandle|false $ch */
            $ch = curl_init($url);
            if ($ch !== false) {
                curl_setopt_array($ch, [
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => $payload,
                    CURLOPT_HTTPHEADER => [
                        'Content-Type: application/json',
                        'Accept: application/json',
                    ],
                    CURLOPT_CONNECTTIMEOUT => $timeoutSec,
                    CURLOPT_TIMEOUT => $timeoutSec,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_MAXREDIRS => 0,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                ]);
                $body = curl_exec($ch);
                if ($body === false) {
                    $err = curl_error($ch);
                } else {
                    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                }
                unset($ch);
            }
        } elseif (extension_loaded('openssl') && blackcat_preflight_ini_flag('allow_url_fopen')) {
            $host = parse_url($url, PHP_URL_HOST);
            $ssl = [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
                'SNI_enabled' => true,
                'disable_compression' => true,
            ];
            if (is_string($host) && $host !== '') {
                $ssl['peer_name'] = $host;
            }
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
                    'content' => $payload,
                    'timeout' => $timeoutSec,
                    'follow_location' => 0,
                    'max_redirects' => 0,
                ],
                'ssl' => $ssl,
            ]);

            /** @var array<int,string>|null $http_response_header */
            $http_response_header = null;
            $body = @file_get_contents($url, false, $context);
            if ($body === false) {
                $err = 'stream request failed';
            } else {
                $statusLine = is_array($http_response_header) ? ($http_response_header[0] ?? null) : null;
                if (is_string($statusLine) && preg_match('/^HTTP\\/\\d+\\.\\d+\\s+(\\d{3})\\b/', $statusLine, $m)) {
                    $status = (int) $m[1];
                }
            }
        } else {
            return [
                'ok' => false,
                'code' => 'rpc_client_unavailable',
                'details' => 'No outbound HTTPS client available to test RPC connectivity.',
                'hints' => [
                    'Enable cURL(SSL) or OpenSSL + allow_url_fopen.',
                ],
            ];
        }

        if ($status === 429) {
            return [
                'ok' => true,
                'code' => 'rpc_rate_limited',
                'details' => 'RPC reachable but rate-limited (HTTP 429). You may need multiple endpoints for production quorum.',
                'hints' => [
                    'Add 2+ RPC endpoints in runtime config for strict production.',
                    'If your hosting blocks outbound HTTPS, BlackCat cannot operate in strict mode.',
                ],
            ];
        }

        if ($status !== null && $status >= 200 && $status < 300 && is_string($body) && $body !== '') {
            /** @var mixed $decoded */
            $decoded = json_decode($body, true);
            if (is_array($decoded) && isset($decoded['result']) && is_string($decoded['result'])) {
                return [
                    'ok' => true,
                    'details' => 'Outbound RPC OK: ' . $url . ' (eth_chainId=' . $decoded['result'] . ')',
                ];
            }

            return [
                'ok' => true,
                'details' => 'Outbound RPC OK: ' . $url,
            ];
        }

        $detail = 'RPC check failed: ' . $url;
        if ($status !== null) {
            $detail .= ' (HTTP ' . $status . ')';
        }
        if (is_string($err) && $err !== '') {
            $detail .= ' — ' . $err;
        }
        return [
            'ok' => false,
            'code' => 'rpc_unreachable',
            'details' => $detail,
            'hints' => [
                'Ensure outbound HTTPS is allowed from PHP (egress firewall, hosting policy).',
                'If your hosting blocks outbound HTTPS, BlackCat cannot keep a Web3-backed trust state.',
            ],
        ];
    }

    return [
        'ok' => false,
        'code' => 'rpc_missing',
        'details' => 'No RPC endpoints configured in preflight script.',
    ];
}

/**
 * @param array{status:string,title:string,details:string,hints:list<string>} $check
 */
function blackcat_preflight_render_check(array $check): string
{
    $status = $check['status'];
    $badgeClass = $status === 'pass' ? 'pass' : ($status === 'warn' ? 'warn' : 'fail');
    $badgeText = strtoupper($status);

    $hintsHtml = '';
    if ($check['hints'] !== []) {
        $hintsHtml .= '<ul class="hints">';
        foreach ($check['hints'] as $hint) {
            $hintsHtml .= '<li>' . htmlspecialchars($hint, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</li>';
        }
        $hintsHtml .= '</ul>';
    }

    return '<div class="check">'
        . '<div class="checkHead">'
        . '<span class="badge ' . $badgeClass . '">' . $badgeText . '</span>'
        . '<div class="checkTitle">' . htmlspecialchars($check['title'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</div>'
        . '</div>'
        . '<div class="checkBody">'
        . '<div class="checkDetails">' . htmlspecialchars($check['details'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</div>'
        . $hintsHtml
        . '</div>'
        . '</div>';
}

$checks = [];

$phpCheck = blackcat_preflight_check_php_version();
$checks[] = [
    'id' => 'php_version',
    'title' => 'PHP version',
    'status' => $phpCheck['ok'] ? 'pass' : 'fail',
    'details' => $phpCheck['details'] ?? 'Unknown',
    'hints' => $phpCheck['hints'] ?? [],
];

$extCheck = blackcat_preflight_check_required_extensions();
$checks[] = [
    'id' => 'extensions',
    'title' => 'Required extensions (core)',
    'status' => $extCheck['ok'] ? 'pass' : 'fail',
    'details' => $extCheck['details'] ?? 'Unknown',
    'hints' => $extCheck['hints'] ?? [],
];

$tlsCheck = blackcat_preflight_check_tls_verify_capability();
$checks[] = [
    'id' => 'tls_verify',
    'title' => 'TLS verification capability',
    'status' => $tlsCheck['ok'] ? 'pass' : 'fail',
    'details' => $tlsCheck['details'] ?? 'Unknown',
    'hints' => $tlsCheck['hints'] ?? [],
];

$transportCheck = blackcat_preflight_check_web3_transport_capability();
$checks[] = [
    'id' => 'web3_transport',
    'title' => 'Web3 RPC transport (outbound HTTPS client)',
    'status' => $transportCheck['ok'] ? 'pass' : 'fail',
    'details' => $transportCheck['details'] ?? 'Unknown',
    'hints' => $transportCheck['hints'] ?? [],
];

$rpcCheck = blackcat_preflight_check_outbound_rpc();
$checks[] = [
    'id' => 'rpc_outbound',
    'title' => 'Outbound RPC connectivity (Edgen)',
    'status' => ($rpcCheck['ok'] && ($rpcCheck['code'] ?? '') === 'rpc_rate_limited') ? 'warn' : ($rpcCheck['ok'] ? 'pass' : 'fail'),
    'details' => $rpcCheck['details'] ?? 'Unknown',
    'hints' => $rpcCheck['hints'] ?? [],
];

$iniCheck = blackcat_preflight_check_basic_hardening();
$checks[] = [
    'id' => 'php_ini',
    'title' => 'php.ini safety posture',
    'status' => ($iniCheck['ok'] && ($iniCheck['code'] ?? '') === 'php_ini_warn') ? 'warn' : ($iniCheck['ok'] ? 'pass' : 'fail'),
    'details' => $iniCheck['details'] ?? 'Unknown',
    'hints' => $iniCheck['hints'] ?? [],
];

$writeCheck = blackcat_preflight_check_write_access();
$checks[] = [
    'id' => 'write_access',
    'title' => 'Filesystem write access',
    'status' => $writeCheck['ok'] ? 'pass' : 'fail',
    'details' => $writeCheck['details'] ?? 'Unknown',
    'hints' => $writeCheck['hints'] ?? [],
];

$overall = 'pass';
foreach ($checks as $check) {
    if ($check['status'] === 'fail') {
        $overall = 'fail';
        break;
    }
    if ($check['status'] === 'warn') {
        $overall = 'warn';
    }
}

$wantJson = false;
$format = $_GET['format'] ?? null;
if (is_string($format) && strtolower(trim($format)) === 'json') {
    $wantJson = true;
}
if (!$wantJson) {
    $accept = $_SERVER['HTTP_ACCEPT'] ?? null;
    if (is_string($accept) && str_contains(strtolower($accept), 'application/json')) {
        $wantJson = true;
    }
}

$probeMode = blackcat_preflight_probe();
$cleanup = $_GET['cleanup'] ?? null;
if ($probeMode === 'pathinfo' && is_string($cleanup) && trim($cleanup) === '1') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(blackcat_preflight_cleanup_pathinfo_probe(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    exit;
}

if ($wantJson) {
    $policyInfo = blackcat_preflight_policy();
    $probe = null;
    if ($probeMode === 'pathinfo') {
        $p = blackcat_preflight_prepare_pathinfo_probe();
        $deep = blackcat_preflight_probe_deep();
        $variants = $deep ? [
            $p['url_path'] . '/x.php',
            $p['url_path'] . '/index.php',
            $p['url_path'] . '/a.php',
            $p['url_path'] . ';x.php',
            $p['url_path'] . '%3bx.php',
        ] : [
            $p['url_path'] . '/x.php',
        ];

        $probe = [
            'pathinfo' => [
                'mode' => 'browser_or_client',
                'deep' => $deep,
                'control' => [
                    'relative' => $p['url_path'],
                    'absolute' => blackcat_preflight_absolute_url($p['url_path']),
                    'expected_http_status' => 200,
                    'marker' => $p['marker'],
                    'expected_output_token' => $p['expected'],
                ],
                'variants' => array_map(static function (string $u): array {
                    return [
                        'relative' => $u,
                        'absolute' => blackcat_preflight_absolute_url($u),
                    ];
                }, $variants),
                'cleanup' => [
                    'required' => true,
                    'relative' => '?probe=pathinfo&cleanup=1&token=' . rawurlencode($p['id']) . '&file=' . rawurlencode($p['filename']),
                    'absolute' => blackcat_preflight_absolute_url('?probe=pathinfo&cleanup=1&token=' . rawurlencode($p['id']) . '&file=' . rawurlencode($p['filename'])),
                ],
                'notes' => [
                    'This probe is best-effort and cannot prove 100% safety.',
                    'Run it in any web-accessible directory where uploads can land.',
                    'Always call cleanup after testing (it removes the probe file).',
                ],
            ],
        ];
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'generated_at' => gmdate('c'),
        'policy' => $policyInfo['policy'],
        'php_sapi' => PHP_SAPI,
        'overall' => $overall,
        'checks' => $checks,
        'probe' => $probe,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    exit;
}

$overallBadgeClass = $overall === 'pass' ? 'pass' : ($overall === 'warn' ? 'warn' : 'fail');
$overallTitle = $overall === 'pass' ? 'READY' : ($overall === 'warn' ? 'WARNINGS' : 'BLOCKED');

$checksHtml = '';
foreach ($checks as $check) {
    $checksHtml .= blackcat_preflight_render_check($check);
}

$docLink = 'blackcat-installer/docs/STAGE3_KERNEL_MINIMAL_BUNDLE.md';
$policy = blackcat_preflight_policy()['policy'];

$probePanel = '';
if ($probeMode === 'pathinfo') {
    $p = blackcat_preflight_prepare_pathinfo_probe();
    $deep = blackcat_preflight_probe_deep();
    $probeConfig = [
        'id' => $p['id'],
        'filename' => $p['filename'],
        'url' => $p['url_path'],
        'variants' => $deep ? [
            $p['url_path'] . '/x.php',
            $p['url_path'] . '/index.php',
            $p['url_path'] . '/a.php',
            $p['url_path'] . ';x.php',
            $p['url_path'] . '%3bx.php',
        ] : [
            $p['url_path'] . '/x.php',
        ],
        'expected' => $p['expected'],
        'marker' => $p['marker'] ?? null,
        'cleanup_url' => '?probe=pathinfo&cleanup=1&token=' . rawurlencode($p['id']) . '&file=' . rawurlencode($p['filename']),
        'deep' => $deep,
    ];

    $probePanel = '<div class="check" style="margin-top:12px;">'
        . '<div class="checkHead"><span class="badge warn" id="bcProbeBadge">RUNNING</span>'
        . '<div><div class="checkTitle">CGI PathInfo Probe (best-effort)</div>'
        . '<div class="sub">This simulates the classic <code>file.txt/x.php</code> exploit surface when <code>cgi.fix_pathinfo</code> is enabled.</div></div></div>'
        . '<div class="checkBody">'
        . '<div class="checkDetails" id="bcProbeSummary">Running probe…</div>'
        . '<ul class="hints" id="bcProbeHints">'
        . '<li>Note: This probe is <strong>informational</strong>. Strict production should still disable <code>cgi.fix_pathinfo</code> where possible.</li>'
        . ($deep ? '<li>Deep mode: multiple variants are tested (<code>deep=1</code>).</li>' : '<li>Tip: add <code>&amp;deep=1</code> to test more variants.</li>')
        . '</ul>'
        . '</div>'
        . '</div>'
        . '<script>'
        . '(() => {'
        . 'const cfg = ' . json_encode($probeConfig, JSON_UNESCAPED_SLASHES) . ';'
        . 'const badge = document.getElementById("bcProbeBadge");'
        . 'const summary = document.getElementById("bcProbeSummary");'
        . 'const hints = document.getElementById("bcProbeHints");'
        . 'const set = (cls, txt) => { badge.className = "badge " + cls; badge.textContent = txt; };'
        . 'const addHint = (t) => { const li = document.createElement("li"); li.textContent = t; hints.appendChild(li); };'
        . 'const readText = async (url) => {'
        . '  try {'
        . '    const res = await fetch(url, { cache: "no-store", credentials: "same-origin" });'
        . '    const text = await res.text();'
        . '    return { fetched: true, status: res.status, ok: res.ok, text };'
        . '  } catch (e) {'
        . '    return { fetched: false, status: 0, ok: false, text: "", error: String(e && e.message ? e.message : e) };'
        . '  }'
        . '};'
        . '(async () => {'
        . '  const control = await readText(cfg.url);'
        . '  const variants = Array.isArray(cfg.variants) ? cfg.variants : [];'
        . '  const results = [];'
        . '  for (const u of variants) { results.push({ url: u, res: await readText(u) }); }'
        . '  const marker = (typeof cfg.marker === "string" && cfg.marker) ? cfg.marker : null;'
        . '  const controlIsReachable = control.fetched && control.status === 200 && (!marker || control.text.includes(marker));'
        . '  const controlExec = control.fetched && control.text.includes(cfg.expected);'
        . '  const variantExec = results.some((r) => r.res.fetched && r.res.text.includes(cfg.expected));'
        . '  if (!control.fetched) {'
        . '    set("warn", "INCONCLUSIVE");'
        . '    summary.textContent = "Probe could not run (browser could not fetch the control file).";'
        . '    addHint("Control fetch failed: " + (control.error || "unknown error"));'
        . '  } else if (!controlIsReachable) {'
        . '    set("warn", "INCONCLUSIVE");'
        . '    summary.textContent = "Probe is inconclusive: the control probe file was not reachable (expected HTTP 200).";'
        . '    addHint("Control URL: " + cfg.url + " (HTTP " + String(control.status) + ")");'
        . '    addHint("Ensure this preflight file is served from a normal web-accessible directory (not rewritten), then re-run the probe.");'
        . '  } else if (controlExec) {'
        . '    set("fail", "VULNERABLE");'
        . '    summary.textContent = "CRITICAL: The server executed a .txt file as PHP. This hosting is unsafe for strict deployments.";' 
        . '  } else if (variantExec) {'
        . '    set("fail", "VULNERABLE");'
        . '    summary.textContent = "VULNERABLE: A PathInfo-style request caused PHP execution (cgi.fix_pathinfo-style exploit surface).";'
        . '    addHint("Fix: Set php.ini cgi.fix_pathinfo=0 and ensure webserver uses try_files / correct SCRIPT_FILENAME routing.");'
        . '  } else {'
        . '    set("pass", "NO EXEC");'
        . '    summary.textContent = "No PHP execution observed for the tested PathInfo variants in this probe.";' 
        . '    addHint("This does not guarantee safety; it only indicates this specific probe did not trigger execution.");'
        . '  }'
        . '  if (cfg.deep) {'
        . '    for (const r of results) {'
        . '      const safe = r.res.fetched && !r.res.text.includes(cfg.expected);'
        . '      addHint((safe ? "PASS" : "CHECK") + ": " + r.url + " (HTTP " + String(r.res.status) + ")");'
        . '    }'
        . '  }'
        . '  try { await fetch(cfg.cleanup_url, { cache: "no-store", credentials: "same-origin" }); } catch (e) {}'
        . '})();'
        . '})();'
        . '</script>';
}

echo '<!doctype html>'
    . '<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />'
    . '<title>BlackCat Hosting Preflight</title>'
    . '<style>'
    . ':root{color-scheme:dark;}'
    . 'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;'
    . 'font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;'
    . 'background:radial-gradient(900px 420px at 15% 0%,rgba(86,116,255,.22),transparent 55%),'
    . 'radial-gradient(900px 420px at 85% 0%,rgba(118,227,157,.14),transparent 60%),#0b0f17;color:#e7eefc;}'
    . '.wrap{width:min(980px,100%);} '
    . '.card{background:rgba(15,21,36,.75);border:1px solid rgba(31,42,68,.95);border-radius:16px;'
    . 'box-shadow:0 24px 80px rgba(0,0,0,.35);overflow:hidden;}'
    . '.head{padding:16px 18px;border-bottom:1px solid rgba(31,42,68,.95);display:flex;align-items:center;justify-content:space-between;gap:12px;}'
    . '.title{margin:0;font-size:18px;letter-spacing:.2px;}'
    . '.sub{margin:4px 0 0;color:#9fb0d0;font-size:12px;}'
    . '.badge{display:inline-flex;align-items:center;gap:8px;border-radius:999px;padding:6px 10px;'
    . 'border:1px solid rgba(31,42,68,.95);font-weight:700;letter-spacing:.6px;font-size:11px;}'
    . '.badge.pass{background:rgba(118,227,157,.12);border-color:rgba(118,227,157,.28);color:#76e39d;}'
    . '.badge.warn{background:rgba(255,212,107,.12);border-color:rgba(255,212,107,.28);color:#ffd46b;}'
    . '.badge.fail{background:rgba(255,123,114,.12);border-color:rgba(255,123,114,.28);color:#ff7b72;}'
    . '.body{padding:16px 18px;}'
    . '.note{background:rgba(255,123,114,.10);border:1px solid rgba(255,123,114,.25);border-radius:12px;padding:10px 12px;color:#ffb4ae;margin-bottom:12px;}'
    . '.note strong{color:#ff7b72;}'
    . '.grid{display:grid;gap:10px;}'
    . '.check{border:1px solid rgba(31,42,68,.95);border-radius:14px;background:rgba(11,15,23,.35);overflow:hidden;}'
    . '.checkHead{display:flex;gap:10px;align-items:center;padding:10px 12px;border-bottom:1px solid rgba(31,42,68,.95);} '
    . '.checkTitle{font-weight:700;}'
    . '.checkBody{padding:10px 12px;color:#9fb0d0;}'
    . '.checkDetails{color:#e7eefc;margin-bottom:8px;}'
    . '.hints{margin:0;padding-left:18px;}'
    . '.hints li{margin:4px 0;}'
    . '.footer{margin-top:14px;color:#9fb0d0;font-size:12px;}'
    . 'a{color:#8ab4ff;text-decoration:none;} a:hover{text-decoration:underline;}'
    . 'code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#ffd46b;}'
    . '</style>'
    . '</head><body>'
    . '<div class="wrap"><div class="card">'
    . '<div class="head">'
    . '<div><h1 class="title">BlackCat Hosting Preflight</h1>'
    . '<div class="sub">Single-file diagnostics for constrained hosting (FTP / no Composer). Policy: <code>' . htmlspecialchars($policy, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code>. Delete this file after use.</div></div>'
    . '<div class="badge ' . $overallBadgeClass . '">' . $overallTitle . '</div>'
    . '</div>'
    . '<div class="body">'
    . '<div class="note"><strong>Action:</strong> remove this file after you finish checking. It should not remain publicly accessible.</div>'
    . '<div class="grid">' . $checksHtml . '</div>'
    . $probePanel
    . '<div class="footer">'
    . 'Next steps: if this is <span class="badge ' . $overallBadgeClass . '">' . $overallTitle . '</span>, follow the Stage 3 docs: '
    . '<code>' . htmlspecialchars($docLink, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code>. '
    . 'For machine-readable output: add <code>?format=json</code>.'
    . '</div>'
    . '</div></div></div>'
    . '</body></html>';
