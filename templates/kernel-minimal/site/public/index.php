<?php

declare(strict_types=1);

/**
 * BlackCat kernel minimal bundle (Stage 3 template).
 *
 * - Single entrypoint for all HTTP requests
 * - Boot TrustKernel early (fail-closed in strict)
 * - Hosts the one-time installer UI under `/_blackcat/setup`
 */

$autoload = __DIR__ . '/../vendor/autoload.php';
if (!is_file($autoload)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "BlackCat boot failed: missing vendor/autoload.php\n";
    exit;
}
require $autoload;

use BlackCat\Core\Kernel\HttpKernel;
use BlackCat\Core\Kernel\HttpKernelContext;

$docroot = @realpath(__DIR__);
$docroot = is_string($docroot) && $docroot !== '' ? $docroot : __DIR__;

$siteDir = @realpath(dirname($docroot));
$siteDir = is_string($siteDir) && $siteDir !== '' ? $siteDir : dirname($docroot);

$bundleRoot = @realpath(dirname($siteDir));
$bundleRoot = is_string($bundleRoot) && $bundleRoot !== '' ? $bundleRoot : dirname($siteDir);

$stateDir = rtrim($bundleRoot, "/\\") . DIRECTORY_SEPARATOR . '.blackcat';
$configPath = rtrim($bundleRoot, "/\\") . DIRECTORY_SEPARATOR . 'config.runtime.json';
$setupPath = __DIR__ . '/../_blackcat/setup.php';

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url(is_string($requestUri) ? $requestUri : '/', PHP_URL_PATH);
$path = is_string($path) && $path !== '' ? $path : '/';

$assetDir = __DIR__ . '/../_blackcat/asset';
$assetMap = [
    '/apple-touch-icon.png' => ['file' => 'apple-touch-icon.png', 'type' => 'image/png'],
    '/favicon-32x32.png' => ['file' => 'favicon-32x32.png', 'type' => 'image/png'],
    '/favicon-16x16.png' => ['file' => 'favicon-16x16.png', 'type' => 'image/png'],
    '/favicon.ico' => ['file' => 'favicon.ico', 'type' => 'image/x-icon'],
    '/site.webmanifest' => ['file' => 'site.webmanifest', 'type' => 'application/manifest+json; charset=utf-8'],
    '/android-chrome-192x192.png' => ['file' => 'android-chrome-192x192.png', 'type' => 'image/png'],
    '/android-chrome-512x512.png' => ['file' => 'android-chrome-512x512.png', 'type' => 'image/png'],
    // Setup UI images (optional, but recommended).
    '/_blackcat/assets/hero-banner.png' => ['file' => 'hero-banner.png', 'type' => 'image/png'],
    '/_blackcat/assets/https-required-cat.png' => ['file' => 'https-required-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/https-required-cat-fallback.svg' => ['file' => 'https-required-cat-fallback.svg', 'type' => 'image/svg+xml; charset=utf-8'],
    '/_blackcat/assets/trusted-vs-untrusted.png' => ['file' => 'trusted-vs-untrusted.png', 'type' => 'image/png'],
];

if (isset($assetMap[$path])) {
    $meta = $assetMap[$path];
    $filePath = $assetDir . DIRECTORY_SEPARATOR . $meta['file'];
    if (!is_file($filePath)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Not found.\n";
        exit;
    }

    header('Content-Type: ' . $meta['type']);
    header('Cache-Control: public, max-age=86400');
    header('X-Content-Type-Options: nosniff');

    $size = @filesize($filePath);
    if (is_int($size)) {
        header('Content-Length: ' . $size);
    }

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($method === 'HEAD') {
        exit;
    }

    @readfile($filePath);
    exit;
}

if ($path === '/_blackcat/setup' || str_starts_with($path, '/_blackcat/setup/')) {
    if (!is_file($setupPath)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Not found.\n";
        exit;
    }

    /** @noinspection PhpIncludeInspection */
    require $setupPath;
    blackcat_setup_handle([
        'docroot' => $docroot,
        'site_dir' => $siteDir,
        'bundle_root' => $bundleRoot,
        'state_dir' => $stateDir,
        'config_path' => $configPath,
    ]);
    return;
}

// Friendly first-run: if runtime config is missing, redirect to setup.
if (!is_file($configPath)) {
    if (is_file($setupPath)) {
        header('Location: /_blackcat/setup', true, 302);
        header('Content-Type: text/plain; charset=utf-8');
        echo "BlackCat is not installed yet. Redirecting to /_blackcat/setup ...\n";
        exit;
    }

    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    echo "BlackCat is not installed (config.runtime.json is missing).\n";
    echo "Hint: upload config.runtime.json or restore the Stage-3 setup module.\n";
    exit;
}

// Explicit config init to support bundle-root config.runtime.json without env.
$configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
if (class_exists($configClass) && is_callable([$configClass, 'initFromJsonFileIfNeeded'])) {
    $method = 'initFromJsonFileIfNeeded';
    try {
        $configClass::$method($configPath);
    } catch (Throwable $e) {
        http_response_code(503);
        header('Content-Type: text/plain; charset=utf-8');
        echo "BlackCat config init failed (fail-closed).\n";
        echo "Hint: open /_blackcat/setup to review.\n";
        exit;
    }
}

HttpKernel::run(static function (HttpKernelContext $ctx): void {
    header('Content-Type: text/plain; charset=utf-8');
    echo "BlackCat kernel is running.\n";
    echo "Trust status: " . ($ctx->status->trusted ? 'trusted' : 'untrusted') . "\n";
    echo "Enforcement: " . $ctx->status->enforcement . "\n";
});
