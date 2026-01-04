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

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url(is_string($requestUri) ? $requestUri : '/', PHP_URL_PATH);
$path = is_string($path) && $path !== '' ? $path : '/';

if ($path === '/_blackcat/setup' || str_starts_with($path, '/_blackcat/setup/')) {
    /** @noinspection PhpIncludeInspection */
    require __DIR__ . '/../_blackcat/setup.php';
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
    header('Location: /_blackcat/setup', true, 302);
    header('Content-Type: text/plain; charset=utf-8');
    echo "BlackCat is not installed yet. Redirecting to /_blackcat/setup ...\n";
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
