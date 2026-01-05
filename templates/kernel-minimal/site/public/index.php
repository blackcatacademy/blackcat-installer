<?php

declare(strict_types=1);

/**
 * BlackCat kernel minimal bundle (Stage 3 template).
 *
 * - Single entrypoint for all HTTP requests
 * - Boot TrustKernel early (fail-closed in strict)
 * - Hosts the one-time installer UI under `/_blackcat/setup`
 */

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
    '/_blackcat/assets/tls-not-trusted-cat.png' => ['file' => 'tls-not-trusted-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/tls-not-trusted-banner.png' => ['file' => 'tls-not-trusted-banner.png', 'type' => 'image/png'],
    '/_blackcat/assets/tls-not-trusted-fallback.svg' => ['file' => 'tls-not-trusted-fallback.svg', 'type' => 'image/svg+xml; charset=utf-8'],
    '/_blackcat/assets/bg-grid.png' => ['file' => 'bg-grid.png', 'type' => 'image/png'],
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

$autoload = __DIR__ . '/../vendor/autoload.php';
if (!is_file($autoload)) {
    http_response_code(500);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    echo <<<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat — Bundle incomplete</title>
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <style>
      :root { color-scheme: dark; }
      *, *::before, *::after { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100svh;
        display: flex;
        justify-content: center;
        align-items: flex-start;
        padding: clamp(16px, 2.5vh, 56px) 16px 16px;
        font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        position: relative;
        isolation: isolate;
        background:
          radial-gradient(900px 420px at 20% 0%, rgba(86, 116, 255, 0.18), transparent 55%),
          radial-gradient(900px 420px at 80% 0%, rgba(255, 123, 114, 0.12), transparent 60%),
          #0b0f17;
        color: #e7eefc;
      }
      body::before {
        content: "";
        position: fixed;
        inset: 0;
        background: url("/_blackcat/assets/bg-grid.png") repeat;
        background-size: 512px 512px;
        opacity: 0.36;
        mix-blend-mode: screen;
        filter: brightness(2.2) contrast(1.35) saturate(1.15);
        pointer-events: none;
        z-index: 0;
      }
      .card {
        max-width: 980px;
        width: 100%;
        border-radius: 18px;
        border: 1px solid rgba(42, 59, 99, 0.78);
        background:
          radial-gradient(900px 420px at 18% 0%, rgba(255, 255, 255, 0.07), transparent 62%),
          radial-gradient(900px 420px at 82% 0%, rgba(86, 116, 255, 0.10), transparent 66%),
          linear-gradient(180deg, rgba(15, 21, 36, 0.74), rgba(15, 21, 36, 0.40));
        backdrop-filter: blur(18px) saturate(1.25);
        -webkit-backdrop-filter: blur(18px) saturate(1.25);
        box-shadow: 0 30px 100px rgba(0, 0, 0, 0.45);
        overflow: hidden;
        position: relative;
        z-index: 1;
      }
      .banner {
        width: 100%;
        height: clamp(140px, 18vw, 220px);
        background:
          linear-gradient(180deg, rgba(11, 15, 23, 0.00), rgba(11, 15, 23, 0.82)),
          url("/_blackcat/assets/hero-banner.png") left center / cover no-repeat;
        border-bottom: 1px solid rgba(31, 42, 68, 0.95);
      }
      .body { padding: 14px 16px 16px; }
      h1 { margin: 0 0 8px; font-size: 24px; }
      .muted { color: #9fb0d0; }
      .bad { color: #ff7b72; }
      code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      ul { margin: 10px 0 0 18px; padding: 0; }
      li { margin: 6px 0; }
      .box {
        margin-top: 12px;
        padding: 12px 14px;
        border-radius: 14px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.55);
      }
    </style>
  </head>
  <body>
    <main class="card">
      <div class="banner" aria-hidden="true"></div>
      <div class="body">
        <h1>Bundle incomplete <span class="bad">vendor/ missing</span></h1>
        <p class="muted">BlackCat cannot boot because <code>vendor/autoload.php</code> is missing.</p>
        <div class="box">
          <div><strong>Fix:</strong></div>
          <ul>
            <li>Upload the full bundle (including <code>vendor/</code>) via FTP/SFTP.</li>
            <li>Ensure the web root points to <code>site/public/</code>.</li>
            <li>Reload this page.</li>
          </ul>
        </div>
      </div>
    </main>
  </body>
</html>
HTML;
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
    if (is_file($setupPath) && !is_file($stateDir . DIRECTORY_SEPARATOR . 'installed.flag')) {
        header('Location: /_blackcat/setup', true, 302);
        header('Content-Type: text/plain; charset=utf-8');
        echo "BlackCat is not installed yet. Redirecting to /_blackcat/setup ...\n";
        exit;
    }

    http_response_code(503);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    echo <<<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat — Not installed</title>
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <style>
      :root { color-scheme: dark; }
      *, *::before, *::after { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100svh;
        display: flex;
        justify-content: center;
        align-items: flex-start;
        padding: clamp(16px, 2.5vh, 56px) 16px 16px;
        font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        position: relative;
        isolation: isolate;
        background:
          radial-gradient(900px 420px at 20% 0%, rgba(86, 116, 255, 0.18), transparent 55%),
          radial-gradient(900px 420px at 80% 0%, rgba(255, 123, 114, 0.12), transparent 60%),
          #0b0f17;
        color: #e7eefc;
      }
      body::before {
        content: "";
        position: fixed;
        inset: 0;
        background: url("/_blackcat/assets/bg-grid.png") repeat;
        background-size: 512px 512px;
        opacity: 0.36;
        mix-blend-mode: screen;
        filter: brightness(2.2) contrast(1.35) saturate(1.15);
        pointer-events: none;
        z-index: 0;
      }
      .card {
        max-width: 980px;
        width: 100%;
        border-radius: 18px;
        border: 1px solid rgba(42, 59, 99, 0.78);
        background:
          radial-gradient(900px 420px at 18% 0%, rgba(255, 255, 255, 0.07), transparent 62%),
          radial-gradient(900px 420px at 82% 0%, rgba(86, 116, 255, 0.10), transparent 66%),
          linear-gradient(180deg, rgba(15, 21, 36, 0.74), rgba(15, 21, 36, 0.40));
        backdrop-filter: blur(18px) saturate(1.25);
        -webkit-backdrop-filter: blur(18px) saturate(1.25);
        box-shadow: 0 30px 100px rgba(0, 0, 0, 0.45);
        overflow: hidden;
        position: relative;
        z-index: 1;
      }
      .banner {
        width: 100%;
        height: clamp(140px, 18vw, 220px);
        background:
          linear-gradient(180deg, rgba(11, 15, 23, 0.00), rgba(11, 15, 23, 0.82)),
          url("/_blackcat/assets/hero-banner.png") left center / cover no-repeat;
        border-bottom: 1px solid rgba(31, 42, 68, 0.95);
      }
      .body { padding: 14px 16px 16px; }
      h1 { margin: 0 0 8px; font-size: 24px; }
      .muted { color: #9fb0d0; }
      code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      ul { margin: 10px 0 0 18px; padding: 0; }
      li { margin: 6px 0; }
      .box {
        margin-top: 12px;
        padding: 12px 14px;
        border-radius: 14px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.55);
      }
    </style>
  </head>
  <body>
    <main class="card">
      <div class="banner" aria-hidden="true"></div>
      <div class="body">
        <h1>Not installed</h1>
        <p class="muted"><code>config.runtime.json</code> is missing and the installer is not available.</p>
        <div class="box">
          <div><strong>Fix:</strong></div>
          <ul>
            <li>Upload <code>config.runtime.json</code> to the bundle root, or</li>
            <li>Restore the Stage-3 setup module and open <code>/_blackcat/setup</code>.</li>
          </ul>
        </div>
      </div>
    </main>
  </body>
</html>
HTML;
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
