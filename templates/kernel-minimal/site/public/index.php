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
    '/_blackcat/assets/fatal-error-cat.png' => ['file' => 'fatal-error-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/https-required-cat-fallback.svg' => ['file' => 'https-required-cat-fallback.svg', 'type' => 'image/svg+xml; charset=utf-8'],
    '/_blackcat/assets/trusted-vs-untrusted.png' => ['file' => 'trusted-vs-untrusted.png', 'type' => 'image/png'],
    '/_blackcat/assets/tls-not-trusted-cat.png' => ['file' => 'tls-not-trusted-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/tls-not-trusted-banner.png' => ['file' => 'tls-not-trusted-banner.png', 'type' => 'image/png'],
    '/_blackcat/assets/tls-not-trusted-fallback.svg' => ['file' => 'tls-not-trusted-fallback.svg', 'type' => 'image/svg+xml; charset=utf-8'],
    '/_blackcat/assets/bg-grid.png' => ['file' => 'bg-grid.png', 'type' => 'image/png'],
    '/_blackcat/assets/bg-grid-red.png' => ['file' => 'bg-grid-red.png', 'type' => 'image/png'],
    // Optional mascots (used by various fail-closed pages).
    '/_blackcat/assets/vendor-missing-cat.png' => ['file' => 'vendor-missing-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/config-missing-cat.png' => ['file' => 'config-missing-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/config-invalid-cat.png' => ['file' => 'config-invalid-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/docroot-misconfigured-cat.png' => ['file' => 'docroot-misconfigured-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/preflight-failed-cat.png' => ['file' => 'preflight-failed-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/installer-locked-cat.png' => ['file' => 'installer-locked-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/integrity-tamper-cat.png' => ['file' => 'integrity-tamper-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/rpc-outage-cat.png' => ['file' => 'rpc-outage-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/request-blocked-cat.png' => ['file' => 'request-blocked-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/kernel-paused-cat.png' => ['file' => 'kernel-paused-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/incident-queued-cat.png' => ['file' => 'incident-queued-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/not-found-cat.png' => ['file' => 'not-found-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/internal-error-cat.png' => ['file' => 'internal-error-cat.png', 'type' => 'image/png'],
    '/_blackcat/assets/method-not-allowed-cat.png' => ['file' => 'method-not-allowed-cat.png', 'type' => 'image/png'],
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

$host = $_SERVER['HTTP_HOST'] ?? '';
$host = is_string($host) ? strtolower(trim($host)) : '';
$host = explode(':', $host, 2)[0] ?? '';
$isDevHost = in_array($host, ['localhost', '127.0.0.1', '::1'], true);

$documentRoot = $_SERVER['DOCUMENT_ROOT'] ?? null;
$documentRoot = is_string($documentRoot) ? trim($documentRoot) : '';
$documentRootReal = $documentRoot !== '' ? @realpath($documentRoot) : false;
$publicReal = @realpath(__DIR__);
if (is_string($documentRootReal) && $documentRootReal !== '' && is_string($publicReal) && $publicReal !== '' && $documentRootReal !== $publicReal) {
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

    $docHint = $isDevHost
        ? '<details class="box"><summary><strong>Dev details</strong> (docroot)</summary>'
            . '<pre><code>DOCUMENT_ROOT: ' . htmlspecialchars($documentRootReal, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "\n"
            . 'Expected:      ' . htmlspecialchars($publicReal, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code></pre>'
            . '</details>'
        : '';

    echo <<<HTML
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat — Docroot misconfigured</title>
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
        background: url("/_blackcat/assets/bg-grid-red.png") repeat;
        background-size: 512px 512px;
        opacity: 0.30;
        mix-blend-mode: screen;
        filter: brightness(2.1) contrast(1.32) saturate(1.1);
        pointer-events: none;
        z-index: 0;
      }
      @media (prefers-reduced-motion: no-preference) {
        body::before { animation: bcGridDrift 52s linear infinite; }
        @keyframes bcGridDrift {
          from { background-position: 0 0; }
          to { background-position: 240px 120px; }
        }
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
      h1 { margin: 0 0 6px; font-size: 24px; }
      .muted { color: #9fb0d0; }
      .bad { color: #ff7b72; }
      .lead { margin: 0; }
      .head { display: flex; gap: 14px; align-items: center; }
      .mascot {
        flex: 0 0 auto;
        width: 86px;
        height: 86px;
        border-radius: 16px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.35);
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 18px 60px rgba(0, 0, 0, 0.35);
      }
      .mascot img { width: 92%; height: 92%; object-fit: contain; }
      code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      pre { margin: 10px 0 0; overflow: auto; }
      ul { margin: 10px 0 0 18px; padding: 0; }
      li { margin: 6px 0; }
      .box {
        margin-top: 12px;
        padding: 12px 14px;
        border-radius: 14px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.55);
      }
      details > summary { cursor: pointer; user-select: none; }
    </style>
  </head>
	  <body>
	    <main class="card">
	      <div class="banner" aria-hidden="true"></div>
	      <div class="body">
	        <div class="head">
	          <div class="mascot" aria-hidden="true">
	            <img src="/_blackcat/assets/docroot-misconfigured-cat.png" alt="" />
	          </div>
	          <div>
	            <h1>Docroot misconfigured <span class="bad">fix required</span></h1>
	            <p class="muted lead">Your web server is not pointing to <code>site/public/</code> as the document root. This is unsafe because internal files may become directly accessible.</p>
	          </div>
	        </div>
	        <div class="box">
	          <div><strong>Fix:</strong></div>
	          <ul>
	            <li>Set the document root to <code>site/public/</code>.</li>
            <li>Ensure all requests route through <code>site/public/index.php</code> (front controller).</li>
            <li>After fixing, reload the page.</li>
          </ul>
        </div>
        <div class="box">
          <div><strong>Why this is fail-closed:</strong></div>
          <ul class="muted">
            <li>Misconfigured docroot can expose <code>vendor/</code>, <code>config.runtime.json</code>, and <code>.blackcat/</code>.</li>
            <li>BlackCat refuses to boot in this state.</li>
          </ul>
        </div>
        {$docHint}
      </div>
    </main>
  </body>
</html>
HTML;
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
        background: url("/_blackcat/assets/bg-grid-red.png") repeat;
        background-size: 512px 512px;
        opacity: 0.36;
        mix-blend-mode: screen;
        filter: brightness(2.2) contrast(1.35) saturate(1.15);
        pointer-events: none;
        z-index: 0;
      }
      @media (prefers-reduced-motion: no-preference) {
        body::before { animation: bcGridDrift 52s linear infinite; }
        @keyframes bcGridDrift {
          from { background-position: 0 0; }
          to { background-position: 240px 120px; }
        }
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
      h1 { margin: 0 0 6px; font-size: 24px; }
      .muted { color: #9fb0d0; }
      .bad { color: #ff7b72; }
      .lead { margin: 0; }
      .head { display: flex; gap: 14px; align-items: center; }
      .mascot {
        flex: 0 0 auto;
        width: 86px;
        height: 86px;
        border-radius: 16px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.35);
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 18px 60px rgba(0, 0, 0, 0.35);
      }
      .mascot img { width: 92%; height: 92%; object-fit: contain; }
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
	        <div class="head">
	          <div class="mascot" aria-hidden="true">
	            <img src="/_blackcat/assets/vendor-missing-cat.png" alt="" />
	          </div>
	          <div>
	            <h1>Bundle incomplete <span class="bad">vendor/ missing</span></h1>
	            <p class="muted lead">BlackCat cannot boot because <code>vendor/autoload.php</code> is missing.</p>
	          </div>
	        </div>
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
use BlackCat\Core\Kernel\HttpKernelOptions;

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
        background: url("/_blackcat/assets/bg-grid-red.png") repeat;
        background-size: 512px 512px;
        opacity: 0.36;
        mix-blend-mode: screen;
        filter: brightness(2.2) contrast(1.35) saturate(1.15);
        pointer-events: none;
        z-index: 0;
      }
      @media (prefers-reduced-motion: no-preference) {
        body::before { animation: bcGridDrift 52s linear infinite; }
        @keyframes bcGridDrift {
          from { background-position: 0 0; }
          to { background-position: 240px 120px; }
        }
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
      h1 { margin: 0 0 6px; font-size: 24px; }
      .muted { color: #9fb0d0; }
      .lead { margin: 0; }
      .head { display: flex; gap: 14px; align-items: center; }
      .mascot {
        flex: 0 0 auto;
        width: 86px;
        height: 86px;
        border-radius: 16px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.35);
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 18px 60px rgba(0, 0, 0, 0.35);
      }
      .mascot img { width: 92%; height: 92%; object-fit: contain; }
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
	        <div class="head">
	          <div class="mascot" aria-hidden="true">
	            <img src="/_blackcat/assets/config-missing-cat.png" alt="" />
	          </div>
	          <div>
	            <h1>Not installed</h1>
	            <p class="muted lead"><code>config.runtime.json</code> is missing and the installer is not available.</p>
	          </div>
	        </div>
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

        $host = $_SERVER['HTTP_HOST'] ?? '';
        $host = is_string($host) ? strtolower(trim($host)) : '';
        $host = explode(':', $host, 2)[0] ?? '';
        $isDev = in_array($host, ['localhost', '127.0.0.1', '::1'], true);

        $debugHtml = '';
        if ($isDev) {
            $debugHtml = '<details class="box"><summary><strong>Dev debug</strong> (exception)</summary>'
                . '<pre><code>' . htmlspecialchars(get_class($e) . ': ' . $e->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code></pre>'
                . '</details>';
        }

        echo <<<HTML
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat — Config init failed</title>
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
        background: url("/_blackcat/assets/bg-grid-red.png") repeat;
        background-size: 512px 512px;
        opacity: 0.36;
        mix-blend-mode: screen;
        filter: brightness(2.2) contrast(1.35) saturate(1.15);
        pointer-events: none;
        z-index: 0;
      }
      @media (prefers-reduced-motion: no-preference) {
        body::before { animation: bcGridDrift 52s linear infinite; }
        @keyframes bcGridDrift {
          from { background-position: 0 0; }
          to { background-position: 240px 120px; }
        }
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
      h1 { margin: 0 0 6px; font-size: 24px; }
      .muted { color: #9fb0d0; }
      .bad { color: #ff7b72; }
      .lead { margin: 0; }
      .head { display: flex; gap: 14px; align-items: center; }
      .mascot {
        flex: 0 0 auto;
        width: 86px;
        height: 86px;
        border-radius: 16px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.35);
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 18px 60px rgba(0, 0, 0, 0.35);
      }
      .mascot img { width: 92%; height: 92%; object-fit: contain; }
      code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      pre { margin: 10px 0 0; background: rgba(11, 15, 23, 0.55); border: 1px solid rgba(31, 42, 68, 0.95); padding: 12px 14px; border-radius: 14px; overflow: auto; }
      ul { margin: 10px 0 0 18px; padding: 0; }
      li { margin: 6px 0; }
      .box {
        margin-top: 12px;
        padding: 12px 14px;
        border-radius: 14px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.55);
      }
      details > summary { cursor: pointer; user-select: none; }
    </style>
  </head>
	  <body>
	    <main class="card">
	      <div class="banner" aria-hidden="true"></div>
	      <div class="body">
	        <div class="head">
	          <div class="mascot" aria-hidden="true">
	            <img src="/_blackcat/assets/config-invalid-cat.png" alt="" />
	          </div>
	          <div>
	            <h1>Config init failed <span class="bad">fail-closed</span></h1>
	            <p class="muted lead">BlackCat refused to boot because <code>config.runtime.json</code> failed validation. This prevents attackers from weakening the security kernel by tampering with config.</p>
	          </div>
	        </div>
	        <div class="box">
	          <div><strong>Fix:</strong></div>
	          <ul>
	            <li>If the installer is available: open <code>/_blackcat/setup</code> and regenerate the runtime config.</li>
            <li>If the installer is disabled: upload a valid <code>config.runtime.json</code> to the bundle root.</li>
            <li>Reload after fixing.</li>
          </ul>
        </div>
        {$debugHtml}
      </div>
    </main>
  </body>
</html>
HTML;
        exit;
    }
}

$kernelOptions = new HttpKernelOptions();
// Keep TrustKernel fail-closed on sensitive ops, but allow this template to render a richer status page
// (instead of a generic 503) even when the instance is temporarily untrusted.
$kernelOptions->checkTrustOnRequest = false;
$kernelOptions->prettyErrorPages = true;
$kernelOptions->prettyErrorGrid = 'bg-grid-red.png';

HttpKernel::run(
    static function (HttpKernelContext $ctx) use ($path, $configPath, $setupPath, $stateDir, $isDevHost): void {
        $status = $ctx->status;

        if ($path === '/health' || $path === '/_blackcat/health') {
            $payload = $status->toMonitorArray();
            $ok = ($status->enforcement !== 'strict') || $status->readAllowed;
            $code = $ok ? 200 : 503;

            http_response_code($code);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store');
            echo json_encode(['ok' => $ok, 'status' => $payload], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
            return;
        }

        $sendHtmlHeaders = static function (int $code): void {
            http_response_code($code);
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
        };

        $renderShell = static function (int $code, string $title, string $badgeHtml, string $leadHtml, string $bodyHtml, ?string $mascotUrl = null) use ($sendHtmlHeaders): void {
            $isError = $code >= 400;
            $gridUrl = $isError ? '/_blackcat/assets/bg-grid-red.png' : '/_blackcat/assets/bg-grid.png';
            $accent2 = $isError ? 'rgba(255, 123, 114, 0.12)' : 'rgba(118, 227, 157, 0.12)';

            $mascotHtml = '';
            if (is_string($mascotUrl) && $mascotUrl !== '') {
                $safe = htmlspecialchars($mascotUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                $mascotHtml = '<div class="mascot" aria-hidden="true"><img src="' . $safe . '" alt="" /></div>';
            }

            $sendHtmlHeaders($code);
            echo <<<HTML
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{$title}</title>
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
          radial-gradient(900px 420px at 80% 0%, {$accent2}, transparent 60%),
          #0b0f17;
        color: #e7eefc;
      }
      body::before {
        content: "";
        position: fixed;
        inset: 0;
        background: url("{$gridUrl}") repeat;
        background-size: 512px 512px;
        opacity: 0.30;
        mix-blend-mode: screen;
        filter: brightness(2.1) contrast(1.32) saturate(1.1);
        pointer-events: none;
        z-index: 0;
      }
      @media (prefers-reduced-motion: no-preference) {
        body::before { animation: bcGridDrift 52s linear infinite; }
        @keyframes bcGridDrift {
          from { background-position: 0 0; }
          to { background-position: 240px 120px; }
        }
      }
      .card {
        max-width: 1100px;
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
        height: clamp(140px, 18vw, 240px);
        background:
          linear-gradient(180deg, rgba(11, 15, 23, 0.00), rgba(11, 15, 23, 0.86)),
          url("/_blackcat/assets/hero-banner.png") left center / cover no-repeat;
        border-bottom: 1px solid rgba(31, 42, 68, 0.95);
      }
      .body { padding: 14px 16px 16px; }
      h1 { margin: 0; font-size: 26px; letter-spacing: 0.2px; }
      .muted { color: #9fb0d0; }
      .lead { margin: 6px 0 0; }
      .head { display: flex; gap: 14px; align-items: center; }
      .mascot {
        flex: 0 0 auto;
        width: 96px;
        height: 96px;
        border-radius: 16px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.35);
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 18px 60px rgba(0, 0, 0, 0.35);
      }
      .mascot img { width: 92%; height: 92%; object-fit: contain; }
      .row { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; }
      .pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        background: rgba(18, 32, 66, 0.8);
        border: 1px solid rgba(31, 42, 68, 0.95);
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      }
      .pill.ok { background: rgba(118, 227, 157, 0.12); border-color: rgba(118, 227, 157, 0.28); color: #76e39d; }
      .pill.bad { background: rgba(255, 123, 114, 0.12); border-color: rgba(255, 123, 114, 0.28); color: #ff7b72; }
      .pill.warn { background: rgba(255, 212, 107, 0.12); border-color: rgba(255, 212, 107, 0.28); color: #ffd46b; }
      .box {
        margin-top: 12px;
        padding: 12px 14px;
        border-radius: 14px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.55);
      }
      code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      pre { margin: 10px 0 0; overflow: auto; }
      a { color: #8ab4ff; }
      .grid2 { display: grid; grid-template-columns: 1fr; gap: 10px; }
      @media (min-width: 980px) { .grid2 { grid-template-columns: 1fr 1fr; } }
    </style>
  </head>
  <body>
    <main class="card">
      <div class="banner" aria-hidden="true"></div>
      <div class="body">
        <div class="head">
          {$mascotHtml}
          <div>
            <h1>{$title} {$badgeHtml}</h1>
            <p class="muted lead">{$leadHtml}</p>
          </div>
        </div>
        {$bodyHtml}
      </div>
    </main>
  </body>
</html>
HTML;
        };

        $isTrusted = $status->trustedNow;
        $trustedBadge = $isTrusted ? '<span class="pill ok">trusted</span>' : '<span class="pill bad">untrusted</span>';
        $enforcementBadge = $status->enforcement === 'strict'
            ? '<span class="pill warn">strict</span>'
            : '<span class="pill">warn</span>';

        $extraBadges = '<div class="row">'
            . $trustedBadge
            . $enforcementBadge
            . ($status->rpcOkNow ? '<span class="pill ok">rpc ok</span>' : '<span class="pill bad">rpc error</span>')
            . ($status->readAllowed ? '<span class="pill ok">read allowed</span>' : '<span class="pill bad">read blocked</span>')
            . ($status->writeAllowed ? '<span class="pill ok">write allowed</span>' : '<span class="pill bad">write blocked</span>')
            . '</div>';

        $setupAvailable = is_file($setupPath) && !is_file($stateDir . DIRECTORY_SEPARATOR . 'installed.flag');

        if ($status->enforcement === 'strict' && !$status->readAllowed) {
            $codes = $status->errorCodes;
            $codeHtml = $codes !== []
                ? '<div class="box"><strong>Trust errors:</strong><ul><li><code>' . implode('</code></li><li><code>', array_map(static fn (string $c): string => htmlspecialchars($c, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), $codes)) . '</code></li></ul></div>'
                : '<div class="box"><strong>Trust errors:</strong> <span class="muted">none</span></div>';

            $actions = '<div class="box"><strong>What happens now:</strong><ul>'
                . '<li>BlackCat denies sensitive operations and blocks the request entry in <strong>strict</strong> mode.</li>'
                . '<li>This prevents secret exfiltration / DB writes during tamper or RPC outage.</li>'
                . '</ul></div>';

            $fixes = '<div class="box"><strong>How to fix:</strong><ul>'
                . '<li>Restore integrity (remove unexpected files, revert tampered changes).</li>'
                . '<li>Ensure your RPC quorum is healthy (multiple endpoints recommended).</li>'
                . ($setupAvailable ? '<li>Open <code>/_blackcat/setup</code> (maintenance only) to review and re-attest the release root.</li>' : '<li>If setup is disabled, fix files and redeploy a trusted bundle.</li>')
                . '</ul></div>';

            $lead = 'Your instance is currently <strong>untrusted</strong>. This is a fail-closed security kernel: it blocks writes and sensitive operations until integrity is restored.';

            $render = $extraBadges . '<div class="grid2">' . $actions . $fixes . '</div>' . $codeHtml;
            $mascot = '/_blackcat/assets/fatal-error-cat.png';
            foreach ($codes as $c) {
                if (str_contains($c, 'paused')) {
                    $mascot = '/_blackcat/assets/kernel-paused-cat.png';
                    break;
                }
                if (str_starts_with($c, 'integrity_')) {
                    $mascot = '/_blackcat/assets/integrity-tamper-cat.png';
                    break;
                }
                if (str_starts_with($c, 'rpc_')) {
                    $mascot = '/_blackcat/assets/rpc-outage-cat.png';
                    break;
                }
            }

            $renderShell(503, 'BlackCat Kernel', '<span class="pill bad">fail-closed</span>', $lead, $render, $mascot);
            return;
        }

        if ($path !== '/' && $path !== '/index.php') {
            $lead = 'This is a <strong>kernel-minimal</strong> bundle template. Only the front controller and setup module are present.';
            $body = $extraBadges
                . '<div class="box"><strong>Try:</strong><ul>'
                . '<li><a href="/">/</a> — kernel status</li>'
                . '<li><a href="/health">/health</a> — monitoring JSON</li>'
                . ($setupAvailable ? '<li><a href="/_blackcat/setup">/_blackcat/setup</a> — Stage 3 installer</li>' : '')
                . '</ul></div>';

            $renderShell(404, 'BlackCat Kernel', '<span class="pill warn">404</span>', $lead, $body, '/_blackcat/assets/not-found-cat.png');
            return;
        }

        $controller = htmlspecialchars($ctx->kernel->instanceControllerAddress(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $configLabel = $isDevHost
            ? $configPath
            : 'config.runtime.json (bundle root)';
        $lead = 'Your kernel is running. In production, BlackCat enforces <strong>HTTPS-only</strong>, strict runtime hardening, and <strong>Web3-backed integrity</strong> checks.';
        $body = $extraBadges
            . '<div class="grid2">'
            . '<div class="box"><strong>On-chain anchor:</strong><div class="muted">Instance controller</div><div><code>' . $controller . '</code></div></div>'
            . '<div class="box"><strong>Runtime config:</strong><div class="muted">Source file</div><div><code>' . htmlspecialchars($configLabel, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code></div></div>'
            . '</div>'
            . '<div class="box"><strong>Next steps:</strong><ul>'
            . '<li>Deploy your application behind this front controller (keep a single HTTP entrypoint).</li>'
            . '<li>Keep <code>vendor/</code> read-only and lock down file write permissions.</li>'
            . '<li>Use a second RPC endpoint + quorum for production reliability.</li>'
            . '</ul></div>';

        if ($setupAvailable) {
            $body .= '<div class="box"><strong>Security note:</strong> the installer increases attack surface. After setup, create <code>.blackcat/installed.flag</code> or remove the setup module.</div>';
        }

        $renderShell(200, 'BlackCat Kernel', '<span class="pill ok">online</span>', $lead, $body);
    },
    $_SERVER,
    $kernelOptions,
);
