<?php

declare(strict_types=1);

// Optional: shared fail-closed error page UI (no Composer dependency).
// Keep the bundle resilient even if vendor/ is missing.
$__blackcatErrorUi = __DIR__ . DIRECTORY_SEPARATOR . 'error-ui.php';
if (is_file($__blackcatErrorUi)) {
    /** @noinspection PhpIncludeInspection */
    require_once $__blackcatErrorUi;
}

use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Config\Runtime\RuntimeConfigInstaller;
use BlackCat\Config\Security\KernelAttestations;
use BlackCat\Core\TrustKernel\Bytes32;
use BlackCat\Core\TrustKernel\IntegrityManifestBuilder;
use BlackCat\Core\TrustKernel\TrustPolicyV3;

/**
 * Stage 3 one-time setup handler (template).
 *
 * Security model:
 * - Setup is gated by an install token stored under `<bundle>/.blackcat/install.token`.
 * - Setup can be disabled permanently by creating `<bundle>/.blackcat/installed.flag`.
 * - The setup UI is served only from the front controller (never as a direct PHP entrypoint).
 */

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_handle(array $paths): void
{
    $path = blackcat_request_path();
    if ($path === '/_blackcat/setup') {
        blackcat_setup_page($paths);
        return;
    }

    if (str_starts_with($path, '/_blackcat/setup/api/')) {
        blackcat_setup_api($paths, substr($path, strlen('/_blackcat/setup/api/')));
        return;
    }

    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Not found.\n";
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_page(array $paths): void
{
    if (blackcat_setup_is_disabled($paths['state_dir'])) {
        // Installer is intentionally unavailable after install (minimize web attack surface).
        // Use signed upgrade tooling instead of reopening setup.
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Not found.\n";
        exit;
    }

    if (!blackcat_is_https_request()) {
        http_response_code(400);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

        $gridHtml = <<<'HTML'
            <div class="panel">
              <strong>Do this:</strong>
              <ol>
                <li>Enable HTTPS (recommended: Let’s Encrypt).</li>
                <li>If you use a reverse proxy, forward the original scheme (<code>Forwarded: proto=https</code> or <code>X-Forwarded-Proto: https</code>) — only trusted local peers are honored.</li>
                <li>Reload via <code>https://</code> and open <code>/_blackcat/setup</code> again.</li>
              </ol>
            </div>
            <div class="panel">
              <strong>Why BlackCat blocks HTTP:</strong>
              <ul class="muted">
                <li>HTTP can be downgraded or intercepted (MITM).</li>
                <li>Setup handles secrets + approvals; a single unsafe request can compromise the system.</li>
                <li>Fail-closed is intentional: no “click-through” bypass.</li>
              </ul>
              <div class="footer warn">Tip: after install, BlackCat disables setup by default. You can also delete the setup module for zero web attack surface.</div>
            </div>
HTML;

        if (function_exists('blackcat_error_ui_render_page')) {
            echo blackcat_error_ui_render_page([
                'title' => 'BlackCat Setup — HTTPS Required',
                'h1_prefix' => 'BlackCat Setup',
                'pill' => 'HTTPS only',
                'lede_html' => '<strong>Plain HTTP is not allowed.</strong> Setup is a high-trust operation (install token + wallet approvals). BlackCat blocks it over HTTP to prevent downgrade and MITM attacks.',
                'grid_html' => $gridHtml,
                'style_vars' => [
                    'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                    'mascot_primary_url' => '/_blackcat/assets/fatal-error-cat.png',
                ],
            ]);
        } else {
            echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — HTTPS Required</title><h1>HTTPS required</h1>';
        }
        exit;
    }

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!is_string($method) || !in_array(strtoupper(trim($method)), ['GET', 'HEAD'], true)) {
        http_response_code(405);
        header('Allow: GET, HEAD');
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

        $gridHtml = <<<'HTML'
            <div class="panel">
              <strong>Allowed on this endpoint:</strong>
              <ul>
                <li><code>GET</code></li>
                <li><code>HEAD</code></li>
              </ul>
            </div>
            <div class="panel">
              <strong>What to do:</strong>
              <ul class="muted">
                <li>Retry with <code>GET</code> (open <code>/_blackcat/setup</code> in a browser).</li>
                <li>For scripts and automation, use <code>/_blackcat/setup/api/*</code>.</li>
              </ul>
            </div>
HTML;

        if (function_exists('blackcat_error_ui_render_page')) {
            echo blackcat_error_ui_render_page([
                'title' => 'BlackCat Setup — Method Not Allowed',
                'h1_prefix' => 'BlackCat Setup',
                'pill' => 'method not allowed',
                'lede_html' => '<strong>This endpoint is read-only.</strong> Only <code>GET</code>/<code>HEAD</code> are accepted here. For actions, use the setup API endpoints.',
                'grid_html' => $gridHtml,
                'style_vars' => [
                    'accent_rgb' => '255, 212, 107',
                    'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                    'mascot_primary_url' => '/_blackcat/assets/method-not-allowed-cat.png',
                ],
            ]);
        } else {
            echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Method Not Allowed</title><h1>Method not allowed</h1>';
        }
        exit;
    }

    $stateDir = $paths['state_dir'];
    blackcat_ensure_state_dir($stateDir);
    if (!is_dir($stateDir)) {
        blackcat_setup_render_preflight_page($paths, [
            'Unable to create state directory (.blackcat). Fix permissions and reload.',
        ], []);
        exit;
    }

    $preflight = blackcat_setup_preflight($paths);
    if ($preflight['errors'] !== []) {
        blackcat_setup_render_preflight_page($paths, $preflight['errors'], $preflight['warnings']);
        exit;
    }

    $tlsGate = blackcat_setup_tls_gate($stateDir);
    if ($tlsGate['mode'] === 'prod' && $tlsGate['trusted'] !== true) {
        blackcat_setup_render_tls_not_trusted_page($tlsGate);
        exit;
    }

    $tokenPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.token';
    if (!is_file($tokenPath)) {
        $token = bin2hex(random_bytes(32));
        $written = @file_put_contents($tokenPath, $token . "\n");
        if ($written === false || !is_file($tokenPath)) {
            blackcat_setup_render_preflight_page($paths, [
                'Unable to write .blackcat/install.token (permissions or disk error). Fix and reload.',
            ], $preflight['warnings']);
            exit;
        }
        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($tokenPath, 0600);
        }
    }

    $tlsBarHtml = '';
    if ($tlsGate['mode'] === 'dev' && $tlsGate['trusted'] !== true) {
        $tlsBarHtml = '<div class="tlsBar" role="status">'
            . '<strong>DEV WARNING:</strong> TLS certificate is not publicly trusted. '
            . 'Do <strong>not</strong> use this mode in production. Install a CA-trusted certificate (e.g., Let’s Encrypt) and reload. '
            . '</div>';
    }

    $nonce = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    if ($tlsGate['mode'] === 'prod' && $tlsGate['trusted'] === true) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
    header(
        "Content-Security-Policy: default-src 'none'; "
        . "script-src 'nonce-{$nonce}'; "
        . "script-src-attr 'none'; "
        . "connect-src 'self'; "
        . "img-src 'self' data:; "
        . "style-src 'unsafe-inline'; "
        . "base-uri 'none'; "
        . "form-action 'none'; "
        . "frame-ancestors 'none'"
    );
    $assetDir = rtrim($paths['site_dir'], "/\\") . DIRECTORY_SEPARATOR . '_blackcat' . DIRECTORY_SEPARATOR . 'asset';
    $trustIllustrationPath = $assetDir . DIRECTORY_SEPARATOR . 'trusted-vs-untrusted.png';
    $trustIllustrationHtml = '';
    if (is_file($trustIllustrationPath)) {
        $trustIllustrationHtml = '<div class="illustration">'
            . '<img src="/_blackcat/assets/trusted-vs-untrusted.png" alt="Trusted vs untrusted (release trust + integrity)" loading="lazy" />'
            . '<div class="cap">'
            . '<strong>Trusted vs Untrusted:</strong> a trusted release root lets production stay <span class="ok">trusted</span>. '
            . 'Unexpected changes flip the kernel to <span class="bad">untrusted</span> and enforce fail-closed in strict mode.'
            . '</div>'
            . '</div>';
    }

    $page = <<<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat Setup</title>
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <style>
      :root { color-scheme: dark; }

      body {
        margin: 0;
        padding: 24px;
        font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        position: relative;
        isolation: isolate;
        background:
          radial-gradient(900px 420px at 20% 0%, rgba(86, 116, 255, 0.18), transparent 55%),
          radial-gradient(900px 420px at 80% 0%, rgba(118, 227, 157, 0.12), transparent 60%),
          #0b0f17;
        color: #e7eefc;
      }
      body::before {
        content: "";
        position: fixed;
        inset: 0;
        background: url("/_blackcat/assets/bg-grid.png") repeat;
        background-size: 512px 512px;
        opacity: 0.34;
        mix-blend-mode: screen;
        filter: brightness(2.2) contrast(1.35) saturate(1.15);
        pointer-events: none;
        z-index: 1;
      }
      body::after {
        content: "";
        position: fixed;
        inset: -20%;
        background:
          radial-gradient(circle at 18% 18%, rgba(86, 116, 255, 0.18), transparent 52%),
          radial-gradient(circle at 82% 28%, rgba(118, 227, 157, 0.12), transparent 54%),
          radial-gradient(circle at 55% 85%, rgba(255, 212, 107, 0.08), transparent 56%);
        filter: blur(56px) saturate(1.06);
        opacity: 0.38;
        pointer-events: none;
        z-index: 0;
      }
      @media (prefers-reduced-motion: no-preference) {
        body::before { animation: bcGridDrift 52s linear infinite; }
        body::after { animation: bcAuroraDrift 54s ease-in-out infinite alternate; }
        @keyframes bcGridDrift {
          from { background-position: 0 0; }
          to { background-position: 240px 120px; }
        }
        @keyframes bcAuroraDrift {
          from { transform: translate3d(-0.6%, -0.4%, 0) scale(1.02); }
          to { transform: translate3d(0.9%, 0.8%, 0) scale(1.05); }
        }
      }

      a { color: #8ab4ff; }
      code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      pre { background: rgba(15, 21, 36, 0.8); border: 1px solid #1f2a44; padding: 12px; border-radius: 12px; overflow: auto; }

      .wrap { max-width: 1180px; margin: 0 auto; position: relative; z-index: 2; }

      .hero {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 12px;
        padding: 18px 18px;
        border-radius: 16px;
        border: 1px solid rgba(42, 59, 99, 0.9);
        background:
          linear-gradient(180deg, rgba(15, 21, 36, 0.86), rgba(15, 21, 36, 0.62)),
          url("/_blackcat/assets/hero-banner.png") center / cover no-repeat;
        box-shadow: 0 20px 70px rgba(0, 0, 0, 0.35);
        margin: 4px 0 16px;
      }

      .heroTitle { margin: 0; font-size: 26px; letter-spacing: 0.2px; }
      .heroSub { margin: 6px 0 0; }
      .heroBadges { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; margin-top: 2px; }
      .heroDetails { margin-top: 10px; }
      .heroDetails summary { cursor: pointer; user-select: none; }
      .heroDetails summary::-webkit-details-marker { display: none; }
      .heroDetails summary::before { content: "▸"; display: inline-block; margin-right: 8px; color: #9fb0d0; }
      .heroDetails[open] summary::before { content: "▾"; }
      .heroDetails ul { margin: 8px 0 0 18px; padding: 0; }
      .heroDetails li { margin: 3px 0; }

      .illustration {
        margin-top: 12px;
        border-radius: 14px;
        overflow: hidden;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.35);
      }
      .illustration img { display: block; width: 100%; height: auto; }
      .illustration .cap {
        padding: 10px 12px;
        font-size: 12px;
        color: #9fb0d0;
        border-top: 1px solid rgba(31, 42, 68, 0.95);
      }

      .card {
        position: relative;
        border: 1px solid rgba(31, 42, 68, 0.82);
        border-radius: 16px;
        padding: 16px;
        margin: 12px 0;
        background:
          radial-gradient(900px 420px at 18% 0%, rgba(255, 255, 255, 0.06), transparent 62%),
          radial-gradient(900px 420px at 82% 0%, rgba(86, 116, 255, 0.09), transparent 66%),
          linear-gradient(180deg, rgba(15, 21, 36, 0.52), rgba(15, 21, 36, 0.22));
        backdrop-filter: blur(18px) saturate(1.25);
        -webkit-backdrop-filter: blur(18px) saturate(1.25);
        box-shadow:
          0 20px 70px rgba(0, 0, 0, 0.30),
          0 0 0 1px rgba(86, 116, 255, 0.08),
          inset 0 1px 0 rgba(255, 255, 255, 0.10),
          inset 0 -24px 40px rgba(0, 0, 0, 0.18);
        overflow: hidden;
      }
      .card::before {
        content: "";
        position: absolute;
        inset: -1px;
        background:
          radial-gradient(420px 180px at 18% 0%, rgba(86, 116, 255, 0.10), transparent 70%),
          radial-gradient(420px 180px at 82% 0%, rgba(118, 227, 157, 0.09), transparent 70%),
          linear-gradient(180deg, rgba(255, 255, 255, 0.06), transparent 42%);
        opacity: 0.48;
        pointer-events: none;
      }
      .card > * { position: relative; z-index: 1; }

      .row { display: flex; gap: 12px; flex-wrap: wrap; }
      .row > * { flex: 1 1 320px; }

      .ok { color: #76e39d; }
      .bad { color: #ff7b72; }
      .muted { color: #9fb0d0; }
      .warn { color: #ffd46b; }

      button {
        background: linear-gradient(180deg, #22345f, #162342);
        color: #e7eefc;
        border: 1px solid #2a3b63;
        border-radius: 12px;
        padding: 10px 12px;
        cursor: pointer;
        transition: transform .04s ease, background .15s ease, border-color .15s ease, opacity .15s ease;
      }
      button:hover { background: linear-gradient(180deg, #29406f, #1a2a4f); border-color: #355084; }
      button:active { transform: translateY(1px); }
      button:disabled { opacity: 0.55; cursor: not-allowed; }

      input, textarea, select {
        width: 100%;
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid #2a3b63;
        background: rgba(11, 15, 23, 0.72);
        color: #e7eefc;
        outline: none;
      }
      input:focus, textarea:focus, select:focus { border-color: #5674ff; box-shadow: 0 0 0 3px rgba(86, 116, 255, 0.18); }
      textarea { min-height: 96px; }

      .grid { display: grid; grid-template-columns: 1fr; gap: 10px; }
      @media (min-width: 980px) { .grid { grid-template-columns: 1fr 1fr; } }

      .k { font-weight: 650; }

      .pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        background: rgba(18, 32, 66, 0.8);
        border: 1px solid rgba(31, 42, 68, 0.95);
      }
      .pill.ok { background: rgba(118, 227, 157, 0.12); border-color: rgba(118, 227, 157, 0.28); color: #76e39d; }
      .pill.bad { background: rgba(255, 123, 114, 0.12); border-color: rgba(255, 123, 114, 0.28); color: #ff7b72; }

      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      .small { font-size: 12px; }

      .tlsBar {
        position: fixed;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 9999;
        padding: 10px 14px;
        background: rgba(255, 123, 114, 0.14);
        border-top: 1px solid rgba(255, 123, 114, 0.35);
        color: #ffb4ae;
        text-align: center;
        backdrop-filter: blur(10px);
      }
      .tlsBar strong { color: #ff7b72; }
    </style>
  </head>
  <body>
	    <div class="wrap">
	      <header class="hero">
	        <div>
	          <h1 class="heroTitle">BlackCat Setup <span class="pill mono">Kernel Minimal</span></h1>
	          <p class="heroSub muted">FTP-friendly installer for hosting environments where you can’t run Composer on the server. It bootstraps TrustKernel (Web3-backed integrity) and writes strict runtime config.</p>
	          <details class="heroDetails">
	            <summary class="muted">What is “Stage 3”?</summary>
	            <div class="small muted">
	              Stage 3 is the <strong>kernel-minimal</strong> bootstrap: upload a prebuilt bundle, verify integrity, register it on-chain, then permanently disable the installer.
	            </div>
	            <ul class="small muted">
	              <li><span class="mono">No</span> server-side private keys.</li>
	              <li><span class="mono">No</span> Composer required on the server.</li>
	              <li>Production is <strong>fail-closed</strong> on untrusted TLS + integrity mismatches.</li>
	            </ul>
	          </details>
	        </div>
	        <div class="heroBadges">
	          <span class="pill mono">HTTPS required</span>
	          <span class="pill mono">Stage 3</span>
	          <span class="pill mono">No server keys</span>
	          <span class="pill mono">ReleaseRegistry</span>
	          <span class="pill mono">Wallet-signed</span>
	          <span class="pill mono">Edgen 4207</span>
	        </div>
	      </header>

    <div class="card">
      <h2>1) Unlock installer</h2>
      <p>For safety, setup is gated by an <strong>install token</strong> stored outside web docroot:</p>
      <pre><code>.blackcat/install.token</code></pre>
      <p>Open it via FTP/SFTP (same place you uploaded this bundle) and paste the token below.</p>
      <div class="row">
        <div>
          <input id="token" placeholder="paste install token here" autocomplete="off" />
        </div>
        <div style="flex: 0 0 220px">
          <button id="saveToken">Save token</button>
          <button id="clearToken" style="margin-left:8px">Clear</button>
        </div>
      </div>
      <p id="tokenStatus" class="muted"></p>
    </div>

    <div class="grid">
      <div class="card">
        <h2>2) Build integrity manifest</h2>
        <p>This scans <code>site/</code> (immutable code root) and writes:</p>
        <pre><code>.blackcat/integrity.manifest.json</code></pre>
        <div class="row">
          <div style="flex: 0 0 220px">
            <button id="buildManifest">Build manifest</button>
            <button id="verifyRelease" style="margin-left:8px">Verify release root</button>
          </div>
          <div>
            <div class="small muted">Release trust: <span id="releaseTrust" class="pill mono">unknown</span></div>
            <div class="small muted">
              Registry:
              <a id="releaseRegistryLink" href="https://edgenscan.io" target="_blank" rel="noreferrer">open explorer</a>
            </div>
          </div>
        </div>
        __BLACKCAT_TRUST_ILLUSTRATION__
        <pre id="manifestOut" style="display:none"></pre>
        <pre id="releaseOut" style="display:none"></pre>
      </div>

	      <div class="card">
	        <h2>3) On-chain: create InstanceController</h2>
	        <p class="muted">No private keys are stored on the server. Broadcast from <strong>any</strong> EVM wallet (hardware wallet recommended): browser wallet (MetaMask/Rabby), explorer “Write contract”, or CLI (cast).</p>
	        <p class="small muted">Network: <span class="mono">Edgen Chain</span> (<span class="mono">chain_id=4207</span>)</p>
	        <p class="small muted"><strong>Option A:</strong> use a browser wallet (below). <strong>Option B:</strong> click <span class="mono">Generate tx intent (manual)</span> and send from another device / hardware wallet.</p>

        <div class="row">
          <div>
            <label class="k">Wallet</label>
            <div class="small muted">Account: <span id="walletAccount" class="mono">not connected</span></div>
            <div class="small muted">Chain: <span id="walletChain" class="mono">unknown</span></div>
	          </div>
	          <div style="flex: 0 0 240px">
	            <button id="connectWallet">Connect browser wallet</button>
	            <button id="switchChain" style="margin-left:8px">Switch/Add chain</button>
	          </div>
	        </div>

        <div class="row">
          <div>
            <label class="k">InstanceFactory address</label>
            <input id="instanceFactory" placeholder="0x..." autocomplete="off" readonly />
            <div class="small muted">This factory is also the on-chain registry of trusted installations (<span class="mono">isInstance</span>).</div>
          </div>
          <div>
            <label class="k">ReleaseRegistry address</label>
            <input id="releaseRegistry" placeholder="0x..." autocomplete="off" readonly />
            <div class="small muted">Must already trust your bundle root (official releases are published by the registry owner).</div>
          </div>
        </div>

        <div class="row">
          <div>
            <label class="k">Root authority (cold wallet recommended)</label>
            <input id="rootAuthority" placeholder="0x..." autocomplete="off" />
          </div>
          <div>
            <label class="k">Upgrade authority</label>
            <input id="upgradeAuthority" placeholder="0x..." autocomplete="off" />
          </div>
        </div>
        <div class="row">
          <div>
            <label class="k">Emergency authority</label>
            <input id="emergencyAuthority" placeholder="0x..." autocomplete="off" />
          </div>
          <div>
            <label class="k">Enforcement</label>
            <select id="enforcement">
              <option value="strict" selected>strict (production)</option>
              <option value="less-strict">less-strict (hosting waiver)</option>
              <option value="warn">warn (dev/compat)</option>
            </select>
            <div class="small muted">Enforcement is committed on-chain via the policy hash.</div>
          </div>
        </div>

        <div class="row">
          <div>
            <label class="k">Policy hash (v3)</label>
            <input id="policyHash" placeholder="0x... (computed)" autocomplete="off" readonly />
          </div>
          <div>
            <label class="k">Policy version</label>
            <div class="small muted"><span class="mono">v3</span> (runtime-config attestation)</div>
          </div>
        </div>

	        <p class="small muted">This step will create a new InstanceController bound to: <span class="mono">manifest.root</span> + <span class="mono">manifest.uri_hash</span> + <span class="mono">policy_hash_v3</span> (selected enforcement).</p>
	        <button id="computePolicy">Compute policy hash</button>
	        <button id="createInstance" style="margin-left:8px">Broadcast create tx (browser wallet)</button>
	        <button id="createInstanceManual" style="margin-left:8px">Generate tx intent (manual)</button>
	        <pre id="chainOut" style="display:none"></pre>
	      </div>

      <div class="card">
        <h2>4) Write runtime config</h2>
        <p>Writes:</p>
        <pre><code>config.runtime.json</code></pre>
        <div class="row">
          <div>
            <label class="k">InstanceController address</label>
            <input id="instanceController" placeholder="0x..." autocomplete="off" />
          </div>
          <div>
            <label class="k">RPC quorum</label>
            <input id="rpcQuorum" type="number" min="1" value="2" />
          </div>
        </div>
        <label class="k">RPC endpoints (one per line, HTTPS)</label>
        <textarea id="rpcEndpoints" spellcheck="false"></textarea>
        <div class="row">
          <div>
            <label class="k">Trust mode</label>
            <select id="trustMode">
              <option value="full" selected>full (recommended)</option>
              <option value="root_uri">root_uri</option>
            </select>
          </div>
          <div>
            <label class="k">max_stale_sec</label>
            <input id="maxStale" type="number" min="1" value="180" />
          </div>
        </div>
        <label class="k">Allowed hosts (optional, one per line)</label>
        <textarea id="allowedHosts" spellcheck="false" placeholder="example.com&#10;*.example.com"></textarea>
        <button id="writeConfig">Write config</button>
        <pre id="configOut" style="display:none"></pre>
      </div>
    </div>

	    <div class="card">
	      <h2>5) On-chain: lock runtime-config attestation</h2>
	      <p class="muted">After writing <code>config.runtime.json</code>, lock the runtime config attestation on-chain:</p>
	      <div class="small muted">Required signer: <span class="mono">rootAuthority</span></div>
	      <div class="small muted"><strong>Option A:</strong> broadcast via browser wallet. <strong>Option B:</strong> generate tx intent and sign elsewhere.</div>
	      <button id="lockAttestation">Broadcast lock tx (browser wallet)</button>
	      <button id="lockAttestationManual" style="margin-left:8px">Generate tx intent (manual)</button>
	      <pre id="attOut" style="display:none"></pre>
	    </div>

	    <div class="card">
	      <h2>6) Disable installer</h2>
	      <p>When everything is working, permanently disable this setup UI (recommended for production).</p>
	      <button id="finish">Create installed.flag (disable setup)</button>
	      <pre id="finishOut" style="display:none"></pre>
	    </div>

      <script src="/_blackcat/ethers.umd.min.js" nonce="__BLACKCAT_CSP_NONCE__"></script>
      <script nonce="__BLACKCAT_CSP_NONCE__">
      const $ = (id) => document.getElementById(id);
      const api = async (path, opts = {}) => {
        const token = localStorage.getItem("bc_install_token") || "";
        const headers = Object.assign({ "Accept": "application/json" }, opts.headers || {});
        if (token) headers["X-BlackCat-Install-Token"] = token;
        const res = await fetch(path, Object.assign({}, opts, { headers }));
        const text = await res.text();
        let data = null;
        try { data = JSON.parse(text); } catch (e) { data = { ok: false, error: "non-json response", raw: text }; }
        if (!res.ok) return Object.assign({ http_status: res.status }, data);
        return data;
      };

      const refreshStatus = async () => {
        const token = localStorage.getItem("bc_install_token") || "";
        $("token").value = token;
        $("tokenStatus").textContent = token ? "Token saved in this browser." : "Token not set yet.";

        const st = await api("/_blackcat/setup/api/status");
        if (st && st.ok) {
          if (st.suggested && st.suggested.rpc_endpoints) {
            $("rpcEndpoints").value = st.suggested.rpc_endpoints.join("\\n");
          }
          if (st.suggested && st.suggested.allowed_hosts) {
            $("allowedHosts").value = st.suggested.allowed_hosts.join("\\n");
          }
          if (st.summary && st.summary.root) {
            // Best-effort: show root in the manifest output panel for convenience.
            $("manifestOut").style.display = "block";
            $("manifestOut").textContent = JSON.stringify(st.summary, null, 2);
          }
        }
      };

      const CHAIN_ID_DEC = 4207;
      const CHAIN_ID_HEX = "0x106f";
      const DEFAULT_FACTORY = "0x92C80Cff5d75dcD3846EFb5DF35957D5Aed1c7C5";
      const DEFAULT_REGISTRY = "0x22681Ee2153B7B25bA6772B44c160BB60f4C333E";
      const EXPLORER_BASE = "https://edgenscan.io";
      const DEFAULT_ENFORCEMENT = "__BLACKCAT_ENFORCEMENT__";

      const isHexAddress = (v) => typeof v === "string" && /^0x[a-fA-F0-9]{40}$/.test(v.trim());
      const isBytes32 = (v) => typeof v === "string" && /^0x[a-fA-F0-9]{64}$/.test(v.trim());

      const wallet = {
        provider: null,
        signer: null,
        account: null,
        chainId: null,
      };

      const setWalletUi = () => {
        $("walletAccount").textContent = wallet.account || "not connected";
        $("walletChain").textContent = wallet.chainId ? `${wallet.chainId}` : "unknown";
      };

	      const requireEthereum = () => {
	        const eth = window.ethereum;
	        if (!eth || !eth.request) {
	          throw new Error("Browser wallet not found (window.ethereum). Install MetaMask/Rabby (or use the manual tx intent buttons).");
	        }
	        if (!window.ethers) {
	          throw new Error("ethers.js failed to load. Ensure /_blackcat/ethers.umd.min.js is reachable.");
	        }
	        return eth;
	      };

      const connectWallet = async () => {
        const eth = requireEthereum();
        await eth.request({ method: "eth_requestAccounts" });
        wallet.provider = new window.ethers.providers.Web3Provider(eth, "any");
        wallet.signer = wallet.provider.getSigner();
        wallet.account = (await wallet.signer.getAddress()) || null;
        wallet.chainId = (await wallet.provider.getNetwork()).chainId || null;
        setWalletUi();

        // Default authorities to the connected account (user can override).
        if (wallet.account && isHexAddress(wallet.account)) {
          if (!isHexAddress($("rootAuthority").value)) $("rootAuthority").value = wallet.account;
          if (!isHexAddress($("upgradeAuthority").value)) $("upgradeAuthority").value = wallet.account;
          if (!isHexAddress($("emergencyAuthority").value)) $("emergencyAuthority").value = wallet.account;
          saveAuthorities();
        }
      };

      const ensureChain = async () => {
        const eth = requireEthereum();
        try {
          await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_ID_HEX }] });
        } catch (e) {
          // 4902 = unknown chain
          const code = e && typeof e === "object" ? e.code : null;
          if (code !== 4902) throw e;
          await eth.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: CHAIN_ID_HEX,
                chainName: "Edgen Chain",
                rpcUrls: ["https://rpc.layeredge.io"],
                nativeCurrency: { name: "EDGEN", symbol: "EDGEN", decimals: 18 },
                blockExplorerUrls: ["https://edgenscan.io"],
              },
            ],
          });
        }

        if (wallet.provider) {
          wallet.chainId = (await wallet.provider.getNetwork()).chainId || null;
          setWalletUi();
        }
      };

      const readManifestSummary = async () => {
        const st = await api("/_blackcat/setup/api/status");
        if (!st || !st.ok) throw new Error(st && st.error ? st.error : "Unable to read /status");
        if (!st.summary || !st.summary.root || !st.summary.uri_hash) {
          throw new Error("Missing manifest summary. Run 'Build manifest' first.");
        }
        const root = String(st.summary.root || "").trim();
        const uriHash = String(st.summary.uri_hash || "").trim();
        if (!isBytes32(root) || !isBytes32(uriHash)) throw new Error("Invalid manifest summary bytes32 values.");
        return { root, uriHash };
      };

      const setReleaseRegistryLink = () => {
        const addr = $("releaseRegistry").value.trim();
        const href = isHexAddress(addr) ? `${EXPLORER_BASE}/address/${addr}` : EXPLORER_BASE;
        $("releaseRegistryLink").setAttribute("href", href);
      };

      const setReleaseTrustUi = (trusted, error = null) => {
        const el = $("releaseTrust");
        if (error) {
          el.textContent = "error";
          el.classList.remove("ok");
          el.classList.add("bad");
          el.setAttribute("title", String(error));
          $("createInstance").disabled = true;
          return;
        }
        if (trusted === true) {
          el.textContent = "trusted";
          el.classList.remove("bad");
          el.classList.add("ok");
          el.removeAttribute("title");
          $("createInstance").disabled = false;
          return;
        }
        if (trusted === false) {
          el.textContent = "untrusted";
          el.classList.remove("ok");
          el.classList.add("bad");
          el.setAttribute("title", "ReleaseRegistry does not trust this root (tampered/unpublished).");
          $("createInstance").disabled = true;
          return;
        }
        el.textContent = "unknown";
        el.classList.remove("ok");
        el.classList.remove("bad");
        el.removeAttribute("title");
        $("createInstance").disabled = true;
      };

      const verifyReleaseRoot = async () => {
        const { root } = await readManifestSummary();
        const registry = $("releaseRegistry").value.trim();
        if (!isHexAddress(registry)) throw new Error("Invalid ReleaseRegistry address.");

	        if (!wallet.provider) {
	          throw new Error("Connect a browser wallet first to verify on-chain release trust (or verify in the block explorer).");
	        }
	        if (wallet.chainId !== CHAIN_ID_DEC) {
	          throw new Error("Switch to Edgen Chain (chain_id=4207) first.");
	        }

        const registryAbi = [
          "function isTrustedRoot(bytes32 root) view returns (bool)",
        ];
        const rr = new window.ethers.Contract(registry, registryAbi, wallet.provider);
        const ok = await rr.isTrustedRoot(root);
        setReleaseTrustUi(Boolean(ok));
        return Boolean(ok);
      };

      const normalizeEnforcement = (raw) => {
        const v = (typeof raw === "string" ? raw : "").trim();
        if (v === "strict" || v === "less-strict" || v === "warn") return v;
        return "strict";
      };
      const getEnforcement = () => normalizeEnforcement($("enforcement").value);
      const loadEnforcement = () => {
        const fromUrl = normalizeEnforcement(DEFAULT_ENFORCEMENT);
        if (fromUrl !== "strict") return fromUrl;
        try {
          const raw = localStorage.getItem("bc_enforcement");
          if (raw) return normalizeEnforcement(raw);
        } catch (_) {}
        return fromUrl;
      };
      const applyEnforcement = () => {
        $("enforcement").value = loadEnforcement();
      };

      const computePolicyHash = async () => {
        const mode = $("trustMode").value;
        const maxStale = parseInt($("maxStale").value || "180", 10);
        const enforcement = getEnforcement();
        const res = await api("/_blackcat/setup/api/policy-v3", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode, max_stale_sec: maxStale, enforcement }),
        });
        if (!res || !res.ok) throw new Error(res && res.error ? res.error : "policy-v3 failed");
        const policyHash = res.policy_hash_v3 || res.policy_hash_v3_strict;
        if (!policyHash || !isBytes32(policyHash)) throw new Error("Invalid policy hash.");
        $("policyHash").value = policyHash;
        return policyHash;
      };

      const saveAuthorities = () => {
        const data = {
          root: $("rootAuthority").value.trim(),
          upgrade: $("upgradeAuthority").value.trim(),
          emergency: $("emergencyAuthority").value.trim(),
        };
        localStorage.setItem("bc_authorities", JSON.stringify(data));
      };
      const loadAuthorities = () => {
        try {
          const raw = localStorage.getItem("bc_authorities");
          if (!raw) return;
          const parsed = JSON.parse(raw);
          if (parsed && typeof parsed === "object") {
            if (typeof parsed.root === "string") $("rootAuthority").value = parsed.root;
            if (typeof parsed.upgrade === "string") $("upgradeAuthority").value = parsed.upgrade;
            if (typeof parsed.emergency === "string") $("emergencyAuthority").value = parsed.emergency;
          }
        } catch (_) {}
      };

      $("saveToken").addEventListener("click", async () => {
        const t = $("token").value.trim();
        if (!t) return;
        localStorage.setItem("bc_install_token", t);
        await refreshStatus();
      });

      $("rootAuthority").addEventListener("change", saveAuthorities);
      $("upgradeAuthority").addEventListener("change", saveAuthorities);
      $("emergencyAuthority").addEventListener("change", saveAuthorities);
      $("clearToken").addEventListener("click", async () => {
        localStorage.removeItem("bc_install_token");
        await refreshStatus();
      });

      $("buildManifest").addEventListener("click", async () => {
        $("manifestOut").style.display = "block";
        $("manifestOut").textContent = "Working...";
        $("releaseOut").style.display = "none";
        const res = await api("/_blackcat/setup/api/build-manifest", { method: "POST" });
        $("manifestOut").textContent = JSON.stringify(res, null, 2);
        setReleaseTrustUi(null);
        try {
          if (wallet.provider && wallet.chainId === CHAIN_ID_DEC) {
            const ok = await verifyReleaseRoot();
            $("releaseOut").style.display = "block";
            $("releaseOut").textContent = JSON.stringify({ ok: true, trusted: ok }, null, 2);
          }
        } catch (_) {
          // ignore here; user can click "Verify release root" after connecting wallet.
        }
      });

      $("verifyRelease").addEventListener("click", async () => {
        $("releaseOut").style.display = "block";
        $("releaseOut").textContent = "Working...";
        try {
          const ok = await verifyReleaseRoot();
          $("releaseOut").textContent = JSON.stringify({ ok: true, trusted: ok }, null, 2);
        } catch (e) {
          setReleaseTrustUi(null);
          $("releaseOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
        }
      });

      $("connectWallet").addEventListener("click", async () => {
        $("chainOut").style.display = "block";
        $("chainOut").textContent = "Working...";
        try {
          await connectWallet();
          setReleaseRegistryLink();
          if (wallet.chainId === CHAIN_ID_DEC) {
            try {
              const ok = await verifyReleaseRoot();
              $("releaseOut").style.display = "block";
              $("releaseOut").textContent = JSON.stringify({ ok: true, trusted: ok }, null, 2);
            } catch (_) {}
          }
          $("chainOut").textContent = JSON.stringify({ ok: true, account: wallet.account, chain_id: wallet.chainId }, null, 2);
        } catch (e) {
          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
        }
      });
      $("switchChain").addEventListener("click", async () => {
        $("chainOut").style.display = "block";
        $("chainOut").textContent = "Working...";
        try {
          await ensureChain();
          setReleaseRegistryLink();
          if (wallet.chainId === CHAIN_ID_DEC) {
            try {
              const ok = await verifyReleaseRoot();
              $("releaseOut").style.display = "block";
              $("releaseOut").textContent = JSON.stringify({ ok: true, trusted: ok }, null, 2);
            } catch (_) {}
          }
          $("chainOut").textContent = JSON.stringify({ ok: true, chain_id: wallet.chainId }, null, 2);
        } catch (e) {
          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
        }
      });

      $("computePolicy").addEventListener("click", async () => {
        $("chainOut").style.display = "block";
        $("chainOut").textContent = "Working...";
        try {
          const policy = await computePolicyHash();
          const enforcement = getEnforcement();
          $("chainOut").textContent = JSON.stringify({ ok: true, enforcement, policy_hash_v3: policy }, null, 2);
        } catch (e) {
          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
        }
      });

	      $("createInstance").addEventListener("click", async () => {
	        $("chainOut").style.display = "block";
	        $("chainOut").textContent = "Working...";
	        try {
	          if (!wallet.signer) await connectWallet();
          if (wallet.chainId !== CHAIN_ID_DEC) {
            await ensureChain();
            wallet.chainId = (await wallet.provider.getNetwork()).chainId || null;
            setWalletUi();
          }
          if (wallet.chainId !== CHAIN_ID_DEC) throw new Error("Wrong chain. Expected chain_id=4207 (Edgen).");

          const factoryAddress = $("instanceFactory").value.trim();
          if (!isHexAddress(factoryAddress)) throw new Error("Invalid InstanceFactory address.");
          const rootAuthority = $("rootAuthority").value.trim();
          const upgradeAuthority = $("upgradeAuthority").value.trim();
          const emergencyAuthority = $("emergencyAuthority").value.trim();
          if (!isHexAddress(rootAuthority)) throw new Error("Invalid root authority address.");
          if (!isHexAddress(upgradeAuthority)) throw new Error("Invalid upgrade authority address.");
          if (!isHexAddress(emergencyAuthority)) throw new Error("Invalid emergency authority address.");

          const { root, uriHash } = await readManifestSummary();
          const releaseOk = await verifyReleaseRoot();
          if (!releaseOk) {
            throw new Error("Release root is NOT trusted by ReleaseRegistry. Upload an official bundle or wait for the registry to be updated.");
          }
          const policyHash = await computePolicyHash();

          const factoryAbi = [
            "function createInstance(address rootAuthority,address upgradeAuthority,address emergencyAuthority,bytes32 genesisRoot,bytes32 genesisUriHash,bytes32 genesisPolicyHash) returns (address)",
            "event InstanceCreated(address indexed instance,address indexed rootAuthority,address indexed upgradeAuthority,address emergencyAuthority,address createdBy)",
          ];

          const factory = new window.ethers.Contract(factoryAddress, factoryAbi, wallet.signer);
          const predicted = await factory.callStatic.createInstance(
            rootAuthority,
            upgradeAuthority,
            emergencyAuthority,
            root,
            uriHash,
            policyHash
          );

          const tx = await factory.createInstance(
            rootAuthority,
            upgradeAuthority,
            emergencyAuthority,
            root,
            uriHash,
            policyHash
          );

          $("chainOut").textContent = JSON.stringify(
            {
              ok: true,
              stage: "broadcasted",
              tx_hash: tx.hash,
              tx_link: `${EXPLORER_BASE}/tx/${tx.hash}`,
              predicted_instance: predicted,
              instance_link: `${EXPLORER_BASE}/address/${predicted}`,
            },
            null,
            2
          );
          const receipt = await tx.wait();

          $("instanceController").value = predicted;
          localStorage.setItem("bc_instance_controller", predicted);

          $("chainOut").textContent = JSON.stringify(
            {
              ok: true,
              stage: "mined",
              tx_hash: tx.hash,
              tx_link: `${EXPLORER_BASE}/tx/${tx.hash}`,
              block: receipt.blockNumber,
              instance_controller: predicted,
              instance_link: `${EXPLORER_BASE}/address/${predicted}`,
              manifest_root: root,
              manifest_uri_hash: uriHash,
              enforcement: getEnforcement(),
              policy_hash_v3: policyHash,
            },
            null,
            2
          );
        } catch (e) {
          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
	        }
	      });

	      $("createInstanceManual").addEventListener("click", async () => {
	        $("chainOut").style.display = "block";
	        $("chainOut").textContent = "Working...";
	        try {
	          if (!window.ethers) throw new Error("ethers.js failed to load. Ensure /_blackcat/ethers.umd.min.js is reachable.");

	          const factoryAddress = $("instanceFactory").value.trim();
	          if (!isHexAddress(factoryAddress)) throw new Error("Invalid InstanceFactory address.");
	          const rootAuthority = $("rootAuthority").value.trim();
	          const upgradeAuthority = $("upgradeAuthority").value.trim();
	          const emergencyAuthority = $("emergencyAuthority").value.trim();
	          if (!isHexAddress(rootAuthority)) throw new Error("Invalid root authority address.");
	          if (!isHexAddress(upgradeAuthority)) throw new Error("Invalid upgrade authority address.");
	          if (!isHexAddress(emergencyAuthority)) throw new Error("Invalid emergency authority address.");

	          const { root, uriHash } = await readManifestSummary();
	          const policyHash = await computePolicyHash();

	          const abi = [
	            "function createInstance(address rootAuthority,address upgradeAuthority,address emergencyAuthority,bytes32 genesisRoot,bytes32 genesisUriHash,bytes32 genesisPolicyHash) returns (address)",
	          ];
	          const iface = new window.ethers.utils.Interface(abi);
	          const data = iface.encodeFunctionData("createInstance", [
	            rootAuthority,
	            upgradeAuthority,
	            emergencyAuthority,
	            root,
	            uriHash,
	            policyHash,
	          ]);

	          const cast = [
	            "cast send --rpc-url https://rpc.layeredge.io \\",
	            `  ${factoryAddress} \\`,
	            "  \"createInstance(address,address,address,bytes32,bytes32,bytes32)\" \\",
	            `  ${rootAuthority} ${upgradeAuthority} ${emergencyAuthority} ${root} ${uriHash} ${policyHash}`,
	          ].join("\n");

	          $("chainOut").textContent = JSON.stringify(
	            {
	              ok: true,
	              mode: "manual_tx_intent",
	              chain_id: CHAIN_ID_DEC,
	              to: factoryAddress,
	              value: "0x0",
	              data,
	              args: {
	                root_authority: rootAuthority,
	                upgrade_authority: upgradeAuthority,
	                emergency_authority: emergencyAuthority,
	                manifest_root: root,
	                manifest_uri_hash: uriHash,
	                enforcement: getEnforcement(),
	                policy_hash_v3: policyHash,
	              },
	              notes: [
	                "Send this transaction from a separate device / hardware wallet if desired.",
	                "If the bundle root is not trusted by ReleaseRegistry, the tx is expected to REVERT (fail-closed).",
	                "After it is mined, copy the InstanceCreated event 'instance' address and paste it into step 4.",
	              ],
	              explorer_factory: `${EXPLORER_BASE}/address/${factoryAddress}`,
	              cli_example_cast: cast,
	            },
	            null,
	            2
	          );
	        } catch (e) {
	          $("chainOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
	        }
	      });

	      $("writeConfig").addEventListener("click", async () => {
	        $("configOut").style.display = "block";
	        $("configOut").textContent = "Working...";
        const endpoints = $("rpcEndpoints").value.split(/\\r?\\n/).map(s => s.trim()).filter(Boolean);
        const hosts = $("allowedHosts").value.split(/\\r?\\n/).map(s => s.trim()).filter(Boolean);
        const payload = {
          instance_controller: $("instanceController").value.trim(),
          rpc_endpoints: endpoints,
          rpc_quorum: parseInt($("rpcQuorum").value || "1", 10),
          mode: $("trustMode").value,
          max_stale_sec: parseInt($("maxStale").value || "180", 10),
          enforcement: getEnforcement(),
          allowed_hosts: hosts,
        };
        const res = await api("/_blackcat/setup/api/write-config", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        $("configOut").textContent = JSON.stringify(res, null, 2);
        if (res && res.ok && res.runtime_config_attestation) {
          localStorage.setItem("bc_runtime_attestation", JSON.stringify(res.runtime_config_attestation));
        }
      });

	      $("lockAttestation").addEventListener("click", async () => {
	        $("attOut").style.display = "block";
	        $("attOut").textContent = "Working...";
	        try {
	          if (!wallet.signer) await connectWallet();
          if (wallet.chainId !== CHAIN_ID_DEC) {
            await ensureChain();
            wallet.chainId = (await wallet.provider.getNetwork()).chainId || null;
            setWalletUi();
          }
          if (wallet.chainId !== CHAIN_ID_DEC) throw new Error("Wrong chain. Expected chain_id=4207 (Edgen).");

	          const instance = $("instanceController").value.trim();
	          if (!isHexAddress(instance)) throw new Error("Invalid InstanceController address.");
	
	          const rootAuthority = $("rootAuthority").value.trim();
	          if (isHexAddress(rootAuthority) && wallet.account && rootAuthority.toLowerCase() !== wallet.account.toLowerCase()) {
	            throw new Error("Connect the ROOT authority account in your browser wallet to lock the attestation.");
	          }

          const raw = localStorage.getItem("bc_runtime_attestation");
          if (!raw) throw new Error("No runtime attestation found. Write config first.");
          const att = JSON.parse(raw);
          const key = String(att.key || "").trim();
          const value = String(att.value || "").trim();
          if (!isBytes32(key) || !isBytes32(value)) throw new Error("Invalid attestation key/value.");

          const controllerAbi = [
            "function setAttestationAndLock(bytes32 key,bytes32 value)",
          ];
          const controller = new window.ethers.Contract(instance, controllerAbi, wallet.signer);
          const tx = await controller.setAttestationAndLock(key, value);
          $("attOut").textContent = JSON.stringify({ ok: true, stage: "broadcasted", tx_hash: tx.hash, key, value }, null, 2);
          const receipt = await tx.wait();
          $("attOut").textContent = JSON.stringify({ ok: true, stage: "mined", tx_hash: tx.hash, block: receipt.blockNumber, key, value }, null, 2);
        } catch (e) {
          $("attOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
	        }
	      });

	      $("lockAttestationManual").addEventListener("click", async () => {
	        $("attOut").style.display = "block";
	        $("attOut").textContent = "Working...";
	        try {
	          if (!window.ethers) throw new Error("ethers.js failed to load. Ensure /_blackcat/ethers.umd.min.js is reachable.");

	          const instance = $("instanceController").value.trim();
	          if (!isHexAddress(instance)) throw new Error("Invalid InstanceController address.");

	          const raw = localStorage.getItem("bc_runtime_attestation");
	          if (!raw) throw new Error("No runtime attestation found. Write config first.");
	          const att = JSON.parse(raw);
	          const key = String(att.key || "").trim();
	          const value = String(att.value || "").trim();
	          if (!isBytes32(key) || !isBytes32(value)) throw new Error("Invalid attestation key/value.");

	          const abi = ["function setAttestationAndLock(bytes32 key,bytes32 value)"];
	          const iface = new window.ethers.utils.Interface(abi);
	          const data = iface.encodeFunctionData("setAttestationAndLock", [key, value]);

	          const cast = [
	            "cast send --rpc-url https://rpc.layeredge.io \\",
	            `  ${instance} \\`,
	            "  \"setAttestationAndLock(bytes32,bytes32)\" \\",
	            `  ${key} ${value}`,
	          ].join("\n");

	          $("attOut").textContent = JSON.stringify(
	            {
	              ok: true,
	              mode: "manual_tx_intent",
	              chain_id: CHAIN_ID_DEC,
	              to: instance,
	              value: "0x0",
	              data,
	              args: { key, value },
	              notes: [
	                "This must be signed by the ROOT authority (cold wallet recommended).",
	                "After it is mined, the attestation key is locked on-chain.",
	              ],
	              explorer_instance: `${EXPLORER_BASE}/address/${instance}`,
	              cli_example_cast: cast,
	            },
	            null,
	            2
	          );
	        } catch (e) {
	          $("attOut").textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
	        }
	      });

      $("finish").addEventListener("click", async () => {
        $("finishOut").style.display = "block";
        $("finishOut").textContent = "Working...";
        const res = await api("/_blackcat/setup/api/finish", { method: "POST" });
        $("finishOut").textContent = JSON.stringify(res, null, 2);
      });

      refreshStatus();

      // Defaults + local cache restore
      $("instanceFactory").value = DEFAULT_FACTORY;
      $("releaseRegistry").value = DEFAULT_REGISTRY;
      setReleaseRegistryLink();
      applyEnforcement();
      $("enforcement").addEventListener("change", () => {
        const v = getEnforcement();
        try { localStorage.setItem("bc_enforcement", v); } catch (_) {}
        $("policyHash").value = "";
      });
      const cachedIc = localStorage.getItem("bc_instance_controller");
      if (cachedIc && isHexAddress(cachedIc)) $("instanceController").value = cachedIc;
      loadAuthorities();
      setReleaseTrustUi(null);
      </script>
    </div>

    __BLACKCAT_TLS_BAR__
  </body>
</html>
HTML;

    echo str_replace(
        ['__BLACKCAT_TLS_BAR__', '__BLACKCAT_TRUST_ILLUSTRATION__', '__BLACKCAT_CSP_NONCE__', '__BLACKCAT_ENFORCEMENT__'],
        [$tlsBarHtml, $trustIllustrationHtml, $nonce, blackcat_setup_policy()],
        $page,
    );
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api(array $paths, string $endpoint): void
{
    if (!blackcat_is_https_request()) {
        blackcat_json(['ok' => false, 'error' => 'HTTPS is required for setup.'], 400);
        return;
    }

    if (blackcat_setup_is_disabled($paths['state_dir'])) {
        $hostPort = blackcat_normalize_http_host($_SERVER['HTTP_HOST'] ?? null);
        $isDev = blackcat_is_dev_host($hostPort['host']);
        if ($isDev) {
            blackcat_json(['ok' => false, 'error' => 'Setup is disabled (installed.flag present).'], 403);
            return;
        }
        blackcat_json(['ok' => false, 'error' => 'Not found.'], 404);
        return;
    }

    $tlsGate = blackcat_setup_tls_gate($paths['state_dir']);
    if ($tlsGate['mode'] === 'prod' && $tlsGate['trusted'] !== true) {
        blackcat_json([
            'ok' => false,
            'error' => 'Trusted TLS is required for production setup (CA verification failed).',
        ], 400);
        return;
    }

    if (blackcat_setup_is_disabled($paths['state_dir'])) {
        blackcat_json(['ok' => false, 'error' => 'Setup is disabled (installed.flag present).'], 403);
        return;
    }

    $token = blackcat_read_install_token($paths['state_dir']);
    if ($token === null) {
        blackcat_json(['ok' => false, 'error' => 'Missing install token file (.blackcat/install.token).'], 500);
        return;
    }

    $provided = blackcat_read_provided_token();
    if ($provided === null || !hash_equals($token, $provided)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid or missing install token.'], 401);
        return;
    }

    $endpoint = trim($endpoint, "/ \t\r\n");
    if ($endpoint === 'status') {
        blackcat_setup_api_status($paths);
        return;
    }

    if ($endpoint === 'build-manifest') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            blackcat_json(['ok' => false, 'error' => 'Method not allowed.'], 405);
            return;
        }
        blackcat_setup_api_build_manifest($paths);
        return;
    }

    if ($endpoint === 'write-config') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            blackcat_json(['ok' => false, 'error' => 'Method not allowed.'], 405);
            return;
        }
        blackcat_setup_api_write_config($paths);
        return;
    }

    if ($endpoint === 'policy-v3') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            blackcat_json(['ok' => false, 'error' => 'Method not allowed.'], 405);
            return;
        }
        blackcat_setup_api_policy_v3();
        return;
    }

    if ($endpoint === 'finish') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            blackcat_json(['ok' => false, 'error' => 'Method not allowed.'], 405);
            return;
        }
        blackcat_setup_api_finish($paths);
        return;
    }

    blackcat_json(['ok' => false, 'error' => 'Unknown endpoint: ' . $endpoint], 404);
}

/**
 * Production safety gate: require CA-trusted TLS for the setup flow.
 *
 * Why:
 * - The setup UI controls on-chain authorities + runtime config.
 * - A MITM during setup can swap addresses/policies and steal control permanently.
 * - Browsers don't expose "certificate trusted" reliably to JS; this is verified from the server side.
 *
 * @return array{mode:'dev'|'prod',host:string,port:int,trusted:bool,error:?string}
 */
function blackcat_setup_tls_gate(string $stateDir): array
{
    blackcat_ensure_state_dir($stateDir);

    $hostPort = blackcat_normalize_http_host($_SERVER['HTTP_HOST'] ?? null);
    $host = $hostPort['host'];
    $port = $hostPort['port'];
    $mode = blackcat_is_dev_host($host) ? 'dev' : 'prod';

    $cachePath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'tls.trust.cache.json';
    $cache = null;
    if (is_file($cachePath)) {
        $raw = file_get_contents($cachePath);
        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $cache = $decoded;
            }
        }
    }

    $cacheOk = false;
    if (is_array($cache)) {
        $ts = $cache['checked_at'] ?? null;
        $ch = $cache['host'] ?? null;
        $cp = $cache['port'] ?? null;
        if (is_int($ts) && is_string($ch) && is_int($cp)) {
            if ($ch === $host && $cp === $port && (time() - $ts) < 60) {
                $cacheOk = true;
            }
        }
    }

    if ($cacheOk) {
        return [
            'mode' => $mode,
            'host' => $host,
            'port' => $port,
            'trusted' => (bool) ($cache['trusted'] ?? false),
            'error' => is_string($cache['error'] ?? null) ? (string) $cache['error'] : null,
        ];
    }

    [$trusted, $err] = blackcat_tls_is_publicly_trusted($host, $port);

    $payload = [
        'checked_at' => time(),
        'host' => $host,
        'port' => $port,
        'trusted' => $trusted,
        'error' => $err,
    ];
    @file_put_contents($cachePath, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    if (DIRECTORY_SEPARATOR !== '\\') {
        @chmod($cachePath, 0600);
    }

    return [
        'mode' => $mode,
        'host' => $host,
        'port' => $port,
        'trusted' => $trusted,
        'error' => $err,
    ];
}

/**
 * @return array{host:string,port:int}
 */
function blackcat_normalize_http_host(mixed $raw): array
{
    $fallback = ['host' => '', 'port' => 443];

    if (!is_string($raw)) {
        return $fallback;
    }

    $raw = trim($raw);
    if ($raw === '' || str_contains($raw, "\0") || str_contains($raw, '/') || str_contains($raw, '\\')) {
        return $fallback;
    }

    // IPv6 in brackets: [::1]:443
    if (str_starts_with($raw, '[')) {
        $end = strpos($raw, ']');
        if ($end === false) {
            return $fallback;
        }
        $host = substr($raw, 1, $end - 1);
        $rest = substr($raw, $end + 1);
        $port = 443;
        if (str_starts_with($rest, ':')) {
            $portRaw = substr($rest, 1);
            if ($portRaw !== '' && ctype_digit($portRaw)) {
                $p = (int) $portRaw;
                if ($p >= 1 && $p <= 65535) {
                    $port = $p;
                }
            }
        }
        return ['host' => strtolower(trim($host)), 'port' => $port];
    }

    $host = $raw;
    $port = 443;
    if (preg_match('/^(.+):(\\d{1,5})$/', $raw, $m) === 1) {
        $host = $m[1];
        $p = (int) $m[2];
        if ($p >= 1 && $p <= 65535) {
            $port = $p;
        }
    }

    return ['host' => strtolower(trim($host)), 'port' => $port];
}

function blackcat_is_dev_host(string $host): bool
{
    $host = strtolower(trim($host));
    if ($host === '' || str_contains($host, "\0")) {
        return false;
    }

    if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
        return true;
    }

    if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return str_starts_with($host, '127.');
    }

    if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        return $host === '::1';
    }

    return false;
}

/**
 * Installer UI policy selector (enforcement).
 *
 * - strict: production default (fail-closed)
 * - less-strict: still fail-closed, but allows a limited set of probe-based waivers
 * - warn: compatibility mode (do not use for production)
 *
 * @return 'strict'|'less-strict'|'warn'
 */
function blackcat_setup_policy(): string
{
    $raw = $_GET['policy'] ?? null;
    if (is_string($raw)) {
        $v = strtolower(trim($raw));
        if ($v === 'warn' || $v === 'dev') {
            return 'warn';
        }
        if ($v === 'less-strict' || $v === 'less_strict' || $v === 'lessstrict' || $v === 'ls') {
            return 'less-strict';
        }
        if ($v === 'strict' || $v === 'prod') {
            return 'strict';
        }
    }
    return 'strict';
}

/**
 * @return array{0:bool,1:?string} (trusted, error_code)
 */
function blackcat_tls_is_publicly_trusted(string $host, int $port): array
{
    $host = strtolower(trim($host));
    if ($host === '' || str_contains($host, "\0")) {
        return [false, 'invalid_host'];
    }

    // SSRF hardening: reject private/reserved IP literals (except localhost dev).
    if (@filter_var($host, FILTER_VALIDATE_IP) !== false) {
        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        if (@filter_var($host, FILTER_VALIDATE_IP, $flags) === false) {
            return [false, 'host_is_private_ip'];
        }
    } else {
        // Conservative hostname validation to avoid Host-header tricks.
        if (preg_match('/^[a-z0-9.-]+$/', $host) !== 1 || strlen($host) > 253) {
            return [false, 'invalid_hostname'];
        }

        $ips = [];
        $a = @gethostbynamel($host);
        if (is_array($a)) {
            foreach ($a as $ip) {
                if (is_string($ip)) {
                    $ips[] = $ip;
                }
            }
        }
        if (function_exists('dns_get_record')) {
            $aaaa = @dns_get_record($host, DNS_AAAA);
            if (is_array($aaaa)) {
                foreach ($aaaa as $row) {
                    $ip = $row['ipv6'] ?? null;
                    if (is_string($ip)) {
                        $ips[] = $ip;
                    }
                }
            }
        }

        if ($ips === []) {
            return [false, 'dns_no_records'];
        }

        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        foreach ($ips as $ip) {
            if (@filter_var($ip, FILTER_VALIDATE_IP, $flags) === false) {
                return [false, 'dns_resolves_to_private_ip'];
            }
        }
    }

    $connectHost = $host;
    if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        $connectHost = '[' . $host . ']';
    }

    // Prefer OpenSSL extension (stream_socket_client + strict peer verification).
    if (extension_loaded('openssl')) {
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
                'SNI_enabled' => true,
                'peer_name' => $host,
                'disable_compression' => true,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $timeout = 2.0;
        $fp = @stream_socket_client(
            'ssl://' . $connectHost . ':' . $port,
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $ctx
        );

        if (!is_resource($fp)) {
            return [false, 'tls_connect_failed'];
        }

        @stream_set_timeout($fp, 2);
        @fclose($fp);
        return [true, null];
    }

    // Fallback: cURL HTTPS verification (does not require PHP OpenSSL extension).
    $hasCurl = extension_loaded('curl') && function_exists('curl_init') && function_exists('curl_version');
    $hasCurlSsl = false;
    if ($hasCurl) {
        $v = @curl_version();
        if (is_array($v)) {
            $features = $v['features'] ?? null;
            $sslVersion = $v['ssl_version'] ?? null;
            if (is_int($features) && defined('CURL_VERSION_SSL') && (($features & CURL_VERSION_SSL) !== 0)) {
                $hasCurlSsl = true;
            } elseif (is_string($sslVersion) && $sslVersion !== '') {
                $hasCurlSsl = true;
            }
        }
    }
    if (!$hasCurlSsl) {
        return [false, 'tls_verify_unavailable'];
    }

    $url = 'https://' . $connectHost . ':' . $port . '/';
    $ch = @curl_init();
    if ($ch === false) {
        return [false, 'tls_verify_unavailable'];
    }

    @curl_setopt($ch, CURLOPT_URL, $url);
    @curl_setopt($ch, CURLOPT_NOBODY, true);
    @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    @curl_setopt($ch, CURLOPT_HEADER, false);
    @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    @curl_setopt($ch, CURLOPT_MAXREDIRS, 0);
    @curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
    @curl_setopt($ch, CURLOPT_TIMEOUT, 2);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    if (defined('CURLPROTO_HTTPS')) {
        @curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        @curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    }

    $ok = @curl_exec($ch);
    if ($ok !== false) {
        @curl_close($ch);
        return [true, null];
    }

    $errno = @curl_errno($ch);
    @curl_close($ch);
    if (is_int($errno) && $errno !== 0) {
        // 60 = CURLE_PEER_FAILED_VERIFICATION (common "untrusted cert" case).
        if ($errno === 60) {
            return [false, 'tls_not_trusted'];
        }
        return [false, 'curl_error_' . (string) $errno];
    }

    return [false, 'tls_connect_failed'];
}

/**
 * @param array{mode:'dev'|'prod',host:string,port:int,trusted:bool,error:?string} $tlsGate
 */

function blackcat_setup_render_tls_not_trusted_page(array $tlsGate): void
{
    http_response_code(400);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    $host = htmlspecialchars($tlsGate['host'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $port = (int) $tlsGate['port'];
    $err = $tlsGate['error'] !== null ? htmlspecialchars($tlsGate['error'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') : 'unknown';

    $detailsHtml = '<div class="muted small">CA-trusted TLS verification failed for <code>'
        . $host
        . '</code>:<code>'
        . (string) $port
        . '</code>.</div>'
        . '<div class="muted small">Error: <code>'
        . $err
        . '</code></div>';

    $gridHtml = '<div class="panel">'
        . '<strong>Fix:</strong>'
        . '<ol>'
        . '<li>Install a CA-trusted certificate (Let’s Encrypt).</li>'
        . '<li>Confirm the browser lock has no warnings.</li>'
        . '<li>Reload this page.</li>'
        . '</ol>'
        . '</div>'
        . '<div class="panel">'
        . '<strong>Details (server-side TLS check):</strong>'
        . $detailsHtml
        . '</div>';

    if (function_exists('blackcat_error_ui_render_page')) {
        echo blackcat_error_ui_render_page([
            'title' => 'BlackCat Setup — Trusted TLS Required',
            'h1_prefix' => 'BlackCat Setup',
            'pill' => 'trusted TLS required',
            'lede_html' => '<strong>Blocked:</strong> the TLS certificate is not publicly trusted. BlackCat refuses to continue to prevent MITM during setup.',
            'grid_html' => $gridHtml,
            'style_vars' => [
                'accent_rgb' => '255, 212, 107',
                'accent2_rgb' => '86, 116, 255',
                'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                'mascot_primary_url' => '/_blackcat/assets/tls-not-trusted-cat.png',
            ],
        ]);
        return;
    }

    echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Trusted TLS Required</title><h1>Trusted TLS required</h1>';
}

function blackcat_setup_preflight(array $paths): array
{
    $errors = [];
    $warnings = [];

    $policy = blackcat_setup_policy();
    $isWarnPolicy = ($policy === 'warn');
    $isLessStrictPolicy = ($policy === 'less-strict');

    $iniBool = static function (string $key): bool {
        $raw = @ini_get($key);
        if ($raw === false) {
            return false;
        }
        $v = strtolower(trim((string) $raw));
        if ($v === '' || $v === '0' || $v === 'off' || $v === 'false' || $v === 'no') {
            return false;
        }
        return true;
    };

    $iniStr = static function (string $key): ?string {
        $raw = @ini_get($key);
        if ($raw === false) {
            return null;
        }
        $v = trim((string) $raw);
        return $v !== '' ? $v : null;
    };

    // --- Runtime hardening gate (align with TrustKernel strict policy) ---

    if ($iniBool('allow_url_include')) {
        $errors[] = 'php.ini hardening: allow_url_include is enabled. Disable it (high-risk remote file include).';
    }

    $displayErrorsEnabled = $iniBool('display_errors') || $iniBool('display_startup_errors');
    if ($displayErrorsEnabled) {
        // Best-effort: detect whether the runtime can override this (ini_set) like HttpKernel does.
        $canOverride = false;
        if (function_exists('ini_set')) {
            @ini_set('display_errors', '0');
            @ini_set('display_startup_errors', '0');
            $afterErrors = $iniBool('display_errors');
            $afterStartup = $iniBool('display_startup_errors');
            $canOverride = !$afterErrors && !$afterStartup;
        }

        $msg = 'php.ini hardening: display_errors/display_startup_errors is enabled. Disable them to prevent information disclosure (use log_errors instead).'
            . ($canOverride ? ' Note: it appears overrideable at runtime (ini_set), but you should still disable it in hosting settings.' : '');

        if ($isWarnPolicy || $canOverride) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $logErrors = $iniBool('log_errors');
    if (!$logErrors) {
        $warnings[] = 'php.ini hardening: log_errors is disabled. Enable it so errors are logged instead of displayed.';
    }

    $openBasedir = $iniStr('open_basedir');
    if ($openBasedir === null) {
        $msg = 'php.ini hardening: open_basedir is not set. Set it to restrict filesystem access (required for a strict trust-kernel deployment).';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    } else {
        $allowed = array_filter(array_map('trim', explode(PATH_SEPARATOR, $openBasedir)), static fn (string $p): bool => $p !== '');

        $bundleRoot = $paths['bundle_root'];
        $stateDir = $paths['state_dir'];
        $configPath = $paths['config_path'];

        $mustAllow = [
            'bundle_root' => $bundleRoot,
            '.blackcat' => $stateDir,
            'config.runtime.json dir' => dirname($configPath),
        ];

        $allowedOk = static function (string $required, array $allowedList): bool {
            $req = @realpath($required);
            $req = is_string($req) && $req !== '' ? $req : $required;
            $req = rtrim($req, "/\\") . DIRECTORY_SEPARATOR;

            foreach ($allowedList as $base) {
                $b = @realpath($base);
                $b = is_string($b) && $b !== '' ? $b : $base;
                $b = rtrim($b, "/\\") . DIRECTORY_SEPARATOR;
                if (str_starts_with($req, $b)) {
                    return true;
                }
            }
            return false;
        };

        foreach ($mustAllow as $label => $path) {
            if (!$allowedOk($path, $allowed)) {
                $msg = 'php.ini hardening: open_basedir blocks access to ' . $label . '. Adjust open_basedir or deploy the bundle under an allowed path.';
                if ($isWarnPolicy) {
                    $warnings[] = $msg;
                } else {
                    $errors[] = $msg;
                }
            }
        }
    }

    $pharReadonly = $iniStr('phar.readonly');
    if ($pharReadonly !== null && $pharReadonly !== '1') {
        $msg = 'php.ini hardening: phar.readonly is disabled. Set phar.readonly=1 to reduce PHAR deserialization risks.';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    if ($iniBool('enable_dl')) {
        $msg = 'php.ini hardening: enable_dl is enabled. Disable it (runtime extension loading increases attack surface).';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $autoPrepend = $iniStr('auto_prepend_file');
    if ($autoPrepend !== null) {
        $msg = 'php.ini hardening: auto_prepend_file is set. Remove it (hidden code injection risk).';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $autoAppend = $iniStr('auto_append_file');
    if ($autoAppend !== null) {
        $msg = 'php.ini hardening: auto_append_file is set. Remove it (hidden code injection risk).';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $cgiFixPathinfo = $iniBool('cgi.fix_pathinfo');
    if ($cgiFixPathinfo && in_array(PHP_SAPI, ['fpm-fcgi', 'cgi', 'cgi-fcgi'], true)) {
        if ($isWarnPolicy) {
            $warnings[] = 'php.ini hardening: cgi.fix_pathinfo is enabled. This increases risk in some CGI/FPM configurations.';
        } elseif ($isLessStrictPolicy) {
            $warnings[] = 'php.ini hardening: cgi.fix_pathinfo is enabled. less-strict can proceed only with a best-effort NO EXEC probe + a locked on-chain waiver attestation; otherwise the kernel will fail-closed.';
        } else {
            $errors[] = 'php.ini hardening: cgi.fix_pathinfo is enabled. Set cgi.fix_pathinfo=0 for strict deployments on FPM/CGI.';
        }
    }

    $disableFunctionsRaw = $iniStr('disable_functions');
    $parseCsv = static function (?string $raw): array {
        if ($raw === null || trim($raw) === '') {
            return [];
        }
        $out = [];
        foreach (preg_split('/[\\s,]+/', trim($raw)) ?: [] as $part) {
            $p = strtolower(trim((string) $part));
            if ($p === '' || str_contains($p, "\0")) {
                continue;
            }
            $out[$p] = true;
        }
        return array_keys($out);
    };
    $disabled = $parseCsv($disableFunctionsRaw);
    $dangerous = ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec'];
    $callable = [];
    foreach ($dangerous as $fn) {
        // If disabled (disable_functions) or unavailable (extension not loaded),
        // function_exists() should be false. Treat "callable" as the actual risk.
        if (function_exists($fn)) {
            $callable[] = $fn;
        }
    }
    if ($callable !== []) {
        $msg = 'php.ini hardening: dangerous process-exec functions are callable: ' . implode(', ', $callable) . '. Disable them (recommended: disable_functions=' . implode(',', $dangerous) . ').';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    } elseif ($disabled === [] && $isWarnPolicy) {
        // Informational: some hostings disable these at another layer; strict prod should still disable explicitly.
        $warnings[] = 'php.ini hardening: disable_functions is empty, but no dangerous process-exec functions appear callable in this runtime.';
    }

    $hasOpenSsl = extension_loaded('openssl');
    $hasCurl = extension_loaded('curl') && function_exists('curl_init') && function_exists('curl_version');
    $hasCurlSsl = false;
    if ($hasCurl) {
        $v = @curl_version();
        if (is_array($v)) {
            $features = $v['features'] ?? null;
            $sslVersion = $v['ssl_version'] ?? null;
            if (is_int($features) && defined('CURL_VERSION_SSL') && (($features & CURL_VERSION_SSL) !== 0)) {
                $hasCurlSsl = true;
            } elseif (is_string($sslVersion) && $sslVersion !== '') {
                // Some builds expose ssl_version but not features reliably.
                $hasCurlSsl = true;
            }
        }
    }
    if (!$hasOpenSsl && !$hasCurlSsl) {
        $errors[] = 'Missing TLS verification capability (OpenSSL extension or PHP curl with HTTPS support). BlackCat crypto uses libsodium, but setup still requires CA-trusted TLS verification to prevent MITM.';
    }

    // Web3 transport (align with TrustKernel expectations).
    $allowUrlFopen = $iniBool('allow_url_fopen');
    $web3TransportOk = $hasCurlSsl || ($allowUrlFopen && $hasOpenSsl);
    if (!$web3TransportOk) {
        $msg = 'Web3 transport is unavailable: no HTTPS-capable client detected (need cURL with SSL or OpenSSL + allow_url_fopen). TrustKernel cannot read on-chain state on this hosting.';
        if ($isWarnPolicy) {
            $warnings[] = $msg;
        } else {
            $errors[] = $msg;
        }
    }

    $docroot = $paths['docroot'];
    $bundleRoot = $paths['bundle_root'];
    $stateDir = $paths['state_dir'];
    $configPath = $paths['config_path'];

    $docrootReal = @realpath($docroot);
    $bundleReal = @realpath($bundleRoot);
    if (is_string($docrootReal) && is_string($bundleReal)) {
        $docrootReal = rtrim($docrootReal, "/\\") . DIRECTORY_SEPARATOR;
        $bundleReal = rtrim($bundleReal, "/\\") . DIRECTORY_SEPARATOR;
        if (str_starts_with($bundleReal, $docrootReal)) {
            $errors[] = 'Misconfigured web root: bundle_root must not be inside docroot (sensitive files could be web-accessible).';
        }
    }

    // Ensure state dir is writable and not world-writable (POSIX).
    if (!is_dir($stateDir)) {
        $errors[] = 'State directory is missing (.blackcat).';
        return ['errors' => $errors, 'warnings' => $warnings];
    }

    if (!is_writable($stateDir)) {
        $errors[] = 'State directory is not writable (.blackcat).';
    }

    if (DIRECTORY_SEPARATOR !== '\\') {
        $perms = @fileperms($stateDir);
        if (is_int($perms)) {
            $mode = $perms & 0777;
            if (($mode & 0002) !== 0) {
                $errors[] = 'State directory is world-writable (.blackcat). Fix permissions (recommended: 0700).';
            } elseif (($mode & 0020) !== 0) {
                $warnings[] = 'State directory is group-writable (.blackcat). Consider tightening permissions (recommended: 0700).';
            }
        }
    }

    // Ensure bundle root is writable for config.runtime.json.
    $configDir = dirname($configPath);
    if (!is_dir($configDir) || !is_writable($configDir)) {
        $errors[] = 'Bundle root is not writable (needed to write config.runtime.json).';
    }

    if (is_file($configPath) && !is_writable($configPath)) {
        $errors[] = 'config.runtime.json exists but is not writable.';
    }

    return ['errors' => $errors, 'warnings' => $warnings];
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 * @param list<string> $errors
 * @param list<string> $warnings
 */

function blackcat_setup_render_preflight_page(array $paths, array $errors, array $warnings): void
{
    http_response_code(503);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    $errItems = '';
    foreach ($errors as $e) {
        $errItems .= '<li><strong class="bad">ERROR</strong> ' . htmlspecialchars($e, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</li>';
    }
    $warnItems = '';
    foreach ($warnings as $w) {
        $warnItems .= '<li><strong class="warn">WARN</strong> ' . htmlspecialchars($w, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</li>';
    }

    $gridHtml = '<div class="panel">'
        . '<strong>Checklist:</strong>'
        . '<ul>'
        . $errItems
        . $warnItems
        . '</ul>'
        . '<div class="footer muted">Preflight is intentionally strict — it prevents writing secrets into unsafe paths/permissions.</div>'
        . '</div>'
        . '<div class="panel">'
        . '<strong>Common fixes:</strong>'
        . '<ul class="muted">'
        . '<li>Ensure server-side TLS verification works (OpenSSL extension or PHP <code>curl</code> with HTTPS support).</li>'
        . '<li>Harden php.ini (disable <code>display_errors</code>, set <code>open_basedir</code>, and disable dangerous functions via <code>disable_functions</code>).</li>'
        . '<li>Ensure <code>.blackcat/</code> is writable and not world-writable.</li>'
        . '<li>Ensure the bundle root is writable for <code>config.runtime.json</code>.</li>'
        . '<li>Reload <code>/_blackcat/setup</code> after fixing permissions.</li>'
        . '</ul>'
        . '</div>';

    if (function_exists('blackcat_error_ui_render_page')) {
        echo blackcat_error_ui_render_page([
            'title' => 'BlackCat Setup — Preflight Failed',
            'h1_prefix' => 'BlackCat Setup',
            'pill' => 'preflight failed',
            'lede_html' => '<strong>Fix the server environment</strong> before continuing. This protects the installer from writing secrets/config into unsafe locations.',
            'grid_html' => $gridHtml,
            'style_vars' => [
                'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                'mascot_primary_url' => '/_blackcat/assets/preflight-failed-cat.png',
            ],
        ]);
        return;
    }

    echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Preflight Failed</title><h1>Preflight failed</h1>';
}


function blackcat_setup_render_disabled_page(array $paths): void
{
    http_response_code(404);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    $gridHtml = '<div class="panel">'
        . '<strong>What this means:</strong>'
        . '<ul class="muted">'
        . '<li>This instance has already been initialized.</li>'
        . '<li>The web installer is intentionally locked after setup.</li>'
        . '</ul>'
        . '</div>'
        . '<div class="panel">'
        . '<strong>Next steps:</strong>'
        . '<ul class="muted">'
        . '<li>Use the signed upgrade/recovery flow to make changes.</li>'
        . '<li>If you need a clean install, deploy a fresh bundle.</li>'
        . '</ul>'
        . '</div>';

    if (function_exists('blackcat_error_ui_render_page')) {
        echo blackcat_error_ui_render_page([
            'title' => 'BlackCat Setup — Disabled',
            'h1_prefix' => 'BlackCat Setup',
            'pill' => 'installer locked',
            'lede_html' => '<strong>Installer locked.</strong> This deployment is sealed to keep the web attack surface minimal.',
            'grid_html' => $gridHtml,
            'style_vars' => [
                'accent_rgb' => '255, 212, 107',
                'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                'mascot_primary_url' => '/_blackcat/assets/installer-locked-cat.png',
            ],
        ]);
        return;
    }

    echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Disabled</title><h1>Installer locked</h1>';
}


function blackcat_setup_render_front_controller_required_page(): void
{
    http_response_code(400);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

    $gridHtml = '<div class="panel">'
        . '<strong>What this means:</strong>'
        . '<ul>'
        . '<li>Your server must route all requests to the front controller (<code>index.php</code>).</li>'
        . '<li>Direct access to <code>/_blackcat/setup.php</code> is blocked by design.</li>'
        . '</ul>'
        . '</div>'
        . '<div class="panel">'
        . '<strong>Fix:</strong>'
        . '<ul class="muted">'
        . '<li>Point the document root to the directory that contains <code>index.php</code>.</li>'
        . '<li>Enable URL rewriting so all requests route through <code>index.php</code> (Apache: <code>AllowOverride All</code> / Nginx: <code>try_files</code>).</li>'
        . '<li>Reload and open <code>/_blackcat/setup</code> again.</li>'
        . '</ul>'
        . '<div class="footer warn">Front controller is a required part of BlackCat security (single entrypoint).</div>'
        . '</div>';

    if (function_exists('blackcat_error_ui_render_page')) {
        echo blackcat_error_ui_render_page([
            'title' => 'BlackCat Setup — Front Controller Required',
            'h1_prefix' => 'BlackCat Setup',
            'pill' => 'front controller required',
            'lede_html' => '<strong>Fail-closed:</strong> setup must be served through the front controller to enforce routing, HTTPS, and trust checks.',
            'grid_html' => $gridHtml,
            'style_vars' => [
                'grid_url' => '/_blackcat/assets/bg-grid-red.png',
                'mascot_primary_url' => '/_blackcat/assets/fatal-error-cat.png',
            ],
        ]);
        return;
    }

    echo '<!doctype html><meta charset="utf-8" /><title>BlackCat Setup — Front Controller Required</title><h1>Front controller required</h1>';
}

function blackcat_setup_api_policy_v3(): void
{
    $raw = file_get_contents('php://input');
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($decoded)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid JSON body.'], 400);
        return;
    }

    $mode = $decoded['mode'] ?? 'full';
    if (!is_string($mode)) {
        blackcat_json(['ok' => false, 'error' => 'mode must be a string.'], 400);
        return;
    }
    $mode = strtolower(trim($mode));
    if (!in_array($mode, ['full', 'root_uri'], true)) {
        blackcat_json(['ok' => false, 'error' => 'mode must be "full" or "root_uri".'], 400);
        return;
    }

    $maxStale = $decoded['max_stale_sec'] ?? 180;
    if (!is_int($maxStale)) {
        if (is_string($maxStale) && ctype_digit(trim($maxStale))) {
            $maxStale = (int) trim($maxStale);
        } else {
            blackcat_json(['ok' => false, 'error' => 'max_stale_sec must be an integer.'], 400);
            return;
        }
    }
    if ($maxStale <= 0) {
        blackcat_json(['ok' => false, 'error' => 'max_stale_sec must be >= 1.'], 400);
        return;
    }

    $enforcement = $decoded['enforcement'] ?? 'strict';
    if (!is_string($enforcement)) {
        blackcat_json(['ok' => false, 'error' => 'enforcement must be a string.'], 400);
        return;
    }
    $enforcement = strtolower(trim($enforcement));
    if (!in_array($enforcement, ['strict', 'less-strict', 'warn'], true)) {
        blackcat_json(['ok' => false, 'error' => 'enforcement must be "strict", "less-strict", or "warn".'], 400);
        return;
    }

    $attKey = Bytes32::normalizeHex(KernelAttestations::runtimeConfigAttestationKeyV1());
    $policy = new TrustPolicyV3($mode, $maxStale, $enforcement, $attKey);
    $policyStrict = new TrustPolicyV3($mode, $maxStale, 'strict', $attKey);
    $policyLessStrict = new TrustPolicyV3($mode, $maxStale, 'less-strict', $attKey);
    $policyWarn = new TrustPolicyV3($mode, $maxStale, 'warn', $attKey);

    blackcat_json([
        'ok' => true,
        'attestation_key_v1' => $attKey,
        'enforcement' => $enforcement,
        'policy_hash_v3' => $policy->hashBytes32(),
        'policy_hash_v3_strict' => $policyStrict->hashBytes32(),
        'policy_hash_v3_less_strict' => $policyLessStrict->hashBytes32(),
        'policy_hash_v3_warn' => $policyWarn->hashBytes32(),
        'note' => 'Policy hash does not depend on runtime config contents (only mode/max_stale/enforcement + attestation key).',
    ]);
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api_status(array $paths): void
{
    $suggestedHost = null;
    $rawHost = $_SERVER['HTTP_HOST'] ?? null;
    if (is_string($rawHost) && $rawHost !== '' && !str_contains($rawHost, "\0")) {
        $suggestedHost = preg_replace('/:\\d+$/', '', strtolower(trim($rawHost)));
    }

    $suggested = [
        'rpc_endpoints' => [
            'https://rpc.layeredge.io',
            'https://edgenscan.io/api/eth-rpc',
        ],
        'allowed_hosts' => $suggestedHost !== null ? [$suggestedHost] : [],
    ];

    $stateDir = $paths['state_dir'];
    $manifestPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'integrity.manifest.json';
    $summaryPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.summary.json';

    $summary = null;
    if (is_file($summaryPath)) {
        $raw = file_get_contents($summaryPath);
        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $summary = $decoded;
            }
        }
    }

    blackcat_json([
        'ok' => true,
        'paths' => [
            'docroot' => $paths['docroot'],
            'site_dir' => $paths['site_dir'],
            'bundle_root' => $paths['bundle_root'],
            'state_dir' => $paths['state_dir'],
            'config_path' => $paths['config_path'],
            'manifest_path' => $manifestPath,
        ],
        'exists' => [
            'manifest' => is_file($manifestPath),
            'config' => is_file($paths['config_path']),
            'installed_flag' => blackcat_setup_is_disabled($stateDir),
            'summary' => $summary !== null,
        ],
        'summary' => $summary,
        'suggested' => $suggested,
    ]);
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api_build_manifest(array $paths): void
{
    $stateDir = $paths['state_dir'];
    blackcat_ensure_state_dir($stateDir);

    $siteDir = $paths['site_dir'];
    if (!is_dir($siteDir) || is_link($siteDir)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid integrity root directory: ' . $siteDir], 500);
        return;
    }

    $out = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'integrity.manifest.json';
    $summaryPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.summary.json';

    try {
        $res = IntegrityManifestBuilder::build($siteDir);
        $manifest = $res['manifest'];

        $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new RuntimeException('Unable to encode manifest JSON.');
        }

        if (@file_put_contents($out, $json . "\n") === false) {
            throw new RuntimeException('Unable to write manifest: ' . $out);
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($out, 0640);
        }

        $summary = [
            'ok' => true,
            'root' => $res['root'],
            'uri_hash' => $res['uri_hash'],
            'files_count' => $res['files_count'],
            'generated_at' => gmdate('c'),
        ];
        @file_put_contents($summaryPath, json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($summaryPath, 0640);
        }

        blackcat_json($summary);
    } catch (Throwable $e) {
        blackcat_json(['ok' => false, 'error' => $e->getMessage()], 500);
    }
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api_write_config(array $paths): void
{
    $stateDir = $paths['state_dir'];
    $manifestPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'integrity.manifest.json';
    if (!is_file($manifestPath)) {
        blackcat_json(['ok' => false, 'error' => 'Missing manifest. Run build-manifest first.'], 400);
        return;
    }

    $raw = file_get_contents('php://input');
    $decoded = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($decoded)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid JSON body.'], 400);
        return;
    }

    $instance = $decoded['instance_controller'] ?? null;
    if (!is_string($instance) || !preg_match('/^0x[a-fA-F0-9]{40}$/', $instance)) {
        blackcat_json(['ok' => false, 'error' => 'Invalid instance_controller (expected 0x + 40 hex).'], 400);
        return;
    }

    $rpcEndpoints = $decoded['rpc_endpoints'] ?? null;
    if (!is_array($rpcEndpoints) || $rpcEndpoints === []) {
        blackcat_json(['ok' => false, 'error' => 'rpc_endpoints must be a non-empty list.'], 400);
        return;
    }
    $endpoints = [];
    foreach ($rpcEndpoints as $i => $v) {
        if (!is_string($v)) {
            blackcat_json(['ok' => false, 'error' => 'rpc_endpoints[' . $i . '] must be a string.'], 400);
            return;
        }
        $v = trim($v);
        if ($v === '' || str_contains($v, "\0")) {
            blackcat_json(['ok' => false, 'error' => 'rpc_endpoints[' . $i . '] is invalid.'], 400);
            return;
        }
        $endpoints[] = $v;
    }

    $quorum = $decoded['rpc_quorum'] ?? 1;
    if (!is_int($quorum)) {
        if (is_string($quorum) && ctype_digit(trim($quorum))) {
            $quorum = (int) trim($quorum);
        } else {
            blackcat_json(['ok' => false, 'error' => 'rpc_quorum must be an integer.'], 400);
            return;
        }
    }
    if ($quorum < 1) {
        blackcat_json(['ok' => false, 'error' => 'rpc_quorum must be >= 1.'], 400);
        return;
    }
    if ($quorum > count($endpoints)) {
        blackcat_json(['ok' => false, 'error' => 'rpc_quorum must be <= number of rpc_endpoints.'], 400);
        return;
    }

    $enforcement = $decoded['enforcement'] ?? 'strict';
    if (!is_string($enforcement)) {
        blackcat_json(['ok' => false, 'error' => 'enforcement must be a string.'], 400);
        return;
    }
    $enforcement = strtolower(trim($enforcement));
    if (!in_array($enforcement, ['strict', 'less-strict', 'warn'], true)) {
        blackcat_json(['ok' => false, 'error' => 'enforcement must be "strict", "less-strict", or "warn".'], 400);
        return;
    }

    // Strict + less-strict require redundant RPC quorum (avoid single-endpoint trust).
    if ($enforcement !== 'warn') {
        if (count($endpoints) < 2) {
            blackcat_json(['ok' => false, 'error' => 'At least 2 rpc_endpoints are required (quorum trust needs redundancy).'], 400);
            return;
        }
        if ($quorum < 2) {
            blackcat_json(['ok' => false, 'error' => 'rpc_quorum must be >= 2 for a strict/less-strict trust kernel deployment.'], 400);
            return;
        }
    }

    $mode = $decoded['mode'] ?? 'full';
    if (!is_string($mode)) {
        blackcat_json(['ok' => false, 'error' => 'mode must be a string.'], 400);
        return;
    }
    $mode = strtolower(trim($mode));
    if (!in_array($mode, ['full', 'root_uri'], true)) {
        blackcat_json(['ok' => false, 'error' => 'mode must be "full" or "root_uri".'], 400);
        return;
    }

    $maxStale = $decoded['max_stale_sec'] ?? 180;
    if (!is_int($maxStale)) {
        if (is_string($maxStale) && ctype_digit(trim($maxStale))) {
            $maxStale = (int) trim($maxStale);
        } else {
            blackcat_json(['ok' => false, 'error' => 'max_stale_sec must be an integer.'], 400);
            return;
        }
    }

    $allowedHostsRaw = $decoded['allowed_hosts'] ?? [];
    $allowedHosts = [];
    if (is_array($allowedHostsRaw)) {
        foreach ($allowedHostsRaw as $v) {
            if (!is_string($v)) {
                continue;
            }
            $v = trim($v);
            if ($v !== '' && !str_contains($v, "\0")) {
                $allowedHosts[] = $v;
            }
        }
    }

    $txOutboxDir = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'tx-outbox';
    if (!is_dir($txOutboxDir)) {
        @mkdir($txOutboxDir, 0770, true);
        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($txOutboxDir, 0770);
        }
    }

    $payload = [
        'trust' => [
            'integrity' => [
                'root_dir' => 'site',
                'manifest' => '.blackcat/integrity.manifest.json',
                'image_digest_file' => '.blackcat/image.digest',
            ],
            'web3' => [
                'chain_id' => 4207,
                'rpc_endpoints' => $endpoints,
                'rpc_quorum' => $quorum,
                'max_stale_sec' => $maxStale,
                'timeout_sec' => 5,
                'mode' => $mode,
                'tx_outbox_dir' => '.blackcat/tx-outbox',
                'contracts' => [
                    'instance_controller' => $instance,
                    'release_registry' => '0x22681Ee2153B7B25bA6772B44c160BB60f4C333E',
                    'instance_factory' => '0x92C80Cff5d75dcD3846EFb5DF35957D5Aed1c7C5',
                ],
            ],
        ],
    ];

    if ($allowedHosts !== []) {
        $payload['http'] = [
            'allowed_hosts' => $allowedHosts,
        ];
    }

    $path = $paths['config_path'];

    $existedBefore = file_exists($path);
    try {
        RuntimeConfigInstaller::init($payload, $path, true);
        $repo = ConfigRepository::fromJsonFile($path);

        $runtimeConfig = $repo->toArray();
        $attKey = Bytes32::normalizeHex(KernelAttestations::runtimeConfigAttestationKeyV1());
        $attValue = Bytes32::normalizeHex(KernelAttestations::runtimeConfigAttestationValueV1($runtimeConfig));

        $policy = new TrustPolicyV3($mode, $maxStale, $enforcement, $attKey);
        $policyStrict = new TrustPolicyV3($mode, $maxStale, 'strict', $attKey);
        $policyLessStrict = new TrustPolicyV3($mode, $maxStale, 'less-strict', $attKey);
        $policyWarn = new TrustPolicyV3($mode, $maxStale, 'warn', $attKey);
        $policyHash = $policy->hashBytes32();

        blackcat_json([
            'ok' => true,
            'config_path' => $path,
            'runtime_config_attestation' => [
                'key' => $attKey,
                'value' => $attValue,
                'enforcement' => $enforcement,
                'policy_hash_v3' => $policyHash,
                'policy_hash_v3_strict' => $policyStrict->hashBytes32(),
                'policy_hash_v3_less_strict' => $policyLessStrict->hashBytes32(),
                'policy_hash_v3_warn' => $policyWarn->hashBytes32(),
            ],
            'note' => 'Commit the manifest root + policy hash on-chain, then set+lock the runtime config attestation key/value on the InstanceController.',
        ]);
    } catch (Throwable $e) {
        // Avoid leaving an invalid/unsafe config behind if validation fails.
        if (!$existedBefore && is_file($path)) {
            @unlink($path);
        }
        blackcat_json(['ok' => false, 'error' => $e->getMessage()], 500);
    }
}

/**
 * @param array{docroot:string,site_dir:string,bundle_root:string,state_dir:string,config_path:string} $paths
 */
function blackcat_setup_api_finish(array $paths): void
{
    $stateDir = $paths['state_dir'];
    blackcat_ensure_state_dir($stateDir);

    $flag = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'installed.flag';
    if (@file_put_contents($flag, gmdate('c') . "\n") === false) {
        blackcat_json(['ok' => false, 'error' => 'Unable to write installed.flag'], 500);
        return;
    }
    if (DIRECTORY_SEPARATOR !== '\\') {
        @chmod($flag, 0600);
    }

    $tokenPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.token';
    $tokenRemoved = false;
    if (is_file($tokenPath)) {
        $tokenRemoved = (@unlink($tokenPath) !== false);
    }

    blackcat_json([
        'ok' => true,
        'installed_flag' => $flag,
        'install_token_removed' => $tokenRemoved,
        'note' => 'Installer disabled. This deployment is sealed to keep the web attack surface minimal. Use the signed upgrade/recovery flow for changes; for a clean reinstall, deploy a fresh bundle.',
    ]);
}

function blackcat_setup_is_disabled(string $stateDir): bool
{
    $flag = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'installed.flag';
    return is_file($flag);
}

function blackcat_read_install_token(string $stateDir): ?string
{
    $path = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.token';
    if (!is_file($path)) {
        return null;
    }
    $raw = file_get_contents($path);
    if (!is_string($raw)) {
        return null;
    }
    $token = trim($raw);
    return $token !== '' && !str_contains($token, "\0") ? $token : null;
}

function blackcat_read_provided_token(): ?string
{
    $headers = [
        $_SERVER['HTTP_X_BLACKCAT_INSTALL_TOKEN'] ?? null,
        $_SERVER['HTTP_AUTHORIZATION'] ?? null,
    ];

    foreach ($headers as $raw) {
        if (!is_string($raw)) {
            continue;
        }
        $raw = trim($raw);
        if ($raw === '' || str_contains($raw, "\0")) {
            continue;
        }
        if (str_starts_with(strtolower($raw), 'bearer ')) {
            $raw = trim(substr($raw, 7));
        }
        if ($raw !== '' && !str_contains($raw, "\0")) {
            return $raw;
        }
    }

    return null;
}

function blackcat_is_https_request(): bool
{
    $https = $_SERVER['HTTPS'] ?? null;
    if (is_string($https) && ($https === 'on' || $https === '1')) {
        return true;
    }
    if (is_int($https) && $https === 1) {
        return true;
    }

    $port = $_SERVER['SERVER_PORT'] ?? null;
    if (is_string($port) && trim($port) === '443') {
        return true;
    }
    if (is_int($port) && $port === 443) {
        return true;
    }

    // Only honor forwarded HTTPS indicators when the immediate peer is a local, trusted proxy.
    // This prevents clients from spoofing X-Forwarded-Proto / Forwarded on plain HTTP requests.
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;
    if (!blackcat_is_loopback_ip($remoteAddr)) {
        return false;
    }

    $xfp = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null;
    if (is_string($xfp)) {
        $first = trim(explode(',', $xfp, 2)[0] ?? '');
        if (strtolower($first) === 'https') {
            return true;
        }
    }

    $forwarded = $_SERVER['HTTP_FORWARDED'] ?? null;
    if (is_string($forwarded) && stripos($forwarded, 'proto=') !== false) {
        // RFC 7239: Forwarded: proto=https;host=example.com
        foreach (explode(',', $forwarded) as $part) {
            foreach (explode(';', $part) as $kv) {
                $kv = trim($kv);
                if (stripos($kv, 'proto=') !== 0) {
                    continue;
                }
                $val = trim(substr($kv, 6));
                $val = trim($val, "\"'");
                if (strtolower($val) === 'https') {
                    return true;
                }
            }
        }
    }

    return false;
}

function blackcat_is_loopback_ip(mixed $ip): bool
{
    if (!is_string($ip)) {
        return false;
    }
    $ip = trim($ip);
    if ($ip === '') {
        return false;
    }

    if (@filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return str_starts_with($ip, '127.');
    }

    if (@filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        return strtolower($ip) === '::1';
    }

    return false;
}

function blackcat_ensure_state_dir(string $stateDir): void
{
    if (is_dir($stateDir)) {
        return;
    }
    @mkdir($stateDir, 0700, true);
    if (DIRECTORY_SEPARATOR !== '\\') {
        @chmod($stateDir, 0700);
    }
}

function blackcat_request_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url(is_string($uri) ? $uri : '/', PHP_URL_PATH);
    $path = is_string($path) && $path !== '' ? $path : '/';
    if (str_contains($path, "\0")) {
        return '/';
    }
    return $path;
}

/**
 * @param array<string,mixed> $data
 */
function blackcat_json(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        echo "{\"ok\":false,\"error\":\"json_encode failed\"}\n";
        return;
    }
    echo $json . "\n";
}

// If this file is executed directly (misconfigured docroot), fail closed with a clear message.
if (PHP_SAPI !== 'cli') {
    $script = $_SERVER['SCRIPT_FILENAME'] ?? null;
    $scriptReal = is_string($script) ? @realpath($script) : null;
    $selfReal = @realpath(__FILE__);
    if (is_string($scriptReal) && is_string($selfReal) && $scriptReal === $selfReal) {
        blackcat_setup_render_front_controller_required_page();
        exit;
    }
}
