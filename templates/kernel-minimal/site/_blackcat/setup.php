<?php

declare(strict_types=1);

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

        echo <<<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat Setup — HTTPS Required</title>
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <style>
      :root { color-scheme: dark; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
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
        opacity: 0.28;
        mix-blend-mode: screen;
        filter: brightness(1.8) contrast(1.25);
        pointer-events: none;
        z-index: 0;
      }
      .card {
        max-width: 920px;
        width: 100%;
        border-radius: 18px;
        border: 1px solid rgba(42, 59, 99, 0.9);
        background: rgba(15, 21, 36, 0.78);
        box-shadow: 0 30px 100px rgba(0, 0, 0, 0.45);
        overflow: hidden;
        position: relative;
        z-index: 1;
      }
      .banner {
        width: 100%;
        height: 0;
        padding-top: 31.25%; /* 500 / 1600 */
        background:
          linear-gradient(180deg, rgba(11, 15, 23, 0.05), rgba(11, 15, 23, 0.9)),
          url("/_blackcat/assets/hero-banner.png") left center / cover no-repeat;
        border-bottom: 1px solid rgba(31, 42, 68, 0.95);
      }
      .top {
        padding: 18px;
        display: flex;
        gap: 18px;
        align-items: flex-start;
        flex-wrap: wrap;
      }
      .imgWrap {
        width: 128px;
        height: 128px;
        margin-top: -72px;
        border-radius: 0;
        position: relative;
        background:
          url("/_blackcat/assets/https-required-cat.png") center / contain no-repeat,
          url("/_blackcat/assets/https-required-cat-fallback.svg") center / 92px 92px no-repeat;
        display: grid;
        place-items: center;
        overflow: visible;
        filter:
          drop-shadow(0 18px 55px rgba(0, 0, 0, 0.55))
          drop-shadow(0 0 26px rgba(255, 123, 114, 0.28))
          drop-shadow(0 0 46px rgba(86, 116, 255, 0.10));
        transform: translateY(-2px);
      }
      .imgWrap::before {
        content: "";
        position: absolute;
        inset: -18px;
        background: radial-gradient(circle at 50% 45%, rgba(255, 123, 114, 0.26) 0%, rgba(255, 123, 114, 0.0) 62%);
        filter: blur(7px);
        opacity: 0.85;
        pointer-events: none;
        z-index: -1;
      }
      @media (max-width: 520px) {
        .imgWrap { width: 112px; height: 112px; margin-top: -62px; }
      }
      h1 { margin: 0; font-size: 26px; letter-spacing: 0.2px; }
      .muted { color: #9fb0d0; }
      .pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        background: rgba(255, 123, 114, 0.12);
        border: 1px solid rgba(255, 123, 114, 0.28);
        color: #ff7b72;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        margin-left: 10px;
      }
      .body { padding: 12px 18px 18px 18px; }
      .steps {
        margin: 12px 0 0;
        padding: 12px 14px;
        border-radius: 14px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.55);
      }
      code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      .warn { color: #ffd46b; }
      .footer { margin-top: 10px; font-size: 12px; color: #9fb0d0; }
    </style>
  </head>
	  <body>
	    <main class="card">
	      <div class="banner" aria-hidden="true"></div>
	      <div class="top">
	        <div class="imgWrap" aria-hidden="true"></div>
	        <div>
	          <h1>BlackCat Setup <span class="pill">HTTPS required</span></h1>
	          <p class="muted">No worries — this is intentional. Installation is blocked over HTTP to prevent downgrade + MITM attacks.</p>
	        </div>
	      </div>

      <div class="body">
        <div class="steps">
          <div><strong>Fix:</strong></div>
          <ol>
            <li>Enable TLS (e.g., Let’s Encrypt) on your domain.</li>
            <li>If you use a reverse proxy, forward HTTPS correctly (X-Forwarded-Proto / Forwarded: proto=https) from a trusted local peer (127.0.0.1 / ::1).</li>
            <li>Reload this page over <code>https://</code>.</li>
          </ol>
          <div class="footer warn">Tip: the setup UI is token-gated and can be permanently disabled after install.</div>
        </div>
      </div>
    </main>
  </body>
</html>
HTML;
        exit;
    }

    if (blackcat_setup_is_disabled($paths['state_dir'])) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "BlackCat setup is disabled (installed.flag present).\n";
        exit;
    }

    $stateDir = $paths['state_dir'];
    blackcat_ensure_state_dir($stateDir);

    $tlsGate = blackcat_setup_tls_gate($stateDir);
    if ($tlsGate['mode'] === 'prod' && $tlsGate['trusted'] !== true) {
        blackcat_setup_render_tls_not_trusted_page($tlsGate);
        exit;
    }

    $tokenPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.token';
    if (!is_file($tokenPath)) {
        $token = bin2hex(random_bytes(32));
        @file_put_contents($tokenPath, $token . "\n");
        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($tokenPath, 0600);
        }
    }

    $tlsBarHtml = '';
    if ($tlsGate['mode'] === 'dev' && $tlsGate['trusted'] !== true) {
        $tlsBarHtml = '<div class="tlsBar" role="status">'
            . '<strong>DEV WARNING:</strong> TLS certificate is not publicly trusted. '
            . 'Do <strong>not</strong> use this mode in production. Install a CA-trusted certificate (e.g., Let’s Encrypt) and reload.'
            . '</div>';
    }

    header('Content-Type: text/html; charset=utf-8');
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
        opacity: 0.22;
        mix-blend-mode: screen;
        filter: brightness(1.7) contrast(1.2);
        pointer-events: none;
        z-index: 0;
      }

      a { color: #8ab4ff; }
      code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      pre { background: rgba(15, 21, 36, 0.8); border: 1px solid #1f2a44; padding: 12px; border-radius: 12px; overflow: auto; }

      .wrap { max-width: 1180px; margin: 0 auto; position: relative; z-index: 1; }

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
        background: rgba(15, 21, 36, 0.72);
        border: 1px solid rgba(31, 42, 68, 0.95);
        border-radius: 16px;
        padding: 16px;
        margin: 12px 0;
        box-shadow: 0 10px 32px rgba(0, 0, 0, 0.25);
      }

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
            <label class="k">Policy hash (v3 strict)</label>
            <input id="policyHash" placeholder="0x... (computed)" autocomplete="off" readonly />
          </div>
        </div>

	        <p class="small muted">This step will create a new InstanceController bound to: <span class="mono">manifest.root</span> + <span class="mono">manifest.uri_hash</span> + <span class="mono">policy_hash_v3_strict</span>.</p>
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

      <script src="/_blackcat/ethers.umd.min.js"></script>
      <script>
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

      const computePolicyHash = async () => {
        const mode = $("trustMode").value;
        const maxStale = parseInt($("maxStale").value || "180", 10);
        const res = await api("/_blackcat/setup/api/policy-v3", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode, max_stale_sec: maxStale }),
        });
        if (!res || !res.ok) throw new Error(res && res.error ? res.error : "policy-v3 failed");
        if (!res.policy_hash_v3_strict || !isBytes32(res.policy_hash_v3_strict)) throw new Error("Invalid policy hash.");
        $("policyHash").value = res.policy_hash_v3_strict;
        return res.policy_hash_v3_strict;
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
          $("chainOut").textContent = JSON.stringify({ ok: true, policy_hash_v3_strict: policy }, null, 2);
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
              policy_hash_v3_strict: policyHash,
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
	                policy_hash_v3_strict: policyHash,
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
        ['__BLACKCAT_TLS_BAR__', '__BLACKCAT_TRUST_ILLUSTRATION__'],
        [$tlsBarHtml, $trustIllustrationHtml],
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

    if (!extension_loaded('openssl')) {
        return [false, 'openssl_missing'];
    }

    $connectHost = $host;
    if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        $connectHost = '[' . $host . ']';
    }

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

    $page = <<<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat Setup — Trusted TLS Required</title>
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <style>
      :root { color-scheme: dark; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
        font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        position: relative;
        isolation: isolate;
        background:
          linear-gradient(180deg, rgba(11, 15, 23, 0.88), rgba(11, 15, 23, 0.88)),
          url("/_blackcat/assets/tls-not-trusted-banner.png") center / cover no-repeat,
          url("/_blackcat/assets/hero-banner.png") center / cover no-repeat,
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
        opacity: 0.24;
        mix-blend-mode: screen;
        filter: brightness(1.75) contrast(1.25);
        pointer-events: none;
        z-index: 0;
      }
      .card {
        max-width: 980px;
        width: 100%;
        border-radius: 18px;
        border: 1px solid rgba(42, 59, 99, 0.9);
        background: rgba(15, 21, 36, 0.78);
        box-shadow: 0 30px 100px rgba(0, 0, 0, 0.45);
        overflow: hidden;
        position: relative;
        z-index: 1;
      }
      .top {
        padding: 18px;
        display: flex;
        gap: 16px;
        align-items: center;
        flex-wrap: wrap;
        background:
          linear-gradient(180deg, rgba(15, 21, 36, 0.35), rgba(15, 21, 36, 0.92)),
          url("/_blackcat/assets/tls-not-trusted-banner.png") center / cover no-repeat,
          url("/_blackcat/assets/hero-banner.png") center / cover no-repeat;
      }
      .iconWrap {
        width: 120px;
        height: 120px;
        border-radius: 16px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background:
          url("/_blackcat/assets/tls-not-trusted-cat.png") center / cover no-repeat,
          url("/_blackcat/assets/tls-not-trusted-fallback.svg") center / 74px 74px no-repeat,
          rgba(11, 15, 23, 0.55);
        display: grid;
        place-items: center;
        overflow: hidden;
      }
      .pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        background: rgba(255, 123, 114, 0.12);
        border: 1px solid rgba(255, 123, 114, 0.28);
        color: #ff7b72;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        margin-left: 10px;
      }
      h1 { margin: 0; font-size: 26px; letter-spacing: 0.2px; }
      .muted { color: #9fb0d0; }
      .body { padding: 0 18px 18px 18px; }
      .box {
        margin-top: 12px;
        padding: 12px 14px;
        border-radius: 14px;
        border: 1px solid rgba(31, 42, 68, 0.95);
        background: rgba(11, 15, 23, 0.55);
      }
      code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      .small { font-size: 12px; }
      .warn { color: #ffd46b; }
    </style>
  </head>
  <body>
    <main class="card">
      <div class="top">
        <div class="iconWrap" aria-hidden="true"></div>
        <div>
          <h1>BlackCat Setup <span class="pill">trusted TLS required</span></h1>
          <p class="muted"><strong>This is not the HTTP block.</strong> You are on <code>https://</code>, but the certificate is not publicly trusted. Production installation is fail-closed to prevent MITM during setup.</p>
        </div>
      </div>
      <div class="body">
        <div class="box">
          <div><strong>Fix:</strong></div>
          <ol>
            <li>Install a CA-trusted certificate (recommended: Let’s Encrypt).</li>
            <li>Verify the browser shows a normal secure lock (no warnings).</li>
            <li>Reload this setup page over <code>https://</code>.</li>
          </ol>
          <div class="muted warn">Local demo tip: use <code>localhost</code> (dev mode shows a persistent warning banner instead of blocking).</div>
        </div>
        <div class="box">
          <div><strong>Details (server-side TLS verification):</strong></div>
          <div class="muted small">BlackCat tried to verify a CA-trusted TLS handshake to <code>__TLS_HOST__</code>:<code>__TLS_PORT__</code> and refused to continue.</div>
          <div class="muted small">Error: <code>__TLS_ERR__</code></div>
        </div>
      </div>
    </main>
  </body>
</html>
HTML;
    echo str_replace(
        ['__TLS_HOST__', '__TLS_PORT__', '__TLS_ERR__'],
        [$host, (string) $port, $err],
        $page,
    );
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

    $attKey = Bytes32::normalizeHex(KernelAttestations::runtimeConfigAttestationKeyV1());
    $policy = new TrustPolicyV3($mode, $maxStale, 'strict', $attKey);

    blackcat_json([
        'ok' => true,
        'attestation_key_v1' => $attKey,
        'policy_hash_v3_strict' => $policy->hashBytes32(),
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

        $policy = new TrustPolicyV3($mode, $maxStale, 'strict', $attKey);
        $policyHash = $policy->hashBytes32();

        blackcat_json([
            'ok' => true,
            'config_path' => $path,
            'runtime_config_attestation' => [
                'key' => $attKey,
                'value' => $attValue,
                'policy_hash_v3_strict' => $policyHash,
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
        'note' => 'Installer disabled. For re-install, remove installed.flag and re-open /_blackcat/setup to generate a new install token.',
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
