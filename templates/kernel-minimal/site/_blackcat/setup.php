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
        echo '<!doctype html><meta charset="utf-8"><title>BlackCat Setup</title>';
        echo '<h1>BlackCat Setup</h1>';
        echo '<p><strong>HTTPS is required</strong> for installation. Enable TLS on your domain and reload this page.</p>';
        echo '<p>If you are behind a reverse proxy, ensure it forwards HTTPS correctly.</p>';
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
    $tokenPath = rtrim($stateDir, "/\\") . DIRECTORY_SEPARATOR . 'install.token';
    if (!is_file($tokenPath)) {
        $token = bin2hex(random_bytes(32));
        @file_put_contents($tokenPath, $token . "\n");
        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($tokenPath, 0600);
        }
    }

    header('Content-Type: text/html; charset=utf-8');
    echo <<<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>BlackCat Setup</title>
    <style>
      :root { color-scheme: dark; }
      body { margin: 0; padding: 24px; font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background: #0b0f17; color: #e7eefc; }
      a { color: #8ab4ff; }
      code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      pre { background: #0f1524; padding: 12px; border-radius: 10px; overflow: auto; }
      .card { background: #0f1524; border: 1px solid #1f2a44; border-radius: 14px; padding: 16px; margin: 12px 0; }
      .row { display: flex; gap: 12px; flex-wrap: wrap; }
      .row > * { flex: 1 1 320px; }
      .ok { color: #76e39d; }
      .bad { color: #ff7b72; }
      .muted { color: #9fb0d0; }
      button { background: #1b2a4d; color: #e7eefc; border: 1px solid #2a3b63; border-radius: 10px; padding: 10px 12px; cursor: pointer; }
      button:hover { background: #22345f; }
      input, textarea, select { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid #2a3b63; background: #0b0f17; color: #e7eefc; }
      textarea { min-height: 96px; }
      .grid { display: grid; grid-template-columns: 1fr; gap: 10px; }
      @media (min-width: 980px) { .grid { grid-template-columns: 1fr 1fr; } }
      .k { font-weight: 600; }
      .pill { display: inline-block; padding: 2px 10px; border-radius: 999px; background: #122042; border: 1px solid #1f2a44; margin-left: 8px; }
    </style>
  </head>
  <body>
    <h1>BlackCat Setup <span class="pill">Stage 3</span></h1>
    <p class="muted">This wizard prepares a strict, fail-closed TrustKernel deployment without requiring server-side Composer.</p>

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
        <button id="buildManifest">Build manifest</button>
        <pre id="manifestOut" style="display:none"></pre>
      </div>

      <div class="card">
        <h2>3) Write runtime config</h2>
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
      <h2>4) On-chain actions (manual)</h2>
      <p class="muted">This template does not broadcast transactions. Use your preferred wallet/tooling to:</p>
      <ol>
        <li>Create or select an <code>InstanceController</code> for this install.</li>
        <li>Set genesis <code>activeRoot</code> to the manifest root.</li>
        <li>Set genesis <code>activePolicyHash</code> to the recommended policy hash.</li>
        <li>Set+lock runtime config attestation (<code>key</code>, <code>value</code> shown after writing config).</li>
      </ol>
      <p class="muted">Once done, open the site root and verify it becomes <span class="ok">trusted</span> in strict mode.</p>
    </div>

    <div class="card">
      <h2>5) Disable installer</h2>
      <p>When everything is working, permanently disable this setup UI.</p>
      <button id="finish">Create installed.flag (disable setup)</button>
      <pre id="finishOut" style="display:none"></pre>
    </div>

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
        }
      };

      $("saveToken").addEventListener("click", async () => {
        const t = $("token").value.trim();
        if (!t) return;
        localStorage.setItem("bc_install_token", t);
        await refreshStatus();
      });
      $("clearToken").addEventListener("click", async () => {
        localStorage.removeItem("bc_install_token");
        await refreshStatus();
      });

      $("buildManifest").addEventListener("click", async () => {
        $("manifestOut").style.display = "block";
        $("manifestOut").textContent = "Working...";
        const res = await api("/_blackcat/setup/api/build-manifest", { method: "POST" });
        $("manifestOut").textContent = JSON.stringify(res, null, 2);
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
      });

      $("finish").addEventListener("click", async () => {
        $("finishOut").style.display = "block";
        $("finishOut").textContent = "Working...";
        const res = await api("/_blackcat/setup/api/finish", { method: "POST" });
        $("finishOut").textContent = JSON.stringify(res, null, 2);
      });

      refreshStatus();
    </script>
  </body>
</html>
HTML;
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

    blackcat_json(['ok' => true, 'installed_flag' => $flag]);
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
