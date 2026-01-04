# Stage 3 — Kernel Minimal Bundle (FTP / no Composer on the server)

Goal: deploy **BlackCat Core + Config** with a strict, fail-closed TrustKernel setup on a server where you can only upload files (FTP/SFTP) and cannot run Composer.

This bundle ships:
- `site/public/index.php` — single entrypoint (front controller)
- `/_blackcat/setup` — one-time installer UI (token-gated), disabled after install

## 1) Build the bundle (workstation / CI)

From the monorepo root (where `blackcat-core/` and `blackcat-config/` are present):

```bash
bash blackcat-installer/scripts/build-kernel-minimal-bundle.sh
```

Output:
- `blackcat-installer/dist/blackcat-kernel-minimal-bundle/`
- `blackcat-installer/dist/blackcat-kernel-minimal-bundle.zip`

## 2) Upload to the server

Upload the whole directory (or unzip it on the server):

```
blackcat-kernel-minimal-bundle/
  site/
  .blackcat/
```

Important:
- The web docroot must point to `site/public/`.
- Keep `.blackcat/` and `config.runtime.json` outside web docroot.

## 3) Run the one-time installer

Open:

`https://YOUR_DOMAIN/_blackcat/setup`

Flow:
1) The server creates `.blackcat/install.token`.
2) You open that token via FTP and paste it into the setup page.
3) Click **Build manifest** → it writes `.blackcat/integrity.manifest.json` and shows the `root` bytes32.
4) Create/configure your on-chain InstanceController (manual for now).
5) Enter the InstanceController address and click **Write config** → it writes `config.runtime.json` and prints:
   - recommended `policy_hash_v3_strict`
   - runtime-config attestation `key` + `value`
6) Commit those values on-chain.
7) Click **Disable installer** → creates `.blackcat/installed.flag` (setup becomes unavailable).

## 4) Troubleshooting

- If you see `503` at `/`:
  - open `/_blackcat/setup` and verify `config.runtime.json` exists,
  - ensure you have **2+** working RPC endpoints if running strict quorum >= 2,
  - verify the on-chain `activeRoot` matches the local manifest `root`.

- If setup says “HTTPS required”:
  - enable TLS (Let’s Encrypt) and ensure the app is not downgraded to HTTP between proxy and PHP.

