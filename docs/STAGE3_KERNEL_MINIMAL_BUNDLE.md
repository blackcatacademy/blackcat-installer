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
4) (Optional) Click **Verify release root** (requires a browser wallet) → the installer calls `ReleaseRegistry.isTrustedRoot(root)` and:
   - shows **trusted/untrusted**,
   - blocks instance creation if untrusted (fail-closed).
5) Create the on-chain instance (two options):
   - **Browser wallet** (MetaMask/Rabby): connect wallet, set authority addresses (root / upgrade / emergency), click **Compute policy hash**, then **Broadcast create tx**.
   - **Manual / offline**: click **Generate tx intent (manual)** and send it from another device / hardware wallet / CLI.
   - This broadcasts `InstanceFactory.createInstance(...)` (and reverts if the root is not trusted).
   - The factory is also an on-chain “installations registry” via `isInstance(...)` + `InstanceCreated` events.
6) Click **Write config** → it writes `config.runtime.json` and prints:
   - runtime-config attestation `key` + `value`
7) Lock the runtime-config attestation (two options):
   - **Browser wallet**: click **Broadcast lock tx**.
   - **Manual / offline**: click **Generate tx intent (manual)** and sign elsewhere.
   - This broadcasts `InstanceController.setAttestationAndLock(key,value)` from the **root authority** wallet.
8) Open the site root and verify it becomes **trusted** in strict mode.
9) Click **Disable installer** → creates `.blackcat/installed.flag` (setup becomes unavailable) and removes the install token.

Notes:
- No private keys are stored server-side. All on-chain transactions are initiated by your wallet.
- After a successful install you may additionally delete `site/_blackcat/setup.php` from the bundle (optional hardening). The front controller will then return `404` for `/_blackcat/setup`.
- `ReleaseRegistry` is a global trust list for **official** BlackCat release roots; end-users should not need to publish anything there.
- If you modify the bundle files after building it, your computed manifest `root` will not match any trusted release root, and instance creation will fail (by design).

## 4) Troubleshooting

- If you see `503` at `/`:
  - open `/_blackcat/setup` and verify `config.runtime.json` exists,
  - ensure you have **2+** working RPC endpoints if running strict quorum >= 2,
  - verify the on-chain `activeRoot` matches the local manifest `root`.

- If setup says “HTTPS required”:
  - enable TLS (Let’s Encrypt) and ensure the app is not downgraded to HTTP between proxy and PHP.

- If setup says “trusted TLS required”:
  - production setup is fail-closed until the HTTPS certificate validates against a trusted CA,
  - fix TLS (recommended: Let’s Encrypt) and reload,
  - for localhost demo a self-signed cert is allowed and the UI shows a persistent **DEV WARNING** banner.

- If instance creation fails:
  - ensure MetaMask is on **Edgen Chain** (`chain_id=4207`) and your wallet has enough EDGEN for gas,
  - ensure you uploaded an **untampered** official bundle (otherwise `GenesisRootNotTrusted` is expected),
  - ensure your authority addresses are valid `0x...` EVM addresses.

## Local demo (Docker / localhost)

If you want to preview the setup UI locally (and iterate on visuals), a self-contained HTTPS demo stack is included:

```bash
docker compose -f blackcat-installer/docker-compose.stage3-demo.yml up --build
```

Then open:

`https://localhost:8449/_blackcat/setup`

For live UI editing (no rebuild needed):

```bash
docker compose \
  -f blackcat-installer/docker-compose.stage3-demo.yml \
  -f blackcat-installer/docker-compose.stage3-demo.dev.yml \
  up --build
```

Notes:
- The certificate is self-signed (your browser will warn).
- This is expected for local demo; the setup UI will show a persistent **DEV WARNING** banner.
- To read the install token for local testing:

```bash
docker compose -f blackcat-installer/docker-compose.stage3-demo.yml exec stage3-demo cat /srv/bundle/.blackcat/install.token
```
