# Google Drive OAuth 2.0 Client ID Setup & Verification Guide

`rship` uses **OAuth 2.0 Desktop PKCE on loopback (`http://127.0.0.1:<ephemeral-port>/callback`)**—never the deprecated OOB (`urn:ietf:wg:oauth:2.0:oob`) flow.

Google enforces two distinct paths for Google Drive OAuth Client IDs:

| Path | Best For | Google Review / CASA Audit? | Setup Time |
| :--- | :--- | :--- | :--- |
| **Path A: Bring Your Own Client ID (Recommended)** | Personal use, teams, self-hosted servers, power users | **None** (stays in *Testing* or *Internal* Google Workspace mode, up to 100 test users) | **~5 minutes** |
| **Path B: Public Verified OAuth App** | Distributing a shared default Client ID for arbitrary third-party users | **Yes** — `drive` / `drive.readonly` are **Restricted Scopes** requiring Google Verification + annual **CASA Tier 2** security assessment (~$500–$1,800/yr). `drive.file` is **Non-Sensitive** (no CASA audit!). | **2–6 weeks** |
| **Path C: Service Account (RS256 JWT)** | Automated CI/servers accessing **Shared Drives** or Google Workspace **Domain-Wide Delegation** | **None** | **~5 minutes** |

---

## Path A: Create Your Own Google Cloud OAuth 2.0 Desktop Client ID (5 Minutes)

### Step 1: Create a Google Cloud Project & Enable Drive API
1. Open [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project (e.g. `rship-personal-drive`) and select it.
3. Go to **APIs & Services → Library**, search for **Google Drive API**, and click **Enable**.

### Step 2: Configure Google Auth Platform (OAuth Consent Screen)
1. Go to **Google Auth Platform → Overview → Get Started** (or **APIs & Services → OAuth consent screen**).
2. **App Information**:
   - **App name**: `rship` (or `rship-personal`)
   - **User support email**: your Google email
3. **Audience**:
   - If you have a Google Workspace org and only org users will access it → select **Internal** (no 7-day refresh-token expiry, no verification needed!).
   - For standard `@gmail.com` accounts → select **External**.
4. **Contact Information**: your developer email. Click **Create**.

### Step 3: Add Scopes & Test Users (External / Personal Accounts)
1. Go to **Google Auth Platform → Data Access → Add or Remove Scopes**.
2. Choose the narrowest scope that fits your workflow:
   - **Full Google Drive access** (`sync` existing folders): `https://www.googleapis.com/auth/drive` (CLI alias: `--scope drive`)
   - **App-created files only** (no CASA audit if later verified!): `https://www.googleapis.com/auth/drive.file` (CLI alias: `--scope drive.file`)
   - **Read-only backup/mirror**: `https://www.googleapis.com/auth/drive.readonly` (CLI alias: `--scope drive.readonly`)
3. Save scopes.
4. Go to **Google Auth Platform → Audience → Test users → Add users**, and add every Google email address you plan to authorize.
   > **Important note on Refresh Token expiry in Testing mode**: For External apps left in **Testing** mode, Google expires OAuth refresh tokens after **7 days**.
   > - For personal/long-running headless jobs without weekly re-auth, either:
   >   1. Use **Internal** (Google Workspace), OR
   >   2. Click **Publish app** (switches status to *In production*; personal users see an "Unverified app → Advanced → Continue" warning once during login, and refresh tokens stop expiring every 7 days!), OR
   >   3. Use **Path C (Service Account)** for Shared Drives.

### Step 4: Create Desktop App OAuth Client Credentials
1. Go to **Google Auth Platform → Clients → Create Client** (or **APIs & Services → Credentials → Create Credentials → OAuth client ID**).
2. **Application type**: select **Desktop app** *(Critical: Google automatically permits `http://127.0.0.1:<any-port>/callback` loopback redirects ONLY for **Desktop app** clients!)*
3. **Name**: `rship-desktop`.
4. Click **Create** and copy the generated **Client ID** and **Client Secret**.

### Step 5: Authorize `rship`
```bash
# Interactive Desktop PKCE login (opens loopback listener on 127.0.0.1)
rship auth gdrive gdrive \
  --client-id "<YOUR_CLIENT_ID>.apps.googleusercontent.com" \
  --client-secret "<YOUR_CLIENT_SECRET>"

# Optional: move credentials immediately into OS Keyring (Windows Credential Manager / macOS Keychain / Linux Secret Service)
rship auth keyring-migrate

# Verify connectivity & inspect Drive quota
rship config test gdrive
rship about gdrive:
```

### Step 6: Headless Server / VPS & Docker Authorization

Authorize on your laptop/desktop first (where a browser is available), then export a portable credential bundle. `rship auth export` automatically resolves any `keyring://` references into the bundle, and `rship auth import` writes inline credentials plus OAuth token files directly—**no OS keyring is required on the server or inside Docker**.

```bash
# On desktop (single or multiple remotes):
rship auth export gdrive -o gdrive.bundle

# Copy `gdrive.bundle` over SSH to headless server, then import & delete the bundle:
rship auth import --input gdrive.bundle
rm -f gdrive.bundle

# Inspect active config & state/token paths on the server:
rship config path
rship config test gdrive
```

By default on Linux, `rship` stores:
- **Config file**: `~/.config/rship/config.toml` (e.g. `/root/.config/rship/config.toml` for `root`)
- **State & OAuth tokens**: `~/.local/share/rship/` (`tokens/<remote>.json` + SQLite resume journal)

#### Running Inside Docker / Docker Compose

Both the config file **and** the state/tokens directory must be mounted into the container, because `config.toml` holds `client_id` / `client_secret` while OAuth `access_token` / `refresh_token` live in `<state_dir>/tokens/<remote>.json`:

```text
/srv/rship/
├── config.toml          # copied from ~/.config/rship/config.toml
└── state/
    └── tokens/          # copied from ~/.local/share/rship/tokens/
        └── gdrive.json
```

```yaml
services:
  app:
    environment:
      - RSHIP_CONFIG=/rship/config.toml
      - RSHIP_STATE_DIR=/rship/state
    volumes:
      - /srv/rship:/rship              # state/ MUST be writable for token refresh & SQLite WAL
      # Optional: mount the static musl binary directly if not baked into the image
      - /usr/local/bin/rship:/usr/local/bin/rship:ro
```

> **Important Docker notes**:
> - **Do not mount `state/` as `:ro`**: Google Drive access tokens expire roughly every hour; `rship` automatically refreshes and writes updated tokens back to `tokens/<remote>.json`, and persists transfer checkpoints in SQLite inside `state/`.
> - **Non-root containers**: Match host directory ownership to the container's UID/GID (e.g. `chown -R 1000:1000 /srv/rship`) so token refreshes succeed.
> - **CLI flags**: You can also pass `--config /path/to/config.toml --state-dir /path/to/state` directly on any command instead of environment variables.

---

## Path B: Preparing a Public Verified Google OAuth App (Checklist)

If you decide to publish a shared official Client ID for `rship` users, prepare these items **before** clicking **Submit for Verification** in Google Cloud Console:

### 1. Decide Scope Strategy (Huge Cost & Timeline Difference!)
- **`drive.file` (Recommended for a shared public Client ID)**:
  - Classified by Google as **Non-Sensitive**!
  - Requires **NO** CASA Tier 2 security audit, **NO** restricted-scope review, and fast verification.
  - Trade-off: can only access files/folders created by `rship` (ideal for encrypted `rship` vaults and backups!).
  - Power users who need full existing Drive access (`drive`) can always plug in their own Client ID via Path A (just like `rclone` recommends!).
- **`drive` / `drive.readonly` (Restricted Scopes)**:
  - Requires full **Google Restricted Scope Verification** PLUS an annual third-party **CASA Tier 2** security assessment (OWASP ASVS Level 2 scan & remediation letter from an authorized lab).

### 2. Required Assets for Google Verification Submission
1. **Verified Domain & App Homepage**:
   - Verify domain ownership in [Google Search Console](https://search.google.com/search-console).
   - Host the standalone public docs site (`website/`, published via GitHub Pages at `https://hua0512.github.io/rship/` or your custom domain) explaining what `rship` does and linking clearly to the Privacy Policy.
2. **Public Privacy Policy URL**:
   - Must be hosted on the verified domain and explain Google API User Data usage + Google API Services User Data Policy Limited Use compliance.
   - Included both in Markdown at [`docs/PRIVACY_POLICY.md`](./PRIVACY_POLICY.md) and as a dedicated public page at `/privacy` (`website/privacy.md`).
3. **App Logo**: 120×120 px PNG/JPG (< 1 MB) — ready at [`assets/logo-120.png`](../assets/logo-120.png) (plus vector [`assets/logo.svg`](../assets/logo.svg) and favicon [`assets/logo.ico`](../assets/logo.ico)).
4. **Scope Justification Template** (paste into GCP Verification Form):
   - **`drive.file`**: *"rship is a local, user-controlled open-source CLI backup and file synchronization utility. It requests `drive.file` solely to create, upload, resume, verify, and manage user-initiated backup folders and files in the user's own Google Drive directly from the user's local machine. No user data or OAuth tokens are transmitted to any developer-operated server."*
   - **`drive`** *(if applying for restricted scope)*: *"rship is an open-source, local-first command-line synchronization engine (similar to rclone/rsync) that synchronizes existing user directories with the user's own Google Drive using incremental `changes.list` tracking and crash-resumable uploads. All API requests originate directly from the user's machine to `googleapis.com`; the developer operates no backend servers and never receives user tokens or file contents."*
5. **Unlisted YouTube Demo Video (Required by Google Reviewers)**:
   - Record a 60–90 second English screencast (with captions/narration) showing:
     1. Running `rship auth gdrive ...` in terminal,
     2. Browser opening the Google OAuth consent screen with the **exact visible `client_id`** in the address bar and requested scope list,
     3. Clicking **Allow** and landing on the loopback success page,
     4. Running `rship about gdrive:`, `rship copy ./demo gdrive:rship-demo`, and `rship ls gdrive:rship-demo` showing the uploaded file in Google Drive.
6. **Secret Hygiene for Public Desktop Clients**:
   - Google treats Desktop App `client_secret` values as non-confidential per RFC 8252 (since native binaries can be inspected), which is why `rship` enforces **PKCE (`S256`)** and exact loopback `state` validation on every OAuth flow.

---

## Path C: Service Account Setup (Shared Drives & Workspace DwD)

> Note: Google Drive Service Accounts have **0 bytes of personal My Drive quota** on modern GCP accounts; use them with a **Shared Drive (`--shared-drive-id`)** or Google Workspace **Domain-Wide Delegation (`--impersonate user@domain.com`)**.

1. In GCP Console → **IAM & Admin → Service Accounts → Create Service Account**.
2. Open the Service Account → **Keys → Add Key → Create new key → JSON** and download `sa.json`.
3. Add the Service Account's email (`...@...iam.gserviceaccount.com`) as **Content Manager** on your target Google Shared Drive (copy the Shared Drive ID from its URL `https://drive.google.com/drive/folders/<SHARED_DRIVE_ID>`).
4. Configure `rship`:
   ```bash
   rship auth gdrive team \
     --service-account-file ./sa.json \
     --shared-drive-id "<SHARED_DRIVE_ID>"

   # Or with Google Workspace Domain-Wide Delegation:
   rship auth gdrive corp \
     --service-account-file ./sa.json \
     --impersonate "backup-bot@example.com"
   ```
