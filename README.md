# COP EMMA MEMBERSHIP

A private Streamlit app for authorized users to search, add, and edit church membership records. Supabase Auth handles email/password accounts and Supabase Postgres stores only authenticated-encrypted member records and encrypted before/after audit snapshots.

The source workbook has 247 non-empty member rows across 34 worksheet columns. The first worksheet column has no header and is excluded; member records contain exactly the remaining 33 named member-detail fields, and the search results table displays all 33 columns.

## Security before setup

The database credential pasted into the original chat is considered exposed. **Rotate/revoke it in Supabase before use.** This app does not use that connection string or a database superuser password. It talks to Supabase Auth and the PostgREST API with the project URL and public anon/publishable key; database policies and restricted RPC functions enforce authorization.

The Excel workbook contains personal information. Keep the local `membership.xlsx` out of source control and deployment artifacts. The repository ignore rules exclude it and Streamlit secrets.

## Configure Supabase

1. Create a Supabase project and configure Auth email/password sign-in and SMTP delivery. In Supabase Dashboard → Authentication → URL Configuration, set **Site URL** to `https://cop-emma-membership.streamlit.app` and add that URL to **Redirect URLs**. Add `http://localhost:8501` to the allow list only if you also need local development; do not leave it as the Site URL for production. Dashboard invitations use this Auth URL configuration for their email redirect. If the invitation email still contains localhost, check that the Site URL and the invite email template do not specify a localhost redirect. Disable public sign-up; create or invite accounts only through Supabase Dashboard.
2. In SQL Editor, apply [`supabase/schema.sql`](./supabase/schema.sql). Reapplying this idempotent schema after an app update adds any missing member-detail columns. It creates encrypted-record storage, roles, append-only audit history, row-level policies, and narrowly granted RPC functions.
3. In Supabase Dashboard → Authentication → Users, create/invite the first administrator. Copy that Auth user's UUID and run the bootstrap `INSERT` at the bottom of `supabase/schema.sql`, replacing the example UUID. This is the only manual first-admin role assignment.
4. Create `.streamlit/secrets.toml` from [`secrets.toml.example`](./secrets.toml.example), then fill in the project URL and public anon/publishable key:

   ```powershell
   New-Item -ItemType Directory -Force .streamlit
   Copy-Item secrets.toml.example .streamlit\secrets.toml
   ```
5. Generate a new random 32-byte encryption key and base64-encode it. For example, in PowerShell:

   ```powershell
   $bytes = New-Object byte[] 32
   [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
   [Convert]::ToBase64String($bytes)
   ```

   Store the output as `record_encryption_key` in `.streamlit/secrets.toml`. Use a separate key per environment. Never send it in chat, add it to source control, or put it in the workbook.

The secrets file has this form:

```toml
supabase_url = "https://YOUR_PROJECT_REF.supabase.co"
supabase_anon_key = "YOUR_SUPABASE_ANON_OR_PUBLISHABLE_KEY"
record_encryption_key = "BASE64_ENCODED_32_BYTE_AES_KEY"
database_password = "ROTATED_DATABASE_PASSWORD_FOR_MANUAL_MIGRATIONS"
```

The Supabase anon/publishable key is available in Supabase Dashboard → Project Settings → API Keys. It is intended for client access only in combination with the RLS policies above; never use a service-role or database password in this setting.
`database_password` is a local secret reserved for separately authorized administrative database migrations. The Streamlit app uses Supabase Auth/PostgREST and does not read this variable.

## Local setup and one-time workbook import

Use Python 3.11 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Before deploying, put the source workbook at the project root as `membership.xlsx`. Once the first admin account and role exist, run the importer from another terminal:

```powershell
python -m scripts.import_workbook
```

The importer prompts for an admin email/password, encrypts records locally, and sends them through a single atomic RPC. It imports the 33 named detail fields and excludes the blank first worksheet column. It refuses to run against a non-empty dataset, and does not print member data. Do not deploy or commit the source workbook.

## Users and roles

- **Admin**: view/edit members and history; export or bulk-import member workbooks; assign `admin` or `editor` roles.
- **Editor**: view/search/add/edit members and view history.

An admin creates/invites an email/password account in Supabase Dashboard → Authentication → Users, then uses the app's Admin users tab to assign the new user's UUID a role. Public sign-up is not provided. To let invitees set a password in the app, update Supabase Dashboard → Authentication → Email Templates → **Invite user** so its invitation link points directly to the app with the one-time token hash:

```html
<a href="https://cop-emma-membership.streamlit.app/?token_hash={{ .TokenHash }}&type=invite">Accept invitation and set your password</a>
```

Keep the deployed app URL as the Supabase Site URL and allow it in Redirect URLs. The app verifies the invitation token and then prompts the invitee to choose a password that meets the project's Auth password policy. This direct link is needed because Streamlit cannot read Supabase tokens returned in a URL fragment. Resend any invitations sent before changing the template. Configure Supabase Auth email delivery and password policies before inviting users.
The Admin users tab provides an export of every member record and accepts `.xlsx` uploads using the same blank leading column and 33 detail fields. Bulk imports append new records atomically, skip rows that exactly match existing data or an earlier row in that upload, and are limited to 1,000 new records per import. This lets admins reimport an exported workbook without duplicating its existing rows. Treat uploaded and exported workbooks as sensitive personal data and store them securely.

## Streamlit Community Cloud

Deploy the repository without `membership.xlsx`. In the app's Streamlit Community Cloud settings, add the three values from the secrets template using the TOML form shown above. The local secrets file is ignored by Git. Apply Supabase SQL and bootstrap the first admin before opening the deployed app. Community Cloud stores the app secrets server-side; never render or log them.

## Encryption, audit, and recovery

- Each of the 33 named fields is encrypted separately with AES-256-GCM in the app before being sent to its correspondingly named PostgreSQL column; values in those columns are ciphertext, not plaintext. The UUID and field name are authenticated as additional data, so ciphertext cannot be moved to another record or field. A second encrypted JSON payload supports full-record before/after audit snapshots. Database IDs, role assignments, timestamps, actor IDs, and change actions remain visible to Supabase administrators.
- Authorized app sessions decrypt the dataset in memory for substring search. This suits the current few-hundred-row workbook; re-evaluate if the dataset grows substantially. Use HTTPS and protect access to the Streamlit deployment and Supabase project.
- Save RPC writes a record and its encrypted before/after audit event atomically. App users cannot directly update/delete records or delete audit rows through the API. Audit history can be read by editors and admins.
- Back up the encryption key separately from the database backup. If the key is lost, member records and audit snapshots cannot be recovered. Key rotation requires a coordinated decrypt-and-re-encrypt migration before switching the app to a replacement key; this app does not perform key rotation automatically.
- A database backup alone is insufficient for restoration: retain the exact key version needed for its ciphertext. Restrict Supabase dashboard/project access, enable MFA for administrators, and test restore procedures.

## Checks

Run the focused local unit tests with:

```powershell
python -m unittest discover -v
```

Tests cover authenticated encryption/tampering, UUID binding, key validation, in-memory search, workbook import/export layout, and exact-match bulk-import deduplication. Live authentication, RLS, and RPC behavior require a separately configured Supabase project.
