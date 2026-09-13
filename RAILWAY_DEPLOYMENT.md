# Railway deployment guide

## What this deployment requires

SecureVote stores voter records in SQLite and encrypted ballots in a local JSON ledger. A Railway volume is therefore mandatory for a real deployment. The application refuses to start on Railway without a mounted volume unless `ALLOW_EPHEMERAL_DATA=true` is explicitly set for a disposable test.

The repository includes a Dockerfile so Railway builds the same Python 3.13 and Gunicorn environment on every deployment.

## 1. Create the service

1. Create a Railway project in the intended account.
2. Deploy `omkarNavle4518/securevote-online-voting-system` from the `main` branch.
3. Keep one service replica. SQLite and the file-backed ledger are intentionally single-instance.
4. Generate a Railway domain after the deployment is healthy.

## 2. Attach persistent storage

Attach one Railway volume to the web service and choose `/data` as its mount path. Railway exposes that location through `RAILWAY_VOLUME_MOUNT_PATH`, and the application automatically stores these files there:

- `voting.db`
- `chain_data.json`
- `secret.key`, used only when `BALLOT_SECRET` is absent outside production

Do not point `DATA_DIR` somewhere outside the mounted volume. Do not run more than one replica with this SQLite design.

## 3. Configure variables

Add these non-secret values:

```text
APP_ENV=production
ALLOW_DEV_OTP=false
ALLOW_EPHEMERAL_DATA=false
SHOW_LIVE_RESULTS=false
SMTP_FROM_NAME=SecureVote
EMAIL_PROVIDER=brevo
```

Add these values privately in Railway. Never commit them to GitHub:

```text
FLASK_SECRET_KEY=<long random value>
BALLOT_SECRET=<different long random value>
ADMIN_USERNAME=<private admin name>
ADMIN_PASSWORD=<strong value of at least 12 characters>
SMTP_USER=<sender address verified in Brevo>
BREVO_API_KEY=<Brevo transactional email API key>
```

Railway Trial and Hobby plans block outbound SMTP. The `brevo` provider sends OTPs through HTTPS instead. A Brevo free account can verify an individual sender address by email, so a custom domain is not required for initial testing. Keep the old SMTP variables only if the service later moves to a plan that permits SMTP.

Changing `BALLOT_SECRET` after votes exist makes old encrypted ballots unreadable. Changing `FLASK_SECRET_KEY` invalidates active sessions and outstanding OTP hashes.

## 4. Verify before sharing

1. Confirm `/health` returns HTTP 200 with `status` set to `ok` and `persistent_storage` set to `true`.
2. Register a test voter using an email different from the sender account.
3. Verify both registration and login OTP delivery.
4. Cast one test vote and confirm a second vote is rejected.
5. Check the admin counts, election pause control, tally, and ledger validation.
6. Restart the service and confirm the voter and test ballot still exist.

## Ownership and attribution

Deploy this repository only if you own the code or have permission under its license or from its author. Hosting the same authorized repository from another team member's account is normal. Renaming or reformatting unlicensed code does not create ownership.
