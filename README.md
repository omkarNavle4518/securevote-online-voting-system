# SecureVote

SecureVote is a Flask-based academic online voting system with email OTP registration and login, encrypted ballots, one-voter-one-vote enforcement, an admin dashboard, and a local tamper-evident hash chain.

> This is a college demonstration project, not a real public-election platform. The custom hash chain demonstrates tamper evidence but is not a decentralized blockchain and has no independent consensus network.

## Features

- Email OTP verification during registration and login
- Six-digit cryptographically generated OTPs
- OTP hashes instead of plaintext OTP storage
- Five-minute expiry, five-attempt limit, and 60-second resend cooldown
- Unique random Voter ID after successful email verification
- Fernet-encrypted candidate choices in a hash-linked ledger
- Transaction and process locking to stop duplicate rapid vote submissions
- Admin dashboard, election open/pause control, tally, and ledger validation
- Public results hidden while voting is open, with an opt-in demo override
- CSRF protection, secure production cookies, security headers, input validation, and no-cache responses on sensitive pages
- Deployment health check at `/health`, including persistent-storage status on Railway
- Automatic SQLite schema initialization when Gunicorn starts
- Atomic ledger file writes to reduce corruption risk
- Automatic use of an attached Railway volume through `RAILWAY_VOLUME_MOUNT_PATH`
- Production startup guard that prevents accidental ephemeral Railway storage

## Project structure

```text
app.py                       Flask routes, OTP, database, and voting logic
blockchain.py                Tamper-evident block ledger
templates/                   Jinja HTML templates
static/style.css             Responsive styling
render.yaml                  Render Blueprint configuration
Dockerfile                   Reproducible Railway container build
gunicorn.conf.py             Production server settings
Procfile                     Alternative platform start command
.env.example                 Environment-variable template without secrets
requirements.txt             Production dependencies
requirements-dev.txt         Test dependencies
tests/                       Automated application tests
RENDER_DEPLOYMENT.md         Exact deployment and Gmail setup guide
RAILWAY_DEPLOYMENT.md        Railway volume, variables, and verification guide
```

## Run locally

1. Create and activate a virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. For a local demo, run:

   ```bash
   python app.py
   ```

4. Open `http://127.0.0.1:5000`.

Without email-provider credentials, local development displays the OTP only when `ALLOW_DEV_OTP=true`. Production mode never exposes an OTP on screen.

Local-only admin defaults are `admin` and `admin@123`. Production refuses to start unless a separate strong admin username and password are configured.

## Production environment variables

| Variable | Required in production | Purpose |
| --- | --- | --- |
| `APP_ENV` | Yes | Use `production` |
| `FLASK_SECRET_KEY` | Yes | Signs sessions and OTP hashes |
| `BALLOT_SECRET` | Yes | Derives the Fernet ballot encryption key |
| `ADMIN_USERNAME` | Yes | Admin login username |
| `ADMIN_PASSWORD` | Yes | Admin password, minimum 12 characters |
| `EMAIL_PROVIDER` | Yes | `brevo` for Railway Trial/Hobby; `smtp` where outbound SMTP is available |
| `BREVO_API_KEY` | With `EMAIL_PROVIDER=brevo` | Brevo API key with transactional-email access |
| `SMTP_USER` | Yes | Verified sender email for Brevo, or SMTP login address |
| `SMTP_PASS` | With `EMAIL_PROVIDER=smtp` | Google App Password or other SMTP password |
| `SMTP_HOST` | With `EMAIL_PROVIDER=smtp` | Defaults to `smtp.gmail.com` |
| `SMTP_PORT` | With `EMAIL_PROVIDER=smtp` | Defaults to `587` |
| `SMTP_FROM_NAME` | No | Sender name, defaults to `SecureVote` |
| `DATA_DIR` | Platform dependent | Explicit persistent data location; Railway automatically uses its mounted volume |
| `ALLOW_DEV_OTP` | Yes | Must remain `false` in production |
| `ALLOW_EPHEMERAL_DATA` | Railway safety override | Keep `false`; use `true` only for a disposable test without a volume |
| `SHOW_LIVE_RESULTS` | No | Keep `false` for a fair election; `true` is only useful for demos |

Railway Trial and Hobby plans block outbound SMTP. Use `EMAIL_PROVIDER=brevo` there so OTP messages travel through Brevo's HTTPS API. Verify `SMTP_USER` as a sender in Brevo, and store `BREVO_API_KEY` only as a private environment variable. The SMTP path remains available for local use and hosting plans that allow it.

The Blueprint generates `FLASK_SECRET_KEY` and `BALLOT_SECRET`. Never commit real passwords, App Passwords, or API keys to GitHub or place them in `.env.example`.

## Persistent data

The project writes three files under `DATA_DIR`:

- `voting.db`: voter records, voting status, and hashed OTP state
- `chain_data.json`: encrypted ballots and hash-linked blocks
- `secret.key`: local-only fallback encryption key when `BALLOT_SECRET` is not set

The included Render Blueprint mounts a disk at `/var/data/securevote`. On Railway, attach a volume at `/data`; the application detects the Railway-provided mount path automatically. Keep one Gunicorn worker and one service replica because the application uses SQLite and a local ledger file.

## Test

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Important limitations

- Email ownership is checked, but government identity and voter eligibility are not verified.
- The ledger is centralized and file-backed. It is not Ethereum or another distributed blockchain.
- Admins can see voter names and emails. Ballot choices are encrypted and linked only to a one-way hash of the Voter ID.
- This design is intentionally single-instance. Horizontal scaling needs a shared database and a different ledger architecture.
- Persistent SQLite storage requires a mounted platform volume. See `RAILWAY_DEPLOYMENT.md` for Railway or `RENDER_DEPLOYMENT.md` for Render.

## Code ownership

Deploy this repository only when you own it or have permission to use it. Railway does not require superficial rewrites of authorized code. Changing identifiers, formatting, or branding does not turn unlicensed code into original work.
