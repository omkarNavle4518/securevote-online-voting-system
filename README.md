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
- Render health check at `/health`
- Automatic SQLite schema initialization when Gunicorn starts
- Atomic ledger file writes to reduce corruption risk

## Project structure

```text
app.py                       Flask routes, OTP, database, and voting logic
blockchain.py                Tamper-evident block ledger
templates/                   Jinja HTML templates
static/style.css             Responsive styling
render.yaml                  Render Blueprint configuration
gunicorn.conf.py             Production server settings
Procfile                     Alternative Render start command
.env.example                 Environment-variable template without secrets
requirements.txt             Production dependencies
requirements-dev.txt         Test dependencies
tests/                       Automated application tests
RENDER_DEPLOYMENT.md         Exact deployment and Gmail setup guide
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

Without SMTP credentials, local development displays the OTP only when `ALLOW_DEV_OTP=true`. Production mode never exposes an OTP on screen.

Local-only admin defaults are `admin` and `admin@123`. Render production refuses to start unless a separate strong admin username and password are configured.

## Production environment variables

| Variable | Required on Render | Purpose |
| --- | --- | --- |
| `APP_ENV` | Yes | Use `production` |
| `FLASK_SECRET_KEY` | Yes | Signs sessions and OTP hashes |
| `BALLOT_SECRET` | Yes | Derives the Fernet ballot encryption key |
| `ADMIN_USERNAME` | Yes | Admin login username |
| `ADMIN_PASSWORD` | Yes | Admin password, minimum 12 characters |
| `SMTP_USER` | Yes | New Gmail address used to send OTPs |
| `SMTP_PASS` | Yes | Google 16-character App Password, not the Gmail login password |
| `SMTP_HOST` | Yes | `smtp.gmail.com` |
| `SMTP_PORT` | Yes | `587` |
| `SMTP_FROM_NAME` | No | Sender name, defaults to `SecureVote` |
| `DATA_DIR` | Yes | Persistent data location, `/var/data/securevote` in the Blueprint |
| `ALLOW_DEV_OTP` | Yes | Must remain `false` in production |
| `SHOW_LIVE_RESULTS` | No | Keep `false` for a fair election; `true` is only useful for demos |

The Blueprint generates `FLASK_SECRET_KEY` and `BALLOT_SECRET`. Never commit real passwords or App Passwords to GitHub or place them in `.env.example`.

## Persistent data

The project writes three files under `DATA_DIR`:

- `voting.db`: voter records, voting status, and hashed OTP state
- `chain_data.json`: encrypted ballots and hash-linked blocks
- `secret.key`: local-only fallback encryption key when `BALLOT_SECRET` is not set

The included Render Blueprint mounts a 1 GB persistent disk at `/var/data/securevote`. Keep one Gunicorn worker and one Render instance because the application uses SQLite and a local ledger file.

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
- Gmail SMTP and persistent SQLite storage require a paid Render web service. See `RENDER_DEPLOYMENT.md` before deploying.
