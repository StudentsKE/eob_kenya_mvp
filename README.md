# e-OB Kenya — corrected MVP

A local Flask MVP for controlled development/testing. The post-login screens are now connected to the backend.

## Working flow

Login → Dashboard → OB Register → New Occurrence → Save → OB Details → Amend/Correct → Version History / Audit → Assign Officer → Record Action → Supervisor Review.

## Run

Python 3.11+ recommended.

```bash
python -m venv .venv
# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

Demo accounts:

- `admin / ChangeMe123!`
- `obofficer / ChangeMe123!`
- `supervisor / ChangeMe123!`

Set `EOB_SECRET_KEY` to a strong random value before serious testing. The SQLite database is created automatically as `eob.db`.

## Notes

- The original static HTML designs remain in `ui/` for reference.
- The live application uses Jinja templates in `templates/`.
- `/ui/register`, `/ui/ob/<id>`, and `/ui/ob/<id>/amend` are compatibility redirects to the working routes.
- Amendments are stored as versions with a required reason; the audit trail is retained.
- OB number allocation uses a write transaction to reduce duplicate-number races in SQLite.

This remains a development prototype, not an approved National Police Service system. Do not enter real police, victim, suspect, witness, or other sensitive operational data. Before deployment, perform the required legal, privacy, security, authorization, retention, backup/DR, threat-modeling and penetration-testing reviews.


## Security and user-management updates

- New users receive a temporary password and must change it on first login.
- Passwords are **not encrypted** because passwords should never be stored reversibly. The MVP uses a salted scrypt password hash after a server-side HMAC-SHA256 pepper. Set `EOB_PASSWORD_PEPPER` to a long random secret in production.
- National ID/passport references captured in OB forms are encrypted at rest with Fernet. Set `EOB_FIELD_ENCRYPTION_KEY` to a securely managed Fernet key in production; the local `.field_key` file is only a development fallback.
- The OB Register supports search by OB number, station code, reporting person, location, narrative, category, status, date, and ID/passport last four digits. Full identification numbers are not used as plaintext search terms.
- The interface uses a Kenya-police-inspired navy/blue/red/gold palette and a text-only NPS placeholder crest; no official logo asset is bundled.

### Production security note
This remains a development MVP. For operational deployment, use HTTPS, secure secret storage, managed PostgreSQL, CSRF protection, MFA, centralized audit logging, key rotation, backups, access reviews, and a formal security/privacy assessment before entering real police records or identification data.

## Online stakeholder demo

This repository includes `render.yaml`, a `Procfile`, a `/health` endpoint and synthetic demo data support for a presentation-only deployment.

### Render

1. Push this project to a GitHub repository.
2. In Render, create a Web Service from that repository, or use the included Blueprint configuration.
3. The service uses `pip install -r requirements.txt` and Gunicorn.
4. Keep `EOB_DEMO_MODE=1` for a pitch environment and use synthetic data only.
5. Do not connect real police records or personal identification data to this demo deployment.

For a real deployment, replace SQLite with PostgreSQL, use managed secret/key storage, configure backups, logging, access reviews, MFA and an appropriate security/privacy assessment.
