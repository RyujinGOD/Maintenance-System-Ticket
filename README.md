# Ticket System Full (Flask) - Enhanced Prototype

## Features added in this "full" package
- JWT token-based API authentication (PyJWT)
- File attachments for tickets (uploads/)
- Unit tests (pytest) and a GitHub Actions CI workflow
- Dockerfile & docker-compose for containerized local running
- Email scaffold (Flask-Mail) and CSV export
- All original server-rendered templates remain for manual testing

## Run locally (development)
1. Create virtualenv:
   ```
   python -m venv venv
   source venv/bin/activate   # on Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Optional: copy `.env.example` to `.env` and edit SMTP / SECRET_KEY / DATABASE_URL.
3. Run:
   ```
   python app.py
   ```
   The app will create `app.db` and an uploads/ directory on first run.
4. Use `/bootstrap-admin` to create an initial admin (admin@example.com / admin123).

## Docker (recommended for testing)
```
docker build -t ticket-system-full .
docker run -p 5000:5000 --env-file .env -v "$(pwd)/uploads:/app/uploads" ticket-system-full
```
Or with docker-compose:
```
docker compose up --build
```

## Testing & CI
- Run unit tests locally: `pytest -q`
- GitHub Actions workflow `/.github/workflows/ci.yml` runs `pytest`.

## Notes
- File uploads are stored under `uploads/` by default; in production, use S3 or another object store.
- JWT tokens expire (configurable in `config.py`).
- This is a prototype; secure secrets properly for production.
