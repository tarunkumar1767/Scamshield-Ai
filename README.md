# ScamShield AI

ScamShield AI is a full-stack educational tool for reviewing suspicious messages, screenshots, and URLs. It provides automated guidance and heuristic indicators; it is not an authority and cannot guarantee that content is safe or malicious.

## The problem and solution

Scam messages often rely on urgency, impersonation, unexpected payment requests, and links that are difficult to judge quickly. ScamShield brings three lightweight checks into one interface, explains the signals it finds, and keeps only a minimal analysis history in the browser.

## Features

- Landing page, sign-up, sign-in, password reset, and account-scoped workspace (Supabase Auth when configured).
- Local development demo access when Supabase is not configured.
- Message analysis through FastAPI, with deterministic `DEMO_MODE`/fallback analysis, the official Google Gemini SDK, or an OpenAI-compatible provider.
- Screenshot text extraction in the browser with Tesseract.js, followed by `POST /api/analyze/image`; image bytes stay in the browser.
- URL structure checks for protocol, hostname, port, path, query, and common heuristic indicators. The submitted destination is never visited.
- Dashboard with locally calculated totals and recent scans.
- History with details, deletion, and clear-all confirmation. It stores sanitized analysis metadata, not the original message or screenshot.
- Safety Center with scam education, fictional examples, and a browser-only checklist.

## Technology

- Frontend: React, TypeScript, Vite, Tailwind CSS, Lucide icons, Tesseract.js, Supabase JS.
- Backend: Python, FastAPI, Pydantic Settings, Uvicorn.
- Storage: browser `localStorage` for scan history and Safety Center checklist state.
- Optional AI service: Google Gen AI SDK for Gemini, with an OpenAI-compatible Chat Completions option for other providers; credentials stay on the backend.

## Project structure

```text
.
├── backend/
│   ├── app/
│   │   ├── analyzer.py       # Demo and optional AI message analysis
│   │   ├── config.py         # Backend environment settings
│   │   ├── main.py           # FastAPI app and API routes
│   │   └── url_analyzer.py   # Local URL parsing and heuristic assessment
│   ├── .env.example
│   └── requirements.txt
├── frontend/
│   ├── package-lock.json
│   ├── vite.config.ts
│   ├── vercel.json
│   ├── src/
│   │   ├── components/AuthPage.tsx
│   │   ├── lib/supabase.ts
│   │   ├── AppNew.tsx        # App routes, scanners, dashboard, history, safety center
│   │   ├── index.css
│   │   └── main.tsx
│   ├── .env.example
│   └── package.json
├── .env.example              # Combined environment template
└── README.md
```

## Requirements

- Node.js 20.19+ or 22.12+ (required by the locked Vite 8 release) and npm.
- Python 3.10 or newer and pip.
- A modern browser. Tesseract.js may need network access on its first use to obtain OCR language data.

## Run locally

Open two terminals from the project root.

### 1. Configure and start the backend

```powershell
Copy-Item backend/.env.example backend/.env
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend listens at `http://127.0.0.1:8000`. Check `http://127.0.0.1:8000/health` or open the interactive API docs at `http://127.0.0.1:8000/docs`.

### 2. Configure and start the frontend

In a second terminal, from the project root:

```powershell
Copy-Item frontend/.env.example frontend/.env
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**.

## Demo mode

`backend/.env.example` sets `DEMO_MODE=true`. In this mode, message and URL analysis work without AI credentials. The message analyzer uses deterministic educational signals; the URL checker uses local structural heuristics. Neither result confirms safety or maliciousness.

If Supabase environment values are absent and `VITE_DEMO_MODE=true`, the development build offers a clearly labeled local demo session. It does not create or authenticate an account, stores no password, and ends when the page is refreshed. Demo access is limited to Vite development mode; a production build does not enable it.

## Optional Supabase authentication

For real accounts, create a Supabase project and enable email/password authentication. Add the project URL and publishable/anon key to `frontend/.env`:

```dotenv
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-publishable-or-anon-key
VITE_DEMO_MODE=true
```

Configure the Supabase Site URL as `http://localhost:5173` and add `http://localhost:5173/reset-password` to the Auth redirect URL allow list. Restart Vite after changing environment values. The browser must only receive the public anon/publishable key; **never put a service-role key in frontend variables**. Real sign-up, login, session persistence, sign-out, and password reset depend on valid Supabase project settings and credentials.

## Optional AI message analysis

Keep AI provider credentials in `backend/.env`, never in Vite variables or source control. Set:

```dotenv
DEMO_MODE=false
AI_API_KEY=your-provider-key
AI_API_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
AI_MODEL=gemini-3.8-flash
AI_REQUEST_TIMEOUT_SECONDS=60
```

For a Google hostname, the backend uses the official Google Gen AI SDK and Gemini Interactions API; `AI_API_BASE_URL` selects the Google provider while the SDK manages its API transport. The request uses structured JSON output, low thinking for Gemini 3 models, a configured timeout, and `store=false`. Set `AI_API_KEY` and `AI_MODEL` only in the backend environment. `AI_REQUEST_TIMEOUT_SECONDS` defaults to 60 and accepts values from 1 to 300 seconds. Other configured provider hosts continue through the OpenAI-compatible Chat Completions path.

Every valid AI response is checked against the ScamShield schema and score bands. Provider requests are attempted at most three times for transient HTTP, timeout, and network failures with bounded exponential backoff and jitter; permanent configuration/authentication failures are not retried. Any provider failure, invalid JSON, or schema mismatch returns deterministic analysis labeled `analysis_source: "fallback"` and `demo_mode: false`. The UI identifies fallback output as deterministic and not AI-generated. Provider bodies, credentials, stack traces, and submitted content are never logged or returned as provider errors. Health checks report configuration presence only and do not call the provider.

## Deployment

The frontend and backend are deployed separately. The frontend calls the backend using `VITE_API_URL`; set it to `https://scamshield-ai-ekb5.onrender.com` for the current deployment, with no trailing slash. In local development, Vite proxies `/api` to `http://127.0.0.1:8000`.

### Frontend — Vercel

- **Root directory:** `frontend`
- **Install command:** `npm install` (or `npm ci` to install exactly from the committed lockfile)
- **Build command:** `npm run build`
- **Output directory:** `dist`
- `frontend/vercel.json` rewrites client-side routes to the Vite entry page so direct links and refreshes work.
- **Environment variables:**
  - `VITE_API_URL` — required; the deployed Render backend origin, without a trailing slash.
  - `VITE_SUPABASE_URL` — required for real Supabase authentication.
  - `VITE_SUPABASE_ANON_KEY` — required for real Supabase authentication. Use only the public anon/publishable key; never use a service-role key in the browser.

For this deployment, set these values in Vercel (keep Supabase values private to the project's Vercel settings; never put a service-role key here):

```dotenv
VITE_API_URL=https://scamshield-ai-ekb5.onrender.com
VITE_SUPABASE_URL=https://<project-ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<public-anon-or-publishable-key>
```

Set the Supabase Auth Site URL to the deployed Vercel origin and add `<your-vercel-origin>/reset-password` to the allowed redirect URLs. Configure both the production domain and any intended Vercel preview domains explicitly as Supabase redirect URLs.

### Backend — Render

- **Root directory:** `backend`
- **Build/install command:** `pip install -r requirements.txt`
- **Start command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Environment variables:**
  - `DEMO_MODE` — `true` to run without an AI provider; set `false` only when provider credentials and a model are configured.
  - `FRONTEND_URL` — optional additional exact frontend origins; separate multiple origins with commas and omit paths. The two ScamShield Vercel origins and the local Vite origins are allowed by default. Do not use `*`.
  - `AI_API_KEY` — optional backend-only provider credential; required only when `DEMO_MODE=false`.
  - `AI_MODEL` — provider model name; required only when `DEMO_MODE=false`.
  - `AI_API_BASE_URL` — provider base URL; a Google hostname selects the official Gemini SDK, otherwise the OpenAI-compatible path is used. Defaults to `https://api.openai.com/v1`.
  - `AI_REQUEST_TIMEOUT_SECONDS` — provider request timeout in seconds; defaults to `60`, allowed range `1`–`300`.
  - `URL_REPUTATION_API_KEY` — reserved optional variable; the current URL checker is heuristic-only and does not use a reputation service.

For AI analysis on the current deployment, set `DEMO_MODE=false` and provide the provider's own API key and supported model in Render. Never use a Supabase URL, anon key, or service-role key as `AI_API_KEY`.

```dotenv
DEMO_MODE=false
AI_API_KEY=<provider-key-set-only-in-Render>
AI_API_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
AI_MODEL=gemini-3.8-flash
AI_REQUEST_TIMEOUT_SECONDS=60
FRONTEND_URL=https://scamshield-ai-j7gz.vercel.app,https://scamshield-ai-j7gz-ed4qkl7s-tarunkataria007s-projects.vercel.app
```

The health endpoint is `GET /api/health` (the legacy `GET /health` route remains available). It returns backend status, demo-mode status, and a boolean indicating whether the AI key and model are present; this does not verify that the provider is reachable. The API does not visit submitted URLs.

After updating Render environment variables, use **Manual Deploy → Deploy latest commit** if automatic deploys are disabled. After updating Vercel variables, trigger a new deployment so Vite rebuilds the frontend with the new values.

### Supabase

Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` in Vercel's project environment settings for every environment that should use real accounts. These are public frontend configuration values, not service credentials. Keep all AI provider keys and other private credentials in Render environment settings only. If Supabase is not configured, the production app does not enable the local development demo login.

## API routes

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Backend and demo-mode status |
| `GET` | `/api/health` | Deployment health check |
| `POST` | `/api/analyze/message` | Analyze `{ "message": "..." }` and return structured risk guidance |
| `POST` | `/api/analyze/image` | Analyze `{ "extracted_text": "..." }` from browser-side Tesseract OCR; image bytes stay in the browser |
| `POST` | `/api/analyze/url` | Analyze `{ "url": "https://example.com/path" }` locally without visiting it |

FastAPI's generated schema and interactive docs are at `/docs` while the backend is running.

## Privacy and security notes

- Scan history is local to the browser and namespaced by the current user ID when real Supabase auth is active. It is not synchronized to a server.
- History keeps risk level/score, category, a short sanitized summary, and limited analysis details needed to reopen a result. It does not store the submitted full message or uploaded screenshot. Sensitive-looking codes and payment numbers in stored result text are redacted.
- Screenshot images are read in the browser. Only OCR-extracted text is submitted for message analysis.
- URL analysis parses the address locally on the backend and does not resolve DNS, open, crawl, or execute the submitted destination.
- The optional message AI provider receives the message content when configured and `DEMO_MODE=false`; avoid submitting secrets or personal information.
- Environment files and dependency/build directories are ignored by `.gitignore`. Review your own environment files before sharing or committing the project.

## Limitations

- The demo message analyzer is a small rule-based demonstration, not a trained detection system.
- URL checks are structural heuristics and do not use a reputation database unless one is separately added.
- A clean result is not proof that a sender or site is trustworthy; a warning is not proof of maliciousness.
- Real authentication and AI provider behavior cannot be exercised until the relevant project credentials and settings are supplied.
- OCR accuracy depends on image quality, language, font size, and browser network availability for initial language data.
- Backend automated provider, fallback, route, risk-score, and CORS tests run with `python -m unittest discover -s tests` from `backend`; the frontend can be type-checked and production-built with `npm run build` from `frontend`.

## Suggested next improvements

- Add automated API and UI tests for scanners, history, auth guards, and responsive layouts.
- Add an optional, privacy-reviewed URL reputation integration behind a server-side setting.
- Add retention controls and an explicit export/delete flow for local history.
- Add monitoring and a documented data-retention policy.
- Capture actual product screenshots after configuring a demo account and add them to this README.

## Hackathon demo walkthrough

1. Start the backend with `DEMO_MODE=true` and the Vite development frontend.
2. Open `http://localhost:5173` and enter the labeled local demo session if Supabase is not configured.
3. Scan an educational message, inspect its evidence and recommended actions, then view the saved record in History and Dashboard.
4. Upload a screenshot with readable text to demonstrate in-browser OCR, or inspect a sample URL to see structural findings without visiting it.
5. Visit the Safety Center for fictional examples and the interactive checklist.

## Screenshots

No screenshots are included yet. Add screenshots captured from a running application here when they are available.

<!-- Vercel deployment trigger -->
