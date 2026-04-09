# DNS Censorship Toolkit

Detects DNS-based censorship and provides actionable bypass recommendations.

## Core Loop

```
Input domain → Detect (ISP / Public / DoH) → Classify → Recommend fix
```

## Detection Methods

| Method | Signal | Fix |
|---|---|---|
| `poisoning` | ISP IP ≠ DoH IP | Switch to 1.1.1.1 / 8.8.8.8 |
| `hijacking` | ISP returns private IP (RFC 1918) | Use DNS over HTTPS |
| `nxdomain` | ISP says NXDOMAIN, DoH resolves | Switch resolver |
| `timeout` | ISP doesn't respond, DoH works | Use encrypted DNS |

## Setup

### Backend

```bash
cd backend
npm install
node server.js
```

Server runs on `http://localhost:3000`

### Frontend

Open `frontend/index.html` in any browser.

## API

### POST /check

**Request:**
```json
{ "domain": "example.com" }
```

With custom ISP resolver:
```json
{ "domain": "example.com", "resolver": "196.x.x.x" }
```

**Response:**
```json
{
  "domain": "example.com",
  "status": "blocked",
  "method": "nxdomain",
  "evidence": {
    "isp_result": "ENOTFOUND",
    "isp_source": "196.x.x.x",
    "public_result": "93.184.216.34",
    "doh_result": "93.184.216.34"
  },
  "recommendation": "Your ISP is falsely reporting this domain as non-existent. Switch your DNS resolver to 1.1.1.1 or 8.8.8.8, or enable DNS over HTTPS in your browser."
}
```

## Deployment

**Backend:** Render or Railway — connect GitHub repo, deploy `/backend`

**Frontend:** GitHub Pages — enable in repo settings, select `/frontend`

After deploying backend, update `API_URL` in `frontend/index.html` to your deployed URL.

## Validation

Run the test suite before deploying:

```bash
cd backend
node test.js
```

All 4 spec cases + RFC 1918 coverage must pass (currently 19/19).
