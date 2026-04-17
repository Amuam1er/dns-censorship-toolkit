# DNS Censorship Toolkit

A DNS-based censorship detection and circumvention system that identifies 
ISP-level interference and provides actionable bypass recommendations.

**Live Demo:** https://amuam1er.github.io/dns-censorship-toolkit

---

## Overview

This system solves a single problem: users cannot reliably tell when access 
to a website is being manipulated at the DNS level, nor how to bypass it.

**Core loop:**
Input domain → Detect (ISP / Public / DoH) → Classify → Recommend fix

Built as a final year dissertation project at The ICT University, Faculty of 
Information and Communication Technology, 2026.

**Research topic:** Design and Implementation of a DNS-Based Censorship 
Detection and Circumvention System

---

## Detection Methods

| Method | Signal | Recommended Fix |
|---|---|---|
| `poisoning` | ISP IP ≠ DoH IP | Switch to 1.1.1.1 / 8.8.8.8 |
| `hijacking` | ISP returns private IP (RFC 1918) | Use DNS over HTTPS |
| `nxdomain` | ISP says domain doesn't exist, DoH resolves it | Switch resolver |
| `timeout` | ISP drops DNS query, DoH works | Use encrypted DNS |
| `cdn-variance` | IPs differ but all are known CDN nodes | No action needed |

---

## System Architecture
[ User Interface ]
↓
[ API Layer — POST /check ]
↓
[ DNS Query Module ]
├── ISP Resolver (system DNS)
├── Public Resolver (1.1.1.1)
└── DoH Resolver (Cloudflare HTTPS)
↓
[ Comparison Engine ]
↓
[ Classification Engine ]
↓
[ Recommendation Engine ]
↓
[ Response to User ]

---

## Setup

### Backend

```bash
cd backend
npm install
node server.js
```

Server runs on `http://localhost:3000`

### Frontend

Open `index.html` in any browser, or access the live deployment above.

---

## API Reference

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
  "recommendation": "Your ISP is falsely reporting this domain as 
  non-existent. Switch your DNS resolver to 1.1.1.1 or 8.8.8.8, 
  or enable DNS over HTTPS in your browser."
}
```

---

## Validation

Run the full test suite before deploying:

```bash
cd backend
node test.js
```

26/26 tests passing across all detection categories including full 
RFC 1918 private IP coverage and CDN variance detection.

---

## Deployment

**Backend:** Railway — root directory set to `/backend`

**Frontend:** GitHub Pages — `index.html` served from root

After deploying backend, update `API_URL` in `index.html` to your 
live Railway URL.

---

## Known Limitations

- Detects DNS-layer interference only. IP blocking and deep packet 
  inspection (DPI) are outside scope.
- CDN whitelist covers major providers (Cloudflare, Google, Fastly, 
  Akamai) but is not exhaustive.
- ISP resolver detection uses the server's network context, not the 
  user's local machine.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.

This software is free to use, modify, and distribute under the terms 
of the GPL-3.0. Any derivative work must also remain open source.

---

## Citation

If you use this project in academic work, please cite:
Amuam Beng (2026). DNS Censorship Detection & Circumvention System.
ICT University, Faculty of Information and Communication Technology.
https://github.com/Amuam1er/dns-censorship-toolkit

---

## Acknowledgements

Supervised by Engr. Tekoh Palma, ICT University.