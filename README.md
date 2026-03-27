# Pawtner Hope

Pawtner Hope is a Go-based pet adoption and donation platform with a static HTML frontend and a JSON API backend.
It supports:

- Pet discovery, filtering, and CRUD operations
- User registration with email OTP verification
- Login with token-based auth
- Adoption inquiries and service bookings
- Donation processing with receipt generation
- Optional MongoDB persistence
- Optional SMTP email delivery for OTP, welcome, and receipts

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Run the App](#run-the-app)
- [API Reference](#api-reference)
- [Authentication Flow](#authentication-flow)
- [Data and Persistence](#data-and-persistence)
- [Testing](#testing)
- [Docker](#docker)
- [Fly.io Deployment](#flyio-deployment)
- [Default Admin Account](#default-admin-account)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

## Overview

The server is implemented in a single Go entrypoint, `server.go`, and serves both:

1. Static pages (`index.html`, `adoption.html`, `donate.html`, etc.)
2. API endpoints under `/api/...`

At startup, the app seeds in-memory data (pets, services, and default admin). If MongoDB is configured, it loads and syncs data to the database.

## Features

### Core platform

- Pet listing and filtering by species/status/search query
- Pet details lookup by ID
- Pet create/update/delete
- Service list and booking creation
- Contact form submission
- Adoption inquiry submission
- Donation creation and receipt generation
- Statistics endpoint for dashboard views

### Auth and account

- Signup with email OTP verification
- Login returning an auth token
- Authenticated profile endpoint (`/api/auth/me`)
- Role metadata (`role`, `isadmin`) in token/user payload

### Background processing

- Worker goroutines for:
  - Email sending jobs
  - Donation payment processing simulation
  - Payment confirmation listener

### Email support (optional)

- OTP email for registration verification
- Welcome email after successful verification
- Donation receipt email

If SMTP is not configured, email operations are safely skipped (logged, no crash).

## Tech Stack

- Language: Go 1.21+ (module target), Docker build arg supports newer versions
- HTTP: Standard library (`net/http`)
- Password hashing: `golang.org/x/crypto/bcrypt`
- Database: MongoDB via `go.mongodb.org/mongo-driver/v2`
- Frontend: Static HTML pages styled with CSS/Tailwind (CDN usage in pages)
- Deployment: Docker + Fly.io config included

## Project Structure

```text
.
|- server.go             # Main backend server and API handlers
|- server_test.go        # Unit/integration-style tests for core logic and handlers
|- go.mod / go.sum       # Go module definition
|- Dockerfile            # Multi-stage image build
|- fly.toml              # Fly.io deployment config
|- index.html            # Landing page
|- auth.html             # Login/Register + OTP flow UI
|- adoption.html         # Adoption page UI
|- donate.html           # Donation page UI
|- service.html          # Services page UI
|- admin.html            # Admin page UI
|- dashboard.html        # Dashboard page UI
|- server_old/           # Older server versions
```

## Getting Started

### Prerequisites

- Go 1.21 or newer
- (Optional) MongoDB instance
- (Optional) Gmail app password for SMTP emails

### 1. Clone and install dependencies

```bash
git clone <your-repo-url>
cd pawtner-hope
go mod download
```

### 2. Configure environment

Create a `.env` file in the project root:

```env
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority
GMAIL_USER=your-email@gmail.com
GMAIL_PASS=your-app-password
```

Notes:

- `.env` is optional
- Existing system environment variables take priority over values in `.env`
- If `MONGODB_URI` is missing, app runs in memory-only mode
- If `GMAIL_USER`/`GMAIL_PASS` are missing, emails are skipped

## Environment Variables

| Name          | Required | Purpose                                                                     |
| ------------- | -------- | --------------------------------------------------------------------------- |
| `MONGODB_URI` | No       | Enables MongoDB connection and persistence                                  |
| `GMAIL_USER`  | No       | SMTP sender account for outgoing emails                                     |
| `GMAIL_PASS`  | No       | SMTP app password for sender account                                        |
| `PORT`        | No       | Present in deployment configs; current server code listens on fixed `:8080` |

## Run the App

### Local run

```bash
go run .
```

Server starts on:

- `http://localhost:8080`

### Open frontend pages

- `/`
- `/service.html`
- `/adoption.html`
- `/donate.html`
- `/auth.html`
- `/admin.html`
- `/dashboard.html`

## API Reference

All API endpoints return JSON.

### Pets

| Method | Endpoint         | Description                       |
| ------ | ---------------- | --------------------------------- |
| GET    | `/api/pets`      | List pets (supports query params) |
| GET    | `/api/pets/{id}` | Get pet by ID                     |
| POST   | `/api/pets`      | Create pet                        |
| PUT    | `/api/pets/{id}` | Update pet                        |
| DELETE | `/api/pets/{id}` | Delete pet                        |

Query params for `GET /api/pets`:

- `species`
- `status`
- `q` (searches name/species/breed)

### Services and bookings

| Method | Endpoint        | Description                               |
| ------ | --------------- | ----------------------------------------- |
| GET    | `/api/services` | List services (optional `category` query) |
| GET    | `/api/bookings` | List all bookings                         |
| POST   | `/api/bookings` | Create service booking                    |

### Contact and stats

| Method | Endpoint          | Description         |
| ------ | ----------------- | ------------------- |
| POST   | `/api/contact`    | Submit contact form |
| GET    | `/api/statistics` | Platform statistics |

### Auth

| Method | Endpoint             | Description                        |
| ------ | -------------------- | ---------------------------------- |
| POST   | `/api/auth/register` | Start signup and send OTP          |
| POST   | `/api/auth/verify`   | Verify OTP and create account      |
| POST   | `/api/auth/login`    | Login and receive token            |
| GET    | `/api/auth/me`       | Get current user from Bearer token |

### Adoptions

| Method | Endpoint         | Description             |
| ------ | ---------------- | ----------------------- |
| GET    | `/api/adoptions` | List adoption inquiries |
| POST   | `/api/adoptions` | Create adoption inquiry |

### Donations

| Method | Endpoint         | Description                          |
| ------ | ---------------- | ------------------------------------ |
| GET    | `/api/donations` | List donations                       |
| POST   | `/api/donations` | Create donation and generate receipt |

### Example request snippets

Register:

```bash
curl -X POST http://localhost:8080/api/auth/register \
	-H "Content-Type: application/json" \
	-d '{"email":"alice@example.com","username":"alice","password":"secret123"}'
```

Verify OTP:

```bash
curl -X POST http://localhost:8080/api/auth/verify \
	-H "Content-Type: application/json" \
	-d '{"email":"alice@example.com","code":"123456"}'
```

Login:

```bash
curl -X POST http://localhost:8080/api/auth/login \
	-H "Content-Type: application/json" \
	-d '{"email":"alice@example.com","password":"secret123"}'
```

Get profile:

```bash
curl http://localhost:8080/api/auth/me \
	-H "Authorization: Bearer <token>"
```

Create donation:

```bash
curl -X POST http://localhost:8080/api/donations \
	-H "Content-Type: application/json" \
	-d '{
		"donorName":"Alice",
		"donorEmail":"alice@example.com",
		"amount":500,
		"paymentMethod":"UPI",
		"paymentViaDeeplink":true
	}'
```

## Authentication Flow

1. User submits email/username/password to register endpoint.
2. Server creates a pending registration and emails a 6-digit OTP (5-minute expiry).
3. User submits OTP to verify endpoint.
4. Server creates the user and sends a welcome email.
5. User logs in and receives a token valid for 24 hours.
6. Client sends `Authorization: Bearer <token>` to access `/api/auth/me`.

## Data and Persistence

### In-memory first

The app maintains in-memory slices and maps for fast reads and updates.

### MongoDB sync behavior

- If connected, pets/users/donations/inquiries are loaded from MongoDB at startup.
- Writes are synced asynchronously with upsert behavior.
- If pets collection is empty, sample pets are seeded to MongoDB.

### Default seeded data

- Sample pets and services
- Default admin account

## Testing

Run tests:

```bash
go test ./...
```

Current status (as of 2026-03-16): one test fails in `TestHashPassword` because bcrypt hashes are intentionally salted and therefore non-deterministic.

## Docker

Build image:

```bash
docker build -t pawtner-hope .
```

Run container:

```bash
docker run --rm -p 8080:8080 \
	-e MONGODB_URI="<your-uri>" \
	-e GMAIL_USER="<your-email>" \
	-e GMAIL_PASS="<your-app-password>" \
	pawtner-hope
```

The Dockerfile uses a multi-stage build and runs as a non-root user.

## Fly.io Deployment

This repo includes `fly.toml` configured for app name `pawtner-hope` and internal port `8080`.

Typical deploy flow:

```bash
fly auth login
fly launch --copy-config --no-deploy
fly secrets set MONGODB_URI="<your-uri>" GMAIL_USER="<email>" GMAIL_PASS="<app-pass>"
fly deploy
```

## Default Admin Account

Seeded on startup:

- Email: `admin@pawtner.com`
- Password: `admin123`

Change this for production use.

## Troubleshooting

### Server starts but emails are not sent

- Check `GMAIL_USER` and `GMAIL_PASS`
- Ensure Gmail app password is used (not account password)
- Look for `[EMAIL-SKIP]` or `[EMAIL-ERROR]` logs

### Data does not persist across restarts

- Confirm `MONGODB_URI` is set and reachable
- Check startup logs for MongoDB connection and ping success

### CORS or API access issues

- API handlers include permissive CORS headers
- Verify your frontend calls the correct host/port (`localhost:8080`)

### Port overrides not working

- Current server code listens on fixed `:8080`
- `PORT` env is not yet used by `http.ListenAndServe`

## Security Notes

- Tokens are stored in-memory (not JWT, not persisted)
- No rate limiting on auth/OTP endpoints
- Default admin credentials are static in source
- CORS is wide open (`*`)

For production hardening, prioritize:

1. Replace static admin credentials and force secure bootstrapping
2. Move to signed tokens (JWT) with revocation strategy
3. Add rate limiting and brute-force protection
4. Restrict CORS origins
5. Integrate structured config management and secrets rotation
