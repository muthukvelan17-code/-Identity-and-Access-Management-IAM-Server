# Enterprise Identity Provider (IdP) using Spring Authorization Server

A centralized, secure Authentication and Authorization server compliant with OAuth2.0 and OpenID Connect (OIDC) protocols.

---

## Technical Stack

* **Language**: Java 17
* **Framework**: Spring Boot 3.2.4 & Spring Authorization Server
* **Security**: Spring Security 6
* **Database**: PostgreSQL (Production) / H2 (Local Dev)
* **Caching**: Redis (Token caching, blacklisting, and session management)
* **Documentation**: Swagger/OpenAPI 3
* **Deployment**: Docker & Docker Compose

---

## Features

* **OAuth2.0 Flows**: Authorization Code, Client Credentials, and Refresh Token.
* **OpenID Connect (OIDC)**: Well-known configurations and userinfo claims.
* **Multi-Factor Authentication (MFA)**: TOTP (Google Authenticator) alongside Twilio SMS and SendGrid email OTP channels.
* **Token Blacklisting**: Redis-backed token revocation.
* **Audit Logging**: Automatic detection of authentication successes, failures, and token generation events.
* **Rate Limiting**: Throttling on registration and login endpoints via Bucket4j.

---

## Getting Started

### Local Development (Zero Configuration)
For quick local testing without external Postgres and Redis requirements, activate the `local` profile. This sets up an in-memory H2 database and handles token blacklisting in memory.

1. Build the project:
   ```bash
   mvn clean install -DskipTests
   ```
2. Run with the local profile:
   ```bash
   mvn spring-boot:run -Dspring-boot.run.profiles=local
   ```
3. Access OpenAPI documentation:
   * **Swagger UI**: http://localhost:9000/swagger-ui.html
   * **API Docs**: http://localhost:9000/v3/api-docs

### Production Run with Docker Compose
To spin up the full production stack including PostgreSQL and Redis:

1. Build the multi-stage docker image:
   ```bash
   docker-compose build
   ```
2. Launch the services:
   ```bash
   docker-compose up -d
   ```

---

## API Documentation

### Public Endpoints
* `POST /api/auth/register` - Create a new user account
* `POST /api/auth/login` - Authenticate and fetch access/refresh tokens
* `POST /api/auth/send-otp` - Dispatch an SMS/Email OTP code
* `POST /api/auth/verify-otp` - Validate the sent OTP code
* `POST /api/auth/reset-password-request` - Trigger password reset link dispatch
* `POST /api/auth/reset-password` - Update password using the reset token

### Authenticated Endpoints
* `GET /api/auth/profile` - Fetch current user profile
* `POST /api/auth/logout` - Blacklists the active access token in Redis

### Admin Endpoints (Requires `ROLE_ADMIN`)
* `GET /api/admin/users` - List all system users
* `POST /api/admin/roles` - Dynamically create new roles
* `GET /api/admin/audit` - Inspect the system audit logs
* `POST /api/admin/revoke` - Force blacklist/revocation of a token
