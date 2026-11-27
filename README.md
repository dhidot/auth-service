# Auth Service

`auth-service` adalah REST API autentikasi dan otorisasi untuk ekosistem CareerTrack. Layanan ini menangani registrasi, verifikasi email, login, access/refresh token berbasis JWT, profil pengguna, logout sesi tertentu, serta pencabutan seluruh sesi.

## Teknologi

- Java 21
- Spring Boot 4.0.7
- Spring Security
- Spring Data JPA
- PostgreSQL 16
- Flyway
- JWT (JJWT 0.12.7)
- SpringDoc OpenAPI/Swagger UI
- Maven Wrapper
- Docker & Docker Compose
- JUnit 5 dan Testcontainers

## Fitur

- Registrasi pengguna dan validasi data
- Verifikasi alamat email dengan token
- Login menggunakan email dan password
- Access token JWT dan refresh token
- Perbaruan access token tanpa login ulang
- Endpoint profil pengguna `/api/auth/me`
- Logout satu sesi
- Logout dari seluruh sesi/perangkat
- RBAC dengan role dan permission
- Admin bootstrap melalui konfigurasi aplikasi
- Health check liveness dan readiness
- Flyway database migration

## Persyaratan

Untuk menjalankan aplikasi secara langsung:

- JDK 21
- PostgreSQL
- Maven Wrapper (disertakan dalam repository)

Untuk menjalankan melalui Docker:

- Docker Desktop / Docker Engine
- Docker Compose

## Konfigurasi

Aplikasi berjalan di port `8081`. Semua credential dibaca dari environment variable; jangan menulis nilainya di `application.properties`.

| Variable | Wajib | Keterangan |
|---|---|---|
| `DB_URL` | Tidak | Default `jdbc:postgresql://localhost:15433/auth_db` (port Postgres dari `compose.yaml`) |
| `DB_USERNAME` | Ya | User database |
| `DB_PASSWORD` | Ya | Password database |
| `JWT_PRIVATE_KEY` | Ya | RSA private key (≥ 2048 bit, PKCS#8 PEM, atau PEM yang di-base64 dalam satu baris) untuk menandatangani token RS256. Kalau kosong, rusak, atau terlalu pendek, aplikasi **menolak start**. |
| `JWT_SECRET` | Tidak (transisi) | Secret HS256 lama. **Hanya** dipakai untuk memeriksa token yang terbit sebelum pindah ke RS256, dan dihapus setelah masa transisi 7 hari (ADR 0001). Kalau di-set, minimal 32 byte. |
| `ADMIN_USERNAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Ya | Akun admin bootstrap |
| `NOTIFICATION_ENABLED` | Tidak | Default `false`. `true` untuk mengirim email verifikasi lewat Notification Service |
| `NOTIFICATION_SERVICE_URL` | Tidak | Default `http://localhost:8082` |
| `NOTIFICATION_INTERNAL_API_KEY` | Jika notifikasi aktif | Key internal ke Notification Service |
| `VERIFICATION_PAGE_URL` | Tidak | Default `http://localhost:3000/verify-email` |

Buat private key JWT (sekali saja per environment, **jangan di-commit**):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
# Untuk .env / environment variable satu baris:
base64 < jwt-private.pem | tr -d '\n'
```

Spring Boot juga membaca environment variable lewat *relaxed binding*: `JWT_PRIVATE_KEY` otomatis menjadi property `jwt.private-key`.

### Format token (ADR 0001)

Token ditandatangani **RS256** dengan header `kid`. Claim: `iss=careertrack-auth`, `aud=careertrack-api`, `sub` = UUID user, `sid` = ID sesi login (tetap sama saat refresh token dirotasi), `username` (hanya untuk tampilan), `type` (`ACCESS`/`REFRESH`), `tokenVersion`, `jti`, `iat`, dan `exp`. Service lain memeriksa token dengan public key dari `GET /.well-known/jwks.json`. Endpoint ini hanya untuk jaringan internal: tidak dirutekan Caddy maupun gateway. Detailnya ada di `docs/adr/0001-kontrak-identitas-jwt.md`.

## Menjalankan secara lokal (IntelliJ / Maven)

1. Jalankan PostgreSQL, misalnya hanya service database dari Compose:
   ```bash
   docker compose up -d postgres
   ```
2. Isi environment variable di **Run → Edit Configurations → Environment variables** (IntelliJ), atau export di terminal:
   ```bash
   export DB_USERNAME=careertrack
   export DB_PASSWORD=<password-db>
   export JWT_PRIVATE_KEY="$(cat jwt-private.pem)"
   export ADMIN_USERNAME=admin ADMIN_EMAIL=admin@example.test ADMIN_PASSWORD=<password-admin>
   ./mvnw spring-boot:run
   ```
3. Cek: `curl http://localhost:8081/actuator/health` harus membalas `200`.

## Menjalankan dengan Docker Compose

Buat file `.env` di root project (sudah masuk `.gitignore`, jangan di-commit):

```dotenv
DB_USERNAME=careertrack
DB_PASSWORD=<password-db>
JWT_PRIVATE_KEY=<hasil base64 satu baris>
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.test
ADMIN_PASSWORD=<password-admin>
```

Lalu jalankan:

```bash
docker compose up -d --build
```

| Service | Alamat dari laptop |
|---|---|
| Auth Service | `http://127.0.0.1:18081` |
| PostgreSQL | `127.0.0.1:15433` |

Compose menolak start kalau salah satu variable wajib belum diisi.

## Endpoint

| Method | Path | Akses |
|---|---|---|
| POST | `/api/auth/register` | Publik |
| POST | `/api/auth/verify-email` | Publik |
| POST | `/api/auth/login` | Publik (akun aktif dan terverifikasi) |
| POST | `/api/auth/refresh` | Refresh token valid |
| GET | `/api/auth/me` | Access token |
| POST | `/api/auth/logout` | Access token + refresh token di body |
| POST | `/api/auth/logout-all` | Access token |
| GET | `/.well-known/jwks.json` | Publik, tapi **hanya jaringan internal** (public key untuk verifikasi token) |
| GET | `/actuator/health` | Publik (liveness/readiness) |

Swagger UI tersedia di `/swagger-ui.html` saat aplikasi berjalan.

## Testing

Integration test memakai Testcontainers, jadi Docker harus berjalan. RSA key untuk test dibuat otomatis di memori (`TestJwtKeyContextCustomizerFactory`), jadi tidak ada private key yang perlu disiapkan atau di-commit:

```bash
./mvnw test
```

## CI/CD

Workflow `.github/workflows/auth-image.yml`:

- **Pull request ke `main`:** menjalankan test.
- **Push ke `main`:** test, lalu build dan publish image `linux/amd64` ke GHCR dengan tag commit SHA dan `production`. Server EC2 mengambil tag `production` lewat timer systemd.
- **Manual:** tab **Actions → Auth Service CI and Image → Run workflow** (`workflow_dispatch`) untuk build ulang tanpa commit baru.
