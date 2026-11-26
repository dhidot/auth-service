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

Aplikasi menggunakan port `8081` secara default.

| Konfigurasi | Environment property | Default/lokasi |
|---|---|---|
| URL database | `DB_URL` | `jdbc:postgresql://localhost:5433/auth_db` |
| Username admin | `ADMIN_USERNAME` | wajib diisi |
| Email admin | `ADMIN_EMAIL` | wajib diisi |
| Password admin | `ADMIN_PASSWORD` | wajib diisi |
| Secret JWT | `JWT_SECRET` | didukung oleh Compose; aplikasi juga memiliki secret bawaan untuk development |
| Database Compose | `DB_USERNAME` | wajib diisi melalui `.env` |
| Password database Compose | `DB_PASSWORD` | wajib diisi melalui `.env` |

> Konfigurasi database dan admin dapat disediakan sebagai environment variable sehingga tidak perlu mengubah source code.

## Menjalankan dengan Docker Compose

Buat file `.env` pada root project:

