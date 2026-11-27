# ADR 0001 — Kontrak Identitas JWT Lintas Service

**Status:** Diterima
**Tanggal:** 27 November 2026
**Pemilik kontrak:** Auth Service
**Berlaku untuk:** Auth Service, API Gateway, Application Service (rencana), dan service lain yang menerima access token

---

## Jadi, sebenarnya ini ngapain?

Access token itu ibarat **kartu identitas** yang dibawa user ke setiap service. Selama ini hanya ada satu "petugas" yang memeriksa kartu, yaitu Auth Service. Sebentar lagi akan ada service baru (Application Service) yang juga harus memeriksa kartu itu sebelum menampilkan data lamaran kerja milik user.

Sebelum service baru dibangun, semua pihak harus sepakat tentang empat hal:

1. **Nomor identitas apa yang tertulis di kartu?** (`sub`)
2. **Bagaimana kartu disegel supaya tidak bisa dipalsukan, dan siapa yang boleh membuat segel?** (signing)
3. **Kalau kartu dicabut (logout semua device), seberapa cepat service lain tahu?** (revocation)
4. **Siapa saja yang memeriksa kartu?** (verifikasi)

Kalau keputusan ini salah, akibatnya sulit diperbaiki belakangan: data lamaran tersimpan dengan ID yang salah, atau satu service yang kebobolan bisa membuat kartu ADMIN palsu.

---

## Kondisi sebelum keputusan

| Aspek | Kondisi |
|---|---|
| Claim | `sub` = username, `type` (ACCESS/REFRESH), `tokenVersion`, `jti`, `iat`, `exp` |
| Signing | HS256 dengan satu `JWT_SECRET`, yang dipakai untuk membuat **dan** memeriksa token |
| `iss` / `aud` | Tidak ada |
| Verifikasi | Hanya di Auth: tanda tangan, lalu ambil user dari DB berdasarkan username, lalu cocokkan `tokenVersion` dan status akun |
| Umur token | Access 15 menit, refresh 7 hari |
| Catatan | `SecurityConfig` sudah mengizinkan `GET /.well-known/jwks.json`, tetapi endpoint-nya belum ada |

---

## Keputusan

### 1. `sub` = UUID user

- Token baru berisi `sub` = `users.id` (UUID).
- Username tetap tersedia sebagai claim terpisah `username`, hanya untuk tampilan. **Tidak boleh** dipakai untuk otorisasi atau sebagai kunci data.
- Application Service memakai `sub` sebagai `owner_user_id`.

**Alasan:** UUID tidak pernah berubah, sedangkan username mungkin bisa diganti di masa depan. UUID juga sesuai dengan ERD (`owner_user_id UUID`), dan tidak memuat informasi pribadi.

### 2. Signing = RS256 + JWKS

- Auth menandatangani token dengan **private key RSA (≥ 2048 bit)**. Hanya Auth yang memegang kunci ini.
- Auth menerbitkan **public key** di `GET /.well-known/jwks.json` dalam format JWKS, masing-masing dengan `kid`.
- Header token berisi `alg: RS256` dan `kid`.
- Gateway dan Application Service memeriksa token dengan public key dari JWKS. Mereka **tidak pernah** memegang private key.
- JWKS cukup diakses di jaringan internal Docker (`http://auth:8081/.well-known/jwks.json`). Endpoint ini **tidak** dibuka lewat Caddy, karena tidak ada konsumen di luar server.

**Alasan:** dengan HS256, setiap service yang bisa memeriksa token juga bisa membuat token. Kalau satu service kebobolan, penyerang bisa membuat token ADMIN palsu. Dengan RS256, kebocoran public key tidak berbahaya. `kid` memungkinkan pergantian kunci tanpa downtime.

### 3. Revocation: service selain Auth menerima jeda maksimal 15 menit

- Endpoint milik Auth tetap memeriksa `tokenVersion` dan status akun di DB pada setiap request, jadi logout dan logout-all **langsung** berlaku di Auth.
- Service lain memeriksa token **tanpa** bertanya ke Auth. Setelah logout-all, access token lama masih diterima sampai kadaluarsa, **paling lama 15 menit**.
- Umur access token tetap 15 menit. Kalau suatu saat butuh jeda lebih pendek, umurnya diturunkan (misalnya 5 menit), tanpa mengubah arsitektur.

**Alasan:** cara ini paling sederhana dan tidak membuat setiap request bergantung pada Auth. Alternatif "tanya Auth di setiap request" menambah latensi, dan kalau Auth mati, semua service ikut mati.

### 4. Verifikasi di gateway dan di setiap service

Untuk route yang membutuhkan login (misalnya `/api/applications/**`):

- **Gateway** menolak lebih awal (401) token yang tanda tangannya salah, kadaluarsa, `iss`/`aud`-nya salah, atau `type`-nya bukan `ACCESS`.
- **Application Service memeriksa ulang** dengan aturan yang sama, lalu mengambil `owner_user_id` dari `sub`.
- Tidak ada service yang memercayai header identitas buatan service lain (misalnya `X-User-Id`).

**Alasan:** *defense in depth*. Kalau suatu saat Application Service bisa diakses tanpa lewat gateway (salah konfigurasi port atau jaringan), service itu tetap aman.

---

## Kontrak access token (versi baru)

**Header**

```json
{ "alg": "RS256", "typ": "JWT", "kid": "<id-kunci-aktif>" }
```

**Payload**

| Claim | Contoh | Wajib diperiksa oleh penerima |
|---|---|---|
| `iss` | `careertrack-auth` | ✅ harus sama persis |
| `aud` | `careertrack-api` | ✅ harus memuat nilai ini |
| `sub` | `3f1c...-uuid` | ✅ UUID valid. Inilah identitas user. |
| `type` | `ACCESS` | ✅ harus `ACCESS` (refresh token tidak boleh dipakai sebagai access token) |
| `exp` | epoch detik | ✅ belum lewat (toleransi selisih jam 30 detik) |
| `iat` | epoch detik | – |
| `jti` | UUID | – (dipakai Auth) |
| `tokenVersion` | `3` | Hanya Auth (dicocokkan ke DB) |
| `username` | `dhito` | Tidak untuk otorisasi, hanya tampilan |
| `roles` | `["USER"]` | Opsional, akan dipakai untuk otorisasi kasar |

**Aturan penerima:**
- Hanya menerima `alg = RS256` (*allowlist*). Token dengan `alg: none` atau `HS256` ditolak, untuk mencegah serangan *algorithm confusion*.
- Public key diambil dari JWKS berdasarkan `kid`, di-cache, dan di-refresh saat muncul `kid` yang belum dikenal.

Refresh token memakai format yang sama (`type: REFRESH`, `aud` sama), tetapi **hanya diterima oleh Auth**, dan tetap dicocokkan ke hash di tabel `refresh_tokens`.

---

## Rencana migrasi (tanpa memaksa user login ulang)

| Tahap | Isi | Catatan |
|---|---|---|
| **A. Auth: terbitkan token baru** | Auth menerbitkan token RS256 dengan `kid`, `iss`, `aud`, `sub` = UUID, dan `username`. Endpoint JWKS tersedia. Auth **masih menerima** token HS256 lama untuk diperiksa. | Validasi saat startup seperti `JWT_SECRET`: private key wajib ada, RSA ≥ 2048 bit |
| **B. Auth: terima dua bentuk `sub`** | Kalau `sub` berupa UUID, user dicari lewat id. Kalau bukan, dicari lewat username (token lama). | 12 tempat yang memakai `authentication.getName()` disesuaikan |
| **C. Masa transisi 7 hari** | Umur refresh token lama paling lama 7 hari. Setiap kali user me-refresh, ia mendapat token baru. | Tidak ada yang dipaksa login ulang |
| **D. Bersihkan** | Setelah 7 hari: hapus jalur HS256 dan pencarian lewat username, lalu `JWT_SECRET` tidak dipakai lagi | Catat tanggal mulai tahap A |
| **E. Gateway** | Pemeriksaan JWT untuk route non-auth (resource server reaktif, `jwk-set-uri` internal, validator `iss`/`aud`/`type`) | Dikerjakan bersama route Application Service pertama |
| **F. Application Service** | Pemeriksaan yang sama, dan `owner_user_id` diambil dari `sub` | Bagian dari P5 |

Frontend (BFF) **tidak berubah**: BFF tidak membaca isi token, hanya menyimpannya di cookie HttpOnly dan meneruskannya.

---

## Pengelolaan kunci

- **Production:** private key (PEM) disimpan sebagai secret di server (`.env` dengan permission 600, atau file read-only yang di-mount ke container). Kunci tidak pernah di-commit dan tidak pernah dicetak ke log.
- **Lokal dan test:** setiap developer membuat kuncinya sendiri. Test membuat kunci sementara di memori.
- **Rotasi:**
  1. Tambah kunci baru di JWKS (dua `kid` aktif sekaligus).
  2. Auth mulai menandatangani dengan kunci baru.
  3. Tunggu lebih dari 7 hari, sampai semua token lama kadaluarsa.
  4. Hapus kunci lama dari JWKS.
- **Kalau private key bocor:** buat kunci baru, hapus kunci lama dari JWKS **segera** (semua token lama otomatis tidak valid), lalu semua user login ulang.

---

## Konsekuensi

**Positif**
- Service baru bisa memeriksa token tanpa memegang rahasia yang bisa memalsukan token.
- Data milik user diikat ke ID yang stabil.
- Klaim `iss`, `aud`, dan `type` mencegah token dipakai di tempat yang salah.

**Negatif dan yang diterima**
- Logout-all butuh paling lama 15 menit untuk berlaku di service selain Auth.
- Ada pekerjaan migrasi dan masa transisi 7 hari dengan dua jalur verifikasi di Auth.
- Muncul tugas operasional baru: menyimpan dan merotasi private key.

---

## Alternatif yang ditolak

| Alternatif | Kenapa ditolak |
|---|---|
| `sub` tetap username | Application Service harus memetakan username ke UUID, dan akan rusak kalau username bisa diganti |
| HS256 dengan secret yang dibagi | Satu service kebobolan berarti bisa membuat token ADMIN palsu |
| HS256 + introspection ke Auth di setiap request | Latensi bertambah, dan semua service bergantung pada Auth yang hidup |
| Revocation instan lewat cek ke Auth | Alasan sama dengan di atas. Jeda 15 menit dianggap dapat diterima untuk aplikasi ini. |
| Hanya gateway yang memeriksa token lalu mengirim header user id | Berbahaya kalau service bisa diakses tanpa lewat gateway |
