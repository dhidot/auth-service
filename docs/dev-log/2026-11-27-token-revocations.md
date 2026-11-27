# Daftar Pencabutan Token (ADR 0001, Tahap C2)

**Tanggal:** 27 November 2026
**Branch:** `feat/token-revocations`
**Dasar:** [ADR 0001, keputusan 3 (revisi)](../adr/0001-kontrak-identitas-jwt.md)
**Status:** Selesai di kode. **Aman di-deploy tanpa secret baru**: endpoint internal nonaktif sampai `REVOCATIONS_INTERNAL_API_KEY` dipasang (saat gateway siap memakainya di tahap E).

---

## Jadi, sebenarnya ini ngapain?

Access token itu **kartu identitas** dengan masa berlaku 15 menit. Sebelum ini, saat user logout, Auth membuang **kartu cadangannya** (refresh token), tapi **kartu yang sedang dipegang** (access token) masih berlaku sampai kadaluarsa. Kalau kartu itu sempat disalin orang lain, orang itu masih bisa memakainya sampai 15 menit.

Sekarang Auth punya **papan pengumuman "kartu yang sudah dicabut"**:

| Kejadian | Yang ditulis di papan | Berlaku sampai |
|---|---|---|
| **Logout** (satu device) | "Kartu dengan nomor sesi `sid` = S tidak berlaku" | 16 menit |
| **Logout semua device** | "Semua kartu milik user X yang dibuat sebelum jam T tidak berlaku" | 16 menit |

Setelah 16 menit, catatan dihapus otomatis, karena semua kartu yang terkena pasti sudah kadaluarsa sendiri. Papannya selalu kecil.

**Siapa yang membaca papan?**
1. **Auth sendiri**, mulai sekarang: setiap request mengecek papan. Logout langsung berlaku, bahkan untuk kartu yang disalin.
2. **Gateway**, nanti di tahap E: mengambil seluruh isi papan setiap ±5 detik lewat `GET /internal/revocations`, lalu menolak kartu yang dicabut sebelum sampai ke Application Service.

---

## Yang berubah

| File | Perubahan |
|---|---|
| `V15__create_token_revocations.sql` | Tabel baru dengan *check constraint*: SESSION wajib punya `session_id`, USER wajib punya `not_before`. Index di `expires_at` dan `session_id`. FK ke `users` dengan `ON DELETE CASCADE`. |
| `entity/TokenRevocation`, `repository/TokenRevocationRepository` | Entity + query: daftar aktif, cek sesi, hapus yang kadaluarsa |
| `service/TokenRevocationService` | `revokeSession`, `revokeAllForUser`, `isSessionRevoked`, `activeRevocations`, dan `purgeExpired` (dijadwalkan setiap 10 menit) |
| `service/serviceImpl/AuthServiceImpl` | `logout` mencatat pencabutan sesi; `logout-all` mencatat pencabutan user. Keduanya dalam **transaksi yang sama** dengan revoke refresh token. |
| `security/jwt/JwtAuthenticationFilter` | Token dengan `sid` yang sudah dicabut ditolak |
| `controller/InternalRevocationController` | `GET /internal/revocations` dengan `X-Internal-Api-Key` |
| `config/TimeConfig` | Bean `Clock` (bisa diganti di test) + `@EnableScheduling` |
| `SecurityConfig`, `application.properties`, README, ADR | Konfigurasi dan dokumentasi |

---

## Keputusan teknis dan alasannya

### 1. Snapshot, bukan cursor (berbeda dari draf ADR)
Draf ADR menulis `?since=<cursor>`. Masalahnya, ID dari `BIGSERIAL` dibagikan **saat insert**, bukan saat commit:

```
Transaksi A: dapat id 10 ........................ commit
Transaksi B:      dapat id 11 ... commit
Gateway:                              baca → lihat 11, cursor = 11
                                                     → id 10 tidak akan pernah terbaca
```

Logout di transaksi A tidak akan pernah sampai ke gateway. Karena catatan hanya hidup 16 menit, **mengambil seluruh daftar aktif** di setiap polling tetap ringan, dan tidak mungkin ada yang terlewat. ADR sudah diperbarui.

### 2. `notBefore` dibulatkan ke atas ke detik berikutnya
`iat` di JWT berpresisi detik. Contoh:
```
token dibuat     10:00:00.200  → iat = 10:00:00
logout-all       10:00:00.700
```
Kalau `notBefore` = 10:00:00, aturan `iat < notBefore` **tidak** mencabut token itu. Dengan pembulatan ke atas (10:00:01), token itu ikut tercabut. Efek sampingnya: login baru yang terjadi pada detik yang **sama persis** dengan logout-all juga ikut tercabut. Itu sangat jarang terjadi, karena user perlu mengetik ulang password, dan lebih aman daripada melewatkan satu token.

### 3. Masa simpan = umur access token + 60 detik
Verifier menerima selisih jam sampai 30 detik. Margin 60 detik memastikan catatan tidak terhapus sementara token yang dicabut masih bisa lolos di sisi verifier.

### 4. Auth ikut memeriksa papan
Sebelumnya, logout satu device **tidak** membuat access token itu ditolak oleh Auth sendiri. Auth hanya mengecek `tokenVersion`, yang naik saat logout-all. Sekarang filter Auth mengecek `sid` di papan (satu query ber-index, karena filter memang sudah mengakses DB di setiap request). Logout langsung berlaku di Auth.

### 5. Endpoint nonaktif sampai key dipasang
Kalau `REVOCATIONS_INTERNAL_API_KEY` kosong, endpoint membalas **404**. Versi ini bisa di-deploy sekarang tanpa menambah secret di server. Key dipasang bersamaan dengan gateway di tahap E. Kalau key di-set tapi kurang dari 32 karakter, Auth menolak start. Key dibandingkan secara *constant-time*.

### 6. Token lama tanpa `sid`
Refresh token yang terbit sebelum tahap A tidak punya sesi. Logout-nya tetap me-revoke refresh token dan BFF menghapus cookie, tapi tidak ada catatan sesi yang bisa ditulis. Masa transisi ini berakhir paling lambat 4 Des 2026.

---

## Verifikasi

### Test: **182/182** (sebelumnya 169, +13)
- `TokenRevocationServiceTest` (6): masa simpan 15 menit + 60 detik, `notBefore` dibulatkan ke atas (10:00:00.700 → 10:00:01), sesi tanpa `sid` tidak dicatat, hanya catatan aktif yang dihitung, purge
- `RevocationIntegrationTest` (6, Postgres sungguhan):
  - **Logout laptop**: access token laptop langsung **401**, sementara sesi HP tetap **200**
  - **Logout-all**: catatan USER muncul dengan `iat < notBefore`
  - Endpoint internal: tanpa key, key salah, atau key + 1 karakter → 401
  - Kontrak JSON + `Cache-Control: no-store`
  - Catatan kadaluarsa tidak ikut dikirim dan terhapus oleh purge; catatan aktif tetap ada
  - Database menolak catatan yang tidak konsisten (SESSION tanpa `sid`, USER tanpa `notBefore`)
- `MeEndpointIntegrationTest` (+1): tanpa key, endpoint **404**
- `AuthServiceImplTest`: logout mencatat sesi, logout-all mencatat user **setelah** revoke refresh token, dan logout yang ditolak tidak mencatat apa pun

### Cek balik
Pengecekan sesi di filter dimatikan sementara, dan test langsung gagal: `Status expected:<401> but was:<200>`. Tanpa perubahan ini, access token yang sudah logout masih bisa dipakai.

---

## Kontrak `GET /internal/revocations`

```http
GET /internal/revocations
X-Internal-Api-Key: <REVOCATIONS_INTERNAL_API_KEY>
```
```json
{
  "serverTime": 1795770000,
  "revocations": [
    { "type": "SESSION", "sub": "<uuid user>", "sid": "<uuid sesi>", "expiresAt": 1795770960 },
    { "type": "USER",    "sub": "<uuid user>", "notBefore": 1795769401, "expiresAt": 1795770960 }
  ]
}
```
Semua waktu dalam **epoch detik**, supaya bisa langsung dibandingkan dengan `iat` dan `exp` di JWT.

**Aturan untuk gateway (tahap E):** token ditolak kalau ada catatan `SESSION` dengan `sid` yang sama, **atau** catatan `USER` dengan `sub` yang sama dan `iat < notBefore`.

---

## Deploy

Tidak ada perubahan di server untuk PR ini:
- Migrasi V15 berjalan otomatis saat Auth start.
- Endpoint internal nonaktif sampai key dipasang.
- Setelah deploy, **logout langsung berlaku di Auth**.

## Berikutnya: tahap E (gateway)
- Verifikasi JWT dengan JWKS (`iss`, `aud`, `type=ACCESS`, `alg=RS256`) untuk route non-auth
- Polling `/internal/revocations` setiap ±5 detik (dengan `REVOCATIONS_INTERNAL_API_KEY` di EC2)
- Dikerjakan bersama route Application Service pertama
