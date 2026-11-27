# Validasi JWT Secret saat Startup

**Tanggal:** 26 November 2026
**Branch:** `feat/jwt-secret-validation`
**Status:** Selesai, siap review.

## Latar belakang (bug yang ditemukan)

Login di frontend lokal gagal dengan **502 Bad Gateway**. Penelusurannya:

| Lapisan | Hasil |
|---|---|
| BFF `localhost:3000/api/v1/auth/login` | 502 "Authentication service is temporarily unavailable" |
| Gateway `:8080/api/auth/login` | 500 (diteruskan dari Auth) |
| Auth `:8081/api/auth/login` | **500 Internal Server Error** |

Akar masalahnya:

1. `application.properties` berisi `jwt.secret=${JWT_SECRET}` tanpa nilai default.
2. Auth dijalankan dari IntelliJ **tanpa** environment variable `JWT_SECRET`.
3. `JwtProperties` memakai `@ConfigurationProperties`. Kalau placeholder tidak bisa di-resolve, binding ini **tidak gagal**: nilainya diisi teks mentah `${JWT_SECRET}` (13 byte).
4. App tetap start dan register tetap jalan. Tapi saat password cocok, `Keys.hmacShaKeyFor()` dari JJWT menolak key yang kurang dari 256 bit, melempar `WeakKeyException`, dan login berakhir 500.

Masalah utamanya: **konfigurasi yang rusak baru ketahuan saat user login**, bukan saat aplikasi start.

## Solusi

`JwtProperties` sekarang divalidasi saat startup (`@Validated` + Bean Validation):

| Aturan | Annotation | Pesan error |
|---|---|---|
| Secret wajib ada | `@NotBlank` | `must be set (provide the JWT_SECRET environment variable)` |
| Bukan placeholder mentah | `@AssertTrue isSecretResolved()` | `jwt.secret is an unresolved placeholder; set the JWT_SECRET environment variable` |
| Minimal 32 byte UTF-8 (256 bit) | `@AssertTrue isSecretLongEnough()` | `jwt.secret must be at least 32 bytes (256 bits) for HS256` |
| Masa berlaku token positif | `@Positive` | Pesan default |

Contoh output saat Auth di-start tanpa `JWT_SECRET` (sudah dicoba di aplikasi sungguhan):

```
APPLICATION FAILED TO START

Description:
Binding to target com.commerce.auth.config.JwtProperties failed:
    Property: jwt.secretResolved
    Value: "false"
    Reason: jwt.secret is an unresolved placeholder; set the JWT_SECRET environment variable
```

## Keputusan desain

- **Fail fast, bukan fallback.** Tidak ada secret default di kode. Secret default yang ikut ter-commit adalah celah keamanan, karena siapa pun yang membaca repo bisa memalsukan JWT.
- **Hitung dalam byte, bukan karakter.** JJWT memakai `secret.getBytes(UTF_8)`, jadi validasinya juga menghitung byte. Contohnya `"€"` adalah 1 karakter tapi 3 byte.
- **Deteksi `${` secara eksplisit.** Placeholder mentah `${JWT_SECRET}` panjangnya 13 byte, jadi sebenarnya sudah tertangkap oleh aturan panjang. Tapi pesan khusus "unresolved placeholder" langsung memberi tahu apa yang harus diperbaiki.
- **Hanya satu pesan per kasus.** `isSecretLongEnough()` tidak ikut melapor kalau secret kosong atau masih placeholder, supaya tidak muncul tiga error untuk satu masalah.

## Fakta menarik: relaxed binding

Spring Boot otomatis memetakan env `JWT_SECRET` ke property `jwt.secret` (*relaxed binding*). Jadi env var itu terbaca walaupun baris di `application.properties` dihapus. Ini juga alasan test validasi menghapus property source env sistem: tanpa itu, `JWT_SECRET` di mesin atau CI ikut terbaca dan kasus "secret hilang" malah lulus start.

## Test

- **Baru: `JwtPropertiesValidationTest` (7 test, `ApplicationContextRunner`):** start dengan secret 32 byte; gagal kalau secret hilang, kosong, masih placeholder, atau 31 byte; panjang dihitung dalam byte UTF-8; gagal kalau expiration bernilai 0.
- **Suite lengkap:** 135/135 lulus (sebelumnya 128), dijalankan dengan `JWT_SECRET` di-set seperti di CI.
- **Uji manual di aplikasi sungguhan:** tanpa `JWT_SECRET`, Auth menolak start dengan pesan di atas. Dengan secret acak 32 byte, Auth start dalam ±2,8 detik dan `/actuator/health` 200.

## Dampak ke production

Aman. Login di production selama ini berhasil, yang membuktikan `JWT_SECRET` di EC2 sudah ≥ 32 byte (JJWT akan menolak kalau kurang). `compose.yaml` juga sudah mewajibkan `JWT_SECRET` (`${JWT_SECRET:?...}`). Kalaupun suatu saat secret rusak, container gagal start, health check gagal, dan skrip CD melakukan rollback otomatis. Itu jauh lebih baik daripada container "sehat" yang semua loginnya 500.

## Cara menjalankan Auth di lokal sekarang

1. Buat secret: `openssl rand -base64 48`
2. IntelliJ → Run → Edit Configurations → Environment variables:
   `JWT_SECRET=<hasil>;DB_USERNAME=...;DB_PASSWORD=...`
3. Kembalikan `application.properties` ke versi `${...}` supaya tidak ada credential di file yang bisa ter-commit.

## Langkah berikutnya

- Sesuaikan README (branch `docs/readme`), yang masih menyebut "aplikasi juga memiliki secret bawaan untuk development". Itu sudah tidak benar.
- Pertimbangkan `.env` atau profile `application-local.properties` yang masuk `.gitignore` untuk development.
