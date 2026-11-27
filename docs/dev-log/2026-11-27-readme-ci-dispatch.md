# README, `.gitignore`, dan Tombol Build Manual di CI

**Tanggal:** 27 November 2026
**Branch:** `docs/readme` (di-rebase ke `main` setelah PR #10)
**Tujuan utama:** setelah di-merge, push ke `main` ini memicu CI dan publish image `production`. Itu yang membawa validasi JWT (PR #10, yang di-merge saat GitHub Actions mati) ke EC2.

## Yang berubah

| File | Perubahan | Kenapa |
|---|---|---|
| `README.md` | Ditulis ulang mulai bagian Konfigurasi | Versi lama terpotong di tengah ("Buat file `.env`…" tanpa lanjutan), menyebut port DB yang salah (`5433`, seharusnya `15433`), dan mengklaim ada "secret bawaan untuk development" yang sudah tidak ada |
| `.gitignore` | Tambah `.env`, `.env.*`, kecuali `.env.example` | README menyuruh membuat `.env` berisi secret, tapi file itu belum di-ignore (yang ada hanya `.env.docker`) |
| `.github/workflows/auth-image.yml` | Tambah `workflow_dispatch`; job `publish` juga jalan untuk trigger manual di `main` | Supaya image bisa di-build ulang tanpa commit baru, misalnya setelah Actions mati seperti kemarin |
| `mvnw` | Mode file `100644` → `100755` | `./mvnw` gagal dengan "Permission denied". CI aman karena memanggil `bash ./mvnw`, tapi perintah di README tidak jalan |

## Isi README baru

- **Tabel environment variable** yang sesuai `application.properties`: `DB_*`, `JWT_SECRET` (minimal 32 byte, aplikasi menolak start kalau tidak valid), `ADMIN_*`, `NOTIFICATION_*`, dan `VERIFICATION_PAGE_URL`.
- **Cara menjalankan lokal** lewat IntelliJ atau Maven tanpa menulis credential di file.
- **Cara menjalankan dengan Docker Compose**, termasuk contoh `.env` dengan placeholder.
- **Daftar endpoint**, cara menjalankan test, dan penjelasan alur CI/CD.

## Detail teknis

### Kondisi `publish` di workflow
```yaml
if: (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main'
```
`workflow_dispatch` bisa dijalankan dari branch apa pun lewat dropdown "Run workflow". Syarat `github.ref == 'refs/heads/main'` memastikan hanya `main` yang bisa menimpa tag `production`. Dari branch lain, tombol ini hanya menjalankan test.

### `.env.*` dengan pengecualian
`!.env.example` membatalkan aturan di atasnya. Contoh config tanpa secret masih bisa di-commit, sedangkan `.env`, `.env.local`, `.env.docker`, dan sejenisnya selalu diabaikan.

## Verifikasi lokal

| Cek | Hasil |
|---|---|
| YAML workflow valid, trigger: `workflow_dispatch`, `pull_request`, `push` | ✅ |
| `git check-ignore`: `.env` dan `.env.*` diabaikan, `.env.example` tidak | ✅ |
| `JWT_SECRET=... ./mvnw test` (langsung, tanpa `sh`) | ✅ 135/135 |

## Setelah merge

1. Push ke `main` memicu **Auth Service CI and Image**: test, lalu publish image `production`.
2. Timer systemd di EC2 (setiap ±2 menit) mengambil digest baru, me-restart container Auth, menunggu 3 health check berturut-turut, atau rollback kalau gagal.
3. Cek: `curl -i https://careertrack.duckdns.org/api/auth/me` harus tetap `401` untuk request anonim.

**Catatan production:** Auth versi baru menolak start kalau `JWT_SECRET` di EC2 tidak valid. Login production selama ini berhasil, jadi secret-nya pasti sudah ≥ 32 byte. Kalaupun ada masalah, skrip CD otomatis rollback ke image lama.
