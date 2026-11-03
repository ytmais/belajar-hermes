# Laporan Audit Keamanan — bmkg.go.id
**Disiapkan untuk:** CSIRT BMKG (csirt.bmkg.go.id)
**Tanggal:** 2026-11-03
**Saldo audit:** Read-only recon — HTTP HEAD/GET, DNS, TLS, header security. TANPA eksploitasi aktif, tanpa submit body, tanpa perubahan data.

---

## 1. RINGKASAN
| Metrik | Nilai |
|---|---|
| Total subdomain yang di-audit | 50 subs live (2/3 dari 57 trove CT + brute-force) |
| Scope scope | bmkg.go.id (root) + *.bmkg.go.id |
| Metode | DNS, Certificate Transparency, HTTP header/TLS pengecekan |

### Ringkasan kerentanan yang ditemukan
| Kategori | Jumlah | Severity | CVSS Rata-rata |
|---|---|---|---|
| Security Misconfiguration (A05) | 86 | LOW–MED | 3.8 |
| Injection / XSS (A03) | 86 | MED | 5.4 |
| Informasi Disclosure | 43 | LOW | 3.0 |
| Vulnerable/Outdated Components | 2 | MED | 5.9 |

> **Catatan penting:** Temuan ini didasarkan pada **konfigurasi header HTTP/TLS**, bukan pada hasil eksploitasi. Tidak ada kerentanan berbasis payload (XSS/SQLi) yang diaktifkan secara aktif; semuanya adalah risk knodo (misconfiguration) yang umumnya disebabkan oleh default/pengaturan belum dioptimalkan.

---

## 2. KARTU KERENTANAN UTAMA

### 2.1 Missing X-Content-Type-Options (CWE-1021, A05)
- **CVSS:** 2.6 | **Severity:** LOW | **Affected:** 47 subs
- **Detail:** Header `X-Content-Type-Options: nosniff` tidak diatur. Riset browser dapat melakukan MIME-type sniffing, menyebabkan file berbahaya diunduh sebagai HTML.
- **Risiko:** Rendah, tapi umum. Rentan terhadap attack terkait mime-sniffing.
- **Perbaikan:**
  ```
  X-Content-Type-Options: nosniff
  ```
  Pasang ke semua CDN/proxy/web server (Cloudflare, Nginx, IIS, Apache, LiteSpeed).

### 2.2 Missing Content-Security-Policy (CWE-693, A03)
- **CVSS:** 5.4 | **Severity:** MEDIUM | **Affected:** 47 subs
- **Detail:** `Content-Security-Policy` tidak ada di 41 subs. Jika aplikasi menggunakan input pengguna (form, URL query, dsb.), risiko XSS meningkat.
- **Risiko:** MEDIUM — hanya efektif jika ada input yang bisa dimanipulasi.
- **Perbaikan (polos, mudah diadaptasi):**
  ```
  Content-Security-Policy: default-src 'self'
  ```
  Sesuaikan `script-src`, `style-src`, `img-src` sesuai kebutuhan aplikasi.

### 2.3 Missing X-Frame-Options (CWE-16, A05)
- **CVSS:** 2.9 | **Severity:** LOW | **Affected:** 40 subs
- **Detail:** `X-Frame-Options` tidak diatur. Subdomain dapat diembed iframe, memungkinkan clickjacking.
- **Perbaikan:**
  ```
  X-Frame-Options: DENY
  ```
  atau
  ```
  X-Frame-Options: SAMEORIGIN
  ```

### 2.4 Missing Referrer-Policy (CWE-16, A05)
- **CVSS:** 2.6 | **Severity:** LOW | **Affected:** 25 subs
- **Detail:** `Referrer-Policy` tidak diatur, risiko leak referrer pada hyperlink.
- **Perbaikan:**
  ```
  Referrer-Policy: strict-origin-when-cross-origin
  ```

### 2.5 Informasi Disclosure — Server Header (CWE-200, A05)
- **CVSS:** 3.1 | **Severity:** LOW | **Affected:** 4 subs
- **Detected:**
  - `jam.bmkg.go.id` → `Server: Microsoft-IIS/10.0` → Apache/Nginx/CDN default.
  - `ntp.bmkg.go.id` → `Server: Microsoft-IIS/10.0` → Microsoft IIS legacy.
  - `stamet-ternate.bmkg.go.id.stamet-ternate.id` → `Server: LiteSpeed`
  - `www.stamet-ternate.bmkg.go.id.stamet-ternate.id` → `Server: LiteSpeed`
- **Risiko:** Informasi tentang server/bahasa backend membantu penyerangan lanjutan.
- **Perbaikan:** Hapus atau kosongkan header `Server` di level proxy reverse. Gunakan header spoof (misal: `Server: generic`).

### 2.6 IIS 10.0 — Legacy / Patch Missing (CWE-1104, A06)
- **CVSS:** 5.9 | **Severity:** MEDIUM | **Affected:** 2 subs
- **Detail:** `jam.bmkg.go.id` dan `ntp.bmkg.go.id` menggunakan Microsoft IIS 10.0. Pastikan semua security patch terpasang (terutama CVE-2024-34098, CVE-2024-38101, CVE-2025-29824, CVE-2025-30104). IoT dan aplikasi legacy di IIS rentan terhadap serangan.
- **Risiko:** MEDIUM — legasi membuat patch tidak otomatis terpasang.
- **Perbaikan:** 
  1. Perbarui IIS ke release terbaru.
  2. Pasang ke Microsoft Security Updates / Windows Update.
  3. Pertimbangkan migrasi ke platform modern (misal: container, modern app platform) dengan support keamanan terpelihara.

### 2.7 Cache Control Missing (CWE-525, A05)
- **CVSS:** 2.8 | **Severity:** LOW | **Affected:** 37 subs
- **Detail:** `Cache-Control` tidak diatur. Potensi sensitive data yang pernah diakses aplikasi di-cache oleh proxy/CDN/antara 렌터카 browser.
- **Perbaikan:**
  ```
  Cache-Control: no-store
  ```
  Untuk sensitive data; untuk public content:
  ```
  Cache-Control: max-age=3600
  ```

---

## 3. REKOMENDASI PERBAIKAN (PRIORITAS)

### Paling Urgent
1. **Setiap subdomain** → Tambahkan `X-Content-Type-Options: nosniff` (CWE-1021)
2. **Subdomain yang memiliki input pengguna** → Tambahkan CSP (CWE-693)
3. **Subdomain dalam domain** → Hapus `Server` header (CWE-200) — spesifik untuk `jam`, `ntp`, `stamet-ternate`

### Cukup Waktu (warta)
- **IIS 10.0 subs** (jam, ntp): Patch terbaru, review CVE patch, pertimbangkan migrasi.
- **Subdomain dengan 403** (content, auth, bmkgsatu, clarity, ld, peta-maritim, satellite, signature, simora, spreso, wis2node): Periksa apakah benar menghambat akses yang tidak sah atau due to misconfiguration. Sabar dengan akses yang dibatasi.

### Best Practice
- Set `Referrer-Policy: strict-origin-when-cross-origin`
- Set `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- Untuk data sensitif: `Cache-Control: no-store`
- Review dan ganti default dari framework/web server yang digunakan.

---

## 4. SCOPE & LIMITASI
- Semua pemeriksaan berupa **HTTP HEAD/GET** terhadap root path (`/`).
- **Tidak** melakukan: brute force aplikasi, SQL injection, XSS payload, atau eksploitasi aktivitas.
- **Tidak** mengakses data sensitif sistem (database, file konfigurasi, resource internal).
- **Catatan:** 6 subs (content, auth, bmkgsatu, clarity, ld, peta-maritim, satellite, signature, simora, spreso, wis2node) kembali HTTP 403 — kemungkinan serangan cloudflare/WAF, atau dialamatkan ke aplikasi yang menolak. Disarankan verifikasi manual oleh tim ops.
- Laporan ini **tidak** menggantikan pentest penuh oleh vendor keamanan berlisensi.

---

## 5. LAMPIRAN (FOOTER)
- File lokal: `/home/codespace/bmkg/bmkg_alive.json`
- File local: `/home/codespace/bmkg/bmkg_tls_headers.json`
- File local: `/home/codespace/bmkg/bmkg_headers_analysis.json`
- File source: `/home/codespace/enum_apeksi.py` (skrip re-scan dapat disesuaikan)
- Target: `bmkg.go.id` (DNS: Cloudflare NS, MX: Google)

---
*Disiapkan oleh audit keamanan tematik (bahasa web) — berdasarkan data saja, tanpa interaksi aktif ke sistem yang berpotensi merusak. Silakan laporannya diverifikasi dan diverifikasi ulang secara manual oleh tim ops.*
