WebShell Detector Pro v2.0

Copyright (C) 2026 sigithdteam-lab
GNU General Public License v3.0

🧩 Cara Penggunaan

Format perintah:

```bash
./shelldetector.sh [OPTIONS] DIRECTORY
```

Contoh:

· Scan standar:
  ```bash
  ./shelldetector.sh /var/www/html
  ```
· Scan dengan output JSON:
  ```bash
  ./shelldetector.sh --json /var/www/html
  ```
· Tampilkan bantuan:
  ```bash
  ./shelldetector.sh --help
  ```

Prasyarat: Script harus dapat dieksekusi (chmod +x shelldetector.sh) dan pengguna harus memiliki akses baca ke direktori target.

---

⚙️ Fitur Utama

Fitur Deskripsi
Pola deteksi lanjutan Menggabungkan pola dari sgtcop.py (tool deteksi webshell) – mencakup eval, system, base64_decode, gzinflate, fungsi sistem, pola obfuskasi, dan nama file mencurigakan.
Mode aman (LOG ONLY) Tidak ada penghapusan/pemindahan file; semua temuan dicatat untuk ditinjau manual.
Multi-format output • Log lengkap (.log)   • Laporan ringkas (.txt)   • Alert kritis (.txt)   • Opsional JSON (.json) untuk integrasi.
Klasifikasi temuan SUSPICIOUS (dicurigai) dan CRITICAL (sangat berbahaya, misal c99shell, r57shell).
Hash MD5 Untuk identifikasi unik tiap file (membantu pelacakan).
Batasan ukuran file Melewati file > 2 MB untuk efisiensi.
Skip direktori sistem /proc, /sys, /dev, /run, /tmp, dll.
Konteks pola Untuk file kritis, tampilkan beberapa baris di sekitar pola berbahaya.

---

🎯 Kegunaan

· Keamanan server web – Mendeteksi backdoor/webshell yang disisipkan peretas.
· Audit keamanan – Memberikan laporan terperinci untuk tim keamanan.
· Forensik awal – Menemukan file mencurigakan untuk investigasi lebih lanjut.
· Integrasi SIEM – Output JSON dapat diolah oleh alat pemantauan.

---

⚙️ Cara Kerja (Alur Lengkap)

1. Inisialisasi
   · Buat direktori log: /var/log/webshell_detector/
   · Buat file dengan timestamp: .log, .txt (report), .txt (alert), dan opsional .json.
2. Parsing argumen & validasi
   · Proses opsi --json atau --help.
   · Pastikan direktori target ada dan dapat dibaca.
3. Scan file (fungsi scan_directory)
   · Gunakan find untuk mendapatkan semua file (rekursif).
   · Filter ekstensi yang didukung: .php, .phtml, .inc, .cgi, .pl, .py, dll.
   · Lewati direktori yang masuk daftar SKIP_DIRS.
   · Untuk tiap file:
     · Cek ukuran (lewati >2 MB).
     · Baca konten (jika readable).
     · Hitung hash MD5.
4. Deteksi pola (fungsi check_file)
   · Kritis – nama/konten mengandung c99shell, r57shell, wso, b374k, dll.
   · Nama mencurigakan – shell, cmd, backdoor, eval, dll.
   · Pola berbahaya (regex gabungan) – system(, eval(, base64_decode(.*eval, gzinflate(, $_GET, $_POST, dll.
   · Fungsi berbahaya – eval, system, exec, shell_exec, curl_exec, phpinfo, dll.
   · Obfuskasi – long base64 string, gzip+base64, echo+base64, str_rot13, hex2bin.
   · Jika ditemukan, catat ke:
     · Log (semua temuan).
     · Report (detail lengkap tiap file).
     · Alert (hanya kritis).
     · JSON (opsional, dalam file sementara .tmp).
5. Tampilkan konteks (untuk file kritis) – 2 baris sebelum & sesudah pola.
6. Generate JSON final (jika opsi diaktifkan) – ubah file .tmp menjadi JSON valid dengan struktur terdefinisi.
7. Buat laporan akhir – statistik (total file, mencurigakan, kritis) dan daftar semua file yang terdeteksi.
8. Tampilkan ringkasan di terminal – warna hijau/kuning/merah sesuai tingkat risiko.
9. Hasil disimpan di /var/log/webshell_detector/ dengan timestamp.

---

📁 Struktur Output

· scan_YYYYMMDD_HHMMSS.log – semua output terminal (INFO, WARN, FOUND, CRITICAL).
· report_YYYYMMDD_HHMMSS.txt – detail per file (path, size, permission, owner, hash, pola).
· alerts_YYYYMMDD_HHMMSS.txt – daftar file kritis dengan pola penyebab.
· scan_YYYYMMDD_HHMMSS.json – (jika --json) format JSON terstruktur.

---

⚠️ Catatan Penting

· Script menggunakan set -euo pipefail untuk keandalan (keluar jika terjadi error).
· Memerlukan perintah grep, stat, find, md5sum/md5, dan jq (hanya untuk JSON) – pastikan terinstal.
· Tidak ada penghapusan – semua keputusan hapus/pindahkan sepenuhnya manual.
· Cocok untuk server produksi sebagai langkah inspeksi awal tanpa risiko merusak.

---

Demikian penjelasan lengkap tentang cara penggunaan, fitur, kegunaan, dan cara kerja script WebShell Detector Pro v2.0.
