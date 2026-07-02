# FridaFlow

Android cihazlarda Frida server kurulumunu tek komutla yapan, interaktif ve otomatik bir CLI aracı.

Cihazı ADB üzerinden algılar, mimarisini tespit eder, PC'de kurulu Frida sürümüyle eşleşen (veya fallback) `frida-server` binary'sini GitHub'dan indirir, cihaza push eder, çalıştırılabilir yapar ve başlatır.

## Özellikler

- ADB üzerinden bağlı cihaz/emülatör otomatik tespiti (çoklu cihaz desteği)
- Cihaz mimarisinin (`x86`, `x86_64`, `arm`, `arm64`) otomatik algılanması
- PC'deki yüklü Frida sürümüyle otomatik versiyon eşleştirme
- GitHub Releases API üzerinden `frida-server` indirme
- Root/non-root cihaz desteği (root varsa SELinux'u geçici olarak permissive yapar)
- Otomatik port forwarding (`27042` / `27043`)
- Kurulum sonrası otomatik başlatma ve doğrulama
- `rich` tabanlı okunur terminal arayüzü

## Gereksinimler

- Python 3.10+
- [ADB](https://developer.android.com/tools/adb) (`adb` komutu PATH'te olmalı)
- USB Debugging açık bir Android cihaz veya çalışan emülatör

## Kurulum

```bash
git clone https://github.com/<kullanici-adi>/frida-flow.git
cd frida-flow
pip install -r requirements.txt
```

`rich` paketi kurulu değilse araç ilk çalıştırmada otomatik olarak yüklemeyi dener.

## Kullanım

```bash
python3 frida-flow.py
```

Araç sırasıyla:

1. ADB kurulumunu kontrol eder
2. Bağlı cihazları listeler ve seçim ister (tek cihaz varsa otomatik seçer)
3. Cihaz bilgilerini (model, Android sürümü, SDK, root durumu) gösterir
4. Cihaz mimarisini algılar / manuel seçim sunar
5. Uygun `frida-server` sürümünü bulur ve indirir
6. Onay sonrası cihaza kurar, izinleri ayarlar
7. İsteğe bağlı olarak server'ı başlatır ve doğrular

## Uyarı

Bu araç yalnızca **yetkili güvenlik testleri, kendi cihazlarınız veya üzerinde test izniniz olan sistemler** için kullanılmalıdır. Yetkisiz cihazlarda kullanımından doğacak sonuçlardan kullanıcı sorumludur.

## Lisans

[MIT](LICENSE)
