# Backend API Test Rehberi

Bu dokümanda backend API'yi test etmek için gerekli tüm adımlar ve komutlar bulunmaktadır.

## Ön Gereksinimler

```bash
# curl yüklü olmalı
curl --version

# jq yüklü olmalı (JSON formatlamak için)
sudo apt install jq

# veya
brew install jq
```

## 1. Servis Sağlık Kontrolü

```bash
# Basit sağlık kontrolü
curl http://localhost:8000/health

# Formatlı çıktı
curl -s http://localhost:8000/health | jq

# Beklenen çıktı:
# {
#   "status": "healthy",
#   "database": "connected",
#   "ollama": "connected",
#   "version": "1.0.0"
# }
```

## 2. Kullanıcı Kaydı Testi

```bash
# Test kullanıcısı oluştur
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Kullanıcı",
    "email": "test@example.com",
    "password": "123456"
  }' | jq

# Beklenen çıktı:
# {
#   "message": "Hesap başarıyla oluşturuldu."
# }

# Aynı email ile tekrar deneme (hata beklenr)
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Kullanıcı 2",
    "email": "test@example.com",
    "password": "654321"
  }' | jq

# Beklenen çıktı:
# {
#   "detail": "Bu e-posta adresi zaten kayıtlı."
# }
```

## 3. Giriş Testi

```bash
# Doğru bilgilerle giriş
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test@example.com",
    "password": "123456"
  }' | jq

# Beklenen çıktı:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIs...",
#   "token_type": "bearer",
#   "user_name": "Test Kullanıcı",
#   "user_id": 1
# }

# Token'ı kaydet
export TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"123456"}' | jq -r .access_token)

echo "Token: $TOKEN"

# Yanlış şifre ile giriş (hata beklenir)
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test@example.com",
    "password": "yanlis_sifre"
  }' | jq

# Beklenen çıktı:
# {
#   "detail": "E-posta veya şifre hatalı."
# }
```

## 4. Kullanıcı Bilgileri Testi

```bash
# Token ile kullanıcı bilgilerini al
curl http://localhost:8000/api/me \
  -H "Authorization: Bearer $TOKEN" | jq

# Beklenen çıktı:
# {
#   "id": 1,
#   "name": "Test Kullanıcı",
#   "email": "test@example.com"
# }

# Token olmadan deneme (hata beklenir)
curl http://localhost:8000/api/me | jq

# Beklenen çıktı:
# {
#   "detail": "Yetkilendirme başlığı (Authorization header) eksik"
# }
```

## 5. Sohbet Oluşturma Testi

```bash
# Yeni sohbet oluştur
curl -X POST http://localhost:8000/api/chats \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "title": "İlk Test Sohbetim"
  }' | jq

# Beklenen çıktı:
# {
#   "id": 1,
#   "user_id": 1,
#   "title": "İlk Test Sohbetim",
#   "created_at": "2025-11-12T18:30:00Z",
#   "updated_at": "2025-11-12T18:30:00Z"
# }

# Chat ID'yi kaydet
export CHAT_ID=$(curl -s -X POST http://localhost:8000/api/chats \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Test Chat"}' | jq -r .id)

echo "Chat ID: $CHAT_ID"
```

## 6. Sohbet Listeleme Testi

```bash
# Tüm sohbetleri listele
curl http://localhost:8000/api/chats \
  -H "Authorization: Bearer $TOKEN" | jq

# Beklenen çıktı:
# [
#   {
#     "id": 1,
#     "user_id": 1,
#     "title": "İlk Test Sohbetim",
#     "created_at": "2025-11-12T18:30:00Z",
#     "updated_at": "2025-11-12T18:30:00Z"
#   }
# ]
```

## 7. Belirli Sohbet Detayı Testi

```bash
# Belirli bir sohbeti ve mesajlarını getir
curl http://localhost:8000/api/chats/$CHAT_ID \
  -H "Authorization: Bearer $TOKEN" | jq

# Beklenen çıktı:
# {
#   "id": 1,
#   "user_id": 1,
#   "title": "İlk Test Sohbetim",
#   "created_at": "2025-11-12T18:30:00Z",
#   "updated_at": "2025-11-12T18:30:00Z",
#   "messages": []
# }
```

## 8. AI Kod Üretme Testi

```bash
# Basit kod üretme isteği
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "prompt": "Python ile hello world yazdır",
    "chat_id": 1,
    "context_files": []
  }' | jq

# Beklenen çıktı:
# {
#   "id": 2,
#   "sender": "bot",
#   "type": "code",
#   "text": "print(\"Hello, World!\")",
#   "created_at": "2025-11-12T18:31:00Z"
# }

# Context ile kod üretme
# Önce bir test dosyası oluştur
echo 'def test(): pass' > /home/yunus/Desktop/bitirme-projesi/kullanici-kodlari/test.py

curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "prompt": "test.py dosyasındaki fonksiyonu açıkla",
    "chat_id": 1,
    "context_files": ["test.py"]
  }' | jq
```

## 9. Sohbet Silme Testi

```bash
# Sohbeti sil
curl -X DELETE http://localhost:8000/api/chats/$CHAT_ID \
  -H "Authorization: Bearer $TOKEN" | jq

# Beklenen çıktı:
# {
#   "message": "Sohbet başarıyla silindi."
# }

# Tekrar silmeye çalış (hata beklenir)
curl -X DELETE http://localhost:8000/api/chats/$CHAT_ID \
  -H "Authorization: Bearer $TOKEN" | jq

# Beklenen çıktı:
# {
#   "detail": "Sohbet bulunamadı."
# }
```

## 10. Hata Senaryoları Testi

### Geçersiz JSON

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d 'invalid json' | jq
```

### Eksik Alanlar

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test"}' | jq
```

### Geçersiz Token

```bash
curl http://localhost:8000/api/me \
  -H "Authorization: Bearer invalid_token_here" | jq
```

### Başka Kullanıcının Sohbetine Erişim

```bash
# İkinci kullanıcı oluştur
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "İkinci Kullanıcı",
    "email": "test2@example.com",
    "password": "123456"
  }'

# İkinci kullanıcı ile giriş
export TOKEN2=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test2@example.com","password":"123456"}' | jq -r .access_token)

# İlk kullanıcının sohbetine erişmeye çalış (hata beklenir)
curl http://localhost:8000/api/chats/1 \
  -H "Authorization: Bearer $TOKEN2" | jq
```

## 11. Performance Testi

### Basit Load Test (Apache Bench)

```bash
# ab yüklü olmalı
sudo apt install apache-bench

# 100 istek, 10 concurrent
ab -n 100 -c 10 http://localhost:8000/health

# POST isteği için
ab -n 100 -c 10 -p register.json -T application/json http://localhost:8000/register
```

### wrk ile Load Test

```bash
# wrk yükle
git clone https://github.com/wg/wrk.git
cd wrk && make

# 30 saniye boyunca test et
./wrk -t4 -c100 -d30s http://localhost:8000/health
```

## 12. Docker Test

```bash
# Container loglarını izle
docker-compose logs -f backend-api

# Container içine bağlan
docker exec -it backend-api sh

# Container içinde database kontrol
ls -la /app/data/

# Container resource kullanımı
docker stats backend-api

# Container restart
docker-compose restart backend-api

# Container rebuild
docker-compose build --no-cache backend-api
docker-compose up -d backend-api
```

## 13. Veritabanı Testi

```bash
# SQLite CLI ile bağlan
docker exec -it backend-api sh
cd /app/data
apk add sqlite

sqlite3 veritabani.db

# SQL komutları:
.tables
SELECT * FROM users;
SELECT * FROM chats;
SELECT * FROM messages;
.quit
```

## 14. Automated Test Script

```bash
#!/bin/bash

# test-api.sh
set -e

echo "Backend API Test Suite"
echo "======================"

# 1. Health check
echo "1. Health check..."
curl -sf http://localhost:8000/health > /dev/null && echo "✓ OK" || echo "✗ FAIL"

# 2. Register
echo "2. User registration..."
curl -sf -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@test.com","password":"123456"}' > /dev/null && echo "✓ OK" || echo "✗ FAIL"

# 3. Login
echo "3. User login..."
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@test.com","password":"123456"}' | jq -r .access_token)
[ ! -z "$TOKEN" ] && echo "✓ OK" || echo "✗ FAIL"

# 4. Get user info
echo "4. Get user info..."
curl -sf http://localhost:8000/api/me \
  -H "Authorization: Bearer $TOKEN" > /dev/null && echo "✓ OK" || echo "✗ FAIL"

# 5. Create chat
echo "5. Create chat..."
curl -sf -X POST http://localhost:8000/api/chats \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Test Chat"}' > /dev/null && echo "✓ OK" || echo "✗ FAIL"

echo "======================"
echo "Test completed!"
```

## Test Sonuçlarını Değerlendirme

### Başarılı Test Kriterleri

- ✅ Tüm endpoint'ler cevap veriyor
- ✅ HTTP status kodları doğru (200, 201, 401, 404, vs.)
- ✅ JSON response formatları doğru
- ✅ JWT authentication çalışıyor
- ✅ Database CRUD operasyonları çalışıyor
- ✅ Ollama entegrasyonu çalışıyor
- ✅ Hata mesajları anlamlı

### Hata Durumunda

1. Logları kontrol edin: `docker-compose logs backend-api`
2. Container çalışıyor mu: `docker-compose ps`
3. Port çakışması: `netstat -tulpn | grep 8000`
4. Database permissions: `ls -la backend-data/`
5. Ollama servisi: `curl http://localhost:11434/api/tags`

## CI/CD Test Pipeline

```yaml
# .github/workflows/test.yml örneği
name: Backend Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        run: docker-compose build backend-api
      - name: Start services
        run: docker-compose up -d
      - name: Wait for services
        run: sleep 30
      - name: Run tests
        run: ./test-api.sh
      - name: Cleanup
        run: docker-compose down
```

## Sonuç

Tüm testler başarılı bir şekilde geçerse, backend API production'a hazır demektir!
