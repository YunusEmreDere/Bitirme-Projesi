# Backend API Kurulum Rehberi

## Ön Gereksinimler

- Docker ve Docker Compose
- NVIDIA GPU (Ollama için)
- NVIDIA Container Toolkit

## Hızlı Başlangıç

### 1. Projeyi İndirin veya Klonlayın

```bash
cd /home/yunus/Desktop/bitirme-projesi
```

### 2. Gerekli Dizinleri Oluşturun

```bash
mkdir -p backend-data kullanici-kodlari ollama-data
chmod 755 backend-data kullanici-kodlari
```

### 3. Docker Compose ile Başlatın

```bash
# Tüm servisleri başlat
docker-compose up -d

# Sadece backend-api'yi başlat
docker-compose up -d backend-api

# Logları izleyin
docker-compose logs -f backend-api
```

### 4. Servislerin Durumunu Kontrol Edin

```bash
# Backend API sağlık kontrolü
curl http://localhost:8000/health

# Beklenen çıktı:
# {
#   "status": "healthy",
#   "database": "connected",
#   "ollama": "connected",
#   "version": "1.0.0"
# }
```

## API Kullanımı

### Kullanıcı Kaydı

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Kullanıcı",
    "email": "test@example.com",
    "password": "123456"
  }'
```

### Giriş Yapma

```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test@example.com",
    "password": "123456"
  }'

# Token'ı kaydedin:
export TOKEN="eyJhbGc..."
```

### Yeni Sohbet Oluşturma

```bash
curl -X POST http://localhost:8000/api/chats \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "title": "İlk Projem"
  }'
```

### AI ile Kod Üretme

```bash
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "prompt": "Python ile hello world yazdır",
    "chat_id": 1,
    "context_files": []
  }'
```

## Geliştirme Modu

### Hot Reload ile Çalıştırma

```bash
# backend-api dizinine girin
cd backend-api

# Docker içinde Air ile çalıştırın (docker-compose.dev.yml kullanın)
docker-compose -f docker-compose.dev.yml up backend-api
```

### Lokal Geliştirme (Go yüklü ise)

```bash
cd backend-api

# Bağımlılıkları indirin
go mod download

# Air'i yükleyin (hot reload için)
go install github.com/cosmtrek/air@latest

# Air ile çalıştırın
air

# veya doğrudan:
go run main.go
```

## Sorun Giderme

### 1. Backend Başlamıyor

```bash
# Container loglarını kontrol edin
docker-compose logs backend-api

# Container'ı yeniden başlatın
docker-compose restart backend-api
```

### 2. Ollama'ya Bağlanamıyor

```bash
# Ollama servisinin çalıştığından emin olun
docker-compose ps beyin-ollama

# Ollama'nın sağlığını kontrol edin
curl http://localhost:11434/api/tags

# Model yüklü mü kontrol edin
docker exec beyin-ollama ollama list
```

### 3. Veritabanı Hatası

```bash
# Veritabanı dosyasını silip yeniden oluşturun
rm backend-data/veritabani.db
docker-compose restart backend-api
```

### 4. JWT Token Hatası

```bash
# JWT_SECRET_KEY ortam değişkeninin ayarlandığından emin olun
docker-compose exec backend-api env | grep JWT_SECRET_KEY
```

## Üretim Dağıtımı

### 1. Güvenlik Ayarları

```bash
# .env dosyasını oluşturun
cp backend-api/.env.example backend-api/.env

# JWT_SECRET_KEY'i güvenli bir değer ile değiştirin
# openssl ile rastgele anahtar oluşturun:
openssl rand -hex 32
```

### 2. Docker Compose Ayarları

`docker-compose.yml` dosyasında:
- `JWT_SECRET_KEY` değerini güvenli bir değere değiştirin
- `GIN_MODE=release` olduğundan emin olun
- Gerekirse portları değiştirin

### 3. SSL/TLS Ekleyin

Nginx reverse proxy kullanarak SSL sertifikası ekleyin:

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Yedekleme

### Veritabanı Yedeği

```bash
# SQLite veritabanını yedekleyin
cp backend-data/veritabani.db backend-data/veritabani_backup_$(date +%Y%m%d).db

# veya docker volume kullanarak:
docker run --rm -v bitirme-projesi_backend-data:/data \
  -v $(pwd)/backups:/backup alpine \
  tar czf /backup/backend-data-$(date +%Y%m%d).tar.gz /data
```

## Performans İzleme

### Logları İzleyin

```bash
# Tüm logları göster
docker-compose logs -f backend-api

# Sadece hataları göster
docker-compose logs backend-api | grep ERROR
```

### Resource Kullanımı

```bash
# Container istatistiklerini göster
docker stats backend-api

# CPU ve Memory kullanımı
docker stats --no-stream backend-api
```

## İletişim ve Destek

Herhangi bir sorun için:
1. GitHub Issues sayfasını kontrol edin
2. Loglarda hata mesajlarını arayın
3. Docker ve Go versiyonlarınızı kontrol edin
