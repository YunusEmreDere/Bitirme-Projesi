# Eller Serbest Kodlama - Backend API (Go) 🚀

Tam kapsamlı, üretim kalitesinde Go backend servisi.

## 📁 Proje Yapısı

```
bitirme-projesi/
├── backend-api/              # Go Backend API (YENİ!)
│   ├── main.go              # Ana uygulama dosyası
│   ├── go.mod               # Go bağımlılıkları
│   ├── Dockerfile           # Multi-stage Docker build
│   ├── .env.example         # Örnek ortam değişkenleri
│   ├── .air.toml            # Hot reload konfigürasyonu
│   ├── .gitignore           # Git ignore kuralları
│   ├── README.md            # Backend API dokümantasyonu
│   └── KURULUM.md           # Detaylı kurulum rehberi
├── web/                     # React Frontend
├── docker-compose.yml       # Tüm servislerin orchestration'ı
├── backend-data/            # SQLite veritabanı (persistent)
├── kullanici-kodlari/       # AI'nın oluşturacağı kodlar
└── ollama-data/             # Ollama model verileri
```

## 🎯 Backend API Özellikleri

### ✅ Tamamlanan Özellikler

1. **Kullanıcı Yönetimi**
   - Kayıt (bcrypt ile şifreleme)
   - Giriş (JWT token tabanlı)
   - Kullanıcı profili

2. **Sohbet Yönetimi**
   - Yeni sohbet oluşturma
   - Sohbet listeleme
   - Sohbet detayları (mesajlarla birlikte)
   - Sohbet silme

3. **Mesajlaşma**
   - Kullanıcı mesajları
   - Bot yanıtları (Ollama LLM)
   - Mesaj tipleri: text, code, diff
   - Context-aware yanıtlar

4. **AI Entegrasyonu**
   - Ollama API bağlantısı
   - Dosya içeriği okuma (context)
   - Akıllı mesaj tipi tespiti
   - Parametre ayarları (temperature, top_p)

5. **Güvenlik**
   - JWT authentication
   - bcrypt password hashing
   - CORS koruması
   - Path traversal koruması
   - SQL injection koruması (GORM)

6. **DevOps**
   - Multi-stage Docker build
   - Health check endpoint
   - Hot reload (Air)
   - Logging
   - Environment variables

## 🚀 Hızlı Başlangıç

### Tüm Servisleri Başlatma

```bash
# Dizine git
cd /home/yunus/Desktop/bitirme-projesi

# Servisleri başlat
docker-compose up -d

# Logları izle
docker-compose logs -f backend-api
```

### Backend API'yi Test Etme

```bash
# Sağlık kontrolü
curl http://localhost:8000/health

# Kullanıcı kaydı
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@test.com","password":"123456"}'

# Giriş
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@test.com","password":"123456"}'
```

## 🔧 Teknoloji Stack

### Backend (Go)
- **Language:** Go 1.21+
- **Framework:** Gin (web framework)
- **Database:** SQLite + GORM (ORM)
- **Auth:** JWT (golang-jwt/jwt), bcrypt
- **CORS:** gin-contrib/cors
- **Environment:** godotenv

### Infrastructure
- **Container:** Docker (multi-stage build)
- **Orchestration:** Docker Compose
- **AI Engine:** Ollama (llama3:8b)
- **Web Server:** Nginx (frontend)

## 📊 API Endpoints

### Public Endpoints

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/` | Servis durumu |
| GET | `/health` | Sağlık kontrolü |
| POST | `/register` | Kullanıcı kaydı |
| POST | `/login` | Kullanıcı girişi |

### Protected Endpoints (JWT Required)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/api/me` | Kullanıcı bilgileri |
| POST | `/api/chats` | Yeni sohbet oluştur |
| GET | `/api/chats` | Sohbetleri listele |
| GET | `/api/chats/:id` | Sohbet detayı |
| DELETE | `/api/chats/:id` | Sohbet sil |
| POST | `/api/generate` | AI ile kod üret |

## 🗄️ Veritabanı Şeması

### User (Kullanıcı)
```go
type User struct {
    ID             uint
    Name           string
    Email          string    // unique
    HashedPassword string
    CreatedAt      time.Time
}
```

### Chat (Sohbet)
```go
type Chat struct {
    ID        uint
    UserID    uint         // foreign key
    Title     string
    CreatedAt time.Time
    UpdatedAt time.Time
    Messages  []Message
}
```

### Message (Mesaj)
```go
type Message struct {
    ID        uint
    ChatID    uint         // foreign key
    Sender    string       // "user" | "bot"
    Text      string
    Type      string       // "text" | "code" | "diff"
    CreatedAt time.Time
    OldValue  *string      // diff için
    NewValue  *string      // diff için
    Language  *string      // code için
    FilePath  *string      // dosya referansı için
}
```

## 🔐 Güvenlik

1. **Şifre Güvenliği**
   - bcrypt hash (cost: 10)
   - Asla plain-text saklanmaz

2. **Authentication**
   - JWT token (24 saat geçerlilik)
   - HS256 algoritması
   - Gizli anahtar: `JWT_SECRET_KEY` env variable

3. **Authorization**
   - Middleware tabanlı
   - Route-level koruma
   - User-resource ownership kontrolü

4. **CORS**
   - Sadece belirlenen origin'lere izin
   - Credentials desteği
   - Pre-flight handling

5. **Input Validation**
   - Gin binding/validation
   - SQL injection koruması (GORM)
   - Path traversal koruması

## 🔄 Geliştirme Workflow'u

### Hot Reload ile Geliştirme

```bash
cd backend-api

# Air'i yükle (ilk kez)
go install github.com/cosmtrek/air@latest

# Hot reload ile başlat
air
```

### Docker ile Geliştirme

```bash
# Volume mount ile kod değişikliklerini izle
docker-compose up backend-api

# Yeniden build
docker-compose build backend-api
docker-compose up -d backend-api
```

### Test ve Debug

```bash
# Go testleri çalıştır
go test ./...

# Coverage raporu
go test -cover ./...

# Logları izle
docker-compose logs -f backend-api

# Container'a bağlan
docker exec -it backend-api sh
```

## 🌐 Environment Variables

```bash
# Ollama API URL
OLLAMA_API_URL=http://beyin-ollama:11434

# Database path
DATABASE_URL=./data/veritabani.db

# JWT Secret (MUTLAKA DEĞİŞTİR!)
JWT_SECRET_KEY=your-super-secret-key

# Projects directory
PROJECTS_PATH=/app/projects

# Server port
PORT=8000

# Gin mode
GIN_MODE=release  # production
GIN_MODE=debug    # development
```

## 📦 Docker Build

### Manuel Build

```bash
cd backend-api

# Build image
docker build -t backend-api:latest .

# Run container
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -e JWT_SECRET_KEY=secret \
  backend-api:latest
```

### Multi-stage Build Detayları

1. **Builder Stage:** Go 1.21-alpine
   - Bağımlılıkları indir
   - Binary derle (CGO enabled for SQLite)

2. **Runtime Stage:** Alpine latest
   - Minimal image (~50MB)
   - Sadece gerekli paketler
   - Binary kopyala ve çalıştır

## 🐛 Sorun Giderme

### 1. Backend başlamıyor

```bash
# Logları kontrol et
docker-compose logs backend-api

# Container'ı yeniden başlat
docker-compose restart backend-api

# Image'ı yeniden build et
docker-compose build --no-cache backend-api
```

### 2. Ollama'ya bağlanamıyor

```bash
# Ollama çalışıyor mu?
docker-compose ps beyin-ollama

# Ollama API test
curl http://localhost:11434/api/tags

# Model var mı?
docker exec beyin-ollama ollama list
```

### 3. Database hatası

```bash
# Permission kontrolü
ls -la backend-data/

# Database sil ve yeniden oluştur
rm backend-data/veritabani.db
docker-compose restart backend-api
```

### 4. JWT token geçersiz

```bash
# Secret key ayarlı mı?
docker-compose exec backend-api env | grep JWT

# Yeni token al
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@test.com","password":"123456"}'
```

## 📈 Performance Tips

1. **Database:**
   - SQLite WAL mode (Write-Ahead Logging)
   - Index'ler (email, chat_id, user_id)
   - Connection pooling

2. **Caching:**
   - Ollama model cache
   - Static file serving (nginx)

3. **Scaling:**
   - Horizontal: Multiple backend instances (load balancer)
   - Vertical: Increase container resources
   - Database: PostgreSQL'e geçiş (production)

## 🚀 Production Deployment

### Checklist

- [ ] JWT_SECRET_KEY değiştir (rastgele, güçlü)
- [ ] GIN_MODE=release
- [ ] CORS origins güncelle
- [ ] SSL/TLS sertifikası ekle (reverse proxy)
- [ ] Rate limiting ekle
- [ ] Monitoring/logging ekle (Prometheus, Grafana)
- [ ] Database backup stratejisi
- [ ] Environment secrets (Docker secrets, K8s secrets)

### Önerilen Üretim Stack

```
[Internet]
    |
[Cloudflare/CDN]
    |
[Nginx/Traefik] (reverse proxy, SSL)
    |
[Load Balancer]
    |
+-- [Backend API 1] -- [PostgreSQL Primary]
+-- [Backend API 2] -- [PostgreSQL Replica]
+-- [Backend API N]
    |
[Redis Cache]
    |
[Ollama Cluster]
```

## 📝 Notlar

- SQLite sadece prototip için, production'da PostgreSQL kullanın
- File upload limitleri ayarlayın
- Rate limiting implementasyonu ekleyin
- Webhook desteği eklenebilir
- WebSocket desteği eklenebilir (real-time messaging)

## 🤝 Katkıda Bulunma

Bu bir bitirme projesidir. Öneriler için issue açabilirsiniz.

## 📄 Lisans

Akademik kullanım için.

---

**Hazırlayan:** Claude Code (Anthropic)
**Tarih:** 2025-11-12
**Versiyon:** 1.0.0
**Go Version:** 1.21+
**Docker:** Multi-stage Alpine-based
