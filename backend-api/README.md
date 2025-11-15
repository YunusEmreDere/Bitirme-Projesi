# Backend API (Orkestratör) - Eller Serbest Kodlama

Go (Golang) ile geliştirilmiş, yüksek performanslı backend API servisi.

## Teknoloji Stack

- **Dil:** Go 1.21+
- **Web Framework:** Gin
- **Veritabanı:** SQLite + GORM
- **Güvenlik:** JWT (golang-jwt), bcrypt
- **AI Entegrasyonu:** Ollama API

## Özellikler

- ✅ Kullanıcı kayıt ve giriş (JWT tabanlı)
- ✅ Sohbet yönetimi (CRUD operasyonları)
- ✅ Mesaj yönetimi ve geçmişi
- ✅ Ollama LLM entegrasyonu
- ✅ Context-aware kod üretimi
- ✅ Dosya okuma ve işleme
- ✅ Health check endpoint'i
- ✅ CORS desteği

## API Endpoints

### Public Endpoints
- `POST /register` - Yeni kullanıcı kaydı
- `POST /login` - Kullanıcı girişi
- `GET /` - Servis durumu
- `GET /health` - Sağlık kontrolü

### Protected Endpoints (JWT gerekli)
- `GET /api/me` - Kullanıcı bilgileri
- `POST /api/chats` - Yeni sohbet oluştur
- `GET /api/chats` - Kullanıcının sohbetlerini listele
- `GET /api/chats/:id` - Belirli bir sohbeti getir
- `DELETE /api/chats/:id` - Sohbeti sil
- `POST /api/generate` - AI ile kod üret

## Kurulum

### Docker ile (Önerilen)

```bash
# Projeyi başlat
docker-compose up -d backend-api

# Logları izle
docker-compose logs -f backend-api
```

### Manuel Kurulum

```bash
# Bağımlılıkları yükle
cd backend-api
go mod download

# Çalıştır
go run main.go
```

## Geliştirme

### Hot Reload ile Geliştirme

```bash
# Air'i yükle (Go hot reload tool)
go install github.com/cosmtrek/air@latest

# Air ile çalıştır
air
```

### Test

```bash
# Tüm testleri çalıştır
go test ./...

# Coverage ile
go test -cover ./...
```

## Ortam Değişkenleri

`.env.example` dosyasını `.env` olarak kopyalayın ve değerleri güncelleyin:

```bash
cp .env.example .env
```

Önemli değişkenler:
- `OLLAMA_API_URL`: Ollama servisinin adresi
- `DATABASE_URL`: SQLite veritabanı yolu
- `JWT_SECRET_KEY`: JWT için gizli anahtar (mutlaka değiştirin!)
- `PROJECTS_PATH`: AI'nın dosya okuyacağı klasör

## Güvenlik

- Şifreler bcrypt ile hash'lenir
- JWT token'lar 24 saat geçerlidir
- CORS koruması aktif
- Dosya okuma sadece belirlenen klasörle sınırlı
- SQL injection koruması (GORM ORM kullanımı ile)

## Veritabanı Modelleri

### User
- ID (uint, primary key)
- Name (string)
- Email (string, unique)
- HashedPassword (string)
- CreatedAt (timestamp)

### Chat
- ID (uint, primary key)
- UserID (uint, foreign key)
- Title (string)
- CreatedAt (timestamp)
- UpdatedAt (timestamp)

### Message
- ID (uint, primary key)
- ChatID (uint, foreign key)
- Sender (string: "user" veya "bot")
- Text (string)
- Type (string: "text", "code", "diff")
- CreatedAt (timestamp)
- OldValue, NewValue (string, optional - diff için)
- Language, FilePath (string, optional)

## Lisans

Bu proje akademik bir bitirme projesidir.
