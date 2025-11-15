# ----- 1. Aşama: Build (Derleme) Aşaması -----
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Bağımlılıkları (dependencies) önbelleğe almak için önce mod dosyasını kopyala
COPY go.mod ./
RUN go mod download

# Kalan tüm kaynak kodu kopyala
COPY . .

# go.sum dosyasını oluştur
RUN go mod tidy

# Uygulamayı derle (CGO_ENABLED=1 SQLite için gerekli)
RUN apk add --no-cache gcc musl-dev
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o /go/bin/backend-api .

# ----- 2. Aşama: Çalıştırma (Run) Aşaması -----
FROM alpine:latest

# Güvenlik ve veritabanı için gerekli paketler
RUN apk --no-cache add ca-certificates tzdata sqlite-libs wget

WORKDIR /app

# Derlenmiş olan binary'yi 'builder' aşamasından kopyala
COPY --from=builder /go/bin/backend-api .

# Veritabanı dosyalarının saklanacağı 'data' klasörünü oluştur
# (Bu dizin, docker-compose'daki volume ile eşleşecek)
RUN mkdir -p /app/data /app/projects

# API'nin çalışacağı portu aç
EXPOSE 8000

# Konteyner başladığında derlenmiş uygulamayı çalıştır
CMD ["./backend-api"]
