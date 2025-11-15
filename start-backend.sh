#!/bin/bash

# Eller Serbest Kodlama - Backend Başlatma Scripti
# Bu script, backend API servisini başlatmak için gerekli adımları otomatikleştirir

set -e

echo "=========================================="
echo "Eller Serbest Kodlama - Backend API"
echo "=========================================="
echo ""

# Renk kodları
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Fonksiyonlar
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 1. Dizinleri oluştur
log_info "Gerekli dizinler oluşturuluyor..."
mkdir -p backend-data kullanici-kodlari ollama-data
chmod 755 backend-data kullanici-kodlari 2>/dev/null || true

# 2. Docker ve Docker Compose kontrolü
if ! command -v docker &> /dev/null; then
    log_error "Docker bulunamadı! Lütfen Docker'ı yükleyin."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    log_error "Docker Compose bulunamadı! Lütfen Docker Compose'u yükleyin."
    exit 1
fi

log_info "Docker ve Docker Compose bulundu."

# 3. Eski container'ları temizle (isteğe bağlı)
if [ "$1" == "--clean" ]; then
    log_warn "Eski container'lar temizleniyor..."
    docker-compose down -v 2>/dev/null || true
    rm -rf backend-data/*.db 2>/dev/null || true
fi

# 4. Backend API'yi build et
log_info "Backend API build ediliyor..."
docker-compose build backend-api

# 5. Backend API'yi başlat
log_info "Backend API başlatılıyor..."
docker-compose up -d backend-api

# 6. Servislerin başlamasını bekle
log_info "Servisler başlatılıyor... (30 saniye bekleniyor)"
sleep 30

# 7. Sağlık kontrolü
log_info "Backend API sağlık kontrolü yapılıyor..."
for i in {1..10}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        log_info "Backend API başarıyla başlatıldı!"
        echo ""
        echo "=========================================="
        echo "Backend API Bilgileri:"
        echo "=========================================="
        echo "URL: http://localhost:8000"
        echo "Health Check: http://localhost:8000/health"
        echo "API Docs: http://localhost:8000/api"
        echo ""
        echo "Logları izlemek için:"
        echo "  docker-compose logs -f backend-api"
        echo ""
        echo "Durdurmak için:"
        echo "  docker-compose down"
        echo "=========================================="

        # Sağlık durumunu göster
        curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:8000/health

        exit 0
    fi
    log_warn "Backend API henüz hazır değil, tekrar deneniyor... ($i/10)"
    sleep 5
done

log_error "Backend API başlatılamadı! Logları kontrol edin:"
echo "  docker-compose logs backend-api"
exit 1
