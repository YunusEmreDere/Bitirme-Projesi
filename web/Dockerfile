# arauyuz/Dockerfile

# ----- AŞAMA 1: Build Aşaması -----
# Node.js'in hafif (alpine) bir sürümünü 'builder' olarak adlandır
FROM node:20-alpine AS builder

# Çalışma dizinini /app olarak ayarla
WORKDIR /app

# Sadece 'package.json' dosyalarını kopyala
# Bu sayede 'npm install' sadece dosyalar değiştiğinde tekrar çalışır (Docker cache)
COPY package.json package-lock.json ./

# Gerekli kütüphaneleri kur
RUN npm install

# Tüm proje kaynak kodunu kopyala
COPY . .

# React projesini 'build' et (Vite için 'dist' klasörü oluşur)
RUN npm run build

# ----- AŞAMA 2: Sunucu Aşaması -----
# 'builder' aşamasını unut ve sıfırdan, çok hafif bir nginx imajı başlat
FROM nginx:1.25-alpine

# 'builder' aşamasında oluşan 'dist' klasörünü
# Nginx'in web kök dizinine (/usr/share/nginx/html) kopyala
COPY --from=builder /app/dist /usr/share/nginx/html

# (ÖNEMLİ) React Router'ın çalışması için Nginx ayarı
# Bu, /login, /settings gibi sayfalara gidildiğinde 404 hatası almamak için
# tüm istekleri 'index.html'e yönlendirir.
# Önce bu ayar dosyasını kopyalayalım:
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Nginx'in 80 portunu dışarı aç
EXPOSE 80

# Konteyner başladığında Nginx'i başlat
CMD ["nginx", "-g", "daemon off;"]
