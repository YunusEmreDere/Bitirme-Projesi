# ----- AŞAMA 1: Build Aşaması -----
FROM node:20-alpine AS builder

WORKDIR /app

# package.json ve package-lock.json kopyala
COPY package.json package-lock.json ./

# npm install sırasında peer dependency hatalarını yok say
RUN npm install --legacy-peer-deps

# Proje dosyalarını kopyala
COPY . .

# React projesini build et
RUN npm run build

# ----- AŞAMA 2: Sunucu Aşaması -----
FROM nginx:1.25-alpine

# Build edilmiş dosyaları Nginx kök dizinine kopyala
COPY --from=builder /app/dist /usr/share/nginx/html

# React Router için Nginx config dosyasını kopyala
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
