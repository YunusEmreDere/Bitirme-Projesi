package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ----- GEREKLİ YARDIMCI DEĞİŞKENLER -----
var (
	db             *gorm.DB
	err            error
	JWT_SECRET_KEY = []byte(getEnv("JWT_SECRET_KEY", "COK_GIZLI_BIR_ANAHTAR_BITIRME_PROJESI"))
	OLLAMA_API_URL = getEnv("OLLAMA_API_URL", "http://beyin-ollama:11434")
	DATABASE_URL   = getEnv("DATABASE_URL", "./data/veritabani.db")
	PROJECTS_PATH  = getEnv("PROJECTS_PATH", "./projects")
)

// getEnv, ortam değişkenini okur veya varsayılan bir değer döndürür
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// ----- 1. VERİTABANI MODELLERİ (GORM) -----

type User struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Name           string    `json:"name"`
	Email          string    `json:"email" gorm:"unique"`
	HashedPassword string    `json:"-"` // Şifreyi JSON'da gösterme
	CreatedAt      time.Time `json:"created_at"`
	Chats          []Chat    `json:"chats,omitempty" gorm:"foreignKey:UserID"`
}

type Chat struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `json:"user_id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Messages  []Message `json:"messages,omitempty" gorm:"foreignKey:ChatID"`
}

type Message struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	ChatID    uint      `json:"chat_id"`
	Sender    string    `json:"sender"` // "user" veya "bot"
	Text      string    `json:"text" gorm:"type:text"`
	Type      string    `json:"type"` // "text", "code", "diff"
	CreatedAt time.Time `json:"created_at"`
	// Diff mesajları için ek alanlar (isteğe bağlı)
	OldValue *string `json:"old_value,omitempty" gorm:"type:text"`
	NewValue *string `json:"new_value,omitempty" gorm:"type:text"`
	Language *string `json:"language,omitempty"`
	FilePath *string `json:"file_path,omitempty"`
}

// ----- 2. VERİTABANI BAĞLANTISI -----

func DatabaseInit() {
	// Veritabanı dosyasının yolunu al
	dbPath := DATABASE_URL
	if strings.HasPrefix(dbPath, "sqlite:///") {
		dbPath = dbPath[len("sqlite:///"):]
	}

	// /app/data klasörünün var olduğundan emin ol
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Fatal("Veritabanı klasörü oluşturulamadı: ", err)
	}

	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatal("Veritabanına bağlanılamadı: ", err)
	}

	// Modelleri veritabanına otomatik olarak migrate et (tabloları oluştur)
	if err := db.AutoMigrate(&User{}, &Chat{}, &Message{}); err != nil {
		log.Fatal("Veritabanı migration hatası: ", err)
	}

	log.Println("Veritabanı başarıyla başlatıldı:", dbPath)
}

// ----- 3. JWT (GÜVENLİK) MANTIKLARI -----

// JwtClaims, token içinde saklanacak bilgileri tanımlar
type JwtClaims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}

func GenerateJWT(user User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // 24 saat geçerli
	claims := &JwtClaims{
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JWT_SECRET_KEY)
}

// AuthMiddleware, korumalı rotalara erişimi denetler
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"detail": "Yetkilendirme başlığı (Authorization header) eksik"})
			c.Abort()
			return
		}

		// Token genellikle "Bearer <token>" formatındadır
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims := &JwtClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return JWT_SECRET_KEY, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"detail": "Geçersiz veya süresi dolmuş token"})
			c.Abort()
			return
		}

		// Kullanıcı bilgilerini 'context'e ekle, böylece diğer handler'lar erişebilir
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_name", claims.Name)
		c.Next()
	}
}

// getUserID, context'ten kullanıcı ID'sini alır
func getUserID(c *gin.Context) uint {
	userID, exists := c.Get("user_id")
	if !exists {
		return 0
	}
	return userID.(uint)
}

// ----- 4. HTTP HANDLER'LARI (İŞLEYİCİLER) -----

// Request/Response structs
type RegisterRequest struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"` // FastAPI OAuth2 formuna uyum için 'username'
	Password string `json:"password" binding:"required"`
}

type GenerateRequest struct {
	Prompt       string   `json:"prompt" binding:"required"`
	ChatID       uint     `json:"chat_id" binding:"required"`
	ContextFiles []string `json:"context_files"`
	BasePath     string   `json:"base_path"` // Kullanıcının proje kök dizini
}

type CreateChatRequest struct {
	Title string `json:"title" binding:"required"`
}

type MessageResponse struct {
	ID        uint      `json:"id"`
	Sender    string    `json:"sender"`
	Text      string    `json:"text"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
	OldValue  *string   `json:"old_value,omitempty"`
	NewValue  *string   `json:"new_value,omitempty"`
	Language  *string   `json:"language,omitempty"`
	FilePath  *string   `json:"file_path,omitempty"`
}

// ----- DOSYA SİSTEMİ API REQUEST/RESPONSE STRUCTS -----

type FSListRequest struct {
	Path      string `json:"path" binding:"required"`
	Recursive bool   `json:"recursive"`
}

type FSReadRequest struct {
	Path string `json:"path" binding:"required"`
}

type FSWriteRequest struct {
	Path    string `json:"path" binding:"required"`
	Content string `json:"content" binding:"required"`
}

type FSDeleteRequest struct {
	Path string `json:"path" binding:"required"`
}

type FSMoveRequest struct {
	Source      string `json:"source" binding:"required"`
	Destination string `json:"destination" binding:"required"`
}

type FileInfo struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	IsDir     bool      `json:"is_dir"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	Extension string    `json:"extension,omitempty"`
}

type FSListResponse struct {
	Files []FileInfo `json:"files"`
	Total int        `json:"total"`
}

type FSReadResponse struct {
	Content  string `json:"content"`
	Size     int64  `json:"size"`
	Encoding string `json:"encoding"`
}

type FSOperationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

// HandleRegister: /register endpoint'i
func HandleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı alanlar: " + err.Error()})
		return
	}

	// Kullanıcı zaten var mı?
	var existingUser User
	if db.Where("email = ?", req.Email).First(&existingUser).Error == nil {
		c.JSON(http.StatusConflict, gin.H{"detail": "Bu e-posta adresi zaten kayıtlı."})
		return
	}

	// Şifreyi hash'le (bcrypt)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Şifre oluşturulurken hata oluştu."})
		return
	}

	// Yeni kullanıcıyı oluştur
	newUser := User{
		Name:           req.Name,
		Email:          req.Email,
		HashedPassword: string(hashedPassword),
		CreatedAt:      time.Now(),
	}
	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Kullanıcı oluşturulurken hata oluştu."})
		return
	}

	// JWT Token oluştur (Login gibi)
	token, err := GenerateJWT(newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Token oluşturulurken hata oluştu."})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":      "Hesap başarıyla oluşturuldu.",
		"access_token": token,
		"token_type":   "bearer",
		"user_name":    newUser.Name,
		"user_id":      newUser.ID,
	})
}

// HandleLogin: /login endpoint'i
func HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı alanlar."})
		return
	}

	var user User
	if db.Where("email = ?", req.Username).First(&user).Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "E-posta veya şifre hatalı."})
		return
	}

	// Şifreleri karşılaştır
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "E-posta veya şifre hatalı."})
		return
	}

	// JWT Token oluştur
	token, err := GenerateJWT(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Token oluşturulurken hata oluştu."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"token_type":   "bearer",
		"user_name":    user.Name,
		"user_id":      user.ID,
	})
}

// HandleGetMe: /api/me endpoint'i - Kullanıcı bilgilerini döndürür
func HandleGetMe(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":    user.ID,
		"name":  user.Name,
		"email": user.Email,
	})
}

// HandleCreateChat: /api/chats endpoint'i - Yeni sohbet oluşturur
func HandleCreateChat(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var req CreateChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı alanlar."})
		return
	}

	newChat := Chat{
		UserID:    userID,
		Title:     req.Title,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := db.Create(&newChat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Sohbet oluşturulurken hata oluştu."})
		return
	}

	c.JSON(http.StatusCreated, newChat)
}

// HandleGetChats: /api/chats endpoint'i - Kullanıcının tüm sohbetlerini listeler
func HandleGetChats(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var chats []Chat
	if err := db.Where("user_id = ?", userID).Order("updated_at DESC").Find(&chats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Sohbetler getirilirken hata oluştu."})
		return
	}

	c.JSON(http.StatusOK, chats)
}

// HandleGetChat: /api/chats/:id endpoint'i - Belirli bir sohbeti ve mesajlarını getirir
func HandleGetChat(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	chatID := c.Param("id")
	var chat Chat
	if err := db.Where("id = ? AND user_id = ?", chatID, userID).
		Preload("Messages", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).First(&chat).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Sohbet bulunamadı."})
		return
	}

	c.JSON(http.StatusOK, chat)
}

// HandleDeleteChat: /api/chats/:id endpoint'i - Sohbeti siler
func HandleDeleteChat(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	chatID := c.Param("id")
	var chat Chat
	if err := db.Where("id = ? AND user_id = ?", chatID, userID).First(&chat).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Sohbet bulunamadı."})
		return
	}

	// Önce mesajları sil
	db.Where("chat_id = ?", chatID).Delete(&Message{})
	// Sonra sohbeti sil
	db.Delete(&chat)

	c.JSON(http.StatusOK, gin.H{"message": "Sohbet başarıyla silindi."})
}

// readContextFiles, verilen dosya yollarındaki içerikleri okur
func readContextFiles(files []string, basePath string) string {
	var contextBuilder strings.Builder

	for _, filePath := range files {
		var fullPath string

		if basePath != "" {
			// Base path varsa direkt birleştir
			fullPath = filepath.Join(basePath, filePath)
			log.Printf("📖 Context dosyası okunuyor: %s", fullPath)
		} else {
			// Base path yoksa PROJECTS_PATH kullan (eski davranış)
			fullPath = filepath.Join(PROJECTS_PATH, filePath)
			if !strings.HasPrefix(fullPath, PROJECTS_PATH) {
				log.Printf("⚠️ Güvenlik: Erişim reddedildi: %s", filePath)
				continue
			}
		}

		content, err := os.ReadFile(fullPath)
		if err != nil {
			// Dosya yoksa AI'a bildir, error loglamaya gerek yok
			contextBuilder.WriteString("\n--- Dosya: ")
			contextBuilder.WriteString(filePath)
			contextBuilder.WriteString(" (BULUNAMADI - yeni dosya olabilir) ---\n")
			continue
		}

		contextBuilder.WriteString("\n--- Dosya: ")
		contextBuilder.WriteString(filePath)
		contextBuilder.WriteString(" ---\n")
		contextBuilder.Write(content)
		contextBuilder.WriteString("\n")
	}

	return contextBuilder.String()
}

// extractCodeBlock, markdown kod bloğunu çıkarır ve dosya uzantısını belirler
// AI birden fazla kod bloğu gönderebilir (örn: diff + python)
// Bu durumda DIFF olmayan SON programlama dili bloğunu alırız
func extractCodeBlock(text string) (code string, language string, hasCode bool) {
	// TÜM kod bloklarını bul
	re := regexp.MustCompile("```(\\w+)\\s*\\n([\\s\\S]*?)```")
	allMatches := re.FindAllStringSubmatch(text, -1)

	// Kod blokları varsa
	if len(allMatches) > 0 {
		// Geriye doğru ara - DIFF olmayan ilk bloğu bul
		for i := len(allMatches) - 1; i >= 0; i-- {
			lang := allMatches[i][1]
			codeContent := allMatches[i][2]

			// "diff" bloğunu atla - asıl kodu ara
			if lang != "diff" {
				log.Printf("✅ Kod bloğu bulundu: %s (index: %d/%d)", lang, i+1, len(allMatches))
				return codeContent, lang, true
			}
		}

		// Sadece diff varsa, ilk bloğu al (fallback)
		log.Printf("⚠️ Sadece diff bloğu bulundu, ilk bloğu kullanıyorum")
		return allMatches[0][2], allMatches[0][1], true
	}

	// Dil belirtilmemiş kod bloğu ```\n...\n```
	re2 := regexp.MustCompile("```\\s*\\n([\\s\\S]*?)```")
	matches2 := re2.FindStringSubmatch(text)

	if len(matches2) >= 2 {
		log.Printf("✅ Dil belirtilmemiş kod bloğu bulundu")
		return matches2[1], "", true
	}

	// FALLBACK: Markdown yoksa ama kod benzeri içerik varsa kabul et
	trimmed := strings.TrimSpace(text)

	// Python kodu algılama
	if strings.Contains(trimmed, "print(") || strings.Contains(trimmed, "def ") ||
	   strings.Contains(trimmed, "import ") || strings.Contains(trimmed, "class ") {
		log.Printf("🔍 Markdown yok ama Python kodu algılandı")
		return trimmed, "python", true
	}

	// JavaScript/React kodu algılama
	if strings.Contains(trimmed, "function ") || strings.Contains(trimmed, "const ") ||
	   strings.Contains(trimmed, "import React") || strings.Contains(trimmed, "export default") {
		log.Printf("🔍 Markdown yok ama JavaScript kodu algılandı")
		return trimmed, "javascript", true
	}

	// Go kodu algılama
	if strings.Contains(trimmed, "package ") || strings.Contains(trimmed, "func ") {
		log.Printf("🔍 Markdown yok ama Go kodu algılandı")
		return trimmed, "go", true
	}

	log.Printf("❌ Hiçbir kod bloğu bulunamadı")
	return "", "", false
}

// extractFileName, kullanıcı mesajından dosya adını çıkarır
func extractFileName(prompt string, language string) string {
	// "alfabe.py dosyası oluştur" gibi patternleri yakala
	re := regexp.MustCompile(`(\w+\.\w+)`)
	matches := re.FindStringSubmatch(prompt)

	if len(matches) >= 2 {
		return matches[1]
	}

	// Dosya adı bulunamazsa dile göre varsayılan isim ver
	langToExt := map[string]string{
		"python":     ".py",
		"javascript": ".js",
		"go":         ".go",
		"java":       ".java",
		"cpp":        ".cpp",
		"c":          ".c",
		"rust":       ".rs",
	}

	if ext, ok := langToExt[language]; ok {
		return "output" + ext
	}

	return "output.txt"
}

// ----- GÜVENLİK VALIDATOR FONKSİYONLARI -----

// validatePath, dosya yolunun güvenli olup olmadığını kontrol eder
func validatePath(requestedPath string) (string, error) {
	// Boş path kontrolü
	if strings.TrimSpace(requestedPath) == "" {
		return "", os.ErrInvalid
	}

	// Path traversal saldırılarını önle (.., ./, vb.)
	cleanPath := filepath.Clean(requestedPath)

	// Tam dosya yolu
	fullPath := filepath.Join(PROJECTS_PATH, cleanPath)

	// PROJECTS_PATH dışına çıkış kontrolü
	if !strings.HasPrefix(fullPath, PROJECTS_PATH) {
		return "", os.ErrPermission
	}

	// Symlink kontrolü (güvenlik)
	evalPath, err := filepath.EvalSymlinks(fullPath)
	if err == nil {
		// Symlink varsa, gerçek path'i kontrol et
		if !strings.HasPrefix(evalPath, PROJECTS_PATH) {
			return "", os.ErrPermission
		}
	}

	return fullPath, nil
}

// getFileInfo, dosya bilgilerini döndürür
func getFileInfo(path string, relativePath string) (FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, err
	}

	ext := ""
	if !info.IsDir() {
		ext = filepath.Ext(info.Name())
	}

	return FileInfo{
		Name:      info.Name(),
		Path:      relativePath,
		IsDir:     info.IsDir(),
		Size:      info.Size(),
		ModTime:   info.ModTime(),
		Extension: ext,
	}, nil
}

// writeCodeToFile, kod bloğunu context klasörüne yazar
func writeCodeToFile(contextFiles []string, fileName string, code string, basePath string) error {
	var fullPath string

	if basePath != "" {
		// Base path VARSA: Sadece base path kullan, context files'ı yol olarak kullanma
		// Eğer context files varsa, ilk dosyanın klasörünü bul
		if len(contextFiles) > 0 {
			// İlk context dosyasının bulunduğu klasörü al
			targetDir := filepath.Dir(contextFiles[0])
			fullPath = filepath.Join(basePath, targetDir, fileName)
		} else {
			// Context yoksa direkt base path'e yaz
			fullPath = filepath.Join(basePath, fileName)
		}
		log.Printf("📂 Özel proje yolu kullanılıyor: %s", fullPath)
	} else {
		// Base path YOKSA: PROJECTS_PATH kullan (Docker volume - eski davranış)
		var targetDir string
		if len(contextFiles) > 0 {
			targetDir = filepath.Dir(contextFiles[0])
		} else {
			targetDir = "default"
		}

		targetPath := filepath.Join(targetDir, fileName)
		var err error
		fullPath, err = validatePath(targetPath)
		if err != nil {
			return err
		}
		log.Printf("📂 Docker volume yolu kullanılıyor: %s", fullPath)
	}

	// Klasörün var olduğundan emin ol
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Dosyayı yaz
	return os.WriteFile(fullPath, []byte(code), 0644)
}

// detectMessageType, bot yanıtının tipini belirler (text, code, diff)
func detectMessageType(text string) string {
	trimmed := strings.TrimSpace(text)

	// Diff formatını kontrol et
	if strings.Contains(trimmed, "<<<<<<< HEAD") ||
		strings.Contains(trimmed, "=======") ||
		strings.Contains(trimmed, ">>>>>>>") ||
		strings.HasPrefix(trimmed, "diff --git") {
		return "diff"
	}

	// Kod bloğunu kontrol et (markdown formatı)
	if strings.HasPrefix(trimmed, "```") && strings.HasSuffix(trimmed, "```") {
		return "code"
	}

	// Çok sayıda kod karakteristik işaretleri varsa code olarak işaretle
	codeIndicators := []string{
		"func ", "def ", "class ", "import ", "const ", "let ", "var ",
		"return ", "if ", "for ", "while ", "package ", "public ", "private ",
	}
	for _, indicator := range codeIndicators {
		if strings.Contains(trimmed, indicator) {
			// Satır sayısını kontrol et, çok satırlı kod olabilir
			lines := strings.Split(trimmed, "\n")
			if len(lines) > 3 {
				return "code"
			}
		}
	}

	return "text"
}

// ----- DOSYA SİSTEMİ API HANDLER'LARI -----

// HandleFSList: /api/tools/fs/list - Dizin içeriğini listeler
func HandleFSList(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var req FSListRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı istek."})
		return
	}

	// Güvenlik kontrolü
	fullPath, err := validatePath(req.Path)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Erişim reddedildi."})
		return
	}

	// Dizin olup olmadığını kontrol et
	info, err := os.Stat(fullPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Dizin bulunamadı."})
		return
	}

	if !info.IsDir() {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Belirtilen yol bir dizin değil."})
		return
	}

	var files []FileInfo

	if req.Recursive {
		// Recursive listeleme
		err = filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Hataları atla
			}

			// Relative path hesapla
			relPath, _ := filepath.Rel(PROJECTS_PATH, path)

			fileInfo, err := getFileInfo(path, relPath)
			if err == nil {
				files = append(files, fileInfo)
			}
			return nil
		})
	} else {
		// Sadece bu dizini listele
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Dizin okunamadı."})
			return
		}

		for _, entry := range entries {
			entryPath := filepath.Join(fullPath, entry.Name())
			relPath, _ := filepath.Rel(PROJECTS_PATH, entryPath)

			fileInfo, err := getFileInfo(entryPath, relPath)
			if err == nil {
				files = append(files, fileInfo)
			}
		}
	}

	c.JSON(http.StatusOK, FSListResponse{
		Files: files,
		Total: len(files),
	})
}

// HandleFSRead: /api/tools/fs/read - Dosya okur
func HandleFSRead(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var req FSReadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı istek."})
		return
	}

	// Güvenlik kontrolü
	fullPath, err := validatePath(req.Path)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Erişim reddedildi."})
		return
	}

	// Dosya okuma
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"detail": "Dosya bulunamadı."})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Dosya okunamadı."})
		}
		return
	}

	// Dosya bilgisi
	info, _ := os.Stat(fullPath)

	c.JSON(http.StatusOK, FSReadResponse{
		Content:  string(content),
		Size:     info.Size(),
		Encoding: "utf-8",
	})
}

// HandleFSWrite: /api/tools/fs/write - Dosya yazar
func HandleFSWrite(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var req FSWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı istek."})
		return
	}

	// Güvenlik kontrolü
	fullPath, err := validatePath(req.Path)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Erişim reddedildi."})
		return
	}

	// Klasörün var olduğundan emin ol
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Dizin oluşturulamadı."})
		return
	}

	// Dosyayı yaz
	if err := os.WriteFile(fullPath, []byte(req.Content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Dosya yazılamadı."})
		return
	}

	c.JSON(http.StatusOK, FSOperationResponse{
		Success: true,
		Message: "Dosya başarıyla yazıldı.",
		Path:    req.Path,
	})
}

// HandleFSDelete: /api/tools/fs/delete - Dosya veya dizin siler
func HandleFSDelete(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var req FSDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı istek."})
		return
	}

	// Güvenlik kontrolü
	fullPath, err := validatePath(req.Path)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Erişim reddedildi."})
		return
	}

	// Dosya/dizin var mı kontrol et
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Dosya veya dizin bulunamadı."})
		return
	}

	// Sil
	if err := os.RemoveAll(fullPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Silme işlemi başarısız."})
		return
	}

	c.JSON(http.StatusOK, FSOperationResponse{
		Success: true,
		Message: "Dosya/dizin başarıyla silindi.",
		Path:    req.Path,
	})
}

// HandleFSMove: /api/tools/fs/move - Dosya taşır veya yeniden adlandırır
func HandleFSMove(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var req FSMoveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı istek."})
		return
	}

	// Güvenlik kontrolü (source)
	sourcePath, err := validatePath(req.Source)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Kaynak erişim reddedildi."})
		return
	}

	// Güvenlik kontrolü (destination)
	destPath, err := validatePath(req.Destination)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Hedef erişim reddedildi."})
		return
	}

	// Kaynak dosya var mı kontrol et
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Kaynak dosya bulunamadı."})
		return
	}

	// Hedef dizininin var olduğundan emin ol
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Hedef dizin oluşturulamadı."})
		return
	}

	// Taşı/Yeniden adlandır
	if err := os.Rename(sourcePath, destPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Taşıma işlemi başarısız."})
		return
	}

	c.JSON(http.StatusOK, FSOperationResponse{
		Success: true,
		Message: "Dosya başarıyla taşındı.",
		Path:    req.Destination,
	})
}

// HandleGenerate: /api/generate endpoint'i (Ollama'ya bağlanan)
func HandleGenerate(c *gin.Context) {
	userID := getUserID(c)
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Kullanıcı bulunamadı."})
		return
	}

	var req GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Eksik veya hatalı istek."})
		return
	}

	// Sohbetin kullanıcıya ait olduğunu doğrula
	var chat Chat
	if err := db.Where("id = ? AND user_id = ?", req.ChatID, userID).First(&chat).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Bu sohbete erişim yetkiniz yok."})
		return
	}

	// DEBUG: Request bilgilerini logla
	log.Printf("🔍 Request alındı - Prompt: %s", req.Prompt)
	log.Printf("🔍 BasePath: '%s' (length: %d)", req.BasePath, len(req.BasePath))
	log.Printf("🔍 ContextFiles: %v", req.ContextFiles)

	// Kullanıcı mesajını veritabanına kaydet
	userMessage := Message{
		ChatID:    req.ChatID,
		Sender:    "user",
		Text:      req.Prompt,
		Type:      "text",
		CreatedAt: time.Now(),
	}
	if err := db.Create(&userMessage).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Mesaj kaydedilirken hata oluştu."})
		return
	}

	// Context dosyalarını oku
	contextContent := ""
	if len(req.ContextFiles) > 0 {
		contextContent = readContextFiles(req.ContextFiles, req.BasePath)
	}

	// System prompt'u oluştur
	systemPrompt := `Sen Türkçe konuşan bir akıllı kod asistanısın. Kullanıcılar sesli komutlarla senden kod yazmanı, dosya oluşturmanı, dosyaları düzenlemenı isteyecek.

ÖNEMLİ KURALLAR:
1. HER ZAMAN TÜRKÇE KONUŞ. İngilizce cevap verme.
2. Gereksiz konuşma yapma. "Tamam", "İşte kod", "Merhaba" gibi ifadeler yasak.
3. Kullanıcı kod istediğinde SADECE KOD yaz, açıklama yapma.
4. Kullanıcı açıklama isterse o zaman Türkçe açıklama yap.
5. Tüm kod bloklarını markdown formatında yaz: ` + "```python" + `, ` + "```javascript" + `, ` + "```go" + ` gibi.

DOSYA İŞLEMLERİ:
Kullanıcı "dosya oluştur", "dosyaya ekle", "şunu değiştir", "bu satırı sil" gibi komutlar verdiğinde:

1. Önce dosya var mı kontrol et (context files'da görebilirsin)
2. Dosya VARSA:
   - Mevcut içeriği oku
   - İstenen değişiklikleri uygula
   - Önce DIFF formatında değişiklikleri göster:
     ` + "```diff" + `
     - eski satır
     + yeni satır
     ` + "```" + `
   - Sonra TAM güncel dosya içeriğini göster:
     ` + "```python" + `
     # tam güncel kod
     ` + "```" + `

3. Dosya YOKSA:
   - Direkt yeni dosya içeriğini kod bloğu olarak yaz
   - Diff formatına gerek yok

ÖRNEKLER:

Örnek 1 - Yeni dosya:
Kullanıcı: "bu klasörde alfabe.py dosyası oluştur, hello world yazsın"
Sen:
` + "```python" + `
print("Hello World")
` + "```" + `

Örnek 2 - Mevcut dosyayı düzenle:
Kullanıcı: "alfabe.py dosyasına alfabeyi yazdıran fonksiyon ekle"
(Context'te alfabe.py var ve içinde: print("Hello World"))
Sen:
` + "```diff" + `
- print("Hello World")
+ def show_alphabet():
+     print("abcdefghijklmnopqrstuvwxyz")
+
+ print("Hello World")
+ show_alphabet()
` + "```" + `

` + "```python" + `
def show_alphabet():
    print("abcdefghijklmnopqrstuvwxyz")

print("Hello World")
show_alphabet()
` + "```" + `

Örnek 3 - React Native component:
Kullanıcı: "custom button komponenti yaz"
Sen:
` + "```javascript" + `
import React from 'react';
import { TouchableOpacity, Text, StyleSheet } from 'react-native';

export default function CustomButton({ title, onPress }) {
  return (
    <TouchableOpacity style={styles.button} onPress={onPress}>
      <Text style={styles.text}>{title}</Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    backgroundColor: '#007AFF',
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  text: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
});
` + "```" + `

ÖNEMLİ:
- Gereksiz açıklama yapma
- Sadece diff + kod bloğu yaz
- Context files'da dosya varsa mutlaka diff formatı kullan
- Dosya yoksa direkt kod bloğu yaz`

	if contextContent != "" {
		systemPrompt += "\n\nContext files:\n" + contextContent
	}

	// Ollama API'sinin beklediği JSON yapısı
	ollamaReqBody, _ := json.Marshal(map[string]interface{}{
		"model":  "llama3:8b",
		"system": systemPrompt,
		"prompt": req.Prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.7,
			"top_p":       0.9,
		},
	})

	// 'beyin-ollama' servisine HTTP isteği at
	resp, err := http.Post(OLLAMA_API_URL+"/api/generate", "application/json", bytes.NewBuffer(ollamaReqBody))
	if err != nil {
		log.Printf("Ollama bağlantı hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Beyin (Ollama) servisine bağlanılamadı."})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Yanıt okunamadı."})
		return
	}

	// Ollama'dan gelen yanıtı parse et
	var ollamaResp map[string]interface{}
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		log.Printf("❌ Ollama yanıtı parse hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Yanıt ayrıştırılamadı."})
		return
	}

	// Ollama'dan gelen 'response' alanını al
	botText, ok := ollamaResp["response"].(string)
	if !ok || botText == "" {
		// Hata durumunda error mesajını kontrol et
		if errMsg, hasError := ollamaResp["error"].(string); hasError {
			log.Printf("❌ Ollama hatası: %s", errMsg)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "AI yanıt üretemedi: " + errMsg})
		} else {
			log.Printf("❌ Ollama'dan geçersiz yanıt alındı")
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Beyin (Ollama) servisinden geçersiz yanıt alındı."})
		}
		return
	}

	// Kod bloğu varsa otomatik olarak dosyaya yaz
	code, language, hasCode := extractCodeBlock(botText)
	var fileCreatedMsg string

	if hasCode {
		log.Printf("📝 Kod bloğu algılandı: language=%s, length=%d", language, len(code))

		// Kullanıcı prompt'undan dosya adını çıkar
		fileName := extractFileName(req.Prompt, language)
		log.Printf("📂 Dosya adı: %s", fileName)

		// Context klasörünü belirle - yoksa "default" kullan
		targetDir := "default"
		if len(req.ContextFiles) > 0 {
			targetDir = filepath.Dir(req.ContextFiles[0])
			log.Printf("📁 Context klasörü: %s", targetDir)
		} else {
			log.Printf("⚠️ Context klasörü belirtilmemiş, 'default' klasörü kullanılıyor")
		}

		// Tam yolu oluştur (sadece gösterim için)
		var targetPath string
		if req.BasePath != "" {
			targetPath = filepath.Join(req.BasePath, targetDir, fileName)
		} else {
			targetPath = filepath.Join(targetDir, fileName)
		}

		// Dosyayı context klasörüne yaz
		if err := writeCodeToFile(req.ContextFiles, fileName, code, req.BasePath); err != nil {
			log.Printf("❌ Dosya yazma hatası (%s): %v", fileName, err)
			fileCreatedMsg = "\n\n⚠️ Dosya oluşturulamadı: " + err.Error()
		} else {
			log.Printf("✅ Dosya başarıyla oluşturuldu: %s", targetPath)
			fileCreatedMsg = "\n\n✅ Dosya oluşturuldu: " + targetPath
		}
	} else {
		log.Printf("ℹ️ Kod bloğu algılanmadı (botText length: %d)", len(botText))
	}

	// Mesaj tipini belirle
	messageType := detectMessageType(botText)

	// Bot mesajını veritabanına kaydet (dosya oluşturma mesajı eklenmiş halde)
	botMessage := Message{
		ChatID:    req.ChatID,
		Sender:    "bot",
		Text:      botText + fileCreatedMsg,
		Type:      messageType,
		CreatedAt: time.Now(),
	}
	if err := db.Create(&botMessage).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Bot mesajı kaydedilirken hata oluştu."})
		return
	}

	// Chat'in güncelleme zamanını ayarla
	db.Model(&chat).Update("updated_at", time.Now())

	// Yanıtı döndür
	c.JSON(http.StatusOK, MessageResponse{
		ID:        botMessage.ID,
		Sender:    botMessage.Sender,
		Type:      botMessage.Type,
		Text:      botMessage.Text,
		CreatedAt: botMessage.CreatedAt,
	})
}

// HandleHealthCheck: /health endpoint'i - Servis sağlık kontrolü
func HandleHealthCheck(c *gin.Context) {
	// Veritabanı bağlantısını kontrol et
	sqlDB, err := db.DB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "unhealthy",
			"database": "disconnected",
		})
		return
	}

	if err := sqlDB.Ping(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "unhealthy",
			"database": "ping failed",
		})
		return
	}

	// Ollama servisini kontrol et
	ollamaStatus := "unknown"
	resp, err := http.Get(OLLAMA_API_URL + "/api/tags")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			ollamaStatus = "connected"
		}
	} else {
		ollamaStatus = "disconnected"
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "healthy",
		"database": "connected",
		"ollama":   ollamaStatus,
		"version":  "1.0.0",
	})
}

// ----- 5. ANA FONKSİYON VE ROTALAR -----

func main() {
	// Loglama formatını ayarla
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Veritabanını başlat
	DatabaseInit()

	// Gin'i production modda çalıştır (daha az log)
	if os.Getenv("GIN_MODE") != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// CORS (Cross-Origin Resource Sharing) ayarı
	// React (localhost:8080) uygulamasının bu API ile konuşmasına izin ver
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:8080", "http://localhost:5173", "http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// --- Genel Rotalar ---
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "Backend API (Orkestratör) çalışıyor!",
			"version": "1.0.0",
			"service": "bitirme-projesi-backend-api",
		})
	})

	r.GET("/health", HandleHealthCheck)

	// --- Auth Rotaları (Herkese Açık) ---
	r.POST("/register", HandleRegister)
	r.POST("/login", HandleLogin)

	// --- API Rotaları (Korumalı) ---
	api := r.Group("/api")
	api.Use(AuthMiddleware()) // Bu gruptaki her şey JWT token gerektirir
	{
		// Kullanıcı bilgileri
		api.GET("/me", HandleGetMe)

		// Sohbet yönetimi
		api.POST("/chats", HandleCreateChat)
		api.GET("/chats", HandleGetChats)
		api.GET("/chats/:id", HandleGetChat)
		api.DELETE("/chats/:id", HandleDeleteChat)

		// Mesaj oluşturma (Ollama ile)
		api.POST("/generate", HandleGenerate)

		// Dosya Sistemi API'leri (Tools)
		tools := api.Group("/tools")
		{
			// Dosya sistemi operasyonları
			tools.POST("/fs/list", HandleFSList)     // Dizin listeleme
			tools.POST("/fs/read", HandleFSRead)     // Dosya okuma
			tools.POST("/fs/write", HandleFSWrite)   // Dosya yazma
			tools.POST("/fs/delete", HandleFSDelete) // Dosya silme
			tools.POST("/fs/move", HandleFSMove)     // Dosya taşıma/yeniden adlandırma
		}
	}

	// Sunucuyu başlat
	port := getEnv("PORT", "8000")
	log.Printf("Backend API sunucusu http://0.0.0.0:%s adresinde başlatılıyor...", port)
	log.Printf("Database: %s", DATABASE_URL)
	log.Printf("Ollama API: %s", OLLAMA_API_URL)
	log.Printf("Projects Path: %s", PROJECTS_PATH)

	if err := r.Run(":" + port); err != nil {
		log.Fatal("Sunucu başlatılamadı: ", err)
	}
}
