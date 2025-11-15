import React, { useState, useRef } from 'react';
import Modal from './Modal';
// 'contextStyles' import'unuzun 'css' klasörü içinde olduğunu varsayıyorum
import contextStyles from './css/Context.module.css'; 
import modalStyles from './css/Modal.module.css';

function ContextPanel({ onClose, contextFiles, basePath, onUpdateFiles }) {
  const [files, setFiles] = useState(contextFiles);
  const [newFile, setNewFile] = useState('');
  const [projectBasePath, setProjectBasePath] = useState(basePath || '');

  // --- DEĞİŞİKLİK 1: İki ayrı 'ref' ---
  const folderInputRef = useRef(null); // Klasör seçici için
  const fileInputRef = useRef(null);   // Dosya seçici için

  const addFile = () => {
    if (newFile.trim() && !files.includes(newFile.trim())) {
      const updated = [...files, newFile.trim()];
      setFiles(updated);
      setNewFile('');
    }
  };

  // --- DEĞİŞİKLİK 2: Klasör seçme mantığı ---
  const handleFolderSelect = (e) => {
    const selectedFiles = Array.from(e.target.files);
    if (selectedFiles.length === 0) return;

    // Tüm dosyaların tam yollarını al (webkitRelativePath kullanarak)
    const filePaths = selectedFiles.map(file => file.webkitRelativePath);

    // Benzersiz dosya yollarını filtrele
    const uniquePaths = filePaths.filter(path => !files.includes(path));

    if (uniquePaths.length > 0) {
      setFiles([...files, ...uniquePaths]);
    }

    // Input'u sıfırla
    e.target.value = '';
  };

  // --- DEĞİŞİKLİK 3: (Eski) Dosya seçme mantığı ---
  const handleFileSelect = (e) => {
    const selectedFiles = Array.from(e.target.files);
    // Artık 'webkitRelativePath' değil, sadece dosya adını alıyoruz
    const fileNames = selectedFiles.map(file => file.name); 
    
    const newFiles = fileNames.filter(name => !files.includes(name));
    if (newFiles.length > 0) {
      setFiles([...files, ...newFiles]);
    }
    
    e.target.value = '';
  };


  const removeFile = (file) => {
    setFiles(files.filter(f => f !== file));
  };

  const handleSave = () => {
    onUpdateFiles(files, projectBasePath);
    onClose();
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addFile();
    }
  };

  return (
    // 'cardClassName' prop'unu Modal'a iletiyoruz
    <Modal onClose={onClose} cardClassName={modalStyles.modalCardLarge}>
      <div className={contextStyles.contextPanel}>
        <div className={contextStyles.header}>
          <h2>📁 Bağlam Dosyaları</h2>
          <p className={contextStyles.description}>
            AI asistanının farkında olduğu proje dosyalarını yönetin
          </p>
        </div>

        <div className={contextStyles.addFileSection}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: '600', color: '#333' }}>
            🗂️ Proje Kök Dizini (Tam Yol):
          </label>
          <input
            type="text"
            value={projectBasePath}
            onChange={(e) => setProjectBasePath(e.target.value)}
            placeholder="örn: /home/kullanici/projelerim/proje-adi"
            className={contextStyles.fileInput}
            style={{ marginBottom: '16px' }}
          />
        </div>

        <div className={contextStyles.addFileSection}>
          <input
            type="text"
            value={newFile}
            onChange={(e) => setNewFile(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="örn: src/main.py (manuel yol)"
            className={contextStyles.fileInput}
          />
          <button
            onClick={addFile}
            className={contextStyles.addBtn}
            disabled={!newFile.trim()}
          >
            ✍️ Ekle
          </button>
        </div>

        <div className={contextStyles.orDivider}>
          <span>veya</span>
        </div>

        {/* --- DEĞİŞİKLİK 4: İki ayrı gizli input --- */}
        {/* Klasör Seçici */}
        <input
          ref={folderInputRef}
          type="file"
          multiple
          webkitdirectory=""
          mozdirectory=""
          style={{ display: 'none' }}
          onChange={handleFolderSelect}
        />
        {/* Dosya Seçici */}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={handleFileSelect}
          style={{ display: 'none' }}
          accept=".py,.js,.jsx,.ts,.tsx,.json,.css,.html,.txt,.md,.java,.cpp,.c,.h"
        />
        
        {/* --- DEĞİŞİKLİK 5: İki ayrı buton --- */}
        <div className={contextStyles.buttonGroup}>
          <button
            onClick={() => folderInputRef.current?.click()}
            className={contextStyles.selectFileBtn}
          >
            📁 Klasör Seç
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            className={contextStyles.selectFileBtn}
          >
            📄 Dosya Seç
          </button>
        </div>

        <div className={contextStyles.fileList}>
          {files.length === 0 ? (
            <div className={contextStyles.emptyState}>
              <span className={contextStyles.emptyIcon}>📂</span>
              <p>Henüz dosya eklenmedi</p>
              <p className={contextStyles.emptyHint}>
                Yukarıdan dosya veya klasör seçin
              </p>
            </div>
          ) : (
            <>
              {files.map((item, index) => {
                const getIcon = (fileName) => {
                  if (fileName.endsWith('.py')) return '🐍';
                  if (fileName.endsWith('.js') || fileName.endsWith('.jsx')) return '⚡';
                  if (fileName.endsWith('.ts') || fileName.endsWith('.tsx')) return '💙';
                  if (fileName.endsWith('.json')) return '📋';
                  if (fileName.endsWith('.css')) return '🎨';
                  if (fileName.endsWith('.html')) return '🌐';
                  if (fileName.endsWith('.md')) return '📝';
                  if (fileName.endsWith('.java')) return '☕';
                  if (fileName.endsWith('.cpp') || fileName.endsWith('.c')) return '⚙️';
                  return '📄';
                };

                return (
                  <div key={index} className={contextStyles.fileItem}>
                    <div className={contextStyles.fileInfo}>
                      <span className={contextStyles.fileIcon}>
                        {getIcon(item)}
                      </span>
                      <span className={contextStyles.fileName}>{item}</span>
                    </div>
                    <button
                      onClick={() => removeFile(item)}
                      className={contextStyles.removeBtn}
                      title="Kaldır"
                    >
                      ✕
                    </button>
                  </div>
                );
              })}
            </>
          )}
        </div>

        <div className={contextStyles.infoBox}>
          <span className={contextStyles.infoIcon}>💡</span>
          <p>
            Proje kök dizini: Dosyaların oluşturulacağı ana klasör. Klasör/dosya seçtiğinizde, yeni dosyalar bu dizin altında oluşturulur.
          </p>
        </div>

        <div className={modalStyles.modalButtons}>
          <button 
            className={`${modalStyles.modalBtn} ${modalStyles.secondary}`}
            onClick={onClose}
          >
            İptal
          </button>
          <button 
            className={`${modalStyles.modalBtn} ${modalStyles.primary}`}
            onClick={handleSave}
          >
            {files.length > 0 ? `Kaydet (${files.length} bağlam)` : 'Kaydet'}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export default ContextPanel;