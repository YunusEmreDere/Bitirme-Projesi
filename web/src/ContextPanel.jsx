// src/ContextPanel.jsx
import React, { useState } from 'react';
import Modal from './Modal';
import contextStyles from './css/Context.module.css';
import modalStyles from './css/Modal.module.css';

function ContextPanel({ onClose, contextFiles, onUpdateFiles }) {
  const [files, setFiles] = useState(contextFiles);
  const [newFile, setNewFile] = useState('');

  const addFile = () => {
    if (newFile.trim() && !files.includes(newFile.trim())) {
      const updated = [...files, newFile.trim()];
      setFiles(updated);
      setNewFile('');
    }
  };

  const removeFile = (file) => {
    setFiles(files.filter(f => f !== file));
  };

  const handleSave = () => {
    onUpdateFiles(files);
    onClose();
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addFile();
    }
  };

  return (
    <Modal onClose={onClose}>
      <div className={contextStyles.contextPanel}>
        <div className={contextStyles.header}>
          <h2>📁 Bağlam Dosyaları</h2>
          <p className={contextStyles.description}>
            AI asistanının farkında olduğu proje dosyalarını yönetin
          </p>
        </div>

        <div className={contextStyles.addFileSection}>
          <input
            type="text"
            value={newFile}
            onChange={(e) => setNewFile(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="örn: main.py, utils.js, config.json"
            className={contextStyles.fileInput}
          />
          <button
            onClick={addFile}
            className={contextStyles.addBtn}
            disabled={!newFile.trim()}
          >
            + Ekle
          </button>
        </div>

        <div className={contextStyles.fileList}>
          {files.length === 0 ? (
            <div className={contextStyles.emptyState}>
              <span className={contextStyles.emptyIcon}>📂</span>
              <p>Henüz dosya eklenmedi</p>
              <p className={contextStyles.emptyHint}>
                Yukarıdaki alandan dosya ekleyerek başlayın
              </p>
            </div>
          ) : (
            <>
              {files.map((file, index) => (
                <div key={index} className={contextStyles.fileItem}>
                  <div className={contextStyles.fileInfo}>
                    <span className={contextStyles.fileIcon}>
                      {file.endsWith('.py') ? '🐍' : 
                       file.endsWith('.js') || file.endsWith('.jsx') ? '⚡' :
                       file.endsWith('.json') ? '📋' :
                       file.endsWith('.css') ? '🎨' :
                       file.endsWith('.html') ? '🌐' : '📄'}
                    </span>
                    <span className={contextStyles.fileName}>{file}</span>
                  </div>
                  <button
                    onClick={() => removeFile(file)}
                    className={contextStyles.removeBtn}
                    title="Dosyayı kaldır"
                  >
                    ✕
                  </button>
                </div>
              ))}
            </>
          )}
        </div>

        <div className={contextStyles.infoBox}>
          <span className={contextStyles.infoIcon}>💡</span>
          <p>
            Eklediğiniz dosyalar AI'nın çalışma bağlamını oluşturur. 
            AI bu dosyalar hakkında bilgi sahibi olacak ve kod önerilerini buna göre yapacaktır.
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
            {files.length > 0 ? `Kaydet (${files.length} dosya)` : 'Kaydet'}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export default ContextPanel;