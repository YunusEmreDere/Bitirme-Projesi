// src/SettingsModal.jsx
import React, { useState } from 'react';
import Modal from './Modal';
import settingsStyles from './css/Settings.module.css';
import modalStyles from './css/Modal.module.css';

function SettingsModal({ currentUser, onClose, onSave }) {
  const [activeTab, setActiveTab] = useState('profile');
  const [settings, setSettings] = useState({
    name: currentUser?.name || '',
    email: currentUser?.email || '',
    model: 'codellama',
    theme: 'dark'
  });

  const handleSave = () => {
    onSave(settings);
    onClose();
  };

  return (
    <Modal onClose={onClose}>
      <div className={settingsStyles.settingsModal}>
        <h2>⚙️ Ayarlar</h2>
        
        <div className={settingsStyles.tabs}>
          <button
            className={`${settingsStyles.tab} ${activeTab === 'profile' ? settingsStyles.active : ''}`}
            onClick={() => setActiveTab('profile')}
          >
            👤 Profil
          </button>
          <button
            className={`${settingsStyles.tab} ${activeTab === 'ai' ? settingsStyles.active : ''}`}
            onClick={() => setActiveTab('ai')}
          >
            🤖 AI
          </button>
          <button
            className={`${settingsStyles.tab} ${activeTab === 'appearance' ? settingsStyles.active : ''}`}
            onClick={() => setActiveTab('appearance')}
          >
            🎨 Görünüm
          </button>
        </div>

        <div className={settingsStyles.tabContent}>
          {activeTab === 'profile' && (
            <div>
              <div className={settingsStyles.profileInfo}>
                <p><strong>Kullanıcı ID:</strong> {currentUser?.id || 'N/A'}</p>
                <p><strong>Kayıt Tarihi:</strong> {new Date().toLocaleDateString('tr-TR')}</p>
              </div>

              <div className={settingsStyles.formGroup}>
                <label>İsim</label>
                <input
                  type="text"
                  className={settingsStyles.input}
                  value={settings.name}
                  onChange={(e) => setSettings({ ...settings, name: e.target.value })}
                  placeholder="Adınızı girin"
                />
              </div>

              <div className={settingsStyles.formGroup}>
                <label>E-posta</label>
                <input
                  type="email"
                  className={settingsStyles.input}
                  value={settings.email}
                  onChange={(e) => setSettings({ ...settings, email: e.target.value })}
                  placeholder="E-posta adresiniz"
                />
              </div>
            </div>
          )}

          {activeTab === 'ai' && (
            <div>
              <div className={settingsStyles.formGroup}>
                <label>AI Model</label>
                <select
                  className={settingsStyles.select}
                  value={settings.model}
                  onChange={(e) => setSettings({ ...settings, model: e.target.value })}
                >
                  <option value="codellama">CodeLlama (Varsayılan)</option>
                  <option value="deepseek">DeepSeek Coder</option>
                  <option value="mistral">Mistral</option>
                  <option value="llama2">Llama 2</option>
                </select>
                <p className={settingsStyles.hint}>
                  <strong>CodeLlama:</strong> Python, JavaScript ve genel kodlama için optimize edilmiş
                </p>
              </div>

              <div className={settingsStyles.formGroup}>
                <label>Yanıt Hızı</label>
                <select className={settingsStyles.select}>
                  <option value="balanced">Dengeli (Önerilen)</option>
                  <option value="fast">Hızlı</option>
                  <option value="detailed">Detaylı</option>
                </select>
              </div>
            </div>
          )}

          {activeTab === 'appearance' && (
            <div>
              <div className={settingsStyles.formGroup}>
                <label>Tema</label>
                <select
                  className={settingsStyles.select}
                  value={settings.theme}
                  onChange={(e) => setSettings({ ...settings, theme: e.target.value })}
                >
                  <option value="dark">Koyu Tema</option>
                  <option value="light">Açık Tema</option>
                  <option value="auto">Otomatik (Sistem)</option>
                </select>
              </div>

              <div className={settingsStyles.formGroup}>
                <label>Kod Teması</label>
                <select className={settingsStyles.select}>
                  <option value="vscode">VS Code Dark</option>
                  <option value="github">GitHub</option>
                  <option value="dracula">Dracula</option>
                </select>
              </div>
            </div>
          )}
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
            Kaydet
          </button>
        </div>
      </div>
    </Modal>
  );
}

export default SettingsModal;