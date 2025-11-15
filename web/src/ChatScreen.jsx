// ChatScreen.jsx
import React, { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import DiffBlock from './DiffBlock';
import Modal from './Modal';
import SettingsModal from './SettingsModal';
import ContextPanel from './ContextPanel';
import CodeBlock from './CodeBlock';
import TutorialModal from './TutorialModal';

// CSS Modülleri
import chatStyles from './css/Chat.module.css';
import modalStyles from './css/Modal.module.css';

const TUTORIAL_STORAGE_KEY = 'hasSeenTutorial';

function ChatScreen({ currentUser = { name: 'Kullanıcı', email: '' }, onLogout = () => {} }) {
  // State'ler
  const [messageInput, setMessageInput] = useState("");
  const [isRecording, setIsRecording] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [currentChatId, setCurrentChatId] = useState(null);
  const [isThinking, setIsThinking] = useState(false);
  const [audioLevel, setAudioLevel] = useState(0);
  const [isLogoutModalOpen, setIsLogoutModalOpen] = useState(false);
  const [chatToDelete, setChatToDelete] = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isContextOpen, setIsContextOpen] = useState(false);
  const [contextFiles, setContextFiles] = useState(['main.py']);
  const [basePath, setBasePath] = useState('');
  const [showTutorial, setShowTutorial] = useState(false);

  const [allChats, setAllChats] = useState([]);

  const messagesEndRef = useRef(null);

  // Derived
  const currentChat = allChats.find(chat => chat.id === currentChatId);
  const chatMessages = currentChat ? currentChat.messages : [];

  // İlk yüklemede backend'den chat'leri çek
  useEffect(() => {
    const loadChats = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await fetch('http://localhost:8000/api/chats', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const data = await response.json();
          if (data.length > 0) {
            setAllChats(data.map(chat => ({
              ...chat,
              messages: [] // Mesajlar ayrıca yüklenecek
            })));
            setCurrentChatId(data[0].id);
          } else {
            // Hiç chat yoksa yeni oluştur (backend'e kaydet)
            const createResponse = await fetch('http://localhost:8000/api/chats', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
              },
              body: JSON.stringify({ title: "Yeni Sohbet" }),
            });

            if (createResponse.ok) {
              const newChat = await createResponse.json();
              setAllChats([{ ...newChat, messages: [] }]);
              setCurrentChatId(newChat.id);
            }
          }
        }
      } catch (error) {
        console.error('Chat yükleme hatası:', error);
      }
    };

    loadChats();

    // Tutorial kontrolü
    const hasSeenTutorial = localStorage.getItem(TUTORIAL_STORAGE_KEY);
    if (!hasSeenTutorial) {
      setShowTutorial(true);
    }
  }, []);

  // Scroll to bottom on messages change
  useEffect(() => {
    scrollToBottom();
  }, [chatMessages]);

  // Ses seviyesi simülasyonu (kayıt sırasında)
  useEffect(() => {
    let interval;
    if (isRecording) {
      interval = setInterval(() => {
        setAudioLevel(Math.random() * 100);
      }, 100);
    }
    return () => clearInterval(interval);
  }, [isRecording]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  // Sohbet yarat
  const createNewChat = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/api/chats', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          title: "Yeni Sohbet",
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Sohbet oluşturulamadı.');
      }

      // Backend'den gelen chat ID'sini kullan
      const newChat = {
        id: data.id,
        title: data.title,
        messages: [],
        timestamp: data.created_at || new Date().toISOString()
      };

      setAllChats(prev => [newChat, ...prev]);
      setCurrentChatId(data.id);

    } catch (error) {
      console.error('Chat oluşturma hatası:', error);
      // Hata durumunda lokal chat oluştur (fallback)
      const newChatId = (allChats.length > 0 ? Math.max(...allChats.map(c => c.id)) : 0) + 1;
      const newChat = {
        id: newChatId,
        title: "Yeni Sohbet (Lokal)",
        messages: [],
        timestamp: new Date().toISOString()
      };
      setAllChats(prev => [newChat, ...prev]);
      setCurrentChatId(newChatId);
    }
  };

  // Sohbet silme akışı
  const handleDeleteClick = (chatId, e) => {
    e.stopPropagation();
    setChatToDelete(chatId);
  };
  const confirmDeleteChat = () => {
    if (!chatToDelete) return;
    setAllChats(prev => {
      const updated = prev.filter(chat => chat.id !== chatToDelete);
      // Eğer aktif sohbet silindiyse ilk sohbeti aktif yap
      if (currentChatId === chatToDelete) {
        setCurrentChatId(updated.length > 0 ? updated[0].id : null);
      }
      return updated;
    });
    setChatToDelete(null);
  };
  const cancelDeleteChat = () => {
    setChatToDelete(null);
  };

  // Sohbet başlığını ilk kullanıcı mesajına göre güncelle
  const updateChatTitle = (chatId, firstMessage) => {
    setAllChats(prevChats =>
      prevChats.map(chat =>
        chat.id === chatId && chat.title === "Yeni Sohbet"
          ? { ...chat, title: firstMessage.slice(0, 30) + (firstMessage.length > 30 ? '...' : '') }
          : chat
      )
    );
  };

  // Suggestion tuşlarına basınca
  const handleSuggestionClick = (text) => {
    handleSendMessageWithText(text);
  };

  // Enter tuşu ile gönderme
  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Ses ile yazma simülasyonu
  const handleVoiceClick = () => {
    setIsRecording(prev => !prev);
    if (!isRecording) {
      // Simule edilmiş 3s kayıt
      setTimeout(() => {
        setIsRecording(false);
        const spokenText = "main.py dosyasını değiştir"; // Diff test cümlesi
        handleSendMessageWithText(spokenText);
      }, 3000);
    }
  };

  // Kullanıcı mesajını tüm chat yapısına ekle
  const addUserMessage = (text) => {
    setAllChats(prevChats =>
      prevChats.map(chat =>
        chat.id === currentChatId
          ? {
              ...chat,
              messages: [...chat.messages, { type: 'text', sender: 'user', text }],
              timestamp: new Date().toISOString()
            }
          : chat
      )
    );

    // Eğer chat başlığı hala "Yeni Sohbet" ise ilk mesajla başlığı güncelle
    const chat = allChats.find(c => c.id === currentChatId);
    if (chat && chat.messages.length === 0) {
      updateChatTitle(currentChatId, text);
    }
  };

  // ---------- sendMessageToBackend: Gerçek API ile bot cevabı ----------
  const sendMessageToBackend = async (text) => {
    setIsThinking(true);

    try {
      // Backend'e istek at
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/api/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          prompt: text,
          chat_id: currentChatId,
          context_files: contextFiles,
          base_path: basePath,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'AI yanıt veremedi.');
      }

      // Backend'den gelen cevabı mesaj olarak ekle
      const botResponse = {
        type: data.type || 'text',
        sender: 'bot',
        text: data.text,
        // Eğer diff ise:
        oldValue: data.old_value,
        newValue: data.new_value,
        title: data.file_path || 'Değişiklik Önerisi',
      };

      // Yeni mesajı mevcut chat'e ekle
      setAllChats(prevChats =>
        prevChats.map(chat =>
          chat.id === currentChatId
            ? { ...chat, messages: [...chat.messages, botResponse], timestamp: new Date().toISOString() }
            : chat
        )
      );

      setIsThinking(false);

    } catch (apiError) {
      console.error('AI Error:', apiError);

      // Hata mesajını kullanıcıya göster
      const errorResponse = {
        type: 'text',
        sender: 'bot',
        text: `❌ Hata: ${apiError.message}\n\nBackend servisi çalışıyor mu? (http://localhost:8000)`
      };

      setAllChats(prevChats =>
        prevChats.map(chat =>
          chat.id === currentChatId
            ? { ...chat, messages: [...chat.messages, errorResponse], timestamp: new Date().toISOString() }
            : chat
        )
      );

      setIsThinking(false);
    }
  };

  // handleSendMessage yardımcıları
  const handleSendMessageWithText = (text) => {
    if (!text || !text.trim()) return;
    // kullanıcı mesajını ekle
    setAllChats(prevChats =>
      prevChats.map(chat =>
        chat.id === currentChatId
          ? {
              ...chat,
              messages: [...chat.messages, { type: 'text', sender: 'user', text }],
              timestamp: new Date().toISOString()
            }
          : chat
      )
    );

    // Başlığı güncelle (ilk mesaj için)
    const chat = allChats.find(c => c.id === currentChatId);
    if (chat && chat.messages.length === 0) {
      updateChatTitle(currentChatId, text);
    }

    // Backend'e gönder
    sendMessageToBackend(text);
  };

  // Buton veya Enter ile gönderme
  const handleSendMessage = () => {
    if (!messageInput.trim()) return;
    handleSendMessageWithText(messageInput);
    setMessageInput("");
  };

  // Tarih formatlama
  const formatDate = (timestamp) => {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    if (days === 0) return 'Bugün';
    if (days === 1) return 'Dün';
    if (days < 7) return `${days} gün önce`;
    return date.toLocaleDateString('tr-TR');
  };

  // Logout akışı
  const handleLogoutClick = () => setIsLogoutModalOpen(true);
  const confirmLogout = () => {
    setIsLogoutModalOpen(false);
    onLogout();
  };
  const cancelLogout = () => setIsLogoutModalOpen(false);

  // Ayarlar kaydetme (placeholder)
  const handleSettingsSave = (settings) => {
    console.log('Ayarlar kaydedildi:', settings);
    setIsSettingsOpen(false);
  };

  // Bağlam dosyaları güncelleme
  const handleContextUpdate = (files, newBasePath) => {
    setContextFiles(files);
    if (newBasePath !== undefined) {
      setBasePath(newBasePath);
    }
    // Kullanıcıya bilgi mesajı
    const basePathMsg = newBasePath ? ` (Proje: ${newBasePath})` : '';
    handleSendMessageWithText(`(Bağlam güncellendi: ${files.join(', ')})${basePathMsg}`);
  };

  // Öğretici bitir
  const handleFinishTutorial = () => {
    setShowTutorial(false);
    localStorage.setItem(TUTORIAL_STORAGE_KEY, 'true');
  };

  // Markdown için code renderer
  const markdownComponents = {
    code({ node, inline, className, children, ...props }) {
      const match = /language-(\w+)/.exec(className || '');
      const codeString = String(children).replace(/\n$/, '');
      return !inline && match ? (
        <CodeBlock language={match[1]} codeString={codeString} />
      ) : (
        <code className={chatStyles.inlineCode} {...props}>
          {children}
        </code>
      );
    },
    p(props) {
      return <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{props.children}</p>;
    }
  };

  return (
    <>
      <div className={chatStyles.appBackground}>
        <div className={chatStyles.appWrapper}>

          {/* Sidebar */}
          <div className={`${chatStyles.sidebar} ${isSidebarOpen ? '' : chatStyles.closed}`}>
            <div className={chatStyles.sidebarHeader}>
              <h2 className={chatStyles.sidebarTitle}>Sohbetler</h2>
              <button
                className={chatStyles.sidebarToggle}
                onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                title={isSidebarOpen ? "Kapat" : "Aç"}
              >
                {isSidebarOpen ? '←' : '→'}
              </button>
            </div>

            <button className={chatStyles.newChatBtn} onClick={createNewChat}>
              <span className={chatStyles.newChatIcon}>+</span>
              <span>Yeni Sohbet</span>
            </button>

            <div className={chatStyles.chatList}>
              {allChats.length === 0 ? (
                <div className={chatStyles.emptyState}>
                  <span className={chatStyles.emptyIcon}>🗂️</span>
                  <p>Geçmiş sohbet yok</p>
                  <p className={chatStyles.emptySubtext}>Yeni bir sohbet başlatın.</p>
                </div>
              ) : (
                allChats.map(chat => (
                  <div
                    key={chat.id}
                    className={`${chatStyles.chatItem} ${chat.id === currentChatId ? chatStyles.active : ''}`}
                    onClick={() => setCurrentChatId(chat.id)}
                  >
                    <div className={chatStyles.chatItemContent}>
                      <div className={chatStyles.chatItemTitle}>{chat.title}</div>
                      <div className={chatStyles.chatItemDate}>{formatDate(chat.timestamp)}</div>
                    </div>
                    <button
                      className={chatStyles.deleteChatBtn}
                      onClick={(e) => handleDeleteClick(chat.id, e)}
                      title="Sil"
                      disabled={allChats.length <= 1}
                    >
                      🗑️
                    </button>
                  </div>
                ))
              )}
            </div>

            <div className={chatStyles.sidebarFooter}>
              <button className={chatStyles.userProfileButton} onClick={() => setIsSettingsOpen(true)}>
                <div className={chatStyles.userAvatar}>{currentUser?.avatarChar || (currentUser?.name?.charAt(0) || 'U').toUpperCase()}</div>
                <div className={chatStyles.userInfo}>
                  <div className={chatStyles.userName}>{currentUser?.name}</div>
                  <div className={chatStyles.userEmail}>{currentUser?.email}</div>
                </div>
              </button>
              <button
                className={chatStyles.logoutBtn}
                onClick={handleLogoutClick}
                title="Çıkış Yap"
              >
                🚪
              </button>
            </div>
          </div>

          {/* Chat container */}
          <div className={chatStyles.chatContainer}>
            <div className={chatStyles.chatHeader}>
              <div className={chatStyles.headerContent}>
                {!isSidebarOpen && (
                  <button
                    className={chatStyles.menuBtn}
                    onClick={() => setIsSidebarOpen(true)}
                    title="Menüyü Aç"
                  >
                    ☰
                  </button>
                )}
                <div className={chatStyles.botAvatar}>🤖</div>
                <div className={chatStyles.headerInfo}>
                  <h1 className={chatStyles.headerTitle}>Kodlama Asistanı</h1>
                  <p className={chatStyles.headerStatus}>
                    {isThinking ? '💭 Düşünüyor...' : isRecording ? '🎤 Dinliyor...' : `📁 ${contextFiles.length} dosya bağlamda`}
                  </p>
                </div>
                <button className={chatStyles.contextBtn} onClick={() => setIsContextOpen(true)}>
                  Bağlam ({contextFiles.length})
                </button>
              </div>
            </div>

            {/* Messages */}
            <div className={chatStyles.chatMessages}>
              {isRecording && (
                <div className={chatStyles.voiceIndicator}>
                  <div className={chatStyles.waveform}>
                    {[...Array(5)].map((_, i) => (
                      <span
                        key={i}
                        style={{
                          height: `${8 + (audioLevel / 100) * 16}px`,
                          animationDelay: `${i * 0.1}s`
                        }}
                      />
                    ))}
                  </div>
                  <p>🎤 Sizi dinliyorum...</p>
                </div>
              )}

              {/* Karşılama */}
              {currentChat && chatMessages.length === 0 && !isThinking && (
                <div className={chatStyles.welcomeMessage}>
                  <span className={chatStyles.welcomeIcon}>👋</span>
                  <h2>Merhaba, {currentUser?.name}!</h2>
                  <p>Size nasıl yardımcı olabilirim?</p>
                  <div className={chatStyles.suggestionChips}>
                    <button onClick={() => handleSuggestionClick("Bana bir Python 'class'ı yaz")}>Bana bir Python 'class'ı yaz</button>
                    <button onClick={() => handleSuggestionClick("main.py dosyasını değiştir")}>`main.py` dosyasını değiştir (Diff Testi)</button>
                    <button onClick={() => handleSuggestionClick("CSS flexbox nedir?")}>CSS flexbox nedir?</button>
                  </div>
                </div>
              )}

              {/* Liste */}
              {currentChat && chatMessages.map((message, index) => (
                <div key={index} className={`${chatStyles.messageWrapper} ${chatStyles[message.sender] || ''}`}>
                  <div className={`${chatStyles.message} ${chatStyles[message.sender] || ''}`}>
                    {message.sender === 'user' ? (
                      <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{message.text}</p>
                    ) : message.type === 'diff' ? (
                      <DiffBlock
                        oldValue={message.oldValue}
                        newValue={message.newValue}
                        title={message.title}
                      />
                    ) : message.type === 'code' ? (
                      <ReactMarkdown components={markdownComponents}>
                        {message.text}
                      </ReactMarkdown>
                    ) : (
                      <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{message.text}</p>
                    )}
                  </div>
                </div>
              ))}

              {isThinking && (
                <div className={`${chatStyles.messageWrapper} ${chatStyles.bot}`}>
                  <div className={`${chatStyles.message} ${chatStyles.bot} ${chatStyles.thinking}`}>
                    <div className={chatStyles.thinkingDots}>
                      <span></span><span></span><span></span>
                    </div>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Input area */}
            <div className={chatStyles.chatInputArea}>
              <div className={chatStyles.inputContainer}>
                <button
                  type="button"
                  onClick={handleVoiceClick}
                  className={`${chatStyles.voiceBtn} ${isRecording ? chatStyles.recording : ''}`}
                  title="Konuşmak için tıkla"
                  disabled={isThinking}
                >
                  <span>{isRecording ? '⏸️' : '🎤'}</span>
                </button>

                <input
                  type="text"
                  placeholder={isThinking ? "Düşünüyor..." : "Mesajınızı yazın..."}
                  autoComplete="off"
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  className={chatStyles.messageInput}
                  disabled={isThinking}
                />

                <button
                  type="button"
                  onClick={handleSendMessage}
                  className={chatStyles.sendBtn}
                  disabled={!messageInput.trim() || isThinking}
                >
                  Gönder
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Modallar */}
      {isLogoutModalOpen && (
        <Modal onClose={cancelLogout}>
          <h2>Çıkış Yap</h2>
          <p>Oturumu kapatmak istediğinizden emin misiniz?</p>
          <div className={modalStyles.modalButtons}>
            <button className={`${modalStyles.modalBtn} ${modalStyles.secondary}`} onClick={cancelLogout}>İptal</button>
            <button className={`${modalStyles.modalBtn} ${modalStyles.danger}`} onClick={confirmLogout}>Çıkış Yap</button>
          </div>
        </Modal>
      )}

      {chatToDelete && (
        <Modal onClose={cancelDeleteChat}>
          <h2>Sohbeti Sil</h2>
          <p>Bu sohbeti kalıcı olarak silmek istediğinizden emin misiniz?</p>
          <div className={modalStyles.modalButtons}>
            <button className={`${modalStyles.modalBtn} ${modalStyles.secondary}`} onClick={cancelDeleteChat}>İptal</button>
            <button className={`${modalStyles.modalBtn} ${modalStyles.danger}`} onClick={confirmDeleteChat}>Sil</button>
          </div>
        </Modal>
      )}

      {isSettingsOpen && (
        <SettingsModal
          currentUser={currentUser}
          onClose={() => setIsSettingsOpen(false)}
          onSave={handleSettingsSave}
        />
      )}

      {isContextOpen && (
        <ContextPanel
          contextFiles={contextFiles}
          basePath={basePath}
          onClose={() => setIsContextOpen(false)}
          onUpdateFiles={handleContextUpdate}
        />
      )}

      {showTutorial && (
        <TutorialModal onFinish={handleFinishTutorial} />
      )}
    </>
  );
}

export default ChatScreen;
