// src/ChatScreen.jsx
import React, { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import Modal from './Modal';
import SettingsModal from './SettingsModal';
import ContextPanel from './ContextPanel';
import CodeBlock from './CodeBlock';
import chatStyles from './css/Chat.module.css';
import modalStyles from './css/Modal.module.css';

function ChatScreen({ currentUser, onLogout }) {
  const [messageInput, setMessageInput] = useState("");
  const [isRecording, setIsRecording] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [currentChatId, setCurrentChatId] = useState(1);
  const [isThinking, setIsThinking] = useState(false);
  const [audioLevel, setAudioLevel] = useState(0);
  
  const [isLogoutModalOpen, setIsLogoutModalOpen] = useState(false);
  const [chatToDelete, setChatToDelete] = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isContextOpen, setIsContextOpen] = useState(false);
  const [contextFiles, setContextFiles] = useState(['main.py', 'utils.py']);

  const [allChats, setAllChats] = useState([
    {
      id: 1,
      title: "Yeni Sohbet",
      messages: [
        { sender: 'bot', text: `Merhaba! Ben sizin kodlama asistanınızım. Size nasıl yardımcı olabilirim?\n\nŞu anda şu dosyaları görüyorum: \`${['main.py', 'utils.py'].join('`, `')}\`` }
      ],
      timestamp: new Date().toISOString()
    }
  ]);

  const messagesEndRef = useRef(null);
  const currentChat = allChats.find(chat => chat.id === currentChatId);
  const chatMessages = currentChat ? currentChat.messages : [];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [chatMessages]);

  // Simulate audio recording with visual feedback
  useEffect(() => {
    let interval;
    if (isRecording) {
      interval = setInterval(() => {
        setAudioLevel(Math.random() * 100);
      }, 100);
    }
    return () => clearInterval(interval);
  }, [isRecording]);

  const createNewChat = () => {
    const newChatId = (allChats.length > 0 ? Math.max(...allChats.map(c => c.id)) : 0) + 1;
    const newChat = {
      id: newChatId,
      title: "Yeni Sohbet",
      messages: [
        { sender: 'bot', text: 'Merhaba! Size nasıl yardımcı olabilirim?' }
      ],
      timestamp: new Date().toISOString()
    };
    
    setAllChats([newChat, ...allChats]);
    setCurrentChatId(newChatId);
  };

  const handleDeleteClick = (chatId, e) => {
    e.stopPropagation();
    setChatToDelete(chatId);
  };

  const confirmDeleteChat = () => {
    if (!chatToDelete) return;

    const updatedChats = allChats.filter(chat => chat.id !== chatToDelete);
    setAllChats(updatedChats);
    
    if (currentChatId === chatToDelete) {
      setCurrentChatId(updatedChats.length > 0 ? updatedChats[0].id : null);
    }

    setChatToDelete(null);
  };
  
  const cancelDeleteChat = () => {
    setChatToDelete(null);
  };

  const updateChatTitle = (chatId, firstMessage) => {
    setAllChats(prevChats => 
      prevChats.map(chat => 
        chat.id === chatId && chat.title === "Yeni Sohbet"
          ? { ...chat, title: firstMessage.slice(0, 30) + (firstMessage.length > 30 ? '...' : '') }
          : chat
      )
    );
  };

  const handleSendMessage = () => {
    const messageText = messageInput.trim();
    if (messageText === "" || isThinking) return;

    addUserMessage(messageText);
    setMessageInput("");
    sendMessageToBackend(messageText);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleVoiceClick = () => {
    setIsRecording(!isRecording);
    
    if (!isRecording) {
      setTimeout(() => {
        setIsRecording(false);
        const spokenText = "Ses ile gelen örnek metin: Python kodunu açıkla";
        addUserMessage(spokenText);
        sendMessageToBackend(spokenText);
      }, 3000);
    }
  };

  const addUserMessage = (text) => {
    setAllChats(prevChats => 
      prevChats.map(chat => 
        chat.id === currentChatId
          ? { 
              ...chat, 
              messages: [...chat.messages, { sender: 'user', text: text }],
              timestamp: new Date().toISOString()
            }
          : chat
      )
    );

    const chat = allChats.find(c => c.id === currentChatId);
    if (chat && chat.messages.length === 1) {
      updateChatTitle(currentChatId, text);
    }
  };

  const sendMessageToBackend = (text) => {
    setIsThinking(true);
    
    setTimeout(() => {
      const botResponse = `Anladım! "${text}" için bir kod örneği:

\`\`\`python
def example_function():
    # ${text} implementasyonu
    print("Merhaba Dünya!")
    return True
\`\`\`

Bu kod, **${contextFiles[0]}** dosyasına eklenebilir. Başka bir yardım ister misiniz?`;
      
      setAllChats(prevChats => 
        prevChats.map(chat => 
          chat.id === currentChatId
            ? { 
                ...chat, 
                messages: [...chat.messages, { sender: 'bot', text: botResponse }]
              }
            : chat
        )
      );
      setIsThinking(false);
    }, 2000);
  };

  const formatDate = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    
    if (days === 0) return 'Bugün';
    if (days === 1) return 'Dün';
    if (days < 7) return `${days} gün önce`;
    return date.toLocaleDateString('tr-TR');
  };
  
  const handleLogoutClick = () => {
    setIsLogoutModalOpen(true);
  };

  const confirmLogout = () => {
    onLogout();
  };
  
  const cancelLogout = () => {
    setIsLogoutModalOpen(false);
  };

  const handleSettingsSave = (settings) => {
    console.log('Settings saved:', settings);
  };

  const handleContextUpdate = (files) => {
    setContextFiles(files);
    setAllChats(prevChats => 
      prevChats.map(chat => 
        chat.id === currentChatId
          ? { 
              ...chat, 
              messages: [...chat.messages, {
                sender: 'bot',
                text: `✅ Bağlam güncellendi! Şimdi şu dosyaları görüyorum: \`${files.join('`, `')}\``
              }]
            }
          : chat
      )
    );
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
              {allChats.map(chat => (
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
              ))}
            </div>

            {/* User Profile */}
            <div className={chatStyles.sidebarFooter}>
              <button 
                className={chatStyles.userProfileButton}
                onClick={() => setIsSettingsOpen(true)}
              > 
                <div className={chatStyles.userAvatar}>{currentUser?.name?.charAt(0).toUpperCase()}</div>
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

          {/* Main Chat Area */}
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
                    {isThinking ? '💭 Düşünüyor...' : isRecording ? '🎤 Dinliyor...' : `📁 ${contextFiles.length} dosya`}
                  </p>
                </div>
              </div>
              <button 
                className={chatStyles.contextBtn}
                onClick={() => setIsContextOpen(true)}
              >
                📁 Bağlam ({contextFiles.length})
              </button>
            </div>

            <div className={chatStyles.chatMessages}>
              {/* Voice Recording Indicator */}
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

              {currentChat && currentChat.messages.map((message, index) => (
                <div key={index} className={`${chatStyles.messageWrapper} ${chatStyles[message.sender]}`}>
                  <div className={`${chatStyles.message} ${chatStyles[message.sender]}`}>
                    {message.sender === 'bot' ? (
                      <ReactMarkdown
                        components={{
                          code({ node, inline, className, children, ...props }) {
                            const match = /language-(\w+)/.exec(className || '');
                            return !inline && match ? (
                              <CodeBlock language={match[1]} value={String(children).replace(/\n$/, '')} />
                            ) : (
                              <code className={chatStyles.inlineCode} {...props}>
                                {children}
                              </code>
                            );
                          }
                        }}
                      >
                        {message.text}
                      </ReactMarkdown>
                    ) : (
                      <p>{message.text}</p>
                    )}
                  </div>
                </div>
              ))}

              {isThinking && (
                <div className={`${chatStyles.messageWrapper} ${chatStyles.bot}`}>
                  <div className={`${chatStyles.message} ${chatStyles.bot} ${chatStyles.thinking}`}>
                    <div className={chatStyles.thinkingDots}>
                      <span></span>
                      <span></span>
                      <span></span>
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

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

      {/* Modals */}
      {isLogoutModalOpen && (
        <Modal onClose={cancelLogout}>
          <div className={modalStyles.modalIcon + ' ' + modalStyles.warning}>⚠️</div>
          <h2>Çıkış Yap</h2>
          <p>Oturumu kapatmak istediğinizden emin misiniz?</p>
          <div className={modalStyles.modalButtons}>
            <button 
              className={`${modalStyles.modalBtn} ${modalStyles.secondary}`}
              onClick={cancelLogout}
            >
              İptal
            </button>
            <button 
              className={`${modalStyles.modalBtn} ${modalStyles.danger}`}
              onClick={confirmLogout}
            >
              Çıkış Yap
            </button>
          </div>
        </Modal>
      )}

      {chatToDelete && (
        <Modal onClose={cancelDeleteChat}>
          <div className={modalStyles.modalIcon + ' ' + modalStyles.danger}>🗑️</div>
          <h2>Sohbeti Sil</h2>
          <p>Bu sohbeti kalıcı olarak silmek istediğinizden emin misiniz?</p>
          <div className={modalStyles.modalButtons}>
            <button 
              className={`${modalStyles.modalBtn} ${modalStyles.secondary}`}
              onClick={cancelDeleteChat}
            >
              İptal
            </button>
            <button 
              className={`${modalStyles.modalBtn} ${modalStyles.danger}`}
              onClick={confirmDeleteChat}
            >
              Sil
            </button>
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
          onClose={() => setIsContextOpen(false)}
          onUpdateFiles={handleContextUpdate}
        />
      )}
    </>
  );
}

export default ChatScreen;