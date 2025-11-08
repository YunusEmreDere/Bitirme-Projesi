// src/ChatScreen.jsx
import React, { useState, useRef, useEffect } from 'react';

function ChatScreen({ currentUser, onLogout }) {
  const [messageInput, setMessageInput] = useState("");
  const [isRecording, setIsRecording] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [currentChatId, setCurrentChatId] = useState(1);
  
  const [allChats, setAllChats] = useState([
    {
      id: 1,
      title: "Yeni Sohbet",
      messages: [
        { sender: 'bot', text: 'Merhaba! Ben sizin kodlama asistanınızım. Size nasıl yardımcı olabilirim?' }
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

  const createNewChat = () => {
    const newChatId = Math.max(...allChats.map(c => c.id)) + 1;
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

  const deleteChat = (chatId, e) => {
    e.stopPropagation();
    if (allChats.length === 1) {
      alert("Son sohbeti silemezsiniz!");
      return;
    }
    
    const updatedChats = allChats.filter(chat => chat.id !== chatId);
    setAllChats(updatedChats);
    
    if (currentChatId === chatId) {
      setCurrentChatId(updatedChats[0].id);
    }
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
    if (messageText === "") return;

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
    
    setTimeout(() => {
      setIsRecording(false);
      const spokenText = "Konuşma ile gelen sahte metin.";
      addUserMessage(spokenText);
      sendMessageToBackend(spokenText);
    }, 2000);
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
    setTimeout(() => {
      const botResponse = `"${text}" komutunuzu aldım. İşlem yapılıyor...`;
      
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
    }, 1000);
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

  return (
    <div className="app-background">
      <div className="app-wrapper">
        {/* Sidebar */}
        <div className={`sidebar ${isSidebarOpen ? 'open' : 'closed'}`}>
          <div className="sidebar-header">
            <h2 className="sidebar-title">Sohbetler</h2>
            <button 
              className="sidebar-toggle"
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              title={isSidebarOpen ? "Kapat" : "Aç"}
            >
              {isSidebarOpen ? '←' : '→'}
            </button>
          </div>

          <button className="new-chat-btn" onClick={createNewChat}>
            <span className="new-chat-icon">+</span>
            <span>Yeni Sohbet</span>
          </button>

          <div className="chat-list">
            {allChats.map(chat => (
              <div 
                key={chat.id}
                className={`chat-item ${chat.id === currentChatId ? 'active' : ''}`}
                onClick={() => setCurrentChatId(chat.id)}
              >
                <div className="chat-item-content">
                  <div className="chat-item-title">{chat.title}</div>
                  <div className="chat-item-date">{formatDate(chat.timestamp)}</div>
                </div>
                <button 
                  className="delete-chat-btn"
                  onClick={(e) => deleteChat(chat.id, e)}
                  title="Sil"
                >
                  🗑️
                </button>
              </div>
            ))}
          </div>

          {/* User Profile */}
          <div className="sidebar-footer">
            <div className="user-profile">
              <div className="user-avatar">{currentUser?.name?.charAt(0).toUpperCase()}</div>
              <div className="user-info">
                <div className="user-name">{currentUser?.name}</div>
                <div className="user-email">{currentUser?.email}</div>
              </div>
            </div>
            <button className="logout-btn" onClick={onLogout} title="Çıkış Yap">
              🚪
            </button>
          </div>
        </div>

        {/* Main Chat Area */}
        <div className="chat-container">
          <div className="chat-header">
            <div className="header-content">
              {!isSidebarOpen && (
                <button 
                  className="menu-btn"
                  onClick={() => setIsSidebarOpen(true)}
                  title="Menüyü Aç"
                >
                  ☰
                </button>
              )}
              <div className="bot-avatar">🤖</div>
              <div className="header-info">
                <h1 className="header-title">Kodlama Asistanı</h1>
                <p className="header-status">Çevrimiçi</p>
              </div>
            </div>
          </div>

          <div className="chat-messages">
            {chatMessages.map((message, index) => (
              <div key={index} className={`message-wrapper ${message.sender}`}>
                <div className={`message ${message.sender}`}>
                  <p>{message.text}</p>
                </div>
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>

          <div className="chat-input-area">
            <div className="input-container">
              <button 
                type="button" 
                onClick={handleVoiceClick}
                className={`voice-btn ${isRecording ? 'recording' : ''}`}
                title="Konuşmak için tıkla"
              >
                <span>{isRecording ? '⏸️' : '🎤'}</span>
              </button>
              
              <input 
                type="text" 
                placeholder="Mesajınızı yazın..." 
                autoComplete="off"
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                onKeyPress={handleKeyPress}
                className="message-input"
              />
              
              <button 
                type="button"
                onClick={handleSendMessage}
                className="send-btn"
                disabled={!messageInput.trim()}
              >
                Gönder
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ChatScreen;