// src/App.jsx
import React, { useState } from 'react';
import './index.css';
import Login from './Login';
import Register from './Register';
import ChatScreen from './ChatScreen';

function App() {
  const [currentScreen, setCurrentScreen] = useState('login'); // 'login', 'register', 'chat'
  const [currentUser, setCurrentUser] = useState(null);

  const handleLoginSuccess = (user) => {
    setCurrentUser(user);
    setCurrentScreen('chat');
  };

  const handleRegisterSuccess = (user) => {
    setCurrentUser(user);
    setCurrentScreen('chat');
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setCurrentScreen('login');
  };

  const switchToRegister = () => {
    setCurrentScreen('register');
  };

  const switchToLogin = () => {
    setCurrentScreen('login');
  };

  return (
    <>
      {currentScreen === 'login' && (
        <Login 
          onLoginSuccess={handleLoginSuccess}
          onSwitchToRegister={switchToRegister}
        />
      )}

      {currentScreen === 'register' && (
        <Register 
          onRegisterSuccess={handleRegisterSuccess}
          onSwitchToLogin={switchToLogin}
        />
      )}

      {currentScreen === 'chat' && (
        <ChatScreen 
          currentUser={currentUser}
          onLogout={handleLogout}
        />
      )}
    </>
  );
}

export default App;