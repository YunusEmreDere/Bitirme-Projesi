// src/Login.jsx
import React, { useState } from 'react';

function Login({ onLoginSuccess, onSwitchToRegister }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    if (!email || !password) {
      setError('Lütfen tüm alanları doldurun');
      return;
    }

    // Simulated login (replace with real API call)
    setTimeout(() => {
      const user = { 
        email, 
        name: email.split('@')[0] 
      };
      onLoginSuccess(user);
    }, 500);
  };

  return (
    <div className="auth-background">
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <div className="auth-logo">🤖</div>
            <h1 className="auth-title">Kodlama Asistanı</h1>
            <p className="auth-subtitle">Hesabınıza giriş yapın</p>
          </div>

          {error && (
            <div className="auth-error">{error}</div>
          )}

          <div className="auth-form">
            <div className="form-group">
              <label>E-posta</label>
              <input
                type="email"
                placeholder="ornek@email.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="auth-input"
              />
            </div>

            <div className="form-group">
              <label>Şifre</label>
              <input
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="auth-input"
              />
            </div>

            <button onClick={handleSubmit} className="auth-button">
              Giriş Yap
            </button>
          </div>

          <div className="auth-switch">
            <p>
              Hesabınız yok mu?{' '}
              <span className="auth-link" onClick={onSwitchToRegister}>
                Kayıt Ol
              </span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;