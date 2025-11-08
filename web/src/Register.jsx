// src/Register.jsx
import React, { useState } from 'react';

function Register({ onRegisterSuccess, onSwitchToLogin }) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    if (!fullName || !email || !password) {
      setError('Lütfen tüm alanları doldurun');
      return;
    }

    if (password.length < 6) {
      setError('Şifre en az 6 karakter olmalıdır');
      return;
    }

    // Simulated registration (replace with real API call)
    setTimeout(() => {
      const user = { 
        email, 
        name: fullName 
      };
      onRegisterSuccess(user);
    }, 500);
  };

  return (
    <div className="auth-background">
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <div className="auth-logo">🤖</div>
            <h1 className="auth-title">Kodlama Asistanı</h1>
            <p className="auth-subtitle">Yeni hesap oluşturun</p>
          </div>

          {error && (
            <div className="auth-error">{error}</div>
          )}

          <div className="auth-form">
            <div className="form-group">
              <label>Ad Soyad</label>
              <input
                type="text"
                placeholder="John Doe"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="auth-input"
              />
            </div>

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
              Kayıt Ol
            </button>
          </div>

          <div className="auth-switch">
            <p>
              Zaten hesabınız var mı?{' '}
              <span className="auth-link" onClick={onSwitchToLogin}>
                Giriş Yap
              </span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Register;