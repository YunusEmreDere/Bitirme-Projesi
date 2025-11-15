// src/Register.jsx
import React, { useState } from 'react';
import styles from './css/Auth.module.css';

function Register({ onRegisterSuccess, onSwitchToLogin }) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
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

    setIsLoading(true);

    try {
      // Backend'e kayıt isteği gönder
      const response = await fetch('http://localhost:8000/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: fullName,      // Backend'de "name" alanı bekleniyor
          email: email,        // Backend'de "email" alanı bekleniyor
          password: password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Kayıt yapılamadı.');
      }
      
      // Başarılı kayıt
      const user = {
        name: data.user_name || fullName,
        email: data.user_email || email,
        avatarChar: (data.user_name || fullName).charAt(0).toUpperCase()
      };
      
      // Token'ı kaydet
      localStorage.setItem('token', data.access_token);
      localStorage.setItem('user', JSON.stringify(user));

      onRegisterSuccess(user);

    } catch (apiError) {
      console.error('Register error:', apiError);
      if (apiError.message.includes('Failed to fetch')) {
        setError('Bağlantı hatası: Backend servisi çalışmıyor olabilir.');
      } else {
        setError(apiError.message);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={styles.authBackground}>
      <div className={styles.authContainer}>
        <div className={`${styles.authCard} ${styles.authCardSplit}`}>
          
          {/* LEFT PANEL - Coding Illustration */}
          <div className={styles.authLeftPanel}>
            <div className={styles.authLogo}>💻</div>
            <h1 className={styles.authTitle}>Geleceğin Kodlaması</h1>
            <p className={styles.authSubtitle}>
              Sesli komutlarla kod yazın, yapay zeka ile çalışın. Ücretsiz başlayın!
            </p>
            
            {/* Code Animation */}
            <div className={styles.codeAnimation}>
              <div className={styles.codeLine}>{'> function createApp() {'}</div>
              <div className={styles.codeLine}>{'    return "Merhaba Dünya";'}</div>
              <div className={styles.codeLine}>{'> }'}</div>
              <div className={styles.codeLine}>{'> // Harika! 🚀'}</div>
            </div>
          </div>

          {/* RIGHT PANEL - Register Form */}
          <div className={styles.authRightPanel}>
            <div className={styles.authHeaderRight}>
              <h2>Hesap Oluşturun</h2>
            </div>

            {error && (
              <div className={styles.authError}>{error}</div>
            )}

            <form className={styles.authForm} onSubmit={handleSubmit}>
              <div className={styles.formGroup}>
                <label>Ad Soyad</label>
                <input
                  type="text"
                  placeholder="John Doe"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className={styles.authInput}
                  disabled={isLoading}
                  autoComplete="name"
                />
              </div>

              <div className={styles.formGroup}>
                <label>E-posta</label>
                <input
                  type="email"
                  placeholder="ornek@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={styles.authInput}
                  disabled={isLoading}
                  autoComplete="email"
                />
              </div>

              <div className={styles.formGroup}>
                <label>Şifre</label>
                <input
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={styles.authInput}
                  disabled={isLoading}
                  autoComplete="new-password"
                />
              </div>

              <button 
                type="submit"
                className={styles.authButton}
                disabled={isLoading}
              >
                {isLoading ? 'Hesap Oluşturuluyor...' : 'Kayıt Ol'}
              </button>
            </form>

            <div className={styles.authSwitch}>
              <p>
                Zaten hesabınız var mı?{' '}
                <span 
                  className={styles.authLink} 
                  onClick={!isLoading ? onSwitchToLogin : null}
                >
                  Giriş Yap
                </span>
              </p>
            </div>
          </div>
          
        </div>
      </div>
    </div>
  );
}

export default Register;