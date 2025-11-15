import React, { useState } from 'react';
import styles from './css/Auth.module.css';

function Login({ onLoginSuccess, onSwitchToRegister }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email || !password) {
      setError('Lütfen tüm alanları doldurun');
      return;
    }

    setIsLoading(true);

    try {
      // Backend'e JSON gönder (yukarıdaki backend değişikliği ile uyumlu)
      const response = await fetch('http://localhost:8000/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: email,  // veya email: email
          password: password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Giriş yapılamadı.');
      }
      
      // Başarılı giriş
      const user = {
        name: data.user_name,
        email: data.user_email || email,
        avatarChar: (data.user_name || 'U').charAt(0).toUpperCase()
      };
      
      // Token'ı kaydet
      localStorage.setItem('token', data.access_token);
      localStorage.setItem('user', JSON.stringify(user));

      onLoginSuccess(user);

    } catch (apiError) {
      console.error('Login error:', apiError);
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
          
          {/* LEFT PANEL */}
          <div className={styles.authLeftPanel}>
            <div className={styles.authLogo}>🤖</div>
            <h1 className={styles.authTitle}>Eller Serbest Kodlama</h1>
            <p className={styles.authSubtitle}>
              Yapay zeka asistanınızla konuşarak kod yazın. Sesli komutlarla projenizi kontrol edin.
            </p>
            <div className={styles.codeAnimation}>
              <div className={styles.codeLine}>{'> const app = new AI();'}</div>
              <div className={styles.codeLine}>{'> app.listen("voice");'}</div>
              <div className={styles.codeLine}>{'> // Kod yazıyorum... ✨'}</div>
              <div className={styles.codeLine}>{'> console.log("Hazır!");'}</div>
            </div>
          </div>

          {/* RIGHT PANEL - Form */}
          <div className={styles.authRightPanel}>
            <div className={styles.authHeaderRight}>
              <h2>Hoş Geldiniz</h2>
            </div>

            {error && (
              <div className={styles.authError}>{error}</div>
            )}

            <form className={styles.authForm} onSubmit={handleSubmit}>
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
                  autoComplete="current-password"
                />
              </div>

              <button 
                type="submit"
                className={styles.authButton}
                disabled={isLoading}
              >
                {isLoading ? 'Giriş Yapılıyor...' : 'Giriş Yap'}
              </button>
            </form>

            <div className={styles.authSwitch}>
              <p>
                Hesabınız yok mu?{' '}
                <span 
                  className={styles.authLink} 
                  onClick={!isLoading ? onSwitchToRegister : null}
                >
                  Kayıt Ol
                </span>
              </p>
            </div>
          </div>
          
        </div>
      </div>
    </div>
  );
}

export default Login;