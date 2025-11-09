import React, { useState } from 'react';
// DİKKAT: Bu import yolunun (./css/Auth.module.css) dosya yapınızla
// eşleştiğinden emin olun.
import styles from './css/Auth.module.css';

function Login({ onLoginSuccess, onSwitchToRegister }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const fakeApiLogin = (email, password) => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (email.toLowerCase() === 'test@proje.com' && password === '1234') {
          resolve({ 
            email: 'test@proje.com', 
            name: 'Test Kullanıcısı',
            avatarChar: 'T' 
          });
        } else {
          reject(new Error('E-posta veya şifre hatalı.'));
        }
      }, 1500);
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email || !password) {
      setError('Lütfen tüm alanları doldurun');
      return;
    }
    setIsLoading(true); 

    try {
      const user = await fakeApiLogin(email, password);
      onLoginSuccess(user);
    } catch (apiError) {
      setError(apiError.message);
    } finally {
      setIsLoading(false);
    }
  };

  // -----------------------------------------------------------------
  // DÜZELTME BURADA BAŞLIYOR:
  // Tüm 'className' öznitelikleri 'styles' objesini kullanacak şekilde güncellendi.
  // -----------------------------------------------------------------
  return (
    <div className={styles.authBackground}>
      <div className={styles.authContainer}>
        {/* Birden fazla sınıfı birleştirmek için template literal (backtick) kullanılır */}
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