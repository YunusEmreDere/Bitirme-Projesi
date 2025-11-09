import React, { useState } from 'react';
import styles from './css/Auth.module.css';

function Register({ onRegisterSuccess, onSwitchToLogin }) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  
  // --- YENİ EKLENEN PROFESYONEL STATE'LER ---
  const [isLoading, setIsLoading] = useState(false);
  // --- BİTTİ ---

  // Sahte API çağrısını async/await ile simüle edelim
  const fakeApiRegister = (name, email, password) => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        // Gerçekte burada backend'e istek atılır
        // Şimdilik her kaydı başarılı kabul edelim
        const user = { 
          email: email, 
          name: name,
          avatarChar: name.charAt(0).toUpperCase()
        };
        resolve(user);
      }, 1000); // 1 saniye gecikme
    });
  };
  
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

    setIsLoading(true); // Yüklemeyi başlat

    try {
      const user = await fakeApiRegister(fullName, email, password);
      onRegisterSuccess(user); // Başarılı kayıt sonrası App.jsx'e haber ver
    } catch (apiError) {
      setError(apiError.message || 'Kayıt sırasında bir hata oluştu.');
    } finally {
      setIsLoading(false); // Yüklemeyi bitir
    }
  };

  return (
    // 'className' özniteliklerini 'styles' objesiyle güncelliyoruz
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
                  disabled={isLoading} // 'isLoading' state'i eklendi
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
                  disabled={isLoading} // 'isLoading' state'i eklendi
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
                  disabled={isLoading} // 'isLoading' state'i eklendi
                />
              </div>

              <button 
                type="submit" // 'onClick' yerine form submit'i kullanılıyor
                className={styles.authButton} 
                disabled={isLoading} // 'isLoading' state'i eklendi
              >
                {/* Buton metni 'isLoading' state'ine göre değişiyor */}
                {isLoading ? 'Hesap Oluşturuluyor...' : 'Kayıt Ol'}
              </button>
            </form>

            <div className={styles.authSwitch}>
              <p>
                Zaten hesabınız var mı?{' '}
                <span 
                  className={styles.authLink} 
                  onClick={!isLoading ? onSwitchToLogin : null} // 'isLoading' state'i eklendi
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