import React, { useState } from 'react';
import Modal from './Modal';
// Gerekli CSS modüllerini import ediyoruz
import tutorialStyles from './css/Tutorial.module.css';
import modalStyles from './css/Modal.module.css';

// Öğretici adımları
const tutorialSteps = [
  {
    icon: "👋",
    title: "Kodlama Asistanına Hoş Geldiniz!",
    text: "Bu kısa tur, uygulamanın temel özelliklerini hızla öğrenmenize yardımcı olacaktır."
  },
  {
    icon: "🗂️",
    title: "Sohbet Yönetimi",
    text: "Sol panelden yeni sohbetler oluşturabilir, geçmiş konuşmalarınıza dönebilir veya eski sohbetleri silebilirsiniz."
  },
  {
    icon: "📁",
    title: "Bağlam (Context) Paneli",
    text: "Yapay zekanın hangi dosyalarınızdan haberdar olacağını 'Bağlam' butonuna tıklayarak yönetin. Bu, daha isabetli kod önerileri almanızı sağlar."
  },
  {
    icon: "🎤 / ⌨️",
    title: "Etkileşim",
    text: "AI ile konuşmak için 'Mikrofon' butonunu kullanın veya 'Gönder' butonu ile yazılı komutlar verin. Bot'un ürettiği kodları 'Kopyala' butonuyla alabilirsiniz."
  },
  {
    icon: "🚀",
    title: "Hazırsınız!",
    text: "Artık başlayabilirsiniz. Sol alttaki profilinize tıklayarak 'Ayarlar' menüsüne istediğiniz zaman ulaşabilirsiniz."
  }
];

function TutorialModal({ onFinish }) {
  // O an hangi adımda olduğumuzu tutan state
  const [step, setStep] = useState(0);
  const currentStepData = tutorialSteps[step];

  // Sonraki adıma geç
  const nextStep = () => {
    setStep(s => Math.min(s + 1, tutorialSteps.length - 1));
  };

  // Önceki adıma dön
  const prevStep = () => {
    setStep(s => Math.max(s - 1, 0));
  };

  const isLastStep = step === tutorialSteps.length - 1;

  return (
    <Modal onClose={onFinish} cardClassName={modalStyles.modalCardLarge}>
      <div className={tutorialStyles.tutorialContent}>
        
        {/* Adıma özel ikon */}
        <span className={tutorialStyles.tutorialIcon}>{currentStepData.icon}</span>
        
        {/* Adım başlığı ve metni */}
        <h2 className={tutorialStyles.tutorialTitle}>{currentStepData.title}</h2>
        <p className={tutorialStyles.tutorialText}>{currentStepData.text}</p>
        
        {/* Adım göstergesi (Noktalar) */}
        <div className={tutorialStyles.stepIndicator}>
          {tutorialSteps.map((_, index) => (
            <div 
              key={index} 
              className={`${tutorialStyles.dot} ${index === step ? tutorialStyles.activeDot : ''}`}
            />
          ))}
        </div>

        {/* Navigasyon Butonları */}
        <div className={modalStyles.modalButtons}>
          <button 
            className={`${modalStyles.modalBtn} ${modalStyles.secondary}`}
            onClick={prevStep}
            disabled={step === 0} // İlk adımda "Geri" butonu pasif
          >
            Geri
          </button>
          
          {isLastStep ? (
            // Son adımdaysak "Bitir" butonunu göster
            <button 
              className={`${modalStyles.modalBtn} ${modalStyles.primary}`} 
              onClick={onFinish}
            >
              Başlayalım!
            </button>
          ) : (
            // Diğer adımlarda "İleri" butonunu göster
            <button 
              className={`${modalStyles.modalBtn} ${modalStyles.primary}`} 
              onClick={nextStep}
            >
              İleri
            </button>
          )}
        </div>

      </div>
    </Modal>
  );
}

export default TutorialModal;