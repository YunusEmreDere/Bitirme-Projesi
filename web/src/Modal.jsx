// src/Modal.jsx
import React from 'react';
import modalStyles from './css/Modal.module.css';

function Modal({ children, onClose }) {
  return (
    <div className={modalStyles.modalBackdrop} onClick={onClose}>
      <div className={modalStyles.modalCard} onClick={(e) => e.stopPropagation()}>
        <button
          className={modalStyles.modalCloseBtn}
          onClick={onClose}
          title="Kapat"
        >
          ×
        </button>
        <div className={modalStyles.modalContent}>
          {children}
        </div>
      </div>
    </div>
  );
}

export default Modal;