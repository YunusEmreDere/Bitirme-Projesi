import React, { useState } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import chatStyles from './css/Chat.module.css';

function CodeBlock({ language, codeString }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    // Kodu panoya kopyala
    navigator.clipboard.writeText(codeString);
    setCopied(true);
    // 2 saniye sonra "Kopyalandı" yazısını geri al
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={chatStyles.codeBlock}>
      <div className={chatStyles.codeBlockHeader}>
        <span className={chatStyles.codeLanguage}>
          {language || 'code'}
        </span>
        <button className={chatStyles.copyButton} onClick={handleCopy}>
          {copied ? '✓ Kopyalandı' : '📋 Kopyala'}
        </button>
      </div>
      <SyntaxHighlighter
        style={vscDarkPlus}
        language={language || 'text'}
        PreTag="div"
        customStyle={{ 
            margin: 0, 
            borderRadius: '0 0 0.75rem 0.75rem', 
            fontSize: '0.875rem',
            background: '#1e1e1e' // Arka planı zorla
        }}
      >
        {codeString}
      </SyntaxHighlighter>
    </div>
  );
}

export default CodeBlock;