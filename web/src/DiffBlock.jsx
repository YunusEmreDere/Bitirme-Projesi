import React from 'react';
import DiffViewer from 'react-diff-viewer-continued';
import diffStyles from './css/Diff.module.css'; // Yeni CSS dosyasını import ediyoruz

function DiffBlock({ oldValue, newValue, title = "Kod Farkı" }) {
  return (
    <div className={diffStyles.diffBlock}>
      <div className={diffStyles.diffHeader}>
        <span className={diffStyles.diffTitle}>{title}</span>
      </div>
      <div className={diffStyles.diffContent}>
        <DiffViewer
          oldValue={oldValue}
          newValue={newValue}
          splitView={true} // Yan yana (split) görünüm
          showDiffOnly={false} // Tüm dosyayı göster, sadece farkları değil
          leftTitle="Eski Hali"
          rightTitle="Yeni Hali"
          // Stil özelleştirmeleri
          styles={{
            variables: {
              dark: {
                gutterBackground: '#2a2a2a',
                gutterColor: '#888',
                diffAddedBackground: 'rgba(76, 175, 80, 0.1)',
                diffRemovedBackground: 'rgba(244, 67, 54, 0.1)',
                diffAddedColor: '#e0ffe0',
                diffRemovedColor: '#ffe0e0',
                addedColor: '#4CAF50',
                removedColor: '#F44336',
                wordAddedBackground: 'rgba(76, 175, 80, 0.2)',
                wordRemovedBackground: 'rgba(244, 67, 54, 0.2)',
                codeFoldBackground: '#333',
                codeFoldColor: '#aaa',
              },
            },
            line: {
              padding: '0 5px',
            },
            marker: {
              width: '20px', // +/- işaretlerinin olduğu sütunun genişliği
              paddingRight: '5px',
              textAlign: 'center',
              lineHeight: '1.5em',
            },
            content: {
                // fontFamily: 'monospace', // İçerik fontu
                fontSize: '0.9em',
            },
            gutter: {
                // fontFamily: 'monospace', // Satır numarası fontu
                fontSize: '0.9em',
            },
            titleBlock: { // "Eski Hali" "Yeni Hali" başlıkları
                backgroundColor: 'rgba(0, 0, 0, 0.3)',
                padding: '8px 10px',
                color: '#ddd',
                fontWeight: '600',
                borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                fontSize: '0.9em',
            },
          }}
        />
      </div>
    </div>
  );
}

export default DiffBlock;