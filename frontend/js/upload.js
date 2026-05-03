// Drag & drop helper. Accepts a single .json file, calls onFile callback.
(function (global) {
  function setupUploadZone(zoneEl, fileInputEl, onFile) {
    const handle = (file) => {
      if (!file) return;
      if (!file.name.toLowerCase().endsWith('.json')) {
        alert('Veuillez sélectionner un fichier .json BloodHound');
        return;
      }
      onFile(file);
    };

    zoneEl.addEventListener('click', () => fileInputEl.click());
    zoneEl.addEventListener('dragover', (e) => {
      e.preventDefault();
      zoneEl.classList.add('drag-over');
    });
    zoneEl.addEventListener('dragleave', () => zoneEl.classList.remove('drag-over'));
    zoneEl.addEventListener('drop', (e) => {
      e.preventDefault();
      zoneEl.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      handle(file);
    });
    fileInputEl.addEventListener('change', (e) => {
      const file = e.target.files[0];
      handle(file);
      fileInputEl.value = '';
    });
  }

  global.uploadHelper = { setupUploadZone };
})(window);
