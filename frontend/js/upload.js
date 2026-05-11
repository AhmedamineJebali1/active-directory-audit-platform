// Drag & drop helper. Accepts a .json or .zip BloodHound file, calls onFile callback.
//
// IMPORTANT: the zone element must be a <label for="<inputId>"> so the
// click-to-open behavior is browser-native. JS-forwarding the click
// (zoneEl.click() → fileInputEl.click()) used to cause a Windows-specific
// race: when the user double-clicks a file in the picker, the second
// mouse-up gets delivered to the page after the dialog closes and re-fires
// the click handler, reopening the picker. The native <label> path handles
// this correctly.
(function (global) {
  function setupUploadZone(zoneEl, fileInputEl, onFile) {
    const handle = (file) => {
      if (!file) return;
      const name = file.name.toLowerCase();
      if (!name.endsWith('.json') && !name.endsWith('.zip')) {
        if (window.toast) toast.warn('Veuillez sélectionner un fichier BloodHound (.json ou .zip)');
        else alert('Veuillez sélectionner un fichier BloodHound (.json ou .zip)');
        return;
      }
      onFile(file);
    };

    // Drag-and-drop visual feedback + drop handling
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
      fileInputEl.value = '';   // allow re-selecting the same file later
    });
  }

  global.uploadHelper = { setupUploadZone };
})(window);
