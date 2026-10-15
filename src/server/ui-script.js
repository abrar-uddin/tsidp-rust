// Admin UI behaviour. Served from /ui.js so the page can carry a strict
// Content-Security-Policy with no inline script or event handlers.
(function () {
  'use strict';

  function copyValue(input, button) {
    input.select();
    input.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(input.value).then(function () {
      var t = button.textContent;
      button.textContent = 'Copied!';
      button.classList.add('btn-success');
      setTimeout(function () {
        button.textContent = t;
        button.classList.remove('btn-success');
      }, 2000);
    }).catch(function () {
      alert('Failed to copy to clipboard. Please copy manually.');
    });
  }

  document.addEventListener('click', function (ev) {
    var el = ev.target.closest('[data-copy]');
    if (el) {
      var input = el.previousElementSibling;
      if (input && input.tagName === 'INPUT') copyValue(input, el);
      return;
    }
    var confirmEl = ev.target.closest('[data-confirm]');
    if (confirmEl && !window.confirm(confirmEl.getAttribute('data-confirm'))) {
      ev.preventDefault();
    }
  });
})();
