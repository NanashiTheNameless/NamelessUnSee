/* Counts down the email-resend cooldown inside the button itself. The server
 * enforces the cooldown regardless; this only keeps the button honest. */
(function () {
  'use strict';

  var button = document.getElementById('resend-btn');
  if (!button) return;
  var wait = parseInt(button.getAttribute('data-wait'), 10) || 0;
  if (wait <= 0) return;

  var fallback = document.getElementById('resend-wait-note');
  if (fallback) fallback.style.display = 'none';
  var label = button.textContent;

  button.disabled = true;
  var remaining = wait;
  function tick() {
    if (remaining > 0) {
      button.textContent = label + ' (' + remaining + 's)';
      remaining -= 1;
      setTimeout(tick, 1000);
    } else {
      button.textContent = label;
      button.disabled = false;
    }
  }
  tick();
})();
