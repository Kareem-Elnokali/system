document.addEventListener('DOMContentLoaded', () => {
  const container = document.querySelector('#text-rotator');
  if (!container) return;
  const texts = container.querySelectorAll('.rotating-text');
  if (!texts || texts.length === 0) return;
  let current = 0;
  if (!texts[current].classList.contains('active')) {
    texts[current].classList.add('active');
  }
  setInterval(() => {
    if (!texts[current]) return;
    texts[current].classList.remove('active');
    const next = (current + 1) % texts.length;
    setTimeout(() => {
      if (texts[next]) {
        texts[next].classList.add('active');
        current = next;
      }
    }, 500);
  }, 6000);
});
