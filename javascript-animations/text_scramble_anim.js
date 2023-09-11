<script>

class TextScramble {
  constructor(el) {
    this.el = el
    this.chars = '!<>-_\\/[]{}—=+*^?#________'
    this.update = this.update.bind(this)
    this.scrambledText = '';
  }
   scrambleText(text) {
    let newText = text;
    for (let i = 0; i < text.length; i++) {
        let randomChar = this.chars[Math.floor(Math.random() * this.chars.length)];
        newText = newText.replace(text[i], randomChar);
    }
    this.scrambledText = newText;
    return newText;
  }
  setText(newText) {
    //const oldText = this.el.innerHTML;
    newText = newText.replace(/\n/g, "<br>");
    const oldText = this.el.innerText
    const length = Math.max(oldText.length, newText.length)
    const promise = new Promise((resolve) => this.resolve = resolve)
    this.queue = []
    for (let i = 0; i < length; i++) {
      const from = oldText[i] || ''
      const to = newText[i] || ''
      const start = Math.floor(Math.random() * 40)
      const end = start + Math.floor(Math.random() * 40)
      this.queue.push({ from, to, start, end })
    }
    cancelAnimationFrame(this.frameRequest)
    this.frame = 0
    this.update()
    return promise
  }
  update() {
    let output = ''
    let complete = 0
    for (let i = 0, n = this.queue.length; i < n; i++) {
      let { from, to, start, end, char } = this.queue[i]
      if (this.frame >= end) {
        complete++
        output += to
      } else if (this.frame >= start) {
        if (!char || Math.random() < 0.28) {
          char = this.randomChar()
          this.queue[i].char = char
        }
        output += `<span class="dud">${char}</span>`
      } else {
        output += from
      }
    }
    this.el.innerHTML = output
    if (complete === this.queue.length) {
      this.resolve()
    } else {
      this.frameRequest = requestAnimationFrame(this.update)
      this.frame++
    }
  }
  randomChar() {
    return this.chars[Math.floor(Math.random() * this.chars.length)]
  }
}

const elements = document.querySelectorAll('.scramble-text');

elements.forEach(el => {
  const originalText = el.innerText;
  el.setAttribute('data-original-text', originalText);
  const fx = new TextScramble(el);
  fx.scrambleText(originalText);
  el.innerText = fx.scrambledText;
});

const options = {
  root: null,
  rootMargin: '0px',
  threshold: 0
}

video.addEventListener("loadeddata", function() {
const observer = new IntersectionObserver((entries, observer) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const el = entry.target;
      const originalText = el.getAttribute('data-original-text');
      const fx = new TextScramble(el);
      fx.scrambleText(originalText);
      el.innerText = fx.scrambledText;
      setTimeout(() => {
        fx.setText(originalText);
        observer.unobserve(el);
      }, 100);
    }
  });
}, options);

elements.forEach(el => {
  observer.observe(el);
});
});

</script>