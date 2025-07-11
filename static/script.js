document.addEventListener('DOMContentLoaded', () => {
    const toggleThemeBtn = document.getElementById('toggle-theme');
    const toast = document.querySelector('.toast');

    function updateThemeIcon() {
        if (toggleThemeBtn) {
            toggleThemeBtn.textContent = document.body.classList.contains('dark') ? '☀️' : '🌙';
        }
    }

    if (toggleThemeBtn) {
        toggleThemeBtn.addEventListener('click', () => {
            document.body.classList.toggle('dark');
            const theme = document.body.classList.contains('dark') ? 'dark' : 'light';
            localStorage.setItem('theme', theme);
            updateThemeIcon();
        });
    }

    if (localStorage.getItem('theme') === 'dark') {
        document.body.classList.add('dark');
    }

    updateThemeIcon();

    if (toast) {
        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => toast.classList.remove('show'), 4000);
    }
});

// Flask will call this from inline script in template
function showToast(message, type = 'success') {
    if (!message || !message.trim()) return; // ⛔ Skip empty messages

    const toast = document.getElementById('toast');
    const icon = document.getElementById('toast-icon');
    const text = document.getElementById('toast-text');

    if (!toast || !icon || !text) return;

    text.textContent = message;
    toast.classList.remove('toast-success', 'toast-error');

    if (type === 'success') {
        toast.classList.add('toast-success');
        icon.textContent = '✅';
    } else {
        toast.classList.add('toast-error');
        icon.textContent = '❌';
    }

    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}
// Preview image
function previewImage(event) {
    const preview = document.getElementById('preview');
    const file = event.target.files[0];

    if (file && preview) {
        preview.src = URL.createObjectURL(file);
        preview.style.display = 'block';
    } else if (preview) {
        preview.style.display = 'none';
    }
}
function updateFileName(input) {
  const fileNameSpan = document.getElementById('fileName');
  fileNameSpan.textContent = input.files[0]?.name || 'No file chosen';
}

function previewImage(input) {
  const preview = document.getElementById('preview');
  const file = input.files[0];

  if (file) {
    preview.src = URL.createObjectURL(file);
    preview.style.display = 'block';
  } else {
    preview.style.display = 'none';
  }
}