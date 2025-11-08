function togglePassword() {
  const passwordInput = document.getElementById('password');
  const toggleIcon = document.getElementById('toggleIcon');
  if (passwordInput.type === 'password') {
    passwordInput.type = 'text';
    toggleIcon.classList.replace('bi-eye', 'bi-eye-slash');
  } else {
    passwordInput.type = 'password';
    toggleIcon.classList.replace('bi-eye-slash', 'bi-eye');
  }
}

function validatePassword() {
  const password = document.getElementById('password').value;
  const confirm = document.getElementById('confirm').value;
  const alertBox = document.getElementById('passwordAlert');

  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;

  if (!regex.test(password)) {
    alertBox.textContent = "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.";
    alertBox.classList.remove('d-none');
    return false;
  } else if (password !== confirm) {
    alertBox.textContent = "Passwords do not match.";
    alertBox.classList.remove('d-none');
    return false;
  }

  alertBox.classList.add('d-none');
  return true;
}

document.addEventListener("DOMContentLoaded", function () {
  const toggleMain = document.getElementById('togglePassword');
  const mainPass = document.getElementById('password');
  const toggleConfirm = document.getElementById('toggleConfirm');
  const confirmPass = document.getElementById('confirmPassword');

  function toggleVisibility(button, field) {
    if (!button || !field) return;
    button.addEventListener('click', function () {
      const type = field.getAttribute('type') === 'password' ? 'text' : 'password';
      field.setAttribute('type', type);
      const icon = this.querySelector('i');
      icon.classList.toggle('bi-eye');
      icon.classList.toggle('bi-eye-slash');
    });
  }

  toggleVisibility(toggleMain, mainPass);
  toggleVisibility(toggleConfirm, confirmPass);
});

