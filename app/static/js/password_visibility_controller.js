function togglePassword(fieldId, iconId) {
    const passwordField = document.getElementById(fieldId);
    const iconElement = document.getElementById(iconId);

    const type = passwordField.type === 'password' ? 'text' : 'password';
    passwordField.type = type;

    // Toggle the eye icon
    if (type === 'text') {
        iconElement.classList.remove('fa-eye');
        iconElement.classList.add('fa-eye-slash');
    } else {
        iconElement.classList.remove('fa-eye-slash');
        iconElement.classList.add('fa-eye');
    }
}
