// Add event listener for confirmation action
var confirmationButtons = document.querySelectorAll('[data-bs-toggle="modal"]');
confirmationButtons.forEach(function (button) {
  button.addEventListener('click', function () {
    var url = button.getAttribute('data-bs-url');
    document.getElementById('confirmationMessage').innerHTML = 'Are You Sure?'; // Set your confirmation message
    document.getElementById('confirmActionButton').addEventListener('click', function () {
      window.location.href = url;
    });
  });
});
