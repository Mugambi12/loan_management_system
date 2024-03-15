// Add event listener for confirmation action
var confirmationButtons = document.querySelectorAll('[data-bs-toggle="modal"]');
confirmationButtons.forEach(function (button) {
  button.addEventListener("click", function () {
    var url = button.getAttribute("data-bs-url");
    document.getElementById("confirmationMessage").innerHTML =
      "Confirm Action: Are you sure you want to proceed? This action is irreversible.";
    document
      .getElementById("confirmActionButton")
      .addEventListener("click", function () {
        window.location.href = url;
      });
  });
});
