document.addEventListener("DOMContentLoaded", function () {
  var currentStep = 1;
  var totalSteps = document.querySelectorAll(".step").length;

  var prevBtn = document.getElementById("prevStep");
  var nextBtn = document.getElementById("nextStep");
  var submitBtn = document.getElementById("submitBtn");

  updateButtons();

  prevBtn.addEventListener("click", function () {
    if (currentStep > 1) {
      currentStep--;
      updateButtons();
    }
  });

  nextBtn.addEventListener("click", function () {
    if (currentStep < totalSteps) {
      currentStep++;
      updateButtons();
    }
  });

  function updateButtons() {
    document.querySelectorAll(".step").forEach(function (step) {
      step.style.display = "none";
    });

    document.querySelector(
      '.step[data-step="' + currentStep + '"]'
    ).style.display = "block";

    if (currentStep === 1) {
      prevBtn.style.display = "none";
    } else {
      prevBtn.style.display = "block";
    }

    if (currentStep === totalSteps) {
      nextBtn.style.display = "none";
      submitBtn.style.display = "block";
    } else {
      nextBtn.style.display = "block";
      submitBtn.style.display = "none";
    }
  }
});
