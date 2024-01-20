// Retrieve the active tab from local storage
const activeTab = localStorage.getItem("activeTab");

// Set the active tab on page load
$(document).ready(function () {
  if (activeTab) {
    $(`#${activeTab}`).tab("show");
  } else {
    // If no active tab is stored, default to showing Section 1
    $("#tab1").tab("show");
  }
});

// Store the active tab in local storage when a tab is clicked
$(".nav-link").on("shown.bs.tab", function (e) {
  const activeTabId = $(e.target).attr("id");
  localStorage.setItem("activeTab", activeTabId);
});
