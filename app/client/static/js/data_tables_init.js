// Initialize DataTables for elements with the classes data-table-1 and data-table-2.

$(document).ready(function () {
  $(".data-table-1").each(function (_, table) {
    $(table).DataTable();
  });
});

$(document).ready(function () {
  $(".data-table-2").each(function (_, table) {
    $(table).DataTable();
  });
});
