$(document).ready(function () {
  $('#paginate').DataTable({
    "paging": "simple_numbers" // false to disable pagination (or any other option)
  });
  $('.dataTables_length').addClass('bs-select');
});