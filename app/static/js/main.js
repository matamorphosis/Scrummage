var height = 0.7 * screen.height;
height = height.toString() + "px";
$(document).ready(function(){
  $('#paginate').DataTable({
    "scrollY": height,
    "scrollCollapse": true,
    "paging": true,
    "pageLength": 25,
    "autoWidth": true
  });
  $('.dataTables_length').addClass('bs-select');
});