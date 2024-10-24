$(document).ready(function () {
    // Handle the outer collapsible
    $('.outer-collapsible').on('click', function () {
        $(this).next('.outer-content').slideToggle();
    });

    // Handle the inner collapsibles (open by default, can be toggled)
    $('.collapsible').not('.outer-collapsible').on('click', function () {
        $(this).next('.inner-content').slideToggle();
    });
});