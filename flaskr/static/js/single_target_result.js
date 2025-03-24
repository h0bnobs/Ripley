$(document).ready(function () {
    // outer collapsible
    $('.outer-collapsible').on('click', function () {
        $(this).next('.outer-content').slideToggle();
    });

    // inner collapsibles (open by default)
    $('.collapsible').not('.outer-collapsible').on('click', function () {
        $(this).next('.inner-content').slideToggle();
    });
});