$(document).ready(function() {
    $('.open_targets_in_browser').click(function() {
        var targetsFilepath = $('#targets-filepath').text();
        if (targetsFilepath) {
            window.open('/view-targets-file?filepath=' + encodeURIComponent(targetsFilepath), '_blank');
        } else {
            alert('No targets file specified!');
        }
    });
});