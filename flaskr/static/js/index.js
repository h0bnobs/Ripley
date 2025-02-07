$(document).ready(function () {
    var originalConfig = $('#config').val();
    var originalTargets = $('#targets').val();
    var originalPorts = $('#ports').val();
    $('#needs-saving').css('display', 'none');
    $('.open_targets_in_browser').click(function () {
        var targetsFilepath = $('#targets-filepath').text();
        if (targetsFilepath) {
            window.open('/view-targets-file?filepath=' + encodeURIComponent(targetsFilepath), '_blank');
        } else {
            alert('No targets file specified!');
        }
    });

    $('#toggle-files-btn').click(function () {
        $('#files-list').toggle();
    });

    $('#config, #targets, #ports').on('input', function () {
        var newConfig = $('#config').val();
        var newTargets = $('#targets').val();
        var newPorts = $('#ports').val();
        if (newConfig !== originalConfig || newTargets !== originalTargets) {
            $('#needs-saving').css('display', 'inline');
        } else {
            $('#needs-saving').css('display', 'none');
        }
        if (newPorts !== originalPorts) {
            $('.btn_margin2').css('text-decoration', 'underline');
        } else {
            $('.btn_margin2').css('text-decoration', 'none');
        }
    });
});