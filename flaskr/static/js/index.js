$(document).ready(function () {
    var originalConfig = $('#config').val();
    var originalTargets = $('#targets').val();
    var originalVerbose = $('#verbose').is(':checked');
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

    $('#verbose').on('change', function () {
       var newVerbose = $('#verbose').is(':checked');
         if (newVerbose !== originalVerbose) {
              $('#needs-saving').css('display', 'inline');
         } else {
              $('#needs-saving').css('display', 'none');
         }
    });

    $('#config, #targets').on('input', function () {
        var newConfig = $('#config').val();
        var newTargets = $('#targets').val();
        if (newConfig !== originalConfig || newTargets !== originalTargets) {
            $('#needs-saving').css('display', 'inline');
        } else {
            $('#needs-saving').css('display', 'none');
        }
    });
});