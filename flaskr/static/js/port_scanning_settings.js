$(document).ready(function () {
    var originalPorts = $('#ports').val();
    var tcpChecked = $('#tcp').is(':checked');
    var udpChecked = $('#udp').is(':checked');
    var synChecked = $('#syn').is(':checked');

    $('#needs-saving').css('display', 'none');

    $('#ports').on('input', function () {
        var newPorts = $('#ports').val();
        if (newPorts !== originalPorts ) {
            $('#needs-saving').css('display', 'inline');
        } else {
            $('#needs-saving').css('display', 'none');
        }
    });

    $('#tcp, #udp, #syn').on('change', function () {
        var newTcpChecked = $('#tcp').is(':checked');
        var newUdpChecked = $('#udp').is(':checked');
        var newSynChecked = $('#syn').is(':checked');

        if (newTcpChecked !== tcpChecked || newUdpChecked !== udpChecked || newSynChecked !== synChecked) {
            $('#needs-saving').css('display', 'inline');
        } else {
            $('#needs-saving').css('display', 'none');
        }
    });
});