$(document).ready(function () {
    var originalPorts = $('#ports').val();
    var tcpChecked = $('#tcp').is(':checked');
    var udpChecked = $('#udp').is(':checked');
    var synChecked = $('#syn').is(':checked');
    var aggressiveChecked = $('#aggressive_scan').is(':checked');
    var osDetectionChecked = $('#os_detection').is(':checked');

    $('#needs-saving').css('display', 'none');

    $('#os_detection_warning').css('display', 'none');
    if (osDetectionChecked) {
        $('#os_detection_warning').css('display', 'inline');
    }

    $('#aggressive_scan_warning').css('display', 'none');
    if (aggressiveChecked) {
        $('#aggressive_scan_warning').css('display', 'inline');
    }

    $('#ports').on('input', function () {
        var newPorts = $('#ports').val();
        if (newPorts !== originalPorts ) {
            $('#needs-saving').css('display', 'inline');
        } else {
            $('#needs-saving').css('display', 'none');
        }
    });

    $('#tcp, #udp, #syn, #aggressive_scan, #os_detection').on('change', function () {
        var newTcpChecked = $('#tcp').is(':checked');
        var newUdpChecked = $('#udp').is(':checked');
        var newSynChecked = $('#syn').is(':checked');
        var newAggressiveChecked = $('#aggressive_scan').is(':checked');
        var newOsDetectionChecked = $('#os_detection').is(':checked');

        if (newTcpChecked !== tcpChecked || newUdpChecked !== udpChecked || newSynChecked !== synChecked
            || newAggressiveChecked !== aggressiveChecked || newOsDetectionChecked !== osDetectionChecked) {
            $('#needs-saving').css('display', 'inline');
        } else {
            $('#needs-saving').css('display', 'none');
        }

        if (newAggressiveChecked) {
            $('#aggressive_scan_warning').css('display', 'inline');
        } else {
            $('#aggressive_scan_warning').css('display', 'none');
        }

        if (newOsDetectionChecked) {
            $('#os_detection_warning').css('display', 'inline');
        } else {
            $('#os_detection_warning').css('display', 'none');
        }
    });
});