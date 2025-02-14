$(document).ready(function () {
    var pingHostsChecked = $('#ping_hosts').is(':checked');
    var tcpChecked = $('#tcp').is(':checked');
    var arpChecked = $('#arp').is(':checked');
    var icmpChecked = $('#icmp').is(':checked');
    $('#needs-saving').css('display', 'none');

    $('#ping_hosts, #tcp, #arp, #icmp').on('change', function () {
        var newPingHostsChecked = $('#ping_hosts').is(':checked');
        var newTcpChecked = $('#tcp').is(':checked');
        var newArpChecked = $('#arp').is(':checked');
        var newIcmpChecked = $('#icmp').is(':checked');

        if (newPingHostsChecked !== pingHostsChecked || newTcpChecked !== tcpChecked || newArpChecked !== arpChecked || newIcmpChecked !== icmpChecked) {
            $('#needs-saving').css('display', 'inline');
        } else {
            $('#needs-saving').css('display', 'none');
        }
    });
});