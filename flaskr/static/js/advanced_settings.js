$(document).ready(function () {
    $('#needs-saving').css('display', 'none');
    var chatGPT = $('#chatgpt_api_call').is(':checked');
    var enableFfuf = $('#enable_ffuf').is(':checked');

    $('#chatgpt_api_call_warning').css('display', chatGPT ? 'inline' : 'none');
    $('#ffuf_delay_div, #ffuf_wordlists').css('display', enableFfuf ? 'block' : 'none');

    $('#chatgpt_api_call').on('change', function () {
        $('#chatgpt_api_call_warning').css('display', this.checked ? 'inline' : 'none');
    });

    $('#enable_ffuf').on('change', function () {
        if (this.checked) {
            $('#ffuf_delay_div, #ffuf_wordlists').css('display', 'block');
        } else {
            $('#ffuf_delay_div, #ffuf_wordlists').css('display', 'none');
        }
    });

    function uploadFile(inputId, formId, displayId) {
        var fileInput = document.getElementById(inputId);
        var formData = new FormData();
        formData.append("file", fileInput.files[0]);

        $.ajax({
            url: $('#' + formId).attr('action'),
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function (response) {
                window.location.href = '/advanced-settings';
            }
        });
    }

    $('#subdomain-file').on('change', function () {
        uploadFile('subdomain-file', 'upload-subdomain-form', 'subdomain_wordlist_display');
    });

    $('#webpage-file').on('change', function () {
        uploadFile('webpage-file', 'upload-webpage-form', 'webpage_wordlist_display');
    });
});