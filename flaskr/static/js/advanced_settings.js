$(document).ready(function () {
    const $needsSaving = $('#needs-saving').hide();
    const $chatGPTCall = $('#chatgpt_api_call');
    const $apiKeyInput = $('#openai_api_key');
    const $configFilepathInput = $('#config_filepath');
    const $chatGPTWarning = $('#chatgpt_api_call_warning');
    const $configWarning = $('#config_filepath_warning');
    const $ffufRedirectWarning = $('#ffuf_redirect_warning');
    const $enableFfuf = $('#enable_ffuf');
    const $ffufOptions = $('#ffuf_delay_div, #ffuf_wordlists, #ffuf_redirect_div');
    const $chatgptModel = $('#chatgpt_model');
    const $ffufRedirect = $('#ffuf_redirect');

    let originalApiKey = $apiKeyInput.val();
    let originalChatGPT = $chatGPTCall.is(':checked');
    let originalConfigFilepath = $configFilepathInput.val();
    let enableFfufChecked = $enableFfuf.is(':checked');
    let originalChatGPTModel = $chatgptModel.val();
    let originalFfufRedirect = $('#ffuf_redirect').is(':checked');

    function toggleElement($element, condition) {
        $element.toggle(condition);
    }

    function checkChanges(originalValue, newValue) {
        toggleElement($needsSaving, originalValue !== newValue);
    }

    function toggleChatGPTWarning() {
        toggleElement($chatGPTWarning, $chatGPTCall.is(':checked') && !$apiKeyInput.val().trim());
    }

    function toggleConfigFilepathWarning() {
        toggleElement($configWarning, $configFilepathInput.val() !== originalConfigFilepath);
    }

    function toggleFfufRedirectWarning() {
        toggleElement($ffufRedirectWarning, $ffufRedirect.is(':checked'));
        checkChanges(originalFfufRedirect, $ffufRedirect.is(':checked'));
    }

    function toggleFfufOptions() {
        $ffufOptions.css('display', $enableFfuf.is(':checked') ? 'block' : 'none');
    }

    function uploadFile(inputId, formId) {
        let fileInput = document.getElementById(inputId);
        let formData = new FormData();
        formData.append("file", fileInput.files[0]);

        $.ajax({
            url: $('#' + formId).attr('action'),
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function () {
                window.location.href = '/advanced-settings';
            }
        });
    }

    toggleChatGPTWarning();
    toggleConfigFilepathWarning();
    toggleFfufRedirectWarning();
    toggleFfufOptions();

    $chatGPTCall.on('change', function () {
        toggleChatGPTWarning();
        checkChanges(originalChatGPT, $(this).is(':checked'));
    });

    $ffufRedirect.on('change', function () {
        checkChanges(originalFfufRedirect, $(this).val());
        toggleFfufRedirectWarning();
    })

    $chatgptModel.on('change', function () {
        checkChanges(originalChatGPTModel, $(this).val());
    });

    $apiKeyInput.on('input', function () {
        toggleChatGPTWarning();
        checkChanges(originalApiKey, $(this).val());
    });

    $enableFfuf.on('change', function () {
        toggleFfufOptions();
        checkChanges(enableFfufChecked, $(this).is(':checked'));
    });

    $configFilepathInput.on('input', function () {
        toggleConfigFilepathWarning();
    });

    $('#subdomain-file').on('change', function () {
        uploadFile('subdomain-file', 'upload-subdomain-form');
    });

    $('#webpage-file').on('change', function () {
        uploadFile('webpage-file', 'upload-webpage-form');
    });
});
