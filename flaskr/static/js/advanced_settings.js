$(document).ready(function () {
  // Hide "needs-saving" initially.
  $('#needs-saving').hide();

  // Store original values.
  var originalApiKey = $('#openai_api_key').val();
  var originalChatGPT = $('#chatgpt_api_call').is(':checked');

  // Function to toggle the ChatGPT API warning.
  function toggleChatGPTWarning() {
    var chatGPTChecked = $('#chatgpt_api_call').is(':checked');
    var apiKeyEmpty = $('#openai_api_key').val().trim() === '';
    if (chatGPTChecked && apiKeyEmpty) {
      $('#chatgpt_api_call_warning').show();
    } else {
      $('#chatgpt_api_call_warning').hide();
    }
  }

  // Initialize warning on page load.
  toggleChatGPTWarning();

  // Handle ffuf delay and wordlists visibility.
  var enableFfuf = $('#enable_ffuf').is(':checked');
  $('#ffuf_delay_div, #ffuf_wordlists').css('display', enableFfuf ? 'block' : 'none');

  // Event listener for ChatGPT checkbox.
  $('#chatgpt_api_call').on('change', function () {
    toggleChatGPTWarning();
    var newChatGPT = $('#chatgpt_api_call').is(':checked');
    if (newChatGPT !== originalChatGPT) {
      $('#needs-saving').show();
    } else {
      $('#needs-saving').hide();
    }
  });

  // Event listener for OpenAI API key textarea.
  $('#openai_api_key').on('input', function () {
    toggleChatGPTWarning();
    var newApiKey = $('#openai_api_key').val();
    if (newApiKey !== originalApiKey) {
      $('#needs-saving').show();
    } else {
      $('#needs-saving').hide();
    }
  });

  // Event listener for FFUF checkbox.
  $('#enable_ffuf').on('change', function () {
    if (this.checked !== enableFfuf) {
      $('#needs-saving').show();
      $('#ffuf_delay_div, #ffuf_wordlists').css('display', 'block');
    } else {
      $('#needs-saving').hide();
      $('#ffuf_delay_div, #ffuf_wordlists').css('display', 'none');
    }
  });

  // Function for file upload.
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

  // Event listeners for file inputs.
  $('#subdomain-file').on('change', function () {
    uploadFile('subdomain-file', 'upload-subdomain-form', 'subdomain_wordlist_display');
  });

  $('#webpage-file').on('change', function () {
    uploadFile('webpage-file', 'upload-webpage-form', 'webpage_wordlist_display');
  });
});
