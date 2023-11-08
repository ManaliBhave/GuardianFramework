

document.addEventListener('DOMContentLoaded', function () {
  const verdictElement = document.getElementById('verdict');

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0].url;
    console.log("Current URL:", currentUrl);

    // Send the URL to your server for processing
    fetch('http://localhost:5000/predict', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: currentUrl }),
    })
    .then(response => response.json())
    .then(data => {
      // Handle the response and display the verdict
      const verdict = data.result || 'Unknown';
      verdictElement.textContent = `Verdict: ${verdict}`;
    })
    .catch(error => {
      console.error("Error:", error);
      verdictElement.textContent = 'Error occurred';
    });
  });
});
