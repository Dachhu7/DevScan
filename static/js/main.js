async function postJSON(url, data) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(data)
  });
  return res.json();
}

const scanBtn = document.getElementById('scan');
const urlInput = document.getElementById('url');
const resultDiv = document.getElementById('result');
const downloadBtn = document.getElementById('screenshot'); // renamed for download report

let lastReport = null;

function renderSummary(json) {
  resultDiv.innerHTML = '';
  lastReport = json;

  if (json.error) {
    resultDiv.innerHTML = `<div class="p-3 bg-red-700/30 rounded">${json.error}</div>`;
    return;
  }

  const card = document.createElement('div');
  card.className = 'bg-white/5 p-4 rounded-lg border border-white/5 max-h-[400px] overflow-auto';
  
  let vulnHtml = '';
  for (const [url, details] of Object.entries(json.vulnerabilities)) {
    vulnHtml += `<div class="mb-2"><strong>${url}</strong><ul class="ml-4 list-disc">`;
    if (Array.isArray(details)) {
      for (const i of details) {
        vulnHtml += `<li>${i}</li>`;
      }
    }
    vulnHtml += `</ul></div>`;
  }

  card.innerHTML = `
    <div class="mb-2"><strong>Start URL:</strong> ${json.start_url}</div>
    <div class="mb-2"><strong>Pages scanned:</strong> ${json.pages_scanned}</div>
    <div class="mb-2"><strong>Vulnerabilities found:</strong></div>
    ${vulnHtml}
  `;
  resultDiv.appendChild(card);
}

scanBtn.addEventListener('click', async () => {
  const url = urlInput.value.trim();
  if (!url) return alert('Enter a URL starting with http:// or https://');
  resultDiv.innerHTML = '<div class="p-3">Scanning… this may take a while depending on the site size.</div>';
  try {
    const r = await postJSON('/api/scan', {url});
    renderSummary(r);
  } catch (e) {
    resultDiv.innerHTML = `<div class="p-3 bg-red-700/30 rounded">Scan failed: ${e}</div>`;
  }
});

downloadBtn.addEventListener('click', async () => {
  if (!lastReport) return alert("Run a scan first to download the report.");
  try {
    const response = await fetch('/api/download', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(lastReport)
    });
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "DevScan_Report.json";
    a.click();
    window.URL.revokeObjectURL(url);
  } catch(e) {
    alert("Failed to download report: " + e);
  }
});
