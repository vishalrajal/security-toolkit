// DOM Elements
const form = document.getElementById("scan-form");
const domainInput = document.getElementById("domain");
const urlInput = document.getElementById("seed-url");
const button = document.getElementById("scan-button");
const outputEl = document.getElementById("output");
const outputContainer = document.querySelector(".output-container");
const appStatus = document.getElementById("app-status");
const statusDot = appStatus.querySelector(".dot");
const statusText = appStatus.querySelector(".text");
const resolveCheckbox = document.getElementById("resolve-dns");
const portScanCheckbox = document.getElementById("port-scan");
const discoveryCheckbox = document.getElementById("url-discovery");
const copyButton = document.getElementById("copy-button");
const clearButton = document.getElementById("clear-button");

// Helpers
function setStatus(text, mode) {
  statusText.textContent = text;
  appStatus.classList.remove("running", "error");
  if (mode) {
    appStatus.classList.add(mode);
  }
}

function updateOutput(text, htmlContent = null) {
  if (htmlContent) {
    outputEl.innerHTML = htmlContent;
  } else {
    outputEl.textContent = text;
  }

  if (text.trim() || htmlContent) {
    outputContainer.classList.add("has-content");
  } else {
    outputContainer.classList.remove("has-content");
  }
}

// Event Listeners
form.addEventListener("submit", async (e) => {
  e.preventDefault();

  let domain = domainInput.value.trim();
  const seedUrl = urlInput.value.trim();

  // If domain is empty but URL is provided, try to extract hostname
  if (!domain && seedUrl) {
    try {
      const u = new URL(seedUrl.startsWith("http") ? seedUrl : "https://" + seedUrl);
      domain = u.hostname; // Update the 'domain' variable for the API call
      // Optional: Auto-fill domain? User asked for "either/or".
      // Let's NOT auto-fill domainInput to force "URL seed only" mode if they left domain empty.
      // But we might want to populate it for display? 
      // Decision: Let's follow the refined plan: "Allow submission if domain IS empty"
    } catch (e) {
      // ignore
    }
  }

  if (!domain && !seedUrl) {
    setStatus("Please enter a domain or seed URL", "error");
    domainInput.focus();
    return;
  }

  button.disabled = true;
  setStatus("Scanning...", "running");

  // Clear previous output
  updateOutput("");

  // Enable discovery if URL provided or checkbox checked
  const enableDiscovery = discoveryCheckbox.checked || !!seedUrl;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domain,
        url: seedUrl,
        resolve_dns: resolveCheckbox.checked,
        port_scan: portScanCheckbox.checked,
        url_discovery: enableDiscovery
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(errText || "Server error");
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop(); // Keep partial line in buffer

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const update = JSON.parse(line);
          if (update.type === "progress") {
            setStatus(`Scanning... ${update.percentage}%`, "running");
          } else if (update.type === "result") {
            handleScanResult(update.data);
          }
        } catch (e) {
          console.error("Failed to parse progress line:", line, e);
        }
      }
    }

  } catch (err) {
    setStatus("Error", "error");
    updateOutput(`Request failed: ${err.message}`);
  } finally {
    button.disabled = false;
  }
});

function handleScanResult(data) {
  if (!data.success) {
    setStatus("Scan Failed", "error");
    updateOutput((data.error ? `Error: ${data.error}\n\n` : "") +
      (data.output || "No output received from subfinder."));
    return;
  }

  setStatus("Ready");

  let textOutput = data.output || "";
  // Pretty-print JSON if port scan active (existing logic)
  if (portScanCheckbox.checked && textOutput) {
    try {
      const parsed = JSON.parse(textOutput);
      textOutput = JSON.stringify(parsed, null, 2);
    } catch { }
  }

  if (!textOutput && (!data.discovered_urls || data.discovered_urls.length === 0)) {
    updateOutput("Scan finished, but no unique subdomains or URLs were found.");
    return;
  }

  // Compose final display
  let finalHtml = "";

  // Subfinder/Portscan Text Output
  if (textOutput) {
    finalHtml += `<div class="section-title">Subdomains / Hosts</div>`;
    finalHtml += `<div class="raw-output">${escapeHtml(textOutput)}</div>`;
  }

  // URL Discovery Table
  if (data.discovered_urls && data.discovered_urls.length > 0) {
    finalHtml += `<div class="section-title">Discovered URLs (${data.discovered_urls.length})</div>`;
    finalHtml += `<div class="table-container">
          <table class="url-table">
            <thead>
              <tr>
                <th>URL</th>
                <th>Status</th>
                <th>Tags</th>
              </tr>
            </thead>
            <tbody>
              ${renderUrlRows(data.discovered_urls)}
            </tbody>
          </table>
        </div>`;
  }

  // Use HTML update
  updateOutput(" ", finalHtml);
}

function renderUrlRows(urls) {
  return urls.map(u => {
    const statusClass = u.status_code >= 200 && u.status_code < 300 ? 'status-ok' :
      u.status_code >= 300 && u.status_code < 400 ? 'status-redirect' : 'status-error';

    let tagsHtml = (u.tags || []).map(t => `<span class="tag">${t}</span>`).join('');
    if (u.classification && u.classification !== 'endpoint') {
      tagsHtml += `<span class="tag tag-class">${u.classification}</span>`;
    }

    return `<tr>
            <td class="col-url" title="${u.original_url}">
                <a href="${u.original_url}" target="_blank">${escapeHtml(u.original_url)}</a>
                ${u.final_url && u.final_url !== u.original_url ? `<div class="redirect-arrow">↳ ${escapeHtml(u.final_url)}</div>` : ''}
            </td>
            <td><span class="status-badge-small ${statusClass}">${u.status_code}</span></td>
            <td><div class="tags-gap">${tagsHtml}</div></td>
        </tr>`;
  }).join('');
}

function escapeHtml(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Copy Feature
copyButton.addEventListener("click", () => {
  const text = outputEl.textContent;
  if (!text) return;

  navigator.clipboard.writeText(text).then(() => {
    const originalInner = copyButton.innerHTML;
    const originalWidth = copyButton.offsetWidth;

    // Visual feedback
    copyButton.style.width = `${originalWidth}px`;
    copyButton.innerHTML = `<span class="btn-label" style="color:var(--success)">Copied!</span>`;

    setTimeout(() => {
      copyButton.innerHTML = originalInner;
      copyButton.style.width = 'auto';
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy mode', err);
  });
});

// Clear Feature
clearButton.addEventListener("click", () => {
  updateOutput("");
  setStatus("Ready");
  domainInput.value = "";
  domainInput.focus();
});


