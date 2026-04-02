  async function initiateScan() {
    const urlInput = document.getElementById("target-url").value.trim();
    if (!urlInput) return;

    // UI Elements
    const btnText = document.getElementById("btn-text");
    const btnLoader = document.getElementById("btn-loader");
    const dashboard = document.getElementById("results-dashboard");
    const errorBox = document.getElementById("error-box");

    // Reset UI to Loading State
    btnText.classList.add("hidden");
    btnLoader.classList.remove("hidden");
    dashboard.classList.add("hidden");
    errorBox.classList.add("hidden");
    document.getElementById("scan-btn").disabled = true;

    // Scan started logic
    // Hide Old Results, Show Matrix Radar!
    document.getElementById("results-dashboard").classList.add("hidden");
    document.getElementById("scan-overlay").style.display = "flex";

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlInput }),
      });

      const data = await response.json();

      if (!response.ok || data.status === "error") {
        throw new Error(data.message || "Server Unreachable");
      }

      // Fill Data
      document.getElementById("res-url").innerText = data.url;
      document.getElementById("res-status").innerText = data.server_status;
      document.getElementById("res-loc").innerText = data.server_loc;
      document.getElementById("res-age").innerText = data.domain_age;
      document.getElementById("res-ssl").innerText = data.ssl_info;
      document.getElementById("res-vt").innerText = data.vt_report;
      document.getElementById("res-typo").innerText = data.typo_check;
      // After success logic
      document.getElementById("scan-overlay").style.display = "none"; // Hide loader
      document.getElementById("results-dashboard").classList.remove("hidden"); // Show your exact dashboard

      // Start Typewriter Magic!
      typeWriter("ai-output", data.ai_verdict, 20);

      // Handle URLHaus data (Nuvvu idi kinda marchipoyav, ikkada pettesanu)
      document.getElementById("res-urlhaus").innerText = data.urlhaus_report;

      // Handle Image Preview
      const imgObj = document.getElementById("res-screenshot");
      const placeholder = document.getElementById("preview-placeholder");

      if (data.screenshot_url && !data.screenshot_url.includes("error")) {
        imgObj.src = data.screenshot_url;
        imgObj.style.display = "block";
        placeholder.style.display = "none";
      } else {
        // Screenshot block ayithe, oka professional 'Shield' image chupinchu
        imgObj.src = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png";
        imgObj.style.display = "block";
        placeholder.innerText = "Preview Blocked by Site Firewall (WAF)";
      }

      // Handle Verdict Colors
      const banner = document.getElementById("verdict-banner");
      const verdictText = document.getElementById("final-verdict");

      banner.className = "verdict-banner"; // Reset
      verdictText.innerText = `FINAL VERDICT: ${data.verdict}`;

      if (data.verdict === "SAFE") banner.classList.add("safe");
      else if (data.verdict === "SUSPICIOUS") banner.classList.add("suspicious");
      else banner.classList.add("critical");

      // Show Dashboard
      dashboard.classList.remove("hidden");
    } catch (error) {
      errorBox.innerText = `⚠️ SYSTEM ERROR: ${error.message}`;
      errorBox.classList.remove("hidden");
    } finally {
      // Reset Button
      btnText.classList.remove("hidden");
      btnLoader.classList.add("hidden");
      document.getElementById("scan-btn").disabled = false;
    }
  }

  // Allow pressing 'Enter' to scan
  document
    .getElementById("target-url")
    .addEventListener("keypress", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        initiateScan();
      }
    });

  // --- IMAGE ZOOM LOGIC ---
  document.addEventListener("DOMContentLoaded", function() {
      const modal = document.getElementById("imageModal");
      const img = document.getElementById("res-preview");
      const modalImg = document.getElementById("zoomedImage");
      const closeBtn = document.getElementsByClassName("close-modal")[0];
      const themeToggle = document.getElementById("theme-toggle");

      if (modal && img && modalImg && closeBtn) {
          // Click on image to open modal
          img.onclick = function() {
              // Prevent zooming if the image is still the loading spinner
              if (this.src && !this.src.includes('spinner') && !this.src.includes('loading')) {
                  modal.style.display = "block";
                  modalImg.src = this.src;
              }
          }

          // Click on 'X' to close
          closeBtn.onclick = function() {
              modal.style.display = "none";
          }

          // Click anywhere outside the image to close
          modal.onclick = function(event) {
              if (event.target !== modalImg) {
                  modal.style.display = "none";
              }
          }
      }

      if (themeToggle) {
          const storedTheme = localStorage.getItem("sentinel-theme");
          const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
          const initialTheme = storedTheme || (prefersLight ? "light" : "dark");

          const setTheme = (theme) => {
              document.body.setAttribute("data-theme", theme);
              themeToggle.checked = theme === "light";
          };

          setTheme(initialTheme);

          themeToggle.addEventListener("change", () => {
              const nextTheme = themeToggle.checked ? "light" : "dark";
              setTheme(nextTheme);
              localStorage.setItem("sentinel-theme", nextTheme);
          });
      }
  });

  /* --- Level 3: Typewriter Effect Engine --- */
  function typeWriter(elementId, text, speed = 25) {
      const element = document.getElementById(elementId);
      if (!element) return;

      // Clear the box first for clean start
      element.innerHTML = "";

      // Convert raw text to handle Markdown-like bullet points cleanly (if any)
      const processedText = text.replace(/\*/g, '').split('\n'); // Removes * and splits lines
      let lineIndex = 0;

      // Recursive function to type lines sequentially
      function typeNextLine() {
          if (lineIndex < processedText.length) {
              let currentLineText = processedText[lineIndex].trim();
              if (currentLineText === "") { // Skip empty lines
                  lineIndex++; typeNextLine(); return; 
              }

              // Add bullet symbol and prepare list item
              const listItem = document.createElement("p");
              listItem.style.marginBottom = "8px"; // Spacing
              listItem.innerHTML = "<span class='ai-bullet'>»</span> "; // Bullet symbol
              element.appendChild(listItem);

              let charIndex = 0;
              // Type the current line character by character
              const timer = setInterval(() => {
                  if (charIndex < currentLineText.length) {
                      listItem.innerHTML += currentLineText.charAt(charIndex);
                      charIndex++;
                  } else {
                      clearInterval(timer); // Line finished
                      lineIndex++;
                      setTimeout(typeNextLine, 100); // Small delay before next line
                  }
              }, speed);
          }
      }
    // Start typing the first line
    typeNextLine();
  }

  // --- QR CODE UPLOAD & DECODE ---
  document
    .getElementById("qr-input")
    .addEventListener("change", function (event) {
      const file = event.target.files[0];
      if (!file) return;

      const status = document.getElementById("qr-status");
      status.innerText = "Decoding QR...";

      const reader = new FileReader();

      reader.onload = function () {
        const img = new Image();
        img.src = reader.result;

        img.onload = function () {
          const canvas = document.createElement("canvas");
          const ctx = canvas.getContext("2d");

          canvas.width = img.width;
          canvas.height = img.height;

          ctx.drawImage(img, 0, 0);

          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

          const code = jsQR(imageData.data, canvas.width, canvas.height);

          if (code && code.data) {
            status.innerText = "QR decoded ✅";

            // Extracted link
            const extractedURL = code.data.trim();
            if (!extractedURL.startsWith("http")) {
              status.innerText = "Invalid URL in QR";
              return;
            }

            // Put into input field
            document.getElementById("target-url").value = extractedURL;

            // Auto trigger scan (optional)
            initiateScan();
          } else {
            status.innerText = "❌ No QR code detected";
          }
        };
      };

      reader.readAsDataURL(file);
    });
