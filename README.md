# Decepta Scam Shield

Decepta Scam Shield is a Chrome extension that checks web pages and emails for scams, phishing and fraud. It gives each page or email a red, yellow or green safety badge with a score out of 100, and explains the warning signs in plain language, so people who are not technical can understand the risk.

It combines two checks:

- **Rule checks** run locally on every page. They look for mismatched links, suspicious domains and paths, look-alike characters, sender names that don't match their address, risky attachment types, urgent or payment-pressure wording, and hidden text.
- **AI check** reads the visible text, hidden text, links with their full addresses, forms, sender details, attachment names, and up to five images. It judges the content the way a fraud analyst would and explains each warning sign in simple words.

The final score is the higher of the two results, so a serious sign is never hidden by a low score from the other check.

## Features

- Red, yellow and green badge with a score from 0 to 100
- Plain-language explanations of each warning sign
- Checks the full link address, including path and query string
- Finds hidden or disguised text, such as tiny, transparent, or background-colored text
- Reads words inside images, such as fake login screens or prize notices
- Optional file check for PDF or image attachments (up to 5 MB)
- Works on normal web pages and in Gmail

## What you need

- Google Chrome, or another Chromium browser such as Edge or Brave
- An Anthropic API key from [console.anthropic.com](https://console.anthropic.com). Each user needs their own key.

The rule checks work without a key. The AI check requires one.

## Installation

1. Download this repository: click **Code**, then **Download ZIP**, and unzip the folder.
2. Open Chrome and go to `chrome://extensions`.
3. Turn on **Developer mode** in the top right corner.
4. Click **Load unpacked** and select the unzipped `decepta-extension` folder.
5. Click the puzzle-piece icon in Chrome's toolbar and pin **Decepta Scam Shield**.
6. Click **Details** under the extension and set **Site access** to **On all sites**.
7. Click the Decepta icon, open **Settings**, paste your Anthropic API key, and click **Save key**.

## How to use

1. Open the web page or email you want to check.
2. Click the Decepta icon.
3. (Optional) Choose a PDF or image attachment from the file picker. Save the attachment from Gmail to your computer first.
4. Click **Analyze this page or email**.
5. Read the score, the rule findings, and the AI findings. The AI check can take 10 to 20 seconds.

## Privacy

When the AI check runs, the page text, links, sender details, images, and any file you add are sent to Anthropic's API to be analyzed. Nothing is sent to any other server. Your API key is stored only in your browser's local extension storage. Do not analyze sensitive personal or financial information you would not want shared with an AI service.

## Limitations

- The extension cannot read attachments automatically. You must save them and select them in the popup.
- Gmail changes its layout from time to time. If email text is missing, the content script may need small updates.
- The AI can be wrong. Use the result as a warning, not a final verdict. When in doubt, verify through the official website or phone number of the organization.
- The extension cannot check whether a sender's domain is registered to a real company, and it does not block pages.
- Works on Chrome-based browsers only, not on phones, Firefox or Safari.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | Extension settings and permissions |
| `background.js` | Calls the AI service and returns its analysis |
| `popup.html` | The popup window layout and styling |
| `popup.js` | Page reading, rule checks, scoring and display |
| `test.html` | A fake bank page for testing the warnings |

## Team

Built as a PSDT (Problem Solving and Design Thinking) midterm project: Decepta (FORENSICX), by KOMAL YADAV & RASHI GARG.

## License

For educational use. Add a license here if you plan to share it publicly.
