const $ = id => document.getElementById(id);

const LEVELS = {
  low:    { label: "LOW RISK",    color: "#1e8e3e" },
  medium: { label: "MEDIUM RISK", color: "#f9ab00" },
  high:   { label: "HIGH RISK",   color: "#d93025" }
};

const BRANDS = ["paypal", "google", "microsoft", "amazon", "apple", "netflix", "facebook", "instagram",
  "bank", "irs", "sbi", "hdfc", "icici", "axis", "flipkart", "paytm", "phonepe", "income tax", "gov"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"];
const BAD_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".zip", ".mov"];
const URGENCY = ["act now", "expires in", "within 24 hours", "last warning", "final notice", "immediately",
  "limited time", "suspended", "blocked"];
const PAYMENT = ["pay now", "payment failed", "payment pending", "account will be blocked",
  "account has been suspended", "account will be suspended", "verify your account", "will be locked",
  "unpaid", "reset your password", "unusual sign-in", "update your details", "kyc"];
const OFFERS = ["you have won", "congratulations", "lottery", "claim your prize", "free iphone",
  "guaranteed returns", "double your money", "only rs", "bitcoin", "work from home", "gift card"];
const PATH_WORDS = /(login|signin|sign-in|verify|verification|secure|account|update|payment|confirm|wallet|banking|password|otp)/;
const DANGEROUS_FILES = /\.(exe|scr|js|vbs|bat|cmd|html?|lnk|iso|img|docm|xlsm)$/i;

// Runs inside the page and each frame. It must be self-contained.
function extractPage() {
  const text = (document.body ? document.body.innerText : "").replace(/\n{3,}/g, "\n\n").slice(0, 8000);

  const links = [...document.querySelectorAll("a[href]")].slice(0, 300).map(a => {
    let destination = a.href;
    try {
      const u = new URL(a.href);
      if (/(^|\.)google\.[a-z.]+$/i.test(u.hostname) && u.pathname === "/url") {
        destination = u.searchParams.get("q") || u.searchParams.get("url") || destination;
      }
    } catch (e) { /* keep original */ }
    return { shown: a.textContent.trim().slice(0, 120), destination: String(destination).slice(0, 500) };
  }).filter(l => /^https?:/i.test(l.destination));

  const forms = [...document.querySelectorAll("form")].slice(0, 20).map(f => ({
    action: String(f.action || location.href).slice(0, 300),
    fields: [...f.querySelectorAll("input")].slice(0, 20).map(i => i.type + ":" + (i.name || i.autocomplete || ""))
  }));

  const senders = [...document.querySelectorAll("[email]")].slice(0, 20)
    .map(e => `${e.textContent.trim()} <${e.getAttribute("email")}>`);

  const attachments = [...document.querySelectorAll("[download_url]")].slice(0, 30)
    .map(e => (e.getAttribute("download_url") || "").split(":")[1] || "(unnamed)");

  function bgOf(e) {
    while (e) {
      const c = getComputedStyle(e).backgroundColor;
      if (c && c !== "rgba(0, 0, 0, 0)" && c !== "transparent") return c;
      e = e.parentElement;
    }
    return "rgb(255, 255, 255)";
  }
  function hiddenAncestor(e) {
    for (let n = e; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.display === "none" || s.visibility === "hidden") return true;
    }
    return false;
  }

  const hiddenText = [];
  const nodes = document.body ? document.body.querySelectorAll("*") : [];
  for (const e of nodes) {
    if (hiddenText.length >= 40) break;
    if (e.children.length > 0) continue;
    const t = (e.textContent || "").trim();
    if (t.length < 3) continue;
    const s = getComputedStyle(e);
    const tiny = parseFloat(s.fontSize) < 3;
    const transparent = parseFloat(s.opacity) < 0.05;
    const sameColor = s.color === bgOf(e);
    if (hiddenAncestor(e) || tiny || transparent || sameColor) {
      hiddenText.push(t.slice(0, 200));
    }
  }

  const images = [...document.images]
    .filter(i => /^https?:/i.test(i.src) && (i.naturalWidth === 0 || i.naturalWidth >= 100))
    .slice(0, 5).map(i => i.src);

  return { url: location.href, text, links, forms, senders, attachments, images, hiddenText };
}

function mergePages(list) {
  const out = { url: "", text: "", links: [], forms: [], senders: [], attachments: [], images: [], hiddenText: [] };
  list.forEach(p => {
    if (!p) return;
    if (!out.url) out.url = p.url;
    out.text += (p.text || "") + "\n";
    ["links", "forms", "senders", "attachments", "images", "hiddenText"]
      .forEach(k => out[k].push(...(p[k] || [])));
  });
  out.text = out.text.slice(0, 8000);
  out.images = out.images.slice(0, 5);
  return out;
}

function parts(u) {
  try {
    const x = new URL(u);
    return { host: x.hostname.toLowerCase().replace(/^www\./, ""), path: x.pathname, query: x.search, protocol: x.protocol };
  } catch (e) {
    return { host: "", path: "", query: "", protocol: "" };
  }
}

// Rule-based checks. Serious findings put the score at 70 or higher.
function analyzeLocally(d) {
  const hits = [];
  const add = (critical, points, message) => hits.push({ critical, points, message });

  const pageProtocol = parts(d.url).protocol;
  const fieldsAll = d.forms.flatMap(f => f.fields.map(x => x.toLowerCase()));
  const hasPassword = fieldsAll.some(x => x.startsWith("password:"));
  const hasSensitive = fieldsAll.some(x => /(cc-|card|cvv|otp|pin|upi)/.test(x));
  const httpForm = d.forms.find(f => f.action.startsWith("http:"));

  if (pageProtocol === "http:" && hasPassword) {
    add(true, 0, "This page asks for a password over an insecure connection (http). Anything typed can be stolen.");
  }
  if (httpForm) {
    add(true, 0, `A form sends your information to an insecure address: ${httpForm.action}`);
  }

  d.links.forEach(l => {
    const dest = parts(l.destination);
    const shown = (l.shown.match(/([a-z0-9-]+\.)+[a-z]{2,}/i) || [])[0];
    const dom = shown ? shown.toLowerCase().replace(/^www\./, "") : "";
    if (dom && dest.host && !dest.host.endsWith(dom)) {
      add(true, 0, `The link shows "${l.shown.slice(0, 50)}" but goes to ${dest.host}.`);
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(dest.host)) {
      add(true, 0, `A link uses a raw IP address (${dest.host}) instead of a company name.`);
    }
    if (dest.host.includes("xn--")) {
      add(true, 0, `A link uses look-alike characters (${dest.host}) to imitate a real site.`);
    }
    if (SHORTENERS.includes(dest.host)) {
      add(false, 8, `A link hides its real destination behind a shortener (${dest.host}).`);
    }
    if (BAD_TLDS.some(t => dest.host.endsWith(t))) {
      add(false, 10, `A link goes to a domain ending that scammers use often (${dest.host}).`);
    }
    if ((dest.host.match(/-/g) || []).length >= 2) {
      add(false, 5, `A link domain has several hyphens (${dest.host}).`);
    }
    if (dest.host && PATH_WORDS.test((dest.path + " " + dest.query).toLowerCase())) {
      add(false, 8, `A link goes to a sensitive-looking page (${dest.host}${dest.path}).`);
    }
    if (dest.query.length > 200) {
      add(false, 5, `A link has an unusually long query string (${dest.host}), which can hide tracking or data.`);
    }
  });

  d.senders.forEach(s => {
    const m = s.match(/<([^>]+)>/);
    const domain = m ? (m[1].split("@")[1] || "").toLowerCase() : "";
    const brand = BRANDS.find(b => s.toLowerCase().includes(b));
    if (brand && domain) {
      const reg = domain.split(".").slice(-2)[0] || "";
      const bn = brand.replace(/\s/g, "");
      if (!(reg.includes(bn) && !reg.includes("-"))) {
        add(true, 0, `The sender "${s.slice(0, 80)}" uses a well-known name, but the address belongs to ${domain}.`);
      }
    }
  });

  d.attachments.forEach(a => {
    if (DANGEROUS_FILES.test(a)) {
      add(true, 0, `Attachment "${a}" is a file type often used to spread malware.`);
    }
  });

  const textLower = d.text.toLowerCase();
  const hiddenLower = d.hiddenText.join(" ").toLowerCase();
  const found = (list, s) => list.filter(w => s.includes(w));

  const urg = found(URGENCY, textLower);
  if (urg.length) add(false, 8, `Urgent wording ("${urg[0]}") is meant to rush you into acting.`);
  const pay = found(PAYMENT, textLower);
  if (pay.length) add(false, 15, `The page pressures you about a payment or account problem ("${pay[0]}").`);
  const off = found(OFFERS, textLower);
  if (off.length) add(false, 15, `The page makes a prize or too-good offer ("${off[0]}").`);
  if (hasSensitive) {
    add(false, 5, "The page asks for card, PIN or one-time-code details. Enter them only on a site you fully trust.");
  }
  if (d.hiddenText.length) {
    const hiddenHits = found([...URGENCY, ...PAYMENT, ...OFFERS], hiddenLower);
    if (hiddenHits.length) {
      add(true, 0, `Hidden text (invisible to you) contains pressure wording ("${hiddenHits[0]}"). This is a common trick.`);
    } else {
      add(false, 5, `The page contains ${d.hiddenText.length} hidden or disguised text items.`);
    }
  }

  const crit = hits.filter(h => h.critical).length;
  const weak = hits.filter(h => !h.critical).reduce((s, h) => s + h.points, 0);
  const score = crit > 0
    ? 70 + Math.min(29, weak + 5 * (Math.min(crit, 6) - 1))
    : Math.min(69, weak);

  return { score, messages: hits.map(h => h.message).slice(0, 25) };
}

function hostOf(u) {
  return parts(u).host;
}

function toBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(bin);
}

async function readFile(file) {
  if (!file) return null;
  if (file.size > 5 * 1024 * 1024) throw new Error("That file is larger than 5 MB.");
  const data = toBase64(await file.arrayBuffer());
  if (file.type === "application/pdf") {
    return { type: "document", source: { type: "base64", media_type: "application/pdf", data } };
  }
  if (file.type.startsWith("image/")) {
    return { type: "image", source: { type: "base64", media_type: file.type, data } };
  }
  throw new Error("Only PDF or image files are supported.");
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

const levelOf = s => (s >= 70 ? "high" : s >= 30 ? "medium" : "low");

function render(page, local, ai, note) {
  const aiScore = ai ? Number(ai.score) || 0 : null;
  const finalScore = Math.max(local.score, aiScore || 0);
  const info = LEVELS[levelOf(finalScore)];

  const box = $("result");
  box.textContent = "";

  const badge = el("div", undefined, "badge");
  badge.style.background = info.color;
  badge.append(
    el("div", String(finalScore), "score"),
    el("div", "out of 100", "small"),
    el("div", info.label, "label")
  );
  box.append(badge);

  box.append(el("div",
    `Rule checks: ${local.score}  ·  AI check: ${aiScore === null ? "not run" : aiScore}`,
    "small"));

  if (note) box.append(el("p", note, "note"));
  if (ai && ai.summary) box.append(el("p", ai.summary, "summary"));

  box.append(el("div", "Rule-based findings", "section"));
  if (local.messages.length) {
    const list = el("ul");
    local.messages.forEach(m => list.append(el("li", m)));
    box.append(list);
  } else {
    box.append(el("p", "None found by the rule checks.", "small"));
  }

  if (ai && (ai.reasons || []).length) {
    box.append(el("div", "AI findings", "section"));
    ai.reasons.forEach(x => {
      const d = el("div", undefined, "reason");
      d.append(el("strong", x.title || "Warning sign"));
      d.append(el("div", x.explanation || ""));
      if (x.evidence) d.append(el("div", "Evidence: " + x.evidence, "evidence"));
      box.append(d);
    });
  }

  if (ai && ai.what_to_do) box.append(el("p", "What to do: " + ai.what_to_do));
  if (ai && ai.could_not_check && ai.could_not_check.length) {
    box.append(el("p", "Could not check: " + ai.could_not_check.join("; "), "small"));
  }

  const p = parts(page.url);
  box.append(el("div",
    `${p.host}${p.path} · ${page.links.length} links · ${page.forms.length} forms · ${page.images.length} images · ${page.hiddenText.length} hidden text items`,
    "small"));
  box.append(el("div",
    "Privacy: the page text, links and any file you added are sent to the AI service when the AI check runs.",
    "small"));
}

async function run() {
  const box = $("result");
  box.className = "";
  box.textContent = "Reading the page...";

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https?:/.test(tab.url || "")) {
    box.textContent = "Open a normal website (http or https) first.";
    return;
  }

  let page, file;
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id, allFrames: true },
      func: extractPage
    });
    page = mergePages(results.map(r => r.result));
    file = await readFile($("file").files[0]);
  } catch (err) {
    box.className = "err";
    box.textContent = "Could not read the page: " + err.message;
    return;
  }

  const local = analyzeLocally(page);

  const { apiKey } = await chrome.storage.local.get("apiKey");
  let ai = null;
  let note = "";

  if (!apiKey) {
    note = "No API key saved, so only the rule checks ran. Open Settings, paste your key, and click Save key to add the AI check.";
  } else {
    box.textContent = "Rule checks done. Asking the AI to read the page... this can take 10 to 20 seconds.";
    try {
      const reply = await chrome.runtime.sendMessage({
        type: "analyze",
        payload: { ...page, file, localFindings: local.messages }
      });
      if (!reply || reply.error) {
        note = "AI check failed: " + ((reply && reply.error) || "no response from the background worker");
      } else {
        ai = reply;
      }
    } catch (err) {
      note = "AI check failed: " + err.message;
    }
  }

  render(page, local, ai, note);
}

async function init() {
  const { apiKey } = await chrome.storage.local.get("apiKey");
  if (apiKey) $("apiKey").placeholder = "Key saved. Paste a new one to replace it.";

  $("saveKey").addEventListener("click", async () => {
    const key = $("apiKey").value.trim();
    if (!key) {
      $("saveKey").textContent = "Paste a key first";
      setTimeout(() => { $("saveKey").textContent = "Save key"; }, 1500);
      return;
    }
    await chrome.storage.local.set({ apiKey: key });
    $("apiKey").value = "";
    $("apiKey").placeholder = "Key saved.";
    $("saveKey").textContent = "Key saved ✓";
  });

  $("analyze").addEventListener("click", run);
}

document.addEventListener("DOMContentLoaded", init);
