const axios = require("axios");
const cheerio = require("cheerio");
const fs = require("fs");

const OUTPUT = process.env.NODE_CANDIDATES_FILE || "node_candidates.json";
const MAX_IPSPEED_PROFILES = Math.min(Number(process.env.MAX_IPSPEED_PROFILES || 6), 6);
const INTERVAL_MS = 10000;
const client = axios.create({
  timeout: 20000,
  maxRedirects: 5,
  headers: { "User-Agent": "OneVPN-source-collector/1.0", Accept: "text/html,application/json,text/plain,*/*" }
});

function toProfile(body, source) {
  const text = String(body || "").replace(/^\uFEFF/, "");
  if (!/^\s*remote\s+\S+\s+\d+/im.test(text) ||
      !/^\s*dev\s+(?:tun|tap)\b/im.test(text)) return null;
  return { ovpn_text: text, country: "Unknown", country_code: "XX", source: source };
}

async function fetchConfig(url, source) {
  try {
    const response = await client.get(url, { responseType: "text" });
    const direct = toProfile(response.data, source);
    if (direct) return direct;
    const contentType = String((response.headers && response.headers["content-type"]) || "");
    if (!contentType.includes("html") && !/<(?:html|!doctype)/i.test(String(response.data).slice(0, 500))) return null;
    const $ = cheerio.load(response.data);
    const links = new Set();
    $("a[href]").each((_, node) => {
      const href = $(node).attr("href");
      const label = $(node).text().toLowerCase();
      if (href && (/\\.ovpn(?:$|[?#])/i.test(href) || /(download|config|openvpn)/.test(label))) {
        try { links.add(new URL(href, url).href); } catch (_) {}
      }
    });
    for (const link of Array.from(links).slice(0, 5)) {
      try {
        const file = await client.get(link, { responseType: "text" });
        const item = toProfile(file.data, source);
        if (item) return item;
      } catch (_) {}
    }
    return null;
  } catch (error) {
    console.log(source + ": download failed (" +
      ((error.response && error.response.status) || error.code || error.message) + ")");
    return null;
  }
}

async function scrapeIpspeed() {
  const pages = [
    "https://ipspeed.info/free-openvpn.php",
    "https://ipspeed.info/tr/free-openvpn.php",
    "https://ipspeed.info/es/free-openvpn.php"
  ];
  let html = null;
  let pageUrl = null;
  for (const url of pages) {
    try {
      const response = await client.get(url);
      html = response.data;
      pageUrl = url;
      break;
    } catch (error) {
      console.log("IPSpeed: " + url + " returned HTTP " +
        ((error.response && error.response.status) || "network-error"));
    }
  }
  if (!html) {
    console.log("IPSpeed: source unavailable to this runner; no access-control bypass attempted.");
    return [];
  }

  const $ = cheerio.load(html);
  const urls = new Set();
  $("a[href], [data-href], [data-url], [data-download-url]").each((_, node) => {
    const el = $(node);
    ["href", "data-href", "data-url", "data-download-url"].forEach(attr => {
      const value = el.attr(attr);
      if (!value) return;
      try {
        const absolute = new URL(value, pageUrl).href;
        const label = (el.text() + " " + absolute).toLowerCase();
        if (/\.ovpn(?:$|[?#])/.test(absolute.toLowerCase()) ||
            /(download|config|profile)/.test(label)) urls.add(absolute);
      } catch (_) {}
    });
  });

  const results = [];
  let previous = 0;
  for (const url of Array.from(urls).slice(0, MAX_IPSPEED_PROFILES)) {
    const wait = INTERVAL_MS - (Date.now() - previous);
    if (previous && wait > 0) await new Promise(resolve => setTimeout(resolve, wait));
    previous = Date.now();
    const item = await fetchConfig(url, "IPSpeed");
    if (item) results.push(item);
  }
  console.log("IPSpeed: collected " + results.length + " valid profiles.");
  return results;
}

/*
 * The following feeds are opt-in and require written permission for both
 * automated collection and republication. No CAPTCHA solving, HTML scraping,
 * token acquisition, or access-control/rate-limit evasion is implemented.
 * Feed JSON shape: [{ovpn|content|config|url|download_url: ...}] or {profiles:[...]}.
 */
async function approvedFeed(name, urlName, keyName, approvalName) {
  if (process.env[approvalName] !== "true") {
    console.log(name + ": disabled until provider permission for collection and republication is confirmed.");
    return [];
  }
  const url = process.env[urlName];
  if (!url) {
    console.log(name + ": approved feed URL is not configured.");
    return [];
  }
  const headers = {};
  if (process.env[keyName]) headers.Authorization = "Bearer " + process.env[keyName];
  try {
    const response = await client.get(url, { headers, responseType: "json" });
    const rows = Array.isArray(response.data) ? response.data : response.data.profiles;
    if (!Array.isArray(rows)) {
      console.log(name + ": invalid feed schema.");
      return [];
    }
    const output = [];
    for (const row of rows.slice(0, 100)) {
      let body = row.ovpn || row.content || row.config;
      if (!body && (row.url || row.download_url)) {
        const item = await fetchConfig(new URL(row.url || row.download_url, url).href, name);
        if (item) output.push(item);
      } else {
        const item = toProfile(body, name);
        if (item) output.push(item);
      }
    }
    console.log(name + ": collected " + output.length + " profiles from approved feed.");
    return output;
  } catch (error) {
    console.log(name + ": feed request failed (" +
      ((error.response && error.response.status) || error.code || error.message) + ")");
    return [];
  }
}

async function main() {
  const all = [];
  all.push.apply(all, await scrapeIpspeed());
  all.push.apply(all, await approvedFeed("PublicVPNList", "PUBLICVPNLIST_API_URL",
    "PUBLICVPNLIST_API_KEY", "PUBLICVPNLIST_MIRROR_AUTHORIZED"));
  all.push.apply(all, await approvedFeed("HuntVPN", "HUNTVPN_FEED_URL",
    "HUNTVPN_FEED_TOKEN", "HUNTVPN_MIRROR_AUTHORIZED"));
  fs.writeFileSync(OUTPUT, JSON.stringify(all), "utf8");
  console.log("Node collector wrote " + all.length + " candidates to " + OUTPUT + ".");
}

main().catch(error => {
  console.error("Node collector failed: " + error.message);
  process.exitCode = 1;
});
