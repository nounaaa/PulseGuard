import logging
import asyncio
import aiohttp
import json
import re
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode

# ── API KEYS ──────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = "API KEY"
VIRUSTOTAL_KEY   = "API KEY"
ABUSEIPDB_KEY    = "API KEY"
IPINFO_TOKEN     = "API KEY"
URLSCAN_KEY      = "API KEY"
GOOGLE_SAFE_BROWSING_KEY = "API KEY"
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

SOCIAL_PLATFORMS = [
    "Instagram", "X", "Twitter", "TikTok", "Snapchat", "Reddit",
    "Pinterest", "Telegram", "Threads", "YouTube", "Tumblr", "Twitch",
    "Facebook", "LinkedIn", "Flipboard", "Itemfix", "TrashboxRU",
    "CodeSandbox", "Xbox"
]

DEV_PLATFORMS = [
    "GitHub", "GitLab", "Replit", "DockerHub", "HackerNews", "StackOverflow",
    "BitBucket", "Gitea", "Gitee", "HackerOne", "HackerEarth", "Hackster",
    "Codecademy", "Codechef", "Codeforces", "Codewars", "Asciinema", "Atcoder",
    "Vjudge", "Arduino", "SpeakerDeck", "HackMD", "Hugging Face", "Kaggle",
    "Launchpad", "Codeberg", "Npmjs", "Cplusplus", "Coroflot", "GitBook",
    "Apple Developer", "CryptoHack", "BraveCommunity"
]

PLATFORMS_LIST = """📋 *Platforms PulseGuard checks:*
━━━━━━━━━━━━━━

📱 *Social Media*
Instagram, X (Twitter), TikTok, Snapchat, Reddit, Pinterest, Telegram, Threads, YouTube, Tumblr, Twitch

💻 *Developer*
GitHub, GitLab, Replit, DockerHub, HackerNews, StackOverflow, BitBucket, Codechef, Codeforces, HackerOne, Kaggle, Hugging Face, Arduino, Codewars, Atcoder, Vjudge, Cplusplus, Coroflot, and more

✍️ *Creator*
Medium, Patreon, Bandcamp, SoundCloud, Dribbble, Behance, BuyMeACoffee, Gumroad, Itch.io, Linktree, CGTrader, Audiojungle, ThemeForest, Sketchfab, ReverbNation, Issuu, Slides

🎮 *Gaming*
Steam, Chess.com, Osu, Roblox, Monkeytype, Kongregate, TETR.IO, NitroType, Pokemon Showdown, RuneScape, Star Citizen, Terraria Forums, Xbox Gamertag, Wowhead

🌐 *Other*
Wikipedia, GoodReads, Strava, Duolingo, Trello, Slack, WordPress, Academia.edu, Discord, Pastebin, TradingView, Genius, TheMovieDB, Anilist, and 80+ more

━━━━━━━━━━━━━━
_PulseGuard by [PulseAI](https://pulseai.qa)_"""

def is_valid_ip(ip: str) -> bool:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))

def is_valid_url(url: str) -> bool:
    return url.startswith(("http://", "https://", "www."))

def format_number(n: int) -> str:
    return f"{n:,}"

def is_social(platform: str) -> bool:
    return any(s.lower() in platform.lower() for s in SOCIAL_PLATFORMS)

def is_dev(platform: str) -> bool:
    return any(s.lower() in platform.lower() for s in DEV_PLATFORMS)

def clean_results(found: dict, username: str) -> dict:
    cleaned = {}
    for platform, url in found.items():
        if username.lower() in url.lower():
            cleaned[platform] = url
        elif any(p.lower() in platform.lower() for p in ["GitHub", "Reddit", "Twitter", "X.com"]):
            cleaned[platform] = url
    if "Instagram" not in cleaned:
        cleaned["Instagram"] = f"https://www.instagram.com/{username}/"
    if "X" not in cleaned and "Twitter" not in cleaned:
        cleaned["X (Twitter)"] = f"https://x.com/{username}"
    return cleaned

def format_results(found: dict, filter_type: str, username: str) -> str:
    if filter_type == "social":
        filtered = {p: u for p, u in found.items() if is_social(p)}
        label = "social media"
    elif filter_type == "dev":
        filtered = {p: u for p, u in found.items() if is_dev(p)}
        label = "developer"
    else:
        filtered = found
        label = "all"

    if not filtered:
        return f"✅ Username not found on any {label} platforms."

    if filter_type == "all":
        social = {p: u for p, u in filtered.items() if is_social(p)}
        dev = {p: u for p, u in filtered.items() if is_dev(p)}
        other = {p: u for p, u in filtered.items() if not is_social(p) and not is_dev(p)}
        sections = []
        if social:
            lines = "\n".join([f"• [{p}]({u})" for p, u in social.items()])
            sections.append(f"📱 *Social Media* ({len(social)})\n{lines}")
        if dev:
            lines = "\n".join([f"• [{p}]({u})" for p, u in dev.items()])
            sections.append(f"💻 *Developer* ({len(dev)})\n{lines}")
        if other:
            lines = "\n".join([f"• [{p}]({u})" for p, u in list(other.items())[:20]])
            sections.append(f"🌐 *Other* ({len(other)})\n{lines}")
            if len(other) > 20:
                sections[-1] += f"\n_...and {len(other) - 20} more_"
        return "\n\n".join(sections)
    elif filter_type == "social":
        lines = "\n".join([f"• [{p}]({u})" for p, u in filtered.items()])
        return f"📱 *Social Media* ({len(filtered)})\n{lines}"
    else:
        lines = "\n".join([f"• [{p}]({u})" for p, u in filtered.items()])
        return f"💻 *Developer* ({len(filtered)})\n{lines}"

def _run_sherlock(username: str) -> dict:
    try:
        import subprocess
        result = subprocess.run(
            ["py", "-3.11", "-m", "sherlock_project.sherlock", username,
             "--print-found", "--no-color", "--timeout", "10"],
            capture_output=True, text=True, timeout=120,
            cwd=os.path.expanduser("~")
        )
        found = {}
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            line = line.strip()
            if "[+]" in line:
                parts = line.split("[+]", 1)
                if len(parts) > 1:
                    rest = parts[1].strip()
                    if "http" in rest:
                        if ": http" in rest:
                            platform = rest.split(":")[0].strip()
                            url = "http" + rest.split(": http", 1)[1].strip()
                        else:
                            platform = rest.split(" ")[0].strip()
                            url = rest.strip()
                        if platform and url:
                            found[platform] = url
        return found
    except Exception as e:
        logger.error(f"Sherlock error: {e}")
        return {}

async def virustotal_scan_url(session: aiohttp.ClientSession, url: str) -> dict:
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        async with session.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        ) as resp:
            data = await resp.json()
            if "data" not in data:
                return {"error": "Could not submit URL"}
            analysis_id = data["data"]["id"]
        await asyncio.sleep(3)
        async with session.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        ) as resp:
            result = await resp.json()
            stats = result.get("data", {}).get("attributes", {}).get("stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
    except Exception as e:
        return {"error": str(e)}

async def urlscan_scan(session: aiohttp.ClientSession, url: str) -> dict:
    try:
        headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
        async with session.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"}
        ) as resp:
            data = await resp.json()
            if "uuid" not in data:
                return {"error": "Scan not initiated"}
            uuid = data["uuid"]
            result_url = f"https://urlscan.io/result/{uuid}/"
        await asyncio.sleep(10)
        async with session.get(f"https://urlscan.io/api/v1/result/{uuid}/") as resp:
            if resp.status == 200:
                result = await resp.json()
                verdicts = result.get("verdicts", {}).get("overall", {})
                page = result.get("page", {})
                return {
                    "malicious": verdicts.get("malicious", False),
                    "score": verdicts.get("score", 0),
                    "categories": verdicts.get("categories", []),
                    "domain": page.get("domain", "unknown"),
                    "ip": page.get("ip", "unknown"),
                    "country": page.get("country", "unknown"),
                    "result_url": result_url,
                }
            return {"error": "Result not ready yet", "result_url": result_url}
    except Exception as e:
        return {"error": str(e)}

async def google_safe_browsing_check(session: aiohttp.ClientSession, url: str) -> dict:
    try:
        payload = {
            "client": {"clientId": "pulseguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        async with session.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}",
            json=payload
        ) as resp:
            data = await resp.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = list(set([m.get("threatType", "UNKNOWN") for m in matches]))
                return {"malicious": True, "threats": threat_types}
            return {"malicious": False, "threats": []}
    except Exception as e:
        return {"error": str(e)}

async def abuseipdb_check(session: aiohttp.ClientSession, ip: str) -> dict:
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params
        ) as resp:
            data = await resp.json()
            d = data.get("data", {})
            return {
                "ip": d.get("ipAddress"),
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "country": d.get("countryCode", "Unknown"),
                "isp": d.get("isp", "Unknown"),
                "usage_type": d.get("usageType", "Unknown"),
                "total_reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt", "Never"),
                "is_tor": d.get("isTor", False),
                "is_public": d.get("isPublic", True),
            }
    except Exception as e:
        return {"error": str(e)}

async def ipinfo_lookup(session: aiohttp.ClientSession, ip: str) -> dict:
    try:
        async with session.get(
            f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
        ) as resp:
            data = await resp.json()
            privacy = data.get("privacy", {})
            return {
                "ip": data.get("ip"),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": data.get("country", "Unknown"),
                "org": data.get("org", "Unknown"),
                "timezone": data.get("timezone", "Unknown"),
                "vpn": privacy.get("vpn", False),
                "proxy": privacy.get("proxy", False),
                "tor": privacy.get("tor", False),
                "hosting": privacy.get("hosting", False),
            }
    except Exception as e:
        return {"error": str(e)}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    text = (
        f"🛡️ *Welcome to PulseGuard, {user.first_name}*\n\n"
        "Your personal threat intelligence bot. Built by PulseAI.\n\n"
        "*What I can do:*\n"
        "🔗 `/scanlink <url>` — Scan a link for phishing & malware\n"
        "🌐 `/scanip <ip>` — Look up an IP address\n"
        "🖼️ `/scanimage` — Reverse image search for catfishing\n"
        "👤 `/scanusername <username>` — Find accounts across platforms\n"
        "🔎 `/whois <domain>` — Domain registration info\n"
        "📧 `/scanemail <email>` — Analyze a suspicious email address\n"
        "📍 `/myip` — Look up your own IP info\n"
        "📋 `/platforms` — See all platforms we check\n"
        "ℹ️ `/help` — Show all commands\n\n"
        "_Stay safe out there._\n\n"
        "〔 [pulseai.qa](https://pulseai.qa) 〕"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🛡️ *PulseGuard Commands*\n\n"
        "*Link Scanning*\n"
        "`/scanlink <url>` — Full phishing & malware scan\n\n"
        "*IP Intelligence*\n"
        "`/scanip <ip>` — Geolocation, ISP, abuse history\n"
        "`/myip` — Look up your own IP\n\n"
        "*Image Search*\n"
        "`/scanimage` — Reverse image search\n\n"
        "*OSINT*\n"
        "`/scanusername <username>` — Find accounts on platforms\n"
        "`/whois <domain>` — Domain registration lookup\n"
        "`/scanemail <email>` — Analyze suspicious email address\n"
        "`/platforms` — See all platforms we check\n\n"
        "━━━━━━━━━━━━━━\n"
        "_Powered by VirusTotal • URLScan • Google Safe Browsing • AbuseIPDB • IPInfo • Sherlock_\n"
        "_Built by [PulseAI](https://pulseai.qa)_"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🛡️ *PulseGuard by PulseAI*\n\n"
        "A free threat intelligence tool for everyone.\n\n"
        "Scan suspicious links before you click them.\n"
        "Look up IPs to check if they're malicious.\n"
        "Reverse search images to catch catfish.\n"
        "Find accounts across the internet.\n"
        "Know what's out there before it hits you.\n\n"
        "Built during a time when digital safety matters more than ever.\n\n"
        "🌐 [pulseai.qa](https://pulseai.qa)\n"
        "Built by Najla Al Maadeed"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

async def scanlink(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide a URL.\nExample: `/scanlink https://example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    url = context.args[0]
    if not is_valid_url(url):
        await update.message.reply_text(
            "⚠️ That doesn't look like a valid URL. Make sure it starts with `http://` or `https://`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    msg = await update.message.reply_text("🔍 Scanning link... this takes ~15 seconds.")
    async with aiohttp.ClientSession() as session:
        vt_task = virustotal_scan_url(session, url)
        us_task = urlscan_scan(session, url)
        gsb_task = google_safe_browsing_check(session, url)
        vt, us, gsb = await asyncio.gather(vt_task, us_task, gsb_task)

    vt_malicious = vt.get("malicious", 0) if "error" not in vt else 0
    vt_suspicious = vt.get("suspicious", 0) if "error" not in vt else 0
    us_malicious = us.get("malicious", False) if "error" not in us else False
    gsb_malicious = gsb.get("malicious", False) if "error" not in gsb else False
    total_flags = vt_malicious + vt_suspicious + (1 if us_malicious else 0) + (1 if gsb_malicious else 0)

    if total_flags == 0:
        verdict = "✅ *CLEAN*"
        verdict_line = "No threats detected."
    elif total_flags <= 2:
        verdict = "⚠️ *SUSPICIOUS*"
        verdict_line = "Treat with caution."
    else:
        verdict = "🚨 *MALICIOUS*"
        verdict_line = "Do NOT visit this site."

    if "error" not in vt:
        vt_section = (
            f"*VirusTotal*\n"
            f"Malicious: `{vt['malicious']}` engines\n"
            f"Suspicious: `{vt['suspicious']}` engines\n"
            f"Clean: `{vt['harmless']}` engines"
        )
    else:
        vt_section = f"*VirusTotal*\n`Error: {vt['error']}`"

    if "error" not in gsb:
        if gsb_malicious:
            threats = ", ".join([t.replace("_", " ").title() for t in gsb.get("threats", [])])
            gsb_section = f"*Google Safe Browsing*\n🚨 Threat detected: `{threats}`"
        else:
            gsb_section = f"*Google Safe Browsing*\n✅ No threats found"
    else:
        gsb_section = f"*Google Safe Browsing*\n`Error checking`"

    if "error" not in us:
        categories = ", ".join(us.get("categories", [])) or "None"
        us_section = (
            f"*URLScan*\n"
            f"Domain: `{us.get('domain', 'unknown')}`\n"
            f"Hosted in: `{us.get('country', 'unknown')}`\n"
            f"Malicious: `{'Yes' if us.get('malicious') else 'No'}`\n"
            f"Categories: `{categories}`\n"
            f"[Full report]({us.get('result_url', '')})"
        )
    else:
        us_section = f"*URLScan*\n`{us.get('error', 'Error')}`"

    text = (
        f"🔗 *Link Scan Report*\n"
        f"━━━━━━━━━━━━━━\n"
        f"`{url[:60]}{'...' if len(url) > 60 else ''}`\n\n"
        f"Verdict: {verdict}\n"
        f"{verdict_line}\n\n"
        f"{vt_section}\n\n"
        f"{gsb_section}\n\n"
        f"{us_section}\n\n"
        f"━━━━━━━━━━━━━━\n"
        f"_PulseGuard by [PulseAI](https://pulseai.qa)_"
    )
    await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

async def scanip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide an IP address.\nExample: `/scanip 1.2.3.4`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    ip = context.args[0]
    if not is_valid_ip(ip):
        await update.message.reply_text(
            "⚠️ That doesn't look like a valid IP address.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    msg = await update.message.reply_text("🌐 Looking up IP...")
    async with aiohttp.ClientSession() as session:
        abuse_task = abuseipdb_check(session, ip)
        info_task = ipinfo_lookup(session, ip)
        abuse, info = await asyncio.gather(abuse_task, info_task)
    abuse_score = abuse.get("abuse_score", 0) if "error" not in abuse else 0
    is_tor = abuse.get("is_tor", False) or info.get("tor", False)
    is_vpn = info.get("vpn", False)
    if abuse_score >= 50:
        verdict = "🚨 *HIGH RISK*"
    elif abuse_score >= 15:
        verdict = "⚠️ *SUSPICIOUS*"
    else:
        verdict = "✅ *CLEAN*"
    if "error" not in abuse:
        abuse_section = (
            f"*Abuse Intelligence*\n"
            f"Risk Score: `{abuse['abuse_score']}%`\n"
            f"Total Reports: `{format_number(abuse['total_reports'])}`\n"
            f"Last Reported: `{abuse['last_reported'] or 'Never'}`"
        )
    else:
        abuse_section = f"*Abuse Intelligence*\n`Error fetching data`"
    if "error" not in info:
        flags = []
        if is_tor: flags.append("🧅 Tor exit node")
        if is_vpn: flags.append("🔒 VPN")
        if info.get("proxy"): flags.append("🔀 Proxy")
        if info.get("hosting"): flags.append("🖥️ Hosting/datacenter")
        flags_line = "\n".join(flags) if flags else "None detected"
        info_section = (
            f"*Geolocation*\n"
            f"Location: `{info['city']}, {info['region']}, {info['country']}`\n"
            f"ISP/Org: `{info['org']}`\n"
            f"Timezone: `{info['timezone']}`\n\n"
            f"*Privacy Flags*\n{flags_line}"
        )
    else:
        info_section = f"*Geolocation*\n`Error fetching data`"
    text = (
        f"🌐 *IP Scan Report*\n"
        f"━━━━━━━━━━━━━━\n"
        f"IP: `{ip}`\n\n"
        f"Verdict: {verdict}\n\n"
        f"{abuse_section}\n\n"
        f"{info_section}\n\n"
        f"━━━━━━━━━━━━━━\n"
        f"_PulseGuard by [PulseAI](https://pulseai.qa)_"
    )
    await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)

async def myip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = await update.message.reply_text("📍 Looking up your IP...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://ipinfo.io/json?token=" + IPINFO_TOKEN) as resp:
                data = await resp.json()
        privacy = data.get("privacy", {})
        flags = []
        if privacy.get("vpn"): flags.append("🔒 VPN detected")
        if privacy.get("proxy"): flags.append("🔀 Proxy detected")
        if privacy.get("tor"): flags.append("🧅 Tor detected")
        if privacy.get("hosting"): flags.append("🖥️ Hosting/datacenter")
        flags_line = "\n".join(flags) if flags else "No anonymization detected"
        text = (
            f"📍 *Your IP Info*\n"
            f"━━━━━━━━━━━━━━\n\n"
            f"IP: `{data.get('ip', 'Unknown')}`\n"
            f"Location: `{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}`\n"
            f"ISP: `{data.get('org', 'Unknown')}`\n"
            f"Timezone: `{data.get('timezone', 'Unknown')}`\n\n"
            f"*Privacy Status*\n{flags_line}\n\n"
            f"━━━━━━━━━━━━━━\n"
            f"_PulseGuard by [PulseAI](https://pulseai.qa)_"
        )
        await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{str(e)}`", parse_mode=ParseMode.MARKDOWN)

async def platforms(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(PLATFORMS_LIST, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

async def scanusername(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide a username.\nExample: `/scanusername johndoe`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    username = context.args[0]
    keyboard = [
        [InlineKeyboardButton("📱 Social media only", callback_data=f"uscan_social_{username}")],
        [InlineKeyboardButton("💻 Developer platforms only", callback_data=f"uscan_dev_{username}")],
        [InlineKeyboardButton("🌐 Everything", callback_data=f"uscan_all_{username}")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        f"👤 Scanning username: `{username}`\n\nWhat are you looking for?",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup
    )

async def scanusername_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    parts = data.split("_", 2)
    filter_type = parts[1]
    username = parts[2]
    filter_labels = {
        "social": "social media platforms",
        "dev": "developer platforms",
        "all": "all platforms"
    }
    await query.edit_message_text(
        f"👤 Scanning `{username}` across {filter_labels.get(filter_type, 'all platforms')}...\n_This takes ~30 seconds._",
        parse_mode=ParseMode.MARKDOWN
    )
    loop = asyncio.get_event_loop()
    found = await loop.run_in_executor(None, lambda: _run_sherlock(username))
    found = clean_results(found, username)
    if not found:
        await query.edit_message_text(
            f"👤 *Username Scan: `{username}`*\n"
            f"━━━━━━━━━━━━━━\n\n"
            f"✅ Not found on any checked platforms.\n\n"
            f"━━━━━━━━━━━━━━\n"
            f"_PulseGuard by [PulseAI](https://pulseai.qa)_",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    body = format_results(found, filter_type, username)
    total = len(found)
    text = (
        f"👤 *Username Scan: `{username}`*\n"
        f"━━━━━━━━━━━━━━\n\n"
        f"Found on *{total} platform{'s' if total != 1 else ''}* total\n\n"
        f"{body}\n\n"
        f"━━━━━━━━━━━━━━\n"
        f"_PulseGuard by [PulseAI](https://pulseai.qa)_"
    )
    if len(text) > 4000:
        text = text[:3900] + "\n\n_...truncated. Use social/dev filter for cleaner results._\n\n━━━━━━━━━━━━━━\n_PulseGuard by [PulseAI](https://pulseai.qa)_"
    await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

async def whois_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide a domain.\nExample: `/whois google.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    domain = context.args[0].replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
    msg = await update.message.reply_text(f"🔎 Looking up `{domain}`...")
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, lambda: whois.whois(domain))
        creation = w.creation_date
        expiry = w.expiration_date
        updated = w.updated_date
        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiry, list): expiry = expiry[0]
        if isinstance(updated, list): updated = updated[0]
        creation_str = creation.strftime("%Y-%m-%d") if creation else "Unknown"
        expiry_str = expiry.strftime("%Y-%m-%d") if expiry else "Unknown"
        updated_str = updated.strftime("%Y-%m-%d") if updated else "Unknown"
        age_warning = ""
        if creation:
            age_days = (datetime.now() - creation).days
            if age_days < 30:
                age_warning = "🚨 *Domain created less than 30 days ago — high phishing risk*\n\n"
            elif age_days < 180:
                age_warning = "⚠️ *Domain is less than 6 months old — treat with caution*\n\n"
        registrar = w.registrar or "Unknown"
        country = w.country or "Unknown"
        name_servers = w.name_servers
        if isinstance(name_servers, list):
            name_servers = "\n".join([f"  `{ns}`" for ns in list(name_servers)[:3]])
        else:
            name_servers = f"`{name_servers}`" if name_servers else "Unknown"
        text = (
            f"🔎 *WHOIS: `{domain}`*\n"
            f"━━━━━━━━━━━━━━\n\n"
            f"{age_warning}"
            f"Registrar: `{registrar}`\n"
            f"Country: `{country}`\n"
            f"Created: `{creation_str}`\n"
            f"Expires: `{expiry_str}`\n"
            f"Updated: `{updated_str}`\n\n"
            f"*Name Servers*\n{name_servers}\n\n"
            f"━━━━━━━━━━━━━━\n"
            f"_PulseGuard by [PulseAI](https://pulseai.qa)_"
        )
        await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        if "No match" in str(e) or "No whois" in str(e):
            await msg.edit_text(
                f"🔎 *WHOIS: `{domain}`*\n"
                f"━━━━━━━━━━━━━━\n\n"
                f"🚨 *Domain does not exist*\n"
                f"This domain is not registered — if someone sent you a link to this site, it's either fake or newly created.\n\n"
                f"━━━━━━━━━━━━━━\n"
                f"_PulseGuard by [PulseAI](https://pulseai.qa)_",
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await msg.edit_text(f"❌ Error looking up domain: `{str(e)[:100]}`", parse_mode=ParseMode.MARKDOWN)

async def scanemail(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide an email address.\nExample: `/scanemail suspicious@example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    email = context.args[0]
    if "@" not in email or "." not in email.split("@")[-1]:
        await update.message.reply_text(
            "⚠️ That doesn't look like a valid email address.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    msg = await update.message.reply_text(f"📧 Analyzing `{email}`...")
    try:
        domain = email.split("@")[1]
        flags = []
        info_lines = []
        try:
            loop = asyncio.get_event_loop()
            mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, "MX"))
            mx_list = [str(r.exchange) for r in mx_records]
            info_lines.append(f"Mail servers: `{', '.join(mx_list[:2])}`")
        except:
            flags.append("🚨 No MX records — domain cannot receive email")
            info_lines.append("Mail servers: `None found`")
        try:
            loop = asyncio.get_event_loop()
            a_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, "A"))
            info_lines.append(f"Domain IP: `{str(list(a_records)[0])}`")
        except:
            flags.append("🚨 Domain does not resolve — likely fake")
        try:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, lambda: whois.whois(domain))
            creation = w.creation_date
            if isinstance(creation, list): creation = creation[0]
            if creation:
                age_days = (datetime.now() - creation).days
                info_lines.append(f"Domain age: `{age_days} days`")
                if age_days < 30:
                    flags.append("🚨 Domain created less than 30 days ago")
                elif age_days < 180:
                    flags.append("⚠️ Domain less than 6 months old")
        except:
            flags.append("⚠️ Could not retrieve domain registration info")
        disposable = ["mailinator.com", "tempmail.com", "guerrillamail.com", "10minutemail.com",
                      "throwam.com", "yopmail.com", "sharklasers.com", "trashmail.com",
                      "fakeinbox.com", "dispostable.com", "maildrop.cc", "spamgourmet.com"]
        if domain.lower() in disposable:
            flags.append("🚨 Disposable/temporary email service")
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"]
        if domain.lower() in free_providers:
            info_lines.append(f"Provider: `{domain} (free email provider)`")
        else:
            info_lines.append(f"Provider: `{domain} (custom domain)`")
        flags_text = "\n".join(flags) if flags else "✅ No red flags detected"
        info_text = "\n".join(info_lines)
        if flags:
            verdict = "🚨 *SUSPICIOUS*" if any("🚨" in f for f in flags) else "⚠️ *CAUTION*"
        else:
            verdict = "✅ *LOOKS LEGITIMATE*"
        text = (
            f"📧 *Email Analysis*\n"
            f"━━━━━━━━━━━━━━\n\n"
            f"Email: `{email}`\n"
            f"Verdict: {verdict}\n\n"
            f"*Domain Info*\n{info_text}\n\n"
            f"*Red Flags*\n{flags_text}\n\n"
            f"━━━━━━━━━━━━━━\n"
            f"_PulseGuard by [PulseAI](https://pulseai.qa)_"
        )
        await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        await msg.edit_text(f"❌ Error analyzing email: `{str(e)}`", parse_mode=ParseMode.MARKDOWN)

async def scanimage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.photo:
        await update.message.reply_text(
            "📸 Send me a photo to scan. Just attach an image to your message.",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    msg = await update.message.reply_text("🔍 Getting image search links...")
    try:
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id)
        file_url = file.file_path
        google_lens = f"https://lens.google.com/uploadbyurl?url={file_url}"
        yandex = f"https://yandex.com/images/search?rpt=imageview&url={file_url}"
        tineye = f"https://www.tineye.com/search?url={file_url}"
        text = (
            f"🖼️ *Reverse Image Search*\n"
            f"━━━━━━━━━━━━━━\n\n"
            f"Click the links below to search this image:\n\n"
            f"🔍 [Google Lens]({google_lens})\n"
            f"🟡 [Yandex Images]({yandex})\n"
            f"👁️ [TinEye]({tineye})\n\n"
            f"_Yandex is best for finding faces & catfish._\n"
            f"_Google Lens is best for objects & places._\n\n"
            f"━━━━━━━━━━━━━━\n"
            f"_PulseGuard by [PulseAI](https://pulseai.qa)_"
        )
        await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{str(e)}`", parse_mode=ParseMode.MARKDOWN)

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if is_valid_url(text):
        context.args = [text]
        await scanlink(update, context)
    elif is_valid_ip(text):
        context.args = [text]
        await scanip(update, context)
    else:
        await update.message.reply_text(
            "Send me a URL or IP to scan, or use /help to see all commands.",
            parse_mode=ParseMode.MARKDOWN
        )

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("about", about))
    app.add_handler(CommandHandler("scanlink", scanlink))
    app.add_handler(CommandHandler("scanip", scanip))
    app.add_handler(CommandHandler("myip", myip))
    app.add_handler(CommandHandler("scanusername", scanusername))
    app.add_handler(CommandHandler("whois", whois_lookup))
    app.add_handler(CommandHandler("scanemail", scanemail))
    app.add_handler(CommandHandler("scanimage", scanimage))
    app.add_handler(CommandHandler("platforms", platforms))
    app.add_handler(CallbackQueryHandler(scanusername_callback, pattern="^uscan_"))
    app.add_handler(MessageHandler(filters.PHOTO, scanimage))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    logger.info("PulseGuard is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
