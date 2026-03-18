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
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ── HELPERS ───────────────────────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))

def is_valid_url(url: str) -> bool:
    return url.startswith(("http://", "https://", "www."))

def risk_emoji(score: int) -> str:
    if score == 0:
        return "✅"
    elif score <= 3:
        return "⚠️"
    else:
        return "🚨"

def format_number(n: int) -> str:
    return f"{n:,}"

# ── API CALLS ─────────────────────────────────────────────────────────────────

async def virustotal_scan_url(session: aiohttp.ClientSession, url: str) -> dict:
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        # Submit URL for scanning
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

        # Get results
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
        headers = {
            "API-Key": URLSCAN_KEY,
            "Content-Type": "application/json"
        }
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

async def abuseipdb_check(session: aiohttp.ClientSession, ip: str) -> dict:
    try:
        headers = {
            "Key": ABUSEIPDB_KEY,
            "Accept": "application/json"
        }
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

# ── COMMAND HANDLERS ──────────────────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    text = (
        f"🛡️ *Welcome to PulseGuard, {user.first_name}*\n\n"
        "Your personal threat intelligence bot. Built by PulseAI.\n\n"
        "*What I can do:*\n"
        "🔗 `/scanlink <url>` — Scan a link for phishing & malware\n"
        "🌐 `/scanip <ip>` — Look up an IP address\n"
        "ℹ️ `/help` — Show all commands\n\n"
        "_Stay safe out there._\n\n"
        "〔 [pulseai.qa](https://pulseai.qa) 〕"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🛡️ *PulseGuard Commands*\n\n"
        "*Link Scanning*\n"
        "`/scanlink <url>` — Full phishing & malware scan\n"
        "Example: `/scanlink https://suspicious-site.com`\n\n"
        "*IP Intelligence*\n"
        "`/scanip <ip>` — Geolocation, ISP, abuse history\n"
        "Example: `/scanip 1.2.3.4`\n\n"
        "*About*\n"
        "`/about` — About PulseGuard\n\n"
        "━━━━━━━━━━━━━━\n"
        "_Powered by VirusTotal • URLScan • AbuseIPDB • IPInfo_\n"
        "_Built by [PulseAI](https://pulseai.qa)_"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🛡️ *PulseGuard by PulseAI*\n\n"
        "A free threat intelligence tool for everyone.\n\n"
        "Scan suspicious links before you click them.\n"
        "Look up IPs to check if they're malicious.\n"
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
        vt, us = await asyncio.gather(vt_task, us_task)

    # Build verdict
    vt_malicious = vt.get("malicious", 0) if "error" not in vt else 0
    vt_suspicious = vt.get("suspicious", 0) if "error" not in vt else 0
    us_malicious = us.get("malicious", False) if "error" not in us else False
    total_flags = vt_malicious + vt_suspicious + (1 if us_malicious else 0)

    if total_flags == 0:
        verdict = "✅ *CLEAN*"
        verdict_line = "No threats detected."
    elif total_flags <= 3:
        verdict = "⚠️ *SUSPICIOUS*"
        verdict_line = "Treat with caution."
    else:
        verdict = "🚨 *MALICIOUS*"
        verdict_line = "Do NOT visit this site."

    # VirusTotal section
    if "error" not in vt:
        vt_section = (
            f"*VirusTotal*\n"
            f"Malicious: `{vt['malicious']}` engines\n"
            f"Suspicious: `{vt['suspicious']}` engines\n"
            f"Clean: `{vt['harmless']}` engines"
        )
    else:
        vt_section = f"*VirusTotal*\n`Error: {vt['error']}`"

    # URLScan section
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

    # Verdict
    abuse_score = abuse.get("abuse_score", 0) if "error" not in abuse else 0
    is_tor = abuse.get("is_tor", False) or info.get("tor", False)
    is_vpn = info.get("vpn", False)

    if abuse_score >= 50:
        verdict = "🚨 *HIGH RISK*"
    elif abuse_score >= 15:
        verdict = "⚠️ *SUSPICIOUS*"
    else:
        verdict = "✅ *CLEAN*"

    # AbuseIPDB section
    if "error" not in abuse:
        abuse_section = (
            f"*Abuse Intelligence*\n"
            f"Risk Score: `{abuse['abuse_score']}%`\n"
            f"Total Reports: `{format_number(abuse['total_reports'])}`\n"
            f"Last Reported: `{abuse['last_reported'] or 'Never'}`"
        )
    else:
        abuse_section = f"*Abuse Intelligence*\n`Error fetching data`"

    # IPInfo section
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

# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("about", about))
    app.add_handler(CommandHandler("scanlink", scanlink))
    app.add_handler(CommandHandler("scanip", scanip))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("PulseGuard is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
