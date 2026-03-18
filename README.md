# PulseGuard
PulseGuard by PulseAI — your personal cybersecurity scanner.   🔗 Scan any link before you click it 🌐 Look up any IP address 🛡️ Powered by VirusTotal, URLScan, AbuseIPDB &amp; IPInfo  Free to use. Built in Qatar. 🌐 pulseai.qa
# PulseGuard Setup Guide

## 1. Install Python dependencies
```
pip install -r requirements.txt
```

## 2. Fill in your API keys
Open bot.py and replace the placeholders at the top:
- API KEY FOR TELEGRAM    → your BotFather token
- API KEY FOR VIRUSTOTAL  → from virustotal.com/gui/my-apikey
- API KEY FOR ABUSEIPDB   → from abuseipdb.com/account/api
- API KEY FOR IPINFO      → from ipinfo.io/account/token
- API KEY FOR URLSCAN     → from urlscan.io/user/profile/

## 3. Run the bot
```
python bot.py
```

## 4. Test it
Open Telegram, find your bot, send:
- /start
- /scanlink https://google.com
- /scanip 8.8.8.8

## 5. Keep it running 24/7 (optional)
Run on a VPS using screen or systemd:
```
screen -S pulseguard
python bot.py
# Ctrl+A then D to detach
```
