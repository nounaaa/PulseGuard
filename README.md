# 🛡️ PulseGuard

**Free threat intelligence Telegram bot built by [PulseAI](https://pulseai.qa)**

PulseGuard is an open-source cybersecurity tool that lets anyone scan suspicious links, look up IPs, reverse search images, investigate usernames, and analyze email addresses — all from Telegram. No technical knowledge required.

Built in Qatar during a time when digital safety matters more than ever.

---

## 🤖 Try it

**[@PulseGuardBot](https://t.me/YourBotUsername)** on Telegram — free

---

## ✨ Features

| Command | Description |
|---|---|
| `/scanlink <url>` | Scan a URL for phishing & malware across 70+ engines |
| `/scanip <ip>` | Geolocate an IP, check abuse history, detect VPN/Tor/proxy |
| `/scanimage` | Reverse image search via Google Lens, Yandex & TinEye |
| `/scanusername <username>` | Find accounts across 300+ platforms (social, dev, gaming) |
| `/whois <domain>` | Domain registration info, age, registrar, nameservers |
| `/scanemail <email>` | Analyze email for red flags — disposable, fake domains, no MX |
| `/myip` | Look up your own IP info and privacy status |
| `/platforms` | See all platforms checked by username scanner |

---

## 🔌 Powered by

- [VirusTotal](https://virustotal.com) — 70+ antivirus & threat engines
- [Google Safe Browsing](https://developers.google.com/safe-browsing) — phishing & malware database
- [URLScan.io](https://urlscan.io) — deep link analysis & screenshots
- [AbuseIPDB](https://abuseipdb.com) — IP abuse & attack history
- [IPInfo](https://ipinfo.io) — geolocation, ISP, VPN/Tor detection
- [Sherlock](https://github.com/sherlock-project/sherlock) — username OSINT across 300+ sites

---

## 🚀 Self-hosting

### Requirements
- Python 3.11
- Chrome (for image search)

### Setup

**1. Clone the repo**
```bash
git clone https://github.com/yourusername/pulseguard.git
cd pulseguard
```

**2. Install dependencies**
```bash
pip install python-telegram-bot==20.7 aiohttp==3.9.1 selenium webdriver-manager python-whois dnspython sherlock-project
```

**3. Get your API keys**

| Service | Free tier | Link |
|---|---|---|
| Telegram Bot | Free | [@BotFather](https://t.me/BotFather) |
| VirusTotal | 500 req/day | [virustotal.com](https://virustotal.com) |
| URLScan | 100 scans/day | [urlscan.io](https://urlscan.io) |
| AbuseIPDB | 1000 checks/day | [abuseipdb.com](https://abuseipdb.com) |
| IPInfo | 50k req/month | [ipinfo.io](https://ipinfo.io) |
| Google Safe Browsing | Free | [console.cloud.google.com](https://console.cloud.google.com) |

**4. Add your keys**

Open `bot.py` and fill in the API keys at the top:
```python
TELEGRAM_TOKEN           = "your token here"
VIRUSTOTAL_KEY           = "your key here"
ABUSEIPDB_KEY            = "your key here"
IPINFO_TOKEN             = "your token here"
URLSCAN_KEY              = "your key here"
GOOGLE_SAFE_BROWSING_KEY = "your key here"
```

**5. Run**
```bash
python bot.py
```

---

## 🗺️ Roadmap

- [ ] File scanner (PDF, exe, zip via VirusTotal)
- [ ] Phone number lookup
- [ ] Dark web mention checker
- [ ] Web dashboard on pulseai.qa
- [ ] Arabic language support

---

## ⚠️ Disclaimer

PulseGuard is built for defensive and educational purposes only. All scanning is performed using publicly available APIs. Do not use this tool to investigate individuals without consent. The developer is not responsible for misuse.

---

## 👩‍💻 Built by

**Najla Al Maadeed** — Cybersecurity student & founder of [PulseAI](https://pulseai.qa), Doha, Qatar.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](www.linkedin.com/in/najlaalmaadeed)
[![PulseAI](https://img.shields.io/badge/PulseAI-pulseai.qa-brightgreen)](https://pulseai.qa)

---

## 📄 License

MIT License — free to use, modify, and distribute.
