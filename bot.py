
"""
Telegram Xavfsizlik Boti — Snort/IDS uslubida
Windows uchun: faqat standart + telegram kutubxonasi kerak
O'rnatish: pip install python-telegram-bot
"""

import os
import re
import io
import hashlib
import zipfile
import logging
import struct
from pathlib import Path
from datetime import datetime

from telegram import Update, Message
from telegram.ext import (
    Application, MessageHandler, CommandHandler,
    filters, ContextTypes
)

# ─── BOT SOZLAMALARI ──────────────────────────────────────────────────────────
BOT_TOKEN  = "8426714435:AAEQmDOX5qZtZQYxmNa7CnoTyRObCSHIDmg"
LOG_CHAT_ID = None   # Admin ID (ixtiyoriy): 123456789

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO
)
log = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
#  SNORT USLUBIDA QOIDALAR (rules)
# ══════════════════════════════════════════════════════════════════════════════

# Har bir qoida: (id, tavsif, xavf_darajasi)
EXTENSION_RULES = {
    # Android
    ".apk":  ("SID:1001", "Android ilovasi — zararli bo'lishi mumkin",       "HIGH"),
    ".xapk": ("SID:1002", "Android to'plam fayli",                           "HIGH"),
    # Windows bajariladigan
    ".exe":  ("SID:2001", "Windows PE bajariladigan fayl",                   "CRITICAL"),
    ".msi":  ("SID:2002", "Windows o'rnatuvchi paketi",                      "CRITICAL"),
    ".bat":  ("SID:2003", "Windows Batch skript",                            "CRITICAL"),
    ".cmd":  ("SID:2004", "Windows CMD skript",                              "CRITICAL"),
    ".ps1":  ("SID:2005", "PowerShell skript — RAT/Troyan vositasi",        "CRITICAL"),
    ".vbs":  ("SID:2006", "VBScript — klassik zararli skript",              "CRITICAL"),
    ".hta":  ("SID:2007", "HTML Application — bajariladigan",               "CRITICAL"),
    ".pif":  ("SID:2008", "Program Information File — zararli",             "CRITICAL"),
    ".scr":  ("SID:2009", "Windows screensaver — zararli bo'lishi mumkin",  "HIGH"),
    # Tizim
    ".dll":  ("SID:3001", "Windows DLL — injeksiya xavfi",                  "CRITICAL"),
    ".sys":  ("SID:3002", "Windows kernel drayveri",                        "CRITICAL"),
    ".drv":  ("SID:3003", "Windows drayver fayli",                          "HIGH"),
    # Skriptlar
    ".js":   ("SID:4001", "JavaScript — dropper bo'lishi mumkin",           "HIGH"),
    ".jse":  ("SID:4002", "Encoded JavaScript — yashirilgan skript",        "CRITICAL"),
    ".wsh":  ("SID:4003", "Windows Script Host fayli",                      "HIGH"),
    ".wsf":  ("SID:4004", "Windows Script File",                            "HIGH"),
    ".jar":  ("SID:4005", "Java arxivi — bajariladigan",                    "HIGH"),
    ".py":   ("SID:4006", "Python skript",                                  "MEDIUM"),
    ".sh":   ("SID:4007", "Shell skript",                                   "HIGH"),
    # Arxivlar
    ".zip":  ("SID:5001", "ZIP arxivi — ichida xavfli fayl bo'lishi mumkin","MEDIUM"),
    ".rar":  ("SID:5002", "RAR arxivi",                                     "MEDIUM"),
    ".7z":   ("SID:5003", "7-Zip arxivi",                                   "MEDIUM"),
    ".tar":  ("SID:5004", "TAR arxivi",                                     "MEDIUM"),
    ".gz":   ("SID:5005", "GZIP siqilgan fayl",                             "MEDIUM"),
    ".iso":  ("SID:5006", "Disk tasviri — zararli bo'lishi mumkin",         "HIGH"),
    # Office makro
    ".docm": ("SID:6001", "Word makro — keng tarqalgan hujum usuli",        "HIGH"),
    ".xlsm": ("SID:6002", "Excel makro fayli",                              "HIGH"),
    ".pptm": ("SID:6003", "PowerPoint makro fayli",                         "HIGH"),
    ".xlam": ("SID:6004", "Excel Add-in — zararli bo'lishi mumkin",         "HIGH"),
}

# Snort kabi Magic Bytes imzolari
MAGIC_RULES = [
    ("SID:7001", b"MZ",                   "Windows PE bajariladigan (MZ header)",   "CRITICAL"),
    ("SID:7002", b"\x7fELF",              "Linux ELF bajariladigan",                "HIGH"),
    ("SID:7003", b"PK\x03\x04",           "ZIP/APK/JAR arxivi",                    "MEDIUM"),
    ("SID:7004", b"Rar!\x1a\x07",         "RAR arxivi",                            "MEDIUM"),
    ("SID:7005", b"\xca\xfe\xba\xbe",     "Java CLASS fayli",                      "HIGH"),
    ("SID:7006", b"\x7fELF",              "ELF bajariladigan",                     "HIGH"),
    ("SID:7007", b"7z\xbc\xaf\x27\x1c",  "7-Zip arxivi",                          "MEDIUM"),
    ("SID:7008", b"\x1f\x8b",             "GZIP siqilgan fayl",                    "MEDIUM"),
    ("SID:7009", b"MSCF",                 "Microsoft Cabinet fayli",               "HIGH"),
    ("SID:7010", b"#!",                   "Unix shebang — skript fayli",           "MEDIUM"),
]

# ZIP ichidagi xavfli pattern'lar (Snort content matching uslubi)
ZIP_CONTENT_RULES = [
    ("SID:8001", re.compile(r"\.exe$",        re.I), "CRITICAL", "ZIP ichida .exe"),
    ("SID:8002", re.compile(r"\.dll$",        re.I), "CRITICAL", "ZIP ichida .dll"),
    ("SID:8003", re.compile(r"\.bat$",        re.I), "CRITICAL", "ZIP ichida .bat"),
    ("SID:8004", re.compile(r"\.ps1$",        re.I), "CRITICAL", "ZIP ichida PowerShell"),
    ("SID:8005", re.compile(r"\.vbs$",        re.I), "CRITICAL", "ZIP ichida VBScript"),
    ("SID:8006", re.compile(r"autorun\.inf$", re.I), "CRITICAL", "Autorun fayli — USB worm belgisi"),
    ("SID:8007", re.compile(r"\.hta$",        re.I), "CRITICAL", "ZIP ichida HTA"),
    ("SID:8008", re.compile(r"\.scr$",        re.I), "HIGH",     "ZIP ichida Screensaver"),
    ("SID:8009", re.compile(r"\.apk$",        re.I), "HIGH",     "ZIP ichida APK"),
    ("SID:8010", re.compile(r"\.jar$",        re.I), "HIGH",     "ZIP ichida JAR"),
    ("SID:8011", re.compile(r"\.js$",         re.I), "HIGH",     "ZIP ichida JavaScript"),
    ("SID:8012", re.compile(r"desktop\.ini$", re.I), "MEDIUM",   "Windows tizim fayli yashiringan"),
]

# Mazmun ichidagi xavfli string'lar (Snort payload inspection)
PAYLOAD_RULES = [
    ("SID:9001", b"cmd.exe",          "MEDIUM",   "CMD murojaat — shell hujumi"),
    ("SID:9002", b"powershell",       "HIGH",     "PowerShell murojaat"),
    ("SID:9003", b"WScript.Shell",    "HIGH",     "WScript Shell — skript hujumi"),
    ("SID:9004", b"HKEY_LOCAL_MACHINE","MEDIUM",  "Registry murojaat"),
    ("SID:9005", b"CreateObject",     "MEDIUM",   "COM ob'ekt yaratish"),
    ("SID:9006", b"Shell.Application","HIGH",     "Shell ilovasi — privilege escalation"),
    ("SID:9007", b"Net.WebClient",    "HIGH",     "Tarmoq yuklab olish — dropper belgisi"),
    ("SID:9008", b"Invoke-Expression","CRITICAL", "PS IEX — keng tarqalgan RAT usuli"),
    ("SID:9009", b"FromBase64String", "HIGH",     "Base64 dekodlash — yashiringan kod"),
    ("SID:9010", b"bypass",           "HIGH",     "Security bypass urinishi"),
]

# Ma'lum zararli hashlar (MD5 yoki SHA256 qo'shing)
KNOWN_BAD_HASHES: set[str] = {
    # VirusTotal dan olgan real hashlarni shu yerga qo'shing
    # "d41d8cd98f00b204e9800998ecf8427e",
}

# ══════════════════════════════════════════════════════════════════════════════
#  TAHLIL FUNKSIYALARI
# ══════════════════════════════════════════════════════════════════════════════

def compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def check_extension(filename: str) -> list[dict]:
    ext = Path(filename).suffix.lower()
    if ext in EXTENSION_RULES:
        sid, desc, risk = EXTENSION_RULES[ext]
        return [{"sid": sid, "risk": risk, "desc": desc, "category": "EXTENSION"}]
    return []

def check_magic(data: bytes) -> list[dict]:
    results = []
    head = data[:8]
    for sid, sig, desc, risk in MAGIC_RULES:
        if head.startswith(sig):
            results.append({"sid": sid, "risk": risk, "desc": desc, "category": "MAGIC_BYTES"})
    return results

def check_zip_contents(data: bytes) -> list[dict]:
    results = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            for name in names:
                for sid, pat, risk, desc in ZIP_CONTENT_RULES:
                    if pat.search(name):
                        results.append({
                            "sid": sid, "risk": risk,
                            "desc": desc,
                            "detail": name,
                            "category": "ZIP_CONTENT"
                        })
    except Exception:
        pass
    return results

def check_payload(data: bytes, filename: str) -> list[dict]:
    """Matnli fayllar ichida xavfli string'larni qidiradi."""
    results = []
    ext = Path(filename).suffix.lower()
    text_exts = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".wsh", ".wsf", ".py", ".sh"}
    if ext not in text_exts:
        return results
    sample = data[:8192]  # Faqat birinchi 8KB
    for sid, pattern, risk, desc in PAYLOAD_RULES:
        if pattern.lower() in sample.lower():
            results.append({"sid": sid, "risk": risk, "desc": desc, "category": "PAYLOAD"})
    return results

def check_hashes(hashes: dict) -> list[dict]:
    results = []
    for algo, val in hashes.items():
        if val in KNOWN_BAD_HASHES:
            results.append({
                "sid": "SID:0001",
                "risk": "CRITICAL",
                "desc": f"Hash ({algo.upper()}) ma'lum zararli dasturlar bazasida!",
                "category": "HASH_MATCH"
            })
    return results

def overall_risk(alerts: list[dict]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    risks = {a["risk"] for a in alerts}
    for lvl in order:
        if lvl in risks:
            return lvl
    return "CLEAN"

# ══════════════════════════════════════════════════════════════════════════════
#  HISOBOT
# ══════════════════════════════════════════════════════════════════════════════

RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "CLEAN":    "✅",
}

CATEGORY_NAME = {
    "EXTENSION":   "📎 Kengaytma",
    "MAGIC_BYTES": "🔮 Magic Bytes",
    "ZIP_CONTENT": "📦 Arxiv tarkibi",
    "PAYLOAD":     "💉 Payload",
    "HASH_MATCH":  "🧬 Hash bazasi",
}

def build_report(filename: str, size: int, hashes: dict, alerts: list[dict]) -> tuple[str, str]:
    top = overall_risk(alerts)
    e   = RISK_EMOJI[top]
    blocked = top in ("CRITICAL", "HIGH")

    lines = [
        "━" * 38,
        f"{'🚨 XAVFLI FAYL ANIQLANDI' if blocked else '🔍 XAVFSIZLIK TEKSHIRUVI'}",
        "━" * 38,
        f"📄 <b>Fayl:</b> <code>{filename}</code>",
        f"📏 <b>Hajm:</b> {size/1024:.1f} KB",
        f"⏰ <b>Vaqt:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"⚡ <b>Xavf darajasi:</b> {e} <b>{top}</b>",
        "",
        "🧬 <b>Kriptografik imzolar:</b>",
        f"  MD5:    <code>{hashes['md5']}</code>",
        f"  SHA1:   <code>{hashes['sha1']}</code>",
        f"  SHA256: <code>{hashes['sha256']}</code>",
    ]

    if alerts:
        lines += ["", f"⚠️ <b>Snort qoidalari ishladi ({len(alerts)} ta alert):</b>"]
        for i, a in enumerate(alerts, 1):
            cat   = CATEGORY_NAME.get(a["category"], a["category"])
            re_   = RISK_EMOJI.get(a["risk"], "❓")
            detail = f"\n     └ <code>{a['detail']}</code>" if a.get("detail") else ""
            lines.append(
                f"  {i}. [{a['sid']}] {re_} {a['risk']}\n"
                f"     {cat}: {a['desc']}{detail}"
            )
    else:
        lines += ["", "✅ <b>Hech qanday xavfli belgi topilmadi.</b>"]

    action = "🚫 FAYL BLOKLANDI VA O'CHIRILDI" if blocked else "ℹ️ Fayl o'tkazildi (ehtiyot bo'ling)"
    lines += [
        "",
        f"<b>Qaror:</b> {action}",
        "─" * 38,
        "💡 <i>Noma'lum manbadan kelgan faylni hech qachon ochmang!</i>",
    ]

    return "\n".join(lines), top

# ══════════════════════════════════════════════════════════════════════════════
#  TELEGRAM HANDLER'LAR
# ══════════════════════════════════════════════════════════════════════════════

async def handle_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg: Message = update.message
    doc = msg.document
    if not doc:
        return

    filename = doc.file_name or "nomsiz"
    size     = doc.file_size or 0

    await msg.reply_text(
        f"⏳ <b>Snort IDS tekshiruvi boshlandi...</b>\n"
        f"📄 <code>{filename}</code>",
        parse_mode="HTML"
    )

    if size > 20 * 1024 * 1024:
        await msg.reply_text("⚠️ Fayl 20 MB dan katta. Faqat kengaytma va hajm tekshiriladi.")
        alerts = check_extension(filename)
        report, top = build_report(filename, size, {"md5":"—","sha1":"—","sha256":"—"}, alerts)
        await msg.reply_text(report, parse_mode="HTML")
        return

    try:
        tg_file = await ctx.bot.get_file(doc.file_id)
        data = bytes(await tg_file.download_as_bytearray())
    except Exception as ex:
        await msg.reply_text(f"❌ Yuklab olishda xato: {ex}")
        return

    # Barcha qoidalarni tekshirish
    hashes = compute_hashes(data)
    alerts = []
    alerts += check_hashes(hashes)
    alerts += check_extension(filename)
    alerts += check_magic(data)
    alerts += check_zip_contents(data)
    alerts += check_payload(data, filename)

    report, top = build_report(filename, size, hashes, alerts)

    if top in ("CRITICAL", "HIGH"):
        await msg.reply_text(report, parse_mode="HTML")
        try:
            await msg.delete()
        except Exception:
            await msg.reply_text("⚠️ Faylni o'chirishga harakat qildim, lekin admin huquqi yo'q.")
    else:
        await msg.reply_text(report, parse_mode="HTML")

    # Admin logga
    if LOG_CHAT_ID:
        try:
            await ctx.bot.send_message(
                LOG_CHAT_ID,
                f"🔔 [{top}] {filename} | User: {msg.from_user.id} | "
                f"SHA256: {hashes['sha256'][:16]}..."
            )
        except Exception:
            pass

    log.info(f"[{top}] {filename} | {len(alerts)} alert | SHA256: {hashes['sha256']}")


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ <b>Snort IDS/IPS Telegram Bot</b>\n\n"
        "Fayl yuboring — men uni real vaqtda tekshiraman:\n\n"
        "🔍 <b>Tekshiruv turlari:</b>\n"
        "  • 📎 Kengaytma tahlili (25+ tur)\n"
        "  • 🔮 Magic bytes imzo tekshiruvi\n"
        "  • 📦 ZIP/APK ichki tarkib skaneri\n"
        "  • 💉 Payload string tahlili\n"
        "  • 🧬 MD5/SHA256 hash bazasi\n\n"
        "🔴 CRITICAL/🟠 HIGH → fayl bloklanadi\n"
        "🟡 MEDIUM → ogohlantirish\n"
        "✅ CLEAN → xavfsiz",
        parse_mode="HTML"
    )

async def cmd_rules(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ext_count     = len(EXTENSION_RULES)
    magic_count   = len(MAGIC_RULES)
    zip_count     = len(ZIP_CONTENT_RULES)
    payload_count = len(PAYLOAD_RULES)
    total         = ext_count + magic_count + zip_count + payload_count

    await update.message.reply_text(
        f"📋 <b>Faol Snort qoidalari:</b>\n\n"
        f"  📎 Kengaytma:    {ext_count} ta qoida\n"
        f"  🔮 Magic Bytes:  {magic_count} ta qoida\n"
        f"  📦 ZIP tarkibi:  {zip_count} ta qoida\n"
        f"  💉 Payload:      {payload_count} ta qoida\n"
        f"  ─────────────────\n"
        f"  📊 Jami: <b>{total} ta qoida</b>",
        parse_mode="HTML"
    )

# ══════════════════════════════════════════════════════════════════════════════
#  ASOSIY DASTUR
# ══════════════════════════════════════════════════════════════════════════════

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("rules", cmd_rules))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    log.info(" Snort IDS Bot ishga tushdi (Windows mode)...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
