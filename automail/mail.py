"""
marketing_mailer.py
وصف: إرسال حملات بريدية تسويقية شرعية مع دعم لإلغاء الاشتراك، سجلات، ومحاولات إعادة الإرسال.
استخدام:
  1) جهّز ملف recipients.csv بصيغة: name,email
  2) اضبط إعدادات SMTP أدناه (لا تضع كلمة المرور في كود عام - استخدم متغيّئات بيئة أو ملف محلي آمن).
  3) شغّل: python marketing_mailer.py
"""

import csv
import time
import ssl
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Tuple

# -------- إعدادات عامة (غيّرها) --------
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587               # use 587 + starttls or 465 for SSL
EMAIL_ADDRESS = "karemzatar28@gmail.com"     # بريد المرسل
EMAIL_PASSWORD = "ibkt ikuv whdh bfgv"  # **لا تضع كلمة المرور في الكود عند المشاركة**
RECIPIENTS_CSV = "recipients.csv"     # ملف CSV يحتوي name,email في كل سطر
LOG_FILE = "mailer.log"

SUBJECT = "You have been hacked"
# قالب HTML (يمكن تضمين {name} و {email} و {unsubscribe_url})
MESSAGE_HTML = """
<html>
  <body style="font-family: Arial, sans-serif; font-size:16px; color:#222;">
    <p>I see you {name},</p>
<p>Your eamil/gmail has hacked by <b>M4</b>.</p>
<p>We have full access to your device and all your personal information.</p>
<p>We can see everything you do on your device, including your browsing history, messages, and photos.</p>
<p>We can also access your contacts and social media accounts.</p>
  </body>
</html>
"""

# توصيات للالتزام: لا تبعث لمستلمين لم يأذنوا، ضع رابط إلغاء اشتراك منطقي، واحترم القوانين المحلية.

# -------- إعدادات الإرسال --------
DELAY_BETWEEN_EMAILS = 0.1     # ثواني بين كل رسالة (زوّد الوقت لتقليل علامة spam)
MAX_RETRIES = 10                # محاولات إعادة إرسال عند فشل
RETRY_BACKOFF = 0.1            # عامل مضاعفة للانتظار بين المحاولات

DRY_RUN = False                # لو True سيطبع فقط ولا يرسل فعلاً (للاختبار)

# -------- تهيئة اللوقينج --------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

def read_recipients(csv_path: str) -> list[Tuple[str,str]]:
    recipients = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row: 
                continue
            # توقع: name,email أو فقط email
            if len(row) == 1:
                name = row[0].split("@")[0]
                email = row[0].strip()
            else:
                name = row[0].strip() or row[1].split("@")[0]
                email = row[1].strip()
            if "@" in email:
                recipients.append((name, email))
    return recipients

def make_unsubscribe_url(email: str) -> str:
    # غيّر لينك إلغاء الاشتراك ليشير لنظامك. مثال: https://yourdomain.com/unsubscribe?email=...
    return f"https://example.com/unsubscribe?email={email}"

def build_message(sender: str, recipient_email: str, recipient_name: str) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["From"] = sender
    msg["To"] = recipient_email
    msg["Subject"] = SUBJECT

    # List-Unsubscribe header يساعد مزودي البريد (مثل Gmail) على إظهار رابط إلغاء الاشتراك للمستخدم
    unsubscribe_mailto = "mailto:unsubscribe@example.com"
    unsubscribe_http = make_unsubscribe_url(recipient_email)
    msg.add_header("List-Unsubscribe", f"<{unsubscribe_mailto}>, <{unsubscribe_http}>")

    html_body = MESSAGE_HTML.format(
        name=recipient_name,
        email=recipient_email,
        unsubscribe_url=unsubscribe_http
    )
    part_html = MIMEText(html_body, "html", _charset="utf-8")
    msg.attach(part_html)
    return msg

def send_via_smtp(message: MIMEMultipart, smtp_server: str, smtp_port: int, user: str, password: str):
    # استخدم STARTTLS (منفذ 587) مع سياق افتراضي آمن
    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, smtp_port, timeout=60) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(user, password)
        server.send_message(message)

def safe_send(recipient_name: str, recipient_email: str):
    msg = build_message(EMAIL_ADDRESS, recipient_email, recipient_name)

    if DRY_RUN:
        logging.info(f"[DRY RUN] جاهز لإرسال إلى {recipient_email}")
        return True

    attempt = 0
    wait = 1.0
    while attempt < MAX_RETRIES:
        try:
            send_via_smtp(msg, SMTP_SERVER, SMTP_PORT, EMAIL_ADDRESS, EMAIL_PASSWORD)
            logging.info(f"✅ تم الإرسال إلى {recipient_email}")
            return True
        except smtplib.SMTPException as e:
            attempt += 1
            logging.warning(f"محاولة {attempt}/{MAX_RETRIES} فشلت لإرسال {recipient_email}: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(wait)
                wait *= RETRY_BACKOFF
            else:
                logging.error(f"❌ فشل نهائي في الإرسال إلى {recipient_email}: {e}")
                return False
        except Exception as e:
            logging.exception(f"خطأ غير متوقع عند الإرسال إلى {recipient_email}: {e}")
            return False

def main():
    recipients = read_recipients(RECIPIENTS_CSV)
    logging.info(f"تم تحميل {len(recipients)} مستلم(ين) من {RECIPIENTS_CSV}")

    sent_count = 0
    for name, email in recipients:
        success = safe_send(name, email)
        if success:
            sent_count += 1
        # تأخير بين الرسائل لتقليل احتمالية أن يعتبر مزودو البريد رسائل سبام
        time.sleep(DELAY_BETWEEN_EMAILS)

    logging.info(f"تم الانتهاء: مُرسلة: {sent_count} / {len(recipients)}")

if __name__ == "__main__":
    main()
