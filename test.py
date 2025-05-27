import re
from email import message_from_string
from urllib.parse import urlparse

# Sample phishing phrases
URGENT_PHRASES = ["urgent", "immediate action", "your account will be suspended", "verify your identity", "click here"]
COMMON_ERRORS = ["you're identity", "click hear", "to you verify"]

def analyze_email(email_raw):
    report = {
        "spoofed_sender": False,
        "header_issues": [],
        "suspicious_links": [],
        "urgent_language": [],
        "grammar_issues": [],
        "summary": []
    }

    msg = message_from_string(email_raw)

    # 1. Analyze sender
    sender = msg.get("From", "")
    if not re.search(r"paypal\.com", sender, re.IGNORECASE):
        report["spoofed_sender"] = True
        report["summary"].append("Sender address appears spoofed: " + sender)

    # 2. Analyze headers
    received = msg.get_all("Received", [])
    if received:
        for rcv in received:
            if "unknown" in rcv or "suspicious" in rcv:
                report["header_issues"].append(rcv)
                report["summary"].append("Suspicious header: " + rcv)

    # 3. Analyze body for links, urgency, grammar
    body = get_email_body(msg).lower()

    # Suspicious links
    urls = re.findall(r'https?://[^\s]+', body)
    for url in urls:
        domain = urlparse(url).netloc
        if not ("paypal.com" in domain):
            report["suspicious_links"].append(url)
            report["summary"].append("Suspicious URL found: " + url)

    # Urgency
    for phrase in URGENT_PHRASES:
        if phrase in body:
            report["urgent_language"].append(phrase)
            report["summary"].append("Urgent language: " + phrase)

    # Grammar
    for error in COMMON_ERRORS:
        if error in body:
            report["grammar_issues"].append(error)
            report["summary"].append("Grammar error: " + error)

    return report

def get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
    else:
        return msg.get_payload(decode=True).decode(errors="ignore")
    return ""

# Example usage
with open("phishing_email.txt", "r") as f:
    email_text = f.read()

report = analyze_email(email_text)
print("\n--- Phishing Analysis Report ---")
for k, v in report.items():
    if isinstance(v, list):
        print(f"\n{k.capitalize()}:")
        for item in v:
            print(f" - {item}")
    else:
        print(f"\n{k.capitalize()}: {v}")
