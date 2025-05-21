import os
from flask import Flask, render_template, request
from imap_tools import MailBox, AND
from collections import Counter
import datetime

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    error = None
    if request.method == 'POST':
        imap_server = request.form['imap_server']
        email_account = request.form['email_account']
        email_password = request.form['email_password']
        mailbox_to_scan = request.form.get('mailbox_to_scan', 'INBOX')
        days_to_scan = int(request.form.get('days_to_scan', 60))
        min_count = int(request.form.get('min_count', 3))
        try:
            senders_with_unsubscribe_option = Counter()
            total_emails_from_sender = Counter()
            with MailBox(imap_server).login(email_account, email_password, initial_folder=mailbox_to_scan) as mailbox:
                scan_start_date = (datetime.date.today() - datetime.timedelta(days=days_to_scan))
                criteria = AND(date_gte=scan_start_date)
                for msg in mailbox.fetch(criteria, mark_seen=False, reverse=True, headers_only=True):
                    sender_email = msg.from_
                    sender_display_name = msg.from_values.name if msg.from_values else ""
                    full_sender_id = f"{sender_display_name} <{sender_email}>" if sender_display_name else sender_email
                    full_sender_id_lower = full_sender_id.lower()
                    total_emails_from_sender[full_sender_id_lower] += 1
                    has_unsubscribe_header = False
                    for header in msg.headers:
                        header_name = header[0]
                        if header_name.lower() == 'list-unsubscribe':
                            has_unsubscribe_header = True
                            break
                    if has_unsubscribe_header:
                        senders_with_unsubscribe_option[full_sender_id_lower] += 1
            results = []
            for sender, count in sorted(senders_with_unsubscribe_option.items(), key=lambda item: item[1], reverse=True):
                if count >= min_count:
                    total_count = total_emails_from_sender.get(sender, count)
                    results.append({
                        'sender': sender,
                        'unsubscribe_count': count,
                        'total_count': total_count
                    })
        except Exception as e:
            error = str(e)
    return render_template('index.html', results=results, error=error)

# Vercel looks for the variable 'app'
app = app