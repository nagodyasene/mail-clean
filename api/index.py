import os
from flask import Flask, render_template, redirect, request, session, url_for, jsonify
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from urllib.parse import urlencode, unquote
import datetime
import re
import base64
import email.utils
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-this")

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify']

# Config from environment variables
CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = os.environ.get('OAUTH_REDIRECT_URI')


def get_flow():
    """Create and return an OAuth 2.0 flow object."""
    return Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )


def get_gmail_service():
    """Get authenticated Gmail API service if the user is logged in."""
    if 'token' not in session:
        return None

    creds = Credentials(
        token=session['token'],
        refresh_token=session.get('refresh_token'),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=SCOPES
    )
    return build('gmail', 'v1', credentials=creds)


@app.route('/')
def index():
    """Home page route."""
    authenticated = 'token' in session
    return render_template('index.html', authenticated=authenticated)


@app.route('/login')
def login():
    """Initiate OAuth login flow."""
    flow = get_flow()
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['state'] = state
    return redirect(auth_url)


@app.route('/oauth2callback')
def oauth2callback():
    """Handle the OAuth callback."""
    # Error handling for missing code
    if 'error' in request.args:
        error = request.args.get('error')
        return f"Authorization failed: {error}", 400

    # No state in session means the user didn't start from our login flow
    if 'state' not in session:
        return "Invalid session state. Please start login again.", 400

    try:
        # Exchange auth code for tokens
        flow = get_flow()
        flow.fetch_token(authorization_response=request.url)

        # Store credentials in session
        credentials = flow.credentials
        session['token'] = credentials.token
        session['refresh_token'] = credentials.refresh_token

        # Redirect to the home page with success
        return redirect(url_for('index'))

    except Exception as e:
        # Complete error handling
        print(f"OAuth callback error: {str(e)}")
        return f"Error during authorization: {str(e)}", 400


@app.route('/logout')
def logout():
    """Clear session and log user out."""
    session.clear()
    return redirect(url_for('index'))


def parse_unsubscribe_link(unsubscribe_header):
    """Parse the List-Unsubscribe header to extract mailto and http links."""
    links = {}

    # Extract links from the angle brackets
    matches = re.findall(r'<([^>]+)>', unsubscribe_header)

    for link in matches:
        if link.startswith('mailto:'):
            links['mailto'] = link
        elif link.startswith('http'):
            links['http'] = link

    return links


@app.route('/scan', methods=['POST'])
def scan():
    """Scan Gmail for the "unsubscribe" headers."""
    if 'token' not in session:
        return redirect(url_for('login'))

    days_to_scan = int(request.form.get('days_to_scan', 60))
    min_unsub = int(request.form.get('min_count', 3))
    max_messages = int(request.form.get('max_messages', 100))  # Keep small for serverless

    service = get_gmail_service()
    if not service:
        return redirect(url_for('login'))

    # Date range query
    since = datetime.datetime.now() - datetime.timedelta(days=days_to_scan)
    since_str = since.strftime('%Y/%m/%d')
    query = f'after:{since_str}'

    try:
        # Get message IDs only (fast)
        msg_list = service.users().messages().list(
            userId='me', q=query, maxResults=max_messages
        ).execute()
        messages = msg_list.get('messages', [])

        # Process headers
        from collections import Counter, defaultdict
        senders_with_unsub = Counter()
        total_emails_from_sender = Counter()
        unsubscribe_links = defaultdict(list)  # Store unsubscribe links by sender
        sender_emails = {}  # Map display name to email address

        for msg_meta in messages:
            msg = service.users().messages().get(
                userId='me', id=msg_meta['id'], format='metadata',
                metadataHeaders=['From', 'List-Unsubscribe', 'Message-ID']
            ).execute()

            headers = {}
            for header in msg['payload'].get('headers', []):
                headers[header['name']] = header['value']

            sender_full = headers.get('From', '')
            sender = sender_full.lower()
            message_id = headers.get('Message-ID', '')

            # Store the sender email for later use
            if sender:
                sender_emails[sender] = sender_full

            total_emails_from_sender[sender] += 1

            if 'List-Unsubscribe' in headers:
                unsubscribe_header = headers['List-Unsubscribe']
                senders_with_unsub[sender] += 1

                # Parse and store unsubscribe links
                links = parse_unsubscribe_link(unsubscribe_header)
                if links:
                    # Store with message ID to have unique links per message
                    unsubscribe_links[sender].append({
                        'message_id': msg_meta['id'],
                        'links': links
                    })

        results = []
        for sender, count in sorted(senders_with_unsub.items(), key=lambda x: x[1], reverse=True):
            if count >= min_unsub:
                # Get the first unsubscribe link we found for this sender (most recent)
                unsub_info = unsubscribe_links[sender][0] if unsubscribe_links[sender] else {}

                sender_result = {
                    'sender': sender,
                    'sender_full': sender_emails.get(sender, sender),
                    'unsubscribe_count': count,
                    'total_count': total_emails_from_sender.get(sender, count),
                    'unsubscribe_links': unsub_info.get('links', {}),
                    'message_id': unsub_info.get('message_id', '')
                }
                results.append(sender_result)

        session['scan_results'] = results  # Store in session for unsubscribe operations

        return render_template('index.html', authenticated=True, results=results, error=None)
    except Exception as e:
        return render_template('index.html', authenticated=True, results=None, error=str(e))


@app.route('/unsubscribe', methods=['POST'])
def unsubscribe():
    """Process a single "unsubscribe" request."""
    if 'token' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    # Get sender and unsubscribe method from request
    sender = request.form.get('sender')
    method = request.form.get('method', 'http')  # 'http' or 'mailto'
    message_id = request.form.get('message_id', '')

    if not sender:
        return jsonify({'success': False, 'error': 'No sender specified'}), 400

    # Get stored scan results
    results = session.get('scan_results', [])
    sender_info = None

    # Find the sender in the results
    for result in results:
        if result['sender'] == sender:
            sender_info = result
            break

    if not sender_info or 'unsubscribe_links' not in sender_info:
        return jsonify({'success': False, 'error': 'No unsubscribe link found for this sender'}), 404

    # Process the unsubscribe action based on the method
    try:
        if method == 'http' and 'http' in sender_info['unsubscribe_links']:
            # For HTTP links, we can redirect the user to an unsubscribe page
            unsubscribe_url = sender_info['unsubscribe_links']['http']
            return jsonify({
                'success': True,
                'redirect': unsubscribe_url,
                'sender': sender
            })

        elif method == 'mailto' and 'mailto' in sender_info['unsubscribe_links']:
            # For mailto links, we need to extract info and send an email
            service = get_gmail_service()
            if not service:
                return jsonify({'success': False, 'error': 'Not authenticated'}), 401

            mailto_link = sender_info['unsubscribe_links']['mailto']
            # Parse mailto: link
            mailto_parts = mailto_link.replace('mailto:', '').split('?')
            to_email = mailto_parts[0]

            subject = ''
            body = ''

            if len(mailto_parts) > 1:
                params = mailto_parts[1].split('&')
                for param in params:
                    if '=' in param:
                        key, value = param.split('=')
                        if key.lower() == 'subject':
                            subject = unquote(value)
                        elif key.lower() == 'body':
                            body = unquote(value)

            # If no subject is provided, use a default
            if not subject:
                subject = 'Unsubscribe request'

            # Create the email message
            message = f"From: {session.get('email', 'me')}\r\n"
            message += f"To: {to_email}\r\n"
            message += f"Subject: {subject}\r\n\r\n"
            message += body

            # Encode the message
            encoded_message = base64.urlsafe_b64encode(message.encode()).decode()

            # Send the email
            service.users().messages().send(
                userId='me',
                body={'raw': encoded_message}
            ).execute()

            return jsonify({
                'success': True,
                'method': 'mailto',
                'sender': sender,
                'message': 'Unsubscribe email sent successfully'
            })

        else:
            return jsonify({
                'success': False,
                'error': f'No supported unsubscribe method found for {sender}'
            }), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/batch_unsubscribe', methods=['POST'])
def batch_unsubscribe():
    """Process multiple unsubscribe requests."""
    if 'token' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    senders = request.json.get('senders', [])

    if not senders:
        return jsonify({'success': False, 'error': 'No senders specified'}), 400

    results = []
    for sender in senders:
        # Use the individual "unsubscribe" logic for each sender
        # We simulate a form submission for each sender
        form_data = {'sender': sender}
        resp = unsubscribe()
        results.append({
            'sender': sender,
            'success': resp.get('success', False),
            'message': resp.get('message', 'Unknown error')
        })

    return jsonify({
        'success': True,
        'results': results,
        'message': f'Processed {len(results)} unsubscribe requests'
    })


@app.route('/unsubscribe_all_high_percentage', methods=['POST'])
def unsubscribe_all_high_percentage():
    """Unsubscribe from all senders with >95% unsubscribe rate."""
    if 'token' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    threshold = request.json.get('threshold', 95)
    results = session.get('scan_results', [])

    high_percentage_senders = []
    for result in results:
        percentage = (result['unsubscribe_count'] / result['total_count']) * 100
        if percentage >= threshold:
            high_percentage_senders.append(result['sender'])

    if not high_percentage_senders:
        return jsonify({
            'success': False,
            'error': f'No senders found with ≥{threshold}% unsubscribe rate'
        }), 404

    # Use the batch "unsubscribe" endpoint
    return batch_unsubscribe()


# Required for Vercel
app = app