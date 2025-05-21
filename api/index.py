import os
from flask import Flask, render_template, redirect, request, session, url_for
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from urllib.parse import urlencode
import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-this")

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

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
    """Get authenticated Gmail API service if user is logged in."""
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
    """Handle the OAuth callback - CRITICAL PATH."""
    # Debug info
    print("Callback received!")

    # Error handling for missing code
    if 'error' in request.args:
        error = request.args.get('error')
        return f"Authorization failed: {error}", 400

    # No state in session means user didn't start from our login flow
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

        # Redirect to home page with success
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


@app.route('/scan', methods=['POST'])
def scan():
    """Scan Gmail for unsubscribe headers."""
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

        # Batch get headers
        from collections import Counter
        senders_with_unsub = Counter()
        total_emails_from_sender = Counter()

        for msg_meta in messages:
            msg = service.users().messages().get(
                userId='me', id=msg_meta['id'], format='metadata',
                metadataHeaders=['From', 'List-Unsubscribe']
            ).execute()

            headers = {}
            for header in msg['payload'].get('headers', []):
                headers[header['name']] = header['value']

            sender = headers.get('From', '').lower()
            total_emails_from_sender[sender] += 1

            if 'List-Unsubscribe' in headers:
                senders_with_unsub[sender] += 1

        results = []
        for sender, count in sorted(senders_with_unsub.items(), key=lambda x: x[1], reverse=True):
            if count >= min_unsub:
                results.append({
                    'sender': sender,
                    'unsubscribe_count': count,
                    'total_count': total_emails_from_sender.get(sender, count)
                })
        return render_template('index.html', authenticated=True, results=results, error=None)
    except Exception as e:
        return render_template('index.html', authenticated=True, results=None, error=str(e))


# Required for Vercel
app = app