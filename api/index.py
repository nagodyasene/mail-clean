import os
import json
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

        # Full results for display in the template
        display_results = []
        # Minimal results for storage in session (to reduce cookie size)
        session_results = []

        for sender, count in sorted(senders_with_unsub.items(), key=lambda x: x[1], reverse=True):
            if count >= min_unsub:
                # Get the first unsubscribe link we found for this sender (most recent)
                unsub_info = unsubscribe_links[sender][0] if unsubscribe_links[sender] else {}

                # Full result for display
                sender_result = {
                    'sender': sender,
                    'sender_full': sender_emails.get(sender, sender),
                    'unsubscribe_count': count,
                    'total_count': total_emails_from_sender.get(sender, count),
                    'unsubscribe_links': unsub_info.get('links', {}),
                    'message_id': unsub_info.get('message_id', '')
                }
                display_results.append(sender_result)

                # Minimal result for session storage - only essential data for unsubscribe operations
                session_result = {
                    'sender': sender,
                    'unsubscribe_links': unsub_info.get('links', {}),
                    'message_id': unsub_info.get('message_id', '')
                }
                session_results.append(session_result)

        # Store minimal data in session for unsubscribe operations
        session['scan_results'] = session_results

        return render_template('index.html', authenticated=True, results=display_results, error=None)
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

    # Track this sender as unsubscribed in the session
    if 'unsubscribed_senders' not in session:
        session['unsubscribed_senders'] = []

    # Add to unsubscribed senders if not already there
    if sender not in session['unsubscribed_senders']:
        unsubscribed_senders = session['unsubscribed_senders']
        unsubscribed_senders.append(sender)
        session['unsubscribed_senders'] = unsubscribed_senders

    # Get stored scan results
    results = session.get('scan_results', [])
    sender_info = None

    # Find the sender in the results
    for result in results:
        if result['sender'] == sender:
            sender_info = result
            break

    if not sender_info:
        # If sender not found in session, try to rescan for this specific sender
        service = get_gmail_service()
        if not service:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401

        try:
            # Get the most recent messages from this sender
            query = f'from:{sender}'
            msg_list = service.users().messages().list(
                userId='me', q=query, maxResults=5
            ).execute()
            messages = msg_list.get('messages', [])

            if not messages:
                return jsonify({'success': False, 'error': f'No messages found from {sender}'}), 404

            # Check each message for unsubscribe headers
            for msg_meta in messages:
                msg = service.users().messages().get(
                    userId='me', id=msg_meta['id'], format='metadata',
                    metadataHeaders=['From', 'List-Unsubscribe', 'Message-ID']
                ).execute()

                headers = {}
                for header in msg['payload'].get('headers', []):
                    headers[header['name']] = header['value']

                if 'List-Unsubscribe' in headers:
                    unsubscribe_header = headers['List-Unsubscribe']
                    links = parse_unsubscribe_link(unsubscribe_header)

                    if links:
                        # Create a temporary sender_info
                        sender_info = {
                            'sender': sender,
                            'unsubscribe_links': links,
                            'message_id': msg_meta['id']
                        }
                        break

            if not sender_info:
                return jsonify({'success': False, 'error': 'No unsubscribe links found for this sender'}), 404

        except Exception as e:
            return jsonify({'success': False, 'error': f'Error rescanning for sender: {str(e)}'}), 500

    if 'unsubscribe_links' not in sender_info or not sender_info['unsubscribe_links']:
        return jsonify({'success': False, 'error': 'No unsubscribe link found for this sender. The sender may not provide unsubscribe options.'}), 404

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
        # Get stored scan results
        scan_results = session.get('scan_results', [])
        sender_info = None

        # Find the sender in the results
        for result in scan_results:
            if result['sender'] == sender:
                sender_info = result
                break

        # Determine the method (prefer http over mailto)
        # If sender_info is None, the unsubscribe function will handle it with its fallback mechanism
        if sender_info and 'unsubscribe_links' in sender_info:
            method = 'http' if 'http' in sender_info['unsubscribe_links'] else 'mailto'
            message_id = sender_info.get('message_id', '')
        else:
            # Default to http method if sender not found in scan results
            method = 'http'
            message_id = ''

        # Create a request context with form data
        with app.test_request_context(
            '/unsubscribe', 
            method='POST',
            data={'sender': sender, 'method': method, 'message_id': message_id}
        ):
            # Call the unsubscribe function directly
            resp = unsubscribe()
            # Convert response to dict if it's a tuple (response, status_code)
            if isinstance(resp, tuple):
                resp_data = resp[0].get_json()
            else:
                resp_data = resp

            results.append({
                'sender': sender,
                'success': resp_data.get('success', False),
                'message': resp_data.get('message', 'Unknown error')
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

    # Get high percentage senders directly from the request
    # The frontend already has this information from the display results
    high_percentage_senders = request.json.get('senders', [])

    if not high_percentage_senders:
        threshold = request.json.get('threshold', 95)
        return jsonify({
            'success': False,
            'error': f'No senders found with ≥{threshold}% unsubscribe rate'
        }), 404

    # Create a new request with the senders
    with app.test_request_context(
        '/batch_unsubscribe',
        method='POST',
        content_type='application/json',
        data=json.dumps({'senders': high_percentage_senders})
    ):
        # Call the batch_unsubscribe function
        return batch_unsubscribe()


@app.route('/delete_emails', methods=['POST'])
def delete_emails():
    """Delete all emails from a specific sender."""
    if 'token' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    # Get sender from request
    sender = request.form.get('sender')
    if not sender:
        return jsonify({'success': False, 'error': 'No sender specified'}), 400

    # Check if the sender is in the unsubscribed list
    unsubscribed_senders = session.get('unsubscribed_senders', [])
    if sender not in unsubscribed_senders:
        return jsonify({
            'success': False, 
            'error': 'You must unsubscribe from this sender before deleting emails'
        }), 400

    try:
        service = get_gmail_service()
        if not service:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401

        # Search for emails from this sender
        query = f'from:{sender}'
        result = service.users().messages().list(userId='me', q=query).execute()
        messages = result.get('messages', [])

        # If no messages found
        if not messages:
            return jsonify({
                'success': True,
                'message': f'No emails found from {sender}',
                'count': 0
            })

        # Delete each message (move to trash)
        for message in messages:
            try:
                # First try to trash the message
                service.users().messages().trash(userId='me', id=message['id']).execute()
            except Exception as e:
                # If trashing fails, try to delete the message
                try:
                    service.users().messages().delete(userId='me', id=message['id']).execute()
                except Exception as inner_e:
                    print(f"Error deleting message {message['id']}: {str(inner_e)}")
                    # Re-raise the original exception if both methods fail
                    raise e

        return jsonify({
            'success': True,
            'message': f'Successfully deleted {len(messages)} emails from {sender}',
            'count': len(messages)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/check_unsubscribed_senders', methods=['GET'])
def check_unsubscribed_senders():
    """Return the list of senders that the user has unsubscribed from."""
    if 'token' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    unsubscribed_senders = session.get('unsubscribed_senders', [])
    return jsonify({
        'success': True,
        'unsubscribed_senders': unsubscribed_senders
    })


@app.route('/batch_delete_emails', methods=['POST'])
def batch_delete_emails():
    """Delete emails from multiple senders."""
    if 'token' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    senders = request.json.get('senders', [])
    if not senders:
        return jsonify({'success': False, 'error': 'No senders specified'}), 400

    results = []
    total_deleted = 0

    for sender in senders:
        # Create a request context with form data
        with app.test_request_context(
            '/delete_emails', 
            method='POST',
            data={'sender': sender}
        ):
            # Call the delete_emails function directly
            resp = delete_emails()
            # Convert response to dict if it's a tuple (response, status_code)
            if isinstance(resp, tuple):
                resp_data = resp[0].get_json()
            else:
                resp_data = resp.get_json() if hasattr(resp, 'get_json') else resp

            count = resp_data.get('count', 0)
            total_deleted += count

            results.append({
                'sender': sender,
                'success': resp_data.get('success', False),
                'message': resp_data.get('message', 'Unknown error'),
                'count': count
            })

    return jsonify({
        'success': True,
        'results': results,
        'total_deleted': total_deleted,
        'message': f'Deleted a total of {total_deleted} emails from {len(results)} senders'
    })


# Required for Vercel
app = app
