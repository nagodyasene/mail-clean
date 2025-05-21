# Email Unsubscribe Analysis

A tool to analyze and manage email unsubscriptions from your Gmail account.

## Features

- Scan your Gmail for emails with unsubscribe headers
- Analyze which senders send the most emails with unsubscribe options
- Easily unsubscribe from unwanted emails directly from the interface
- Batch unsubscribe from multiple senders at once

## Local Development Setup

Follow these steps to run the application locally:

1. **Clone the repository**

2. **Install dependencies**
   ```
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   - Copy the `.env.example` file to a new file named `.env`
   - Fill in your Google OAuth credentials in the `.env` file
   - You can create OAuth credentials at https://console.cloud.google.com/apis/credentials
   - Make sure to add `http://localhost:5000/oauth2callback` as an authorized redirect URI in your Google OAuth settings

4. **Run the local development server**
   ```
   python local.py
   ```

5. **Access the application**
   - Open your browser and go to http://localhost:5000
   - Click "Login with Google" to authenticate with your Gmail account
   - Grant the necessary permissions to scan your emails

## OAuth Configuration

When setting up your Google OAuth credentials, you'll need to:

1. Create a new project in the Google Cloud Console
2. Enable the Gmail API for your project
3. Create OAuth 2.0 Client ID credentials
4. Add `http://localhost:5000/oauth2callback` as an authorized redirect URI
5. Copy the Client ID and Client Secret to your `.env` file

### Local Development Note

For local development, the application sets `OAUTHLIB_INSECURE_TRANSPORT=1` to allow OAuth over HTTP. This is necessary because OAuth2 normally requires HTTPS, but most local development environments use HTTP.

**WARNING:** This setting should NEVER be used in production as it bypasses OAuth2 security requirements. In production, always use HTTPS for OAuth flows.

## Deployment

This application is configured for deployment on Vercel. The `vercel.json` file contains the necessary configuration.

## License

See the LICENSE file for details.
