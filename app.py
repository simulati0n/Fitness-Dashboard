from flask import Flask, render_template, redirect, request, session, url_for
import requests, fitbit, secrets, hashlib, base64, random
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote_plus
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

REDIRECT_URI = 'http://127.0.0.1:5000/callback'
TOKEN_URL = 'https://api.fitbit.com/oauth2/token'
SCOPE = 'heartrate activity respiratory_rate'

def generate_code_verifier():
    length = 64
    code_verifier = secrets.token_urlsafe(length)
    return code_verifier

def generate_code_challenge(code_verifier):
    sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip("=")
    return code_challenge

def get_auth_url(client_id, redirect_uri, scope, code_verifier):
    code_challenge = generate_code_challenge(code_verifier)
    code_challenge_method = "S256"  # Standard for SHA256

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    
    auth_url = f"https://www.fitbit.com/oauth2/authorize?{urlencode(params)}"
    return auth_url

CODE_VERIFIER = generate_code_verifier()

@app.route("/login")
def login():
    # Redirect user to Fitbit's OAuth 2.0 authorization URL
    return redirect(get_auth_url(CLIENT_ID,REDIRECT_URI,SCOPE,CODE_VERIFIER))


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Authorization failed: Missing code", 400

    token_url = "https://api.fitbit.com/oauth2/token"

    credentials = f"{CLIENT_ID}:{CLIENT_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    payload = {
        "grant_type": "authorization_code",
        "code": code, 
        "redirect_uri": REDIRECT_URI,
        "code_verifier": CODE_VERIFIER
    }
    headers = {"Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(token_url, data=payload, headers=headers)

    if response.status_code != 200:
        return f"Failed to get tokens: {response.status_code}, {response.text}", 400

    tokens = response.json()
    session["access_token"] = tokens.get("access_token")
    session["refresh_token"] = tokens.get("refresh_token")
    session["expires_at"] = datetime.now() + timedelta(seconds=tokens.get("expires_in", 3600))

    return redirect(url_for("dashboard"))

@app.route("/refresh-token")
def refresh_token():
    if "refresh_token" not in session:
        return redirect("/login")

    token_url = "https://api.fitbit.com/oauth2/token"
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": session["refresh_token"]
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(token_url, data=payload, headers=headers)
    if response.status_code != 200:
        return "Failed to refresh token", 400

    tokens = response.json()
    session["access_token"] = tokens["access_token"]
    session["refresh_token"] = tokens["refresh_token"]
    session["expires_at"] = datetime.now() + timedelta(seconds=tokens["expires_in"])

    return "Token refreshed!"

def getHeartData(date, period):
    access_token = session.get("access_token")
    
    if not access_token:
        return "User is not authenticated", 400
    
    api_url = "https://api.fitbit.com/1/user/-/activities/heart/date/{date}/{period}.json"

    url = api_url.format(date=date, period=period)
    
    # Authorization header
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    
    # GET request to Fitbit API
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        return f"Failed to get heart rate data: {response.status_code}, {response.text}", 400

    # Parse the response data
    heart_data = response.json()["activities-heart"][0]
    dateTime = heart_data.get("dateTime")
    restingHR = heart_data.get("value", {}).get("restingHeartRate")
    hrZones = heart_data.get("value", {}).get("heartRateZones", [])

    return {
        "dateTime": dateTime,
        "restingHR":restingHR,
        "hrZones":hrZones
    }

def getSteps(date, period):
    access_token = session.get("access_token")
    
    if not access_token:
        return "User is not authenticated", 400
    
    api_url = "https://api.fitbit.com/1/user/-/activities/steps/date/{date}/{period}.json"

    url = api_url.format(date=date, period=period)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print(f"Failed to get steps data: {response.status_code}, {response.text}")
        return []  # Return an empty list if the request fails
    
    # Parse response
    steps_data = response.json().get("activities-steps", [])
    parsed_steps = [{"dateTime": entry.get("dateTime"), "value": entry.get("value")} for entry in steps_data]
    
    return parsed_steps

@app.route("/dashboard")
def dashboard():
    heart_data = getHeartData("2025-03-18","1d")

    dateTime = heart_data.get("dateTime")
    restingHR = heart_data.get("restingHR")
    hrZones = heart_data.get("hrZones")

    steps_data = getSteps("2025-03-23","7d")

    return render_template("dashboard.html",resting_heart_rate=restingHR,
                           heart_rate_zones = hrZones,dateTime = dateTime, steps_data=steps_data,
                           )

@app.route("/")
def home():
    if "access_token" in session:
        return redirect(url_for("dashboard"))  # Show dashboard if logged in
    return render_template("index.html")  # Simple login link

if __name__ == "__main__":
    app.run(debug=True)