from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
import os
import uuid
import requests
import json
from requests.auth import HTTPBasicAuth

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", str(uuid.uuid4()))

# This information is obtained upon registration of a new uaepass
client_id = os.environ.get("UAEPASS_CLIENT_ID", "sandbox_stage")
client_secret = os.environ.get("UAEPASS_CLIENT_SECRET", "sandbox_stage")
authorization_base_url = os.environ.get(
    "UAEPASS_AUTHORIZATION_BASE_URL", "https://stg-id.uaepass.ae/idshub/authorize"
)
token_url = os.environ.get(
    "UAEPASS_AUTHORIZATION_TOKEN_URL", "https://stg-id.uaepass.ae/idshub/token"
)
scope = "urn:uae:digitalid:profile:general"


@app.route("/")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. uaepass)
    using an URL with a few key OAuth parameters.
    """
    uaepass = OAuth2Session(
        client_id, redirect_uri="https://{}/callback".format(request.host), scope=scope
    )
    authorization_url, state = uaepass.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session["oauth_state"] = state
    return redirect(
        authorization_url
        + "&acr_values=urn:safelayer:tws:policies:authentication:level:low"
    )


# Step 2: User authorization, this happens on the provider.


@app.route("/callback", methods=["GET"])
def callback():
    """Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    code = request.args.get("code", default="", type=str)
    state = request.args.get("state", default="", type=str)

    querystring = {
        "grant_type": "authorization_code",
        "redirect_uri": "https://{}/callback".format(request.host),
        "code": code,
    }
    basic = HTTPBasicAuth(client_id, client_secret)

    response = requests.post(token_url, params=querystring, auth=basic)
    print(response.status_code)
    if response.status_code != 200:
        return response.text
    print(response.text)
    print(response.json())

    return redirect(
        "/profile?access_token="
        + response.json()["access_token"]
        + "&scope="
        + response.json()["scope"]
        + "&token_type="
        + response.json()["token_type"]
        + "&expires_in="
        + str(response.json()["expires_in"])
    )


@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token."""
    uaepass = OAuth2Session(client_id, token=session["oauth_token"])
    return jsonify(uaepass.get("https://stg-id.uaepass.ae/idshub/userinfo").json())


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ["DEBUG"] = "1"

    app.secret_key = os.urandom(24)
    app.run(debug=True)
