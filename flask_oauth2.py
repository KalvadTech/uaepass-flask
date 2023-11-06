from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
import os
import uuid

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
    return redirect(authorization_url+ "&acr_values=urn:safelayer:tws:policies:authentication:level:low")


# Step 2: User authorization, this happens on the provider.


@app.route("/callback", methods=["GET"])
def callback():
    """Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    print(request.url)
    uaepass = OAuth2Session(client_id, state=session["oauth_state"])
    token = uaepass.fetch_token(
        token_url, client_secret=client_secret, authorization_response=request.url
    )

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session["oauth_token"] = token

    return redirect(url_for(".profile"))


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
