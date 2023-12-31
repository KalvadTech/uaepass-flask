from flask import Flask, request, redirect, session, url_for, render_template
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
userinfo_url = os.environ.get(
    "UAEPASS_USERINFO_URL", "https://stg-id.uaepass.ae/idshub/userinfo"
)
scope = "urn:uae:digitalid:profile:general"


@app.route("/")
def welcome():
    return render_template("welcome.html")


@app.route("/uaepass")
def uaepass():
    redirect_uri = "https://{}/callback".format(request.host)
    state = str(uuid.uuid4())
    user_type = request.args.get("user_type", default="resident", type=str)
    if user_type == "visitor":
        scope = "scope=urn:uae:digitalid:profile:general urn:uae:digitalid:profile:general:profileType urn:uae:digitalid:profile:general:unifiedId"
    else:
        scope = "urn:uae:digitalid:profile:general"
    acr_values = "urn:safelayer:tws:policies:authentication:level:low"
    uaepass_redirect_url = "{}?response_type=code&client_id={}&scope={}&state={}&redirect_uri={}&acr_values={}".format(
        authorization_base_url, client_id, scope, state, redirect_uri, acr_values
    )
    session["oauth_state"] = state
    return redirect(
        uaepass_redirect_url,
        code=302,
    )


@app.route("/callback", methods=["GET"])
def callback():
    redirect_uri = "https://{}/callback".format(request.host)
    code = request.args.get("code", default="", type=str)
    state = request.args.get("state", default="", type=str)
    if code != "":
        querystring = {
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            "code": code,
        }
        headers = {"Content-Type": "multipart/form-data; charset=UTF-8"}
        print(querystring)
        basic = HTTPBasicAuth(client_id, client_secret)

        response = requests.post(
            token_url, params=querystring, auth=basic, headers=headers
        )
        print(response.status_code)
        print(response.text)
        if response.status_code != 200:
            return response.text, response.status_code
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
    access_token = request.args.get("access_token", default="", type=str)
    headers = {
        "Authorization": "Bearer {}".format(access_token),
    }
    response = requests.get(userinfo_url, headers=headers)
    print(response.json())
    content = response.json()
    return render_template("profile.html", content=content)


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ["DEBUG"] = "1"

    app.secret_key = os.urandom(24)
    app.run(debug=True)
