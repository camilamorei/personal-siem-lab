from datetime import datetime, timezone

from flask import Flask, render_template, request
from werkzeug.security import check_password_hash

from security_logger import log_auth_event

app = Flask(__name__)

# Fictitious test users. Only the password hashes are stored in the code.
# alice -> Alice@2026 | bob -> Bob@2026
USERS = {
    "alice": "scrypt:32768:8:1$WCGz3W8yki0Fr19c$cd89521776f9b8d0d10d3ea9aa693b19ba87b51992752ec6259dddc702da9e0e75076869f41a55179194c25a1d0f7c4f7932f8ef2541f294a065144268bf61fa",
    "bob": "scrypt:32768:8:1$XgwVNj6lDYtXV2gJ$04d00ed6d42cebdd03d33d172db11f28e2f1ece65f43cf75364210b863c384119fb3b515d055edf010509f5c2fb64d6d0b5037c7c534202cc7ddc87863643474",
}


@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        stored_hash = USERS.get(username)
        src_ip = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")

        if stored_hash and check_password_hash(stored_hash, password):
            log_auth_event(username, "success", src_ip, user_agent)
            return render_template(
                "welcome.html",
                username=username,
                ip=request.remote_addr,
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            ), 200

        # The UI shows a generic message, but the log keeps the real reason
        reason = "invalid_password" if stored_hash else "unknown_user"
        log_auth_event(username, "failure", src_ip, user_agent, reason)

        return render_template(
            "login.html",
            error="Invalid username or password.",
            username=username,
        ), 401

    return render_template("login.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
