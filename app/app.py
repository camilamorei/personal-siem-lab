from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":
        username = request.form.get("username")
        return f"Tentativa recebida para o usuário: {username}"

    return render_template("login.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
