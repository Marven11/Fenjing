from flask import (
    Flask,
    request,
    render_template,
    render_template_string,
    redirect,
    url_for,
    session,
)
import time
import os

app = Flask(__name__)
app.secret_key = "NSS"
FILTER_KEYWORDS = [
    ".",
    "/",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "0",
    "_",
    "g",
    "read",
    "%",
]
TIME_LIMIT = 1


def contains_forbidden_keywords(complaint):
    for keyword in FILTER_KEYWORDS:
        if keyword.lower() in complaint:
            return True
    return False


@app.route("/", methods=["GET", "POST"])
def index():
    session["user"] = "test"
    command = request.form.get("cmd", "coding")
    return render_template("index.html", command=command)


@app.route("/test", methods=["GET", "POST"])
def shell():
    if session.get("user") != "test":
        return str("Auth.html")
    cmd = request.args.get("cmd", "试一试")
    if request.method == "POST":
        css_url = url_for("static", filename="style.css")
        command = request.form.get("cmd")
        if contains_forbidden_keywords(command):
            return str("forbidden.html")
        return render_template_string(
            f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Loving Music</title>
            <link rel="stylesheet" href="{css_url}">
            <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
        </head>
        <body>
            <div class="container">
                <h1>Loving coding</h1>
                <p class="emoji">🧑‍💻</p>
                <p>{command}</p>
            </div>
        </body>
        </html>
        """,
            command=command,
            css_url=css_url,
        )
    return str("shell.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8449, debug=True)
