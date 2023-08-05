"""一个可以被SSTI的服务器
"""
import random

from flask import Flask, request, render_template_string

app = Flask(__name__)
blacklist = [
    '0"',
    ".",
    '"',
    "system",
    "eval",
    "exec",
    "popen",
    "subprocess",
    "posix",
    "builtins",
    "namespace",
    "read",
    "self",
    "mro",
    "base",
    "global",
    "init",
    "chr",
    "value",
    "pop",
    "import",
    "include",
    "request",
    "{{",
    "}}",
    "config",
    "=",
    "lipsum",
    "~",
    "url_for",
]


def waf_words(s):
    return [word for word in blacklist if word in s]


def waf_pass(s):
    return waf_words(s) == []


def lengthlimit1_waf_pass(s):
    if len(s) > 155:
        return False
    blacklist = [
        "[",
        "]",
    ]
    for ban in blacklist:
        if ban in s:
            return False
    return True


def lengthlimit2_waf_pass(inp):
    blacklist = [
        "mro",
        "url",
        "join",
        "attr",
        "dict",
        "()",
        "init",
        "import",
        "os",
        "system",
        "lipsum",
        "current_app",
        "globals",
        "subclasses",
        "|",
        "getitem",
        "popen",
        "read",
        "ls",
        "flag.txt",
        "cycler",
        "[]",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "=",
        "+",
        ":",
        "update",
        "config",
        "self",
        "class",
        "%",
        "#",
    ]
    for b in blacklist:
        if b in inp:
            return False
    if len(inp) <= 70:
        return True
    if len(inp) > 70:
        return False


@app.route("/", methods=["GET", "POST"])
def index():
    name = request.args.get("name", "world")
    template = f"""
Hello, {name}
<form action="/" method="GET">
<input type="text" name="name" id="">
<input type="submit" value="">
</form>
"""

    return render_template_string(template)


@app.route("/nonrespond", methods=["GET", "POST"])
def nonrespond():
    template = f"Hello, World!"

    return render_template_string(template)


@app.route("/verifyheader", methods=["GET", "POST"])
def verifyheader():
    user_agent = request.headers.get("User-Agent", "")
    custom_key = request.headers.get("Custom-Key", "")
    cookie_data = request.cookies.get("data", "")

    if "114514" not in user_agent:
        return "I want 114514 browser!"
    if "114514" not in custom_key:
        return "Set Custom-Key as 114514!"
    if "114514" not in cookie_data:
        return "Set data as 114514 in cookie!"
    name = request.args.get("name", "world")
    template = f"Hello, {name}"

    return render_template_string(template)


@app.route("/static_waf", methods=["GET", "POST"])
def static_waf():
    name = request.args.get("name", "world")
    if not waf_pass(name):
        return "Nope"
    template = f"Hello, {name}"
    return render_template_string(template)


@app.route("/static_waf2", methods=["GET"])
def static_waf2():
    # [安洵杯 2020]Normal SSTI，侵删
    url_black_list = ["%1c", "%1d", "%1f", "%1e", "%20", "%2b", "%2c", "%3c", "%3e"]
    black_list = [
        ".",
        "[",
        "]",
        "{{",
        "=",
        "_",
        "'",
        '""',
        "\\x",
        "request",
        "config",
        "session",
        "url_for",
        "g",
        "get_flashed_messages",
        "*",
        "for",
        "if",
        "format",
        "list",
        "lower",
        "slice",
        "striptags",
        "trim",
        "xmlattr",
        "tojson",
        "set",
        "=",
        "chr",
    ]
    url = request.url
    name = request.args.get("name", "")

    if any(w in url for w in url_black_list) or any(w in name for w in black_list):
        return "Nope"
    return render_template_string("Here: {}".format(name))


@app.route("/dynamic_waf", methods=["GET", "POST"])
def dynamic_waf():
    name = request.args.get("name", "world")
    if not waf_pass(name):
        return waf_words(name)[0]
    template = f"Hello, {name}"
    return render_template_string(template)


@app.route("/weird_waf", methods=["GET", "POST"])
def weird_waf():
    name = request.args.get("name", "world")
    if not waf_pass(name) and len(name) < 10 and random.random() < 0.9:
        return "Naidesu"
    template = f"Hello, {name}"
    return render_template_string(template)


@app.route("/reversed_waf", methods=["GET", "POST"])
def reversed_waf():
    name = request.args.get("name", "world")[::-1]
    if not waf_pass(name):
        return "Nope"
    template = f"Hello, {name}"
    return render_template_string(template)


@app.route("/lengthlimit1_waf", methods=["GET", "POST"])
def lengthlimit1_waf():
    name = request.args.get("name", "world")
    if not lengthlimit1_waf_pass(name):
        return "Nope"
    template = f"Hello, {name}"
    return render_template_string(template)


@app.route("/lengthlimit2_waf", methods=["GET", "POST"])
def lengthlimit2_waf():
    name = request.args.get("name", "world")
    if not lengthlimit2_waf_pass(name):
        return "Nope"
    template = f"Hello, {name}"
    return render_template_string(template)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
