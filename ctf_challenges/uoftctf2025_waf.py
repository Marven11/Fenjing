"""一个可以被SSTI的服务器
"""

import random

from flask import Flask, request, render_template_string
from jinja2 import Template

app = Flask(__name__)

blacklist = [
    "#",
    "%",
    "!",
    "=",
    "+",
    "-",
    "/",
    "&",
    "^",
    "<",
    ">",
    "and",
    "or",
    "not",
    "\\",
    "[",
    "]",
    ".",
    "_",
    ",",
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
    '"',
    "'",
    "`",
    "?",
    "attr",
    "request",
    "args",
    "cookies",
    "headers",
    "files",
    "form",
    "json",
    "flag",
    "lipsum",
    "cycler",
    "joiner",
    "namespace",
    "url_for",
    "flash",
    "config",
    "session",
    "dict",
    "range",
    "lower",
    "upper",
    "format",
    "get",
    "item",
    "key",
    "pop",
    "globals",
    "class",
    "builtins",
    "mro",
    "True",
    "False",
]


@app.route("/", methods=["GET", "POST"])
def index():
    name = request.args.get("name", "world")
    print(f"{name=}")
    if any(w in name for w in blacklist):
        return "NO!"
    template = f"""
Hello, {name}
"""

    return render_template_string(template)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
