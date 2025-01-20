"""一个可以被SSTI的服务器
"""

import random

from flask import Flask, request, render_template_string
from jinja2 import Template

app = Flask(__name__)

blacklist = [
    "\t",
    " ",
    "'",
    '"',
    "_",
    "getitem",
    "request",
    "popen",
    "cookies",
    "args",
    "class",
    "mro",
    "bases",
    "subclasses",
    "read",
    "globals",
    "init",
    ".",
    "eval",
    "import",
    "system",
    "builtins",
    "os",
    "pop",
    "[",
    "form",
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
