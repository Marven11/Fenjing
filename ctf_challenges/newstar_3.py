from flask import Flask, request
from jinja2 import Template
import re

app = Flask(__name__)


@app.route("/")
def index():
    name = request.args.get("name", "CTFer")
    if not re.findall(
        r'class|init|mro|subclasses|flag|cat|env|"|eval|system|popen|globals|builtins|\+| |attr|\~|request|\:|base|\{\%|_',
        name,
    ):
        t = Template(
            "<body bgcolor=#6B6882><br><p><b><font color='white' size=6px><center>Welcome to NewStarCTF Again And Again, Dear "
            + name
            + "</font></center></b></p><br><hr><br><font color='white' size=6px><center>Try to GET me a NAME</center></font><!--This is Hint: Waf Has Been Updated Again, More And More Safe!--></body>"
        )
        return t.render()
    else:
        t = Template("Get Out!Hacker!")
        return t.render()


if __name__ == "__main__":
    app.run()
