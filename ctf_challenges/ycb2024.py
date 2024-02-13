from flask import Flask,request
from jinja2 import Template
import re

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get('name','CTFer<!--?guesswhat=CTFer')
    if not re.findall(r"'|_|\\x|\\u|{{|\+|attr|\.| |class|init|globals|popen|system|env|exec|shell_exec|flag|passthru|proc_popen",name):
        t = Template("hello "+name)
        return t.render()
    else:
        t = Template("Hacker!!!")
        return t.render()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)
