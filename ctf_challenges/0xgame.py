from flask import Flask, request, render_template, render_template_string
import os
app = Flask(__name__)

flag=os.getenv("flag")
os.unsetenv("flag")
@app.route('/')
def index():
    return open(__file__, "r").read()


@app.errorhandler(404)
def page_not_found(e):
    print(request.root_url)
    return render_template_string("<h1>The Url {} You Requested Can Not Found</h1>".format(request.url))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000)