"""一个可以被SSTI的服务器
"""

from flask import Flask
from flask import request
from flask import render_template_string

app = Flask(__name__)
@app.route('/',methods=['GET', 'POST'])
def test():
    name = request.args.get("name", "world")
    template = '''
        <!-- ?name= -->
        <div class="center-content error">
            <h1>Hello %s!<br/>Welcome To My Blog</h1>
        </div> 
    ''' %(name)

    return render_template_string(template)

if __name__ == '__main__':
    app.run(host="0.0.0.0",port=5000)
