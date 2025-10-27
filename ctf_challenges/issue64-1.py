import random
from flask import Flask, render_template_string, render_template, request

app = Flask(__name__)

nicknames = ['Is %s 20 years old?', 'Are you 18 years old, %s?', 'Let me guess! %s is 19 years old.', '%s may be an adult.', '%s is probably old.', '%s is 21 years old.']

blacklist = ['}}', '{{', ']', '[', ']', '\'', ' ', '+', '_', '.', 'x', 'g', 'request', 'print', 'args', 'values', 'input', 'globals', 'getitem', 'class', 'mro', 'base', 'session', 'add', 'chr', 'ord', 'redirect', 'url_for', 'popen', 'os', 'read', 'flag', 'config', 'builtins', 'get_flashed_messages', 'get', 'subclasses', 'form', 'cookies', 'headers']

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            p = request.values.get('nickname')
            id = random.randint(0, len(nicknames) - 1)
            if p != None:
                for s in blacklist:
                    if s in p:
                        return 'Hacker! restricted characters!'
                     
                return render_template_string(nicknames[id] % p)

        except Exception as e:
            print(e)
            return 'Exception'
            
    return str('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
