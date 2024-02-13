from flask import Flask, request, render_template, render_template_string,send_from_directory
import re
import os
import logging

app = Flask(__name__)
app.logger.disabled = True
log = logging.getLogger('werkzeug')
log.disabled = True

@app.route('/', methods=['GET', 'POST'])
def index():
    return str('index.html')

@app.route('/secr3ttt', methods=['GET', 'POST'])
def secr3t():

    name = request.args.get('klf', '')
    template = f'''
        klf不会连这都绕不过去吧～
        你好！%s
       '''
    bl = ['_', '\\', '\'', '"', 'request', "+", 'class', 'init', 'arg', 'config', 'app', 'self', 'cd', 'chr',
          'request', 'url', 'builtins', 'globals', 'base', 'pop', 'import', 'popen', 'getitem', 'subclasses', '/',
          'flashed', 'os', 'open', 'read', 'count', '*', '43', '45', '38', '124', '47', '59', '99', '100', 'cat', '~',
          ':', 'not', '0', 'length', 'index', '-', 'ord', '37', '94', '96', '48', '49', '50', '51', '52', '53', '54',
          '55', '56', '57',
          '58', '59', '[', ']', '@', '^', '#', 'dict(dict']
    for i in bl:
        if i in name:
            return str('klf.html')
            #return "真是klf！！！回去多学学啦"

    two_bracket_pattern = r"\s*\)\s*\)"
    two_bracket_match = re.search(two_bracket_pattern, name)
    bracket_comma_bracket_pattern = r"\s*\)\s*(,)?\s*\)"
    bracket_comma_bracket_match = re.search(bracket_comma_bracket_pattern, name)
    bracket_bracket_line_pattern = r"\s*\)\s*\)\s*\|"
    bracket_bracket_line_match = re.search(bracket_bracket_line_pattern, name)
    comma_bracket_bracket_line_pattern = r"\s*,\s*\)\s*\)\s*\|"
    comma_bracket_bracket_line_match = re.search(comma_bracket_bracket_line_pattern, name)
    # 2 % 1 | asdf % asdf
    pattern_mo = r"\d+\s*%\s*\d+|[a-zA-Z]+\s*%\s*[a-zA-Z]+"
    matche_mo = re.search(pattern_mo, name)

    if two_bracket_match:
        if bracket_comma_bracket_match.group(1):
            print("bracket_comma_bracket_match: " + name)
            return str('klf.html')
        elif comma_bracket_bracket_line_match:
            print("comma_bracket_bracket_line_match: " + name)
            return str('klf.html')
        elif bracket_bracket_line_match:
            print("bracket_bracket_line_match: " + name)
            # return render_template_string(template % name)
            return str('klf.html')
        else:
            print("two_bracket_match: " + name)
            return str('klf.html')

    # 输出匹配的结果
    if matche_mo :
        print("match_mo: " + name)
        return str('klf.html')


    a=render_template_string(template % name)
    print("passed: " + name)
    if "{" in a:
        return a + str('win.html')
    return  a
@app.route('/robots.txt', methods=['GET'])
def robots():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'robots.txt', mimetype='text/plain')




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7888, debug=False)
