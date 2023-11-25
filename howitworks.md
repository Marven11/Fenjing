## 总览

焚靖使用自研算法动态生成语法树，从而生成payload

焚靖会先测试页面，拿到WAF页面的哈希，并据此生成payload，其中重点是生成表达式：

在用户指定生成目标后，焚靖会以深度优先的方式递归展开生成目标为一系列更小的节点，从而生成一棵语法树（大概算是，我还没学编译原理）并将语法树转换成payload

对于每一次展开，焚靖会测试展开结果是否可以通过WAF，如果可以就将展开结果返回，否则更换另一种展开方式。

## 生成表达式

比如说有两个生成字符串的规则：

1. 直接使用字符串的字面量：`"abcd"`
2. 将字符串拼接在一起：`"a""b""c""d"`

将这两个规则写成表达式后如下所示：

```python
def gen_string_1(value):
    return '"' + value + '"' # 这里是演示，暂时不处理转义

def gen_string_2(value):
    return "".join(repr(c) for c in value)
```

这样就可以通过调用这两个函数自动生成字符串的payload

然后还有两个取对象属性的规则：

1. 使用`[]`，如：`lipsum["__globals__"]`
2. 使用`|attr`filter, 如：`lipsum|attr("__globals__")`

将这两个规则写成表达式后如下所示：

```python
def gen_attribute_1(obj, attr_name):
    return f"{obj}[{repr(attr_name)}]"

def gen_attribute_2(obj, attr_name):
    return f"{obj}|attr{repr(attr_name)})"
```

那问题来了，我们要怎么取属性的规则调用取字符串的规则呢

我们可以这样，规定一系列元素：

- `("literal", "xxx")`代表值为xxx字面量
- `("string", "xxx")`代表值为"xxx"的字符串
- `("attribute", aaa, bbb)`代表取aaa的bbb属性，比如`("attribute", ("literal", "lipsum"), "__globals__")`

然后改写上面的字符串规则，让其返回一系列字面量元素：

```python
def gen_string_1(value):
    return [
        ("literal", '"' + value + '"')
    ]

def gen_string_2(value):
    return [
        ("literal", repr(c))
        for c in value
    ]
```

这样，这两个函数返回的就是一个列表，其中每一个元素都代表一个字面量

使用时需要将所有的字面量元素的值拼接起来。

改写上面取属性的规则：

```python
def gen_attribute_1(obj, attr_name):
    return [
        obj,
        ("literal", "["),
        ("string", attr_name),
        ("literal", "]"),
    ]

def gen_attribute_2(obj, attr_name):
    return [
        obj,
        ("literal", "|attr("),
        ("string", attr_name),
        ("literal", ")"),
    ]
```

这样，在利用上面的规则函数生成表达式时，我们就可以这样：

- 调用`gen_attribute_1(("literal", "lipsum"), "__globals__")`，拿到一系列元素的列表：
    - `[("literal", "lipsum"), ("literal", "["), ("string", "__globals__"), ("literal", "])]`
- 遍历这个列表，对`"string"`类型的元素使用上面的第一条规则将其展开成这个列表：
    - `[("literal", '"__globals__"')]`
- 最后我们就有了一棵语法树（是不是很像lisp）：

```python
[
    (("literal", "lipsum"), None),
    (("literal", "["), None),
    (("string", "__globals__"), [ # 这一段会被单独送给WAF检测
        (("literal", '"__globals__"'), None)
    ]),
    (("literal", "]"), None),
]
```

将这棵语法树中的literal元素的值拼接起来即可：`lipsum["__globals__"]`

然后，检测WAF是在上面将`("string", "__globals__")`展开成列表之后完成的，也就是检测其对应的生成结果是否能通过WAF。

如果能通过WAF就将其加入到树中, 如果不能就换一条规则。这个工具绕过WAF的魔法都是在这里完成的（

焚靖所有的绕过规则都在[payload_gen.py](fenjing/payload_gen.py)这个文件中，为了使用上下文中的变量和去除大部分括号我还加了一点内容，大致框架和上方相同。

## 生成最终的payload

就是检测`{{}}`之类的payload能不能通过WAF，可以的话就直接把表达式拼接进去。

## 生成WAF检测函数

首先用一系列经常被ban的payload产生WAF页面，然后收集WAF页面的哈希即可，最后对每一个待检测的payload检测其会不会导致产生WAF页面

