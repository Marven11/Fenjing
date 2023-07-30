"""与HTML表格相关的函数

"""
import sys
import random
import logging
import string
from typing import Dict, List, Union, Iterable
from urllib.parse import urlparse, urlunparse

from bs4 import BeautifulSoup

logger = logging.getLogger("utils.form")
Form = Dict[
    str,
    Union[str, set],
]
if sys.version_info >= (3, 8):
    from typing import Literal

    Form = Dict[
        Literal["action", "inputs", "method"],
        Union[str, set],
    ]


def get_form(action: str, inputs: Iterable, method: str = "POST") -> Form:
    """根据输入生成一个表单

    Args:
        action (str): action
        inputs (Iterable): 所有input
        method (str, optional): 提交方法. Defaults to "POST".

    Returns:
        Form: 表单
    """
    method = method.upper()
    if not action.startswith("/"):
        action = "/" + action
    assert method in ["GET", "POST"]
    return {"action": action, "method": method, "inputs": set(inputs)}


def parse_forms(url, html: Union[str, BeautifulSoup]) -> List[Form]:
    """从html中解析出对应的表单

    Args:
        url (str): HTML对应的URL
        html (Union[str, BeautifulSoup]): HTML

    Returns:
        List[Form]: 所有表单
    """
    parsed_url = urlparse(url)
    uri = parsed_url.path

    if isinstance(html, str):
        bs_doc = BeautifulSoup(html, "html.parser")
    elif isinstance(html, BeautifulSoup):
        bs_doc = html

    details = []
    for form_element in bs_doc.select("form"):
        form = get_form(
            action=form_element.attrs.get("action", uri),
            method=form_element.attrs.get("method", "POST").upper(),
            inputs=[
                element.attrs["name"]
                for element in form_element.select("input")
                if "name" in element.attrs
            ],
        )
        details.append(form)
    return details


def random_fill(form: Form) -> Dict[str, str]:
    """随机填充表格

    Args:
        form (Form): 表格

    Returns:
        Dict[str, str]: 随机填充的结果，键为表格项，值为表格项的值
    """
    return {
        k: "".join(random.choices(string.ascii_lowercase, k=8))
        for k in form["inputs"]
    }


def fill_form(url, form, form_inputs=None, randomly_fill_other=True):
    """根据输入填充表单，返回给requests库的参数

    Args:
        url (str): 表单所在的URL
        form (dict): 表单
        form_inputs (dict, optional): input以及对应的值. Defaults to None.
        randomly_fill_other (bool, optional): 是否随机填充其他input. Defaults to True.

    Returns:
        dict: 给requests的参数
    """
    if randomly_fill_other:
        fill = random_fill(form)
        if form_inputs is not None:
            fill.update(form_inputs)
    else:
        fill = form_inputs
    return {
        "url": urlunparse(urlparse(url)._replace(path=form["action"])),
        "method": form["method"],
        ("data" if form["method"] == "POST" else "params"): fill,
    }
