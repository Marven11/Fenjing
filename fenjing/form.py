from urllib.parse import urlparse, urlunparse
from typing import Iterable
import random
import logging
import string
from typing import Dict, Any, List

from bs4 import BeautifulSoup

logger = logging.getLogger("utils.form")

def Form(*, action: str, inputs: Iterable, method: str = "POST") -> Dict[str, Any]:
    """根据输入生成一个表单

    Args:
        action (str): action
        inputs (Iterable): 所有input
        method (str, optional): 提交方法. Defaults to "POST".

    Returns:
        Dict[str, Any]: 表单
    """
    method = method.upper()
    if not action.startswith("/"):
        action = "/" + action
    assert method in ["GET", "POST"]
    return {
        "action": action,
        "method": method,
        "inputs": set(inputs)
    }


def parse_forms(url, html: str | BeautifulSoup) -> List[dict]:
    """从html中解析出对应的表单

    Args:
        url (str): HTML对应的URL
        html (str | BeautifulSoup): HTML

    Returns:
        List[dict]: 所有表单
    """
    parsed_url = urlparse(url)
    uri = parsed_url.path

    if isinstance(html, str):
        bs = BeautifulSoup(html, "html.parser")
    elif isinstance(html, BeautifulSoup):
        bs = html

    details = []
    for form_element in bs.select("form"):
        form = Form(
            action=form_element.attrs.get("action", uri),
            method=form_element.attrs.get("method", "POST").upper(),
            inputs=[
                element.attrs["name"]
                for element in form_element.select("input")
                if "name" in element.attrs
            ]
        )
        details.append(form)
    return details


def random_fill(form):
    """
    randomli fill the form
    """
    return {
        k: "".join(random.choices(string.ascii_lowercase, k=8))
        for k in form["inputs"]
    }


def fill_form(url, form, form_inputs = None, random_fill_other = True):
    """根据输入填充表单，返回给requests库的参数

    Args:
        url (str): 表单所在的URL
        form (dict): 表单
        form_inputs (dict, optional): input以及对应的值. Defaults to None.
        random_fill_other (bool, optional): 是否随机填充其他input. Defaults to True.

    Returns:
        dict: 给requests的参数
    """
    if random_fill_other:
        fill = random_fill(form)
        if form_inputs is not None:
            fill.update(form_inputs)
    else:
        fill = form_inputs
    return {
        "url": urlunparse(urlparse(url)._replace(path=form["action"])),
        "method": form["method"],
        ("data" if form["method"] == "POST" else "params"): fill
    }
