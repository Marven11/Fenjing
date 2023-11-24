"""扫描指定的网站并返回所有表格

"""

import logging
import re
import random
import string

from urllib.parse import urlparse
from typing import Union, Generator, Tuple, List

from bs4 import BeautifulSoup

from .form import get_form, parse_forms, Form
from .requester import Requester
from .colorize import colored

logger = logging.getLogger("scan_url")
PARAM_CHUNK_SIZE = 150


def parse_urls(html: Union[str, BeautifulSoup]) -> list:
    """从html中解析出所有的链接

    Args:
        html (str|BeautifulSoup): HTML

    Returns:
        List[str]: 所有链接
    """
    if isinstance(html, str):
        bs_obj = BeautifulSoup(html, "html.parser")
    elif isinstance(html, BeautifulSoup):
        bs_obj = html

    return [
        element.attrs["href"] for element in bs_obj.select("a") if "href" in element
    ]


def burst_respond_params_data(
    requester: Requester, url: str, html_str: str
) -> Tuple[List[str], List[str]]:
    """根据初始HTML文本爆破对应的URL是否有对应的参数

    Args:
        requester (Requester): Requester
        url (str): 目标url
        html_str (str): 目标的HTML文本

    Returns:
        Tuple[List[str], List[str]]: 产生回显的GET参数和POST参数
    """
    words = re.findall(r"\w{1,30}", html_str) + re.findall(r"[a-zA-Z0-9_-]{1,30}", html_str)
    words = list(set(words))
    random.shuffle(words)
    if len(words) > PARAM_CHUNK_SIZE * 50:
        logger.warning("found %d params, don't burst", len(words))
        return [], []
    logger.warning("Bursting %d params...", len(words))
    respond_get_params, respond_post_params = set(), set()

    for i in range(0, len(words), PARAM_CHUNK_SIZE):
        words_chunk = words[i : i + PARAM_CHUNK_SIZE]
        for _ in range(3):
            params = {
                k: "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
                for k in words_chunk
            }
            data = {
                k: "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
                for k in words_chunk
            }
            resp = requester.request(method="GET", url=url, params=params)
            if resp:
                respond_get_params |= set(k for k, v in params.items() if v in resp.text)
            resp = requester.request(method="POST", url=url, data=data)
            if resp:
                respond_post_params |= set(k for k, v in data.items() if v in resp.text)

    return respond_get_params, respond_post_params


def yield_form(
    requester: Requester, start_url: str
) -> Generator[Tuple[str, List[Form]], None, None]:
    """根据起始URL扫描出所有的表格

    Args:
        requester (Requester): HTTP工具类Requester
        start_url (str): 起始URL

    Yields:
        Generator[Tuple[str, List[Form]], None, None]:
            所有URL与其中的表格
    """
    found = False
    targets = [
        start_url,
    ]
    visited = set()
    logger.warning("Start scanning")
    while targets:
        target_url = targets.pop(0)
        if target_url in visited:
            continue
        visited.add(target_url)

        resp = requester.request(method="GET", url=target_url)
        if resp is None:
            logger.warning("Fetch URL %s failed!", target_url)
            continue

        html = BeautifulSoup(resp.text, "html.parser")
        forms = parse_forms(target_url, html)

        if forms:
            yield target_url, forms
            found = True

        respond_get_params, respond_post_params = burst_respond_params_data(
            requester, target_url, resp.text
        )
        if respond_get_params and len(respond_get_params) < 5:
            logger.warning("Found get params with burst: %s", colored("blue", repr(respond_get_params)))
            yield target_url, [
                get_form(
                    action=urlparse(target_url).path,
                    inputs=respond_get_params,
                    method="GET",
                )
            ]
            found = True
        if respond_post_params and len(respond_get_params) < 5:
            logger.warning("Found post params with burst: %s", colored("blue", repr(respond_post_params)))
            yield target_url, [
                get_form(
                    action=urlparse(target_url).path,
                    inputs=respond_post_params,
                    method="POST",
                )
            ]
            found = True

        targets += parse_urls(html)
    if not found:
        logger.warning("Found nothing.")
