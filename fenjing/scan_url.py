"""扫描指定的网站并返回所有表格

"""

import logging
from typing import Union, Generator, Tuple, List
from .form import parse_forms, Form
from .requester import Requester
from bs4 import BeautifulSoup

logger = logging.getLogger("scan_url")


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
        element.attrs["href"]
        for element in bs_obj.select("a")
        if "href" in element
    ]


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
        targets += parse_urls(html)
    if not found:
        logger.warning("Exit without finding <form> element")
