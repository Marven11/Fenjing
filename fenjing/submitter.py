from typing import List, Callable, Union, NamedTuple, Dict
from urllib.parse import quote
import logging
import subprocess

from .form import Form, fill_form
from .requester import Requester
from .colorize import colored
from .const import CALLBACK_SUBMIT

logger = logging.getLogger("submitter")


Tamperer = Callable[[str], str]


def shell_tamperer(shell_cmd: str) -> Tamperer:
    def tamperer(payload: str):
        proc = subprocess.Popen(
            shell_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc.stdin.write(payload.encode())
        proc.stdin.close()
        ret = proc.wait()
        if ret != 0:
            raise ValueError(
                f"Shell command return non-zero code {ret} for input {payload}"
            )
        return proc.stdout.read().decode()

    return tamperer


class HTTPResponse(NamedTuple):
    """解析后的HTTP响应

    Args:
        status_code: 返回值
        text: HTTP的正文
    """

    status_code: int
    text: str


class BaseSubmitter:
    """
    payload提交器，其会发送对应的payload，并获得相应页面的状态码与正文
    其支持增加tamperer, 在发送之前对payload进行编码
    """

    def __init__(self, callback=None):
        self.tamperers: List[Tamperer] = []
        self.callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )

    def add_tamperer(self, tamperer: Tamperer):
        self.tamperers.append(tamperer)

    def submit_raw(self, raw_payload: str) -> Union[HTTPResponse, None]:
        raise NotImplementedError()

    def submit(self, payload: str) -> Union[HTTPResponse, None]:
        if self.tamperers:
            logger.debug("Applying tampers...")
            for tamperer in self.tamperers:
                payload = tamperer(payload)
        logger.debug("Submit %s", colored("blue", payload))
        return self.submit_raw(payload)


class FormSubmitter(BaseSubmitter):
    """
    向一个表格的某一项提交payload, 其他项随机填充
    """

    def __init__(
        self,
        url: str,
        form: Form,
        target_field: str,
        requester: Requester,
        callback: Union[Callable[[str, Dict], None], None] = None,
    ):
        """传入目标表格的url，form实例与目标表单项，以及用于提交HTTP请求的requester

        Args:
            url (str): 表格所在的url
            form (Form): 表格的实例
            target_field (str): 目标表单项
            requester (Requester): Requester实例，用于实际发送HTTP请求
        """
        super().__init__(callback)
        self.url = url
        self.form = form
        self.req = requester
        self.target_field = target_field

    def submit_raw(self, raw_payload: str) -> Union[HTTPResponse, None]:
        inputs = {self.target_field: raw_payload}
        resp = self.req.request(**fill_form(self.url, self.form, inputs))
        self.callback(
            CALLBACK_SUBMIT,
            {
                "type": "form",
                "form": self.form,
                "inputs": inputs,
                "response": resp,
            },
        )
        if resp is None:
            return None
        return HTTPResponse(resp.status_code, resp.text)


class PathSubmitter(BaseSubmitter):
    """将payload进行url编码后拼接在某个url的后面并提交，看见..和/时拒绝提交"""

    def __init__(
        self,
        url: str,
        requester: Requester,
        callback: Union[Callable[[str, Dict], None], None] = None,
    ):
        """传入目标URL和发送请求的Requester

        Args:
            url (str): 目标URL
            requester (Requester): Requester实例
        """
        super().__init__(callback)

        self.url = url
        self.req = requester

    def submit_raw(self, raw_payload: str) -> Union[HTTPResponse, None]:
        if any(w in raw_payload for w in ["/", ".."]):
            logger.info(
                "Don't submit %s because it can't be in the path.",
                colored("yellow", repr(raw_payload)),
            )
            return None
        resp = self.req.request(
            method="GET", url=self.url + quote(raw_payload)
        )
        self.callback(
            CALLBACK_SUBMIT,
            {
                "type": "path",
                "url": self.url,
                "payload": raw_payload,
                "response": resp,
            },
        )
        if resp is None:
            return None
        return HTTPResponse(resp.status_code, resp.text)


Submitter = BaseSubmitter
