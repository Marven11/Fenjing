"""向某个表格或者路径发出payload的submitter
"""

import logging
import subprocess
import html

from typing import List, Callable, Union, NamedTuple, Dict
from urllib.parse import quote

from .form import Form, fill_form
from .requester import Requester
from .colorize import colored
from .const import CALLBACK_SUBMIT

logger = logging.getLogger("submitter")


Tamperer = Callable[[str], str]


def shell_tamperer(shell_cmd: str) -> Tamperer:
    """返回一个新的shell tamperer

    Args:
        shell_cmd (str): 用于修改payload的命令

    Returns:
        Tamperer: 新的Tamperer
    """

    def tamperer(payload: str):
        proc = subprocess.Popen(
            shell_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert proc.stdin and proc.stdout
        proc.stdin.write(payload.encode())
        proc.stdin.close()
        ret = proc.wait()
        if ret != 0:
            raise ValueError(
                f"Shell command return non-zero code {ret} for input {payload}"
            )
        out = proc.stdout.read().decode()
        if out.endswith("\n"):
            logger.warning(
                "Tamperer %s output %s ends with '\\n', it may cause some issues.",
                shell_cmd,
                out,
            )
        return out

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
        """增加新的tamperer

        Args:
            tamperer (Tamperer): 新的tamperer
        """
        self.tamperers.append(tamperer)

    def submit_raw(self, raw_payload: str) -> Union[HTTPResponse, None]:
        """提交tamperer修改后的payload

        Args:
            raw_payload (str): payload

        Returns:
            Union[HTTPResponse, None]: payload提交结果
        """
        raise NotImplementedError()

    def submit(self, payload: str) -> Union[HTTPResponse, None]:
        """调用tamperer修改payload并提交

        Args:
            raw_payload (str): payload

        Returns:
            Union[HTTPResponse, None]: payload提交结果
        """
        if self.tamperers:
            logger.debug("Applying tampers...")
            for tamperer in self.tamperers:
                payload = tamperer(payload)
        logger.debug("Submit %s", colored("blue", payload))
        resp = self.submit_raw(payload)
        if resp is None:
            return None
        return HTTPResponse(resp.status_code, html.unescape(resp.text))


class RequestSubmitter(BaseSubmitter):
    """向一个url提交GET或POST数据"""

    def __init__(
        self,
        url: str,
        method: str,
        target_field: str,
        params: Union[Dict[str, str], None],
        data: Union[Dict[str, str], None],
        requester: Requester,
    ):
        """传入目标的URL, method和提交的项

        Args:
            url (str): 目标URL
            method (str): 方法
            target_field (str): 目标项
            params (Union[Dict[str, str], None]): 目标GET参数
            data (Union[Dict[str, str], None]): 目标POST参数
        """
        super().__init__()
        self.url = url
        self.method = method
        self.target_field = target_field
        self.params = params if params else {}
        self.data = data if data else {}
        self.req = requester

    def submit_raw(self, raw_payload):
        params, data = self.params.copy(), self.data.copy()
        if self.method == "POST":
            data.update({self.target_field: raw_payload})
        else:
            params.update({self.target_field: raw_payload})
        logger.info(
            "Submit %s",
            colored("blue", f"{self.url} {self.method} params={params} data={data}"),
        )
        return self.req.request(
            method=self.method, url=self.url, params=params, data=data
        )


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
        if not url.endswith("/"):
            logger.warning("PathSubmitter get a url that's not ends with '/', appending it.")
            url += "/"
        self.url = url
        self.req = requester

    def submit_raw(self, raw_payload: str) -> Union[HTTPResponse, None]:
        if any(w in raw_payload for w in ["/", ".."]):
            logger.info(
                "Don't submit %s because it can't be in the path.",
                colored("yellow", repr(raw_payload)),
            )
            return None
        resp = self.req.request(method="GET", url=self.url + quote(raw_payload))
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
