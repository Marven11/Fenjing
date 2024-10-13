"""实际发出网络请求并返回响应
"""

import logging
import traceback
import time
import socket
import ssl
import re
from urllib.parse import parse_qs
from typing import Union, Tuple
import requests

from fenjing.colorize import colored
from .const import DEFAULT_USER_AGENT

logger = logging.getLogger("requester")

# 处理bytes形式的HTTP请求的一系列函数
Response = Tuple[int, str]


def check_line_break(req_pattern: bytes) -> Union[None, bool]:
    """检查换行符，提取Host header前方的换行符并检查

    Args:
        req_pattern (bytes): HTTP请求的模板

    Returns:
        Union[None, bool]: 检查结果，失败时为None
    """
    linebreak_pos = req_pattern.find(b"Host: ")
    if not linebreak_pos:
        return None
    linebreak = req_pattern[linebreak_pos - 2 : linebreak_pos]
    linebreak = bytes(c for c in linebreak if c in b"\r\n")
    if linebreak == b"\r\n" or linebreak == b"\n\r":
        return True
    elif linebreak == b"\n":
        return False
    return None


def fix_line_break(req_pattern: bytes) -> bytes:
    """修正换行符

    Args:
        req_pattern (bytes): 需要修正的请求模板

    Returns:
        bytes: 修正结果
    """
    line_header, _, body = req_pattern.partition(b"\n\n")
    return line_header.replace(b"\n", b"\r\n") + b"\r\n\r\n" + body


def get_tail(req_pattern: bytes) -> Tuple[Union[bytes, None], int]:
    """获得HTTP请求结尾的换行符

    Args:
        req_pattern (bytes): 需要检查的请求模板

    Returns:
        Tuple[Union[bytes, None], int]: 检查结果，换行符以及数量
            找不到时返回None, 0
    """
    lbs = [
        b"\r\n",
        b"\n\r",
        b"\n",
    ]
    for lb in lbs:
        if req_pattern[-len(lb) :] == lb:
            count = 1
            while req_pattern[-count * len(lb) :] == lb * count:
                count += 1
            count -= 1
            return lb, count
    return None, 0


def check_tail(req_pattern: bytes) -> bool:
    """检查HTTP结尾的换行符

    Args:
        req_pattern (bytes): 需要检查的HTTP请求模板

    Returns:
        bool: 检查结果
    """
    return get_tail(req_pattern)[1] == 2


def fix_tail(req_pattern: bytes) -> bytes:
    """修复HTTP请求结尾的换行符

    Args:
        req_pattern (bytes): 请求

    Returns:
        bytes: 修复结果
    """
    lb, count = get_tail(req_pattern)
    if lb is None:
        return req_pattern
    if count <= 2:
        return req_pattern + lb * (2 - count)
    return req_pattern[: -len(lb) * 2 - count]


class TCPRequester:
    """通过创建TCP Socket直接发送原始请求的类"""

    def __init__(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        retry_times=5,
        interval=0.05,
    ):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.interval = interval
        self.retry_times = retry_times
        self.last_request_time: Union[float, None] = None

    def _get_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        if self.use_ssl:
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            sock = ssl_context.wrap_socket(sock)
        sock.connect((self.host, self.port))
        return sock

    def _recv_all(self, sock, bufsize=1024):
        data = b""
        while True:
            chunk = sock.recv(bufsize)
            if not chunk:
                break
            data += chunk
        return data

    def _request_once(self, request: bytes):
        if self.last_request_time:
            duration = time.perf_counter() - self.last_request_time
            if duration < self.interval:
                time.sleep(self.interval - duration)
        self.last_request_time = time.perf_counter()

        try:
            sock = self._get_socket()
        except Exception as exception:
            logger.warning("Get socket failed: %s", repr(exception))
            logger.debug(traceback.format_exc())
            return None

        try:
            sock.sendall(request)
        except Exception as exception:
            logger.warning("Send request failed: %s", repr(exception))
            logger.debug(traceback.format_exc())
            return None

        response = None
        try:
            response = self._recv_all(sock)
        except Exception as exception:
            logger.warning("Receive response failed: %s", repr(exception))
            logger.debug(traceback.format_exc())
            return None
        response = response.decode()
        status_code_result = re.search(r"\d{3}", response.partition("\n")[0])
        if status_code_result is None:
            logging.warning("Failed to find status code: %s", response)
            return None

        try:
            sock.close()
        except Exception as exception:
            logger.warning("Close socket failed, ignoring... %s", repr(exception))

        return int(status_code_result.group(0)), response.partition("\r\n\r\n")[2]

    def request(self, request: bytes) -> Union[Response, None]:
        """发送bytes形式的HTTP请求

        Args:
            request (bytes): 请求

        Returns:
            Union[Response, None]: 响应
        """
        for _ in range(self.retry_times):
            resp = self._request_once(request)
            if resp is not None:
                return resp
        return None


class HTTPRequester:
    """实际发送HTTP请求的类"""

    def __init__(
        self,
        interval=0.0,
        timeout=10,
        retry_times=5,
        retry_interval=1,
        retry_status=(429,),
        user_agent=DEFAULT_USER_AGENT,
        headers=None,
        extra_params_querystr=None,
        extra_data_querystr=None,
        proxy=None,
        no_verify_ssl = False,
    ):
        self.interval = interval
        self.timeout = timeout
        self.retry_times = retry_times
        self.retry_interval = retry_interval
        self.retry_status = retry_status
        self.no_verify_ssl = no_verify_ssl
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.session.verify = not no_verify_ssl
        self.last_request_time = 0
        self.extra_params = {}
        self.extra_data = {}

        if interval > 1:
            logger.warning(
                "Request interval might be %s: %.2fs between two requests.",
                colored("yellow", "too large"),
                interval,
            )

        if headers:
            self.session.headers.update(headers)

        if extra_params_querystr:
            self.extra_params = parse_qs(extra_params_querystr)

        if extra_data_querystr:
            self.extra_data = parse_qs(extra_data_querystr)

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def request_once(self, **kwargs):
        """发出一次网络请求，失败时返回None

        Returns:
            Union[Response, None]: 返回的响应
        """
        duration = time.perf_counter() - self.last_request_time
        if duration < self.interval:
            time.sleep(self.interval - duration)

        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout
        resp = None
        try:
            resp = self.session.request(**kwargs)
        except Exception as exception:  # pylint: disable=W0718
            logger.warning("Request failed with exception: %s", repr(exception))
            logger.debug(traceback.format_exc())
            return None
        if resp.status_code in self.retry_status:
            logger.warning(
                "%s: status code is %s, try to sleep +1s",
                colored("yellow", "Rate limit", bold=True),
                colored("yellow", str(resp.status_code)),
            )
            logger.warning(
                "You might want to use `--interval` option to set request interval."
            )
            time.sleep(1)
            return None
        if resp.status_code not in [200, 500]:
            logger.warning(
                "Not expected status code: %s ... continue anyway",
                colored("yellow", str(resp.status_code)),
            )

        self.last_request_time = time.perf_counter()
        return resp

    def request(self, **kwargs):
        """发送请求，自动重试

        Returns:
            Union[Response, None]: 响应
        """
        if self.extra_params:
            params = self.extra_params.copy()
            params.update(kwargs.get("params", {}))
            kwargs["params"] = params
        if self.extra_data:
            if kwargs["method"] not in ("POST", "PUT", "DELETE", "PATCH"):
                logger.warning(
                    "Method %s might not need a request body, still adding extra data anyway.",
                    kwargs["method"],
                )
            data = self.extra_data.copy()
            data.update(kwargs.get("data", {}))
            kwargs["data"] = data
        for _ in range(self.retry_times):
            resp = self.request_once(**kwargs)
            if resp is not None:
                return resp
        return None
