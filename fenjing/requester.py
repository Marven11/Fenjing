"""实际发出网络请求并返回响应
"""

import logging
import traceback
import time
from urllib.parse import parse_qs

import requests

from fenjing.colorize import colored
from .const import DEFAULT_USER_AGENT

logger = logging.getLogger("requester")


class Requester:
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
    ):
        self.interval = interval
        self.timeout = timeout
        self.retry_times = retry_times
        self.retry_interval = retry_interval
        self.retry_status = retry_status
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.last_request_time = 0
        self.extra_params = {}
        self.extra_data = {}

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
