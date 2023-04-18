import requests
import logging
import traceback
import time

logger = logging.getLogger("requester")
DEFAULT_USER_AGENT = "Fenjing/0.1"

class Requester:
    def __init__(
        self,
        interval=0,
        timeout=10,
        retry_times=5,
        retry_interval=1,
        retry_status=(429, ),
        user_agent=DEFAULT_USER_AGENT
    ):
        self.interval = interval
        self.timeout = timeout
        self.retry_times = retry_times
        self.retry_interval = retry_interval
        self.retry_status = retry_status
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.last_request_time = 0

    def request_once(self, **kwargs):
        duration = time.perf_counter() - self.last_request_time
        if duration < self.interval:
            time.sleep(self.interval - duration)

        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout
        try:
            r = self.session.request(**kwargs)
        except Exception as e:
            logging.warning(f"Exception found when requesting: {type(e)}")
            logging.debug(traceback.format_exc())
            return None
        if r.status_code in self.retry_status:
            return None

        self.last_request_time = time.perf_counter()
        return r

    def request(self, **kwargs):
        for i in range(self.retry_times - 1):
            r = self.request_once(**kwargs)
            if r:
                return r
        return self.request_once(**kwargs)
