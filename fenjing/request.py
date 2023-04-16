import requests
import time
from functools import wraps

def retry_status_code(status_codes=(429, )):
    def _decorator(f):
        @wraps(f)
        def f1(*args, **kwargs):

            resp = f(*args, **kwargs)
            while resp.status_code in status_codes:
                time.sleep(0.5)
                resp = f(*args, **kwargs)
            return resp
        return f1
    return _decorator


def base_request(*args, **kwargs):
    session = requests.Session()
    session.mount("http://", requests.adapters.HTTPAdapter(max_retries=10))
    session.mount("https://", requests.adapters.HTTPAdapter(max_retries=10))
    while True:
        try:
            r = session.request(*args, **kwargs)
            return r
        except requests.exceptions.Timeout:
            continue


common_request = retry_status_code([429, ])(base_request)

