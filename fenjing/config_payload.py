"""生成获取config的payload

"""

from typing import Callable, Dict, Union

from .const import CONFIG
from .full_payload_gen import FullPayloadGen

full_payload_store: Dict[int, FullPayloadGen] = {}


def config_payload(
    waf_func: Callable[
        [
            str,
        ],
        bool,
    ]
) -> Union[str, None]:
    """根据提供的waf函数生成读取config的payload

    Args:
        waf_func (Callable[[str, ], bool]): waf函数，判断提供的payload能否通过waf, 能则返回True

    Returns:
        str|None: payload
    """
    full_payload = None
    if id(waf_func) not in full_payload_store:
        full_payload = FullPayloadGen(waf_func)
        full_payload_store[id(waf_func)] = full_payload
    else:
        full_payload = full_payload_store[id(waf_func)]
    payload, will_print = full_payload.generate(CONFIG)
    if not will_print:
        return None
    return payload
