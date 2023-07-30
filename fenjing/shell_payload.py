"""生成执行Shell指令的payload
"""

from typing import Callable, Tuple, Dict, Union

from .const import OS_POPEN_READ
from .full_payload_gen import FullPayloadGen

full_payload_store: Dict[int, FullPayloadGen] = {}


def exec_cmd_payload(
    waf_func: Callable[
        [
            str,
        ],
        bool,
    ],
    cmd: str,
) -> Tuple[Union[str, None], Union[bool, None]]:
    """根据提供的waf函数为一个shell命令生成对应的payload

    Args:
        waf_func (Callable[[str, ], bool]): waf函数，判断提供的payload能否通过waf, 能则返回True
        cmd (str): 需要执行的shell命令

    Returns:
        Tuple[str|None, bool|None]: 对应的payload, 以及payload是否能生成回显
    """
    full_payload = None
    if id(waf_func) not in full_payload_store:
        full_payload = FullPayloadGen(waf_func)
        full_payload_store[id(waf_func)] = full_payload
    else:
        full_payload = full_payload_store[id(waf_func)]
    return full_payload.generate(OS_POPEN_READ, cmd)
