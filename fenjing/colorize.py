"""给字符串加上ANSI转义符以在命令行中打印出颜色

"""

import platform

IS_SUPPORTED_PLATFORM = platform.system() != "Windows"
IS_COLORING_ENABLED = False


def set_enable_coloring(enable=True):
    """打开或关闭默认关闭的字符串上色

    Args:
        enable (bool, optional): 设置是否开启. Defaults to True.
    """
    global IS_COLORING_ENABLED  # pylint: disable=W0603
    IS_COLORING_ENABLED = enable


def colored(color, text, bold=False):
    """使用ANSI转义字符对文本上色，在windows下不会上色

    Args:
        color (str): 使用的颜色
        text (str): 要上色的字符串
        bold (bool, optional): 是否加粗. Defaults to False.

    Returns:
        str: 上色后的字符串
    """
    return text  # TODO: remove this function
