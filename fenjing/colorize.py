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
    if not IS_SUPPORTED_PLATFORM or not IS_COLORING_ENABLED:
        return text
    colors = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "purple": "35",
        "cyan": "36",
    }
    format_str = "\033[{};{}m{}\033[0m"
    if bold:
        format_str = "\033[1;{};{}m{}\033[0m"
    if color not in colors:
        color = "blue"
    return format_str.format(int(bold), colors[color], text)
