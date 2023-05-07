import platform

SHOULD_COLOR = platform.system() != "Windows"


def colored(color, text, bold=False):
    if not SHOULD_COLOR:
        return text
    colors = {
        'red': '31',
        'green': '32',
        'yellow': '33',
        'blue': '34',
        'purple': '35',
        'cyan': '36',
    }
    format_str = '\033[{};{}m{}\033[0m'
    if bold:
        format_str = '\033[1;{};{}m{}\033[0m'
    if color not in colors:
        color = 'blue'
    return format_str.format(int(bold), colors[color], text)