from typing import Callable

from pygments.lexers.shell import BashLexer

from prompt_toolkit import PromptSession, print_formatted_text, HTML
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import style_from_pygments_cls
from prompt_toolkit.lexers import PygmentsLexer
from pygments.styles import get_style_by_name


# completer = WordCompleter(["@eval", "@get-config", "@help", "@ls", "@cat"])
completer = NestedCompleter.from_nested_dict(
    {
        "@eval": None,
        "@exec": None,
        "@get-config": None,
        "@ls": None,
        "@cat": None,
        "@help": {"eval", "get-config", "ls", "cat", "exec"},
    }
)
style = style_from_pygments_cls(get_style_by_name("inkpot"))

INTERACTIVE_MODE_HELP_LONG = """\
<orange><b>Interactive Console</b></orange>:
- type to execute shell command with os.popen()
- <blue>@eval</blue>: eval python expression on the target server
- <blue>@exec</blue>: exec one line of python statement on the server
- <blue>@get-config</blue>: get the config of the target server
- <blue>@help</blue>: show help, use @help subcommand to show subcommand help
- Press <blue>Ctrl+D</blue> to exit
<orange><b>交互终端</b></orange>：
- 输入任意命令即可在目标上用os.popen()执行
- <blue>@eval</blue>: 调用eval函数执行任意python表达式
- <blue>@exec</blue>: 调用exec函数执行任意python语句，仅支持一行
- <blue>@get-config</blue>: 获得目标的flask config
- <blue>@help</blue>: 获得帮助，使用@help subcommand查看子命令的帮助
- 按下<blue>Ctrl+D</blue>退出
Tab completion is available/有tab补全
<orange><b>Example/示例</b></orange>:
$>> ls /
$>> @eval 1+2+3+100000
$>> @exec print('Hello, World')
$>> @help
$>> @get-config
$>> @help eval\
"""

INTERACTIVE_MODE_HELP_SHORT = """\
<orange><b>Example/示例</b></orange>:
$>> ls /
$>> @eval 1+2+3+100000
$>> @get-config
Type @help for full help/输入@help获得完整帮助\
"""

HELPS = {
    "eval": "Eval any python expression, example: @eval 1+1+4+5+1+4",
    "exec": "Exec any python statement, which return nothing. example: @exec if 1 < 2: print('1 < 2!')",
    "get-config": "Get the config of the target, example: @get-config",
    "ls": "list the directory with python builtin os.listdir()",
    "cat": "read a file with python",
}


def interact(cmd_exec_func: Callable):
    print_formatted_text(HTML(INTERACTIVE_MODE_HELP_SHORT))
    # print(INTERACTIVE_MODE_HELP)
    session = PromptSession(
        lexer=PygmentsLexer(BashLexer),
        completer=completer,
        style=style,
        include_default_pygments_style=False,
    )
    while True:
        try:
            text = session.prompt("$>> ")
        except KeyboardInterrupt:
            print("Use Ctrl+D to exit!")
            continue
        except EOFError:
            break
        if text.strip() == "":
            continue
        if text.strip().lower()[:5] == "@help":
            text = text.strip().lower()
            if len(text) == 5:
                print_formatted_text(HTML(INTERACTIVE_MODE_HELP_LONG))
            else:
                subcommand = text[6:]
                help_text = HELPS.get(subcommand, None)
                if help_text:
                    print(help_text)
                else:
                    print(f"subcommand {repr(subcommand)} not found")
            continue
        result = cmd_exec_func(text)
        print(result)

    print("Bye!")
