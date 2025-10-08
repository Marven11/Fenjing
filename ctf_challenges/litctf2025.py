from flask import Flask, request, render_template_string, jsonify
import html
import re

app = Flask(__name__)

html_page = """

"""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            data = request.get_json()
            cmd = data.get("cmd", "").strip()

            if not cmd:
                return "愿望内容不能为空哦～", 400

            text_pattern = re.compile(r"[a-zA-Z\u4e00-\u9fa5]")
            if not text_pattern.search(cmd):
                return "愿望需要包含文字内容噢）～", 400

            if (
                "{{" in cmd
                or "}}" in cmd
                or "eval" in cmd.lower()
                or "cat" in cmd.lower()
            ):
                return "❌ 愿望被神秘力量屏蔽了～", 200

            rendered = render_template_string(cmd)
            return html.unescape(rendered)

        except Exception as e:
            return f"处理愿望时出错：{str(e)}", 400
    return html_page


if __name__ == "__main__":
    app.run(debug=True)
