# 环境

这是fenjing的源码，你可以使用nix flake进入开发shell

# 任务

你需要为fenjing添加MCP支持, 支持AI通过MCP调用fenjing, 实现CLI支持的功能, 暂时只添加crack和crack path功能

AI可以连接对应的MCP使用这个功能

你需要为fenjing添加一个subcommand: fenjing mcp

# fenjing mcp设计

mcp包含两个工具工具和两个操控session的工具

crack工具接收这些参数

- url
  - 弃用action
- method
- inputs
  - 弃用exec_cmd
- interval

crack path工具接收这些参数

- url
  - 弃用action
- interval

先不要实现上面未提及的参数，包括

- detect_mode等

以上两个工具在实施攻击成功后返回一个uuid4格式的session id，代表一个成功攻击的session

agent在拿到session id后，可以带着session id调用session execute command工具，在目标上执行对应的命令

也可以调用session generate payload工具，生成shell命令对应的payload

# 步骤

- [ ] 创建/tmp/fenjing/文件夹，并创建/tmp/fenjing/STATUS.md，接下来每完成一个milestone就在/tmp/fenjing/STATUS.md中记录状态
- [ ] 在flake.nix等处配置MCP依赖
- [ ] 阅读https://modelcontextprotocol.io/docs/develop/build-server和https://modelcontextprotocol.io/docs/develop/build-client，并将fetch_article的结果复制到/tmp/fenjing/
- [ ] 在/tmp/fenjing/编写一个示例，让MCP客户端调用MCP服务器，理论上来说示例MCP客户端不需要LLM也能正常调用MCP服务器
- [ ] 再在/tmp/fenjing/编写一个MCP调试客户端，可以通过调试客户端调试MCP服务器：列出MCP服务器的工具，传入JSON调用MCP服务器的工具并获得完整结果。
- [ ] 使用MCP调试客户端调试示例MCP服务器，确认MCP调试客户端可以正常使用
- [ ] 参考tests/vulunserver.py在/tmp/fenjing/编写一个示例SSTI服务器，可以被crack和crack-path攻击，并尝试攻击，确认其可以被正常攻击
- [ ] 编写/tmp/fenjing/DESIGN.md，阐述如何根据上面的设计实现fenjign mcp功能
- [ ] 实现fenjing mcp，为mcp添加crack和crack-path功能
- [ ] 尝试使用MCP调试客户端调试fenjing mcp
- [ ] 尝试连接fenjing mcp，攻击示例SSTI服务器
- [ ] 报告以下结果: 示例MCP客户端/服务端, MCP调试客户端, fenjing mcp 测试结果到/tmp/fenjing/RESULT.md

# 写作文风

避免使用无序列表

不要使用emoji

文风简洁有力，就像在做学术报告一样

# 【特别注意】

必须完整阅读https://modelcontextprotocol.io/docs/develop/build-server才能开始编写MCP服务器！

必须检查示例MCP服务器是否少于20行！如果你写不出少于20行的示例MCP服务器，则说明你根本没有阅读文档！必须重新阅读文档并编写！
