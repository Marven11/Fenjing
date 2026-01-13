# 环境

这是fenjing的源码，你可以使用nix flake进入开发shell

# 任务

- [ ] 当前cli.py启动攻击任务的流程较为混乱，需要重构
  - 设计: job.py
    - Job
      - context: 由任务指定类型的context
      - payload_geneartor: 攻击成功后获得的FullPayloadGen/EvalArgsModePayloadGen
      - submitter: 攻击成功后获得的submitter
    - (CrackForm/CrackFormEvalArgs/CrackPath/Scan/...)JobContext - 保存攻击所需要的静态的信息
      - url, form, requester, options, tamper_cmd, method, json_data, requests
    - 函数
      - do crack pre: 根据context的类型发动攻击，获得payload gen
      - do crack: 根据context和传入的exec_cmd等决定，开启交互模式或仅仅生成命令payload并上传
  - mcp禁止使用tamper_cmd
- [ ] 测试前几个任务维护的fenjing mcp功能
  - 将tests/vulunserver.py部署到secret中的dell nixos并访问
  - 调试mcp
    - 测试crack并执行ls /
    - 测试crack-path并执行ls /

# 写作文风

避免使用无序列表

不要使用emoji

文风简洁有力，就像在做学术报告一样

# 暂时搁置

# 注意

- 调试MCP
  - 必须在这台机器上进行调试
  - 必须使用revert_mcp.py脚本正确配置环境启动MCP: `nix develop --command python /路径/revert_mcp.py 'nix develop --command python -m fenjing mcp'`
  - 必须完整阅读revert_mcp.py脚本的代码再行动
  - 必须使用`python -m fenjing mcp`而不是直接启动子模块启动服务器！
  - 启动后：攻击需要大约1-10分钟，耐心等待攻击完成，每次等待约30秒
  - 禁止使用web端测试MCP
    - 你看不到web端的界面
    - 你没有图像识别能力
  - 禁止直接启动MCP server
    - MCP server启动时会一直等待stdin！除非获得inspector等的输入，否则会一直等待！
    - 必须通过inspector或者其他支持的客户端启动！
  - 禁止直接编写JSON RPC和MCP server通信
    - 你不知道MCP的通信流程！更不知道MCP的通信细节！
- 禁止编写临时脚本调试:
  - 临时脚本完全未经验证，更有可能存在bug
  - 你写出的实现本身就有问题，再继续写临时脚本只会写出更多问题！

# 【特别注意】

必须完整阅读https://modelcontextprotocol.io/docs/develop/build-server才能开始编写MCP服务器！

必须检查示例MCP服务器是否少于20行！如果你写不出少于20行的示例MCP服务器，则说明你根本没有阅读文档！必须重新阅读文档并编写！
