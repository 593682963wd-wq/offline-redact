# 离线不可逆文本脱敏

保留中文证件/电话/邮箱/地址等识别及校验、网络标识识别和重叠消歧；支持嵌套JSON值脱敏与不含原值的统计。

## 使用

Python 3.11+。在本目录建立独立虚拟环境：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python cli.py example.json
.venv/bin/python -m unittest discover -v
```

`example.json`从零编写，仅含虚构输入。可以显式提供自己的同结构JSON文件。输出默认为终端；`--output result.json`使用独占创建，避免覆盖已有结果。CLI失败退出码2。

## 数据与边界

不发现本机账号、不读取环境中的模型密钥、不发送消息、不请求远端数据。只处理调用方明确传入的文件、记录或参数。合成示例不代表任何实际业务结果。仅保留离线规则引擎；未保留GUI、OCR/Office解析、学习库、可逆token、密钥、代理或剪贴板守护。JSON键名不脱敏，调用方必须检查字段名。

## 发布状态

本项目源码采用 MIT 许可证，见 LICENSE。依赖按各自上游许可使用，安装的依赖/模型/字体/媒体不随此源码目录分发。

## 2026-11-08 候选修订

- 覆盖内层匹配的URL/DB_URL/秘密优先整体遮盖。
- API秘密包含可见标点，避免只遮盖前缀。
- 网络模式边界使用ASCII限定，兼容中文相邻标签。
- IPv6候选经ipaddress验证，支持压缩写法。

使用包内合成样例复跑；发布集合根目录的 `verify_release.py --project personal-redaction` 会依次执行测试和首次使用命令。原有版本的测试计数属于当时记录，本轮汇总以集合验证报告为准。

授权头中的Bearer空格语法、带空格或转义引号的成对引号密码，会完整遮盖值；不保证识别所有未知密钥格式，交付前仍需人工复核。
