# xkinfoscan
xkInfoScan 是一款集成化的网络信息收集与安全扫描工具，支持 IP / 域名 / URL /信息追踪多维度目标探测，涵盖目录扫描、CMS 识别、漏洞检测、信息泄露挖掘、CDN 检测等核心功能，适用于渗透测试前期信息收集、网络资产测绘及安全风险评估场景。
工具设计遵循 模块化架构，各功能模块独立可配置，支持自定义扫描参数与结果导出，同时提供友好的命令行交互与彩色输出，降低使用门槛。
核心功能 🚀
基于代码分析，xkInfoScan 包含以下 8 大核心模块，覆盖网络信息收集全流程：

模块分类	具体功能	支持参数
信息追踪模块	IP / 手机号 / 用户名关联信息查询	-k（启用模块）
IP 扫描模块	基础信息探测、域名关联、RDAP 注册信息、地理定位、端口扫描、CDN 检测	-i <IP> + --ip-mode [base/domain/rdap/geo/port_scan/cdn]
域名扫描模块	WHOIS 查询、DNS 解析、子域名爆破、IP 绑定检测	-d <域名> + --domain-mode [whois/dns/subdomain/all]
目录扫描模块	基于字典的 Web 目录 / 文件探测，支持 HEAD/GET/POST 请求方法	-u <URL> + -s dir + -m [head/get/post]
CMS 识别模块	多模式 CMS 类型与版本探测（详细 / 快速 / 深度 / 极速）	-u <URL> + -s cms + --cms-mode [json/rapid/holdsword/fast]
漏洞检测模块	Web 应用漏洞（SQLi/XSS）、框架漏洞（Struts2/Spring）、中间件漏洞（Tomcat/Nginx）	-u <URL> + -s poc + --poc-mode [web/framework/middleware/port]
信息泄露模块	基础 / 深度 / 全面模式扫描，检测 SVN/Git/.DS_Store 等敏感文件泄露	-u <URL> + -s infoleak + --info-mode [basic/deep/full]
Web 专项模块	JS 信息提取（JSFinder）、API 接口探测（APIFinder）、403 禁止访问绕过	-u <URL> + -s [webscan/403bypass/leakattack]
环境准备 🛠️
1. 依赖安装
工具依赖 Python 3.7+ 环境，需先安装第三方库：

bash
# 安装核心依赖
pip install -r requirements.txt

核心依赖说明：

validators：URL / 域名格式合法性验证
colorama：命令行彩色输出
argparse：命令行参数解析（Python 内置）
其他模块依赖（如 requests、dnspython 等，需根据实际 requirements.txt 补充）
2. 目录结构
plaintext
xkInfoScan/
├── xkinfoscan.py          # 主程序入口
├── config/                # 功能模块目录
│   ├── dirscan.py         # 目录扫描模块
│   ├── cmsscan.py         # CMS识别模块
│   ├── domaininfo.py      # 域名信息模块
│   ├── ipinfo.py          # IP信息模块（含CDN检测）
│   ├── pocscan.py         # POC漏洞检测模块
│   ├── infoleak.py        # 信息泄露模块
│   ├── ghosttrack.py      # 信息追踪模块
│   ├── vuln/              # 常规漏洞扫描子模块
│   └── webscan/           # Web专项模块（JSFinder/403Bypass）
├── output/                # 扫描结果默认输出目录
└── requirements.txt       # 依赖库列表
使用指南 📝
基础语法
bash
python xkinfoscan.py [目标参数] [功能参数] [通用参数]
关键参数说明
参数分类	参数	说明	示例
目标参数	-u <URL>	目标 URL（需带 http/https）	-u https://example.com
-d <域名>	目标域名（不含协议头）	-d example.com
-i <IP>	目标 IP（支持单 IP / 网段）	-i 192.168.1.1
-k	启用信息追踪模块	-k
功能参数	-s <扫描类型>	指定扫描模块（dir/cms/poc 等）	-s infoleak
--ip-mode <模式>	IP 扫描子模式（如 cdn/port_scan）	--ip-mode cdn
--cms-mode <模式>	CMS 识别模式（如 rapid/fast）	--cms-mode fast
--poc-mode <模式>	POC 检测子模式（如 web/framework）	--poc-mode framework
通用参数	-o <路径>	结果导出路径（支持 CSV/JSON）	-o result.csv
-t <线程数>	扫描线程数（1-100，默认 10）	-t 30
--debug	开启调试模式（显示请求 / 响应详情）	--debug
常用场景示例
以下是工具高频使用场景的命令示例，覆盖核心功能：
1. CDN 检测（IP 模块新增功能）
bash
# 检测目标IP是否使用CDN
python xkinfoscan.py -i 1.1.1.1 --ip-mode cdn
2. 信息追踪（IP / 手机号 / 用户名查询）
bash
# 启用信息追踪模块，交互输入查询目标
python xkinfoscan.py -k
3. 域名全信息扫描
bash
# 扫描域名的WHOIS、DNS、子域名等全部信息，并导出到CSV
python xkinfoscan.py -d example.com --domain-mode all -o domain_result.csv
4. Web 目录扫描（自定义线程与请求方法）
bash
# 使用POST方法、50线程扫描目标URL目录
python xkinfoscan.py -u https://example.com -s dir -m post -t 50
5. 403 禁止访问绕过检测
bash
# 探测目标URL是否存在403绕过漏洞
python xkinfoscan.py -u https://example.com/admin -s 403bypass
6. 深度信息泄露扫描
bash
# 以深度模式扫描目标URL的敏感文件泄露（如.git/.svn）
python xkinfoscan.py -u https://example.com -s infoleak --info-mode deep --debug
注意事项 ⚠️
合法性声明：本工具仅用于 合法授权的网络测试，禁止用于未授权的攻击行为，使用者需承担相应法律责任。
性能优化：
大网段扫描（B 段 / A 段）会消耗大量时间与带宽，建议通过 -t 限制线程数（默认自动限制为 50）。
端口扫描与 POC 检测可能触发目标防护设备告警，建议提前沟通授权。
结果可靠性：
CDN 检测结果基于 IP 段与 ASN 分析，可能存在误判，建议结合多工具交叉验证。
信息泄露扫描依赖字典覆盖度，可自行扩展 config/ 下的字典文件提升效果。
调试与排错：
若程序异常终止，可添加 --debug 参数查看详细错误日志（如请求超时、模块依赖缺失）。
线程数超出 1-100 范围时，工具会自动调整至合法区间。
版本更新 📅
当前版本特性（V1.0）
✅ 新增 CDN 检测模块（--ip-mode cdn）
✅ 完善 403 绕过检测与信息泄露攻击模块
✅ 优化 IP 网段扫描逻辑（支持 A/B/C 段自动生成）
✅ 增加调试模式与错误详情输出
✅ 支持多格式结果导出（CSV/JSON）
许可证 📜
本项目基于 MIT License 开源，允许个人与商业使用，但需保留原作者版权信息，禁止用于非法用途。
联系方式 📧
若发现 BUG 或有功能建议，可通过以下方式反馈：

项目 Issues：提交问题（需替换为实际仓库地址）
开发者邮箱：example@xxx.com（需替换为实际邮箱）

提示：使用前建议先执行 python xkinfoscan.py -h 查看完整参数说明，或参考 config/ 下各模块代码了解具体实现逻辑。
