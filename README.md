# xkInfoScan - 多功能网络信息扫描工具 🕵️‍♂️

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-green.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Tool Type](https://img.shields.io/badge/Tool-Network%20Scanner-orange.svg)


## 项目简介 📖
xkInfoScan 是一款集成化的网络信息收集与安全扫描工具，支持 **IP/域名/URL/信息追踪 多维度目标探测**，涵盖目录扫描、CMS识别、漏洞检测、信息泄露挖掘、CDN检测等核心功能，适用于渗透测试前期信息收集、网络资产测绘及安全风险评估场景。

工具设计遵循 **模块化架构**，各功能模块独立可配置，支持自定义扫描参数与结果导出，同时提供友好的命令行交互与彩色输出，降低使用门槛。

**重要许可说明**：本项目基于 **GNU General Public License v3.0 (GPLv3)** 开源。根据协议要求，任何基于本项目的修改、衍生作品或集成到其他项目中的代码，必须以相同许可证（GPLv3）开源，且需保留原作者版权信息。


## 核心功能 🚀
基于代码分析，xkInfoScan 包含以下8大核心模块，覆盖网络信息收集全流程：

| 模块分类 | 具体功能 | 支持参数 |
|---------|---------|---------|
| **信息追踪模块** | IP/手机号/用户名关联信息查询 | `-k`（启用模块） |
| **IP扫描模块** | 基础信息探测、域名关联、RDAP注册信息、地理定位、端口扫描、CDN检测 | `-i <IP>` + `--ip-mode [base/domain/rdap/geo/port_scan/cdn]` |
| **域名扫描模块** | WHOIS查询、DNS解析、子域名爆破、IP绑定检测 | `-d <域名>` + `--domain-mode [whois/dns/subdomain/all]` |
| **目录扫描模块** | 基于字典的Web目录/文件探测，支持HEAD/GET/POST请求方法 | `-u <URL>` + `-s dir` + `-m [head/get/post]` |
| **CMS识别模块** | 多模式CMS类型与版本探测（详细/快速/深度/极速） | `-u <URL>` + `-s cms` + `--cms-mode [json/rapid/holdsword/fast]` |
| **漏洞检测模块** | Web应用漏洞（SQLi/XSS）、框架漏洞（Struts2/Spring）、中间件漏洞（Tomcat/Nginx） | `-u <URL>` + `-s poc` + `--poc-mode [web/framework/middleware/port]` |
| **信息泄露模块** | 基础/深度/全面模式扫描，检测SVN/Git/.DS_Store等敏感文件泄露 | `-u <URL>` + `-s infoleak` + `--info-mode [basic/deep/full]` |
| **Web专项模块** | JS信息提取（JSFinder）、API接口探测（APIFinder）、403禁止访问绕过 | `-u <URL>` + `-s [webscan/403bypass/leakattack]` |


## 许可协议说明 📜
本项目采用 **GNU General Public License v3.0 (GPLv3)** 授权，使用时需遵守以下核心条款：

1. **开源义务**：任何基于本项目的修改、衍生作品或二次开发成果，必须以 **GPLv3 许可证** 开源，公开完整源代码。
   
2. **商用限制**：允许商业使用，但所有包含本项目代码的商用产品必须开源其完整代码，且不得通过闭源方式限制他人获取源代码。

3. **版权保留**：修改或分发时，必须保留原作者的版权声明和许可证信息，不得移除或修改原始许可条款。

4. **衍生通知**：若对本项目进行修改，需在衍生作品中明确标注修改内容及原项目来源。

完整许可文本请参见 [LICENSE](LICENSE) 文件，或访问 [GPLv3 官方说明](https://www.gnu.org/licenses/gpl-3.0.html)。


## 环境准备 🛠️
### 1. 依赖安装
工具开发时使用 Python 3.12 环境，需先安装第三方库：
```bash
# 安装核心依赖
pip install -r requirements.txt
```
直接下载release压缩包即可，如果你是克隆的需要下载一个dat文件放在data目录里，否则ip地理信息模块不可用  
通过网盘分享的文件：GeoLiteCity.dat
链接: https://pan.baidu.com/s/1_Z-m7vzJGIOOBJ9FIkabXA 提取码: gffx 
--来自百度网盘超级会员v8的分享

### 2. 目录结构
```
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
├── LICENSE                # GPLv3 许可协议
└── requirements.txt       # 依赖库列表
```


## 使用指南 📝
### 基础语法
```bash
python xkinfoscan.py [目标参数] [功能参数] [通用参数]
```

### 关键参数说明
| 参数分类 | 参数 | 说明 | 示例 |
|---------|------|------|------|
| **目标参数** | `-u <URL>` | 目标URL（需带http/https） | `-u https://example.com` |
| | `-d <域名>` | 目标域名（不含协议头） | `-d example.com` |
| | `-i <IP>` | 目标IP（支持单IP/网段） | `-i 192.168.1.1` |
| | `-k` | 启用信息追踪模块 | `-k` |
| **功能参数** | `-s <扫描类型>` | 指定扫描模块（dir/cms/poc等） | `-s infoleak` |
| | `--ip-mode <模式>` | IP扫描子模式（如cdn/port_scan） | `--ip-mode cdn` |
| | `--cms-mode <模式>` | CMS识别模式（如rapid/fast） | `--cms-mode fast` |
| | `--poc-mode <模式>` | POC检测子模式（如web/framework） | `--poc-mode framework` |
| **通用参数** | `-o <路径>` | 结果导出路径（支持CSV/JSON） | `-o result.csv` |
| | `-t <线程数>` | 扫描线程数（1-100，默认10） | `-t 30` |
| | `--debug` | 开启调试模式（显示请求/响应详情） | `--debug` |


### 常用场景示例
以下是工具高频使用场景的命令示例，覆盖核心功能：

#### 1. ip信息探测
```
python xkinfoscan.py -i 1.1.1.1
```
<img width="338" height="295" alt="ip信息" src="https://github.com/user-attachments/assets/a3918687-609b-4d8a-aba8-863a5b198510" />  


<img width="310" height="374" alt="ip" src="https://github.com/user-attachments/assets/03efb6dd-3c5e-4bd1-8671-1c5fbb3c536a" />


#### 2. 信息追踪（IP/手机号/用户名查询）
```bash
# 启用信息追踪模块，交互输入查询目标
python xkinfoscan.py -k
```
<img width="337" height="222" alt="信息追踪" src="https://github.com/user-attachments/assets/5ac759bb-8f14-4563-a659-ef1944f36453" />



#### 3. 域名信息扫描
```bash
# 扫描域名的WHOIS、DNS、子域名等全部信息，并导出到CSV
python xkinfoscan.py -d example.com
```

<img width="233" height="189" alt="域名" src="https://github.com/user-attachments/assets/125d0979-3494-438c-81f7-abfbcb92590d" />

#### 4. url信息扫描
```bash
# 扫描域名的WHOIS、DNS、子域名等全部信息，并导出到CSV
python xkinfoscan.py -u http://example.com
```
<img width="226" height="242" alt="url" src="https://github.com/user-attachments/assets/52001cee-6697-4748-966a-14214eea94e6" />




## 注意事项 ⚠️
1. **合法性声明**：本工具仅用于 **合法授权的网络测试**，禁止用于未授权的攻击行为，使用者需承担相应法律责任。
   
2. **开源合规**：基于本项目进行二次开发、修改或集成到其他项目时，必须遵守 GPLv3 许可证要求，公开所有修改后的代码，并保留原始版权信息。

3. **性能优化**：
   - 大网段扫描（B段/A段）会消耗大量时间与带宽，建议通过 `-t` 限制线程数（默认自动限制为50）。
   - 端口扫描与POC检测可能触发目标防护设备告警，建议提前沟通授权。


## 版本更新 📅
### 当前版本特性（V1.0）
- ✅ CDN检测模块（`--ip-mode cdn`）
- ✅ 完善403绕过检测与信息泄露攻击模块
- ✅ 优化IP网段扫描逻辑（支持A/B/C段自动生成）
- ✅ 增加调试模式与错误详情输出
- ✅ 支持多格式结果导出（CSV/JSON）


## 联系方式 📧
若发现BUG或有功能建议，可通过以下方式反馈：
- 项目Issues：[提交问题](https://github.com/xk11z/xkInfoScan/issues)
- 开发者邮箱：xingxkllz@gmail.com

---
## 参考项目
https://github.com/lijiejie/GitHack  
https://github.com/lijiejie/ds_store_exp  
https://github.com/HunxByts/GhostTrack

