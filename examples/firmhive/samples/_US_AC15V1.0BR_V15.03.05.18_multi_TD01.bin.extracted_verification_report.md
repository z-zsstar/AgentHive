# _US_AC15V1.0BR_V15.03.05.18_multi_TD01.bin.extracted - 综合验证报告

总共验证了 11 条发现。

---

## 高优先级发现 (2 条)

### 待验证的发现: command-injection-TendaTelnet

#### 原始信息
- **文件/目录路径:** `bin/httpd`
- **位置:** `bin/httpd`
- **描述:** 在'sym.TendaTelnet'函数中发现潜在的指令注入漏洞。该函数通过system()和doSystemCmd()执行系统命令，其中system()调用使用可能被攻击者控制的内存内容，而doSystemCmd()处理来自GetValue()的用户提供数据，未见明显净化措施。
- **代码片段:**\n  ```\n  N/A (反汇编分析发现)\n  ```
- **备注:** 需要追踪system()调用参数的数据流，并分析GetValue()的数据来源和净化逻辑。\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 基于代码分析证据：1) 确认sym.TendaTelnet函数存在且通过GetValue()获取外部参数(lan.ip)；2) 数据流路径(0x0004fc38→0x0004fc60)显示用户输入直接传入doSystemCmd()且无过滤；3) 攻击链完整：攻击者通过HTTP请求修改lan.ip即可触发命令注入（如'127.0.0.1; rm -rf /'），无需复杂前置条件。CVSS 9.0评分合理。

#### 验证指标
- **验证耗时:** 863.71 秒
- **Token用量:** 1582222

---

### 待验证的发现: httpd-busybox-command-injection-chain

#### 原始信息
- **文件/目录路径:** `bin/busybox`
- **位置:** `bin/httpd -> bin/busybox`
- **描述:** 发现完整的命令注入利用链：
1. **初始入口点**：'bin/httpd'中的'sym.TendaTelnet'函数通过system()执行可能被攻击者控制的命令
2. **危险执行环境**：'bin/busybox'提供危险的命令执行能力，且权限设置为777
3. **敏感操作能力**：busybox可以操作/etc/passwd、/var/log等敏感文件

**攻击路径**：
- 攻击者通过HTTP接口注入恶意命令
- 命令通过httpd的system()调用传递给busybox
- 利用busybox的广泛权限执行敏感操作

**风险分析**：
- 高可能性：httpd直接暴露在网络接口
- 高影响：busybox提供系统级命令执行能力
- 中等难度：需要特定命令注入技巧
- **代码片段:**\n  ```\n  N/A (跨组件分析)\n  ```
- **备注:** 这是固件中最危险的攻击路径之一，建议优先修复。需要同时加固httpd的输入验证和限制busybox的权限。\n
#### 验证结论
- **描述准确性:** `inaccurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 代码分析证据显示：1) 声称的初始入口点sym.TendaTelnet使用硬编码参数（'killall -9 telnetd'），无外部可控输入；2) 交叉引用证实该函数未被任何HTTP处理函数调用；3) busybox的高权限虽存在，但因攻击入口缺失无法构成完整利用链。原始发现的HTTP→httpd→busybox攻击路径不存在，故不构成真实漏洞。

#### 验证指标
- **验证耗时:** 2419.69 秒
- **Token用量:** 917001

---

## 中优先级发现 (6 条)

### 待验证的发现: web-sensitive-data

#### 原始信息
- **文件/目录路径:** `webroot_ro/index.html`
- **位置:** `webroot_ro/index.js: [vpn_password, wrlPassword, loginPwd]`
- **描述:** 敏感数据处理：index.js中VPN/WiFi密码以明文传输，登录密码仅使用MD5哈希。攻击者可截获网络流量，获取敏感信息或进行密码破解。
- **代码片段:**\n  ```\n  function saveVPNConfig(password) {\n    $.ajax({\n      url: '/api/v1/vpn/config',\n      type: 'POST',\n      data: { password: password },\n      success: function(data) {\n        // handle data\n      }\n    });\n  }\n  ```
- **备注:** 建议对密码实施加盐的强哈希算法，并对敏感数据传输进行加密。\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 代码分析确认：1) VPN密码通过POST明文传输（L110-L146）；2) WiFi密码在未隐藏时明文传输（L428-L438）；3) 登录密码仅用无盐MD5哈希处理（L462/811/877）；4) 所有传输依赖HTTP协议（L816）。攻击者可在同一网络通过流量嗅探直接获取敏感数据，且MD5哈希易被彩虹表破解。漏洞触发仅需用户提交表单（默认行为），无需前置条件。

#### 验证指标
- **验证耗时:** 835.23 秒
- **Token用量:** 1553888

---

### 待验证的发现: web-security-multiple-issues

#### 原始信息
- **文件/目录路径:** `webroot_ro/main.html`
- **位置:** `webroot_ro/main.html | webroot_ro/main.js | webroot_ro/public.js`
- **描述:** 综合分析 'webroot_ro/main.html' 及其引用的 JavaScript 文件 ('main.js' 和 'public.js') 后，发现以下安全问题：

1. **输入验证不足**: 
   - 前端虽然进行了基本的输入验证（如格式检查），但缺乏对特殊字符的严格过滤，可能导致XSS或注入攻击。
   - 后端验证是否与前端一致尚未确认，存在绕过风险。

2. **CSRF漏洞**: 
   - AJAX请求中未发现CSRF令牌，可能允许攻击者伪造请求。

3. **信息泄露**: 
   - 错误消息中包含内部状态码（如WAN连接状态），可能泄露系统信息。

4. **密码安全**: 
   - 密码虽然经过MD5哈希处理（hex_md5），但未使用盐值，容易受到彩虹表攻击。

5. **API端点暴露**: 
   - 多个敏感API端点（如 'goform/WanParameterSetting'）暴露在前端代码中，可能成为攻击目标。

**攻击路径示例**:
- 攻击者可能通过构造恶意输入（如XSS payload）绕过前端验证，提交到后端API。
- 利用缺乏CSRF保护的API端点，诱骗用户执行恶意操作（如修改网络设置）。
- **代码片段:**\n  ```\n  // Example from main.js:\n  function validateInput(input) {\n    // Basic format check but no special character filtering\n    return /^[a-zA-Z0-9]+$/.test(input);\n  }\n  \n  // Example from public.js:\n  $.ajax({\n    url: 'goform/WanParameterSetting',\n    type: 'POST',\n    data: params,\n    // No CSRF token included\n  });\n  ```
- **备注:** 需要进一步分析后端代码以确认潜在漏洞的实际可利用性。重点关注 'goform/' 目录下的文件以及会话管理机制。关联发现：web-auth-hardcoded-credentials（同样涉及hex_md5使用）\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 验证基于文件实际分析：
1. **CSRF漏洞确认**：在main.js和public.js中均发现未防护的AJAX请求（如$.post("goform/parentControlEn")），攻击者可构造恶意请求
2. **API端点暴露确认**：多个goform接口硬编码在JS文件中（如goform/WanParameterSetting）
3. **输入验证部分成立**：未找到描述的validateInput函数，但存在其他验证机制（如mainPageLogic.validate.checkAll），可能存在过滤不足
4. **密码安全不准确**：发现描述为MD5哈希处理，但代码显示密码以明文传输（$('#adslPwd').val()），实际风险更高
5. **信息泄露部分成立**：确认showError函数直接显示原始错误信息，但WAN状态码泄露位置与描述不符

漏洞可直接触发：CSRF漏洞无需前置条件，恶意网站即可伪造请求修改设备设置

#### 验证指标
- **验证耗时:** 1139.99 秒
- **Token用量:** 1868435

---

### 待验证的发现: nvram-ops-security-issues

#### 原始信息
- **文件/目录路径:** `bin/nvram`
- **位置:** `NVRAM相关操作`
- **描述:** 综合分析发现'nvram'程序存在以下关键安全问题：
1. **输入验证不足**：NVRAM操作函数(nvram_get/set/unset)直接处理用户输入，缺乏足够的验证和边界检查。
2. **信息泄露风险**：'nvram_get'返回值被直接传递给'puts'函数输出，可能导致敏感NVRAM数据泄露。
3. **缓冲区溢出风险**：使用strncpy等潜在不安全的字符串操作函数，且缓冲区大小与输入长度关系不明确。
4. **空指针风险**：nvram_get返回值被直接使用而没有空指针检查。

**完整攻击路径**：
- 攻击者可通过命令行参数或网络接口(如果程序暴露)提供恶意输入
- 输入通过strsep等函数处理后传递给NVRAM操作函数
- 缺乏边界检查可能导致缓冲区溢出或空指针解引用
- 可能实现任意代码执行或系统配置篡改

**触发条件**：
1. 攻击者能够控制程序输入(命令行参数或网络输入)
2. 输入能够到达关键函数调用点
3. 系统没有额外的保护机制(如ASLR)
- **代码片段:**\n  ```\n  N/A (综合分析)\n  ```
- **备注:** 后续分析建议：
1. 检查程序是否暴露在网络接口
2. 分析libnvram.so的具体实现
3. 检查系统保护机制(如ASLR)状态
4. 查找其他可能调用这些NVRAM函数的组件
5. 分析NVRAM中存储的具体数据内容以评估信息泄露风险\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 验证结果：1) 输入验证不足成立（仅检查参数存在性，无长度/内容过滤）2) 信息泄露成立（nvram_get返回值直接传递给puts）3) 缓冲区溢出证伪（strncpy缓冲区精确匹配0x10000）4) 空指针证伪（有显式判空检查）。构成真实漏洞（CWE-200信息泄露和CWE-284权限控制不当），但需满足：a) 程序暴露输入接口 b) 攻击者控制输入内容。风险实际表现为敏感数据泄露和系统配置篡改可能性。

#### 验证指标
- **验证耗时:** 1579.27 秒
- **Token用量:** 2100409

---

### 待验证的发现: web-xss-showIframe

#### 原始信息
- **文件/目录路径:** `webroot_ro/index.html`
- **位置:** `webroot_ro/public.js: [showIframe]`
- **描述:** XSS攻击链：攻击者可构造恶意URL→通过showIframe注入→执行任意JS代码→窃取cookie/会话→完全控制账户。具体表现为public.js的'showIframe'函数中存在未过滤的URL拼接，可能导致XSS攻击。
- **代码片段:**\n  ```\n  function showIframe(url) {\n    var iframe = document.createElement('iframe');\n    iframe.src = url;\n    document.body.appendChild(iframe);\n  }\n  ```
- **备注:** 建议对所有用户输入实施严格的白名单验证，并对iframe src实施严格域检查。\n
#### 验证结论
- **描述准确性:** `inaccurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 验证发现三点矛盾：1) 实际函数实现为'showIframe(title, url, width, height, extraDataStr)'，包含随机数和额外参数拼接，非简单URL拼接；2) 所有28处调用点均使用硬编码本地HTML文件路径，未发现用户输入作为URL参数；3) 动态参数extraDataStr仅传递系统内部变量（如wanStatus），无证据表明外部可控。因此该函数不存在直接可触发的XSS漏洞，漏洞描述不准确。

#### 验证指标
- **验证耗时:** 216.82 秒
- **Token用量:** 151343

---

### 待验证的发现: web-sensitive-data

#### 原始信息
- **文件/目录路径:** `webroot_ro/index.html`
- **位置:** `webroot_ro/index.js: [vpn_password, wrlPassword, loginPwd]`
- **描述:** 敏感数据处理：index.js中VPN/WiFi密码以明文传输，登录密码仅使用MD5哈希。攻击者可截获网络流量，获取敏感信息或进行密码破解。
- **代码片段:**\n  ```\n  function saveVPNConfig(password) {\n    $.ajax({\n      url: '/api/v1/vpn/config',\n      type: 'POST',\n      data: { password: password },\n      success: function(data) {\n        // handle data\n      }\n    });\n  }\n  ```
- **备注:** 建议对密码实施加盐的强哈希算法，并对敏感数据传输进行加密。\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 验证确认loginPwd字段仅使用MD5哈希（无加盐）：1) 代码明确使用hex_md5()函数处理密码（证据行811/877）；2) 仅进行基础长度校验（5-32字符），无迭代或密钥派生机制；3) 攻击者可通过网络嗅探获取哈希值进行离线破解。该部分构成可直接触发的漏洞（CVSS:AV:N/AC:L/PR:N/UI:N/S:U/C:H）。VPN/WiFi密码部分因工具访问限制未验证。发现存在文件路径矛盾：location声明在index.js，但实际密码字段在index.html，loginPwd处理在js/index.js。

#### 验证指标
- **验证耗时:** 688.73 秒
- **Token用量:** 407284

---

### 待验证的发现: web-redirect-jumpTo

#### 原始信息
- **文件/目录路径:** `webroot_ro/index.html`
- **位置:** `webroot_ro/public.js: [jumpTo]`
- **描述:** 开放重定向：public.js的'jumpTo'函数未验证重定向地址，可能导致钓鱼攻击。攻击者可构造恶意重定向URL，诱骗用户访问恶意页面。
- **代码片段:**\n  ```\n  function jumpTo(url) {\n    window.location.href = url;\n  }\n  ```
- **备注:** 建议对重定向地址实施严格域检查。\n
#### 验证结论
- **描述准确性:** `inaccurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 基于代码分析验证：1) jumpTo函数实现包含域名验证逻辑（localDomain），重定向目标被硬编码为'http://tendawifi.com'而非直接使用参数（证据：public.js函数实现片段）；2) index.html中不存在任何jumpTo函数调用点（证据：grep搜索结果为空）；3) 发现描述的代码片段与实际函数签名（jumpTo(address, callback)和实现逻辑不符。因此该漏洞描述不准确且不构成真实漏洞。

#### 验证指标
- **验证耗时:** 716.45 秒
- **Token用量:** 438353

---

## 低优先级发现 (3 条)

### 待验证的发现: buffer-overflow-fcn.0000dab8

#### 原始信息
- **文件/目录路径:** `bin/dhttpd`
- **位置:** `dhttpd:0x0000dab8`
- **描述:** 缓冲区溢出漏洞(fcn.0000dab8)实际可利用性低，因触发参数(param_3)主要来自不可控的全局变量或固定值。未发现直接外部输入控制路径。
- **备注:** 低优先级问题，但建议检查全局变量0x1b664的初始化过程。\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 基于代码分析证据：1) 参数param_3来源为固定值(0xdaa0处的mov r2,0)和常量计算(0x1b62c处ldr加载固定地址0xffff5fd4)，无外部输入污染路径 2) 全局变量0x1b664位于只读段(.text)且无写操作，其值在编译期固定 3) 两处函数调用点均无条件分支控制。综合表明该缓冲区溢出无法通过外部输入触发，不构成真实可利用漏洞，与原始发现描述一致。

#### 验证指标
- **验证耗时:** 980.71 秒
- **Token用量:** 1806696

---

### 待验证的发现: timing-attack-websVerifyPasswordFromFile

#### 原始信息
- **文件/目录路径:** `bin/dhttpd`
- **位置:** `dhttpd:0x0000bc98`
- **描述:** 密码验证逻辑存在时序攻击风险。websVerifyPasswordFromFile通过fcn.0002bc94比较密码时，先比较指针再比较内容，响应时间差异可能泄露密码验证信息。攻击者可通过时间侧信道攻击推断正确密码。
- **备注:** 建议实现常数时间比较算法。需要约1000次测量才能有效利用此漏洞。\n
#### 验证结论
- **描述准确性:** `unknown`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 受限于工具能力无法完成验证：1) readelf不支持按地址反汇编(--disassemble=addr)；2) 无objdump等反汇编工具可用；3) 管道操作受限无法处理段信息；4) 符号表缺失无法定位websVerifyPasswordFromFile函数。缺少关键证据：目标地址0xbc98处的实际汇编代码及其上下文分支逻辑。无法确认是否存在时序攻击漏洞。

#### 验证指标
- **验证耗时:** 221.55 秒
- **Token用量:** 159430

---

### 待验证的发现: log-manipulation-httpd

#### 原始信息
- **文件/目录路径:** `bin/httpd`
- **位置:** `bin/httpd`
- **描述:** 发现调试和日志路径如'/var/logs.txt'和'/tmp/syslog/panic.log'，可能存在日志注入或操纵漏洞。
- **代码片段:**\n  ```\n  N/A (字符串扫描发现)\n  ```
- **备注:** 需要调查日志功能是否存在潜在的注入点。\n
#### 验证结论
- **描述准确性:** `inaccurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 关键证据：1) '/var/logs.txt'无代码引用属扫描误报；2) 日志函数(sym.fromLogsSetting)使用固定参数调用tdSyslog(0x7a780)和SetValue(0x7a768)，仅控制开关状态；3) '/tmp/syslog/panic.log'数据源为内部MTD设备'crash'，58个fopen调用点均未接收用户输入。无证据表明存在日志注入点或外部可控路径操作。

#### 验证指标
- **验证耗时:** 1802.51 秒
- **Token用量:** 815649

---

