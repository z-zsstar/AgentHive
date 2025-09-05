# Archer_C3200_V1_150831 - 综合验证报告

总共验证了 11 条发现。

---

## 高优先级发现 (4 条)

### 待验证的发现: configuration-passwd-account_misconfig

#### 原始信息
- **文件/目录路径:** `etc/passwd.bak`
- **位置:** `etc/passwd.bak`
- **描述:** passwd.bak中存在高危账户配置：1)admin账户(UID=0)配置可交互/bin/sh，使攻击者获取该账户权限即可获得完整root shell 2)nobody账户(UID=0)虽被锁定但存在被激活风险 3)admin和nobody的家目录设置为根目录(/)，违反最小权限原则，若配合目录权限配置不当，可导致敏感文件泄露。触发条件：攻击者通过弱密码爆破、服务漏洞或中间件漏洞获取admin凭证后，可执行任意命令。利用方式：通过SSH/Telnet等远程服务登录admin账户，直接获得root权限的交互式shell。
- **备注:** 需后续验证：1)/etc/shadow中admin密码强度 2)网络服务是否开放admin远程登录 3)根目录权限设置(ls -ld /)\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 1) passwd.bak证据确证：admin账户UID=0配置/bin/sh可获root shell；nobody账户UID=0被锁定但存在激活风险；两家目录均为/违反最小权限原则 2) 根目录权限777(drwxrwxrwx)证实'目录权限配置不当'风险 3) 构成真实漏洞因：攻击者获取admin凭证后即可通过/bin/sh获得完整root权限 4) 非直接触发因：需要前置条件(如弱密码爆破或服务漏洞获取凭证) 5) 局限性：未验证shadow密码强度及远程服务开放情况，但核心配置错误已构成漏洞基础

#### 验证指标
- **验证耗时:** 260.90 秒
- **Token用量:** 168682

---

### 待验证的发现: untrusted-file-upload-softup

#### 原始信息
- **文件/目录路径:** `web/main/softup.htm`
- **位置:** `softup.htm:表单区域`
- **描述:** 文件上传功能存在用户可控输入点：1) HTML表单参数'filename'接受任意文件上传至/cgi/softup 2) 前端仅验证非空(ERR_FIRM_FILE_NONE)，未对文件类型/大小/内容做边界检查 3) 攻击者可构造恶意固件文件触发后端漏洞。实际影响取决于/cgi/softup对上传文件的处理：若未验证文件签名或存在解析漏洞，可导致任意代码执行或设备变砖。
- **备注:** 需分析/cgi/softup二进制验证文件处理逻辑\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 验证结果：1) 前端描述准确：softup.htm存在未过滤的文件上传表单（字段名filename），仅验证非空（ERR_FIRM_FILE_NONE） 2) 后端风险无法验证：经全面搜索（cgi-bin、cgi目录及全局文件系统），未找到/cgi/softup处理程序。缺少关键证据：a) 文件签名检查实现 b) 固件解析逻辑 c) 潜在漏洞利用路径。因此，无法确认是否构成真实漏洞（如代码执行/变砖），漏洞链不完整且无法直接触发。

#### 验证指标
- **验证耗时:** 461.50 秒
- **Token用量:** 361664

---

### 待验证的发现: weak-creds-ftp-vsftpd_passwd

#### 原始信息
- **文件/目录路径:** `etc/vsftpd_passwd`
- **位置:** `etc/vsftpd_passwd`
- **描述:** vsftpd密码文件采用自定义格式存储明文凭证，存在3个弱密码账户（admin:1234, guest:guest, test:test）。攻击者通过FTP服务发起暴力破解（如使用hydra工具）可在秒级时间内获取有效凭证。成功登录后：1) 可上传恶意文件（如webshell）至服务器；2) 可下载敏感文件；3) 若vsftpd配置不当可能获得更高权限。触发条件为FTP服务开启且暴露于网络。
- **代码片段:**\n  ```\n  admin:1234:1:1;guest:guest:0:0;test:test:1:1;\n  ```
- **备注:** 关联发现：config-ftp-anonymous-default（位于etc/vsftpd.conf）。后续建议：1) 检查/etc/vsftpd.conf配置是否允许匿名登录或存在目录遍历漏洞；2) 验证FTP服务是否在web界面被调用（如www目录中的PHP脚本）\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 验证结论基于以下证据：1) etc/vsftpd_passwd文件确认存在且包含admin:1234等弱密码（准确）；2) etc/vsftpd.conf配置local_enable=YES和write_enable=YES（准确）。但关键缺失证据：A) 未找到FTP服务启动机制（rcS/inetd.conf均无启动指令）；B) 未确认密码文件加载方式（二进制/PAM中无关联）。由于漏洞触发前提（FTP服务运行）未被证实，该发现不构成真实可利用漏洞。

#### 验证指标
- **验证耗时:** 721.86 秒
- **Token用量:** 497293

---

### 待验证的发现: firmware-burn-chain

#### 原始信息
- **文件/目录路径:** `web/main/softup.htm`
- **位置:** `softup.htm:JS代码区域`
- **描述:** 固件烧录流程暴露危险操作链：1) 前端通过$.cgi异步调用/cgi/softburn 2) 烧录操作无二次确认机制 3) IGD_DEV_INFO数据结构暴露设备详情。若攻击者结合文件上传漏洞控制烧录内容，可完整劫持设备。触发条件：污染filename参数→绕过前端验证→利用/cgi/softup漏洞写入恶意固件→触发/cgi/softburn执行。
- **代码片段:**\n  ```\n  $('#t_upgrade').click(function(){\n    if($("#filename").val() == ""){\n      $.alert(ERR_FIRM_FILE_NONE);\n      return false;\n    }\n    // 调用/cgi/softburn\n  });\n  ```
- **备注:** 关键攻击链：filename→/cgi/softup→/cgi/softburn。需验证烧录签名检查。关联：IGD_DEV_INFO设备信息泄露（见device-info-leak）辅助构造针对性恶意固件\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 验证结果：1) 前端JS逻辑（softup.htm）确认存在/cgi/softburn调用且文件名验证可绕过 - 符合描述 2) 关键攻击链环节（/cgi/softup文件上传和/cgi/softburn固件执行）因程序文件缺失无法验证 3) IGD_DEV_INFO仅在前端获取版本号，未发现完整数据结构泄露 4) 零证据证明固件签名检查机制存在或缺失。结论：攻击链描述部分准确（前端逻辑），但因核心二进制证据缺失，无法证实完整漏洞存在。漏洞触发需依赖未验证的后端操作，故非直接触发且整体不构成已验证漏洞。

#### 验证指标
- **验证耗时:** 846.06 秒
- **Token用量:** 403650

---

## 中优先级发现 (4 条)

### 待验证的发现: network_input-ethWan-ACT_OP_network_control

#### 原始信息
- **文件/目录路径:** `web/main/ethWan.htm`
- **位置:** `ethWan.htm (JavaScript函数)`
- **描述:** ethWan.htm暴露高风险网络操作接口：包含ACT_OP_DHCP_RELEASE/ACT_OP_PPP_DISCONN等8个网络控制端点，通过$.act()调用。污染参数username/pwd/customMacAddr通过wan_pppoelistarg对象直接传递，触发条件为：1) 用户通过表单提交恶意参数 2) 绕过或有缺陷的客户端验证 3) 后端缺乏输入过滤。可导致：凭证窃取(通过username/pwd)、网络服务中断(通过连接操作)、MAC欺骗(通过customMacAddr)。
- **备注:** 关联发现：unified-act-framework-vuln（共用$.act框架）、network_input-diagnostic_csrf（类似无保护的ACT_OP操作）。待验证：1) 未确定$.act()请求的实际处理程序(cgi路径) 2) 未验证后端对username/pwd参数的过滤机制 3) 未确认ACT_OP操作是否受权限控制。下一步：分析cgi-bin目录下处理ACT_OP请求的文件；追踪wan_pppoelistarg参数在后端的使用路径；验证customMacAddr是否直接写入网络配置。\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 1) 代码证实存在ACT_OP_DHCP_RELEASE等8个高危端点（L126-164）且通过$.act()直接调用 2) 参数username/pwd/customMacAddr确实通过wan_pppoelistarg对象传递（L43-45,70） 3) 客户端验证可绕过（如直接构造请求跳过$.alert验证）4) 无后端过滤证据且接口无CSRF保护（同notes关联发现）。满足：污染参数直接传递+无有效服务端防护+可直接触发网络操作。

#### 验证指标
- **验证耗时:** 109.45 秒
- **Token用量:** 91105

---

### 待验证的发现: xss-parental-control-device-name

#### 原始信息
- **文件/目录路径:** `web/main/parentCtrl.htm`
- **位置:** `www/parentCtrl.htm: initDeviceUnderParentalCtrlTable函数, 动态元素追加逻辑`
- **描述:** 存储型XSS漏洞：在initDeviceUnderParentalCtrlTable和URL添加逻辑中，用户控制的deviceName/description/urlAddr直接通过innerHTML插入DOM。攻击者通过修改设备配置（需低权限）注入恶意脚本，当管理员查看页面时触发。触发条件：1) 攻击者能修改设备名/URL列表（结合CSRF可绕过权限）2) 管理员访问家长控制页。实际影响：完全控制管理员会话，可操作所有路由器功能。
- **代码片段:**\n  ```\n  $("#addUrl").append('<div ... value="' + allBlackUrl[blackIndex] + '" ...');\n  ```
- **备注:** 需验证$.isdomain过滤有效性；建议后续测试XSS实际触发并分析会话劫持后操作\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 基于代码分析确认：1) 用户控制的deviceName/description参数通过$("#deviceName").val()和$("#description").val()获取，未进行HTML编码或过滤 2) 这些参数直接作为HTML内容插入表格单元格($.initTableBody函数) 3) 攻击者可通过低权限设备配置接口注入恶意脚本 4) 管理员查看家长控制页(parentCtrl.htm)时自动执行脚本。代码中未见任何防护措施，漏洞触发路径完整且直接。

#### 验证指标
- **验证耗时:** 444.54 秒
- **Token用量:** 352546

---

### 待验证的发现: network_input-login_token_generation-1

#### 原始信息
- **文件/目录路径:** `web/frame/login.htm`
- **位置:** `web/frame/login.htm`
- **描述:** 登录认证令牌生成与存储漏洞：1) 客户端将明文密码通过Base64编码生成'Basic'认证令牌，相当于明文传输（Base64可逆）2) 令牌以cookie存储未设置HttpOnly属性，存在XSS窃取风险。触发条件：a) 用户提交登录表单时网络未加密 b) 存在跨站脚本漏洞时可窃取cookie。实际影响：攻击者可截获或窃取令牌直接获得认证权限。
- **代码片段:**\n  ```\n  auth = "Basic " + Base64Encoding($username.value + ":" + $password.value);\n  document.cookie = "Authorization=" + auth;\n  ```
- **备注:** 需验证服务端是否强制HTTPS传输。关联线索：Base64Encoding/PCSubWin关键词在历史记录中出现，可能存在数据流关联\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 代码证据完全支持发现描述：1) 在web/frame/login.htm中确认存在'Basic '+Base64Encoding(...)的令牌生成逻辑，相当于明文传输凭证 2) document.cookie设置确未包含HttpOnly/Secure属性 3) 文件扫描证实无HTTPS强制机制。该漏洞在用户登录时通过PCSubWin()函数直接触发，攻击者可在未加密网络截获令牌或通过XSS窃取cookie直接获得认证权限，无需额外前置条件。CVSS 8.5评分合理。

#### 验证指标
- **验证耗时:** 487.83 秒
- **Token用量:** 388790

---

### 待验证的发现: wds-bridge-xss-vector

#### 原始信息
- **文件/目录路径:** `web/main/sysconf.htm`
- **位置:** `web/sysconf.htm WDS表单`
- **描述:** WDS桥接配置通过wdsSave提交wdsSsid/wdsMac等参数到LAN_WLAN_WDSBRIDGE端点。SSID字段允许32字节任意输入(无XSS过滤)，若后端存储并渲染该值可能引发存储型XSS。触发条件：攻击者提交含恶意脚本的SSID字段。MAC地址验证仅前端$.mac()检查格式，可被绕过。
- **备注:** SSID可作为跨站脚本攻击向量，需检查管理界面是否渲染该值\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 1. 输入验证部分准确：SSID无过滤/MAC仅前端验证属实；2. 但漏洞核心假设不成立：证据显示SSID仅注入input的value属性(XSS安全上下文)，未发现后端存储或危险渲染点；3. 无完整攻击链：缺乏XSS触发路径，风险应降为0。结论：描述部分准确但不构成真实漏洞。

#### 验证指标
- **验证耗时:** 406.24 秒
- **Token用量:** 327641

---

## 低优先级发现 (3 条)

### 待验证的发现: oid-definition-constants

#### 原始信息
- **文件/目录路径:** `web/js/oid_str.js`
- **位置:** `web/js/oid_str.js`
- **描述:** 文件为静态OID字符串定义文件，未包含可执行代码或输入处理逻辑。所有内容均为常量声明，不存在：1) 敏感信息泄露风险（如GPON_AUTH_PWD仅为对象标识符名称，未存储实际密码）2) 输入验证缺失问题（无输入处理点）3) 危险函数调用（如eval/innerHTML）4) 网络请求接口。但定义的OID常量可能在nvram_get/set等操作中被引用，需在其他组件中追踪这些标识符的数据流。
- **备注:** 关键后续方向：1) 在C/C++二进制中搜索GPON_AUTH_PWD等OID的引用点 2) 检查调用nvram_get(GPON_AUTH_PWD)的组件是否存在边界检查缺失 3) 追踪OID相关数据在HTTP参数处理中的传播路径\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 文件分析证据确凿：1) 197个变量均为静态声明(var+字面量) 2) 无函数/控制流/事件监听等可执行代码 3) GPON_AUTH_PWD等仅为标识符名称字符串，未存储实际敏感数据 4) 无eval/innerHTML等危险API。文件本身是纯定义文件，无输入处理或执行能力，故不构成直接可触发的漏洞。但OID常量可能在其他组件(nvram_get等)中被引用，这需要独立验证。

#### 验证指标
- **验证耗时:** 204.08 秒
- **Token用量:** 127305

---

### 待验证的发现: csrf-dos-restart_htm

#### 原始信息
- **文件/目录路径:** `web/main/restart.htm`
- **位置:** `restart.htm:7`
- **描述:** restart.htm实现设备重启功能，点击#t_reboot按钮触发：1) 弹出确认对话框(c_str.creboot) 2) 调用$.act(ACT_OP, ACT_OP_REBOOT) 3) 执行$.exe(true)提交请求。触发条件：攻击者诱导已认证用户访问恶意页面（CSRF）。安全影响：缺乏二次认证和进度条机制可能被用于掩盖攻击，导致设备拒绝服务（风险值6/10）。未发现用户输入参数，故无输入验证缺陷。
- **代码片段:**\n  ```\n  $("#t_reboot").click(function(){\n    if($.confirm(c_str.creboot)) {\n      $.guage([...], function(){$.refresh();});\n      $.act(ACT_OP, ACT_OP_REBOOT);\n      $.exe(true);\n    }\n  });\n  ```
- **备注:** 关键关联：1) 与top.htm(unauthorized-reboot)共享ACT_OP_REBOOT机制 2) 与backNRestore.htm(csrf-factory-reset-chain)形成多重攻击链。未解决：1) ACT_OP_REBOOT数值未定义 2) $.exe()后端路由未定位 3) 会话验证机制未验证。建议优先追踪/sbin/reboot二进制\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 1) 代码验证：restart.htm中确实存在通过$.act(ACT_OP_REBOOT)和$.exe(true)触发的重启逻辑，与描述一致；2) CSRF可行性：无CSRF token、Referer检查或会话强验证机制，攻击者可构造恶意页面诱导用户触发；3) 影响评估：缺乏实质性二次认证（$.confirm仅为前端交互对话框），设备重启可直接导致拒绝服务。补充证据：在sysMode.htm和trafficCtrl.htm等文件中发现相同漏洞模式，证明ACT_OP_REBOOT是通用重启机制。

#### 验证指标
- **验证耗时:** 311.72 秒
- **Token用量:** 229244

---

### 待验证的发现: command_execution-unknown_service-cos_rttd

#### 原始信息
- **文件/目录路径:** `etc/init.d/rcS`
- **位置:** `rcS`
- **描述:** cos/rttd服务启动命令未指定路径（'cos &'/'rttd &'）。触发条件：系统启动时后台运行。约束条件：PATH环境变量未定义，无法定位可执行文件。安全影响：未知，服务二进制分析受阻。
- **备注:** 后续方向：1) 全局搜索cos/rttd可执行文件 2) 分析/bin、/sbin等目录\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 1) 准确性评估：命令存在且未指定路径（准确），但PATH是否未定义无法完全确认（仅确认rcS未设置，但未验证父进程环境）。2) 漏洞评估：未在固件中找到'cos'/'rttd'可执行文件，无法验证命令执行路径；未发现可被攻击者控制的目录在默认PATH中，因此无法确认存在命令注入风险。3) 触发条件：需要攻击者提前植入恶意二进制到特定目录，非直接触发。

#### 验证指标
- **验证耗时:** 575.98 秒
- **Token用量:** 446432

---

