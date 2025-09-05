# Archer_C50 - 综合验证报告

总共验证了 9 条发现。

---

## 高优先级发现 (4 条)

### 待验证的发现: network_input-libjs_dom_xss-187

#### 原始信息
- **文件/目录路径:** `web/js/lib.js`
- **位置:** `lib.js:187,203`
- **描述:** 高危DOM型XSS漏洞：html()函数直接设置elem.innerHTML（行187），dhtml()函数动态执行脚本（行203）。触发条件：攻击者控制value参数（html函数）或str参数（dhtml函数）。利用方式：注入恶意HTML/JS代码。约束条件：dhtml函数仅当输入含<script>标签时执行脚本。安全影响：完全控制页面DOM，可窃取cookie（含Authorization）或发起恶意请求。
- **代码片段:**\n  ```\n  elem.innerHTML = value;\n  $.each(scripts, function() {$.script(this.text || this.textContent || this.innerHTML || '')});\n  ```
- **备注:** 结合document.cookie操作（行331）可窃取认证令牌。需追踪value/str参数来源。关联知识库：'与XSS漏洞结合可形成完整攻击链：XSS执行→窃取cookie→获取管理员权限'\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 1) 代码存在性验证成功：确认html()函数直接设置innerHTML（行187），dhtml()函数执行<script>标签（行203），document.cookie操作存在（行331）
2) 关键证据缺失：通过6次工具调用和知识库查询，无法验证value/str参数来源：
   - 在lib.js内未找到函数调用点（grep返回空）
   - 知识库无调用链记录
3) 漏洞判定：因无法证明参数可被外部控制（如网络输入），不符合CVE漏洞基本条件
4) 触发可能性：即使漏洞存在，也需要未经验证的前置条件（参数被污染），非直接触发

#### 验证指标
- **验证耗时:** 624.38 秒
- **Token用量:** 520965

---

### 待验证的发现: config-dir_permission-rcS

#### 原始信息
- **文件/目录路径:** `etc/init.d/rcS`
- **位置:** `rcS:18,24`
- **描述:** 脚本创建全局可写目录（0777），包括/var/samba/private（行24）和/var/tmp/dropbear（行18）。触发条件：系统启动时自动执行。安全影响：攻击者可篡改dropbear密钥或samba配置文件（如植入恶意smb.conf），当相关服务启动时实现权限提升或信息窃取。利用链：控制目录→植入恶意配置/密钥→服务加载→系统沦陷。
- **备注:** 需验证dropbear/samba是否使用这些目录\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 验证确认：1) rcS第18/24行确实创建全局可写目录（0777）；2) dropbearmulti二进制包含'/var/tmp/dropbear'路径字符串，证明该目录被服务使用，攻击者可篡改密钥；3) samba部分无配置文件证据，无法验证/var/samba/private使用情况。因此发现描述基本准确但samba部分未证实，漏洞整体成立且触发直接（启动时自动执行）。

#### 验证指标
- **验证耗时:** 1647.32 秒
- **Token用量:** 899387

---

### 待验证的发现: network_input-libjs_dom_xss

#### 原始信息
- **文件/目录路径:** `web/mainFrame.htm`
- **位置:** `js/lib.js: loadMain函数`
- **描述:** 高危DOM型XSS漏洞：当攻击者控制$.loadMain的path参数为HTML字符串时（如'<script>alert(1)</script>'），通过innerHTML直接插入DOM执行任意脚本。触发条件：1) 通过原型污染或错误处理注入恶意path值 2) 触发$.err/$.errBack调用链（如诱导HTTP错误或CGI失败）。实际影响：结合login.htm的认证令牌漏洞，可窃取管理员凭证实现完全设备控制。
- **代码片段:**\n  ```\n  if (!path) path = $.curPage;\n  var bFile = (path.indexOf("<") < 0);\n  ...\n  $.loadPage("main", path, function(){...})\n  ```
- **备注:** 需结合后端错误生成机制验证外部输入如何到达path参数。关联漏洞链：可触发login.htm的认证令牌窃取\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 危险操作（innerHTML插入未过滤内容）存在，但触发路径未验证：1) 所有$.loadMain调用点的path参数均为硬编码或内部状态（如$.curPage），未发现外部输入污染路径；2) $.err/$.errBack机制仅传递数字型错误码，无法注入HTML；3) 关联漏洞链（login.htm认证令牌窃取）无代码证据支持。实际利用需同时满足：a) 原型污染修改$.mainParam（无证据） b) 诱导特定HTTP错误（不可控） c) 绕过错误码数字限制（不可行）。

#### 验证指标
- **验证耗时:** 1942.50 秒
- **Token用量:** 968020

---

### 待验证的发现: attack_chain-file_pollution_to_rce

#### 原始信息
- **文件/目录路径:** `usr/bin/cos`
- **位置:** `usr/bin/cos:0x409bfc [strcpy]`
- **描述:** 高危攻击链：文件污染导致命令注入和缓冲区溢出。具体表现：1) 全局可写文件'/var/tmp/umount_failed_list'内容被污染；2) fcn.00409750读取文件时未验证内容；3) 污染数据经strcpy复制（0x409bfc）触发栈溢出；4) 相同数据在fcn.004099f4的rm -rf命令中执行任意shell命令。触发条件：攻击者写入≥320字节恶意内容到目标文件。安全影响：完全设备控制（风险等级9.5）。
- **代码片段:**\n  ```\n  // 关键漏洞点\n  0x00409bfc  jalr t9 ; sym.imp.strcpy  // 缓冲区溢出\n  (**(gp-0x7f58))(buf,"rm -rf %s%s","/var/usbdisk/",param) // 命令注入\n  ```
- **备注:** 利用约束：1) 需绕过ASLR实现溢出利用 2) 命令注入需避免路径截断。建议后续动态验证溢出可行性并检查HTTP文件上传接口\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 1) 命令注入成立：污染文件内容直接拼接进system()执行（证据：0x00409a68指令） 2) 文件存在引用：'/var/tmp/umount_failed_list'字符串在二进制中 3) 但描述偏差：a) 无strcpy调用（0x409bfc是jalr指令）b) 无缓冲区溢出环节 c) 触发只需命令分隔符而非320字节。修正后仍构成直接可触发的RCE漏洞（利用简单：写入;恶意命令到文件）

#### 验证指标
- **验证耗时:** 5822.94 秒
- **Token用量:** 2241094

---

## 中优先级发现 (2 条)

### 待验证的发现: file-write-var-perm

#### 原始信息
- **文件/目录路径:** `etc/init.d/rcS`
- **位置:** `rcS:8-16,20-22`
- **描述:** 高危目录权限设置：通过 '/bin/mkdir -m 0777' 创建 /var/tmp、/var/usbdisk 等全局可写目录。攻击者获得低权限访问后（如通过 telnetd 漏洞），可在这些目录植入恶意脚本或篡改数据，实现权限提升或持久化控制。触发条件：攻击者获得任意命令执行权限。约束条件：目录在启动时创建且权限持续有效。潜在影响：权限提升、数据篡改或拒绝服务。
- **代码片段:**\n  ```\n  /bin/mkdir -m 0777 -p /var/tmp\n  /bin/mkdir -m 0777 -p /var/usbdisk\n  ```
- **备注:** 需检查 /var 下目录是否被关键服务使用\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 1) 代码验证：在rcS指定位置确认存在全局可写目录创建命令，权限0777允许任意用户读写执行；2) 逻辑验证：命令在系统启动时无条件执行且权限持续有效，telnetd服务提供潜在攻击入口；3) 影响验证：低权限攻击者可在这些目录植入恶意文件（如通过telnet漏洞），实现持久化控制或权限提升。但漏洞需先获取执行权限才能利用，故非直接触发。

#### 验证指标
- **验证耗时:** 113.64 秒
- **Token用量:** 58676

---

### 待验证的发现: command_execution-iptables_path_pollution

#### 原始信息
- **文件/目录路径:** `etc/iptables-stop`
- **位置:** `etc/iptables-stop:4`
- **描述:** 脚本使用相对路径调用iptables命令（如'iptables -F'），未指定绝对路径且未重置PATH环境变量。当PATH被污染（如包含/tmp等可写目录）时，攻击者可放置恶意iptables程序实现命令注入。触发条件：1) 攻击者控制PATH变量 2) 在PATH目录放置恶意程序 3) 脚本被执行。影响：获得root权限（因iptables通常需root权限执行）。
- **代码片段:**\n  ```\n  iptables -t filter -F\n  ```
- **备注:** 需分析调用此脚本的父进程（如init脚本）是否安全设置PATH。固件中常见通过web接口触发服务重启的场景可能被利用。\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 验证确认：1) 脚本确实使用相对路径调用iptables且未重置PATH（技术前提成立）2) 但无法找到任何调用该脚本的父进程或触发机制证据 3) 知识库查询证实无web接口调用记录。漏洞构成需要证明攻击者可控制PATH环境变量，当前缺乏执行上下文证据，无法确认是否满足触发条件。

#### 验证指标
- **验证耗时:** 702.26 秒
- **Token用量:** 558930

---

## 低优先级发现 (3 条)

### 待验证的发现: network_input-auth_error_page-cookie_clear

#### 原始信息
- **文件/目录路径:** `web/frame/accErr.htm`
- **位置:** `web/frame/accErr.htm`
- **描述:** 静态登录错误处理页面，核心行为：1) 页面加载时自动执行deleteCookie函数清除'Authorization'认证cookie，这是合理的会话终止机制；2) 显示固定错误提示文本，包含设备物理重置指引（需按住复位键8-10秒）。无用户输入参数处理，无动态内容生成，未引用外部资源。触发条件仅限于用户访问该页面，无法被外部输入污染或利用。
- **备注:** 设备重置指引可能被用于物理拒绝服务攻击，但非本页面漏洞。建议检查其他涉及认证处理的动态页面（如登录表单）是否存在cookie处理缺陷。\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `True`
- **详细原因:** 代码验证结果：1) 存在明确定义的deleteCookie函数及onload触发机制，准确实现清除Authorization cookie功能；2) 错误提示文本包含描述的物理重置指引；3) 无用户输入处理逻辑，所有内容为硬编码静态HTML。清除cookie是设计合理的会话终止机制，无法被外部输入操纵或形成攻击链。设备重置指引属物理操作提示，不构成软件漏洞。

#### 验证指标
- **验证耗时:** 48.39 秒
- **Token用量:** 15127

---

### 待验证的发现: static_content-web-indexhtm-0001

#### 原始信息
- **文件/目录路径:** `web/index.htm`
- **位置:** `web/index.htm:0 (global) 0x0`
- **描述:** web/index.htm文件被确认为纯框架集文件，不具备任何用户输入接口或网络请求功能。具体表现：1) 无<form>标签，无法提交参数至后端 2) 内联JS仅实现域名重定向（tplinklogin.net → tplinkwifi.net），未调用XMLHttpRequest/fetch API 3) 无HTML注释或隐藏字段泄露敏感信息。该文件无法作为攻击链的初始输入点或数据传播节点。
- **代码片段:**\n  ```\n  <frameset>...</frameset> <script>if(url.indexOf('tplinklogin.net')>=0){window.location=url.replace('tplinklogin.net','tplinkwifi.net')}</script>\n  ```
- **备注:** 需转向其他目录（如cgi-bin）分析实际网络端点\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 文件内容验证：1) 无<form>标签，无法提交参数 2) JS仅执行域名重定向(window.location)，未调用任何网络API 3) 无敏感注释或隐藏字段。该HTML纯属框架容器，不具备任何输入处理或数据传输功能，无法作为攻击入口点。

#### 验证指标
- **验证耗时:** 53.45 秒
- **Token用量:** 23683

---

### 待验证的发现: xss-banner_dynamic_content-1

#### 原始信息
- **文件/目录路径:** `web/frame/banner.htm`
- **位置:** `banner.htm:10-14`
- **描述:** 文件存在潜在XSS漏洞点：使用$.h函数动态设置元素内容，传入$.desc和$.model变量。触发条件：1) 非中文环境($.cn=false) 2) 污染数据通过$.desc/$.model传递。若验证$.h等效innerHTML且变量被外部输入污染，可构成XSS攻击链初始节点。实际风险依赖：a) 变量污染路径验证 b) $.h函数实现分析
- **代码片段:**\n  ```\n  $.h($.id('mname'), '' + $.desc);\n  $.h($.id('mnum'), m_str.bannermodel + $.model);\n  ```
- **备注:** 关键证据缺失：1) 父页面未定位导致无法追踪$.对象数据源 2) 目录限制无法访问web/js验证$.h实现。知识库关联记录：XSS漏洞可能结合lib.js的loadMain漏洞形成cookie窃取→权限提升攻击链（参见notes字段相关记录）\n
#### 验证结论
- **描述准确性:** `unknown`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 无法验证核心要素：1) $.h函数实现是否等效innerHTML（需访问web/js目录）2) $.desc/$.model变量污染路径（需分析父页面数据流）3) $.cn条件触发机制（需全局状态分析）。由于固件分析环境限制，无法获取关键证据支撑漏洞判定。

#### 验证指标
- **验证耗时:** 364.25 秒
- **Token用量:** 246058

---

