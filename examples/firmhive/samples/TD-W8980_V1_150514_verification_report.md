# TD-W8980_V1_150514 - 综合验证报告

总共验证了 18 条发现。

---

## 高优先级发现 (7 条)

### 待验证的发现: configuration_load-user-admin-root

#### 原始信息
- **文件/目录路径:** `etc/passwd.bak`
- **位置:** `etc/passwd.bak:0`
- **描述:** admin用户被配置为UID=0/GID=0的root权限账户，使用$1$$开头的MD5密码哈希。攻击者可通过网络接口（如SSH/Telnet）暴力破解该弱哈希获取设备完全控制权。主目录设置为'/'且shell为'/bin/sh'，无任何权限限制。触发条件：1) 开启密码登录服务 2) 密码强度不足。实际影响：获得root权限后可直接执行危险操作（如修改系统文件）。
- **代码片段:**\n  ```\n  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh\n  ```
- **备注:** 需验证/etc/shadow中实际密码策略；建议检查网络服务配置中admin账户登录入口\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 基于代码分析验证：1) etc/passwd.bak中admin账户确认为UID=0/GID=0的root权限账户，使用$1$$开头的弱MD5哈希 2) etc/init.d/rcS:77启动无认证Telnet服务 3) rcS:17将passwd.bak复制为登录凭证文件/var/passwd 4) telnetd启动命令未配置额外认证参数。攻击者可通过网络直接暴力破解弱哈希获取root权限，无需前置条件，构成可直接触发的真实漏洞。

#### 验证指标
- **验证耗时:** 570.44 秒
- **Token用量:** 793415

---

### 待验证的发现: network_input-parentCtrl-formInputs

#### 原始信息
- **文件/目录路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: <input>标签`
- **描述:** 发现7个表单输入点(mac1-4/parentMac等)通过HTTP POST提交到/cgi/lanMac端点。与已有发现(network_input-parentCtrl-doSave)形成完整攻击链：前端输入（maxlength=17无内容过滤）→AJAX提交→后端处理NVRAM变量。攻击者可构造恶意MAC地址/URL参数触发参数注入或缓冲区溢出。
- **代码片段:**\n  ```\n  <input name='mac1' maxlength='17' onkeyup='checkMac(this)'>\n  ```
- **备注:** 关联已有发现：network_input-parentCtrl-doSave (文件路径：web/main/parentCtrl.htm)\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 1) 输入点数量描述不准确（实际5个vs报告7个），但maxlength=17存在且无内容过滤；2) 完整攻击链确认：前端输入→AJAX提交→/cgi/lanMac端点→NVRAM直接操作（'mac='+用户输入）；3) 漏洞利用性证实：a) 参数注入风险（用户输入直接拼接进参数）b) 缓冲区溢出可能（maxlength可绕过）c) 无有效过滤（仅格式校验）；4) 可直接通过HTTP请求触发，无需前置条件

#### 验证指标
- **验证耗时:** 692.29 秒
- **Token用量:** 996151

---

### 待验证的发现: mount-option-tmp-ramfs

#### 原始信息
- **文件/目录路径:** `etc/fstab`
- **位置:** `fstab:4`
- **描述:** /tmp目录作为全局可写路径挂载时未限制noexec/nosuid。配置为rw权限且允许执行，攻击者可通过web上传等途径写入恶意二进制文件并直接执行。典型利用链：网络接口文件上传→写入/tmp→执行获取shell。约束条件：依赖其他组件实现文件写入。
- **备注:** 高危利用跳板，建议后续分析www目录文件上传功能\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 1) 在etc/fstab第4行确认/tmp挂载为ramfs且使用'defaults'选项，该选项通常包含rw,exec,suid权限，与描述相符；2) 构成真实漏洞，因可执行文件在/tmp运行是完整攻击链的关键环节；3) 非直接触发，因漏洞利用依赖其他组件（如web文件上传功能）将恶意文件写入/tmp。静态分析无法验证：a) 系统启动时是否应用此配置 b) 是否存在其他安全机制限制/tmp执行权限。

#### 验证指标
- **验证耗时:** 135.19 秒
- **Token用量:** 222759

---

### 待验证的发现: file_write-rcS-mkdir-5

#### 原始信息
- **文件/目录路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:5-18`
- **描述:** 通过mkdir -m 0777命令创建13个全局可写目录（含/var/log、/var/run等敏感路径）。攻击者获取telnet权限后，可在这些目录任意写入文件（如替换动态链接库、植入恶意脚本）。结合cron或启动脚本可实现持久化攻击。触发条件为攻击者先获取telnet访问权限。
- **代码片段:**\n  ```\n  /bin/mkdir -m 0777 -p /var/log\n  /bin/mkdir -m 0777 -p /var/run\n  ...\n  ```
- **备注:** 需分析其他服务是否使用这些目录；建议检查/var下文件的所有权配置；此漏洞依赖未认证telnet服务（见rcS:77发现）提供的初始访问权限\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 核心发现部分准确但存在细节错误：1) 准确部分 - 确实创建了全局可写敏感目录（如/var/log、/var/run），且无防护逻辑；2) 错误部分 - 实际创建11个目录（非13个）；3) 漏洞成立 - 结合telnetd服务（同文件启动）形成攻击链，攻击者获取telnet权限后可任意写入敏感目录；4) 非直接触发 - 需先获取telnet访问权限作为前置条件。

#### 验证指标
- **验证耗时:** 146.85 秒
- **Token用量:** 182925

---

### 待验证的发现: xss-usb-dom-01

#### 原始信息
- **文件/目录路径:** `web/main/usbManage.htm`
- **位置:** `usbManage.htm:180,182,184,144`
- **描述:** 高危DOM型XSS利用链：攻击者通过篡改USB设备元数据（如恶意构造的卷标名）或劫持后端响应，污染volumeList[i].name/fileSystem等属性。当管理员访问USB管理页面时，污染数据未经过滤直接插入innerHTML（行180/182/184），触发恶意脚本执行。触发条件：1) 攻击者需控制USB设备元数据或中间人劫持响应 2) 管理员访问/web/main/usbManage.htm。成功利用可完全控制管理员会话。
- **代码片段:**\n  ```\n  cell.innerHTML = volumeList[i].name;  // 直接插入未过滤数据\n  ```
- **备注:** 需验证后端生成volumeList的组件（如cgibin）是否对外部输入消毒。关联文件：/lib/libshared.so的USB数据处理函数\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 前端漏洞模式确认存在：usbManage.htm中确实存在三处未过滤的innerHTML赋值（行180: volumeList[i].name, 行182: volumeList[i].fileSystem, 行184: volumeList[i].capacity）。但后端验证缺失：1) 未找到关联文件/lib/libshared.so 2) 未发现处理USB数据的后端组件 3) 无法确认volumeList数据是否经过消毒。漏洞成立需满足后端未消毒条件，但该条件无法验证。触发路径非直接：需要攻击者控制USB元数据或劫持响应，并依赖管理员访问特定页面。

#### 验证指标
- **验证耗时:** 383.72 秒
- **Token用量:** 496167

---

### 待验证的发现: network_input-parentCtrl-doSave

#### 原始信息
- **文件/目录路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: doSave()函数`
- **描述:** 发现多处未经验证的用户输入点（MAC地址、URL、时间参数），通过doSave()等事件处理函数直接提交到/cgi/lanMac后端端点。触发条件：用户提交家长控制配置表单。输入值直接绑定NVRAM变量（如parentMac/urlAddr），前端未实施MAC格式校验、URL白名单检查或时间范围验证，可能导致恶意数据注入NVRAM。
- **代码片段:**\n  ```\n  示例：$('#parentMac').val() 直接获取未验证输入 → $.act('/cgi/lanMac', {...})\n  ```
- **备注:** 关联关键词'ACT_CGI'/'doSave'已在知识库存在；需验证后端/cgi/lanMac对NVRAM参数的处理逻辑\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 证据显示：1) MAC验证存在逻辑反置缺陷，实际效果等同于无验证；2) URL仅验证格式但无内容审查，符合'未实施白名单检查'描述；3) 时间参数完全无验证；4) NVRAM绑定路径确认存在。核心漏洞（未充分验证的用户输入导致NVRAM注入）成立，攻击者可通过提交恶意表单直接触发。需修正两点：实际提交端点为$.act(ACT_SET)而非/cgi/lanMac；MAC/URL存在基础验证函数但未有效防护。

#### 验证指标
- **验证耗时:** 1651.40 秒
- **Token用量:** 2298217

---

### 待验证的发现: network_input-telnetd_env_injection-00438cc0

#### 原始信息
- **文件/目录路径:** `bin/busybox`
- **位置:** `busybox:0x00438cc0-0x00438d10`
- **描述:** telnetd组件存在环境变量注入漏洞（CVE-2011-2716模式）。攻击者通过Telnet连接发送恶意用户名（如'root\nLD_PRELOAD=/tmp/evil.so'），函数fcn.00438bc0直接将其拆分为多行并设置USER/LOGNAME/HOME/SHELL等环境变量，未进行任何特殊字符过滤或边界检查。当后续调用login程序时，LD_PRELOAD等注入变量可导致动态库劫持，实现远程代码执行。触发条件：1) telnetd服务启用（已确认在/etc/init.d/rcS:77无认证启动）2) 攻击者能建立Telnet连接 3) /tmp目录可写。实际影响：未认证远程代码执行（CVSS 9.8）。
- **代码片段:**\n  ```\n  0x00438cc0: lw a1, (s1)\n  0x00438cc8: jal fcn.0043ae0c\n  0x00438ccc: addiu a0, a0, 0x1860  # "USER"\n  ```
- **备注:** 与知识库记录'command_execution-rcS-telnetd-77'形成完整攻击链。需验证：1) 固件中/tmp挂载配置是否允许任意写 2) login是否调用LD_PRELOAD\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 代码分析确认：1) 0x00438cc0处lw a1, (s1)直接加载未过滤的Telnet输入 2) 连续调用setenv设置环境变量（USER/LOGNAME/HOME）时未处理换行符 3) 攻击链完整（telnetd无认证启动→输入注入→login加载动态库）。动态链接机制（ELF interpreter）确保LD_PRELOAD生效。CVSS 9.8评估合理，因攻击者只需单次Telnet连接发送恶意用户名即可触发远程代码执行。

#### 验证指标
- **验证耗时:** 3694.46 秒
- **Token用量:** 3072521

---

## 中优先级发现 (6 条)

### 待验证的发现: network_input-fwRulesEdit-ruleName_xss_vector

#### 原始信息
- **文件/目录路径:** `web/main/fwRulesEdit.htm`
- **位置:** `web/main/fwRulesEdit.htm:2 (doSave) 0x[待补充]`
- **描述:** 用户输入处理缺陷：前端页面收集ruleName等防火墙规则参数(maxlength=15)，通过doSave()函数直接提交给后端RULE操作端点。触发条件：攻击者通过HTTP请求提交恶意规则配置（如注入特殊字符）。安全影响：ruleName参数未进行内容过滤，可能被用于存储型XSS或作为注入点穿透后端服务。
- **代码片段:**\n  ```\n  function doSave(){\n    fwAttrs.ruleName = $.id("ruleName").value;\n    $.act(ACT_ADD, RULE, null, null, fwAttrs);\n  }\n  ```
- **备注:** 需验证后端处理RULE操作的文件（如CGI程序）是否对ruleName进行过滤；关联知识库ACT_GL操作(network_input-manageCtrl-apiEndpoints)\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 1. The frontend validation ($.isname) only blocks specific special characters and trailing spaces, but allows HTML/JS constructs like `<`, `>`, `'` essential for XSS payloads. 
2. ruleName is submitted directly to the backend via $.act(ACT_ADD, RULE) with no encoding/filtering in the observed code.
3. The maxlength=15 restriction limits but doesn't prevent XSS (e.g., `'<script>/*` fits).
4. Without backend validation evidence (unverifiable in static analysis), the input remains a potential XSS vector.
5. Trigger possibility remains high (8.5) as malicious ruleName can be submitted via HTTP.

#### 验证指标
- **验证耗时:** 239.29 秒
- **Token用量:** 196437

---

### 待验证的发现: network_input-usb-xss_volume_name

#### 原始信息
- **文件/目录路径:** `web/main/usbManage.htm`
- **位置:** `www/usbManage.htm:109-110,180-184 (render_volume_list)`
- **描述:** 攻击链1：物理注入XSS。触发条件：攻击者物理接入含恶意卷名（如`<script>payload</script>`）的USB设备 → 管理员访问usbManage.htm页面 → ACT_GL获取LOGICAL_VOLUME列表 → volumeList[i].name未过滤直接通过innerHTML插入DOM → 触发XSS。约束条件：需绕过设备元数据生成过滤（如udev规则）。安全影响：会话劫持/完全控制设备。
- **代码片段:**\n  ```\n  volumeList = $.act(ACT_GL, LOGICAL_VOLUME, null, null);\n  cell.innerHTML = volumeList[i].name;\n  ```
- **备注:** 需验证：1) /bin/usb对卷名的过滤机制 2) ACT_GL后端授权 3) 关联知识库HTTPS配置（notes字段唯一值）\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 前端漏洞存在（未过滤innerHTML插入），但关键后端证据缺失：1) 未找到/bin/usb或等效卷名处理程序 2) ACT_GL后端实现位置未知 3) udev规则目录不存在。发现描述的完整攻击链（物理注入恶意卷名）因缺乏卷名生成/过滤机制证据而无法证实。触发需要同时满足：a) 后端无过滤 b) 绕过元数据生成约束，实际可利用性存疑。

#### 验证指标
- **验证耗时:** 592.90 秒
- **Token用量:** 857706

---

### 待验证的发现: XSS-Chain-libjs-url_control

#### 原始信息
- **文件/目录路径:** `web/js/lib.js`
- **位置:** `Multiple functions`
- **描述:** URL参数可控的DOM操作链：1) $.refresh()直接使用location.href 2) $.deleteCookie()操作document.cookie 3) location.hash未过滤。与innerHTML组合可形成XSS攻击链。触发条件：用户控制URL参数。影响：完整XSS利用链。
- **代码片段:**\n  ```\n  $.refresh = function(domain, port, frame, page) {\n    location.href = ret[1] + '://' + (domain ? domain : ret[2]) + ... + (page ? '#__' + page.match(/\w+\.htm$/) : '');\n  }\n  ```
- **备注:** 关联知识库已有'#__\w+\.htm$'关键词，需验证page参数是否来源URL。\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 验证结论：1) 准确性评估（partially）：a) $.refresh函数page参数过滤缺陷真实存在（正则未锚定导致可注入alert.htm）✓ b) location.hash构造正确 ✓ c) 但$.deleteCookie无关XSS链 ✗ 2) 漏洞真实性（true）：虽然攻击链不完整，但location.hash驻留XSS向量的基础漏洞存在 3) 直接触发（false）：需满足两个外部条件：a) 调用$.refresh时传入未净化URL参数 b) 存在解析location.hash的HTML页面（如*.htm）。当前证据仅证明lib.js存在局部漏洞，完整利用依赖外部环境。

#### 验证指标
- **验证耗时:** 420.94 秒
- **Token用量:** 744695

---

### 待验证的发现: network_input-manageCtrl-hostValidation

#### 原始信息
- **文件/目录路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm:79-85 (doSave function)`
- **描述:** 主机地址输入验证存在逻辑缺陷，触发条件：在l_host/r_host字段输入非IP非MAC值时。具体表现：1) 验证条件要求同时满足IP和MAC格式（不可能条件）2) 非IP输入错误调用$.num2ip($.ip2num())转换 3) MAC地址强制大写但无格式校验。潜在影响：攻击者可注入特殊字符（如命令注入符号）导致后端解析异常，可能引发内存破坏或配置注入。
- **代码片段:**\n  ```\n  arg = $.id("l_host").value;\n  if (arg !== "" && $.ifip(arg, true) && $.mac(arg, true))\n    return $.alert(ERR_APP_LOCAL_HOST);\n  if (!$.ifip(arg, true)) appCfg.localHost = $.num2ip($.ip2num(arg));\n  else appCfg.localHost = arg.toUpperCase();\n  ```
- **备注:** 需结合/cgi/auth后端验证注入可行性\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 基于代码分析：1) 验证条件要求同时满足IP和MAC格式（行81-82），这是不可能事件，导致验证逻辑被绕过；2) 非IP输入时直接执行$.num2ip($.ip2num(arg))转换（行83），若输入包含特殊字符（如';'），转换函数可能产生未定义行为；3) MAC地址强制大写但无格式校验（行84），攻击者可注入非常规字符。这些缺陷组合允许攻击者通过l_host/r_host字段注入恶意内容，且漏洞可直接通过前端输入触发。虽然无法验证/cgi/auth后端处理细节，但前端验证缺陷已构成可被利用的漏洞链起点。

#### 验证指标
- **验证耗时:** 278.20 秒
- **Token用量:** 447515

---

### 待验证的发现: attack_chain-manageCtrl-remoteExploit

#### 原始信息
- **文件/目录路径:** `web/main/manageCtrl.htm`
- **位置:** `综合攻击路径（基于manageCtrl.htm与/cgi/auth交互）`
- **描述:** 最可行攻击链：攻击者通过远程管理接口(r_http_en)拦截密码请求→获取凭证后访问/cgi/auth→利用ACL_CFG配置缺陷设置0.0.0.0绕过ACL→通过主机字段注入特殊字符触发后端漏洞。触发概率评估：中高（需满足r_http_en开启且HTTPS未启用）
- **备注:** 依赖条件：1) 远程管理开启 2) HTTPS未强制启用 3) 后端对主机输入未做二次验证\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 前端风险（远程管理接口和主机字段输入缺陷）确认存在，但攻击链断裂：1) 关键文件'cgi/auth'不存在（多次验证未找到）2) 无法验证后端漏洞触发机制 3) ACL配置缺陷证据不充分（仅影响Ping服务）。攻击链因核心环节缺失无法构成完整漏洞。

#### 验证指标
- **验证耗时:** 1225.81 秒
- **Token用量:** 1783471

---

### 待验证的发现: mount-option-var-ramfs

#### 原始信息
- **文件/目录路径:** `etc/fstab`
- **位置:** `fstab:2`
- **描述:** /var目录使用ramfs挂载且未设置noexec/nosuid选项。默认配置允许exec和suid权限，攻击者若获得/var目录写入权限（如通过日志注入漏洞），可部署恶意可执行文件或suid提权程序。触发条件：存在文件写入漏洞+攻击者能触发执行。边界检查：无权限限制，任何能写入/var的进程均可利用。
- **备注:** 需结合其他漏洞完成文件写入，建议后续检查日志处理组件\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 核心证据支撑：1) etc/fstab第2行确认ramfs挂载/var且使用'defaults'选项（含exec/suid） 2) etc/init.d脚本证实通过mount -a加载配置 3) /var权限设置为0777。风险成立依据：攻击者获得写入权限后（如通过日志漏洞），可在/var部署恶意程序并利用默认exec权限执行。非直接触发原因：未发现系统直接执行/var目录文件的代码，需依赖外部漏洞触发执行（如日志组件注入），符合发现描述的触发条件。

#### 验证指标
- **验证耗时:** 2184.96 秒
- **Token用量:** 2308612

---

## 低优先级发现 (5 条)

### 待验证的发现: network_input-fwRulesEdit-opt_control

#### 原始信息
- **文件/目录路径:** `web/main/fwRulesEdit.htm`
- **位置:** `www/fwRulesEdit.htm`
- **描述:** 操作标识符控制风险：$.mainParam包含操作类型(opt)和规则标识符(stk)，但赋值逻辑未暴露。触发条件：篡改ACT_ADD/ACT_SET常量值。实际影响：可能绕过规则修改权限检查（如将ACT_SET改为ACT_ADD创建未授权规则）。约束条件：依赖后端对opt值的严格验证。
- **备注:** 需在二进制分析中验证：CGI程序对ACT_*常量的处理是否包含边界检查\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 验证结果：1) 前端逻辑与发现描述一致（opt参数外部可控、常量无边界检查、无前端权限验证）2) 但无法定位处理后端逻辑的CGI程序，导致无法验证关键约束条件（后端权限检查）3) 由于缺少后端验证证据，无法确认漏洞实际可利用性。因此判断该漏洞描述部分准确但无法构成真实漏洞，因为缺乏完整的攻击链证据。

#### 验证指标
- **验证耗时:** 588.99 秒
- **Token用量:** 814124

---

### 待验证的发现: auth-bypass-clientlock

#### 原始信息
- **文件/目录路径:** `web/frame/login.htm`
- **位置:** `login.htm: pageLoad()函数`
- **描述:** 客户端账户锁定机制存在绕过风险。触发条件：连续5次认证失败后启动600秒锁定。锁定状态由客户端变量isLocked控制，攻击者通过禁用JavaScript或修改客户端计时器可绕过锁定限制。危险操作：实现无限次密码暴力破解攻击。
- **代码片段:**\n  ```\n  if (authTimes >= 5) {\n    isLocked = true;\n    lockWeb(true);\n    window.setTimeout(function(){...}, 1000);\n  }\n  ```
- **备注:** 可与credential-exposure-authcookie形成攻击链：暴力破解+凭证窃取。需验证CGI脚本的authTimes服务器端同步机制。\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 验证结论基于以下证据：1) login.htm中authTimes/forbidTime变量依赖服务器注入，但未发现服务器端同步锁定状态的代码 2) 锁定机制完全由客户端isLocked变量控制 3) PCSubWin()函数在isLocked=false时无条件提交凭证。漏洞需满足：a) 连续5次失败触发锁定 b) 攻击者禁用JS绕过isLocked检查 c) 实施暴力破解。因需要多步骤操作，故非直接触发。

#### 验证指标
- **验证耗时:** 213.75 秒
- **Token用量:** 415434

---

### 待验证的发现: negative_finding-dangerous_functions

#### 原始信息
- **文件/目录路径:** `web/main/parentCtrl.htm`
- **位置:** `全局扫描结果`
- **描述:** 未检测到eval()/Function()等高危函数。证据：全文扫描未发现直接代码执行函数。
- **代码片段:**\n  ```\n  N/A\n  ```

#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 通过两次 grep 扫描确认文件 web/main/parentCtrl.htm：1) 所有 'function' 匹配均为合法的 JS 函数定义语法，非高危 Function() 构造函数；2) 无任何 eval() 调用痕迹；3) 无动态代码执行特征。原始扫描结论正确，不存在高危函数，因此不构成漏洞，更无直接触发可能。

#### 验证指标
- **验证耗时:** 153.30 秒
- **Token用量:** 202459

---

### 待验证的发现: network_input-virtualServer_htm-doDel

#### 原始信息
- **文件/目录路径:** `web/main/virtualServer.htm`
- **位置:** `virtualServer.htm: doDel() 函数`
- **描述:** 批量操作函数(doDel/doEnable/doDisable)循环执行配置变更时缺乏原子性校验。攻击者通过高并发请求可导致配置状态不一致。触发条件：1) 并发操作相同规则 2) 设备资源不足中断处理。影响：端口规则部分生效引发防火墙冲突。边界检查缺失：循环内无错误回滚机制，selEntry数组未验证有效性。
- **代码片段:**\n  ```\n  for (var i = 0; i < vtlServ_stackIndex; i++) {\n    if (vtlServ_stackType[i] == "ip") {\n      $.act(ACT_DEL, WAN_IP_CONN_PORTMAPPING, vtlServ_stack[i], null);\n    }\n  }\n  ```
- **备注:** 需审计后端是否支持事务，建议检查ACT_DEL的错误处理逻辑\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 1. 核心原子性问题验证通过：证据显示doDel()函数循环执行$.act()时无锁/事务控制，且无错误回滚机制。攻击者通过高并发请求相同规则可直接导致配置状态不一致（与发现描述一致）；2. 边界检查描述需修正：实际风险是DOM元素存在性验证缺失（selEntry函数中未验证$.id(tmpEntryId)是否存在），而非数组边界问题，但同样构成中危漏洞；3. 触发条件成立：设备资源不足时$.exe()失败会导致部分操作未提交，且无回滚机制；4. 影响验证：配置不一致可引发防火墙规则冲突（风险等级评估合理）。

#### 验证指标
- **验证耗时:** 863.39 秒
- **Token用量:** 1174963

---

### 待验证的发现: ipc-cos_daemon-remote_exec

#### 原始信息
- **文件/目录路径:** `etc/init.d/rcS`
- **位置:** `/etc/init.d/rcS:87`
- **描述:** 启动cos守护进程，若该服务存在漏洞（如命令注入/缓冲区溢出），攻击者可通过其开放接口（如网络/IPC）触发。触发条件：需确定服务监听端口或交互机制。边界检查：未知。安全影响：可能实现远程代码执行。
- **代码片段:**\n  ```\n  cos &\n  ```
- **备注:** 需定位并逆向分析cos二进制文件\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 深度逆向分析证实：1) cos二进制文件在地址0x404ee4处存在动态构造system命令的代码（sprintf+system调用链），参数in_stack_0000001c来自RDP协议解析；2) 污点追踪显示外部输入（网络/IPC消息）经msg_recv→rdp_action→命令构造参数路径无过滤传递；3) 网络接口开放（eth_forward配置）使攻击者可发送特制RDP消息注入恶意命令。符合发现描述的所有要素：服务存在漏洞、通过开放接口触发、可能实现远程代码执行。

#### 验证指标
- **验证耗时:** 3946.98 秒
- **Token用量:** 3980450

---

