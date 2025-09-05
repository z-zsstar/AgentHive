# TD-W8980_V1_150514 高优先级: 19 中优先级: 32 低优先级: 26

## 优先级评分模型

**计算公式:** `PriorityScore = (0.5 * risk_level) + (0.3 * confidence) + (0.2 * trigger_possibility)`

**分层策略:**
- **高优先级:** `PriorityScore >= 8.5`
- **中优先级:** `7.0 <= PriorityScore < 8.5`
- **低优先级:** `PriorityScore < 7.0`

---

## 高优先级发现

### command_execution-rcS-telnetd-77

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:77`
- **类型:** command_execution
- **综合优先级分数:** **9.35**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 在系统启动脚本中直接执行'telnetd'命令且无任何认证参数（如-l /bin/login），导致设备启动时自动开启未认证telnet服务。攻击者可通过网络连接23端口直接获取root shell权限。此问题无需前置条件，设备网络可达即可触发。
- **代码片段:**
  ```
  telnetd
  ```
- **关键词:** telnetd
- **备注:** 需验证/sbin/telnetd是否支持PIE/RELRO防护；建议检查防火墙是否默认开放23端口；此漏洞可被用于访问全局可写目录进行权限维持（见rcS:5-18发现）

---
### network_input-parentCtrl-ajaxEndpoint

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: JavaScript代码段`
- **类型:** network_input
- **综合优先级分数:** **9.3**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危AJAX端点/cgi/info处理系统信息请求。触发条件：发送特制AJAX请求。潜在影响：可能泄露设备敏感信息或成为命令注入跳板，需验证后端处理逻辑。与/cgi/lanMac端点形成平行攻击面。
- **代码片段:**
  ```
  $.act(ACT_CGI, '/cgi/info', ...)
  ```
- **关键词:** ACT_CGI, /cgi/info, $.act
- **备注:** 独立新增端点，需追踪后端CGI程序路径

---
### RCE-libjs-script_exec

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js function definitions`
- **类型:** command_execution
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 10.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** $.script()函数通过动态创建<script>标签执行任意JS代码，相当于eval()。当bScript=true时用于处理AJAX响应，攻击者可通过篡改服务器响应或注入HTML触发代码执行。触发条件：未验证的服务器响应或DOM内容传入$.script()。影响：远程代码执行。
- **代码片段:**
  ```
  $.script = function(data) {
    if (data && /\S/.test(data)) {
      var script = $.d.createElement('script');
      script.text = data;
      $.head.insertBefore(script, $.head.firstChild);
    }
  }
  ```
- **关键词:** $.script, bScript, $.io, script.text
- **备注:** 需检查所有使用bScript参数的$.io调用点，确认响应是否可信。关联网络输入点。

---
### configuration_load-user-admin-root

- **文件路径:** `etc/passwd.bak`
- **位置:** `etc/passwd.bak:0`
- **类型:** configuration_load
- **综合优先级分数:** **9.1**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** admin用户被配置为UID=0/GID=0的root权限账户，使用$1$$开头的MD5密码哈希。攻击者可通过网络接口（如SSH/Telnet）暴力破解该弱哈希获取设备完全控制权。主目录设置为'/'且shell为'/bin/sh'，无任何权限限制。触发条件：1) 开启密码登录服务 2) 密码强度不足。实际影响：获得root权限后可直接执行危险操作（如修改系统文件）。
- **代码片段:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  ```
- **关键词:** admin, UID=0, GID=0, /bin/sh, passwd.bak
- **备注:** 需验证/etc/shadow中实际密码策略；建议检查网络服务配置中admin账户登录入口

---
### mount-option-tmp-ramfs

- **文件路径:** `etc/fstab`
- **位置:** `fstab:4`
- **类型:** configuration_load
- **综合优先级分数:** **9.1**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** /tmp目录作为全局可写路径挂载时未限制noexec/nosuid。配置为rw权限且允许执行，攻击者可通过web上传等途径写入恶意二进制文件并直接执行。典型利用链：网络接口文件上传→写入/tmp→执行获取shell。约束条件：依赖其他组件实现文件写入。
- **关键词:** fstab, /tmp, ramfs, defaults, rw, exec
- **备注:** 高危利用跳板，建议后续分析www目录文件上传功能

---
### network_input-telnetd_env_injection-00438cc0

- **文件路径:** `bin/busybox`
- **位置:** `busybox:0x00438cc0-0x00438d10`
- **类型:** network_input
- **综合优先级分数:** **9.1**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** telnetd组件存在环境变量注入漏洞（CVE-2011-2716模式）。攻击者通过Telnet连接发送恶意用户名（如'root\nLD_PRELOAD=/tmp/evil.so'），函数fcn.00438bc0直接将其拆分为多行并设置USER/LOGNAME/HOME/SHELL等环境变量，未进行任何特殊字符过滤或边界检查。当后续调用login程序时，LD_PRELOAD等注入变量可导致动态库劫持，实现远程代码执行。触发条件：1) telnetd服务启用（已确认在/etc/init.d/rcS:77无认证启动）2) 攻击者能建立Telnet连接 3) /tmp目录可写。实际影响：未认证远程代码执行（CVSS 9.8）。
- **代码片段:**
  ```
  0x00438cc0: lw a1, (s1)
  0x00438cc8: jal fcn.0043ae0c
  0x00438ccc: addiu a0, a0, 0x1860  # "USER"
  ```
- **关键词:** fcn.00438bc0, USER, LOGNAME, HOME, SHELL, setenv, telnetd, login, LD_PRELOAD, rcS:77
- **备注:** 与知识库记录'command_execution-rcS-telnetd-77'形成完整攻击链。需验证：1) 固件中/tmp挂载配置是否允许任意写 2) login是否调用LD_PRELOAD

---
### physical_attack-serial_login-chain

- **文件路径:** `etc/inittab`
- **位置:** `etc/inittab:2`
- **类型:** hardware_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危物理攻击链：inittab中::askfirst条目启动/sbin/getty监听串口ttyS0。结合etc目录全局可写缺陷（rwxrwxrwx），攻击者可篡改passwd.bak植入恶意账户（证据：rcS:17复制操作）。弱密码漏洞（admin:$1$$iC.dUsGpxNNJGeOm1dFio/）允许直接登录。触发条件：物理接入串口发送回车→触发getty→使用默认凭证登录。安全影响：获得root权限。利用概率高（8.0/10），约束条件：需物理接触和设备重启。
- **代码片段:**
  ```
  ::askfirst:/sbin/getty -L ttyS0 115200 vt100
  ```
- **关键词:** ::askfirst, /sbin/getty, ttyS0, passwd.bak, rcS, /var/passwd, admin, $1$$iC.dUsGpxNNJGeOm1dFio/
- **备注:** 关联知识库弱密码记录（configuration_load-user-admin-root）。证据缺口：需验证/bin/login是否使用/var/passwd

---
### network_input-telnetd_auth-binary

- **文件路径:** `etc/init.d/rcS`
- **位置:** `/etc/init.d/rcS:77`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 无认证启动telnetd服务，暴露未加密远程接口。攻击者可通过网络直接连接，若存在默认凭证或二进制漏洞（如缓冲区溢出），可导致设备完全控制。触发条件：网络可达性+漏洞利用。边界检查：无认证机制。安全影响：提供初始攻击立足点，可能串联其他漏洞。
- **代码片段:**
  ```
  telnetd
  ```
- **关键词:** telnetd
- **备注:** 必须分析/bin/telnetd的二进制漏洞

---
### DOM-XSS-libjs-innerHTML

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js function definitions`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 多个函数($.html/$.dhtml/$.append)使用innerHTML插入未过滤的用户输入，导致DOM-XSS漏洞。触发条件：当URL参数/错误消息等外部可控数据传入这些函数时，可执行任意JS代码。影响：攻击者可完全控制Web界面。边界检查：无任何输入过滤或编码。特别危险的是$.err()函数，直接使用错误码构建HTML。
- **代码片段:**
  ```
  html: function(elem, value) {
    if (elem && elem.innerHTML !== undefined){
      if (value === undefined)
        return elem.innerHTML;
      else
        elem.innerHTML = value;
    }
  }
  ```
- **关键词:** $.html, $.dhtml, $.append, innerHTML, $.err
- **备注:** 关联知识库已有innerHTML关键词。需验证$.err调用点是否传入用户可控数据。

---
### xss-dom-libjs-refresh

- **文件路径:** `web/index.htm`
- **位置:** `web/js/lib.js: [$.refresh, $.html]`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** DOM型XSS漏洞：攻击者通过构造恶意URL参数（如含JavaScript代码的查询字符串），触发$.refresh()函数处理location.href，未经任何过滤直接传入$.html()的innerHTML赋值操作。具体触发条件：1) 用户访问构造的恶意URL 2) 页面执行到包含$.refresh()调用的逻辑路径。系统完全缺乏对URL参数的HTML实体编码或内容安全策略(CSP)防护，导致脚本在受害者浏览器执行。
- **代码片段:**
  ```
  $.html: function(elem, value) {... elem.innerHTML = value; ...}
  ```
- **关键词:** $.html, $.dhtml, innerHTML, $.refresh, location.href
- **备注:** 验证PoC：http://target/page.htm?<script>alert(document.cookie)</script>；关联现有关键词：$.html, innerHTML

---
### rce-libjs-io-script

- **文件路径:** `web/index.htm`
- **位置:** `web/js/lib.js: [$.io]`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 远程代码执行漏洞：当CGI处理器使用$.io(..., bScript=true)调用时，API原始响应数据直接传入$.script()执行。攻击者可通过中间人攻击或服务端漏洞注入恶意代码到API响应，触发无条件脚本执行。触发条件：1) 存在使用bScript=true的API调用 2) 攻击者污染API响应内容。无任何脚本内容验证或沙箱机制，造成等效于eval()的安全风险。
- **代码片段:**
  ```
  $.io: function(...) { ... success:function(data) { if (s.bScript) $.script(data); ... } ... }
  ```
- **关键词:** $.script, $.io, bScript, success callback, responseText
- **备注:** 需审计所有调用$.io时设置bScript=true的CGI处理器；关联现有关键词：$.io, $.script

---
### subsequent_task-cgi_rule_validation

- **文件路径:** `web/main/fwRulesEdit.htm`
- **位置:** `后续分析目标：/sbin/ 和 /www/cgi-bin/`
- **类型:** command_execution
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 关键验证任务：分析处理RULE操作的后端CGI程序（位于/sbin或/www/cgi-bin），验证：1) protocol参数是否严格限定TCP/UDP/ICMP（防协议注入）2) ACT_ADD/ACT_SET操作符的边界检查（防未授权规则操作）3) hostList解析是否处理畸形冒号格式（防命令注入）。关联前端利用链：用户输入→fwRulesEdit.htm→$.act请求→CGI解析→防火墙规则执行。
- **关键词:** RULE, ACT_SET, protocol, split, CGI
- **备注:** 由前端风险链触发（fwRulesEdit.htm中的doSave/showWan）。需验证文件：处理ACT_ADD/ACT_SET常量的二进制程序，特别是解析fwAttrs参数的模块。

---
### xss-usb-dom-01

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `usbManage.htm:180,182,184,144`
- **类型:** hardware_input
- **综合优先级分数:** **8.86**
- **风险等级:** 9.0
- **置信度:** 9.2
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危DOM型XSS利用链：攻击者通过篡改USB设备元数据（如恶意构造的卷标名）或劫持后端响应，污染volumeList[i].name/fileSystem等属性。当管理员访问USB管理页面时，污染数据未经过滤直接插入innerHTML（行180/182/184），触发恶意脚本执行。触发条件：1) 攻击者需控制USB设备元数据或中间人劫持响应 2) 管理员访问/web/main/usbManage.htm。成功利用可完全控制管理员会话。
- **代码片段:**
  ```
  cell.innerHTML = volumeList[i].name;  // 直接插入未过滤数据
  ```
- **关键词:** volumeList, name, fileSystem, capacity, innerHTML, usbDeviceList, $.act, ACT_GL
- **备注:** 需验证后端生成volumeList的组件（如cgibin）是否对外部输入消毒。关联文件：/lib/libshared.so的USB数据处理函数

---
### network_input-wanEdit-form_submission_risk

- **文件路径:** `web/main/wanEdit.htm`
- **位置:** `wanEdit.htm:1458 (doSave)`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 表单提交机制存在安全风险：1) 'doSave'函数收集username/pwd等敏感字段明文通过AJAX发送至'ACT_SET'接口（无加密证据） 2) 无CSRF防护令牌 3) 客户端验证依赖有缺陷的isValidGLUIP6AddrStrict等函数。攻击者可：a) 嗅探网络获取凭据 b) 构造CSRF攻击修改WAN配置 c) 绕过客户端验证提交畸形数据。风险触发条件：用户访问恶意页面时自动提交表单（CSRF）或中间人拦截网络流量。
- **关键词:** doSave, $.act, ACT_SET, wan_iplistarg, wan_ppplistarg, username, pwd, pppoa_pwd, WAN_IP_CONN, WAN_PPP_CONN
- **备注:** 关键关联：1) 'ACT_SET'在知识库中已有记录（需交叉分析）2) 依赖的isValidGLUIP6AddrStrict函数存在缺陷（见本批存储的第一个发现）

---
### network_input-setPwd-http_plaintext_password

- **文件路径:** `web/frame/setPwd.htm`
- **位置:** `web/frame/setPwd.htm (具体行号需反编译确认)`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 密码设置页面通过HTTP明文传输Base64编码密码。攻击者可通过中间人攻击捕获并解码pwd参数值获取明文密码。触发条件：用户提交表单时自动触发XMLHttpRequest请求。前端实施6-15字符长度检查但无内容过滤，Base64编码不具备安全性。
- **代码片段:**
  ```
  xmlHttpObj.open("POST", "http://192.168.1.1/cgi/setPwd?pwd=" + Base64Encoding($("newPwd").value), true);
  ```
- **关键词:** setPwd.htm, /cgi/setPwd, /cgi-bin/setPwd, Base64Encoding, xmlHttp.open, pwd=, newPwd
- **备注:** 需分析/cgi-bin/setPwd二进制文件验证后端处理逻辑是否引入二次漏洞（如命令注入）。攻击链关键节点：网络输入(pwd参数)→Base64解码→密码存储/系统调用。知识库中尚未发现/cgi-bin/setPwd相关记录，需优先验证后端处理。

---
### network_input-parentCtrl-formInputs

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: <input>标签`
- **类型:** network_input
- **综合优先级分数:** **8.7**
- **风险等级:** 8.0
- **置信度:** 10.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 发现7个表单输入点(mac1-4/parentMac等)通过HTTP POST提交到/cgi/lanMac端点。与已有发现(network_input-parentCtrl-doSave)形成完整攻击链：前端输入（maxlength=17无内容过滤）→AJAX提交→后端处理NVRAM变量。攻击者可构造恶意MAC地址/URL参数触发参数注入或缓冲区溢出。
- **代码片段:**
  ```
  <input name='mac1' maxlength='17' onkeyup='checkMac(this)'>
  ```
- **关键词:** parentMac, mac1, mac2, mac3, mac4, timeS, timeE, urlInfo, maxlength, /cgi/lanMac, ACT_CGI
- **备注:** 关联已有发现：network_input-parentCtrl-doSave (文件路径：web/main/parentCtrl.htm)

---
### network_input-parentCtrl-doSave

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: doSave()函数`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 发现多处未经验证的用户输入点（MAC地址、URL、时间参数），通过doSave()等事件处理函数直接提交到/cgi/lanMac后端端点。触发条件：用户提交家长控制配置表单。输入值直接绑定NVRAM变量（如parentMac/urlAddr），前端未实施MAC格式校验、URL白名单检查或时间范围验证，可能导致恶意数据注入NVRAM。
- **代码片段:**
  ```
  示例：$('#parentMac').val() 直接获取未验证输入 → $.act('/cgi/lanMac', {...})
  ```
- **关键词:** doSave, parentMac, urlInfo, timeS, ACT_CGI, /cgi/lanMac, enableParentCtrl, urlAddr
- **备注:** 关联关键词'ACT_CGI'/'doSave'已在知识库存在；需验证后端/cgi/lanMac对NVRAM参数的处理逻辑

---
### file_write-rcS-mkdir-5

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:5-18`
- **类型:** file_write
- **综合优先级分数:** **8.6**
- **风险等级:** 8.0
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 通过mkdir -m 0777命令创建13个全局可写目录（含/var/log、/var/run等敏感路径）。攻击者获取telnet权限后，可在这些目录任意写入文件（如替换动态链接库、植入恶意脚本）。结合cron或启动脚本可实现持久化攻击。触发条件为攻击者先获取telnet访问权限。
- **代码片段:**
  ```
  /bin/mkdir -m 0777 -p /var/log
  /bin/mkdir -m 0777 -p /var/run
  ...
  ```
- **关键词:** mkdir, 0777, /var/log, /var/run, /var/tmp
- **备注:** 需分析其他服务是否使用这些目录；建议检查/var下文件的所有权配置；此漏洞依赖未认证telnet服务（见rcS:77发现）提供的初始访问权限

---
### credential_manipulation-passwd-copy

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:17`
- **类型:** configuration_load
- **综合优先级分数:** **8.55**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 7.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 账户文件复制操作（cp -p /etc/passwd.bak /var/passwd）构成物理篡改攻击链。触发条件：物理接触设备修改passwd.bak+系统重启。约束条件：串口认证依赖/var/passwd。安全影响：植入root账户获取完全控制。利用方式：修改源文件添加恶意账户通过串口登录。
- **代码片段:**
  ```
  cp -p /etc/passwd.bak /var/passwd
  ```
- **关键词:** cp -p, /etc/passwd.bak, /var/passwd, physical_attack, serial_login
- **备注:** 证据缺口：未验证串口认证实现。后续建议：分析/bin/login程序

---

## 中优先级发现

### XSS-Chain-libjs-url_control

- **文件路径:** `web/js/lib.js`
- **位置:** `Multiple functions`
- **类型:** network_input
- **综合优先级分数:** **8.45**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** URL参数可控的DOM操作链：1) $.refresh()直接使用location.href 2) $.deleteCookie()操作document.cookie 3) location.hash未过滤。与innerHTML组合可形成XSS攻击链。触发条件：用户控制URL参数。影响：完整XSS利用链。
- **代码片段:**
  ```
  $.refresh = function(domain, port, frame, page) {
    location.href = ret[1] + '://' + (domain ? domain : ret[2]) + ... + (page ? '#__' + page.match(/\w+\.htm$/) : '');
  }
  ```
- **关键词:** $.refresh, location.href, $.deleteCookie, document.cookie, location.hash
- **备注:** 关联知识库已有'#__\w+\.htm$'关键词，需验证page参数是否来源URL。

---
### network_input-fwRulesEdit-unvalidated_params

- **文件路径:** `web/main/fwRulesEdit.htm`
- **位置:** `www/fwRulesEdit.htm: doSave()函数`
- **类型:** network_input
- **综合优先级分数:** **8.45**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 无验证参数传递风险：前端收集8个防火墙规则参数(fwAttrs)直接提交$.act()，其中关键参数protocol/direction完全用户可控且无过滤。触发条件：攻击者构造恶意AJAX请求或绕过前端验证。实际影响：若后端缺乏验证，可导致协议注入（如伪造ICMP类型）或流量方向混淆（如反转内外网方向）。利用链：用户输入→DOM参数→$.act()提交→后端处理→防火墙规则执行。
- **关键词:** protocol, direction, fwAttrs, $.act, doSave, RULE, ACT_SET
- **备注:** 需验证后端CGI对protocol值的处理：检查是否仅允许预设值(TCP/UDP/ICMP)

---
### mount-option-var-ramfs

- **文件路径:** `etc/fstab`
- **位置:** `fstab:2`
- **类型:** configuration_load
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 10.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** /var目录使用ramfs挂载且未设置noexec/nosuid选项。默认配置允许exec和suid权限，攻击者若获得/var目录写入权限（如通过日志注入漏洞），可部署恶意可执行文件或suid提权程序。触发条件：存在文件写入漏洞+攻击者能触发执行。边界检查：无权限限制，任何能写入/var的进程均可利用。
- **关键词:** fstab, /var, ramfs, defaults, exec, suid
- **备注:** 需结合其他漏洞完成文件写入，建议后续检查日志处理组件

---
### network_input-fwRulesEdit-ruleName_xss_vector

- **文件路径:** `web/main/fwRulesEdit.htm`
- **位置:** `web/main/fwRulesEdit.htm:2 (doSave) 0x[待补充]`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 用户输入处理缺陷：前端页面收集ruleName等防火墙规则参数(maxlength=15)，通过doSave()函数直接提交给后端RULE操作端点。触发条件：攻击者通过HTTP请求提交恶意规则配置（如注入特殊字符）。安全影响：ruleName参数未进行内容过滤，可能被用于存储型XSS或作为注入点穿透后端服务。
- **代码片段:**
  ```
  function doSave(){
    fwAttrs.ruleName = $.id("ruleName").value;
    $.act(ACT_ADD, RULE, null, null, fwAttrs);
  }
  ```
- **关键词:** ruleName, doSave, $.act, ACT_ADD, RULE, fwAttrs
- **备注:** 需验证后端处理RULE操作的文件（如CGI程序）是否对ruleName进行过滤；关联知识库ACT_GL操作(network_input-manageCtrl-apiEndpoints)

---
### auth-cleartext-cookie-storage

- **文件路径:** `web/frame/login.htm`
- **位置:** `web/frame/login.htm:0 (PCSubWin)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 7.5
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 认证凭据以Base64编码明文存储在客户端Cookie中，存在敏感信息泄露风险。触发条件：用户提交登录表单时，JavaScript函数PCSubWin()将用户名和密码拼接为'user:password'格式，经Base64编码后存入'Authorization' cookie。未实施任何加密、HTTPOnly或Secure标记等保护措施，且无凭证有效期控制。攻击者可通过XSS漏洞、网络嗅探或中间人攻击窃取该cookie，直接解码获取明文凭证。在未启用HTTPS的环境中风险极高。
- **代码片段:**
  ```
  auth = "Basic "+Base64Encoding(userName+":"+password);
  document.cookie = "Authorization=" + auth;
  ```
- **关键词:** PCSubWin, Base64Encoding, document.cookie, Authorization, userName, pcPassword
- **备注:** 需验证后端是否强制HTTPS传输。攻击链完整度评估：输入点(表单)→传播(JS拼接)→危险操作(cookie写入)，成功利用概率高。建议后续追踪Authorization cookie在后端的验证逻辑。

---
### network_input-usb-stack_injection

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `www/usbManage.htm: handleUsb()第20行`
- **类型:** network_input
- **综合优先级分数:** **8.25**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 未过滤的__stack属性导致命令注入风险。触发条件：通过$.act()调用传递被污染的__stack值（如usbDeviceList[idx].__stack）。具体表现：__stack属性直接拼接进USB_DEVICE操作命令（$.act(ACT_SET, USB_DEVICE, usbDeviceList[idx].__stack)），未进行任何编码或过滤。安全影响：若__stack含恶意命令分隔符（如;、&&），可能注入额外操作系统命令。利用方式：控制USB设备命名或结合idx越界漏洞污染__stack属性。
- **代码片段:**
  ```
  $.act(ACT_SET, USB_DEVICE, usbDeviceList[idx].__stack, null, command)
  ```
- **关键词:** __stack, $.act, ACT_SET, USB_DEVICE, command
- **备注:** 延伸攻击链ID: network_input-usb-param_tampering；需追踪__stack属性来源（可能在后台组件）

---
### network_input-virtualServer_htm-doEdit

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `virtualServer.htm: doEdit() 函数`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** doEdit函数直接使用未经验证的val2参数（堆栈索引）执行配置修改。攻击者通过恶意URL控制val2可越权操作端口转发规则。触发条件：1) 用户访问构造的URL 2) val2超出堆栈边界 3) 后端无二次鉴权。影响：未授权修改/删除规则导致服务中断或内网暴露。边界检查缺失：无对val2的索引范围验证（0 ≤ val2 < vtlServ_stackIndex）。
- **代码片段:**
  ```
  function doEdit(val1, val2) {
    param[0] = 1;
    param[1] = val1;
    param[2] = val2;
    $.loadMain("vtlServEdit.htm", param);
  }
  ```
- **关键词:** doEdit, val2, param[2], vtlServ_stack, vtlServ_stackIndex
- **备注:** 需验证vtlServEdit.htm是否传递val2至危险操作，建议后续分析ACT_SET实现

---
### command_execution-telnetd-noauth

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:77`
- **类型:** network_input
- **综合优先级分数:** **8.15**
- **风险等级:** 8.5
- **置信度:** 7.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** telnetd服务以无认证参数启动（rcS:77），若存在弱密码账户将导致远程未授权访问。触发条件：网络可达且服务运行。约束条件：未启用PAM认证且依赖/etc/passwd.bak凭证文件。安全影响：攻击者可爆破凭证获取shell权限。利用方式：扫描开放telnet端口实施凭证爆破。
- **代码片段:**
  ```
  telnetd
  ```
- **关键词:** telnetd, rcS:77, authentication, /etc/passwd.bak, /var/passwd
- **备注:** 证据缺口：1) 未验证telnetd认证逻辑 2) 未获取passwd.bak内容。后续建议：逆向分析/usr/sbin/telnetd

---
### network_input-usb-xss_volume_name

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `www/usbManage.htm:109-110,180-184 (render_volume_list)`
- **类型:** hardware_input
- **综合优先级分数:** **8.15**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 攻击链1：物理注入XSS。触发条件：攻击者物理接入含恶意卷名（如`<script>payload</script>`）的USB设备 → 管理员访问usbManage.htm页面 → ACT_GL获取LOGICAL_VOLUME列表 → volumeList[i].name未过滤直接通过innerHTML插入DOM → 触发XSS。约束条件：需绕过设备元数据生成过滤（如udev规则）。安全影响：会话劫持/完全控制设备。
- **代码片段:**
  ```
  volumeList = $.act(ACT_GL, LOGICAL_VOLUME, null, null);
  cell.innerHTML = volumeList[i].name;
  ```
- **关键词:** ACT_GL, LOGICAL_VOLUME, volumeList, name, innerHTML
- **备注:** 需验证：1) /bin/usb对卷名的过滤机制 2) ACT_GL后端授权 3) 关联知识库HTTPS配置（notes字段唯一值）

---
### xss-url_management-parentctrl

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: initUrlTbl函数`
- **类型:** network_input
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 存储型XSS漏洞存在于URL管理功能。当攻击者通过认证添加恶意URL时（doAddUrl函数），用户输入未经转义直接通过innerHTML插入页面（initUrlTbl函数）。管理员查看家长控制页面时触发恶意脚本。触发条件：1) 攻击者获得低权限账户 2) 管理员查看含恶意条目的页面。实际影响：会话劫持或权限提升。约束条件：仅影响查看页面的管理员账户。
- **代码片段:**
  ```
  cell.innerHTML = allUrl[i]; // 用户输入直接输出
  ```
- **关键词:** doAddUrl, initUrlTbl, allUrl, urlInfo.value, innerHTML, urltbl
- **备注:** 需验证$.isdomain()过滤效果，建议检查/cgi/info后端处理

---
### network_input-manageCtrl-hostValidation

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm:79-85 (doSave function)`
- **类型:** network_input
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 主机地址输入验证存在逻辑缺陷，触发条件：在l_host/r_host字段输入非IP非MAC值时。具体表现：1) 验证条件要求同时满足IP和MAC格式（不可能条件）2) 非IP输入错误调用$.num2ip($.ip2num())转换 3) MAC地址强制大写但无格式校验。潜在影响：攻击者可注入特殊字符（如命令注入符号）导致后端解析异常，可能引发内存破坏或配置注入。
- **代码片段:**
  ```
  arg = $.id("l_host").value;
  if (arg !== "" && $.ifip(arg, true) && $.mac(arg, true))
    return $.alert(ERR_APP_LOCAL_HOST);
  if (!$.ifip(arg, true)) appCfg.localHost = $.num2ip($.ip2num(arg));
  else appCfg.localHost = arg.toUpperCase();
  ```
- **关键词:** l_host, r_host, $.ifip, $.mac, $.num2ip, $.ip2num, appCfg.localHost, appCfg.remoteHost
- **备注:** 需结合/cgi/auth后端验证注入可行性

---
### network_input-usb-idx_oob

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `www/usbManage.htm: handleUsb()第5行, mountUsb()第3行`
- **类型:** network_input
- **综合优先级分数:** **8.1**
- **风险等级:** 7.0
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未验证的idx参数导致USB设备越界访问。触发条件：用户通过界面操作传递恶意idx值（如负数或超界值）。具体表现：在handleUsb()和mountUsb()函数中直接使用idx索引usbDeviceList数组，未检查idx < usbDeviceList.length。安全影响：攻击者可触发JavaScript运行时错误导致拒绝服务(DoS)，或访问非法内存区域。利用方式：修改HTTP请求中的设备索引参数。
- **代码片段:**
  ```
  if ("Online" == usbDeviceList[idx].status)
  ```
- **关键词:** handleUsb, mountUsb, idx, usbDeviceList
- **备注:** 作为攻击链前置条件（可越界获取__stack属性）；需验证后端是否对idx进行二次校验

---
### credential-exposure-authcookie

- **文件路径:** `web/frame/login.htm`
- **位置:** `login.htm: JavaScript函数PCSubWin()`
- **类型:** network_input
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 认证凭证以Base64明文存储于客户端Cookie。触发条件：用户提交登录表单时调用PCSubWin()函数。凭证未设置HttpOnly/Secure属性，攻击者可通过XSS攻击或网络嗅探获取完整登录凭证。危险操作：获得凭证后可直接模拟用户认证状态访问受控资源。需结合服务器端/cgi-bin分析验证凭证有效期机制。
- **代码片段:**
  ```
  auth = "Basic "+Base64Encoding(userName+":"+password);
  document.cookie = "Authorization=" + auth;
  ```
- **关键词:** Authorization, Base64Encoding, document.cookie, PCSubWin
- **备注:** 关联知识库记录：auth-cleartext-cookie-storage。补充攻击向量：XSS窃取+网络嗅探。需追踪/cgi-bin认证流程验证凭证时效性。

---
### xss-network_input-doAddUrl

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `www/parentCtrl.htm:? (doAddUrl) ?`
- **类型:** network_input
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** doAddUrl()函数存在存储型XSS漏洞：用户输入的urlInfo值未经任何过滤直接通过innerHTML插入DOM（cell.innerHTML = urlInfo.value）。触发条件：1) 攻击者提交含恶意脚本的URL 2) 管理员添加该URL 3) 管理员查看'Blocked URLs'列表。成功利用可导致会话劫持，进而操控设备设置。
- **代码片段:**
  ```
  cell.innerHTML = $.id("urlInfo").value;
  ```
- **关键词:** doAddUrl, urlInfo, innerHTML, urltbl
- **备注:** 完整攻击路径：网络输入(HTTP参数)→DOM操作(innerHTML)→代码执行。建议后续验证$.act调用的后端处理逻辑。关联知识库关键词：doAddUrl/innerHTML/urltbl（已存在）

---
### attack_chain-manageCtrl-remoteExploit

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `综合攻击路径（基于manageCtrl.htm与/cgi/auth交互）`
- **类型:** attack_chain
- **综合优先级分数:** **8.05**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 最可行攻击链：攻击者通过远程管理接口(r_http_en)拦截密码请求→获取凭证后访问/cgi/auth→利用ACL_CFG配置缺陷设置0.0.0.0绕过ACL→通过主机字段注入特殊字符触发后端漏洞。触发概率评估：中高（需满足r_http_en开启且HTTPS未启用）
- **关键词:** r_http_en, /cgi/auth, ACL_CFG, l_host, r_host, userCfg, HTTP_CFG.httpsRemoteEnabled, IPStart, IPEnd
- **备注:** 依赖条件：1) 远程管理开启 2) HTTPS未强制启用 3) 后端对主机输入未做二次验证

---
### network_input-usb-param_tampering

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `www/usbManage.htm:35-36,90-91 (handleUsb/handleVolume)`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 8.0
- **置信度:** 8.5
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 攻击链2：参数篡改越权操作。触发步骤：篡改前端JS或构造恶意请求 → handleUsb/handleVolume中idx参数越界（负数/超长） → 越界访问usbDeviceList数组 → 非法获取__stack值 → 通过$.act(ACT_SET, USB_DEVICE)发送篡改指令 → 后端未验证__stack导致越权操作（如禁用设备）。约束条件：需绕过同源策略。安全影响：服务拒绝/设备控制权夺取。
- **代码片段:**
  ```
  $.act(ACT_SET, USB_DEVICE, usbDeviceList[idx].__stack, null, command);
  ```
- **关键词:** idx, __stack, usbDeviceList, ACT_SET, USB_DEVICE, handleUsb, handleVolume
- **备注:** 关键验证点：1) 后端对__stack的格式校验 2) 关联知识库已有ACT_SET记录（linking_keywords字段）

---
### network_input-cwmp_config-doSave

- **文件路径:** `web/main/cwmp.htm`
- **位置:** `web/main/cwmp.htm: doSave函数`
- **类型:** network_input
- **综合优先级分数:** **7.95**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** CWMP配置页面暴露多个高危输入点(ACS URL/凭证/端口/路径)，通过doSave()函数直接写入NVRAM。验证逻辑存在缺陷：1) CR_path仅检查首字符'/'但未过滤特殊字符 2) CR_port无范围验证(允许非法端口值) 3) 无输入内容过滤。攻击者可构造恶意输入注入NVRAM，结合$.act(ACT_SET)的底层实现缺陷可能导致NVRAM污染或命令注入。
- **代码片段:**
  ```
  if ($.id("CR_path").value.charAt(0) != "/") {...}
  if ((!$.num($.id("CR_port").value, true)) {...}
  $.act(ACT_SET, MANAGEMENT_SERVER, null, null, cwmpObj);
  ```
- **关键词:** doSave, cwmpObj.URL, cwmpObj.X_TPLINK_ConnReqPort, cwmpObj.X_TPLINK_connReqPath, $.act(ACT_SET), MANAGEMENT_SERVER
- **备注:** 关键后续方向：1) 追踪$.act(ACT_SET)在libcms.so或httpd的实现 2) 验证服务端对CR_path的过滤逻辑 3) 检查NVRAM设置函数(如nvram_set)的缓冲区处理

---
### network_input-setPwd-default_admin_credential

- **文件路径:** `web/frame/setPwd.htm`
- **位置:** `web/frame/setPwd.htm (具体行号需反编译确认)`
- **类型:** network_input
- **综合优先级分数:** **7.85**
- **风险等级:** 7.0
- **置信度:** 9.5
- **触发可能性:** 7.5
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 跳过密码设置机制使用硬编码默认密码'admin'。攻击者可诱导用户点击skipBtn按钮，导致设备使用默认凭据。触发条件：用户点击跳过按钮时调用next()函数，自动提交Base64编码的"admin"。
- **代码片段:**
  ```
  function next(){
    xmlHttpObj.open("POST", "http://192.168.1.1/cgi/setPwd?pwd=" + Base64Encoding("admin", true));
  }
  ```
- **关键词:** next(), skipBtn, Base64Encoding("admin"), setSkip, /cgi/setPwd
- **备注:** 需检查固件中其他默认凭据配置。攻击路径：用户交互→默认凭证提交→认证绕过。与发现1共享后端处理端点/cgi/setPwd，需统一验证后端实现。

---
### network_input-wanEdit-ipv6_validation_flaws

- **文件路径:** `web/main/wanEdit.htm`
- **位置:** `wanEdit.htm:0 (isValidGLUIP6AddrStrict)`
- **类型:** network_input
- **综合优先级分数:** **7.8**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** IPv6地址验证函数存在三重缺陷：1) 拒绝RFC兼容的压缩地址（如'1::'），因第46行对空子段的错误处理 2) 第68行变量名错误（'substr1'代替'substr2'）导致段验证失效 3) 保留地址范围检查不一致（允许'::2'但阻塞FC00::/7）。攻击者通过WAN配置界面提交畸形IPv6地址可绕过验证，可能导致：a) 网络栈异常崩溃 b) 绕过ACL规则 c) 触发未处理异常。缺陷触发条件：在IPv6静态配置（initStaticIP）或PPPoEv6配置（initPPPoEv6）流程中提交特定格式地址。
- **关键词:** isValidGLUIP6AddrStrict, ip6Addr, regExp, substr1, substr2, indexOf, parseInt, initStaticIP, initPPPoEv6
- **备注:** 需验证后端是否重复验证IPv6地址。关联文件：处理WAN配置的CGI程序（可能对应知识库中'ACT_SET'相关记录）

---
### network_input-fwRulesEdit-ruleInjection

- **文件路径:** `web/main/fwRulesEdit.htm`
- **位置:** `web/main/fwRulesEdit.htm: doSave函数`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 存在未过滤用户输入构造防火墙规则的风险链：1) 攻击者通过ruleName输入字段（maxlength=15）注入恶意内容 2) 前端JS直接获取输入值，仅调用未实现的$.isname()进行格式校验 3) 所有表单值未经转义直接拼装为fwAttrs对象 4) fwAttrs通过$.act请求发送至后端RULE处理模块。触发条件：用户提交包含特殊字符的规则名称（如';'或'<'）。潜在影响：若后端未正确处理fwAttrs参数，可能导致存储型XSS（污染规则列表）或命令注入（规则执行时触发）
- **代码片段:**
  ```
  fwAttrs.ruleName = $.id("ruleName").value;
  fwAttrs.internalHostRef = ...;
  $.act(ACT_ADD, RULE, null, null, fwAttrs);
  ```
- **关键词:** doSave, ruleName, $.isname, fwAttrs, $.act, ACT_ADD, ACT_SET, RULE, internalHostRef, externalHostRef
- **备注:** 需追踪后端RULE处理模块验证实际漏洞。建议后续分析：1) 定位$.act对应的后端接口（如CGI程序）2) 分析RULE操作对fwAttrs的解析过程 3) 检查规则执行组件的命令构造逻辑。关联说明：ACT_ADD/ACT_SET在其他配置模块（如WAN/ACL）存在，但尚未发现与RULE模块的直接关联。

---
### tamper-usb-param-01

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `usbManage.htm (handleUsb函数逻辑)`
- **类型:** network_input
- **综合优先级分数:** **7.7**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 参数篡改风险：动态请求中的__stack参数（如usbDeviceList[idx].__stack）作为设备唯一标识符，通过$.act(ACT_SET, ...)提交。该参数未在前端显示但可被篡改，攻击者可能修改__stack值越权操作其他USB设备。触发条件：用户点击设备操作按钮时发送恶意构造的__stack。边界检查缺失，后端未确认当前用户是否有权操作目标设备。
- **代码片段:**
  ```
  $.act(ACT_SET, USB_DEVICE, usbDeviceList[idx].__stack, null, command);
  ```
- **关键词:** __stack, $.act, ACT_SET, USB_DEVICE, command.enable, handleUsb, handleVolume
- **备注:** __stack格式示例：'0,1'，关联后端校验：/cgi-bin/usb_controller权限逻辑

---
### network_input-manageCtrl-passwordTransmission

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm:68 (doSave function)`
- **类型:** network_input
- **综合优先级分数:** **7.65**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 密码修改过程明文传输风险，触发条件：用户提交密码修改表单时。具体表现：1) 前端明文获取curPwd/newPwd字段 2) 通过$.act(ACT_CGI, "/cgi/auth")传输未加密的userCfg对象 3) 依赖HTTP_CFG.httpsRemoteEnabled配置决定加密状态。潜在影响：中间人攻击可窃取凭证，结合r_http_en配置实现远程利用。
- **代码片段:**
  ```
  if (userCfg.oldPwd)
    $.act(ACT_CGI, "/cgi/auth", null, null, userCfg);
  ```
- **关键词:** curPwd, newPwd, userCfg, $.act, ACT_CGI, /cgi/auth, r_http_en, HTTP_CFG.httpsRemoteEnabled
- **备注:** 实际风险取决于HTTPS配置状态

---
### configuration_load-user-nobody-root

- **文件路径:** `etc/passwd.bak`
- **位置:** `etc/passwd.bak:0`
- **类型:** configuration_load
- **综合优先级分数:** **7.55**
- **风险等级:** 7.5
- **置信度:** 10.0
- **触发可能性:** 4.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** nobody用户异常配置为UID=0/GID=0的root权限账户（标准应为无权限）。虽然密码字段'*'禁用密码登录，但当攻击者通过服务漏洞（如Web服务漏洞）获取nobody执行权限时，将直接获得root权限。触发条件：1) 存在以nobody身份运行的服务漏洞 2) 漏洞允许执行任意命令。实际影响：形成权限提升利用链（初始漏洞→root权限获取）。
- **代码片段:**
  ```
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **关键词:** nobody, UID=0, GID=0, passwd.bak
- **备注:** 需扫描系统中以nobody身份运行的进程；该配置可能由固件定制错误导致

---
### network_input-fwRulesEdit-split_vulnerability

- **文件路径:** `web/main/fwRulesEdit.htm`
- **位置:** `www/fwRulesEdit.htm: showWan()函数`
- **类型:** network_input
- **综合优先级分数:** **7.45**
- **风险等级:** 7.0
- **置信度:** 7.5
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 主机名解析漏洞：internalHostRef/externalHostRef参数使用split(':')[1]提取主机名。触发条件：提交含多个冒号的畸形值(如'evil:payload:123')。实际影响：可能导致数组越界或未处理异常，结合后端逻辑可能造成命令注入。边界检查：当前文件无长度限制或字符过滤。
- **代码片段:**
  ```
  var host = hostList[i].split(':')[1];
  ```
- **关键词:** internalHostRef, externalHostRef, split, hostList, showWan
- **备注:** 后续应测试：提交host=ATTACK:PAYLOAD:123观察后端解析行为

---
### configuration_load-dir_permission-var_lock

- **文件路径:** `etc/init.d/rcS`
- **位置:** `/etc/init.d/rcS:5-8,12-16,18`
- **类型:** configuration_load
- **综合优先级分数:** **7.4**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 创建全局可写目录（0777权限），包括/var/lock、/var/log、/var/usbdisk等。攻击者可植入恶意文件或篡改日志，若PATH环境变量或cron任务引用这些目录，可能实现权限提升。触发条件：攻击者需具备文件写入能力（如通过Samba/USB接口）。边界检查：无权限限制。安全影响：可能形成持久化后门或权限提升链。
- **代码片段:**
  ```
  /bin/mkdir -m 0777 -p /var/lock
  /bin/mkdir -m 0777 -p /var/log
  /bin/mkdir -m 0777 -p /var/usbdisk
  ```
- **关键词:** /bin/mkdir, 0777, /var/lock, /var/log, /var/usbdisk, /var/samba
- **备注:** 需验证cron任务或服务是否执行这些目录中的文件

---
### configuration_load-high_risk_services-etc_services

- **文件路径:** `etc/services`
- **位置:** `etc/services`
- **类型:** configuration_load
- **综合优先级分数:** **7.4**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 在/etc/services中发现12个高风险服务条目（如telnet、ftp等），使用标准端口但存在安全风险：1) 明文传输凭证(telnet/ftp)；2) 无认证文件传输(tftp)；3) 历史漏洞攻击面(netbios/smb)。触发条件：若这些服务实际启用且暴露在网络上，攻击者可利用弱认证/已知漏洞发起攻击。
- **关键词:** telnet, ftp, tftp, shell, login, exec, netbios-ssn, microsoft-ds, portmapper, sunrpc
- **备注:** 需后续验证：1) 通过进程分析确认服务是否运行；2) 检查防火墙规则是否限制访问；3) 测试服务实现是否存在漏洞（如CVE-2021-3156）。高风险服务可能构成攻击链初始入口。关联发现：/etc/init.d/rcS:77启动无认证telnetd服务（linking_keywords: telnetd），若telnet服务启用则形成完整攻击面。

---
### Parameter-Injection-libjs-cgi

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js function definitions`
- **类型:** network_input
- **综合优先级分数:** **7.35**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** AJAX参数构造($.cgi/$.io)未验证用户输入，允许注入额外参数或路径。触发条件：攻击者控制arg/path参数。影响：可能导致SSRF或参数污染。边界检查：直接拼接用户输入。错误处理流程中直接嵌入errno值，可能被利用。
- **代码片段:**
  ```
  $.cgi = function(path, arg, hook, noquit, unerr) {
    path = (path ? path : $.curPage.replace(/\.htm$/, '.cgi')) + (arg ? '?' + $.toStr(arg, '=', '&') : '');
    // call $.io
  }
  ```
- **关键词:** $.cgi, $.io, $.ajax, arg, path
- **备注:** 关联知识库的'/cgi/auth'等CGI端点，可能形成完整攻击链。

---
### network_input-virtualServer_htm-checkConflict

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `virtualServer.htm: checkConflictFtpPort() 函数`
- **类型:** network_input
- **综合优先级分数:** **7.25**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 端口冲突检测函数checkConflictFtpPort仅检测FTP服务，忽略其他高危服务(如SSH)。攻击者添加冲突规则可导致服务劫持。触发条件：1) 外部端口与未检测服务端口重叠 2) 路由器启用未检测服务。影响：敏感服务被劫持或拒绝服务。边界检查缺失：检测范围未覆盖X_TPLINK_ExternalPortEnd定义外的服务端口。
- **代码片段:**
  ```
  if ((exPort <= ftpServer.portNumber) && (ftpServer.portNumber <= exPortEnd)) {
    conflict = true;
  }
  ```
- **关键词:** checkConflictFtpPort, FTP_SERVER, externalPort, X_TPLINK_ExternalPortEnd
- **备注:** 需验证路由器服务配置文件，建议扩展检测至SSH/Telnet等端口

---
### command_execution-parentCtrl-dynamicEval

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: JavaScript函数调用`
- **类型:** command_execution
- **综合优先级分数:** **7.25**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** setTimeout("$.loadHelp();",100)使用字符串参数存在动态执行风险。触发条件：若攻击者能控制$.loadHelp()实现则可能执行任意代码。当前约束：参数固定，但需验证../js/help.js的实现安全性。
- **代码片段:**
  ```
  setTimeout("$.loadHelp();",100)
  ```
- **关键词:** setTimeout, $.loadHelp
- **备注:** 需验证../js/help.js中loadHelp()是否可控

---
### network_input-usb-command_tamper

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `www/usbManage.htm: handleVolumeForce函数`
- **类型:** network_input
- **综合优先级分数:** **7.2**
- **风险等级:** 6.5
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 用户可控command对象属性未经验证传递。触发条件：通过$.act()传递恶意command对象（如{enable: 'malicious'}}）。具体表现：在handleVolumeForce等函数中，command对象属性（enable/force）直接作为$.act()参数传递。安全影响：攻击者可修改属性值破坏业务逻辑，或触发未预期行为（如强制挂载恶意设备）。利用方式：篡改AJAX请求中的command参数。
- **关键词:** command, enable, force, $.act, handleVolumeForce
- **备注:** 与__stack注入共享$.act()调用点；需验证后端对command属性的处理逻辑

---
### hardware_input-kernel_module-usb_storage

- **文件路径:** `etc/init.d/rcS`
- **位置:** `/etc/init.d/rcS:42-45,52,56,60-62`
- **类型:** hardware_input
- **综合优先级分数:** **7.15**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 动态加载内核模块（如usb-storage.ko），若模块存在漏洞（如内存破坏），攻击者可通过物理USB设备或恶意网络数据触发。触发条件：物理访问或特定网络协议交互。边界检查：无输入验证机制。安全影响：可能导致内核权限提升或系统崩溃。
- **代码片段:**
  ```
  insmod /lib/modules/kmdir/kernel/drivers/usb/storage/usb-storage.ko
  ```
- **关键词:** insmod, usb-storage.ko, ifxusb_host.ko, nf_conntrack_pptp.ko
- **备注:** 需对每个.ko文件进行漏洞分析

---
### mac_bypass-configuration_load-doSave

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `www/parentCtrl.htm:? (doClkSave/doSave) ?`
- **类型:** configuration_load
- **综合优先级分数:** **7.05**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** MAC地址验证逻辑缺陷：doClkSave()中$.mac()验证条件判断错误（验证通过时触发错误提示）。触发条件：提交特殊格式MAC地址（如超长或含特殊字符）。结合setParentMac()无过滤复制（parentMac.value = curPCMac.value），可能绕过MAC验证写入NVRAM，影响防火墙规则。
- **代码片段:**
  ```
  if (($.id("parentMac").value != "") && ($.mac($.id("parentMac").value, true))) { $.alert(ERR_MAC_FORMAT); }
  ```
- **关键词:** doClkSave, doSave, $.act, ACT_SET, FIREWALL, parentMac, curPCMac, $.mac
- **备注:** 需验证$.mac()具体实现（可能在外部JS）。攻击者可结合ARP欺骗污染curPCMac。关联知识库关键词：$.act/ACT_SET/parentMac/curPCMac/$.mac（已存在）

---

## 低优先级发现

### firmware_loading-symlink-hijack

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:42-70`
- **类型:** hardware_input
- **综合优先级分数:** **6.95**
- **风险等级:** 7.0
- **置信度:** 7.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 固件符号链接创建（/tmp/ap_upper_wave300.bin）与驱动加载时序错位，存在运行时固件劫持风险。触发条件：驱动动态加载固件且使用/tmp路径。约束条件：驱动加载先于链接创建（rcS:42-62）。安全影响：替换符号链接指向恶意固件导致代码执行。
- **代码片段:**
  ```
  ln -s /lib/firmware/ap_upper_wave300.bin /tmp/ap_upper_wave300.bin
  ```
- **关键词:** ln -s, /tmp/ap_upper_wave300.bin, insmod, ifxusb_host.ko, firmware_loading
- **备注:** 证据缺口：未反编译驱动验证加载逻辑。后续建议：分析rt2860v2_ap模块的request_firmware调用

---
### configuration_tamper-etc_permissions

- **文件路径:** `etc/inittab`
- **位置:** `etc/`
- **类型:** configuration_load
- **综合优先级分数:** **6.9**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 系统配置篡改风险：etc目录下17个文件（含inittab）均设777权限。攻击者获得低权限shell后可篡改inittab注入恶意命令（如反向shell）。触发条件：篡改文件后需系统重启（未发现SIGHUP重载或看门狗机制证据）。安全影响：重启后获得root shell。利用概率中（6.0/10），约束条件：需先获得执行权限并等待重启。
- **关键词:** inittab, rwxrwxrwx, ::askfirst, reboot
- **备注:** 关键限制：未验证init重载机制（建议分析/sbin/init信号处理）

---
### network_input-virtualServer_htm-doDel

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `virtualServer.htm: doDel() 函数`
- **类型:** network_input
- **综合优先级分数:** **6.65**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 批量操作函数(doDel/doEnable/doDisable)循环执行配置变更时缺乏原子性校验。攻击者通过高并发请求可导致配置状态不一致。触发条件：1) 并发操作相同规则 2) 设备资源不足中断处理。影响：端口规则部分生效引发防火墙冲突。边界检查缺失：循环内无错误回滚机制，selEntry数组未验证有效性。
- **代码片段:**
  ```
  for (var i = 0; i < vtlServ_stackIndex; i++) {
    if (vtlServ_stackType[i] == "ip") {
      $.act(ACT_DEL, WAN_IP_CONN_PORTMAPPING, vtlServ_stack[i], null);
    }
  }
  ```
- **关键词:** doDel, ACT_DEL, selEntry, vtlServ_stackIndex, WAN_IP_CONN_PORTMAPPING
- **备注:** 需审计后端是否支持事务，建议检查ACT_DEL的错误处理逻辑

---
### network_input-portmapping_validation

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `www/virtualServer.htm`
- **类型:** network_input
- **综合优先级分数:** **6.65**
- **风险等级:** 7.0
- **置信度:** 6.5
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 检测到端口映射配置存在潜在输入验证缺陷：1) externalPort/X_TPLINK_ExternalPortEnd参数处理时未显式进行数值边界检查（如端口范围0-65535）2) FTP端口冲突检查函数(checkConflictFtpPort)仅验证FTP服务冲突，未覆盖其他高危服务(如SSH) 3) 通过$.act直接操作WAN_IP_CONN_PORTMAPPING配置项，存在未经验证参数注入风险。攻击者可能构造畸形端口参数或绕过冲突检查，导致非法端口开放或服务冲突。
- **代码片段:**
  ```
  if ((this.externalPort != 0) && (this.X_TPLINK_ExternalPortEnd == 0))
    cell.innerHTML = this.externalPort;
  ```
- **关键词:** externalPort, X_TPLINK_ExternalPortEnd, checkConflictFtpPort, WAN_IP_CONN_PORTMAPPING, $.act, ACT_SET
- **备注:** 需结合后端CGI验证：1) 查找处理ACT_SET操作的CGI程序 2) 验证WAN_IP_CONN_PORTMAPPING参数处理流程 3) 测试端口参数边界检查实现。关联提示：知识库中已存在'$.act','ACT_SET','WAN_IP_CONN_PORTMAPPING'相关记录

---
### configuration_load-manageCtrl-hardcodedPorts

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm:182-191 (checkInvalidPort function)`
- **类型:** configuration_load
- **综合优先级分数:** **6.6**
- **风险等级:** 6.0
- **置信度:** 10.0
- **触发可能性:** 3.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 硬编码敏感端口暴露攻击面，触发条件：端口配置时调用checkInvalidPort函数。具体内容：33344,49152,49153,20005,1900,7547。安全影响：攻击者可定位高危服务（如TR-069的7547端口），结合端口冲突逻辑进行服务干扰攻击。
- **代码片段:**
  ```
  if (port == 33344 ||
    port == 49152 ||
    port == 49153 ||
    port == 20005 ||
    port == 1900 ||
    port == 7547)
  ```
- **关键词:** checkInvalidPort, 33344, 49152, 20005, 7547

---
### auth-bypass-clientlock

- **文件路径:** `web/frame/login.htm`
- **位置:** `login.htm: pageLoad()函数`
- **类型:** network_input
- **综合优先级分数:** **6.6**
- **风险等级:** 6.5
- **置信度:** 8.5
- **触发可能性:** 4.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 客户端账户锁定机制存在绕过风险。触发条件：连续5次认证失败后启动600秒锁定。锁定状态由客户端变量isLocked控制，攻击者通过禁用JavaScript或修改客户端计时器可绕过锁定限制。危险操作：实现无限次密码暴力破解攻击。
- **代码片段:**
  ```
  if (authTimes >= 5) {
    isLocked = true;
    lockWeb(true);
    window.setTimeout(function(){...}, 1000);
  }
  ```
- **关键词:** isLocked, authTimes, forbidTime, lockWeb
- **备注:** 可与credential-exposure-authcookie形成攻击链：暴力破解+凭证窃取。需验证CGI脚本的authTimes服务器端同步机制。

---
### network_input-fwRulesEdit-opt_control

- **文件路径:** `web/main/fwRulesEdit.htm`
- **位置:** `www/fwRulesEdit.htm`
- **类型:** network_input
- **综合优先级分数:** **6.45**
- **风险等级:** 6.5
- **置信度:** 6.0
- **触发可能性:** 7.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 操作标识符控制风险：$.mainParam包含操作类型(opt)和规则标识符(stk)，但赋值逻辑未暴露。触发条件：篡改ACT_ADD/ACT_SET常量值。实际影响：可能绕过规则修改权限检查（如将ACT_SET改为ACT_ADD创建未授权规则）。约束条件：依赖后端对opt值的严格验证。
- **关键词:** $.mainParam, opt, stk, ACT_ADD, ACT_SET, RULE
- **备注:** 需在二进制分析中验证：CGI程序对ACT_*常量的处理是否包含边界检查

---
### env_manipulation-login_env_set-00438bc0

- **文件路径:** `bin/busybox`
- **位置:** `fcn.00438bc0 (0x00438bc0)`
- **类型:** env_set
- **综合优先级分数:** **6.35**
- **风险等级:** 6.5
- **置信度:** 7.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** login组件环境变量处理函数(fcn.00438bc0)直接使用外部传入参数设置USER/TERM变量，未验证来源。此函数与telnetd漏洞共用，若攻击者通过其他途径（如恶意进程）控制参数，可能影响认证流程或触发环境变量依赖漏洞。触发条件：1) 存在环境变量注入点（如telnetd漏洞）2) login进程被调用。实际影响：权限提升或配置篡改（需结合其他漏洞利用）。
- **代码片段:**
  ```
  fcn.0043ae0c("USER",*param_3);
  fcn.0043ae0c("TERM",iVar1);
  ```
- **关键词:** fcn.00438bc0, param_3, USER, TERM, getenv, setenv, telnetd
- **备注:** 与'telnetd_env_injection'共用脆弱函数，通过/etc/services中的login服务配置暴露攻击面

---
### xss-modelname-injection

- **文件路径:** `web/frame/login.htm`
- **位置:** `login.htm: pageLoad()函数`
- **类型:** configuration_load
- **综合优先级分数:** **6.25**
- **风险等级:** 6.0
- **置信度:** 7.5
- **触发可能性:** 5.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 动态内容注入存在XSS风险。触发条件：页面加载时执行pageLoad()函数。modelName/modelDesc变量未经过滤直接注入DOM，若该值来自外部可控输入（如NVRAM），可构造存储型XSS攻击链。危险操作：窃取Authorization cookie实现账户劫持。
- **代码片段:**
  ```
  deleteCookie("Authorization");
  $("mnum").innerHTML = "Model No. " + modelName;
  ```
- **关键词:** deleteCookie, modelName, modelDesc, innerHTML
- **备注:** 攻击链关键节点：1) 污染modelName(nvram_get)→2) XSS注入→3) 窃取Authorization cookie。关联credential-exposure-authcookie形成完整账户劫持链。

---
### ipc-cos_daemon-remote_exec

- **文件路径:** `etc/init.d/rcS`
- **位置:** `/etc/init.d/rcS:87`
- **类型:** ipc
- **综合优先级分数:** **6.15**
- **风险等级:** 6.5
- **置信度:** 7.0
- **触发可能性:** 4.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 启动cos守护进程，若该服务存在漏洞（如命令注入/缓冲区溢出），攻击者可通过其开放接口（如网络/IPC）触发。触发条件：需确定服务监听端口或交互机制。边界检查：未知。安全影响：可能实现远程代码执行。
- **代码片段:**
  ```
  cos &
  ```
- **关键词:** cos
- **备注:** 需定位并逆向分析cos二进制文件

---
### network_input-manageCtrl-apiEndpoints

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm:多处调用（doSave/init函数）`
- **类型:** network_input
- **综合优先级分数:** **6.1**
- **风险等级:** 6.5
- **置信度:** 9.5
- **触发可能性:** N/A
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 关键API端点与配置操作暴露，识别出：1) 认证端点/cgi/auth 2) 信息端点/cgi/info 3) 配置操作ACT_SET/ACT_GET/ACT_GL作用于HTTP_CFG/APP_CFG/ACL_CFG。风险点：ACL_CFG配置时硬编码IPStart/IPEnd为0.0.0.0（第141行），可能导致访问控制失效。
- **关键词:** /cgi/auth, /cgi/info, ACT_SET, ACT_GET, ACT_GL, HTTP_CFG, APP_CFG, ACL_CFG, $.act, IPStart, IPEnd
- **备注:** 需追踪后端对ACL_CFG的处理逻辑

---
### Hardcoded-Credential-libjs-magic

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js window.$ initialization`
- **类型:** configuration_load
- **综合优先级分数:** **5.8**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 2.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 硬编码字符串'magic:0y8nc5094yeyrnoq'可能为安全凭证。若用于身份验证，泄露可导致权限绕过。触发条件：字符串被用于认证逻辑且被外部获取。影响：潜在的身份验证绕过。
- **代码片段:**
  ```
  window.$ = {
    magic: '0y8nc5094yeyrnoq',
    // other properties
  }
  ```
- **关键词:** magic, window.$
- **备注:** 需追踪该字符串在固件中的使用场景，确认是否涉及安全机制。

---
### validation_defect-ipv6_gateway-isValidGLUIP6AddrStrict

- **文件路径:** `web/main/wanEdit.htm`
- **位置:** `wanEdit.htm:10-119`
- **类型:** network_input
- **综合优先级分数:** **5.65**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** IPv6网关验证函数(isValidGLUIP6AddrStrict)存在缺陷：错误拒绝合法地址(::1)，使用脆弱正则表达式，可能被非标准IPv6格式绕过。触发条件：提交静态IPv6配置时。若服务器未复验，可导致IP欺骗风险，风险等级中(6.5)。
- **代码片段:**
  ```
  function isValidGLUIP6AddrStrict(ip6Addr){
  /* 缺陷逻辑：错误过滤::1 */
  }
  ```
- **关键词:** isValidGLUIP6AddrStrict, ip6_gateway, externIp6Gateway
- **备注:** 关联发现：1) 本函数缺陷已被'network_input-wanEdit-form_submission_risk'记录引用（表单验证环节） 2) 需验证CGI脚本中ip6_gateway的后端处理是否依赖此校验

---
### array_boundary-ipc-doDelUrl

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `www/parentCtrl.htm:? (doDelUrl) ?`
- **类型:** ipc
- **综合优先级分数:** **5.45**
- **风险等级:** 5.5
- **置信度:** 7.0
- **触发可能性:** 3.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** doDelUrl()数组操作缺乏边界检查：直接使用delListIndex操作allUrl数组。触发条件：通过原型污染等技术操纵数组长度后，越界访问可能导致内存破坏。实际影响取决于JS引擎实现，可能引发拒绝服务。
- **代码片段:**
  ```
  delList[delListIndex] = allUrl[i - 1]; delListIndex++;
  ```
- **关键词:** doDelUrl, allUrl, delList, delListIndex
- **备注:** 需配合其他漏洞利用，低概率触发但暴露代码质量问题。关联知识库关键词：allUrl（已存在）

---
### xss-dom-banner-htm-dynamic-insert

- **文件路径:** `web/frame/banner.htm`
- **位置:** `banner.htm:15-18`
- **类型:** network_input
- **综合优先级分数:** **5.3**
- **风险等级:** 6.0
- **置信度:** 5.0
- **触发可能性:** 4.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 存在DOM型XSS潜在风险：1) 通过$.h($.id('mname'), '' + $.desc)动态写入DOM 2) 参数$.desc和$.modelName可能被污染 3) 触发条件：a) $.cn=false（非中文环境）b) 污染源控制$.desc或$.modelName值 c) 若$.h()未消毒输入则执行任意JS。实际影响取决于外部JS实现，成功利用可导致会话劫持/恶意操作。
- **代码片段:**
  ```
  $.h($.id('mname'), '' + $.desc);
  $.h($.id('mnum'), m_str.bannermodel + $.modelName);
  ```
- **关键词:** $.h, $.id, $.desc, $.modelName, m_str.bannermodel
- **备注:** 需后续验证：1) 上级JS文件中$.h()的实现是否消毒输入 2) $.desc/$.modelName是否通过nvram_get/api等从外部输入获取 3) 污染源到参数的完整数据流追踪

---
### file_write-samba-writable

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:5-16`
- **类型:** file_write
- **综合优先级分数:** **4.8**
- **风险等级:** 4.0
- **置信度:** 8.0
- **触发可能性:** 2.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 全局可写目录创建（/var/samba/private等）存在理论文件篡改风险，但无实际利用链证据。触发条件：需samba服务运行且使用该目录。约束条件：未发现smbd启动命令或配置文件。安全影响：若服务启动，攻击者可篡改认证文件提权。
- **代码片段:**
  ```
  /bin/mkdir -m 0777 -p /var/samba/private
  ```
- **关键词:** /bin/mkdir, 0777, /var/samba/private, smbd, smb.conf
- **备注:** 关键缺失：未定位smbd二进制。后续建议：搜索samba相关进程启动点

---
### configuration_load-OID_Definitions

- **文件路径:** `web/js/oid_str.js`
- **位置:** `web/js/oid_str.js`
- **类型:** configuration_load
- **综合优先级分数:** **4.7**
- **风险等级:** 4.0
- **置信度:** 9.0
- **触发可能性:** 0.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 文件包含193个OID字符串定义，用于标识设备管理功能模块（如网络配置、访问控制、USB设备管理等）。这些定义本身不构成直接漏洞，但暴露了设备的功能架构和配置入口点。关键风险在于：当这些OID标识符作为API参数被外部输入（如HTTP请求）使用时，若后端处理逻辑未对关联参数进行边界检查或输入验证，可能形成攻击路径。例如：攻击者通过构造恶意OID参数访问WANIPConnection配置项可能绕过网络访问控制，或通过ACL配置项篡改防火墙规则。
- **关键词:** WANIPConnection, ACL, UsbDevice, LANDevice, ManagementServer, UPnPCfg, VoiceService, StorageService, IGD_DEV_INFO, WAN_DEV
- **备注:** 需在后续分析中追踪这些关键词：1) 检查HTTP处理函数是否直接使用OID作为参数 2) 验证ACL/WANIPConnection等关键配置项的set操作是否存在输入过滤缺失 3) 确认USB设备管理接口的权限控制机制。当前文件仅提供标识符定义，实际风险取决于后端对这些标识符的处理逻辑。

---
### network_input-www-index.htm-hash_loading

- **文件路径:** `web/index.htm`
- **位置:** `index.htm: 内联script`
- **类型:** network_input
- **综合优先级分数:** **3.25**
- **风险等级:** 0.5
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** index.htm通过location.href.match(/#__(\w+\.htm)$/)捕获hash值加载页面。触发条件：URL hash需匹配#__[字母数字下划线].htm格式。安全影响：1) 正则字符集(\w)限制文件名只能包含[A-Za-z0-9_]，无法注入路径遍历符号；2) 匹配失败时加载固定页面status.htm/qsStart.htm；3) 无法利用$.loadMain的路径拼接漏洞。实际利用概率：0%
- **代码片段:**
  ```
  if((ret = location.href.match(/#__(\w+\.htm)$/)) && ret[1]) {
    $.loadMain(ret[1]);
  } else {
    $.loadMain($.isFD ? "qsStart.htm" : "status.htm");
  }
  ```
- **关键词:** location.href.match, #__\w+\.htm$, ret[1], $.loadMain, status.htm, qsStart.htm
- **备注:** 需关注其他输入点：1) 表单提交端点 2) API接口 3) 环境变量交互

---
### negative_evidence-password_buffer-fcn.0043b8dc

- **文件路径:** `bin/busybox`
- **位置:** `fcn.0043b8dc (0x0043b8dc)`
- **类型:** authentication
- **综合优先级分数:** **3.22**
- **风险等级:** 1.0
- **置信度:** 9.0
- **触发可能性:** 0.1
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 密码输入缓冲区(fcn.0043b8dc)实现安全：硬编码128字节缓冲区，严格长度检查（≤127字符），逐字符读取防止溢出。未发现边界绕过漏洞。作为负向证据排除密码输入环节的攻击可能性。
- **关键词:** fcn.0043b8dc, sym.imp.read, *0x452ea8, 0x7f

---
### unverified_component-kill_ipc-missing_symbols

- **文件路径:** `bin/busybox`
- **位置:** `N/A`
- **类型:** ipc
- **综合优先级分数:** **3.1**
- **风险等级:** 3.0
- **置信度:** 4.0
- **触发可能性:** 2.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** kill/ipc组件因符号缺失无法验证：1) ipcrm/ipcs函数未定位 2) kill/killall函数不可见。推测性风险：PID验证缺失可能导致进程终止，但需root权限且无直接RCE证据。
- **关键词:** ipcrm, ipcs, kill, killall, pidof
- **备注:** 建议动态测试：fuzz kill命令参数（需root权限触发）

---
### configuration_load-wanEdit-vlan_validation_safe

- **文件路径:** `web/main/wanEdit.htm`
- **位置:** `wanEdit.htm:2437 (enVlanID)`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** VLAN配置处理函数'enVlanID'验证安全：1) 参数'val'仅接受预定义值（"ip","dyn_ip","ppp"） 2) 无用户输入处理 3) 逻辑仅控制UI元素可见性。无可利用攻击面。
- **关键词:** enVlanID, ip_vlan_en, dyn_ip_vlan_en, ppp_vlan_en
- **备注:** 安全验证通过，可排除攻击路径

---
### analysis_task-commonjs_validation

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: JavaScript引用`
- **类型:** analysis_task
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 关键后续任务1: 分析../js/common.js验证AJAX请求的安全处理逻辑。
- **关键词:** ../js/common.js, AJAX, 安全处理, ACT_CGI
- **备注:** 关联发现：network_input-parentCtrl-ajaxEndpoint

---
### analysis_task-cgi_tracing

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: CGI端点调用`
- **类型:** analysis_task
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 关键后续任务2: 追踪/cgi/lanMac和/cgi/info对应的后端CGI程序路径。
- **关键词:** /cgi/lanMac, /cgi/info, CGI路径追踪, 后端处理
- **备注:** 关联发现：network_input-parentCtrl-formInputs和network_input-parentCtrl-ajaxEndpoint

---
### analysis_task-helpjs_inspection

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm: setTimeout调用`
- **类型:** analysis_task
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 建议任务3: 检查../js/help.js中loadHelp()是否可控。
- **关键词:** ../js/help.js, loadHelp, setTimeout, 动态执行
- **备注:** 关联发现：command_execution-parentCtrl-dynamicEval

---
### negative_finding-hardcoded_credentials

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `全局扫描结果`
- **类型:** negative_finding
- **综合优先级分数:** **2.85**
- **风险等级:** 0.0
- **置信度:** 9.5
- **触发可能性:** 0.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 未发现硬编码凭证(password/admin等敏感字段)。证据：全文扫描未匹配password/credential等关键词。
- **代码片段:**
  ```
  N/A
  ```
- **关键词:** password, admin, credential

---
### negative_finding-dangerous_functions

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `全局扫描结果`
- **类型:** negative_finding
- **综合优先级分数:** **2.7**
- **风险等级:** 0.0
- **置信度:** 9.0
- **触发可能性:** 0.0
- **查询相关性:** 6.5
- **阶段:** N/A
- **描述:** 未检测到eval()/Function()等高危函数。证据：全文扫描未发现直接代码执行函数。
- **代码片段:**
  ```
  N/A
  ```
- **关键词:** eval, Function, code_execution

---
