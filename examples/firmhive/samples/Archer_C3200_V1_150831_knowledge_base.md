# Archer_C3200_V1_150831 高优先级: 11 中优先级: 23 低优先级: 19

## 优先级评分模型

**计算公式:** `PriorityScore = (0.5 * risk_level) + (0.3 * confidence) + (0.2 * trigger_possibility)`

**分层策略:**
- **高优先级:** `PriorityScore >= 8.5`
- **中优先级:** `7.0 <= PriorityScore < 8.5`
- **低优先级:** `PriorityScore < 7.0`

---

## 高优先级发现

### weak-creds-ftp-vsftpd_passwd

- **文件路径:** `etc/vsftpd_passwd`
- **位置:** `etc/vsftpd_passwd`
- **类型:** configuration_load
- **综合优先级分数:** **9.5**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 10.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** vsftpd密码文件采用自定义格式存储明文凭证，存在3个弱密码账户（admin:1234, guest:guest, test:test）。攻击者通过FTP服务发起暴力破解（如使用hydra工具）可在秒级时间内获取有效凭证。成功登录后：1) 可上传恶意文件（如webshell）至服务器；2) 可下载敏感文件；3) 若vsftpd配置不当可能获得更高权限。触发条件为FTP服务开启且暴露于网络。
- **代码片段:**
  ```
  admin:1234:1:1;guest:guest:0:0;test:test:1:1;
  ```
- **关键词:** vsftpd_passwd, admin, guest, test, FTP服务, ftp_username
- **备注:** 关联发现：config-ftp-anonymous-default（位于etc/vsftpd.conf）。后续建议：1) 检查/etc/vsftpd.conf配置是否允许匿名登录或存在目录遍历漏洞；2) 验证FTP服务是否在web界面被调用（如www目录中的PHP脚本）

---
### file-permission-ftp-vsftpd_passwd

- **文件路径:** `etc/vsftpd_passwd`
- **位置:** `/etc/vsftpd_passwd`
- **类型:** file_read
- **综合优先级分数:** **9.4**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 9.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** vsftpd_passwd文件权限设置为777（rwxrwxrwx），导致：1) 任意本地用户可读取明文凭证（含admin:1234等弱密码） 2) 攻击者可写入文件添加恶意账户（如添加UID=0账户）。触发条件：攻击者获得本地低权限shell（通过其他漏洞实现）。安全影响：1) 凭证泄露扩展至本地攻击面 2) 文件可写性实现权限提升。利用链：低权限漏洞→读取凭证→登录FTP→上传webshell；或直接添加root账户。
- **代码片段:**
  ```
  admin:1234:1:1;guest:guest:0:0;test:test:1:1;
  ```
- **关键词:** vsftpd_passwd, admin, guest, test, FTP服务, file_permission
- **备注:** 关联已有弱密码记录（weak-creds-ftp-vsftpd_passwd）。需验证：1) vsftpd.conf是否启用此文件 2) 是否存在其他本地漏洞（如命令注入）可触发此文件读取

---
### config-ftp-plaintext

- **文件路径:** `etc/vsftpd.conf`
- **位置:** `etc/vsftpd.conf`
- **类型:** network_input
- **综合优先级分数:** **9.4**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** FTP服务未启用SSL/TLS加密(配置中无ssl_enable参数)。触发条件：任何FTP网络通信过程。安全影响：所有认证凭证和文件内容以明文传输，攻击者通过中间人攻击可获取合法用户凭证。利用方式：ARP欺骗或网络监听截获凭证后登录系统。
- **关键词:** ssl_enable
- **备注:** 需结合网络服务分析验证HTTP/API等其他服务是否依赖FTP凭证

---
### command_execution-telnetd-unauthenticated

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:62`
- **类型:** command_execution
- **综合优先级分数:** **9.25**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** telnetd以无参数模式启动，未启用认证机制。触发条件：系统启动时自动执行。安全影响：攻击者可直接通过telnet获得设备shell权限（无需凭证），导致设备完全沦陷。
- **代码片段:**
  ```
  telnetd
  ```
- **关键词:** telnetd
- **备注:** 需后续分析：1. 定位telnetd二进制路径 2. 验证其默认配置是否强制认证

---
### unified-act-framework-vuln

- **文件路径:** `web/main/sysconf.htm`
- **位置:** `web框架全局`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 所有配置操作共用$.act(ACT_SET, <ENDPOINT>)框架模式，使LAN_WLAN/DDOS_CFG/LED_NIGHTMODE等端点成为统一攻击面。未观察到服务端请求验证逻辑，攻击者可能伪造请求修改配置。关键风险：参数直接映射到系统配置，缺乏服务端二次验证。
- **关键词:** $.act, ACT_SET, LAN_WLAN, DDOS_CFG, LED_NIGHTMODE
- **备注:** 核心攻击路径：HTTP参数→$.act→后端配置处理。关联发现：cgi-handler-ssrf-potential（未验证的ACT_CGI）、api-firewall-rule-bypass（未验证的ACT_SET）、device-info-leak（未验证的ACT_GET）。需重点审计各ENDPOINT对应的后端处理函数

---
### network_input-setPwd-password_cleartext

- **文件路径:** `web/frame/setPwd.htm`
- **位置:** `setPwd.htm:194-202`
- **类型:** network_input
- **综合优先级分数:** **9.14**
- **风险等级:** 9.0
- **置信度:** 9.8
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 密码传输安全漏洞：用户设置的新密码在客户端进行Base64编码后，通过HTTP明文传输到/cgi/setPwd端点（无HTTPS加密）。触发条件：用户提交密码表单时。攻击者可通过中间人攻击直接获取Base64解码后的原始密码。约束条件：仅影响未启用HTTPS的通信环境。潜在影响：直接导致凭证泄露，攻击成功概率高。
- **代码片段:**
  ```
  var prePwd = encodeURIComponent(Base64Encoding($("newPwd").value));
  xmlHttpObj.open("POST", "http://" + window.location.hostname + "/cgi/setPwd?pwd=" + prePwd, true);
  xmlHttpObj.send(null);
  ```
- **关键词:** doSetPassword, Base64Encoding, xmlHttpObj.open, /cgi/setPwd, prePwd, window.location.hostname
- **备注:** 需验证/cgi/setPwd服务端实现是否进行二次验证。与客户端验证绕过漏洞（network_input-setPwd-client_validation_bypass）组合可形成完整密码重置攻击链。

---
### untrusted-file-upload-softup

- **文件路径:** `web/main/softup.htm`
- **位置:** `softup.htm:表单区域`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 文件上传功能存在用户可控输入点：1) HTML表单参数'filename'接受任意文件上传至/cgi/softup 2) 前端仅验证非空(ERR_FIRM_FILE_NONE)，未对文件类型/大小/内容做边界检查 3) 攻击者可构造恶意固件文件触发后端漏洞。实际影响取决于/cgi/softup对上传文件的处理：若未验证文件签名或存在解析漏洞，可导致任意代码执行或设备变砖。
- **关键词:** filename, /cgi/softup, multipart/form-data, ERR_FIRM_FILE_NONE
- **备注:** 需分析/cgi/softup二进制验证文件处理逻辑

---
### network_input-setPwd-client_validation_bypass

- **文件路径:** `web/frame/setPwd.htm`
- **位置:** `setPwd.htm:248-312`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 客户端验证绕过风险：密码强度验证(checkPwd)和匹配验证(PCSubWin)仅在客户端执行。触发条件：攻击者直接构造POST请求到/cgi/setPwd端点。可绕过密码长度限制(1-15字符)、复杂度要求和一致性检查，设置任意密码（包括空密码或超长密码）。约束条件：需能发送HTTP请求到设备。潜在影响：结合服务端验证缺失可实现密码重置攻击。
- **代码片段:**
  ```
  function PCSubWin() {
    if ($password.value == "") { /* 可绕过 */ }
    if ($password.value.length > 15) { /* 可绕过 */ }
    if ($confirm.value != $password.value) { /* 可绕过 */ }
  }
  ```
- **关键词:** checkPwd, PCSubWin, input-error, usrTips, pwdTips, $password.value, $confirm.value
- **备注:** 完整利用需验证/cgi/setPwd的服务端逻辑。与密码明文传输漏洞（network_input-setPwd-password_cleartext）存在协同攻击可能。

---
### firmware-burn-chain

- **文件路径:** `web/main/softup.htm`
- **位置:** `softup.htm:JS代码区域`
- **类型:** network_input
- **综合优先级分数:** **8.7**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 固件烧录流程暴露危险操作链：1) 前端通过$.cgi异步调用/cgi/softburn 2) 烧录操作无二次确认机制 3) IGD_DEV_INFO数据结构暴露设备详情。若攻击者结合文件上传漏洞控制烧录内容，可完整劫持设备。触发条件：污染filename参数→绕过前端验证→利用/cgi/softup漏洞写入恶意固件→触发/cgi/softburn执行。
- **代码片段:**
  ```
  $('#t_upgrade').click(function(){
    if($("#filename").val() == ""){
      $.alert(ERR_FIRM_FILE_NONE);
      return false;
    }
    // 调用/cgi/softburn
  });
  ```
- **关键词:** /cgi/softburn, $.cgi, IGD_DEV_INFO, ACT_GET
- **备注:** 关键攻击链：filename→/cgi/softup→/cgi/softburn。需验证烧录签名检查。关联：IGD_DEV_INFO设备信息泄露（见device-info-leak）辅助构造针对性恶意固件

---
### configuration-passwd-account_misconfig

- **文件路径:** `etc/passwd.bak`
- **位置:** `etc/passwd.bak`
- **类型:** configuration_load
- **综合优先级分数:** **8.69**
- **风险等级:** 8.5
- **置信度:** 9.8
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** passwd.bak中存在高危账户配置：1)admin账户(UID=0)配置可交互/bin/sh，使攻击者获取该账户权限即可获得完整root shell 2)nobody账户(UID=0)虽被锁定但存在被激活风险 3)admin和nobody的家目录设置为根目录(/)，违反最小权限原则，若配合目录权限配置不当，可导致敏感文件泄露。触发条件：攻击者通过弱密码爆破、服务漏洞或中间件漏洞获取admin凭证后，可执行任意命令。利用方式：通过SSH/Telnet等远程服务登录admin账户，直接获得root权限的交互式shell。
- **关键词:** passwd.bak, admin, nobody, UID=0, GID=0, /bin/sh, 家目录=/
- **备注:** 需后续验证：1)/etc/shadow中admin密码强度 2)网络服务是否开放admin远程登录 3)根目录权限设置(ls -ld /)

---
### http-request-injection

- **文件路径:** `web/index.htm`
- **位置:** `www/js/lib.js:500`
- **类型:** network_input
- **综合优先级分数:** **8.6**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危HTTP请求注入漏洞：$.exe()函数拼接attrs参数时未过滤CR/LF字符，导致攻击者可通过可控attrs参数注入任意HTTP头或请求体。触发条件：1) 前端调用$.act()时传入用户控制的attrs参数（如来自URL参数）2) 参数值含%0d%0a序列 3) 触发$.exe()发送请求。实际影响：可绕过认证执行特权操作（如配置篡改）或窃取会话。
- **代码片段:**
  ```
  data += "[...]" + index + "," + obj[6] + "\r\n" + obj[5];
  ```
- **关键词:** $.exe, attrs, obj[5], data+=, \r\n, ACT_GET, ACT_SET
- **备注:** 完整攻击路径：用户输入→$.act()调用→$.exe()注入→后端特权操作

---

## 中优先级发现

### network_input-ethWan-ACT_OP_network_control

- **文件路径:** `web/main/ethWan.htm`
- **位置:** `ethWan.htm (JavaScript函数)`
- **类型:** network_input
- **综合优先级分数:** **8.45**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** ethWan.htm暴露高风险网络操作接口：包含ACT_OP_DHCP_RELEASE/ACT_OP_PPP_DISCONN等8个网络控制端点，通过$.act()调用。污染参数username/pwd/customMacAddr通过wan_pppoelistarg对象直接传递，触发条件为：1) 用户通过表单提交恶意参数 2) 绕过或有缺陷的客户端验证 3) 后端缺乏输入过滤。可导致：凭证窃取(通过username/pwd)、网络服务中断(通过连接操作)、MAC欺骗(通过customMacAddr)。
- **关键词:** ACT_OP_DHCP_RELEASE, ACT_OP_PPP_DISCONN, wan_pppoelistarg, username, pwd, customMacAddr, $.act
- **备注:** 关联发现：unified-act-framework-vuln（共用$.act框架）、network_input-diagnostic_csrf（类似无保护的ACT_OP操作）。待验证：1) 未确定$.act()请求的实际处理程序(cgi路径) 2) 未验证后端对username/pwd参数的过滤机制 3) 未确认ACT_OP操作是否受权限控制。下一步：分析cgi-bin目录下处理ACT_OP请求的文件；追踪wan_pppoelistarg参数在后端的使用路径；验证customMacAddr是否直接写入网络配置。

---
### wifi-adv-param-injection

- **文件路径:** `web/main/sysconf.htm`
- **位置:** `web/sysconf.htm JavaScript函数`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 无线高级配置表单通过wlAdvSave函数收集参数(如beaconInterval/rts)，经$.act(ACT_SET, LAN_WLAN)提交。前端仅验证数值范围(未过滤特殊字符)，攻击者可构造恶意参数触发后端漏洞。触发条件：提交修改无线配置的HTTP请求。实际影响取决于后端对LAN_WLAN的处理，可能造成命令注入或缓冲区溢出。
- **关键词:** wlAdvSave, beaconInterval, rts, frag, LAN_WLAN, ACT_SET, X_TP_BeaconInterval
- **备注:** 关键污点参数：beaconInterval/rts。需验证后端cgibin中LAN_WLAN处理函数

---
### network_input-login_token_generation-1

- **文件路径:** `web/frame/login.htm`
- **位置:** `web/frame/login.htm`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 登录认证令牌生成与存储漏洞：1) 客户端将明文密码通过Base64编码生成'Basic'认证令牌，相当于明文传输（Base64可逆）2) 令牌以cookie存储未设置HttpOnly属性，存在XSS窃取风险。触发条件：a) 用户提交登录表单时网络未加密 b) 存在跨站脚本漏洞时可窃取cookie。实际影响：攻击者可截获或窃取令牌直接获得认证权限。
- **代码片段:**
  ```
  auth = "Basic " + Base64Encoding($username.value + ":" + $password.value);
  document.cookie = "Authorization=" + auth;
  ```
- **关键词:** Authorization, document.cookie, Base64Encoding, pcPassword, PCSubWin
- **备注:** 需验证服务端是否强制HTTPS传输。关联线索：Base64Encoding/PCSubWin关键词在历史记录中出现，可能存在数据流关联

---
### xss-jquery_tpMsg-confirm

- **文件路径:** `web/js/jquery.tpMsg.js`
- **位置:** `jquery.tpMsg.js: 匿名函数(confirm)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** DOM型XSS漏洞存在于$.confirm()函数。攻击者通过控制str或replaceStr参数注入恶意脚本（如<img src=x onerror=alert(1)>），触发条件：当调用confirm()时污染参数被直接写入DOM。无任何输入过滤或边界检查，可导致任意脚本执行。
- **代码片段:**
  ```
  tmp.find("span.text").html(str);
  ```
- **关键词:** confirm, str, replaceStr, tmp.find("span.text").html, html(), $.turnqss
- **备注:** 需验证$.turnqss()的编码效果，建议追踪所有confirm()调用点确认参数是否来自网络输入

---
### xss-parental-control-device-name

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `www/parentCtrl.htm: initDeviceUnderParentalCtrlTable函数, 动态元素追加逻辑`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 存储型XSS漏洞：在initDeviceUnderParentalCtrlTable和URL添加逻辑中，用户控制的deviceName/description/urlAddr直接通过innerHTML插入DOM。攻击者通过修改设备配置（需低权限）注入恶意脚本，当管理员查看页面时触发。触发条件：1) 攻击者能修改设备名/URL列表（结合CSRF可绕过权限）2) 管理员访问家长控制页。实际影响：完全控制管理员会话，可操作所有路由器功能。
- **代码片段:**
  ```
  $("#addUrl").append('<div ... value="' + allBlackUrl[blackIndex] + '" ...');
  ```
- **关键词:** initDeviceUnderParentalCtrlTable, doSaveContentRestriction, innerHTML, entryName, description, urlAddr, $.initTableBody
- **备注:** 需验证$.isdomain过滤有效性；建议后续测试XSS实际触发并分析会话劫持后操作

---
### input-validation-command-injection

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `/www/usbManage.htm:1040(server_name验证),1115(shareName验证),1582(command对象)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.0
- **置信度:** 9.5
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 用户输入验证缺陷可能导致注入攻击。具体表现：1) server_name参数仅前端验证15字符长度和部分特殊字符；2) shareName参数未过滤Shell元字符；3) command.force等隐藏字段无验证。触发条件：提交USB配置表单时。约束条件：前端使用正则过滤（/[\/:*?"<>|\[\]+ ]+/）但未覆盖所有危险字符。安全影响：恶意构造的shareName可能触发后端命令注入。利用方式：绕过过滤注入;|$()等字符执行任意命令。
- **代码片段:**
  ```
  if ((/[\\\/:\*?"<>|\[\]\+ ]+/).test(newStr)) { $.alert(ERR_USB_INVALID_CHAR_IN_FOLDER_NAME); }
  ```
- **关键词:** server_name, shareName, command.force, ERR_USB_INVALID_CHAR_IN_FOLDER_NAME, CMM_USB_SERVER_NAME_LENGTH
- **备注:** 关键风险点：command.force参数直通后端。关联文件：/cgi-bin/usb_manage.cgi

---
### parameter-pollution-usb-mount

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `/www/usbManage.htm:488行(handleVolumeForce实现)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** USB设备操作接口存在参数污染风险。具体表现：$.act()第五参数'command'接收用户控制对象（含enable/force字段）。触发条件：调用handleVolumeForce()等函数时。约束条件：需设备物理存在但可强制操作离线设备。安全影响：篡改command.force=1可能导致异常挂载破坏文件系统。利用方式：结合CSRF伪造command={enable:1,force:1}参数。
- **代码片段:**
  ```
  $.act(ACT_SET, USB_DEVICE, usbDeviceList[idx].__stack, null, command);
  ```
- **关键词:** command, command.enable, command.force, handleVolumeForce, USB_DEVICE, LOGICAL_VOLUME
- **备注:** 需追踪command对象在后端的使用方式。关联文件：/cgi-bin/usb_manage.cgi

---
### configuration_load-rcS-global_writable_dirs

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:8-21,24`
- **类型:** configuration_load
- **综合优先级分数:** **8.3**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** rcS创建13个全局可写目录（0777权限），包括/var/run、/var/tmp/dropbear等敏感位置。触发条件：系统启动时自动执行。安全影响：攻击者可植入恶意文件或篡改PID等运行时数据，结合服务漏洞可能导致权限提升（如通过符号链接攻击或服务配置文件篡改）。
- **代码片段:**
  ```
  /bin/mkdir -m 0777 -p /var/run
  /bin/mkdir -m 0777 -p /var/tmp/dropbear
  ```
- **关键词:** mkdir, 0777, /var/run, /var/tmp/dropbear, /var/samba/private
- **备注:** 需后续分析：1. 检查telnetd/cos/rttd等服务是否使用这些目录 2. 验证目录是否暴露给网络服务

---
### network_input-MiniDLNA-端口暴露

- **文件路径:** `etc/minidlna.conf`
- **位置:** `etc/minidlna.conf`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** MiniDLNA服务暴露在8200端口(br0接口)且无访问控制。攻击者可通过网络发送恶意DLNA请求触发漏洞。若服务以root运行（user配置被注释），漏洞利用将获得设备完全控制权。需验证sbin/minidlnad是否存在缓冲区溢出等漏洞。
- **代码片段:**
  ```
  port=8200
  network_interface=br0
  #user=jmaggard
  ```
- **关键词:** port=8200, network_interface=br0, #user
- **备注:** 关键下一步：分析sbin/minidlnad的协议解析函数

---
### command_execution-telnetd-unauthenticated_start

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:62`
- **类型:** command_execution
- **综合优先级分数:** **8.2**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 10.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** telnetd服务以无认证参数形式启动（命令：'telnetd'）。触发条件：系统启动时自动执行rcS脚本。约束条件：依赖默认认证机制/bin/login。安全影响：若/bin/login存在硬编码凭证或认证逻辑漏洞，攻击者可通过网络直接获取系统权限。利用方式：远程连接telnet服务尝试认证绕过。
- **代码片段:**
  ```
  telnetd
  ```
- **关键词:** telnetd, rcS, /bin/login
- **备注:** 关联知识库记录#telnetd。需后续验证：1) /bin/login的逆向分析 2) 测试默认凭证（如admin/admin）

---
### api-firewall-rule-bypass

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `www/parentCtrl.htm: doSave函数, doSaveContentRestriction函数`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 6.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危API调用链：通过$.act(ACT_SET)直接操作FIREWALL/EXTERNAL_HOST等核心模块，参数如internalHostRef未经充分验证。攻击者结合XSS或CSRF构造恶意请求可：1) 禁用家长控制(enable=0) 2) 修改防火墙规则。触发条件：发送特制AJAX请求到后端处理模块。实际影响：完全绕过访问控制，覆盖系统安全策略。
- **代码片段:**
  ```
  $.act(ACT_SET, RULE, this.__stack, null, ["enable=0"]);
  ```
- **关键词:** $.act, ACT_SET, FIREWALL, EXTERNAL_HOST, RULE, internalHostRef, __stack, enableParentCtrl, IGD_DEV_INFO
- **备注:** 关键线索：追踪RULE/FIREWALL模块处理函数；验证__stack参数结构；需验证$.act(ACT_SET, FIREWALL)是否与现有IGD_DEV_INFO实现共享后端处理逻辑

---
### config-ftp-unsafe-upload

- **文件路径:** `etc/vsftpd.conf`
- **位置:** `etc/vsftpd.conf`
- **类型:** configuration_load
- **综合优先级分数:** **8.15**
- **风险等级:** 7.5
- **置信度:** 10.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 全局写权限开启(write_enable=YES)且本地用户登录启用(local_enable=YES)。触发条件：攻击者获得有效凭证后。安全影响：允许上传任意文件，结合chroot隔离(chroot_local_user=YES)但无例外列表，可能通过上传恶意脚本到可执行目录(如/www)实现代码执行。
- **关键词:** write_enable, local_enable, chroot_local_user
- **备注:** 更新：增加/www目录利用路径分析；与config-ftp-plaintext形成完整攻击链（凭证截获→恶意文件上传→代码执行）

---
### config-ftp-unsafe-upload

- **文件路径:** `etc/vsftpd.conf`
- **位置:** `etc/vsftpd.conf:0 (global) 0x0`
- **类型:** configuration_load
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** FTP服务配置允许认证用户上传文件(write_enable=YES)，但未限制上传文件类型或设置安全沙箱。攻击者获取有效凭证后可通过FTP上传恶意文件(如webshell)，若Web服务可访问FTP目录则形成RCE攻击链。触发条件：1) 攻击者获取本地用户凭证(如弱口令) 2) 系统存在Web服务且与FTP用户目录重叠。约束条件：chroot_local_user配置可能限制目录访问，需验证实际目录结构。
- **关键词:** write_enable, local_enable, chroot_local_user
- **备注:** 需结合/etc/passwd验证用户弱口令风险，并检查/www目录是否与FTP用户目录重叠

---
### network_input-diagnostic_command_injection

- **文件路径:** `web/main/diagnostic.htm`
- **位置:** `diagnostic.htm:80-230 (startDiag function)`
- **类型:** network_input
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 目标地址输入($("#l_addr"))未经格式验证直接用于构造诊断请求(ipping.host/tracert.host)。触发条件：用户提交诊断请求时输入含特殊字符的地址。安全影响：若后端直接拼接系统命令(如ping/traceroute)，可导致命令注入。利用方式：注入命令分隔符(如'; rm -rf /')
- **代码片段:**
  ```
  if ($("#l_addr").prop("value") == "") {...}
  ...
  ipping.host = $("#l_addr").prop("value");
  tracert.host = $("#l_addr").prop("value");
  ```
- **关键词:** startDiag, $("#l_addr"), ipping.host, tracert.host, ACT_OP_IPPING, ACT_OP_TRACERT
- **备注:** 需结合后端CGI验证命令执行方式。关联文件：处理ACT_OP_IPPING/ACT_OP_TRACERT请求的后端程序

---
### csrf-factory-reset-chain

- **文件路径:** `web/main/backNRestore.htm`
- **位置:** `backNRestore.htm:38-53`
- **类型:** network_input
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 工厂重置功能存在CSRF漏洞：1) 用户点击'Factory Restore'按钮触发$.act(ACT_OP_FACTORY_RESET)操作 2) 仅通过$.confirm对话框进行用户确认，无session/cookie验证机制 3) 与ACT_OP_REBOOT共享执行框架，成功重置后清除认证凭据($.deleteCookie("Authorization"))并立即触发设备重启。触发条件：攻击者诱导已认证用户访问恶意页面。实际影响：设备恢复出厂设置+强制重启形成双重拒绝服务攻击链，导致配置全清且服务中断。
- **代码片段:**
  ```
  $("#resetBtn").click(function() {
      $.confirm(c_str.cdefaults, function() {
          $.act(ACT_OP, ACT_OP_FACTORY_RESET);
          $.exe(function(err) {
              if (!err) {
                  $.guage([...], function() {
                      window.location.reload();
                  });
              }
              $.act(ACT_OP, ACT_OP_REBOOT);
              $.exe(function(err) {
                  if (!err) $.deleteCookie("Authorization");
              }, true);
          });
      })
  });
  ```
- **关键词:** ACT_OP_FACTORY_RESET, $.act, ACT_OP_REBOOT, $.deleteCookie, Authorization, resetBtn, ACT_REBOOT
- **备注:** 漏洞链关联：1) 与重启漏洞(unauthorized-reboot)形成连续攻击链 2) 需验证后端：ACT_OP_FACTORY_RESET是否调用mtd erase 3) 清除认证凭据后的设备状态

---
### csrf-missing-usb-operation

- **文件路径:** `web/main/usbManage.htm`
- **位置:** `/www/usbManage.htm: 未指定行号 [全局函数]`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 表单CSRF防护缺失导致USB状态篡改风险。具体表现：所有表单操作通过$.loadMain/$.act触发AJAX请求但未使用CSRF令牌。触发条件：用户点击'Save'/'Scan'按钮时。约束条件：需用户会话有效但无二次验证。安全影响：攻击者可构造恶意页面诱导管理员点击，导致USB设备强制卸载或挂载。利用方式：社工攻击+恶意HTML页面触发$.act(ACT_SET, USB_DEVICE)。
- **关键词:** $.loadMain, $.act, ACT_SET, USB_DEVICE, handleUsb, mountUsb
- **备注:** 需验证后端/cgi-bin/相关程序是否校验CSRF令牌。关联文件：/js/common.js（实现$.act）

---
### device-info-leak

- **文件路径:** `web/index.htm`
- **位置:** `www/frame/bot.htm:12`
- **类型:** network_input
- **综合优先级分数:** **7.95**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 设备信息泄露漏洞：bot.htm通过$.act(ACT_GET, IGD_DEV_INFO)获取并明文展示硬件/软件版本。触发条件：访问含此脚本的页面（无需认证）。安全影响：泄露设备精确版本，辅助攻击者匹配漏洞利用链。
- **代码片段:**
  ```
  var devInfo = $.act(ACT_GET, IGD_DEV_INFO...);
  $("#bot_sver").html(...devInfo.softwareVersion);
  ```
- **关键词:** $.act, ACT_GET, IGD_DEV_INFO, devInfo.softwareVersion, #bot_sver

---
### network_input-diagnostic_csrf

- **文件路径:** `web/main/diagnostic.htm`
- **位置:** `diagnostic.htm:112, 200`
- **类型:** network_input
- **综合优先级分数:** **7.9**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 敏感端点(ACT_OP_IPPING/ACT_OP_TRACERT)通过$.act()暴露且无CSRF保护。触发条件：直接构造恶意POST请求。安全影响：绕过前端界面执行未授权诊断操作。利用方式：伪造请求包操作tracert/ipping对象参数
- **代码片段:**
  ```
  $.act(ACT_OP, ACT_OP_IPPING);
  $.act(ACT_OP, ACT_OP_TRACERT);
  ```
- **关键词:** $.act, ACT_OP, ACT_OP_IPPING, ACT_OP_TRACERT, IPPING_DIAG, TRACEROUTE_DIAG
- **备注:** 需验证后端身份验证机制。攻击路径起始点：网络接口(HTTP POST)

---
### wds-bridge-xss-vector

- **文件路径:** `web/main/sysconf.htm`
- **位置:** `web/sysconf.htm WDS表单`
- **类型:** network_input
- **综合优先级分数:** **7.7**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** WDS桥接配置通过wdsSave提交wdsSsid/wdsMac等参数到LAN_WLAN_WDSBRIDGE端点。SSID字段允许32字节任意输入(无XSS过滤)，若后端存储并渲染该值可能引发存储型XSS。触发条件：攻击者提交含恶意脚本的SSID字段。MAC地址验证仅前端$.mac()检查格式，可被绕过。
- **关键词:** wdsSave, wdsSsid, wdsMac, LAN_WLAN_WDSBRIDGE, BridgeSSID, BridgeBSSID
- **备注:** SSID可作为跨站脚本攻击向量，需检查管理界面是否渲染该值

---
### cgi-handler-ssrf-potential

- **文件路径:** `web/js/lib.js`
- **位置:** `web/js/lib.js:行号未获取`
- **类型:** network_input
- **综合优先级分数:** **7.55**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 文件包含CGI调用机制(ACT_CGI)但未定义具体实现。用户输入通过$.io($.params)获取后可能传递给ACT_CGI操作，未观察到输入验证逻辑。潜在风险：若$.act函数未过滤路径参数，攻击者可构造恶意路径进行服务端请求伪造(SSRF)。触发条件：控制$.params参数值。关联攻击链：结合现有$.act实现(如device-info-leak)，可形成'网络输入→ACT_CGI→后端CGI'的完整利用路径。
- **关键词:** ACT_CGI, $.act, $.io, $.params, /cgi/info, ACT_GET, ACT_OP
- **备注:** 关键关联点：1) 与device-info-leak/unauthorized-reboot共用$.act机制 2) /cgi端点需结合xss-potential-bothtm-version的NVRAM分析建议 3) 完整攻击路径：污染$.params→触发ACT_CGI→SSRF

---
### js-analysis-limitation/web/js/str.js

- **文件路径:** `web/js/str.js`
- **位置:** `web/js/str.js`
- **类型:** network_input
- **综合优先级分数:** **7.5**
- **风险等级:** 7.0
- **置信度:** 10.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 受限于工具能力，无法获取 'web/js/str.js' 文件内容，因此无法进行代码级分析。需文件读取工具支持才能验证以下潜在风险：1) 是否存在敏感信息泄露（如硬编码凭证）；2) 是否包含未过滤的用户输入处理逻辑（如eval()/innerHTML)；3) 是否暴露危险API端点。
- **关键词:** web/js/str.js, js_analysis
- **备注:** 建议后续增加文件内容读取工具以支持JS文件分析，重点关注：DOM操作函数、网络请求处理、加密密钥硬编码等模式

---
### format-string-httpd-0xb514

- **文件路径:** `usr/bin/httpd`
- **位置:** `usr/bin/httpd:0xb514 (fcn.0000b3b4)`
- **类型:** network_input
- **综合优先级分数:** **7.35**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在HTTP 401响应处理中，使用硬编码JS模板(0x10038)和未验证的认证次数(uVar1)、禁止时间(uVar7)执行sprintf。触发条件：1) 访问受限URL触发HTTP 401状态码 2) 全局结构体(*0xb5ac)[0x10]非零。漏洞表现：模板含4个占位符但仅提供2个参数，导致读取栈外数据。边界检查缺失：目标缓冲区512字节未验证参数数量匹配。安全影响：攻击者通过未授权访问触发401响应可能泄露敏感栈数据（如内存地址），无直接代码执行证据。利用概率中等：需精确控制全局结构体状态。
- **代码片段:**
  ```
  sym.imp.sprintf(puVar9 + -0x480, *0xb5bc, uVar1, uVar7);  // *0xb5bc=0x10038
  ```
- **关键词:** fcn.0000b3b4, sprintf, 0x10038, uVar1, uVar7, *0xb5ac, param_1=0x191, /userRpm/LoginRpm.htm
- **备注:** 矛盾点：首次报告需路径含'/frame'但实际触发路径为受限URL。动态测试建议：验证401响应的内存泄露。附加结论：本文件未发现NVRAM/环境变量操作及命令执行函数调用。

---
### xss-jquery_tpMsg-alertAsnyc

- **文件路径:** `web/js/jquery.tpMsg.js`
- **位置:** `jquery.tpMsg.js: jQuery.extend.alertAsnyc`
- **类型:** network_input
- **综合优先级分数:** **7.1**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 多源污染XSS漏洞存在于alertAsnyc()函数。通过控制errno或str参数注入脚本，触发条件：errno/str污染数据在拼接(m_str.errno + ":"+ errno + "<br>" + str)后被html()写入DOM。无安全隔离措施，可组合多个污染源实施攻击。
- **代码片段:**
  ```
  tmp.find("span.text").css(...).html($.turnqss(m_str.errno + ":"+ errno + "<br>" + str));
  ```
- **关键词:** alertAsnyc, errno, str, tmp.find("span.text").html, html(), $.turnqss, m_str.errno
- **备注:** m_str.errno可能来自语言包文件，若该文件可被篡改则扩大攻击面

---

## 低优先级发现

### dos-threshold-bypass

- **文件路径:** `web/main/sysconf.htm`
- **位置:** `web/sysconf.htm DoS表单`
- **类型:** network_input
- **综合优先级分数:** **6.9**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 7.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** DoS防护配置通过doSaveDosProtectionLevelSettings发送icmpLow/udpLow等阈值参数到DDOS_CFG端点。前端验证数值范围(5-3600)，但攻击者可设极高值(如3600)使防护失效。触发条件：提交修改DoS阈值的HTTP请求。实际影响：通过设置非合理阈值可削弱设备抗DDoS能力。
- **关键词:** doSaveDosProtectionLevelSettings, icmpLow, udpLow, tcpLow, DDOS_CFG, synLevelLow

---
### csrf-dos-restart_htm

- **文件路径:** `web/main/restart.htm`
- **位置:** `restart.htm:7`
- **类型:** network_input
- **综合优先级分数:** **6.9**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 7.5
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** restart.htm实现设备重启功能，点击#t_reboot按钮触发：1) 弹出确认对话框(c_str.creboot) 2) 调用$.act(ACT_OP, ACT_OP_REBOOT) 3) 执行$.exe(true)提交请求。触发条件：攻击者诱导已认证用户访问恶意页面（CSRF）。安全影响：缺乏二次认证和进度条机制可能被用于掩盖攻击，导致设备拒绝服务（风险值6/10）。未发现用户输入参数，故无输入验证缺陷。
- **代码片段:**
  ```
  $("#t_reboot").click(function(){
    if($.confirm(c_str.creboot)) {
      $.guage([...], function(){$.refresh();});
      $.act(ACT_OP, ACT_OP_REBOOT);
      $.exe(true);
    }
  });
  ```
- **关键词:** #t_reboot, c_str.creboot, $.act, ACT_OP, ACT_OP_REBOOT, $.exe, $.guage
- **备注:** 关键关联：1) 与top.htm(unauthorized-reboot)共享ACT_OP_REBOOT机制 2) 与backNRestore.htm(csrf-factory-reset-chain)形成多重攻击链。未解决：1) ACT_OP_REBOOT数值未定义 2) $.exe()后端路由未定位 3) 会话验证机制未验证。建议优先追踪/sbin/reboot二进制

---
### network_input-diagnostic_dos

- **文件路径:** `web/main/diagnostic.htm`
- **位置:** `diagnostic.htm:86-94, 118`
- **类型:** network_input
- **综合优先级分数:** **6.7**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 包大小(pktSize)验证存在逻辑缺陷：允许0值(0-65500)但未补偿ICMP头长度(+8字节)。触发条件：设置包大小为0。安全影响：可能导致后端内存分配异常(预分配0字节)。利用方式：构造异常包大小触发拒绝服务
- **代码片段:**
  ```
  pktSize = parseInt($("#l_ping_pkt_size").prop("value"), 10);
  ...
  if (isNaN(pktSize) || pktSize < 0 || pktSize > 65500) {...}
  ...
  pktSize = parseInt($("#l_ping_pkt_size").prop("value"), 10) + 8;
  ```
- **关键词:** pktSize, dataBlockSize, $("#l_ping_pkt_size"), icmpPkts, strstr
- **备注:** 实际风险取决于后端缓冲区处理逻辑。边界检查不完整示例

---
### network_input-MiniDLNA-目录遍历风险

- **文件路径:** `etc/minidlna.conf`
- **位置:** `etc/minidlna.conf`
- **类型:** network_input
- **综合优先级分数:** **6.55**
- **风险等级:** 6.5
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 未显式配置媒体目录(media_dir)和根容器(root_container)，使用默认值可能允许访问敏感路径。结合目录遍历漏洞(如HTTP请求中的路径参数未过滤)，攻击者可读取系统文件。触发条件：minidlna处理恶意文件路径请求时未进行边界检查。
- **代码片段:**
  ```
  #media_dir=AVP,G,/home/zhu/media
  #root_container=.
  ```
- **关键词:** #media_dir, #root_container=.
- **备注:** 需验证minidlna实际文件访问逻辑

---
### input-validation-device-name

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `www/parentCtrl.htm: doSave函数`
- **类型:** network_input
- **综合优先级分数:** **6.5**
- **风险等级:** 6.5
- **置信度:** 7.5
- **触发可能性:** 5.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 输入验证缺陷链：1) MAC地址仅格式校验($.mac)但未过滤特殊字符 2) 设备名校验($.isname)规则未定义 3) 设备名长度未限制导致posfix拼接风险。攻击者通过超长设备名(>32字符)或特殊字符可能触发内存破坏或注入。触发条件：添加新设备时提交恶意输入。
- **代码片段:**
  ```
  if (!($.isname($("#deviceName").val()))) { alert(ERR_FW_ENTRYNAME_INVAD); return; }
  ```
- **关键词:** macAddress, deviceName, $.mac, $.isname, curDevNum, maxDevNum, posfix, ERR_FW_ENTRYNAME_INVAD
- **备注:** 需逆向$.isname实现；测试设备名超长(>64字符)和嵌入HTML标签

---
### command_execution-insmod-hardcoded_path

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:38-60`
- **类型:** command_execution
- **综合优先级分数:** **6.45**
- **风险等级:** 6.0
- **置信度:** 9.5
- **触发可能性:** 3.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** insmod加载内核模块使用硬编码绝对路径（如/lib/modules/kmdir/kernel/drivers/scsi/scsi_mod.ko）。触发条件：系统启动时执行rcS脚本。约束条件：需攻击者先获得文件系统写入权限。安全影响：配合文件篡改漏洞可实现内核级代码执行。利用方式：覆盖模块文件植入恶意代码。
- **代码片段:**
  ```
  insmod /lib/modules/kmdir/kernel/drivers/scsi/scsi_mod.ko
  ```
- **关键词:** insmod, /lib/modules/kmdir/kernel/drivers/scsi/scsi_mod.ko, /lib/modules/tfat.ko
- **备注:** 关键限制：需验证模块文件的权限设置（是否可写）及完整性检查机制

---
### network_input-diagnostic_xss

- **文件路径:** `web/main/diagnostic.htm`
- **位置:** `diagnostic.htm:60-62, 150`
- **类型:** network_input
- **综合优先级分数:** **6.45**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** disNewLine()使用innerHTML直接插入未过滤的诊断结果(ipping.X_TP_Result)。触发条件：诊断返回含恶意脚本的结果时。安全影响：存储型XSS攻击。利用方式：污染DNS响应或中间人攻击注入恶意脚本
- **代码片段:**
  ```
  function disNewLine(info, stat) {
    var showText = $("#result").html();
    showText += info + "\r\n";
    $("#result").html(showText);
  }
  ...
  disNewLine(ipping.X_TP_Result, "");
  ```
- **关键词:** disNewLine, ipping.X_TP_Result, $("#result").html, showText
- **备注:** 需验证诊断输出是否外部可控。关联组件：DNS解析服务或网络中间件

---
### unauthorized-reboot

- **文件路径:** `web/index.htm`
- **位置:** `www/frame/top.htm:0`
- **类型:** network_input
- **综合优先级分数:** **6.1**
- **风险等级:** 6.0
- **置信度:** 7.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 设备重启操作暴露：top.htm通过$.act(ACT_OP, ACT_OP_REBOOT)触发重启。触发条件：用户点击#topReboot元素（可结合CSRF利用）。约束：需有效会话cookie。安全影响：拒绝服务攻击或配置重置。
- **关键词:** $.act, ACT_OP, ACT_OP_REBOOT, #topReboot, ACT_REBOOT
- **备注:** 实际风险依赖后端会话验证强度

---
### network_input-MiniDLNA-协议安全削弱

- **文件路径:** `etc/minidlna.conf`
- **位置:** `etc/minidlna.conf`
- **类型:** network_input
- **综合优先级分数:** **5.7**
- **风险等级:** 5.0
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 禁用严格DLNA模式(strict_dlna=no)可能降低协议解析安全性。结合inotify监控(inotify=yes)，恶意文件创建事件可能触发解析漏洞。攻击链：诱使用户下载畸形媒体文件→inotify触发解析→漏洞利用。
- **代码片段:**
  ```
  inotify=yes
  strict_dlna=no
  ```
- **关键词:** strict_dlna=no, inotify=yes
- **备注:** 需结合文件监控和解析逻辑分析

---
### configuration_load-login_lock_mechanism-1

- **文件路径:** `web/frame/login.htm`
- **位置:** `web/frame/login.htm`
- **类型:** configuration_load
- **综合优先级分数:** **5.35**
- **风险等级:** 3.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 登录锁定机制前端实现缺陷：1) 失败计数器(authTimes)和锁定时间(forbidTime)由后端注入 2) 前端倒计时逻辑通过递归setTimeout实现。攻击者可通过禁用JavaScript或修改客户端时间绕过锁定显示（但后端状态仍有效）。触发条件：连续5次登录失败后，攻击者操纵客户端环境。实际影响：可能造成用户体验欺骗但无实质权限绕过，实际锁定取决于后端验证。
- **代码片段:**
  ```
  if (authTimes >= 5) {
      isLocked = true;
      lockWeb(true);
      count = 600 - forbidTime;
      // 递归倒计时实现
  }
  ```
- **关键词:** authTimes, forbidTime, isLocked, setTimeout, lockWeb
- **备注:** 需在服务端组件验证authTimes的更新和校验机制

---
### xss-potential-bothtm-version

- **文件路径:** `web/frame/bot.htm`
- **位置:** `bot.htm:10-14`
- **类型:** network_input
- **综合优先级分数:** **5.2**
- **风险等级:** 5.0
- **置信度:** 7.0
- **触发可能性:** 3.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 在bot.htm中发现未经验证的DOM输出点：设备版本信息（softwareVersion/hardwareVersion）通过$.html()直接注入页面元素。具体表现：1) 使用$.act(ACT_GET, IGD_DEV_INFO)获取版本数据 2) 通过$("#bot_sver").html()动态插入DOM 3) 未显式进行HTML编码。触发条件：用户访问bot.htm页面（无需认证）时自动执行。安全影响：若版本值包含恶意脚本可导致XSS，但因当前证据不足，存在关键约束：a) 未验证版本信息是否外部可控 b) 未确认$.html()是否自动转义字符。潜在利用需满足：攻击者能污染设备版本存储（如通过固件升级漏洞或NVRAM写入）。
- **代码片段:**
  ```
  var devInfo = $.act(ACT_GET, IGD_DEV_INFO, null, null, ["hardwareVersion", "softwareVersion"]);
  $("#bot_sver").html(s_str.swver + devInfo.softwareVersion);
  ```
- **关键词:** IGD_DEV_INFO, ACT_GET, $.act, devInfo.softwareVersion, devInfo.hardwareVersion, #bot_sver, .html()
- **备注:** 关键待验证项：1) 定位/sbin或/cgi-bin中处理IGD_DEV_INFO的组件 2) 分析版本数据来源（是否来自nvram_get/env_get）3) 验证jQuery.html()转义行为。关联记录：device-info-leak（同IGD_DEV_INFO）

---
### http-link-mitm

- **文件路径:** `web/index.htm`
- **位置:** `www/frame/bot.htm:0`
- **类型:** network_input
- **综合优先级分数:** **5.0**
- **风险等级:** 4.0
- **置信度:** 10.0
- **触发可能性:** N/A
- **查询相关性:** 5.0
- **阶段:** N/A
- **描述:** HTTP链接中间人风险：bot.htm页脚使用HTTP协议支持链接（http://www.tp-link.com/en/support/）。触发条件：用户点击链接。影响：可能被劫持重定向至钓鱼站点。
- **关键词:** http://www.tp-link.com/en/support/, T_sup, bot.htm

---
### uninit-struct-httpd-0x2fa18

- **文件路径:** `usr/bin/httpd`
- **位置:** `usr/bin/httpd:0x2fa18 (global_struct)`
- **类型:** configuration_load
- **综合优先级分数:** **4.1**
- **风险等级:** 4.0
- **置信度:** 5.0
- **触发可能性:** 3.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 地址0xb5ac指向0x2fa18处的全局结构体（含认证计数字段）未发现初始化代码。触发条件：任何使用该结构体的操作（如0xb438/0xb46c）。实际影响：未初始化可能导致认证计数错误或空指针崩溃，无证据表明外部可控。利用概率低。
- **关键词:** 0xb5ac, 0x2fa18, *puVar6, fcn.0000b3b4@0xb438
- **备注:** 需结合固件启动流程分析初始化。与格式化字符串漏洞共享关键结构体指针*0xb5ac。附加结论：本文件未发现NVRAM/环境变量操作及命令执行函数调用。

---
### config-ftp-anonymous-default

- **文件路径:** `etc/vsftpd.conf`
- **位置:** `etc/vsftpd.conf:0 (global) 0x0`
- **类型:** configuration_load
- **综合优先级分数:** **3.9**
- **风险等级:** 2.0
- **置信度:** 9.0
- **触发可能性:** 1.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 匿名访问被显式禁用(anonymous_enable=NO)，但ftp_username保持默认值'ftp'。若未来启用匿名访问，可能导致默认账户权限问题。当前配置下匿名上传(anon_upload_enable)和目录创建(anon_mkdir_write_enable)均未启用。触发条件：管理员错误启用匿名访问功能。
- **关键词:** anonymous_enable, ftp_username

---
### network_input-login-password_validation

- **文件路径:** `bin/login`
- **位置:** `bin/login:0x30c48 (strcmp), 0x30c70 (memset)`
- **类型:** network_input
- **综合优先级分数:** **3.7**
- **风险等级:** 2.0
- **置信度:** 7.0
- **触发可能性:** 3.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 密码验证流程使用strcmp进行安全比较和memset清除缓冲区，实现基本安全防护。触发条件：用户通过登录接口输入密码。约束：1) 需有效用户凭证 2) 依赖BusyBox 1.19.2实现 3) 受反编译深度限制无法验证所有路径。潜在风险：BusyBox可能存在未公开漏洞（如CVE-2021-42374），但当前分析未发现具体可利用缺陷。
- **关键词:** strcmp, memset, Password:
- **备注:** 安全实践记录。建议：1) 检查BusyBox漏洞数据库 2) 动态分析监控认证流程 3) 强化输入过滤机制

---
### deprecated-css-loader

- **文件路径:** `web/js/lib.js`
- **位置:** `web/js/lib.js:行号未获取`
- **类型:** configuration_load
- **综合优先级分数:** **3.7**
- **风险等级:** 2.0
- **置信度:** 9.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 动态CSS加载逻辑使用固定路径，未发现用户输入参与路径拼接。IE版本检测依赖已弃用的$.browser对象，可能因浏览器伪装导致路径解析异常，理论影响有限。
- **关键词:** $.browser.msie, css.href, ./css/ie.file.css

---
### oid-definition-constants

- **文件路径:** `web/js/oid_str.js`
- **位置:** `web/js/oid_str.js`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 文件为静态OID字符串定义文件，未包含可执行代码或输入处理逻辑。所有内容均为常量声明，不存在：1) 敏感信息泄露风险（如GPON_AUTH_PWD仅为对象标识符名称，未存储实际密码）2) 输入验证缺失问题（无输入处理点）3) 危险函数调用（如eval/innerHTML）4) 网络请求接口。但定义的OID常量可能在nvram_get/set等操作中被引用，需在其他组件中追踪这些标识符的数据流。
- **关键词:** GPON_AUTH_PWD, WEB_INCLUDE_TEST, INCLUDE_LAN_WLAN, IGD, VOICE_CAP, LAN_WLAN_GUESTNET, WAN_ETH_INTF
- **备注:** 关键后续方向：1) 在C/C++二进制中搜索GPON_AUTH_PWD等OID的引用点 2) 检查调用nvram_get(GPON_AUTH_PWD)的组件是否存在边界检查缺失 3) 追踪OID相关数据在HTTP参数处理中的传播路径

---
### configuration_load-mount-fstab_dependency

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:3`
- **类型:** configuration_load
- **综合优先级分数:** **0.0**
- **风险等级:** 0.0
- **置信度:** 0.0
- **触发可能性:** 0.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** mount -a命令依赖/etc/fstab配置。触发条件：系统启动。约束条件：无法验证/etc/fstab是否可被外部修改。安全影响：理论上篡改fstab可导致恶意挂载，但当前无证据支持实际可利用性。
- **代码片段:**
  ```
  mount -a
  ```
- **关键词:** mount, -a, /etc/fstab
- **备注:** 证据不足：1) 无法访问/etc目录 2) 未发现相关操作脚本。建议获得完整固件访问后专项分析

---
### command_execution-unknown_service-cos_rttd

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS`
- **类型:** command_execution
- **综合优先级分数:** **0.0**
- **风险等级:** 0.0
- **置信度:** 0.0
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** cos/rttd服务启动命令未指定路径（'cos &'/'rttd &'）。触发条件：系统启动时后台运行。约束条件：PATH环境变量未定义，无法定位可执行文件。安全影响：未知，服务二进制分析受阻。
- **关键词:** cos, rttd
- **备注:** 后续方向：1) 全局搜索cos/rttd可执行文件 2) 分析/bin、/sbin等目录

---
