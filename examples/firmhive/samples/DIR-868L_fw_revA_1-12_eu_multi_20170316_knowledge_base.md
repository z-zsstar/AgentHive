# DIR-868L_fw_revA_1-12_eu_multi_20170316 高优先级: 7 中优先级: 11 低优先级: 1

## 优先级评分模型

**计算公式:** `PriorityScore = (0.5 * risk_level) + (0.3 * confidence) + (0.2 * trigger_possibility)`

**分层策略:**
- **高优先级:** `PriorityScore >= 8.5`
- **中优先级:** `7.0 <= PriorityScore < 8.5`
- **低优先级:** `PriorityScore < 7.0`

---

## 高优先级发现

### path_traversal-http_request_uri_construct

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `fcn.0000adbc:0xb188`
- **类型:** network_input
- **综合优先级分数:** **9.35**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 路径遍历漏洞。具体表现：REQUEST_URI直接用于sprintf构造文件路径，未过滤'../'序列。触发条件：在URI中包含路径遍历序列(如'GET /../../etc/passwd')。安全影响：可访问任意文件（读取敏感文件/删除关键文件）。边界检查：完全缺失路径规范化或过滤机制。
- **代码片段:**
  ```
  sprintf(file_path, "id=%s", user_input);
  ```
- **关键词:** REQUEST_URI, sprintf, fcn.0000adbc, fcn.000266d8, file_path, fileaccess.cgi
- **备注:** 形成关键攻击链节点：控制file_path变量后可触发不安全文件操作（见unsafe_file_operation-fileaccess_cgi发现），同类漏洞在其它CGI中已证实可稳定利用

---
### command_injection-upnp-DeletePortMapping

- **文件路径:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.DeletePortMapping.php`
- **位置:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.DeletePortMapping.php:38`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 确认高危命令注入漏洞：攻击者通过AddPortMapping设置含恶意命令的NewRemoteHost/internalclient参数（如`" ; reboot #`），该值存储于runtime节点。当删除此映射时，DeletePortMapping.php读取污染值拼接到iptables命令（`$cmd = 'iptables -t nat -D DNAT.UPNP...'`），通过fwrite写入SHELL_FILE。双引号包裹无法防御命令分隔符，导致任意命令执行。触发条件：1) 创建含恶意参数的端口映射 2) 触发删除操作（手动/自动）。成功利用概率高（CVSS 9.8），因iptables以root运行。
- **代码片段:**
  ```
  $cmd = 'iptables -t nat -D DNAT.UPNP'.$proto.' --dport '.$extport.' -j DNAT --to-destination "'.$intclnt.'":'.$intport;
  ```
- **关键词:** NewRemoteHost, internalclient, remotehost, intclnt, iptables -t nat -D DNAT.UPNP, SHELL_FILE, fwrite, /runtime/upnpigd/portmapping/entry, AddPortMapping, DeletePortMapping
- **备注:** 完整攻击链：控制输入→污染runtime节点→触发删除→命令注入。需验证：1) SHELL_FILE执行机制 2) AddPortMapping.php的输入过滤

---
### stack_overflow-httpd-REQUEST_URI_fcn.0000ac10

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `fcn.0000ac10:0xac10`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈溢出漏洞：在fcn.0000ac10函数中，strcat操作未验证总长度是否超出auStack_1038缓冲区（4035字节）。触发条件：1) 攻击者通过HTTP请求控制环境变量（如REQUEST_URI）；2) 污染数据经fcn.0000a480处理；3) 拼接后长度超过4035字节。利用方式：构造超长请求（≈4034字节）覆盖返回地址，实现任意代码执行。程序以root权限运行，成功利用可完全控制设备。
- **代码片段:**
  ```
  sym.imp.strcat(*piVar3, piVar3[-1]);
  ```
- **关键词:** REQUEST_URI, strcat, fcn.0000ac10, auStack_1038, 0xfc2, QUERY_STRING
- **备注:** 完整攻击链：HTTP请求 → REQUEST_URI污染 → fcn.0000a480处理 → strcat栈溢出 → EIP劫持

---
### port_validation-upnp-AddPortMapping

- **文件路径:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **位置:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php:15-21,40-50`
- **类型:** network_input
- **综合优先级分数:** **8.8**
- **风险等级:** 8.0
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 端口验证缺陷形成完整攻击路径：攻击者通过UPnP接口提交恶意端口映射请求 → NewExternalPort/NewInternalPort参数仅经isdigit()数字验证 → 无范围检查(0-65535) → 非法端口值(如0或99999)直接用于iptables规则构造 → 导致防火墙服务异常或规则失效。触发条件：1) 设备开启UPnP服务 2) 提交含非数字或超范围端口的请求。实际影响：拒绝服务(防火墙功能瘫痪)或安全绕过(非常规端口绕过检测)。
- **代码片段:**
  ```
  if($NewExternalPort=="" || isdigit($NewExternalPort)==0)
  {
      $_GLOBALS["errorCode"]=716;
  }
  ...
  $cmd = 'iptables -t nat -A DNAT.UPNP'.$proto.' --dport '.$NewExternalPort
  ```
- **关键词:** NewExternalPort, NewInternalPort, isdigit, errorCode=716, errorCode=402, set("externalport", set("internalport", iptables -t nat -A DNAT.UPNP, --dport
- **备注:** 利用链完整度：高。关联漏洞：防火墙瘫痪可能放大命令注入漏洞（参见command_injection-upnp-DeletePortMapping）。后续建议：1) 分析UPnP服务暴露情况 2) 检查防火墙崩溃后的系统行为

---
### stack_overflow-http_request_uri_copy

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `fcn.0000adbc:0xb04c`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 基于栈的缓冲区溢出漏洞。具体表现：当HTTP请求URI长度超过0xFC2字节(4034字节)时，strcpy函数将REQUEST_URI复制到固定大小缓冲区时未检查边界，导致栈内存覆盖。触发条件：发送超长URI请求(>4034字节)。安全影响：可导致服务崩溃或控制流劫持实现任意代码执行。约束条件：缓冲区大小隐式定义，需动态测试确认偏移。
- **代码片段:**
  ```
  strcpy(dest, REQUEST_URI);
  ```
- **关键词:** REQUEST_URI, strcpy, fcn.0000adbc, fileaccess.cgi
- **备注:** 需结合栈布局分析确认精确覆盖点，建议后续动态测试验证利用可行性。与路径遍历漏洞共用REQUEST_URI输入源

---
### unsafe_file_operation-fileaccess_cgi

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `Cross-referenced: fcn.000266d8`
- **类型:** file_read/file_write
- **综合优先级分数:** **8.6**
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 用户控制路径的不安全文件操作。具体表现：fopen64/unlink等函数直接使用REQUEST_URI派生的路径。触发条件：通过HTTP请求控制文件路径参数。安全影响：实现任意文件读/写/删除。约束条件：依赖路径遍历漏洞突破目录限制，两者结合形成完整攻击链。
- **关键词:** fopen64, unlink, fcn.000266d8, file_path, fileaccess.cgi
- **备注:** 与路径遍历漏洞（path_traversal-http_request_uri_construct）形成叠加风险：路径遍历提供任意路径构造能力，本漏洞执行最终危险操作

---
### path_traversal-httpd-REQUEST_URI_fcn.0000adbc

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `fcn.0000adbc:0x1e4`
- **类型:** network_input
- **综合优先级分数:** **8.5**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 路径遍历漏洞：在fcn.0000adbc函数中，用户控制的REQUEST_URI通过sprintf直接拼接进文件路径（格式字符串@0x5cb4），未过滤'../'序列。触发条件：构造恶意路径（如/../../etc/shadow）。利用方式：结合CGI的root权限实现任意文件读取。
- **代码片段:**
  ```
  sym.imp.sprintf(puVar6 + 0 + -0x2af0, 0x5cb4, puVar6 + 0 + -0x106c);
  ```
- **关键词:** REQUEST_URI, sprintf, 0x5cb4, fcn.0000adbc

---

## 中优先级发现

### network_input-ACL-INET_validv4addr_validation

- **文件路径:** `htdocs/phplib/inet.php`
- **位置:** `fatlady/INBFILTER.php:44,50`
- **类型:** network_input
- **综合优先级分数:** **8.3**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 攻击路径1：用户通过ACL配置界面(startip/endip参数)提交恶意IP地址 → INBFILTER.php调用INET_validv4addr验证 → 验证逻辑仅检查数值范围（1-223）但未验证输入长度/格式 → 畸形输入可能导致ipv4networkid底层函数未定义行为。触发条件：访问ACL配置接口并提交特制IP地址。实际影响：结合ipv4networkid实现缺陷可造成服务崩溃或远程代码执行。
- **代码片段:**
  ```
  if(INET_validv4addr(query("startip")) != 1) return i18n("The start IP address is invalid");
  ```
- **关键词:** query, startip, endip, INET_validv4addr, ipv4networkid, /acl/inbfilter/entry
- **备注:** 关联现有发现：INET_validv4addr。需验证：1) ipv4networkid函数实现 2) HTTP.WAN-1.php中的高危调用点

---
### network_input-webaccess_login-credential_hash

- **文件路径:** `htdocs/web/webaccess/index.php`
- **位置:** `htdocs/web/webaccess/index.php`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 静态登录页面将用户凭证(user_name/user_pwd)经HMAC-MD5哈希后通过XMLRequest发送至/auth.cgi。未发现直接命令执行或文件操作，但存在两处关键风险传导路径：1) 用户输入未在前端过滤即哈希传输，依赖后端auth.cgi实现完整验证 2) redirect_category_view.php跳转参数未在页面内验证。触发条件为攻击者拦截/修改哈希前明文或构造恶意跳转URL。
- **关键词:** auth.cgi, user_name, user_pwd, XMLRequest, exec_auth_cgi, redirect_category_view.php, send_request
- **备注:** 需立即分析/webaccess/cgi-bin/auth.cgi：1) 检查哈希解密后是否进行边界校验 2) 追踪SQL查询构造过程 3) 验证category_view.php跳转参数处理。攻击链可能为：未过滤输入→auth.cgi认证绕过→跳转漏洞实现重定向攻击。

---
### network_input-explorer-ajax_mkdir_input

- **文件路径:** `htdocs/web/portal/explorer.php`
- **位置:** `explorer.php: JavaScript函数CreateDir()`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 用户输入点存在于'new_dir_input'字段，通过CreateDir()函数流向Ajax请求参数(action=mkdir&where=)。触发条件：攻击者绕过客户端验证直接构造恶意请求。约束条件：客户端仅检查非法字符(/\:*?"<>|)和首字符空格，无长度限制或服务器端验证。安全影响：可能通过路径遍历实现任意目录创建，若后端处理不当可导致文件系统破坏或RCE前置条件。
- **代码片段:**
  ```
  str+="action=mkdir&path="+encodeURIComponent(path)+"&where="+encodeURIComponent(newDirectoryName);
  ```
- **关键词:** new_dir_input, CreateDir, action=mkdir, where=[用户输入], encodeURIComponent
- **备注:** 客户端验证可被Burp Suite等工具绕过；必须关联分析htdocs/web/portal/__ajax_explorer.sgi对'where'参数的处理

---
### file_write-DUMPLOG_unvalidated_file_write

- **文件路径:** `htdocs/phplib/dumplog.php`
- **位置:** `htdocs/phplib/dumplog.php: DUMPLOG_all_to_file & DUMPLOG_append_to_file`
- **类型:** file_write
- **综合优先级分数:** **7.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 4.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 高危未验证文件写入漏洞：DUMPLOG_*函数直接使用$file参数进行fwrite操作，未实施路径遍历防御（如过滤'../'）。攻击者若控制$file参数可实现：1. 覆盖系统文件（如/etc/passwd）2. 写入webshell。触发条件：存在调用链且$file来自外部输入（如HTTP参数）。实际影响取决于：1. Web服务权限 2. 是否存在暴露的调用接口。
- **代码片段:**
  ```
  fwrite("a", $file, "[Time]".$time);
  ```
- **关键词:** DUMPLOG_append_to_file, DUMPLOG_all_to_file, $file, fwrite
- **备注:** 关键缺口：未发现调用点。后续必须：1. 全局搜索调用DUMPLOG_all_to_file的PHP文件（重点/www目录）2. 验证$file是否源自$_GET/$_POST 3. 检查固件权限模型（Web服务是否root）

---
### network_input-explorer-client_validation_flaws

- **文件路径:** `htdocs/web/portal/explorer.php`
- **位置:** `explorer.php: JavaScript函数CreateDir()`
- **类型:** network_input
- **综合优先级分数:** **7.6**
- **风险等级:** 6.5
- **置信度:** 8.5
- **触发可能性:** 9.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 客户端验证存在三处缺陷：1) 正则表达式/[\\/:*?"<>|]/无法过滤Unicode或URL编码字符；2) 首字符空格检查可通过%20绕过；3) 无路径规范化或../检测。触发条件：直接发送恶意Ajax请求。安全影响：可能实现目录遍历攻击（如where=../../../etc）
- **代码片段:**
  ```
  var re=/[\\/:*?"<>|]/;
  if(re.exec(newDirectoryName)) { alert(...); }
  ```
- **关键词:** new_dir_input, re=/[\\/:*?"<>|]/, newDirectoryName.indexOf(" ")==0
- **备注:** 验证缺陷可被利用进行路径遍历；需结合后端文件htdocs/web/portal/__ajax_explorer.sgi分析完整攻击链

---
### network_input-IP_Validation-INET_validv4host_buffer

- **文件路径:** `htdocs/phplib/inet.php`
- **位置:** `inet.php:34`
- **类型:** network_input
- **综合优先级分数:** **7.55**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 攻击路径2：INET_validv4host函数接收$ipaddr参数时未进行长度检查（最大长度约束缺失）→ 直接传递给ipv4hostid函数 → 超长IP地址字符串可能触发缓冲区溢出。触发条件：上游调用者（如WiFi配置接口）未过滤用户输入长度。潜在影响：远程代码执行或服务拒绝，成功概率取决于ipv4hostid的缓冲区操作实现。
- **代码片段:**
  ```
  function INET_validv4host($ipaddr, $mask)
  {
      $hostid = ipv4hostid($ipaddr, $mask);
      ...
  ```
- **关键词:** INET_validv4host, $ipaddr, ipv4hostid, ipv4maxhost
- **备注:** 关键限制：无法访问fatlady目录验证调用点

---
### access_control-upnp-DeletePortMapping-permission_bypass

- **文件路径:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.DeletePortMapping.php`
- **位置:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.DeletePortMapping.php:0 (行号未知)`
- **类型:** network_input
- **综合优先级分数:** **7.5**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 权限控制缺失：脚本仅通过`query('/runtime/device/layout')!='router'`检查设备角色，未验证调用者身份。攻击者可在局域网内发送伪造UPnP请求删除任意端口映射，导致：1)拒绝服务(删除合法映射) 2)清除攻击痕迹 3)破坏防火墙规则。触发条件：设备处于router模式且UPnP服务开启。
- **关键词:** /runtime/device/layout, router, errorCode, ACTION_NODEBASE, DeletePortMapping, XNODE_del_entry, upnpigd/portmapping
- **备注:** 漏洞独立存在，但可与命令注入链（knowledge_base_id:command_injection-upnp-DeletePortMapping）组合使用：攻击者先删除日志映射掩盖痕迹，再触发命令注入攻击。

---
### input_validation-upnp-AddPortMapping_port_range

- **文件路径:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **位置:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **类型:** network_input
- **综合优先级分数:** **7.3**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 端口范围验证缺失：NewExternalPort和NewInternalPort参数仅通过isdigit()验证数字格式，未进行有效端口范围检查(1-65535)。攻击者可提交0或大于65535的端口值，导致iptables命令执行失败或创建异常DNAT规则。触发条件：通过UPnP协议发送包含无效端口的AddPortMapping请求。
- **关键词:** NewExternalPort, NewInternalPort, isdigit, iptables, DNAT.UPNP, SHELL_FILE
- **备注:** 需验证SHELL_FILE执行机制对异常端口的处理方式。关联知识库：已有3处发现提及SHELL_FILE执行机制（见notes字段）

---
### network_input-web-tools_system_bypass

- **文件路径:** `htdocs/webinc/body/tools_system.php`
- **位置:** `htdocs/webinc/body/tools_system.php:0`
- **类型:** network_input
- **综合优先级分数:** **7.25**
- **风险等级:** 6.0
- **置信度:** 9.5
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 前端界面组件，所有表单提交均指向外部CGI处理器(dlcfg.cgi/seama.cgi)。权限控制依赖客户端JavaScript(PAGE.OnClickDownload/OnClickUpload)，存在被绕过风险。未经验证的输入可能通过绕过JS验证直接提交到CGI处理器。
- **关键词:** dlcfg.cgi, seama.cgi, tools_fw_rlt.php, REPORT_METHOD, sealpac, PAGE.OnClickDownload, PAGE.OnClickUpload
- **备注:** 关键后续分析方向：1) seama.cgi的'sealpac'参数(文件上传入口) 2) dlcfg.cgi配置导出功能 3) tools_fw_rlt.php的'ACTION=langclear'隐藏端点

---
### potential_command_injection-upnp-AddPortMapping_NewInternalClient

- **文件路径:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **位置:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **类型:** network_input
- **综合优先级分数:** **7.2**
- **风险等级:** 8.5
- **置信度:** 6.5
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 潜在命令注入风险：NewInternalClient参数经INET_validv4addr验证后直接拼接到iptables命令（--to-destination参数）。若INET_validv4addr验证不严格（如未过滤特殊字符），攻击者可能注入恶意命令。触发条件：提交包含命令分隔符的伪造IP地址且验证函数存在缺陷。
- **关键词:** NewInternalClient, INET_validv4addr, iptables, --to-destination, SHELL_FILE
- **备注:** 关键依赖项INET_validv4addr需单独分析（文件路径：/htdocs/phplib/inet.php）。知识库中已存在关联分析：该函数缺陷可能导致command_injection-upnp-DeletePortMapping漏洞（见notes字段）

---
### boundary_check_bypass-httpd-REQUEST_URI_fcn.0000adbc

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `fcn.0000adbc:0x0000b04c`
- **类型:** network_input
- **综合优先级分数:** **7.1**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 边界检查绕过风险：fcn.0000adbc中对REQUEST_URI的strlen检查（≤0xfc2）存在条件分支漏洞。当fcn.0000a1c0返回非0时直接操作污染数据，跳过长度验证。触发条件：特殊请求使fcn.0000a1c0返回非零值。利用方式：绕过4034字节限制，使超长污染数据进入处理链。
- **关键词:** REQUEST_URI, fcn.0000a1c0, fcn.0000adbc, 0xfc2

---

## 低优先级发现

### potential_command_injection-upnp-AddPortMapping

- **文件路径:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **位置:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **类型:** network_input
- **综合优先级分数:** **6.85**
- **风险等级:** 7.5
- **置信度:** 6.0
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 潜在命令注入风险(需进一步验证)：$NewInternalClient参数经INET_validv4addr验证后直接拼接至iptables命令，若IP验证函数未过滤特殊字符(如`;`、`|`)，可能通过构造`192.168.1.1';reboot;'`类输入注入命令。触发条件：1) 设备为router模式 2) INET_validv4addr验证通过 3) SHELL_FILE机制执行写入的命令。边界检查：仅依赖INET_validv4addr的过滤效果。
- **代码片段:**
  ```
  $cmd = 'iptables -t nat -A DNAT.UPNP'.$proto.' --dport '.$NewExternalPort.' -j DNAT --to-destination "'.$NewInternalClient.'":'.$NewInternalPort;
  ```
- **关键词:** $NewInternalClient, INET_validv4addr, iptables, --to-destination
- **备注:** 未验证依赖项：1) /htdocs/phplib/inet.php的实现。关联利用链：污染值可被command_injection-upnp-DeletePortMapping漏洞触发执行（参见该发现）。

---
