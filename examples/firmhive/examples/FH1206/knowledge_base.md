# FH1206 (10 个发现)

---

### Vulnerability-soap_control

- **文件/目录路径：** `usr/lib/libupnp.so`
- **位置：** `libupnp.so:0x00006a38 sym.soap_control`
- **风险评分：** 9.5
- **置信度：** 9.0
- **描述：** 该漏洞允许攻击者通过 SOAP 请求实现任意代码执行。具体地，在 sym.soap_process 中，用户输入的 SOAP 请求数据被传递到 sym.soap_control 函数。在地址 0x00006a38，一个函数指针从用户控制的参数（param_3）的偏移 0x14 处加载并通过 `jalr t9` 指令调用。由于缺乏输入验证，攻击者可操纵 SOAP 请求中的输入字符串，使函数指针指向恶意地址，从而执行任意代码。触发条件为发送特制的 SOAP 请求（例如，通过 HTTP 接口），攻击者需拥有有效登录凭据和网络访问权限。潜在攻击包括远程系统完全妥协。约束条件包括攻击者需能发送 SOAP 请求到 UPnP 服务，且函数指针调用未受边界检查。
- **代码片段：**
  ```
  iVar1 = (**(param_3 + 0x14))(param_1,param_2,*(param_1 + 0x38d0),*(param_1 + 0x38d8)); // param_3 is user-controlled, leading to arbitrary function call
  ```
- **关键词：** SOAPACTION HTTP header, urn:schemas-upnp-org:control-1-0#QueryStateVariable, sym.soap_process, sym.soap_control
- **备注：** 此漏洞在 UPnP 库中常见，可能影响多个设备。建议进一步验证在实际环境中的可利用性，并检查其他 SOAP 相关函数（如 action_process）以确认无其他攻击向量。关联文件可能包括网络服务组件，但当前分析限于 libupnp.so。

---
### PermissionMisconfig-ShadowFile

- **文件/目录路径：** `var/etc/shadow`
- **位置：** `shadow:1`
- **风险评分：** 9.0
- **置信度：** 10.0
- **描述：** 在 'shadow' 文件中发现严重权限配置错误，文件权限为 -rwxrwxrwx，允许所有用户（包括非 root 用户）读、写和执行。这导致两个实际可利用的攻击链：1) 非 root 用户可以直接修改文件内容，例如修改 root 密码哈希或添加新用户账户，从而获得 root 权限（通过 su 或登录）；2) 非 root 用户可以读取密码哈希（使用 MD5 算法，$1$ 前缀），进行离线破解（如果密码强度弱）。触发条件简单：攻击者只需拥有有效登录凭据（非 root 用户）并访问文件。边界检查缺失：文件无任何权限限制，允许任意修改。利用方式包括使用文本编辑器或命令直接编辑文件，或使用工具如 john the ripper 破解哈希。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **关键词：** shadow
- **备注：** 此发现基于直接证据：文件权限和内容。建议立即修复文件权限（例如，设置为 640，仅 root 可写）。后续分析应验证系统是否依赖此文件进行认证，并检查其他敏感文件的权限。

---
### command-injection-formexeCommand

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd: sym.formexeCommand (0x0046eefc)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the 'formexeCommand' function, which handles HTTP form submissions. The function retrieves user input from the 'cmdinput' parameter using 'websGetVar' and directly incorporates it into system commands executed via 'doSystemCmd' without any input validation or sanitization. This allows an attacker to inject arbitrary commands by crafting malicious input in the 'cmdinput' parameter. The vulnerability is triggered when a POST request is sent to the associated form handler, and the injected commands are executed with the privileges of the HTTP server process (likely root in embedded systems). Attackers can achieve remote code execution, leading to full compromise of the device.
- **代码片段：**
  ```
  // Vulnerable code in formexeCommand
  // Retrieving user input from 'cmdinput' parameter
  uVar1 = (**(iVar4 + -0x78cc))(*&uStackX_0,*(iVar4 + -0x7fd8) + -0x3bc,*(iVar4 + -0x7fd8) + -0x3b0);
  (**(iVar4 + -0x71b0))(auStack_2308,uVar1);
  // ...
  // Constructing command with user input without sanitization
  (**(iVar4 + -0x7860))(*(iVar4 + -0x7fd8) + -0x388,auStack_2308);
  // Executing command via doSystemCmd
  (**(iVar4 + -0x7508))(auStack_2308);
  ```
- **关键词：** cmdinput (HTTP parameter), formexeCommand (function symbol), websGetVar (function call), doSystemCmd (function call)
- **备注：** The function 'formexeCommand' is registered in 'formDefineTendDa' during HTTP server initialization, making it accessible via HTTP requests. No explicit authentication checks are visible in the function, but it may rely on web application-level authentication. Given that the attacker has valid login credentials, this vulnerability is directly exploitable. Further analysis should verify the execution context (e.g., if httpd runs as root) and check for other similar vulnerabilities in form handlers.

---
### Command-Injection-igd_osl_nat_config

- **文件/目录路径：** `usr/sbin/igd`
- **位置：** `igd:0x00402084 sym.igd_osl_nat_config`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** A command injection vulnerability exists in the UPnP IGD service's port mapping functionality. The vulnerability allows an attacker to execute arbitrary commands with the privileges of the 'igd' process (typically root) by crafting a malicious UPnP AddPortMapping request. Specifically, the `NewInternalClient` parameter is user-controlled and is embedded into a command string using `sprintf` without sanitization. The constructed command is then executed via `_eval`, which interprets shell metacharacters. Trigger conditions include sending a UPnP request with `NewInternalClient` containing commands (e.g., '192.168.1.1; id'). The attack requires the attacker to be on the local network with access to the UPnP service, which is often enabled by default. Potential exploits include full system compromise, data theft, or device takeover.
- **代码片段：**
  ```
  // From igd_osl_nat_config decompilation
  // Command string construction using sprintf
  (**(iVar13 + -0x7f78))(pcVar6, *(iVar13 + -0x7fe0) + 0x591c, param_1, *(param_2 + 0x10), *(param_2 + 0x1a), *(param_2 + 0x2c));
  // Later, strcpy is used to append user-controlled data
  (*pcVar12)(pcVar6, param_2); // param_2 contains NewInternalClient
  // Command execution via _eval
  (**(iVar13 + -0x7f20))(apcStack_19c, *(iVar13 + -0x7fe0) + 0x5968, 0, 0); // _eval call
  ```
- **关键词：** NewInternalClient (UPnP parameter), igd_osl_nat_config function, _eval function
- **备注：** The vulnerability is highly exploitable due to the lack of input sanitization and the use of `_eval` for command execution. The attack chain involves UPnP request processing, making it accessible to authenticated network users. Further verification could involve dynamic testing to confirm command execution. Additional vulnerabilities such as buffer overflows may exist but require more analysis.

---
### PrivEsc-File-passwd_private

- **文件/目录路径：** `var/etc/passwd_private`
- **位置：** `passwd_private:1 (文件路径，无具体行号)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 文件 'passwd_private' 包含 root 用户的 MD5 密码哈希，且权限设置为全局可读、可写、可执行（权限 777）。这允许任何非 root 用户（拥有有效登录凭据）直接读取该文件。攻击者可以获取哈希值并使用离线破解工具（如 John the Ripper 或 hashcat）进行暴力破解或字典攻击。如果密码强度较弱，攻击者可能成功破解哈希，从而获得 root 权限，实现权限提升。触发条件简单：攻击者只需执行读取命令（如 'cat passwd_private'）。边界检查缺失：文件没有适当的访问控制，允许低权限用户访问高敏感数据。潜在攻击方式包括直接读取哈希并破解，利用链完整且可行。
- **代码片段：**
  ```
  root:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:root:/:/bin/sh
  ```
- **关键词：** passwd_private
- **备注：** 此发现基于直接证据：文件内容包含 root 哈希，且权限设置不当。攻击链完整，但成功利用取决于密码强度和破解工具的效率。建议进一步验证哈希的易破解性（例如，使用常见密码字典测试）。关联文件可能包括其他系统密码文件，但本分析仅聚焦于 'passwd_private'。后续分析方向：检查系统中其他敏感文件的权限，或评估密码策略是否强制使用强密码。

---
### Config-AnonymousFTP

- **文件/目录路径：** `var/etc/stupid-ftpd/stupid-ftpd.conf`
- **位置：** `stupid-ftpd.conf:~line 75 (user definition line)`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** 配置文件定义了匿名用户（anonymous） with full permissions (A)，允许未经认证的用户执行任意文件操作（下载、上传、覆盖、删除、创建目录等）。攻击者可以连接到 FTP 服务（端口 2121）并使用匿名登录（无需密码）来利用此权限。如果服务器不以 root 权限运行（如配置文件注释所述），changeroottype=real 可能失败，导致没有有效的文件系统隔离，使攻击者能访问 serverroot（/usr/home/cinek/tmp3/aaa）之外的系统文件，前提是服务器进程有相应权限。这构成了一个完整的攻击链：输入点（FTP 网络接口）→ 数据流（FTP 命令处理）→ 危险操作（任意文件访问和修改）。
- **代码片段：**
  ```
  user=anonymous	*	 /	  5   A
  ```
- **关键词：** stupid-ftpd.conf, FTP port 2121, serverroot=/usr/home/cinek/tmp3/aaa, user=anonymous
- **备注：** 基于配置文件内容分析，攻击链完整且实际可利用。但需要进一步验证服务器二进制代码以确认 changeroottype 行为和服务器的实际运行权限（例如，是否以 root 运行）。建议分析 stupid-ftpd 二进制文件来验证数据流和权限检查。关联文件可能包括服务器可执行文件和相关日志。

---
### 无标题的发现

- **文件/目录路径：** `var/etc/shadow_private`
- **位置：** `etc/shadow_private`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 文件 'shadow_private' 权限设置为 777（所有用户可读、写、执行），导致 root 用户密码哈希泄露。攻击者作为非root用户但拥有登录凭据，可以直接读取文件内容，获取 root 的 MD5 密码哈希（$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1）。攻击链包括：1) 攻击者登录系统；2) 读取 '/etc/shadow_private' 文件；3) 使用破解工具（如 John the Ripper）离线破解哈希；4) 如果破解成功，获得 root 密码并提升权限。MD5 哈希算法较弱，破解概率较高，尤其在密码简单的情况下。触发条件仅为攻击者具有文件读取权限，重现步骤简单（执行 'cat /etc/shadow_private'）。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **关键词：** etc/shadow_private
- **备注：** 此文件可能是一个自定义影子文件，需验证是否被系统用于认证。建议进一步分析系统认证机制和相关组件（如 PAM 配置），以确认此文件的用途和影响范围。同时，检查其他文件是否存在类似权限问题。

---
### XSS-nat_virtualser_rule_entry

- **文件/目录路径：** `webroot/js/privatejs/nat_virtualser.js`
- **位置：** `nat_virtualser.js:rule_entry 函数（具体行号未知，但位于函数内构建 HTML 的部分）`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 存储型跨站脚本（XSS）漏洞存在于 NAT 虚拟服务器配置页面的内部 IP 地址字段渲染过程中。攻击者可以提交恶意规则，其中内部 IP 地址包含 XSS 负载（例如：' onmouseover='alert(1)）。当页面加载时，由于输入值未正确转义，恶意脚本被执行。触发条件：攻击者提交恶意规则后，任何用户（包括管理员）查看 NAT 配置页面。利用方式：攻击者可以窃取会话 cookie、执行任意 JavaScript 代码，或进行权限提升。漏洞源于 `rule_entry` 函数中直接拼接用户输入到 HTML 属性而未转义。
- **代码片段：**
  ```
  text += '<input type="text" class="input-medium" id="pip' + idx + '" name="pip' + idx + '" size="15" maxlength="15" value=' + row[3] + ' validchars="0123456789." onkeypress="return allowChars(this, event)"/>';
  ```
- **关键词：** reqStr, pipX (内部 IP 地址字段), document.frmSetup
- **备注：** 漏洞依赖于后端存储和返回未转义的数据，但前端渲染代码明确显示未转义。建议检查后端处理以确保输入验证和输出编码。关联函数：`showlist` 和 `preSubmit`。需要进一步验证后端是否对存储的数据进行清理。

---
### 命令注入-iprule.sh

- **文件/目录路径：** `bin/iprule.sh`
- **位置：** `iprule.sh:15 (估计行号，基于代码结构)`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 脚本在读取输入文件时使用未引用的变量 $FILE，允许命令注入。具体表现：当脚本被执行时，如果 FILE 参数包含 shell 元字符（如 ;、|、&），则 `cat $FILE` 会被 shell 解释并执行任意命令。触发条件：攻击者直接执行脚本并传递恶意 FILE 参数（例如 './iprule.sh add ";malicious_command" table prio'）。约束条件：脚本仅检查参数数量为 4，但对参数内容无验证；文件存在检查有语法错误（`[ -z -rts ]`），可能不生效。潜在攻击：攻击者可以注入命令执行任意操作，如果脚本以 root 权限运行，可能导致权限提升。利用方式简单直接，无需复杂步骤。
- **代码片段：**
  ```
  rts=\`cat $FILE\`
  ```
- **关键词：** FILE 参数
- **备注：** 漏洞存在性证据充分，但可利用性取决于脚本运行权限。建议进一步分析脚本的调用上下文（例如是否由 root 进程调用）以确认权限提升可能性。此外，检查其他参数（如 TABLE 和 PRIO）在 ip rule 命令中是否也存在注入风险，但当前焦点在 FILE 参数。

---
### XSS-wirelessScan

- **文件/目录路径：** `webroot/js/privatejs/wireless_extra.js`
- **位置：** `wireless_extra.js:wirelessScan 函数和 fillAcc 函数（具体行号不可用，但代码位于处理扫描结果显示的部分）`
- **风险评分：** 6.5
- **置信度：** 8.0
- **描述：** 在 'wireless_extra.js' 文件的无线扫描功能中发现存储型XSS漏洞。攻击者可以通过设置恶意AP的SSID字段注入JavaScript代码。当已登录用户执行无线扫描（通过 '/goform/ApclientScan' 接口）并查看结果时，恶意SSID通过 innerHTML 插入到页面中，导致脚本执行。触发条件：用户访问无线设置页面并点击扫描按钮；攻击者需能控制AP的SSID（如通过物理接近或网络渗透）。潜在利用方式：窃取用户会话Cookie、篡改无线设置、重定向用户到恶意页面。漏洞位于客户端显示逻辑，缺少对SSID内容的HTML转义。
- **代码片段：**
  ```
  // 在 wirelessScan 函数中：
  nc.innerHTML = str[0]; // SSID 直接插入 HTML
  nc.innerHTML = str[1]; // MAC 地址
  // 在 fillAcc 函数中：
  nc.innerHTML = str[0]; // SSID 用于表格显示
  nc.title = decodeSSID(str[0]); // 可能未转义
  ```
- **关键词：** /goform/ApclientScan, remoteSsid, wlScanTab
- **备注：** 漏洞利用需要攻击者能控制无线环境（如设置恶意AP）。decodeSSID 函数未在文件中定义，假设它可能未充分转义HTML。建议后续分析后端 '/goform/ApclientScan' 接口如何处理SSID输入。此漏洞可用于提升权限或持久化攻击，但受网络环境限制。

---
