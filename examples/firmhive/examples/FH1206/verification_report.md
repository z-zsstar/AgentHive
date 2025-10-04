# FH1206 - 验证报告 (10 个发现)

---

## 原始信息

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd: sym.formexeCommand (0x0046eefc)`
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
- **备注：** The function 'formexeCommand' is registered in 'formDefineTendDa' during HTTP server initialization, making it accessible via HTTP requests. No explicit authentication checks are visible in the function, but it may rely on web application-level authentication. Given that the attacker has valid login credentials, this vulnerability is directly exploitable. Further analysis should verify the execution context (e.g., if httpd runs as root) and check for other similar vulnerabilities in form handlers.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。在 formexeCommand 函数中，用户输入从 'cmdinput' 参数通过 websGetVar 获取，并直接用于构建系统命令（如使用格式字符串 '%s > /tmp/cmdTmp.txt'），通过 doSystemCmd 执行，没有任何输入验证或 sanitization。攻击者模型假设为经过身份验证的远程用户（具有 Web 应用访问权限），因为函数可能依赖上层认证。漏洞可利用，因为攻击者可控制 'cmdinput' 参数，注入恶意命令（如分号或管道符），并在 HTTP 服务器进程上下文中执行（在嵌入式系统中通常以 root 权限运行），导致设备完全妥协。PoC 示例：向 formexeCommand 对应的 HTTP 端点发送 POST 请求，设置 'cmdinput' 参数为 'ls; whoami'，这将执行 'ls; whoami > /tmp/cmdTmp.txt'，注入的 'whoami' 命令会被执行。

## 验证指标

- **验证时长：** 97.36 秒
- **Token 使用量：** 122210

---

## 原始信息

- **文件/目录路径：** `bin/iprule.sh`
- **位置：** `iprule.sh:15 (估计行号，基于代码结构)`
- **描述：** 脚本在读取输入文件时使用未引用的变量 $FILE，允许命令注入。具体表现：当脚本被执行时，如果 FILE 参数包含 shell 元字符（如 ;、|、&），则 `cat $FILE` 会被 shell 解释并执行任意命令。触发条件：攻击者直接执行脚本并传递恶意 FILE 参数（例如 './iprule.sh add ";malicious_command" table prio'）。约束条件：脚本仅检查参数数量为 4，但对参数内容无验证；文件存在检查有语法错误（`[ -z -rts ]`），可能不生效。潜在攻击：攻击者可以注入命令执行任意操作，如果脚本以 root 权限运行，可能导致权限提升。利用方式简单直接，无需复杂步骤。
- **代码片段：**
  ```
  rts=\`cat $FILE\`
  ```
- **备注：** 漏洞存在性证据充分，但可利用性取决于脚本运行权限。建议进一步分析脚本的调用上下文（例如是否由 root 进程调用）以确认权限提升可能性。此外，检查其他参数（如 TABLE 和 PRIO）在 ip rule 命令中是否也存在注入风险，但当前焦点在 FILE 参数。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了漏洞。在 bin/iprule.sh 第15行，'rts=`cat $FILE`' 中 $FILE 变量未加引号，允许命令注入。攻击者模型：本地用户或远程攻击者（通过 web 接口等）能执行脚本并控制 FILE 参数。脚本有执行权限（-rwxrwxrwx），且参数检查仅验证数量为4，对内容无过滤。文件存在检查 'if [ -z -rts ]' 语法错误，无效。完整攻击链：攻击者提供恶意 FILE 参数（如 shell 元字符），脚本执行时注入命令。PoC：执行 './iprule.sh add "; malicious_command" table prio'，其中 'malicious_command' 可为 'id > /tmp/exploit' 等任意命令。如果脚本以 root 权限运行，注入命令以 root 执行，导致权限提升。漏洞可利用性高，风险为 High。

## 验证指标

- **验证时长：** 118.42 秒
- **Token 使用量：** 134812

---

## 原始信息

- **文件/目录路径：** `var/etc/passwd_private`
- **位置：** `passwd_private:1 (文件路径，无具体行号)`
- **描述：** 文件 'passwd_private' 包含 root 用户的 MD5 密码哈希，且权限设置为全局可读、可写、可执行（权限 777）。这允许任何非 root 用户（拥有有效登录凭据）直接读取该文件。攻击者可以获取哈希值并使用离线破解工具（如 John the Ripper 或 hashcat）进行暴力破解或字典攻击。如果密码强度较弱，攻击者可能成功破解哈希，从而获得 root 权限，实现权限提升。触发条件简单：攻击者只需执行读取命令（如 'cat passwd_private'）。边界检查缺失：文件没有适当的访问控制，允许低权限用户访问高敏感数据。潜在攻击方式包括直接读取哈希并破解，利用链完整且可行。
- **代码片段：**
  ```
  root:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:root:/:/bin/sh
  ```
- **备注：** 此发现基于直接证据：文件内容包含 root 哈希，且权限设置不当。攻击链完整，但成功利用取决于密码强度和破解工具的效率。建议进一步验证哈希的易破解性（例如，使用常见密码字典测试）。关联文件可能包括其他系统密码文件，但本分析仅聚焦于 'passwd_private'。后续分析方向：检查系统中其他敏感文件的权限，或评估密码策略是否强制使用强密码。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述完全准确：文件 'var/etc/passwd_private' 存在，权限设置为 777（全局可读、可写、可执行），内容包含 root 用户的 MD5 密码哈希（'$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1'）。攻击者模型为已通过身份验证的本地用户（拥有有效登录凭据），他们可以轻松读取文件（例如，使用 'cat /var/etc/passwd_private'）。完整攻击链：攻击者读取哈希后，可使用离线破解工具（如 John the Ripper 或 hashcat）进行暴力破解或字典攻击。如果密码强度弱（例如，常见密码），攻击者可能成功破解哈希，获得 root 权限，实现权限提升。漏洞实际可利用，因为输入可控（文件可读）、路径可达（权限允许任何用户访问）、实际影响严重（root 权限丢失）。可重现的 PoC 步骤：1. 攻击者以非 root 用户身份登录系统；2. 执行命令 'cat /var/etc/passwd_private' 获取 root 密码哈希；3. 使用破解工具（如运行 'john passwd_private' 或 'hashcat -m 500 passwd_private wordlist.txt'）尝试破解；4. 如果破解成功，使用获得的密码提升权限（例如，通过 'su root'）。证据支持所有声明，无需进一步分析。

## 验证指标

- **验证时长：** 121.58 秒
- **Token 使用量：** 140121

---

## 原始信息

- **文件/目录路径：** `var/etc/shadow`
- **位置：** `shadow:1`
- **描述：** 在 'shadow' 文件中发现严重权限配置错误，文件权限为 -rwxrwxrwx，允许所有用户（包括非 root 用户）读、写和执行。这导致两个实际可利用的攻击链：1) 非 root 用户可以直接修改文件内容，例如修改 root 密码哈希或添加新用户账户，从而获得 root 权限（通过 su 或登录）；2) 非 root 用户可以读取密码哈希（使用 MD5 算法，$1$ 前缀），进行离线破解（如果密码强度弱）。触发条件简单：攻击者只需拥有有效登录凭据（非 root 用户）并访问文件。边界检查缺失：文件无任何权限限制，允许任意修改。利用方式包括使用文本编辑器或命令直接编辑文件，或使用工具如 john the ripper 破解哈希。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **备注：** 此发现基于直接证据：文件权限和内容。建议立即修复文件权限（例如，设置为 640，仅 root 可写）。后续分析应验证系统是否依赖此文件进行认证，并检查其他敏感文件的权限。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确基于证据：文件权限为 -rwxrwxrwx，允许所有用户读、写和执行；文件内容包含 root 用户的 MD5 密码哈希（$1$ 前缀）。攻击者模型为已通过身份验证的非 root 用户（拥有有效登录凭据）。漏洞实际可利用：攻击者可以读取哈希进行离线破解（如果密码弱），或直接修改文件以更改 root 密码或添加用户，从而获得 root 权限。完整攻击链：1) 攻击者以非 root 用户登录系统；2) 读取文件：使用命令如 'cat /var/etc/shadow' 获取哈希；3) 修改文件：使用文本编辑器（如 vi）或命令（如 'echo "root::0:0:root:/root:/bin/bash" >> /var/etc/shadow' 设置空密码）；4) 利用修改后的文件执行 'su root' 或登录获得 root 权限。证据支持所有声明，无需额外分析。

## 验证指标

- **验证时长：** 137.24 秒
- **Token 使用量：** 145257

---

## 原始信息

- **文件/目录路径：** `webroot/js/privatejs/wireless_extra.js`
- **位置：** `wireless_extra.js:wirelessScan 函数和 fillAcc 函数（具体行号不可用，但代码位于处理扫描结果显示的部分）`
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
- **备注：** 漏洞利用需要攻击者能控制无线环境（如设置恶意AP）。decodeSSID 函数未在文件中定义，假设它可能未充分转义HTML。建议后续分析后端 '/goform/ApclientScan' 接口如何处理SSID输入。此漏洞可用于提升权限或持久化攻击，但受网络环境限制。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 在 'wireless_extra.js' 文件中，wirelessScan 函数和 fillAcc 函数确实存在存储型 XSS 漏洞。证据如下：
- 在 wirelessScan 函数中，SSID（str[0]）直接通过 innerHTML 插入到表格单元格中（例如：nc.innerHTML = str[0];），没有进行 HTML 转义。
- 在 fillAcc 函数中，SSID 同样通过 innerHTML 插入（nc.innerHTML = str[0];），且 title 属性使用 decodeSSID(str[0])，但 decodeSSID 函数未在文件中定义，可能未充分转义。
- 输入可控：攻击者可以通过设置恶意 AP 的 SSID 字段控制输入（例如，SSID 包含恶意 JavaScript 代码）。
- 路径可达：当已登录用户访问无线设置页面并点击扫描按钮时，会触发 '/goform/ApclientScan' 接口调用，扫描结果显示在页面中，漏洞路径可达。
- 实际影响：恶意脚本执行可导致会话 Cookie 窃取、设置篡改、重定向到恶意页面等安全损害。
攻击者模型：未经身份验证的远程攻击者，通过物理接近或网络渗透设置恶意 AP。
PoC 步骤：
1. 攻击者设置恶意 AP，SSID 为 `<script>alert('XSS')</script>` 或更复杂的载荷如 `<img src=x onerror=alert(document.cookie)>`。
2. 用户登录路由器管理界面，进入无线设置页面，点击扫描按钮。
3. 扫描结果中包含恶意 SSID，通过 innerHTML 插入页面，脚本执行。
风险级别为 Medium，因为漏洞需要用户交互（点击扫描）和攻击者控制无线环境，但一旦利用，可能造成严重危害。

## 验证指标

- **验证时长：** 146.50 秒
- **Token 使用量：** 176353

---

## 原始信息

- **文件/目录路径：** `var/etc/stupid-ftpd/stupid-ftpd.conf`
- **位置：** `stupid-ftpd.conf:~line 75 (user definition line)`
- **描述：** 配置文件定义了匿名用户（anonymous） with full permissions (A)，允许未经认证的用户执行任意文件操作（下载、上传、覆盖、删除、创建目录等）。攻击者可以连接到 FTP 服务（端口 2121）并使用匿名登录（无需密码）来利用此权限。如果服务器不以 root 权限运行（如配置文件注释所述），changeroottype=real 可能失败，导致没有有效的文件系统隔离，使攻击者能访问 serverroot（/usr/home/cinek/tmp3/aaa）之外的系统文件，前提是服务器进程有相应权限。这构成了一个完整的攻击链：输入点（FTP 网络接口）→ 数据流（FTP 命令处理）→ 危险操作（任意文件访问和修改）。
- **代码片段：**
  ```
  user=anonymous	*	 /	  5   A
  ```
- **备注：** 基于配置文件内容分析，攻击链完整且实际可利用。但需要进一步验证服务器二进制代码以确认 changeroottype 行为和服务器的实际运行权限（例如，是否以 root 运行）。建议分析 stupid-ftpd 二进制文件来验证数据流和权限检查。关联文件可能包括服务器可执行文件和相关日志。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确基于配置文件证据。配置文件 'var/etc/stupid-ftpd/stupid-ftpd.conf' 第75行明确定义了匿名用户（user=anonymous）具有完全权限（A），允许下载、上传、覆盖、删除、创建目录等任意文件操作。服务器监听端口2121，匿名登录无需密码（密码为*）。攻击者模型是未经身份验证的远程攻击者，他们可以通过网络连接到FTP服务。完整攻击链验证：输入点（FTP网络接口端口2121）→ 数据流（匿名登录和处理FTP命令）→ 危险操作（任意文件访问和修改）。实际影响包括数据泄露、篡改或服务中断。概念验证（PoC）步骤：1. 使用FTP客户端（如命令行ftp或图形工具）连接至目标IP地址端口2121；2. 输入用户名 'anonymous'，密码任意（如空或任意字符串）；3. 登录后，可执行任意FTP命令，例如：- 列出文件（ls）、下载文件（get）、上传文件（put）、删除文件（delete）、创建目录（mkdir）等。此漏洞无需额外条件即可利用，但若服务器不以root权限运行（如配置文件注释所述），changeroottype=real可能失败，进一步扩大攻击面至serverroot（/usr/home/cinek/tmp3/aaa）之外的系统文件。

## 验证指标

- **验证时长：** 150.52 秒
- **Token 使用量：** 183291

---

## 原始信息

- **文件/目录路径：** `var/etc/shadow_private`
- **位置：** `etc/shadow_private`
- **描述：** 文件 'shadow_private' 权限设置为 777（所有用户可读、写、执行），导致 root 用户密码哈希泄露。攻击者作为非root用户但拥有登录凭据，可以直接读取文件内容，获取 root 的 MD5 密码哈希（$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1）。攻击链包括：1) 攻击者登录系统；2) 读取 '/etc/shadow_private' 文件；3) 使用破解工具（如 John the Ripper）离线破解哈希；4) 如果破解成功，获得 root 密码并提升权限。MD5 哈希算法较弱，破解概率较高，尤其在密码简单的情况下。触发条件仅为攻击者具有文件读取权限，重现步骤简单（执行 'cat /etc/shadow_private'）。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **备注：** 此文件可能是一个自定义影子文件，需验证是否被系统用于认证。建议进一步分析系统认证机制和相关组件（如 PAM 配置），以确认此文件的用途和影响范围。同时，检查其他文件是否存在类似权限问题。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了漏洞。证据显示文件 'var/etc/shadow_private' 权限为 777，所有用户可读，且内容包含 root 用户的 MD5 密码哈希 '$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1'。基于攻击者模型（已通过身份验证的本地非 root 用户），攻击链完整：1) 攻击者登录系统；2) 执行 'cat /var/etc/shadow_private' 读取文件；3) 提取哈希；4) 使用破解工具（如 John the Ripper）离线破解 MD5 哈希；5) 若破解成功，获得 root 密码并提升权限。MD5 算法弱，破解概率高，尤其密码简单时。重现 PoC：作为非 root 用户，执行 'cat /var/etc/shadow_private' 即可获取哈希，然后使用 'john --format=md5crypt hash.txt' 破解。此漏洞导致 root 凭证泄露，风险高。

## 验证指标

- **验证时长：** 156.15 秒
- **Token 使用量：** 188895

---

## 原始信息

- **文件/目录路径：** `usr/lib/libupnp.so`
- **位置：** `libupnp.so:0x00006a38 sym.soap_control`
- **描述：** 该漏洞允许攻击者通过 SOAP 请求实现任意代码执行。具体地，在 sym.soap_process 中，用户输入的 SOAP 请求数据被传递到 sym.soap_control 函数。在地址 0x00006a38，一个函数指针从用户控制的参数（param_3）的偏移 0x14 处加载并通过 `jalr t9` 指令调用。由于缺乏输入验证，攻击者可操纵 SOAP 请求中的输入字符串，使函数指针指向恶意地址，从而执行任意代码。触发条件为发送特制的 SOAP 请求（例如，通过 HTTP 接口），攻击者需拥有有效登录凭据和网络访问权限。潜在攻击包括远程系统完全妥协。约束条件包括攻击者需能发送 SOAP 请求到 UPnP 服务，且函数指针调用未受边界检查。
- **代码片段：**
  ```
  iVar1 = (**(param_3 + 0x14))(param_1,param_2,*(param_1 + 0x38d0),*(param_1 + 0x38d8)); // param_3 is user-controlled, leading to arbitrary function call
  ```
- **备注：** 此漏洞在 UPnP 库中常见，可能影响多个设备。建议进一步验证在实际环境中的可利用性，并检查其他 SOAP 相关函数（如 action_process）以确认无其他攻击向量。关联文件可能包括网络服务组件，但当前分析限于 libupnp.so。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The alert accurately describes the vulnerability. Analysis of libupnp.so confirms that in sym.soap_control at 0x00006a38, a function pointer is loaded from param_3 + 0x14 (user-controlled via SOAP requests) and called via jalr t9 without validation. The attack model assumes an authenticated remote attacker with valid credentials and network access to the UPnP SOAP interface. The path is reachable as sym.soap_control is called from sym.action_process during SOAP request handling. The impact is arbitrary code execution, as controlling the function pointer allows jumping to any address. For exploitation, an attacker can craft a SOAP request with a manipulated action structure where the field at offset 0x14 contains a malicious address (e.g., pointing to shellcode). PoC steps: 1) Send a POST request to the UPnP SOAP endpoint (e.g., /soap.cgi) with authentication; 2) Include a crafted XML SOAP body that sets the function pointer field to the target address; 3) Upon processing, the jalr t9 instruction executes code at that address, leading to full system compromise.

## 验证指标

- **验证时长：** 229.88 秒
- **Token 使用量：** 230893

---

## 原始信息

- **文件/目录路径：** `usr/sbin/igd`
- **位置：** `igd:0x00402084 sym.igd_osl_nat_config`
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
- **备注：** The vulnerability is highly exploitable due to the lack of input sanitization and the use of `_eval` for command execution. The attack chain involves UPnP request processing, making it accessible to authenticated network users. Further verification could involve dynamic testing to confirm command execution. Additional vulnerabilities such as buffer overflows may exist but require more analysis.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确。基于反编译代码分析，在函数 'sym.igd_osl_nat_config' 中，用户控制的 'NewInternalClient' 参数（通过 'param_2 + 0x1c' 访问）被直接嵌入到命令字符串 'igdnat -i %s -eport %d -iport %d -en %d' 中，没有输入清理。构造的命令通过 '_eval' 函数执行，允许 shell 注入。攻击者模型是本地网络上的未经身份验证远程攻击者，因为 UPnP 服务通常默认启用且可访问。漏洞可利用性验证：输入可控（攻击者可伪造 UPnP AddPortMapping 请求）、路径可达（UPnP 请求处理调用此函数）、实际影响（以 root 权限执行任意命令，导致系统妥协）。PoC 步骤：发送 UPnP AddPortMapping 请求，其中 'NewInternalClient' 参数包含恶意命令，如 '192.168.1.1; id'，这将执行 'id' 命令并返回结果。

## 验证指标

- **验证时长：** 281.77 秒
- **Token 使用量：** 250601

---

## 原始信息

- **文件/目录路径：** `webroot/js/privatejs/nat_virtualser.js`
- **位置：** `nat_virtualser.js:rule_entry 函数（具体行号未知，但位于函数内构建 HTML 的部分）`
- **描述：** 存储型跨站脚本（XSS）漏洞存在于 NAT 虚拟服务器配置页面的内部 IP 地址字段渲染过程中。攻击者可以提交恶意规则，其中内部 IP 地址包含 XSS 负载（例如：' onmouseover='alert(1)）。当页面加载时，由于输入值未正确转义，恶意脚本被执行。触发条件：攻击者提交恶意规则后，任何用户（包括管理员）查看 NAT 配置页面。利用方式：攻击者可以窃取会话 cookie、执行任意 JavaScript 代码，或进行权限提升。漏洞源于 `rule_entry` 函数中直接拼接用户输入到 HTML 属性而未转义。
- **代码片段：**
  ```
  text += '<input type="text" class="input-medium" id="pip' + idx + '" name="pip' + idx + '" size="15" maxlength="15" value=' + row[3] + ' validchars="0123456789." onkeypress="return allowChars(this, event)"/>';
  ```
- **备注：** 漏洞依赖于后端存储和返回未转义的数据，但前端渲染代码明确显示未转义。建议检查后端处理以确保输入验证和输出编码。关联函数：`showlist` 和 `preSubmit`。需要进一步验证后端是否对存储的数据进行清理。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `False`
- **风险级别：** `Low`
- **详细原因：** 前端代码确认：在 nat_virtualser.js 的 rule_entry 函数中，row[3]（内部 IP 地址）被直接拼接到 HTML 属性 value 中，未转义且未使用引号包围，这允许注入恶意属性（如 onmouseover）。然而，警报描述为存储型 XSS，这依赖于后端存储和返回未转义的数据，但当前证据未验证后端处理（如输入验证或输出编码）。攻击者模型需已认证的用户提交恶意规则（例如，内部 IP 字段包含 ' onmouseover=alert(1)'），然后任何用户查看页面可能触发 XSS。但完整攻击链不完整：如果后端转义存储的数据，漏洞不可利用。因此，漏洞未确认为真实，风险级别低。PoC 步骤（假设后端未转义）：1. 攻击者以认证身份提交 NAT 规则，内部 IP 设置为 ' onmouseover=alert(1)'；2. 管理员或其他用户查看 NAT 配置页面；3. 如果后端返回未转义数据，鼠标悬停触发 alert(1)。但此外部条件未验证。

## 验证指标

- **验证时长：** 413.92 秒
- **Token 使用量：** 258600

---

