# TD-W8968_V4_150504 - 验证报告 (7 个发现)

---

## 原始信息

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd:0x41bc68 sym.cgiConfigNtp`
- **描述：** A command injection vulnerability exists in the `cgiConfigNtp` function, which handles NTP configuration via CGI. The function reads a date-time string from the global variable `glbWebVar` at offset 0x9e8, formats it into a 'date -s' command using `sprintf`, and executes it via `system`. The input is parsed with `sscanf` using the format '%d.%d.%d-%d:%d:%d', but the original string is used directly in `sprintf` without sanitization. An attacker can inject arbitrary commands by including shell metacharacters (e.g., ';' or '&') in the input. The vulnerability is triggered when a user submits a malicious date-time string through the HTTP interface, such as via a POST request to the NTP configuration endpoint. The attack chain involves: 1. User input being stored in `glbWebVar` through CGI parsing in `web_main` or similar functions; 2. The `cgiConfigNtp` function processing the input and constructing a command string; 3. The command string being executed by `system`, leading to arbitrary command execution as the httpd process user.
- **代码片段：**
  ```
  0x0041bc64      24a5b354       addiu a1, a1, -0x4cac       ; 0x45b354 ; "%d.%d.%d-%d:%d:%d" ; arg2
  0x0041bc68      260409e8       addiu a0, s0, 0x9e8         ; arg1
  0x0041bc6c      0320f809       jalr t9                     ; sscanf
  0x0041bc80      8f99831c       lw t9, -sym.imp.sprintf(gp) ; [0x452180:4]=0x8f998010
  0x0041bc8c      24a5b368       addiu a1, a1, -0x4c98       ; 0x45b368 ; "date -s %s" ; arg2
  0x0041bc90      260609e8       addiu a2, s0, 0x9e8         ; arg3
  0x0041bc94      0320f809       jalr t9                     ; sprintf
  0x0041bca0      8f998938       lw t9, -sym.imp.system(gp)  ; [0x451200:4]=0x8f998010
  0x0041bca4      0320f809       jalr t9                     ; system
  ```
- **备注：** The vulnerability requires the attacker to have valid login credentials to access the NTP configuration functionality. The `glbWebVar` structure is populated from HTTP inputs, likely through `cgiSetVar` or similar functions. Further analysis could identify the exact HTTP endpoint and parameters. No additional vulnerabilities like buffer overflows were found in this function, but other CGI functions should be checked for similar issues.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据来自反汇编代码：函数 `cgiConfigNtp` 从 `glbWebVar+0x9e8` 读取输入，使用 `sscanf` 解析但保留原始字符串，直接用于 `sprintf` 构建命令并执行 via `system`。输入未消毒，shell 元字符（如 ';' 或 '&'）可注入任意命令。攻击路径可达：当输入非空且 `sscanf` 返回 6（成功解析）时，命令执行。攻击者模型为经过认证的远程攻击者（需登录凭证访问 NTP 配置功能）。实际影响：任意命令执行作为 httpd 进程用户（可能高权限）。PoC 步骤：1. 登录设备 web 接口；2. 访问 NTP 配置端点；3. 提交恶意日期时间参数，如 '2023.12.31-12:00:00; whoami'（注入 'whoami' 命令）；4. 服务器执行 'date -s 2023.12.31-12:00:00; whoami'，导致命令注入。

## 验证指标

- **验证时长：** 211.44 秒
- **Token 使用量：** 148867

---

## 原始信息

- **文件/目录路径：** `lib/libwlupnp.so`
- **位置：** `文件: ./libwlupnp.so 函数: fcn.00004b88 地址: 0x00004bb8; 文件: ./libwlupnp.so 函数: sym.upnp_msg_deinit 地址: 0x0000cc38, 0x0000cc20`
- **描述：** 在 'upnp_http_process' 函数中发现一个 use-after-free 漏洞，源于 HTTP 请求处理错误路径。具体表现：当处理 HTTP 请求时，如果 iStack_28 < 0（错误条件），会调用 fcn.00004b88，后者调用 sym.upnp_msg_deinit，在 sym.upnp_msg_deinit 中从污点指针偏移 0x20bc 处加载值并传递给 free 函数。触发条件：攻击者发送特制 HTTP 请求到 UPnP 接口，触发错误处理路径。约束条件：攻击者需拥有有效登录凭据（非 root 用户）。潜在攻击：通过精确控制偏移 0x20bc 处的指针值，可实现任意内存释放，进而导致 use-after-free 或双重释放，可能被利用于代码执行或权限提升。代码逻辑涉及多层函数调用，污点数据从 HTTP 请求结构传播到 free 操作。
- **代码片段：**
  ```
  从 upnp_http_process 反编译代码片段（错误路径）：
  if (iStack_28 < 0) {
      (*(fcn.00004b88 + *(iVar2 + -0x7fd8)))(*aiStackX_0); // 调用 fcn.00004b88
      break;
  }
  
  从 fcn.00004b88 到 sym.upnp_msg_deinit 的污点传播：
  0x00004bb8: jalr t9 // 调用 sym.upnp_msg_deinit，污点在 a0
  
  在 sym.upnp_msg_deinit 中：
  0x0000cc38: lw v0, 0x28(sp); lw v0, 0x20bc(v0); sw v0, 0x18(sp) // 从污点指针加载值
  0x0000cc20: lw a0, 0x18(sp); lw v0, -0x7f98(gp); move t9, v0; jalr t9 // 调用 free
  ```
- **备注：** 此发现基于完整的污点传播路径证据，从 HTTP 输入点到 free 操作。建议后续分析：验证 use-after-free 的具体利用方式（如构造内存布局实现代码执行），检查其他 UPnP 相关函数是否存在类似问题。关联文件：./libwlupnp.so。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了 use-after-free 漏洞。证据如下：1) 在 upnp_http_process 函数（地址 0x00004cc4），当 var_18h < 0 时触发错误路径，调用 fcn.00004b88；2) fcn.00004b88（地址 0x00004bb8）调用 sym.upnp_msg_deinit，传递污点指针 a0；3) 在 sym.upnp_msg_deinit（地址 0x0000cc38 和 0x0000cc20），从指针偏移 0x20bc 处加载值并调用 free。攻击者模型为已认证的非 root 用户，通过发送特制 HTTP 请求控制输入（HTTP 请求结构），使处理函数返回负值触发错误路径。完整攻击链：攻击者控制偏移 0x20bc 处的指针值，触发 free 操作，导致任意内存释放。可利用性验证：输入可控（HTTP 请求可操纵）、路径可达（错误条件可触发）、实际影响（任意释放可能导致 use-after-free 或双重释放，进而代码执行）。PoC 步骤：1) 以有效用户身份认证；2) 发送恶意 HTTP 请求到 UPnP 接口，精心构造请求体使处理函数返回错误（如无效头或数据）；3) 在请求结构中设置偏移 0x20bc 处的值为目标内存地址（如堆块地址）；4) 触发错误路径后，free 释放该地址，后续操作可利用释放的内存布局实现代码执行。

## 验证指标

- **验证时长：** 252.06 秒
- **Token 使用量：** 185190

---

## 原始信息

- **文件/目录路径：** `lib/libwlupnp.so`
- **位置：** `文件: ./libwlupnp.so 函数: sym.soap_process 地址: 0x00009dfc`
- **描述：** 在 'soap_process' 函数中发现一个缓冲区溢出漏洞，源于 SOAP 消息解析过程中对 SOAPACTION 头的手动 null 终止符写入操作。具体问题：使用 strcspn 函数计算分隔符位置后，直接向计算出的地址写入 null 字节（sb zero, (v0)），而未验证该地址是否在缓冲区边界内。触发条件：攻击者发送特制 SOAP 消息，其中 SOAPACTION 头不包含预期分隔符（如引号或空格），导致 strcspn 返回整个字符串长度，使写入位置超出缓冲区边界。约束条件：攻击者需拥有有效登录凭据（非 root 用户）。潜在攻击：通过越界写入 null 字节，可能导致内存损坏，被利用执行任意代码或导致拒绝服务。漏洞涉及缺少边界检查，攻击者可通过控制 SOAPACTION 头内容触发溢出。
- **代码片段：**
  ```
  从 soap_process 反编译代码片段：
  0x00009dd8      8f8280b0       lw v0, -sym.imp.strcspn(gp) ; 调用 strcspn
  0x00009ddc      0040c821       move t9, v0
  0x00009de0      0320f809       jalr t9
  0x00009de4      00000000       nop
  0x00009de8      8fdc0010       lw gp, (var_10h)
  0x00009dec      afc2001c       sw v0, (var_1ch)
  0x00009df0      8fc2001c       lw v0, (var_1ch)
  0x00009df4      8fc30020       lw v1, (var_20h)
  0x00009df8      00621021       addu v0, v1, v0
  0x00009dfc      a0400000       sb zero, (v0) ; 越界写入 null 字节
  ```
- **备注：** 漏洞依赖于 'upnp_msg_get' 返回的缓冲区大小，该函数未进行边界检查。建议进一步分析缓冲区分配机制和堆布局以确认利用细节。关联函数包括 'action_process'。后续分析方向应包括测试实际 SOAP 消息触发和评估内存损坏影响。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 安全警报准确描述了缓冲区溢出漏洞。基于反编译代码分析，在 'sym.soap_process' 函数的地址 0x00009dfc 处，使用 strcspn 计算分隔符位置后，直接向计算出的地址写入 null 字节（sb zero, (v0)），而未验证该地址是否在缓冲区边界内。输入可控：攻击者可通过特制 SOAP 消息控制 SOAPACTION 头内容。路径可达：代码流显示，在通过基本检查（如 SOAPACTION 头非空和特定字符串比较）后，可到达易受攻击路径。实际影响：越界写入 null 字节可能导致内存损坏，被利用执行任意代码或导致拒绝服务。攻击者模型为已认证的非 root 用户（需要有效登录凭据），这降低了即时风险，但漏洞仍可利用。PoC 步骤：1. 攻击者获取有效登录凭据；2. 构造 SOAP 消息，其中 SOAPACTION 头为长字符串且不包含预期分隔符（如引号、制表符或空格）；3. 发送该消息到目标服务；4. strcspn 将返回整个字符串长度，导致 null 字节写入缓冲区之外，触发内存损坏。漏洞风险为中等，因需要认证且利用可能受内存布局影响，但潜在危害严重。

## 验证指标

- **验证时长：** 271.45 秒
- **Token 使用量：** 197806

---

## 原始信息

- **文件/目录路径：** `etc/vsftpd_passwd`
- **位置：** `vsftpd_passwd`
- **描述：** 文件 'vsftpd_passwd' 以明文存储用户密码，包括弱密码（如 '1234', 'guest', 'test'），且包含权限标志（例如 '1' 可能表示管理员权限）。问题表现：攻击者作为非root用户登录后，如果文件可读，可以直接获取密码。触发条件：攻击者访问文件路径并读取内容。约束条件：文件必须具有可读权限，且 vsftpd 服务需使用此文件进行认证。潜在攻击：攻击者使用获取的密码（如 admin 的 '1234'）登录 FTP 或其他服务，提升权限至管理员，执行危险操作。代码逻辑：文件格式为用户名:密码:标志:标志，分号分隔，密码未加密。
- **代码片段：**
  ```
  admin:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **备注：** 证据基于文件内容分析；需要进一步验证文件权限（如是否全局可读）和 vsftpd 配置（如 /etc/vsftpd.conf 是否引用此文件）。建议后续分析检查相关配置文件和服务状态以确认攻击链的可行性。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** 警报描述文件内容正确（明文弱密码和权限标志）且文件全局可读，但未验证 vsftpd 服务实际使用此文件进行认证。攻击者模型为非 root 用户已登录系统；他们可执行 'cat etc/vsftpd_passwd' 读取密码，但缺乏证据证明 vsftpd 配置（/etc/vsftpd.conf）引用此文件，因此无法确认密码可用于登录 FTP 服务或提升权限。漏洞链不完整，无法构成真实漏洞。

## 验证指标

- **验证时长：** 304.10 秒
- **Token 使用量：** 225636

---

## 原始信息

- **文件/目录路径：** `bin/snmpd`
- **位置：** `snmpd:0x004081b0 sym.set_community`
- **描述：** A buffer overflow vulnerability exists in the SNMP community string handling function sym.set_community. The function uses strcpy to copy user-provided community strings from SNMP packets to a fixed-size buffer without bounds checking. An attacker with valid login credentials can send a crafted SNMP packet with a long community string (>72 bytes) to trigger the overflow. The buffer is located at a global address (0x42b040 + index * 0x48), and overflow could corrupt adjacent memory, potentially leading to denial of service or code execution. The vulnerability is triggered when processing SNMP set requests or other operations that modify community strings.
- **代码片段：**
  ```
  From decompilation:
  (**(loc._gp + -0x7fac))(param_2 * 0x48 + 0x42b040, *&uStackX_0);
  Where -0x7fac is strcpy, param_2 is the community index (0-2), and *&uStackX_0 is the user-controlled community string. No length validation is performed before copying.
  ```
- **备注：** The attack chain involves sending a malicious SNMP packet to the snmpd service. Full exploitation requires overcoming potential mitigations (e.g., ASLR, stack canaries), which may not be present in this embedded environment. Further analysis is needed to determine the exact impact and exploitability. Related functions like fcn.004104b0 also use dangerous string operations but lack clear input paths.

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** The code vulnerability in sym.set_community is accurate: strcpy is used without bounds checking, copying data to a fixed buffer at 0x42b040 + index * 0x48. However, the exploitability description is inaccurate. Evidence from decompilation and cross-references shows that sym.set_community is called only during initialization in main (e.g., at 0x402bf4 and 0x402c18), with parameters derived from internal data structures, not directly from SNMP packets. No code path was found where SNMP set requests or other operations trigger this function with attacker-controlled input. The attack model (attacker with valid login credentials sending crafted SNMP packets) is not supported, as the function is not invoked in packet processing loops. Therefore, while a buffer overflow exists, it is not exploitable remotely as described, and thus does not constitute a real vulnerability in this context.

## 验证指标

- **验证时长：** 353.82 秒
- **Token 使用量：** 249716

---

## 原始信息

- **文件/目录路径：** `bin/vsftpd`
- **位置：** `vsftpd:0x41a338 and 0x41a400 (sym.vsf_read_only_check)`
- **描述：** A buffer overflow vulnerability exists in the 'vsf_read_only_check' function due to the use of 'strcpy' to copy user-supplied data into a fixed-size stack buffer (128 bytes) without bounds checking. The function is called during FTP command processing (e.g., for file operations like RETR, STOR) in 'process_post_login'. An attacker with valid FTP credentials could trigger this by sending a crafted file path or argument longer than 127 bytes, potentially overwriting stack memory and leading to arbitrary code execution. The vulnerability requires the attacker to be authenticated but non-root, and exploitation depends on overcoming stack protections and controlling execution flow.
- **代码片段：**
  ```
  From decompiled code:
  (**(loc._gp + -0x7fa8))(acStack_118, uVar1); // strcpy equivalent
  where acStack_118 is a 128-byte buffer and uVar1 is derived from param_2 (user input).
  ```
- **备注：** The vulnerability is plausible based on code analysis, but full exploitability requires verifying that user input flows to param_2 without length restrictions in all paths. Additional analysis is needed to confirm the attack chain, including testing under real conditions. Other functions like vsf_cmdio_get_cmd_and_arg have input length checks, which may mitigate some risks. Recommend further investigation into data flow from FTP commands to vsf_read_only_check.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** The security alert is accurate based on code analysis. The 'vsf_read_only_check' function uses 'strcpy' to copy user input into fixed-size 128-byte stack buffers without bounds checking, as confirmed at addresses 0x0041a338 and 0x0041a400. The function is called from multiple sites in 'process_post_login' during FTP command processing (e.g., for operations like MKDIR, RETR, STOR). User input flows to the function via the second argument (derived from FTP command arguments) without length restrictions in the observed paths. An authenticated FTP user (non-root) can trigger this by sending a crafted command with a file path or argument longer than 127 bytes. For example, a PoC would involve authenticating to the FTP server and issuing a command like 'MKDIR <long_string>' or 'RETR <long_string>', where <long_string> is 128 bytes or more (e.g., 'A' * 128). This would overflow the buffer, potentially overwriting stack memory and allowing arbitrary code execution, though actual exploitation may require bypassing stack protections. The risk is medium due to the authentication prerequisite and the complexity of reliable exploitation.

## 验证指标

- **验证时长：** 452.14 秒
- **Token 使用量：** 280850

---

## 原始信息

- **文件/目录路径：** `lib/libbigballofmud.so`
- **位置：** `libbigballofmud.so:0x6b89c (函数sym.smb_panic)`
- **描述：** 在sym.smb_panic函数中，system函数被调用来执行一个'panic action'命令。命令字符串通过动态函数调用获取（如pcVar2 = (**(iVar9 + -0x5854))()），可能来源于外部配置（如NVRAM或环境变量）。如果攻击者能控制此字符串（例如通过修改配置），可注入恶意命令。触发条件包括系统恐慌事件（如服务崩溃），攻击者可能通过恶意请求触发。完整攻击链：用户可控配置 → 触发panic → system执行，可能导致任意命令执行。
- **代码片段：**
  ```
  反编译代码显示：char *pcVar2 = (**(iVar9 + -0x5854))(); ... uVar3 = (**(iVar9 + -0x5a90))(pcVar2); 其中后者是system调用。缺少输入验证和过滤。
  ```
- **备注：** 需要进一步验证命令字符串的具体来源（如配置文件路径和权限）。关联函数可能包括配置解析例程。建议检查NVRAM设置或环境变量是否可由非root用户修改。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 验证基于反编译代码和汇编分析：在sym.smb_panic函数中，pcVar2 = (**(iVar9 + -0x5854))() 调用sym.lp_panic_action获取命令字符串，uVar3 = (**(iVar9 + -0x5a90))(pcVar2) 执行命令，虽未直接导入system，但返回值检查和上下文确认是system调用。命令字符串源自外部配置（如Samba的panic action参数），攻击者可控制（如通过修改配置文件或NVRAM）。攻击者模型：已认证用户或远程攻击者（如果能修改配置）可通过恶意请求（如SMB崩溃）触发恐慌，导致命令执行。完整攻击链：攻击者修改配置中的panic action为恶意命令（如'rm -rf /'或反向shell）→ 触发恐慌（如发送畸形SMB请求）→ system执行恶意命令。证据支持输入可控、路径可达和实际影响，漏洞可利用。

## 验证指标

- **验证时长：** 540.99 秒
- **Token 使用量：** 297923

---

