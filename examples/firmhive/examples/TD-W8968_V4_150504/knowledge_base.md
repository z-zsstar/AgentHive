# TD-W8968_V4_150504 (7 个发现)

---

### command-injection-cgiConfigNtp

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd:0x41bc68 sym.cgiConfigNtp`
- **风险评分：** 8.5
- **置信度：** 9.0
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
- **关键词：** glbWebVar, CgiSetTable, CgiGetTable
- **备注：** The vulnerability requires the attacker to have valid login credentials to access the NTP configuration functionality. The `glbWebVar` structure is populated from HTTP inputs, likely through `cgiSetVar` or similar functions. Further analysis could identify the exact HTTP endpoint and parameters. No additional vulnerabilities like buffer overflows were found in this function, but other CGI functions should be checked for similar issues.

---
### UAF-upnp_http_process

- **文件/目录路径：** `lib/libwlupnp.so`
- **位置：** `文件: ./libwlupnp.so 函数: fcn.00004b88 地址: 0x00004bb8; 文件: ./libwlupnp.so 函数: sym.upnp_msg_deinit 地址: 0x0000cc38, 0x0000cc20`
- **风险评分：** 8.0
- **置信度：** 9.0
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
- **关键词：** UPnP HTTP 接口（网络输入点）, 函数符号：sym.upnp_http_process, 函数符号：fcn.00004b88, 函数符号：sym.upnp_msg_deinit, 危险函数：sym.imp.free
- **备注：** 此发现基于完整的污点传播路径证据，从 HTTP 输入点到 free 操作。建议后续分析：验证 use-after-free 的具体利用方式（如构造内存布局实现代码执行），检查其他 UPnP 相关函数是否存在类似问题。关联文件：./libwlupnp.so。

---
### Command-Injection-sym.smb_panic

- **文件/目录路径：** `lib/libbigballofmud.so`
- **位置：** `libbigballofmud.so:0x6b89c (函数sym.smb_panic)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在sym.smb_panic函数中，system函数被调用来执行一个'panic action'命令。命令字符串通过动态函数调用获取（如pcVar2 = (**(iVar9 + -0x5854))()），可能来源于外部配置（如NVRAM或环境变量）。如果攻击者能控制此字符串（例如通过修改配置），可注入恶意命令。触发条件包括系统恐慌事件（如服务崩溃），攻击者可能通过恶意请求触发。完整攻击链：用户可控配置 → 触发panic → system执行，可能导致任意命令执行。
- **代码片段：**
  ```
  反编译代码显示：char *pcVar2 = (**(iVar9 + -0x5854))(); ... uVar3 = (**(iVar9 + -0x5a90))(pcVar2); 其中后者是system调用。缺少输入验证和过滤。
  ```
- **关键词：** NVRAM, environment variables, sym.smb_panic, sym.imp.system
- **备注：** 需要进一步验证命令字符串的具体来源（如配置文件路径和权限）。关联函数可能包括配置解析例程。建议检查NVRAM设置或环境变量是否可由非root用户修改。

---
### BOF-soap_process

- **文件/目录路径：** `lib/libwlupnp.so`
- **位置：** `文件: ./libwlupnp.so 函数: sym.soap_process 地址: 0x00009dfc`
- **风险评分：** 7.5
- **置信度：** 8.0
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
- **关键词：** SOAPACTION 头部, 函数符号：sym.soap_process, 函数符号：sym.upnp_msg_get, 函数符号：sym.upnp_msg_save, 危险操作：越界写入
- **备注：** 漏洞依赖于 'upnp_msg_get' 返回的缓冲区大小，该函数未进行边界检查。建议进一步分析缓冲区分配机制和堆布局以确认利用细节。关联函数包括 'action_process'。后续分析方向应包括测试实际 SOAP 消息触发和评估内存损坏影响。

---
### BufferOverflow-sym.set_community

- **文件/目录路径：** `bin/snmpd`
- **位置：** `snmpd:0x004081b0 sym.set_community`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** A buffer overflow vulnerability exists in the SNMP community string handling function sym.set_community. The function uses strcpy to copy user-provided community strings from SNMP packets to a fixed-size buffer without bounds checking. An attacker with valid login credentials can send a crafted SNMP packet with a long community string (>72 bytes) to trigger the overflow. The buffer is located at a global address (0x42b040 + index * 0x48), and overflow could corrupt adjacent memory, potentially leading to denial of service or code execution. The vulnerability is triggered when processing SNMP set requests or other operations that modify community strings.
- **代码片段：**
  ```
  From decompilation:
  (**(loc._gp + -0x7fac))(param_2 * 0x48 + 0x42b040, *&uStackX_0);
  Where -0x7fac is strcpy, param_2 is the community index (0-2), and *&uStackX_0 is the user-controlled community string. No length validation is performed before copying.
  ```
- **关键词：** SNMP community string, SNMP packets
- **备注：** The attack chain involves sending a malicious SNMP packet to the snmpd service. Full exploitation requires overcoming potential mitigations (e.g., ASLR, stack canaries), which may not be present in this embedded environment. Further analysis is needed to determine the exact impact and exploitability. Related functions like fcn.004104b0 also use dangerous string operations but lack clear input paths.

---
### BufferOverflow-vsf_read_only_check

- **文件/目录路径：** `bin/vsftpd`
- **位置：** `vsftpd:0x41a338 and 0x41a400 (sym.vsf_read_only_check)`
- **风险评分：** 6.5
- **置信度：** 6.0
- **描述：** A buffer overflow vulnerability exists in the 'vsf_read_only_check' function due to the use of 'strcpy' to copy user-supplied data into a fixed-size stack buffer (128 bytes) without bounds checking. The function is called during FTP command processing (e.g., for file operations like RETR, STOR) in 'process_post_login'. An attacker with valid FTP credentials could trigger this by sending a crafted file path or argument longer than 127 bytes, potentially overwriting stack memory and leading to arbitrary code execution. The vulnerability requires the attacker to be authenticated but non-root, and exploitation depends on overcoming stack protections and controlling execution flow.
- **代码片段：**
  ```
  From decompiled code:
  (**(loc._gp + -0x7fa8))(acStack_118, uVar1); // strcpy equivalent
  where acStack_118 is a 128-byte buffer and uVar1 is derived from param_2 (user input).
  ```
- **关键词：** param_2 in sym.vsf_read_only_check, FTP commands: RETR, STOR, CWD, etc., Call sites in sym.process_post_login
- **备注：** The vulnerability is plausible based on code analysis, but full exploitability requires verifying that user input flows to param_2 without length restrictions in all paths. Additional analysis is needed to confirm the attack chain, including testing under real conditions. Other functions like vsf_cmdio_get_cmd_and_arg have input length checks, which may mitigate some risks. Recommend further investigation into data flow from FTP commands to vsf_read_only_check.

---
### 无标题的发现

- **文件/目录路径：** `etc/vsftpd_passwd`
- **位置：** `vsftpd_passwd`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** 文件 'vsftpd_passwd' 以明文存储用户密码，包括弱密码（如 '1234', 'guest', 'test'），且包含权限标志（例如 '1' 可能表示管理员权限）。问题表现：攻击者作为非root用户登录后，如果文件可读，可以直接获取密码。触发条件：攻击者访问文件路径并读取内容。约束条件：文件必须具有可读权限，且 vsftpd 服务需使用此文件进行认证。潜在攻击：攻击者使用获取的密码（如 admin 的 '1234'）登录 FTP 或其他服务，提升权限至管理员，执行危险操作。代码逻辑：文件格式为用户名:密码:标志:标志，分号分隔，密码未加密。
- **代码片段：**
  ```
  admin:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **关键词：** vsftpd_passwd, admin:1234, guest:guest, test:test
- **备注：** 证据基于文件内容分析；需要进一步验证文件权限（如是否全局可读）和 vsftpd 配置（如 /etc/vsftpd.conf 是否引用此文件）。建议后续分析检查相关配置文件和服务状态以确认攻击链的可行性。

---
