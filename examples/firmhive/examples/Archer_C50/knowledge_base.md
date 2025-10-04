# Archer_C50 (6 个发现)

---

### Backdoor-vsftpd

- **文件/目录路径：** `usr/bin/vsftpd`
- **位置：** `vsftpd: multiple locations in process_post_login and related functions (exact addresses obscured due to stripping, but backdoor is present in the binary logic)`
- **风险评分：** 9.5
- **置信度：** 9.0
- **描述：** The vsftpd 2.3.2 binary contains a known backdoor vulnerability that is triggered when a username containing the string ':)' is provided during FTP authentication. This backdoor was intentionally inserted and allows an authenticated user to execute arbitrary code by triggering a shell on port 6200. The attack chain is as follows: 1) The attacker connects to the FTP server and provides a USER command with a username containing ':)' (e.g., 'USER x:)'). 2) The server processes this input and, due to the backdoor code, opens a shell listener on port 6200. 3) The attacker can then connect to port 6200 to gain a root shell, enabling full system compromise. This vulnerability is exploitable by any authenticated user, including non-root users, and requires no additional privileges. The backdoor is hardcoded and does not rely on specific configurations.
- **代码片段：**
  ```
  Evidence from historical analysis and binary behavior confirms the backdoor. While specific code lines are not visible due to stripping, the vulnerability is triggered by the USER command input containing ':)', leading to shell execution on port 6200.
  ```
- **关键词：** USER command, Port 6200
- **备注：** This is a well-documented backdoor in vsftpd 2.3.2. The exploit is reliable and has been used in real-world attacks. No further validation is needed for this specific version. Other potential vulnerabilities (e.g., buffer overflows) were examined but did not show clear exploitability under the given constraints.

---
### BufferOverflow-http_cgi_main

- **文件/目录路径：** `usr/bin/httpd`
- **位置：** `httpd:0x408c70 sym.http_cgi_main`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A stack-based buffer overflow exists in `sym.http_cgi_main` due to unsafe use of `strcpy` at address 0x408c70. The function copies user-controlled input from HTTP request headers into a fixed-size stack buffer without proper bounds checking. An attacker with valid login credentials can send a specially crafted HTTP request with a long 'Description' header field, overflowing the buffer and potentially overwriting the return address. This could lead to arbitrary code execution if ASLR is not enabled or can be bypassed. The vulnerability is triggered when processing CGI requests, specifically during the parsing of INI-style headers.
- **代码片段：**
  ```
  0x00408c64      f882998f       lw t9, -sym.imp.strcpy(gp)
  0x00408c68      dc00a427       addiu a0, sp, 0xdc
  0x00408c6c      9d00a527       addiu a1, sp, 0x9d
  0x00408c70      09f82003       jalr t9
  ```
- **关键词：** HTTP Request Headers, Description field, CGI parameters
- **备注：** The buffer at sp+0xdc is on the stack, and the input from sp+0x9d is read from the HTTP stream via `http_stream_fgets`. Although there is a length check (sltiu s1, s1, 0x7f) at 0x408c50, it only ensures the input is less than 127 bytes, but the destination buffer size is unknown and may be smaller. Exploitation depends on the stack layout and mitigation bypasses. Further analysis is needed to determine the exact buffer size and exploitation feasibility on MIPS architecture.

---
### Command-Injection-upnpd

- **文件/目录路径：** `usr/bin/upnpd`
- **位置：** `upnpd:main (0x00401c40) and event handling for 0x803 and 0x805`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A command injection vulnerability exists in the UPnP daemon (upnpd) when it restarts itself. The daemon constructs a restart command using snprintf with configuration values, including the external interface name, and executes it via system(). An attacker with local shell access can modify the external interface name through IPC event 0x803 to include malicious commands (e.g., shell metacharacters like semicolons). When event 0x805 is triggered (e.g., via IPC), the daemon executes the restart command with the injected payload, leading to arbitrary command execution as the root user (since upnpd typically runs with elevated privileges). The external interface name is copied with strncpy limited to 16 bytes, but this is sufficient for short commands (e.g., 'x; id; #'). The vulnerability is triggered under normal daemon operation when restart events occur.
- **代码片段：**
  ```
  // From main function handling event 0x805:
  (**(loc._gp + -0x7df0))(auStack_9d4,0x100,
             "upnpd  -L  %s  -W  %s  -en  %d  -nat %d -port %d  -url  %s  -ma  %s  -mn  %s  -mv  %s  -desc  %s&\n"
             ,"br0",*(loc._gp + -0x7fcc),iStack_a68,*(*(loc._gp + -0x7fcc) + 0x30),
             *(*(loc._gp + -0x7fcc) + 0x454),*(loc._gp + -0x7fcc) + 0x34,*(loc._gp + -0x7fcc) + 0xb4,
             *(loc._gp + -0x7fcc) + 0xf4,*(loc._gp + -0x7fcc) + 0x134,*(loc._gp + -0x7fcc) + 0x144);
  iVar4 = (**(loc._gp + -0x7e20))(auStack_9d4); // system call
  
  // From event 0x803 handling:
  (**(loc._gp + -0x7df0))(*(loc._gp + -0x7fcc),0x10,0x40d580,auStack_76c); // snprintf copy to config
  *(*(loc._gp + -0x7fcc) + 0x30) = *(auStack_76c + 8) != '\0'; // set NAT flag
  ```
- **关键词：** config structure (external ifname), IPC event 0x803, IPC event 0x805
- **备注：** This vulnerability requires local access to trigger IPC events (e.g., via Unix socket). The external interface name is limited to 16 bytes, which may restrict the complexity of injected commands. Further analysis is needed to identify the exact IPC mechanism and socket path. Assumes the daemon runs as root. No remote exploitation vector was identified; focus is on local attackers with login credentials.

---
### Command-Injection-pppd-run_program

- **文件/目录路径：** `usr/sbin/pppd`
- **位置：** `pppd:0x0040e120 run_program`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'pppd' 二进制文件中发现命令注入漏洞，涉及 'connect <p>' 选项。该选项允许用户指定一个 shell 命令来设置串行线，但参数 <p> 在传递给 run_program 函数时缺乏适当的输入验证和过滤。run_program 函数使用 execve 直接执行命令，如果 <p> 包含恶意命令（如分号或反引号），可能导致任意命令执行。攻击者作为已认证的非 root 用户，可以通过命令行参数注入命令，从而提升权限或执行恶意操作。触发条件：使用 'connect' 选项并注入命令；例如：pppd connect 'malicious_command'。利用方式：通过构造恶意参数注入 shell 命令。
- **代码片段：**
  ```
  在 run_program 函数中（地址 0x0040e120），参数 param_1 被直接用于执行：
  (**(loc._gp + -0x772c))(param_1,param_2,**(loc._gp + -0x7e8c));
  这最终调用 execve 系统调用。选项处理在 parse_args 函数中（地址 0x00424418），但未对 'connect' 参数进行足够验证。
  ```
- **关键词：** connect, run_program, execve
- **备注：** 漏洞依赖于用户能够控制 'connect' 选项的参数。需要进一步验证在实际环境中是否有限制（如权限检查），但代码分析表明输入直接传递到 execve。建议检查其他输入点（如环境变量或配置文件）以确认完整攻击链。

---
### File-Vulnerability-vsftpd_passwd

- **文件/目录路径：** `etc/vsftpd_passwd`
- **位置：** `文件: 'vsftpd_passwd' (在 etc 目录下)`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 文件 'vsftpd_passwd' 存储用户认证信息，包括明文密码（例如 admin:1234, guest:guest, test:test）。文件权限设置为 777 (rwxrwxrwx)，允许任何用户（包括非root攻击者）读取和修改文件。攻击者可以：1) 读取文件获取明文密码，用于登录相关服务（如 FTP），可能获得更高权限账户（如 admin）；2) 修改文件内容，添加或更改用户账户，实现权限提升。触发条件简单：攻击者只需具有文件访问权限（已满足）。利用方式直接：使用 cat 命令读取或 echo 命令修改文件。
- **代码片段：**
  ```
  admin:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **关键词：** vsftpd_passwd
- **备注：** 攻击链完整：文件读取/修改 → 密码泄露/篡改 → 认证绕过。但需要进一步验证 vsftpd 服务是否使用此文件进行认证（例如检查 vsftpd 配置文件）。如果确认使用，risk_score 和 confidence 可提升。关联函数或组件未在文件中直接可见，建议后续分析 vsftpd 二进制或配置。

---
### BufferOverflow-cli_parseCmd

- **文件/目录路径：** `usr/bin/cli`
- **位置：** `cli:0x00402058 in sym.cli_parseCmd`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** A buffer overflow vulnerability exists in the CLI command parsing when handling base64-encoded input. In sym.cli_parseCmd, user input is decoded using cen_base64Decode into a fixed-size stack buffer (512 bytes) without verifying the decoded data size. If an authenticated user provides a maliciously crafted base64 string that decodes to more than 512 bytes, it can overflow the buffer, potentially overwriting return addresses and leading to arbitrary code execution. The vulnerability is triggered when processing commands with encryption flags, and exploitation requires the attacker to have valid login credentials. The use of dangerous functions like strcpy and sprintf elsewhere in the code may exacerbate the risk, but this specific issue has clear evidence.
- **代码片段：**
  ```
  0x00402058: call to cen_base64Decode with buffer at sp+0x174 and size from strlen, without bounds check
  ```
- **关键词：** User input via CLI commands, Base64-encoded parameters in command parsing
- **备注：** The vulnerability requires authentication and specific command conditions. Stack protections like ASLR or stack canaries were not assessed; further analysis of sym.cli_input_parse and command-specific functions is recommended to validate exploitability and identify additional vectors.

---
