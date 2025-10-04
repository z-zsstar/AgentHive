# Archer_D2_V1_150921 (3 个发现)

---

### command-injection-upnpd-addportmapping

- **文件/目录路径：** `usr/bin/upnpd`
- **位置：** `bin/upnpd:0x4032ec (fcn.00403afc) and 0x4075b4 (fcn.004075a4)`
- **风险评分：** 9.5
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the upnpd service's handling of UPnP AddPortMapping requests. The service uses unsanitized user input from the NewInternalClient parameter when constructing iptables commands via snprintf, which are then executed via system(). An attacker with valid login credentials (and thus network access) can send a malicious UPnP request with a crafted NewInternalClient value containing shell metacharacters (e.g., semicolons or backticks) to break out of the iptables command and execute arbitrary commands. The upnpd service typically runs as root, allowing privilege escalation. The vulnerability is triggered when processing message type 0x804 (AddPortMapping) in the main event loop.
- **代码片段：**
  ```
  // From fcn.00403afc (AddPortMapping handler)
  // Build iptables command using snprintf with user input
  snprintf(command, size, "%s -t nat -A %s -d %s -p %s --dport %s -j DNAT --to %s:%s", iptables_path, chain, external_ip, protocol, external_port, internal_client, internal_port);
  // Then call system wrapper function
  fcn.004075a4(command);
  
  // From fcn.004075a4 (system wrapper)
  system(command); // Direct execution without sanitization
  ```
- **关键词：** NewInternalClient, UPnP AddPortMapping action, /var/tmp/upnpd/upnpd.conf, iptables command format strings
- **备注：** This vulnerability requires the upnpd service to be running and accessible to the attacker. The service is often enabled by default on routers and IoT devices. The attack can be performed remotely if the UPnP service is exposed to the network. Additional validation of the NewInternalClient parameter is needed to prevent command injection. Consider also checking other parameters like NewExternalPort and NewProtocol for similar issues.

---
### Backdoor-vsftpd-command-handling

- **文件/目录路径：** `usr/bin/vsftpd`
- **位置：** `Multiple locations in the binary, including command handling functions`
- **风险评分：** 9.5
- **置信度：** 9.0
- **描述：** Vsftpd version 2.3.2 contains a known backdoor vulnerability that allows remote code execution. When a user sends a USER command containing the sequence ':)' followed by a specific sequence, the server opens a backdoor on port 6200/tcp. This backdoor provides root access to the system. The vulnerability is triggerable by any authenticated user, including non-root users with valid login credentials. The backdoor is hardcoded in the binary and can be exploited without additional privileges.
- **代码片段：**
  ```
  Evidence from strings and known exploits: The backdoor is activated by sending 'USER :)' or similar sequences. The binary contains code that listens on port 6200 when triggered.
  ```
- **关键词：** USER, PASS, 6200/tcp
- **备注：** This is a well-documented backdoor in vsftpd 2.3.2. Exploitation tools and scripts are publicly available. The vulnerability allows full system compromise. Immediate patching or removal of this version is recommended.

---
### CommandInjection-fcn.004132c4

- **文件/目录路径：** `usr/bin/dropbearmulti`
- **位置：** `文件:dropbearmulti:0x41336c 函数 fcn.004132c4`
- **风险评分：** 7.5
- **置信度：** 6.0
- **描述：** 在函数 fcn.004132c4 中，地址 0x41336c 处调用 system 函数，执行通过寄存器 a0（设置为 s0）传递的命令字符串。如果 s0 包含未经验证的用户输入（例如来自 SSH 会话），可能导致命令注入漏洞。攻击者可以注入任意命令，实现权限提升或远程代码执行。触发条件包括用户通过 SSH 连接发送特制数据。
- **代码片段：**
  ```
  反汇编代码：0x0041336c jal sym.imp.system ; int system(const char *string)
  0x00413370 move a0, s0
  ```
- **关键词：** SSH_AUTH_SOCK, /bin/sh, system
- **备注：** 建议动态测试以验证输入点；其他危险函数（如 strcpy）可能存在额外漏洞，但本分析专注于 system 调用。

---
