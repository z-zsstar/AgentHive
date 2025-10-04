# Archer_D2_V1_150921 - 验证报告 (3 个发现)

---

## 原始信息

- **文件/目录路径：** `usr/bin/upnpd`
- **位置：** `bin/upnpd:0x4032ec (fcn.00403afc) and 0x4075b4 (fcn.004075a4)`
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
- **备注：** This vulnerability requires the upnpd service to be running and accessible to the attacker. The service is often enabled by default on routers and IoT devices. The attack can be performed remotely if the UPnP service is exposed to the network. Additional validation of the NewInternalClient parameter is needed to prevent command injection. Consider also checking other parameters like NewExternalPort and NewProtocol for similar issues.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The vulnerability is verified through code analysis:
- fcn.004075a4 is a system wrapper that executes commands via system() without sanitization.
- A function (fcn.00407d34) constructs an iptables command using snprintf with user-controlled input from the 'NewInternalClient' parameter in AddPortMapping requests.
- The user input is not properly sanitized, allowing command injection via shell metacharacters (e.g., semicolons or backticks).
- The path is reachable: an authenticated remote attacker (with valid login credentials) can send a UPnP AddPortMapping request to trigger the vulnerability.
- The upnpd service runs as root, enabling privilege escalation.

Exploitation PoC:
An attacker can send a crafted UPnP AddPortMapping request with a NewInternalClient value like '192.168.1.100; malicious_command #'. This breaks out of the iptables command and executes arbitrary commands with root privileges. For example:
- Craft a UPnP SOAP request with NewInternalClient set to '192.168.1.100; touch /tmp/pwned #'.
- The snprintf constructs: 'iptables -t nat -A CHAIN -d EXTERNAL_IP -p PROTO --dport EXTERNAL_PORT -j DNAT --to 192.168.1.100; touch /tmp/pwned #:INTERNAL_PORT'.
- system() executes this, running the malicious command 'touch /tmp/pwned' as root.

This confirms a full attack chain from input control to command execution.

## 验证指标

- **验证时长：** 326.98 秒
- **Token 使用量：** 629675

---

## 原始信息

- **文件/目录路径：** `usr/bin/vsftpd`
- **位置：** `Multiple locations in the binary, including command handling functions`
- **描述：** Vsftpd version 2.3.2 contains a known backdoor vulnerability that allows remote code execution. When a user sends a USER command containing the sequence ':)' followed by a specific sequence, the server opens a backdoor on port 6200/tcp. This backdoor provides root access to the system. The vulnerability is triggerable by any authenticated user, including non-root users with valid login credentials. The backdoor is hardcoded in the binary and can be exploited without additional privileges.
- **代码片段：**
  ```
  Evidence from strings and known exploits: The backdoor is activated by sending 'USER :)' or similar sequences. The binary contains code that listens on port 6200 when triggered.
  ```
- **备注：** This is a well-documented backdoor in vsftpd 2.3.2. Exploitation tools and scripts are publicly available. The vulnerability allows full system compromise. Immediate patching or removal of this version is recommended.

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `Low`
- **详细原因：** 基于对usr/bin/vsftpd二进制文件的证据驱动分析：1) 字符串和十六进制搜索未发现':)'序列或端口6200（0x1838）相关证据；2) USER命令处理函数（fcn.00403230和fcn.00405d1c）的反编译代码显示正常认证逻辑，无后门触发条件；3) 无socket/bind/listen调用指向端口6200。攻击者模型（远程攻击者发送USER命令）确认输入可控和路径可达，但无完整传播路径或实际root访问证据。因此，警报描述不准确，漏洞不存在。

## 验证指标

- **验证时长：** 375.36 秒
- **Token 使用量：** 732724

---

## 原始信息

- **文件/目录路径：** `usr/bin/dropbearmulti`
- **位置：** `文件:dropbearmulti:0x41336c 函数 fcn.004132c4`
- **描述：** 在函数 fcn.004132c4 中，地址 0x41336c 处调用 system 函数，执行通过寄存器 a0（设置为 s0）传递的命令字符串。如果 s0 包含未经验证的用户输入（例如来自 SSH 会话），可能导致命令注入漏洞。攻击者可以注入任意命令，实现权限提升或远程代码执行。触发条件包括用户通过 SSH 连接发送特制数据。
- **代码片段：**
  ```
  反汇编代码：0x0041336c jal sym.imp.system ; int system(const char *string)
  0x00413370 move a0, s0
  ```
- **备注：** 建议动态测试以验证输入点；其他危险函数（如 strcpy）可能存在额外漏洞，但本分析专注于 system 调用。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** 安全警报声称在函数 fcn.004132c4 的地址 0x41336c 处调用 system 函数，且 s0 可能包含未经验证的用户输入，导致命令注入。但基于证据分析：
- 反汇编显示函数 fcn.004132c4 仅包含内存初始化操作，并以跳转到 fcn.00412e1c 结束，而 fcn.00412e1c 是一个内存清理函数，没有调用 system。
- 地址 0x0041336c 被识别为独立函数 fcn.0041336c，但代码仅包含 system 调用和栈恢复，没有清晰的数据流显示 s0 来源于用户输入。
- 调用图显示 fcn.004132c4 被 fcn.004160b4 调用，但 fcn.004160b4 的网络操作（如 accept、strlen）没有直接链接到 s0 的设置。
- 攻击者模型为 SSH 用户（未经身份验证或已认证），但证据无法确认 s0 可控或路径可达。因此，漏洞不可利用，警报描述不准确。

## 验证指标

- **验证时长：** 544.48 秒
- **Token 使用量：** 767979

---

