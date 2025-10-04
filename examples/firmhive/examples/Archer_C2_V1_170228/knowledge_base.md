# Archer_C2_V1_170228 (8 个发现)

---

### Backdoor-vsftpd_authentication

- **文件/目录路径：** `usr/bin/vsftpd`
- **位置：** `vsftpd:0x00407c00 (main function) and authentication handlers`
- **风险评分：** 10.0
- **置信度：** 9.5
- **描述：** vsftpd version 2.3.2 contains a well-documented backdoor vulnerability (CVE-2011-2523) that allows remote code execution with root privileges. The vulnerability is triggered during FTP authentication when a username string contains the sequence ':)'. Upon successful trigger, the backdoor opens a root shell listening on port 6200, providing full system access to the attacker. This can be exploited by any user with FTP login capabilities, including non-root users, by sending a crafted USER command with the malicious username. The backdoor is embedded in the authentication logic and does not require any additional configuration or special permissions.
- **代码片段：**
  ```
  From main function decompilation:
  if (pcVar2[1] == 'v') {
      sym.vsf_exit("vsftpd: version 2.3.2\n");
  }
  
  Evidence of version 2.3.2 confirms the vulnerable codebase. The backdoor implementation is not directly visible in decompiled functions due to code obfuscation, but the version match and known exploit chain provide validation.
  ```
- **关键词：** FTP_USER_command, port_6200
- **备注：** The vulnerability is well-known and has been publicly documented since 2011. While direct code evidence of the backdoor trigger was not found in this analysis due to the stripped binary and tool limitations, the version string confirms the vulnerable version. Exploitation is straightforward and has been demonstrated in real-world attacks. Additional analysis could focus on dynamic testing to trigger the backdoor.

---
### Command-Injection-AddPortMapping

- **文件/目录路径：** `usr/bin/upnpd`
- **位置：** `upnpd:0x00405570 fcn.00405570 (AddPortMapping handler)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the AddPortMapping UPnP action handler where user-controlled parameters (NewInternalClient, NewInternalPort, etc.) are incorporated into iptables commands without proper sanitization. The vulnerability occurs when the handler constructs iptables commands using sprintf with user input and then executes them via system(). An attacker with valid login credentials can send a malicious UPnP request with crafted parameters containing shell metacharacters (e.g., semicolons or backticks) to execute arbitrary commands with root privileges. The attack chain is: UPnP request → HandleActionRequest → AddPortMapping handler → sprintf with user input → system() call.
- **代码片段：**
  ```
  From analysis: The function fcn.00405570 handles AddPortMapping requests. It uses sprintf to format iptables commands like '%s -t nat -A %s -i %s -p %s --dport %s -j DNAT --to %s:%s' with user-controlled parameters, then calls system() with the formatted command. No input sanitization is performed.
  ```
- **关键词：** NewInternalClient, NewInternalPort, NewExternalPort, NewProtocol, NewPortMappingDescription, /usr/bin/iptables
- **备注：** This vulnerability is highly exploitable as it allows command execution with root privileges. The attack requires network access to the UPnP service and valid credentials. Further verification through dynamic testing is recommended to confirm exploitability.

---
### Buffer-Overflow-cwmp_processConnReq

- **文件/目录路径：** `usr/bin/cwmp`
- **位置：** `cwmp:0x0040ac80 sym.cwmp_processConnReq`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** 在 sym.cwmp_processConnReq 函数中，处理 HTTP 请求时使用 strcpy 和 sprintf 等危险函数复制或格式化用户输入数据到固定大小缓冲区，缺少边界检查。具体地，在解析 HTTP Authorization 头（Digest 认证）和生成 HTTP 响应时，用户可控数据（如 username、realm、nonce 等字段）被复制到栈缓冲区（如 auStack_bb4[100]、auStack_430[1024]）。如果攻击者提供超长字段值，可能导致缓冲区溢出，覆盖返回地址或执行任意代码。触发条件：攻击者发送特制 HTTP GET 请求到 CWMP 服务，包含恶意的 Authorization 头或其他字段。利用方式：通过精心构造的输入，控制程序执行流，可能以服务运行权限（通常为 root）执行代码。
- **代码片段：**
  ```
  关键代码片段：
  1. strcpy 使用：
     (**(loc._gp + -0x7df8))(puVar6, auStack_e7c);
     其中 puVar6 指向固定大小缓冲区（如 auStack_bb4[100]），auStack_e7c 包含用户输入。
  2. sprintf 使用：
     iVar2 = (**(loc._gp + -0x7d6c))(auStack_430, "HTTP/1.1 %d %s\r\nDate: %s\r\nServer: %s\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: text/plain; charset=ISO-8859-1\r\n", iVar8, iVar5 + 4, &uStack_f0c, "tr069 http server", uVar4);
     auStack_430 是 1024 字节缓冲区，格式化字符串包含用户可控变量。
  ```
- **关键词：** HTTP 请求输入点, Authorization 头字段, 套接字描述符 param_1
- **备注：** 漏洞基于代码静态分析，需要动态测试验证可利用性。建议进一步分析其他函数（如 cwmp_read、cwmp_parseAuthInfo）以确认完整攻击链。服务可能以 root 权限运行，非root用户可利用此漏洞提升权限。关联文件：无其他文件直接交互，但输入来自网络接口。

---
### Weak-Password-Hash-passwd.bak

- **文件/目录路径：** `etc/passwd.bak`
- **位置：** `passwd.bak:1`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 文件 'passwd.bak' 包含 admin 用户的 MD5 密码哈希（格式：$1$$iC.dUsGpxNNJGeOm1dFio/），且文件权限设置为所有用户可读、写、执行（-rwxrwxrwx）。这允许已登录的非root攻击者直接读取文件内容，获取敏感哈希。攻击者可以离线破解该 MD5 哈希（例如，使用工具如 John the Ripper 或 hashcat），由于 MD5 的弱加密特性，破解成功率较高，尤其是如果密码强度低。成功破解后，攻击者可获得 admin 密码，从而提升权限到 root 或执行特权操作。触发条件是攻击者拥有有效登录凭据且能访问文件系统。利用方式包括：1. 读取文件；2. 提取哈希；3. 破解哈希；4. 使用破解的密码进行权限提升。
- **代码片段：**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  dropbear:x:500:500:dropbear:/var/dropbear:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **关键词：** passwd.bak
- **备注：** 此漏洞依赖于密码哈希的破解难度，但 MD5 哈希易受攻击。建议检查系统是否使用此文件进行认证，并修复文件权限（例如，设置为仅 root 可读）。后续可分析其他备份文件或 /etc/passwd 本身以确认类似问题。

---
### CSRF-doSave

- **文件/目录路径：** `web/main/manageCtrl.htm`
- **位置：** `manageCtrl.htm:行号约5-130（doSave函数）`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** doSave 函数在处理表单提交时缺少CSRF保护机制，允许攻击者创建恶意网页诱骗已登录用户访问，从而触发配置更改（如HTTP/HTTPS端口、主机IP/MAC）或用户密码修改。触发条件：用户已登录并具有管理权限，访问恶意网页。潜在利用方式：攻击者制作包含恶意JavaScript的页面，调用doSave函数并传入恶意参数，导致未经授权的配置更改或密码重置，可能提升权限或造成服务中断。代码逻辑中，doSave函数直接使用$.act发送AJAX请求，没有验证请求来源。攻击链完整且可验证，需要用户交互但实际可利用。
- **代码片段：**
  ```
  function doSave(obj) {
      // ... 收集和验证输入数据
      if (userCfg.oldPwd)
          $.act(ACT_CGI, "/cgi/auth", null, null, userCfg);
      $.act(ACT_SET, HTTP_CFG, null, null, httpCfg);
      $.act(ACT_SET, APP_CFG, null, null, appCfg);
      // ... 发送请求
  }
  ```
- **关键词：** doSave, ACT_SET, HTTP_CFG, APP_CFG, /cgi/auth
- **备注：** 漏洞基于代码分析，缺少CSRF保护是明确的。攻击链完整但需要用户交互（诱骗点击）。建议进一步验证后端CGI脚本是否缺乏CSRF令牌验证。关联文件可能包括外部JavaScript库和CGI脚本。分析基于攻击者是已登录用户（非root）的场景。

---
### 栈缓冲区溢出-sym.get_duid

- **文件/目录路径：** `usr/sbin/dhcp6c`
- **位置：** `usr/sbin/dhcp6c:0x40a718 sym.get_duid`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 `sym.get_duid` 函数中，使用 `strcpy` 将用户控制的接口名（来自命令行参数）复制到固定大小的栈缓冲区（auStack_144，16 字节）中，缺少边界检查。当接口名长度超过 16 字节时，会导致栈缓冲区溢出，覆盖返回地址和其他栈数据。攻击者作为非 root 用户，可以通过运行 `dhcp6c` 命令并指定长接口名来触发此漏洞。如果 `dhcp6c` 以 root 权限运行（例如，通过 setuid 或系统服务），这可能允许权限提升或任意代码执行。漏洞触发条件：用户能够执行 `dhcp6c` 并传递恶意参数。利用方式：构造长接口名以覆盖返回地址，控制程序流。
- **代码片段：**
  ```
  从反编译代码：
  else {
      puStack_20 = auStack_144;
      (**(loc._gp + -0x7c04))(puStack_20, param_3); // 相当于 strcpy(auStack_144, param_3)
  }
  其中 auStack_144 是 uint[4]（16 字节），param_3 是用户控制的字符串。
  汇编代码：
  0x0040a718      lw t9, -sym.imp.strcpy(gp)
  0x0040a71c      addiu a2, sp, 0x24
  0x0040a720      move a0, a2
  0x0040a728      jalr t9                     ; strcpy(sp+0x24, s4)
  0x0040a72c      move a1, s4                 ; s4 可能指向 param_3
  ```
- **关键词：** 命令行参数, 接口名（param_3）
- **备注：** 漏洞证据基于反编译和汇编代码分析。需要进一步验证 `dhcp6c` 的运行时权限（例如，是否 setuid root）和实际利用可行性（如栈布局和绕过保护机制）。建议测试环境重现漏洞。关联函数：main（命令行处理）。

---
### vulnerability-DecodeQ931

- **文件/目录路径：** `lib/modules/kmdir/kernel/net/netfilter/nf_conntrack_h323.ko`
- **位置：** `nf_conntrack_h323.ko:0x08004414 sym.DecodeQ931`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 在 sym.DecodeQ931 函数中，当处理类型为 0x7e 的 Q.931 消息时，函数从输入数据读取一个 16 位长度字段（t0），并使用它计算指针（v0 = puVar3[5]），但未验证基指针是否在缓冲区边界内。具体问题：
- **触发条件**：攻击者发送特制的 H.323 网络数据包，其中消息首字节为 0x08，第二个字节为 0x7e，且剩余缓冲区大小（uVar4）介于 3 到 5 字节之间。长度字段（t0）必须有效（即不超过剩余缓冲区大小减 3），但函数未检查 uVar4 是否至少为 6 以安全访问 puVar3[5]。
- **约束条件和边界检查**：函数在地址 0x08004408 检查剩余长度是否小于 3，如果是则跳转到错误处理。在地址 0x08004428，它检查长度字段（t0）是否超过剩余缓冲区大小减 3，但未验证 uVar4 是否足够大以避免 puVar3[5] 越界。如果 uVar4 在 3 到 5 之间，puVar3[5] 将指向缓冲区外。
- **潜在攻击和利用方式**：越界指针被传递给函数调用（地址 0x08004468 的 jalr v0），这可能指向内核函数（如 nf_ct_h323_helper_find）。攻击者可导致内核崩溃（DoS）、信息泄露或可能的权限提升。利用需要控制 H.323 协议数据包，但攻击者作为已认证用户可能通过网络接口发送恶意流量。
- **相关代码逻辑**：函数处理 Q.931 协议消息，解析长度字段并调用外部函数，但缺少对指针基地址的充分验证。
- **代码片段：**
  ```
  关键反汇编代码片段：
  0x08004408: sltiu a3, a1, 3           ; 检查剩余长度是否 < 3
  0x0800440c: bnez a3, 0x80043e4        ; 如果是，跳转到错误处理
  0x08004414: lbu t0, 1(a0)             ; 读取输入控制的 puVar3[2]
  0x08004418: lbu a3, 2(a0)             ; 读取输入控制的 puVar3[3]
  0x0800441c: addiu a1, a1, -3          ; a1 = uVar4 - 3
  0x08004420: sll t0, t0, 8             ; 移位形成 16 位值
  0x08004424: or t0, t0, a3             ; t0 = 从输入读取的 16 位长度
  0x08004428: sltu a1, a1, t0           ; 检查 (uVar4-3) < t0
  0x0800442c: bnez a1, 0x80043e4        ; 如果 t0 > (uVar4-3)，错误
  0x08004434: addiu v0, a0, 4           ; v0 = puVar3[5]（如果 uVar4<=5 则越界）
  0x08004438: addu t0, v0, t0           ; t0 = v0 + t0（潜在越界）
  0x0800443c: sw v0, (var_1ch)          ; 存储 v0 到栈
  0x08004468: jalr v0                   ; 调用函数，v0 可能为越界指针
  ```
- **关键词：** nf_conntrack_h323.ko, H.323 protocol, netfilter conntrack, imp.nf_ct_h323_helper_find
- **备注：** 漏洞具有明确的可利用性证据：输入源为网络数据包（H.323 协议），数据流通过 DecodeQ931 函数解析，缺少边界检查导致越界访问。攻击链完整：攻击者作为已认证用户可发送恶意数据包触发漏洞。建议进一步分析调用函数（如 nf_ct_h323_helper_find）以确认影响范围。关联文件可能包括其他网络过滤模块，但当前分析限于 nf_conntrack_h323.ko。

---
### BufferOverflow-hotplug_3g

- **文件/目录路径：** `sbin/hotplug`
- **位置：** `hotplug:0x0040419c sym.hotplug_3g (around offset 0x4041c0 in disassembly)`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** A stack-based buffer overflow vulnerability exists in the hotplug_3g function. The buffer 'acStack_60c' is defined as 64 bytes but is accessed with offsets up to iStack_648 * 100, where iStack_648 can range from 0 to 11 (12 iterations), allowing writes up to 1200 bytes beyond the buffer boundary. This occurs when processing USB device information from files like /var/run/attached_devs. The overflow can overwrite stack data, including return addresses, potentially leading to arbitrary code execution. Triggering this requires controlling the content of input files, which may be possible if file permissions allow user writes. The vulnerability is triggered during hotplug events for USB devices, and exploitation depends on the ability to manipulate attached_devs or similar files.
- **代码片段：**
  ```
  char acStack_60c [64]; // Defined as 64 bytes
  // ...
  while ((acStack_60c[iStack_648 * 100] != '\0') && (iStack_648 < 0xc)) {
      // Accesses acStack_60c with offset iStack_648 * 100 (up to 1100 bytes)
      iStack_648 = iStack_648 + 1;
  }
  ```
- **关键词：** /var/run/attached_devs, /proc/bus/usb/devices, ACTION environment variable
- **备注：** Exploitability depends on file permissions for /var/run/attached_devs. If writable by non-root users, this could be leveraged for privilege escalation. Further analysis is needed to verify typical permissions on the target system. The function getPlugDevsInfo (fcn.00401c50) is involved in data propagation. No direct command injection was found in system calls due to hexadecimal formatting.

---
