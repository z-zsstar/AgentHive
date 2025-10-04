# _US_AC15V1.0BR_V15.03.05.18_multi_TD01.bin.extracted (23 个发现)

---

### key-exposure-privkeySrv.pem

- **文件/目录路径：** `webroot_ro/pem/privkeySrv.pem`
- **位置：** `privkeySrv.pem`
- **风险评分：** 9.5
- **置信度：** 10.0
- **描述：** The file 'privkeySrv.pem' contains a valid RSA private key in PEM format. It has world-readable, writable, and executable permissions (-rwxrwxrwx), allowing any user, including non-root users with valid login credentials, to read and potentially modify the private key. This exposure enables attackers to steal the key, which could be used to decrypt secure communications (e.g., TLS/SSL traffic), impersonate the server, perform man-in-the-middle attacks, or forge digital signatures if the key is actively used by services. The trigger condition is straightforward: an attacker simply needs to read the file, which requires no elevated privileges or complex exploitation steps. Constraints include the key's validity and its usage in cryptographic operations, but the lack of access controls makes exploitation highly probable.
- **代码片段：**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEAp/iFMY2xpU6y9OMkor5N1SOR8mhRJ4aTBEC/5639e5x3zrV5
  fcKr2A9a4kAZbfDKwG+uBF0pvKVbFJK3tqRdnCHK1miIDPAHSN11NFXKr4gHslq3
  21RZLCQPAlLtMgzQR9/pgahweKDkZPCturdajZl7lXhptN8AKlUTGnVxSK9g8JFf
  lwR2Bq5jwrGHjmzkZzyRkY8l+GFD6Ru1eX5LH0rBHoSg1nmX8k/vApIpq1sLzbeB
  ap6wnnVqJ8mI3PsqPXAIDRvHxH97SCCeVVh1jdenau0OKHWLlhVp1vnIj5CfSyCf
  VRPAfS2s9yGz8+tdVW8M6NeJY3hMm61g2BxZkwIDAQABAoIBADgu71ZI38+8SC2T
  QHDTGLOfJzUe4W5IHCrDAa2by/qptoVEvDNthw9I64xcBmV4ski10k4RX2GDKbjy
  7lJAHjOYNgGLi15Qdw9PS+HKhHY8GN72ayMIzp7uHLsZQ8+G66/u3GsLDTu8DUka
  G/IlXDuax/SSB0GBicufEzm5aL/3poIAwJkqdmBvNu52qPhpeiMhDHRS8ReX0fZu
  lqf23I/jAxQ+JL+Li1z8EqUTGl3QdT+5oBl+LMTOJtjhay0JIKCIbefma7KO0bg/
  1ed0IsBVZnS3IKcUuFAozFNi8bFMPC6SuMVwVZQAtn4NbxsL/negsDnxf9gh0CsR
  InqTBIkCgYEA3R0pswbD3uV7RW7G3086AEUMqIhXSN7jbnL6jrbiQ9o65Yd5JvhQ
  oaJkw2nF6RrBKd76azE3HEJduhJTcE8FIW8HmfFCZyTDTqUlA71sG/MRw90CszBd
  iS3UGlpbSjhCLMhP5TkzzVrl0AhdeMgKzXdXbC3/fv2ibjEpGL1DIt0CgYEAwnjl
  Jn9gX1H/E2CXpI5BcpQPYSGcDARI5rsPYEH3i4qHiZICRg4JoV6mzFXTZOifW+MM
  1Aq8I5gkrZuPY/S8/WaKXLRLOOIJ1PGJSIDYsWt/WrrkuNw2nRZ1gb9/YbD8JQ0T
  avCYAt9QXuc5JAf0Hfw1dLf5aHKLoFjp+0nWDy8CgYB2w5A/QZX5Zic1HxAgp8xO
  ksf+yeSgFl/wVj+wYhjcOx5BZOe0/9FHUBNxRqHv19gC5mp5IuEoA5mWNPuuKjNm
  Rt29WPHCtuNUna1o+dhUltVm75Hgr0y+PuhbE0dPcTJSHXGUfIoPdhBUEfoqwr/S
  ppRFXduK2S7iovMg/59M3QKBgB/K19t1U3IB26t1TRUv1G9A2UrNzc8BHFHsHtVj
  s25ylTneTtTZEqX47VfWaBrFFNhWxBAeOSewhb6EAesbZZIfo1sIdou0GFthqUnb
  FpHauxVAHIhEKAGCXG97uP1li7Ma8iO3dYJys5bwQh0r17LXOn38XZ+/qifqoUXd
  ikstAoGBAKfg2UO030hq71xhPoT3OxehgSgT2cTD3vIyoUqiriB/8Zu2xmBjvx3c
  IMdjjimvfrsxeR71fviWKRRU61REkZD7KAa0VF2ekhuUqyUIbte08KJrls8PF/IJ
  71wT0dGe6kZ8s7hIx/arnYZXPHGwqL5Z68+O0p8t3KlBPsOzVV89
  -----END RSA PRIVATE KEY-----
  ```
- **关键词：** privkeySrv.pem
- **备注：** The private key exposure is critical and requires immediate remediation, such as restricting file permissions to root-only access and rotating the key if it has been compromised. Further analysis should verify if this key is used by any services (e.g., web servers, VPNs) to fully assess the impact. Additionally, check for corresponding public keys or certificates in the system to understand the scope of potential attacks.

---
### Vulnerability-group-permissions

- **文件/目录路径：** `etc_ro/group`
- **位置：** `group`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 文件 'group' 具有全局读写权限（777），允许任何用户修改系统组定义。攻击者作为非 root 用户可以直接编辑该文件，添加自己的用户名到 root 组（例如，将 'root:x:0:' 改为 'root:x:0:attacker'）。修改后，攻击者可以通过重新登录会话或使用 'newgrp root' 命令激活 root 组权限，从而获得 root 级别的系统访问。触发条件简单：攻击者只需拥有文件写入权限（已满足），且系统依赖该文件进行组验证（典型行为）。利用方式直接，无需复杂步骤，成功率高的。
- **代码片段：**
  ```
  文件内容: root:x:0:
  文件权限: -rwxrwxrwx 1 user user 10 5月  10  2017 group
  ```
- **关键词：** group
- **备注：** 此漏洞依赖于系统实时读取组文件或通过命令激活更改；在标准 Unix-like 系统中，组更改通常在新会话或使用 'newgrp' 后生效。建议进一步验证系统如何加载组信息（例如，检查是否使用 NSS 或缓存），并检查其他相关文件（如 'passwd' 或 'shadow'）是否存在类似权限问题。此发现可能关联到系统身份验证机制，需人工确认固件中组文件的实际使用场景。

---
### command-injection-fcn.0000ae64

- **文件/目录路径：** `bin/cfmd`
- **位置：** `cfmd:0xae64 fcn.0000ae64`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** The 'cfmd' daemon contains a command injection vulnerability that allows authenticated non-root users to execute arbitrary commands with root privileges. The attack chain starts from the Unix domain socket '/var/cfm_socket', which is accessible to non-root users due to missing permission restrictions. When a client connects, messages are received and processed by functions like RecvMsg and passed to command execution via doSystemCmd. In function fcn.0000ae64, user-controlled data from NVRAM variables or socket messages is incorporated into system commands using sprintf and then executed via doSystemCmd without proper input validation or sanitization. For example, commands like 'ifconfig' and 'reboot' are constructed with user input, allowing injection of shell metacharacters. An attacker can exploit this by sending crafted messages to the socket or manipulating NVRAM variables to execute arbitrary commands, leading to full system compromise.
- **代码片段：**
  ```
  // Example from fcn.0000ae64 decompilation:
  // User input from NVRAM or socket is used in sprintf
  sprintf(buffer, "ifconfig %s hw ether %s", interface, user_controlled_mac);
  doSystemCmd(buffer);
  // No validation on user_controlled_mac, allowing injection of commands like "; malicious_command"
  ```
- **关键词：** /var/cfm_socket, bcm_nvram_get, bcm_nvram_set, doSystemCmd
- **备注：** The vulnerability requires the attacker to have access to the Unix socket, which may be world-writable based on default permissions. Further verification is needed on the socket permissions in a live system. The function fcn.0000ae64 handles multiple system commands, and similar patterns may exist in other functions. Recommended to check all uses of doSystemCmd and sprintf/strcpy for similar issues.

---
### 无标题的发现

- **文件/目录路径：** `lib/modules/privilege_ip.ko`
- **位置：** `privilege_ip.ko:0x08000228 (fcn.080001e8) and 0x08000398 (pi_rcv_msg)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A buffer overflow vulnerability exists in the 'privilege_ip.ko' kernel module due to lack of bounds checking when adding entries to the global array 'g_k_privi_ip_item'. The function 'fcn.080001e8' (called from 'pi_rcv_msg' with arg1=0) uses memcpy to copy 8 bytes of user-controlled data from message parameters into the array. The array size is fixed at 60 elements (480 bytes), but the count stored at offset 0x1e0 in the global structure is incremented without checking against the array limit. An attacker can send more than 60 messages of type 0 to overflow the array, corrupting adjacent kernel memory. This can lead to kernel crash or privilege escalation by overwriting critical data structures. The vulnerability is triggered when processing messages via 'pi_rcv_msg', which is likely registered as a message handler during module initialization.
- **代码片段：**
  ```
  In fcn.080001e8:
  0x08000228: add r0, r5, r7, lsl 3  ; r5 points to g_k_privi_ip_item, r7 is the current index
  0x0800022c: bl memcpy        ; copies 8 bytes from r6 (user data) to the array
  0x08000298: str r2, [r3, 0x1e0]  ; increments the count without bounds check
  
  In pi_rcv_msg:
  0x080003e0: ldr r6, [r5], 4   ; loads message type
  0x0800041c: bl fcn.080001e8   ; called when type is 0
  0x08000430: bl fcn.080001e8   ; called for other types
  ```
- **关键词：** g_k_privi_ip_item, pi_rcv_msg, fcn.080001e8
- **备注：** The vulnerability is highly exploitable as it allows controlled kernel memory corruption. The attack requires sending multiple messages to 'pi_rcv_msg', which must be accessible to the attacker. Further verification is needed on how 'pi_rcv_msg' is invoked (e.g., via IPC or sysfs), but the code logic confirms the overflow. Exploitation could lead to full system compromise. Recommended to test in a controlled environment and patch by adding bounds checks in fcn.080001e8.

---
### StackOverflow-qos_proc_write_debug_level

- **文件/目录路径：** `lib/modules/qos.ko`
- **位置：** `qos.ko:0x080009e8 sym.qos_proc_write_debug_level`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 qos.ko 模块的 qos_proc_write_debug_level 函数中，发现栈缓冲区溢出漏洞。该函数通过 proc 文件系统处理用户输入，使用 sscanf 解析输入字符串时，格式字符串包含无宽度限制的 %s 说明符（例如 'debug_level=%d,%s'），导致用户可控数据溢出栈上的局部缓冲区。触发条件：攻击者向 /proc/qos/debug_level 写入超过栈缓冲区大小的字符串（例如包含长 IP 地址或调试数据）。约束条件：输入大小被限制为 0x1000 字节，但栈缓冲区大小有限（约 0x4c 字节），溢出可能覆盖保存的寄存器（包括 lr），从而控制程序计数器。潜在攻击方式：精心构造的输入可覆盖返回地址，执行内核模式任意代码，提升权限或导致系统崩溃。相关代码逻辑包括 copy_from_user 将用户数据复制到内核缓冲区，随后 sscanf 解析 without 边界检查。
- **代码片段：**
  ```
  0x080009e8: ldr r1, [0x08000b74]  ; 加载格式字符串地址（例如 'debug_level=%d,%s'）
  0x080009ec: add r2, sp, 0x44      ; 局部缓冲区地址
  0x080009f0: mov r3, r7
  0x080009f4: bl sscanf               ; 解析输入，使用 %s 无边界检查
  ...
  0x08000a48: ldr r6, [sp, 0x14]   ; 可能受溢出影响的栈位置
  ```
- **关键词：** /proc/qos/debug_level, g_qos_debug_level
- **备注：** 漏洞已通过反汇编验证，存在完整的攻击链：用户输入 -> proc 写入 -> copy_from_user -> sscanf 溢出 -> 返回地址覆盖。建议进一步验证通过动态测试触发漏洞。关联函数包括 qos_proc_write_enable（但未发现类似漏洞）。后续分析应关注其他输入点如 qos_rcv_msg 和 IPC 通信。

---
### BufferOverflow-fastnat_conf_proc_port_add

- **文件/目录路径：** `lib/modules/fastnat_configure.ko`
- **位置：** `fastnat_configure.ko:0x080003f4 sym.fastnat_conf_proc_port_add`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** The function 'sym.fastnat_conf_proc_port_add' in the 'fastnat_configure.ko' kernel module handles user input from the /proc filesystem entry 'port_add'. It expects input in the format 'layer=%s protocol=%s port=%d' and uses strchr to locate delimiters ('=' and ',') before copying the substring fields into fixed-size stack buffers (16 bytes each) via memcpy. However, no bounds checking is performed on the length of these substrings, allowing stack buffer overflow if any field exceeds 16 bytes. Trigger conditions include writing a malformed string with long 'layer', 'protocol', or 'port' fields to the proc entry. This can corrupt the kernel stack, overwriting adjacent variables or return addresses, leading to denial-of-service or arbitrary code execution in kernel context. Potential attacks involve crafting input to overwrite critical stack data and hijack control flow. The code logic involves multiple memcpy operations (e.g., at addresses 0x08000550, 0x080005a8, 0x08000604) without size validation.
- **代码片段：**
  ```
  0x08000550      feffffeb       bl memcpy                   ; Copy to var_1ch (layer buffer)
  0x080005a8      feffffeb       bl memcpy                   ; Copy to var_ch (protocol buffer)
  0x08000604      feffffeb       bl memcpy                   ; Copy to var_2ch (port buffer)
  // Stack buffers are 16 bytes each, defined via 'var_2ch', 'var_1ch', 'var_ch'
  ```
- **关键词：** proc_fastnat_port_add, /proc/fastnat/port_add
- **备注：** The vulnerability is directly exploitable if the /proc entry is writable by non-root users, which is common in embedded systems. Attack chain involves user writing to /proc/fastnat/port_add with oversized fields. Further analysis should verify proc entry permissions and test for exploitability. Related functions like 'sym.fastnat_conf_proc_port_del' may have similar issues and should be examined.

---
### Command-Injection-formexeCommand

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd:0x7bc0c sym.formexeCommand`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'httpd' 的 `formexeCommand` 函数中发现命令注入漏洞。该函数处理 HTTP 请求中的用户输入，并通过 `doSystemCmd` 执行系统命令。用户输入通过 `fcn.0002babc` 获取，并使用 `strcpy` 复制到固定大小缓冲区（512 字节），缺少边界检查。随后，输入被直接传递给 `doSystemCmd`，允许攻击者注入恶意命令。触发条件：攻击者发送特制 HTTP 请求到暴露的 CGI 端点（如 `/cgi-bin/` 相关路径），需有效登录凭据。利用方式：在输入中嵌入命令分隔符（如 `;`、`|` 或反引号），注入任意命令执行，可能导致权限提升或设备控制。
- **代码片段：**
  ```
  // 从用户输入获取数据
  uVar2 = fcn.0002babc(*(puVar5 + (0xdcec | 0xffff0000) + iVar1 + -0xc), iVar4 + *0x7befc, iVar4 + *0x7bf00);
  *(puVar5 + -0xc) = uVar2;
  // 使用 strcpy 复制输入到缓冲区，缺少边界检查
  sym.imp.strcpy(puVar5 + iVar1 + -0x21c, *(puVar5 + -0xc));
  // 直接使用用户输入执行系统命令
  sym.imp.doSystemCmd(iVar4 + *0x7bf14, puVar5 + iVar1 + -0x21c);
  ```
- **关键词：** HTTP 请求参数, CGI 处理端点, doSystemCmd 函数调用, fcn.0002babc 输入获取
- **备注：** 攻击链完整：从 HTTP 输入点到命令执行。需验证实际 HTTP 端点路径和认证机制。建议检查其他调用 doSystemCmd 的函数（如 formMfgTest）是否存在类似问题。后续分析应关注输入验证函数（如 fcn.0002babc）和 doSystemCmd 的实现。

---
### command-injection-usbeject-handler

- **文件/目录路径：** `usr/bin/app_data_center`
- **位置：** `app_data_center:0x0000a6e8 fcn.0000a6e8`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在函数 fcn.0000a6e8（处理 'usbeject' 命令）中，攻击者可通过控制 'dev_name' 参数注入任意命令。该参数从用户输入中提取，未经过滤或转义，直接嵌入到固定格式字符串 'cfm post netctrl 51?op=3,string_info=%s' 中，并通过 system 函数执行。触发条件：攻击者作为已认证用户（非 root）发送恶意 HTTP 请求（POST 或 GET）调用 'usbeject' 命令，并提供可控的 'dev_name' 参数。约束条件：输入长度受 snprintf 缓冲区限制（0x800 字节），但命令注入仍可行。潜在攻击方式：注入分号或命令分隔符（如 '; rm -rf /' 或反弹 shell），导致任意命令执行，可能提升权限或破坏系统。
- **代码片段：**
  ```
  关键代码片段：
    - 0x0000a730: ldr r0, [var_818h] ; movw r1, 0xaef0 ; movt r1, 1 ; bl fcn.00009b30  // 提取 'dev_name' 值
    - 0x0000a7ac: ldr r3, [var_14h] ; mov r2, r3 ; bl sym.imp.snprintf  // 使用 snprintf 构建命令字符串，格式为 'cfm post netctrl 51?op=3,string_info=%s'
    - 0x0000a7c0: bl sym.imp.system  // 执行命令，存在注入风险
  ```
- **关键词：** param_3 (dev_name), 命令字符串 'cfm post netctrl 51?op=3,string_info=%s', 环境变量 REQUEST_METHOD, 环境变量 QUERY_STRING
- **备注：** 该漏洞需要攻击者拥有有效登录凭据（非 root 用户）并通过网络接口（如 HTTP API）调用 'usbeject' 命令。关联函数：fcn.00009de8（命令分发器）、fcn.00009b30（键值提取）。建议验证实际利用步骤，例如通过 crafted HTTP 请求注入命令。后续分析应检查其他命令处理函数（如 'request'、'usblist'）是否有类似问题。

---
### BufferOverflow-fcn.00015aa8

- **文件/目录路径：** `usr/sbin/nas`
- **位置：** `nas:0x16124 fcn.00015aa8`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** A buffer overflow vulnerability exists in the 'nas' binary due to the use of strcpy without bounds checking in function fcn.00015aa8. The vulnerability is triggered when processing the '-p' command-line option, where user-supplied input is copied to a stack buffer. Specifically, when the input string length is exactly 5 or 13 characters, strcpy is used to copy the string to a local buffer without size validation, leading to a stack-based buffer overflow. This can overwrite critical stack data, including the return address, allowing an attacker to execute arbitrary code. The attack requires the attacker to have valid login credentials and access to the command-line interface, but no root privileges are needed.
- **代码片段：**
  ```
  // From fcn.00015aa8 decompilation
  switch(iVar8 + -5) {
  case 0:
  case 8:
      uVar4 = sym.imp.strlen(*(puVar9 + -0xc));
      *(puVar9 + -0x10) = uVar4;
      sym.imp.strcpy(puVar9 + iVar1 + -0x7c, *(puVar9 + -0xc)); // Vulnerable strcpy call
      break;
  // ... other cases ...
  }
  ```
- **关键词：** Command-line option: -p, Function: fcn.00015aa8, Function: fcn.00014704, Imported function: strcpy
- **备注：** The vulnerability is directly exploitable via command-line input, and the attack chain is verified through static analysis. However, dynamic testing is recommended to confirm the exact stack layout and exploitation feasibility. The binary is stripped, which may complicate analysis, but the vulnerability is clear. Additional vulnerabilities may exist in other functions, but this is the most prominent finding.

---
### format-string-insert_user_in_smbpasswd

- **文件/目录路径：** `usr/sbin/smbpasswd`
- **位置：** `smbpasswd:0x00001a00 sym.insert_user_in_smbpasswd fprintf调用`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在insert_user_in_smbpasswd函数中，fprintf调用直接使用用户控制的字符串作为格式字符串，未提供额外参数。这允许攻击者注入格式说明符（如%s、%x）来泄露栈内存信息，可能导致敏感信息泄露或内存损坏。触发条件：当使用'-a'选项添加用户时，用户名或密码输入被用于构建传递给fprintf的字符串。潜在攻击：已登录的非root用户可通过恶意输入读取栈内存，可能获取系统信息或辅助权限提升。利用方式：攻击者控制命令行输入中的用户名或密码，插入格式说明符。
- **代码片段：**
  ```
  从反编译代码中，关键行：\`fprintf(iVar1, param_2);\` // param_2直接用作格式字符串，无额外参数
  ```
- **关键词：** smbpasswd, main函数中的snprintf构建的字符串
- **备注：** 漏洞基于反编译和污点追踪证据；用户输入从命令行通过snprintf流向fprintf。攻击链完整：输入点（命令行参数）→ 数据流（snprintf构建）→ 危险操作（fprintf）。建议进一步测试以确认泄露的具体内容，但证据表明实际可利用性高。

---
### XSS-initRuleList

- **文件/目录路径：** `webroot_ro/js/parental_control.js`
- **位置：** `parental_control.js: initRuleList 函数（约行 200-210）`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 在 parental_control.js 的规则列表显示功能中，设备名称（devName）用户输入在输出到HTML时未经过转义，直接通过字符串连接插入到HTML属性和内容中。这允许攻击者注入恶意脚本代码。触发条件：攻击者设置包含XSS负载的设备名称（例如 '<script>alert(1)</script>'），然后通过点击界面元素（如 'head_title2'）查看规则列表，导致脚本执行。潜在攻击包括窃取会话cookie、执行任意操作或提升权限。代码中设备名称验证依赖外部函数 checkDevNameValidity，但未在当前文件定义，因此无法确认过滤是否充分。数据流：用户输入设备名称 -> 通过AJAX保存到后端 -> 从后端获取并显示在规则列表 -> 未转义输出。
- **代码片段：**
  ```
  str += "<tr class='tr-row'><td class='fixed' title='" + obj[i].devName + "'>" + obj[i].devName + "</td>" + "<td title='" + obj[i].mac + "'>" + _("MAC address:") + obj[i].mac.toUpperCase() + "</td>";
  // 后续使用 $('#rule_list #list2').html(str) 插入HTML
  ```
- **关键词：** devName, obj[i].devName, goform/SetOnlineDevName, goform/getParentalRuleList
- **备注：** 设备名称验证函数 checkDevNameValidity 和 clearDevNameForbidCode 未在当前文件定义，需进一步分析后端代码（如 'goform' 处理程序）以确认输入过滤和存储是否安全。攻击链依赖于后端返回未过滤的数据，但前端输出未转义是确凿证据。建议验证后端是否对设备名称进行HTML转义或严格过滤。

---
### XSS-showFinish

- **文件/目录路径：** `webroot_ro/js/index.js`
- **位置：** `index.js:约第 600 行 showFinish 函数`
- **风险评分：** 6.5
- **置信度：** 9.0
- **描述：** 在 'index.js' 文件中发现一个存储型 XSS 漏洞。攻击者可以通过设置恶意 SSID（WiFi 名称）值，当设置完成页面显示 SSID 时，嵌入的 JavaScript 代码会被执行。具体触发条件为：攻击者登录设备后，在快速设置或 WiFi 设置页面修改 SSID 为恶意脚本（例如 `<script>alert('XSS')</script>`），然后完成设置流程。当用户或攻击者访问设置完成页面时（例如通过 'showFinish' 函数），恶意脚本执行。此漏洞允许攻击者窃取会话 cookie、重定向用户或修改页面内容，但由于攻击者已拥有登录凭据，风险被部分缓解。代码中缺少对用户输入的 HTML 转义是根本原因。
- **代码片段：**
  ```
  function showFinish() {
      // ... 其他代码 ...
      $("#ssid_2g").html($("#ssid").val());
      $("#ssid_5g").html($("#ssid").val() + "_5G");
      // ... 其他代码 ...
  }
  ```
- **关键词：** SSID 输入字段, goform/fast_setting_wifi_set API 端点, showFinish 函数
- **备注：** 此漏洞需要攻击者拥有登录凭据，但一旦利用，可导致会话劫持。建议后端对 SSID 输入进行严格过滤和转义。此外，应检查其他用户输入点（如 LAN IP、DNS 设置）是否也存在类似问题。后续分析应关注后端 'goform' 端点如何处理这些输入，以识别可能的命令注入或其他漏洞。

---
### DoS-formSetWanErrerCheck

- **文件/目录路径：** `bin/dhttpd`
- **位置：** `dhttpd:0x00034ca0 formSetWanErrerCheck`
- **风险评分：** 6.5
- **置信度：** 7.5
- **描述：** 函数 'formSetWanErrerCheck' 包含一个 DoS 漏洞，允许认证用户通过 HTTP 参数 'no-notify' 触发 'killall -9 dhttpd' 命令。具体攻击链：1) 用户发送 HTTP 请求（例如 POST 到 /goform）包含参数 'no-notify=true'；2) 函数使用 'fcn.000153cc' 获取参数值，并与硬编码字符串（推断为 'true'）比较；3) 如果匹配，设置 NVRAM 变量 'wan.dnsredirect.flag' 并执行 'doSystemCmd' 调用 'killall -9 dhttpd'；4) 导致 web 服务器终止，造成 DoS。攻击条件：攻击者已认证（非 root），但无需特殊权限。漏洞缺乏输入过滤，依赖硬编码比较，易被利用。
- **代码片段：**
  ```
  0x00034d38      0310a0e1       mov r1, r3                  ; 'no-notify' 参数
  0x00034d3c      e8309fe5       ldr r3, [0x00034e2c]        ; 硬编码字符串地址
  0x00034d40      033084e0       add r3, r4, r3              ; 硬编码字符串 'ture'（可能为 'true'）
  0x00034d44      0320a0e1       mov r2, r3                  ; 比较字符串
  0x00034d48      9f81ffeb       bl fcn.000153cc             ; 获取参数值
  ...
  0x00034d70      14101be5       ldr r1, [s2]                ; 参数值
  0x00034d74      7d53ffeb       bl sym.imp.strcmp           ; 字符串比较
  0x00034d78      0030a0e1       mov r3, r0
  0x00034d7c      000053e3       cmp r3, 0                   ; 检查是否匹配
  0x00034d80      0a00001a       bne 0x34db0                 ; 不匹配则跳转
  ...
  0x00034da4      033084e0       add r3, r4, r3              ; 'killall -9 dhttpd' 命令字符串
  0x00034da8      0300a0e1       mov r0, r3                  ; 命令参数
  0x00034dac      3f53ffeb       bl sym.imp.doSystemCmd      ; 执行危险命令
  ```
- **关键词：** HTTP 参数: no-notify, NVRAM 变量: wan.dnsredirect.flag, 命令: killall -9 dhttpd, 函数: fcn.000153cc, IPC/网络接口: HTTP 请求处理
- **备注：** 攻击链完整：从 HTTP 输入到命令执行。硬编码字符串可能为 'true'，基于上下文推断。漏洞需要认证，但利用简单。建议修复：添加输入验证或移除硬编码命令。未发现权限提升或代码执行。

---
### XSS-onlineQueryVersion

- **文件/目录路径：** `webroot_ro/js/directupgrade.js`
- **位置：** `directupgrade.js:50-70 (onlineQueryVersion 函数)`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在 'directupgrade.js' 的 onlineQueryVersion 函数中，服务器返回的 description 字段（包括 description、description_en、description_zh_tw）被直接插入到 HTML 中而没有转义，导致跨站脚本（XSS）漏洞。具体触发条件：当用户访问固件升级页面时，应用程序通过 AJAX 请求从服务器获取版本信息，并将描述内容动态添加到 DOM 中。如果攻击者能够篡改服务器响应（例如通过中间人攻击或控制服务器），注入恶意 JavaScript 代码，则可在用户浏览器中执行任意脚本。利用方式包括窃取会话 cookie、重定向用户或执行其他恶意操作。代码逻辑中缺少对输入数据的验证和过滤，直接使用 innerHTML 等效操作。攻击链完整：从不可信输入（服务器响应）到危险操作（HTML 插入执行）。
- **代码片段：**
  ```
  var description = ver_info.detail.description;
  if (language == "en") {
      description = ver_info.detail.description_en;
  } else if (language == "cn") {
      description = ver_info.detail.description;
  } else if (language == "zh") {
      description = ver_info.detail.description_zh_tw;
  }
  if (description) {
      descriptionArr = description.join("").split("\n");
  } else {
      descriptionArr = ver_info.detail.description[0].split("\n");
  }
  $("#releaseNote").html("");
  for (var i = 0; i < descriptionArr.length; i++) {
      $("#releaseNote").append("<li>" + descriptionArr[i] + "</li>");
  }
  ```
- **关键词：** ver_info.detail.description, ver_info.detail.description_en, ver_info.detail.description_zh_tw, goform/cloudv2?module=olupgrade&opt=queryversion
- **备注：** 此漏洞需要攻击者控制服务器响应或进行中间人攻击，因此可利用性依赖于网络环境。建议进一步分析后端处理程序（如 'goform/cloudv2'）以确认数据源和验证机制。另外，文件上传功能（通过 'goform/SysToolSetUpgrade'）可能也存在漏洞，但需要后端代码分析。攻击者是已登录用户，但利用可能需额外条件如网络控制。

---
### heap-buffer-overflow-fcn.00010364

- **文件/目录路径：** `bin/vsftpd`
- **位置：** `vsftpd:0x1048c fcn.00010364`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在函数 fcn.00010364 中发现一个堆缓冲区溢出漏洞。该函数处理 FTP 命令输入（可能涉及路径或文件名操作），使用 'strcpy' 将用户可控数据复制到动态分配的堆缓冲区中。分配的大小基于输入字符串的计算，但如果源字符串长度超过分配大小，会导致堆缓冲区溢出。攻击者作为已认证用户，可通过发送特制长路径的 FTP 命令（如 CWD）触发此漏洞，可能覆盖堆元数据或函数指针，导致代码执行。漏洞触发条件包括：用户必须拥有有效登录凭据、发送特定 FTP 命令、并提供超长字符串。潜在利用方式包括通过堆溢出实现任意代码执行或服务崩溃。
- **代码片段：**
  ```
  else {
      uVar1 = sym.imp.malloc(*(iVar4 + *0x105e8 + 8) - *(puVar5 + -8));
      *(iVar4 + *0x105f0) = uVar1;
      *(iVar4 + *0x105f0 + 4) = *(iVar4 + *0x105e8 + 4) - *(puVar5 + -8);
      *(iVar4 + *0x105f0 + 8) = *(iVar4 + *0x105e8 + 8) - *(puVar5 + -8);
      sym.imp.strcpy(*(iVar4 + *0x105f0), *(puVar5 + -0xc) + *(puVar5 + -8));
  }
  ```
- **关键词：** NVRAM 变量通过 nvram_xfr 调用间接影响, FTP 命令通道作为输入点
- **备注：** 此漏洞需要进一步验证具体 FTP 命令的触发路径和堆利用可行性。建议分析堆管理器和环境以确认可利用性。关联函数包括 fcn.0000df94（主命令处理循环）和 fcn.0001a0ac（命令字符串比较）。

---
### BufferOverflow-vmstat-fcn.00009300

- **文件/目录路径：** `usr/bin/vmstat`
- **位置：** `vmstat:0x00009300 fcn.00009300 (具体指令地址需反汇编确认，但调用点在 case 0x10 分支)`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在 'vmstat' 二进制文件中，命令行参数处理函数（fcn.00009300）使用 strcpy 函数复制用户提供的参数到固定缓冲区（地址 *0xa1e8），而没有进行边界检查。攻击者作为非root用户，可以通过传递超长命令行参数（例如，使用特定选项如 '-C' 后跟长字符串）触发缓冲区溢出。溢出可能覆盖栈上的返回地址或局部变量，导致任意代码执行在用户上下文。触发条件：执行 'vmstat' 时提供恶意命令行参数。潜在攻击方式：构造 shellcode 或 ROP 链，但需要绕过 ASLR 和确定精确偏移。漏洞由于缺少输入验证和危险函数使用。
- **代码片段：**
  ```
  // 从反编译代码片段（fcn.00009300）
  case 0x10:
      ppcVar15 = ppcVar15 + 1;
      pcVar3 = *ppcVar15;
      if (pcVar3 == NULL) {
          uVar7 = *0xb5b4;
          uVar9 = 0x18;
          // ... 错误处理
      }
      // ... 参数比较逻辑
      sym.imp.strcpy(*0xa1e8, *ppcVar15);  // 漏洞点：strcpy 无边界检查
      break;
  ```
- **关键词：** *0xa1e8, 命令行参数
- **备注：** 缓冲区大小未知，且二进制被剥离，增加利用难度。攻击者需在本地执行，但可能结合其他漏洞提升影响。建议进一步分析缓冲区布局和测试崩溃点。相关函数：fcn.00009300（主命令行处理）、strcpy（危险函数）。后续可检查其他输入点（如文件读取）和组件交互。

---
### FilePermission-Shadow

- **文件/目录路径：** `etc_ro/shadow`
- **位置：** `shadow:1`
- **风险评分：** 6.5
- **置信度：** 6.0
- **描述：** 非root用户由于宽松的文件权限（rwxrwxrwx）可以读取 'shadow' 文件，获取 root 用户的密码哈希（MD5 格式）。攻击者可以利用此哈希进行离线破解（例如使用工具如 John the Ripper 或 Hashcat），如果密码强度弱，可能获得 root 权限。触发条件是非root用户具有文件读权限；约束包括密码复杂性、哈希算法强度（MD5 相对较弱）和破解工具可用性。潜在攻击方式包括密码破解后通过 su 或 ssh 提升权限。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **关键词：** shadow
- **备注：** 文件权限设置异常宽松，可能表示配置错误。需要进一步验证密码哈希的强度以确认实际可利用性（例如通过离线破解测试）。建议检查系统中其他敏感文件的权限，并评估是否有 IPC 或 NVRAM 交互可能加剧此风险。

---
### pptpd-command-injection-unit-ipup-ipdown

- **文件/目录路径：** `bin/pptpd244.sh`
- **位置：** `pptpd244.sh:14-15`
- **风险评分：** 6.0
- **置信度：** 8.0
- **描述：** 参数 unit 在 IPUP 和 IPDOWN 脚本创建时被直接嵌入 shell 命令中，缺少转义或验证。如果 unit 包含 shell 元字符（如分号），攻击者可注入任意命令。当 IPUP/IPDOWN 脚本被执行时（例如在 PPTP 连接事件中），注入命令可能以脚本运行权限（可能 root）执行。触发条件：攻击者能控制 unit 参数，脚本以高权限运行，且 IPUP/IPDOWN 被触发。利用方式：设置 unit 为 '0; malicious_command' 等值。
- **代码片段：**
  ```
  echo "cfm Post netctrl $up &" >> $IPUP
  echo "cfm Post netctrl $down &" >> $IPDOWN
  ```
- **关键词：** unit, pptp_server, cfm, netctrl
- **备注：** 需要验证脚本如何被调用（例如通过网络接口或 IPC）以及运行权限。建议分析调用者（如 cfm 或 netctrl 组件）以确认输入点和数据流。

---
### pptpd-path-traversal-unit-options

- **文件/目录路径：** `bin/pptpd244.sh`
- **位置：** `pptpd244.sh:9-11`
- **风险评分：** 5.5
- **置信度：** 7.5
- **描述：** 参数 unit 用于构建文件路径（如 /etc/ppp/options$unit.pptpd），缺少路径遍历检查。如果 unit 包含 '../' 序列，攻击者可创建或覆盖任意文件，导致权限提升或拒绝服务。触发条件：攻击者控制 unit 参数，脚本有写权限。利用方式：设置 unit 为 '../../../tmp/evil' 以指向系统文件。
- **代码片段：**
  ```
  confile=/etc/ppp/options$unit.pptpd
  IPUP=/etc/ppp/ip-up$unit
  IPDOWN=/etc/ppp/ip-down$unit
  ```
- **关键词：** unit, /etc/ppp/options, /etc/ppp/ip-up, /etc/ppp/ip-down
- **备注：** 文件路径使用绝对目录，但 unit 可控可能绕过预期路径。需要确认脚本运行权限和目标文件系统结构。

---
### DoS-sym._ctf_ipc_add

- **文件/目录路径：** `lib/modules/fastnat.ko`
- **位置：** `fastnat.ko:0x08000ea0 sym._ctf_ipc_add`
- **风险评分：** 5.0
- **置信度：** 8.0
- **描述：** 如果 param_1 为 0 或 param_2 为 NULL，函数进入无限循环，导致拒绝服务。攻击者可通过传递无效参数调用函数，消耗 CPU 资源。触发条件简单，但无法用于代码执行。
- **代码片段：**
  ```
  if ((param_1 == 0) || (param_2 == NULL)) {
      do { /* infinite loop */ } while(true);
  }
  ```
- **关键词：** param_1, param_2
- **备注：** 易于触发，但影响有限。需确认函数是否通过用户空间接口暴露。

---
### heap-buffer-overflow-fcn.0000c8c8-fcn.0000c9f8

- **文件/目录路径：** `bin/vsftpd`
- **位置：** `vsftpd:0xc9a4 fcn.0000c8c8, vsftpd:0xcad4 fcn.0000c9f8`
- **风险评分：** 5.0
- **置信度：** 6.0
- **描述：** 在函数 fcn.0000c8c8 和 fcn.0000c9f8 中发现固定大小堆缓冲区溢出漏洞。这些函数使用 'strcpy' 将从 'nvram_xfr' 返回的数据复制到固定大小的堆缓冲区（0x800 字节）。如果 NVRAM 返回的数据超过 0x800 字节，会导致堆缓冲区溢出。攻击者可能通过间接控制 NVRAM 内容（例如通过其他服务或配置修改）触发此漏洞，但作为非root用户，直接利用可能受限。漏洞触发条件包括：NVRAM 数据被恶意修改、且 vsftpd 访问该数据。潜在利用方式包括堆溢出导致代码执行或服务拒绝。
- **代码片段：**
  ```
  if (*(puVar4 + -8) == 0) {
      sym.imp.free(*(iVar3 + *0xc9e4));
      uVar1 = 0;
  } else {
      sym.imp.strcpy(*(iVar3 + *0xc9e4), *(puVar4 + -8));
      uVar1 = *(iVar3 + *0xc9e4);
  }
  ```
- **关键词：** NVRAM 变量通过 nvram_xfr 调用, 环境变量或配置文件
- **备注：** 这些漏洞的可利用性依赖于攻击者对 NVRAM 的控制能力，在非root用户场景下可能难以直接利用。建议检查 NVRAM 设置权限和与其他组件的交互。关联函数包括 nvram_xfr 调用点。

---
### pptpd-config-injection-dns-parameters

- **文件/目录路径：** `bin/pptpd244.sh`
- **位置：** `pptpd244.sh:44-45`
- **风险评分：** 3.0
- **置信度：** 6.0
- **描述：** 参数 dns1 和 dns2 被直接写入配置文件，缺少输入验证。如果值包含换行符或特殊字符，可能注入额外配置项，但风险较低，因为配置文件可能由 pppd 解析而非直接执行。触发条件：攻击者控制 dns1/dns2 参数。利用方式：设置 dns1 为 '8.8.8.8\nmalicious_config' 尝试配置注入。
- **代码片段：**
  ```
  echo ms-dns $dns1 >> $confile
  echo ms-dns $dns2 >> $confile
  ```
- **关键词：** dns1, dns2, ms-dns
- **备注：** pppd 配置解析可能忽略无效输入，但建议检查 pppd 版本是否存在解析漏洞。低风险，除非其他组件交互。

---
### DoS-sym._ctf_proc_write_enable

- **文件/目录路径：** `lib/modules/fastnat.ko`
- **位置：** `fastnat.ko:0x08001304 sym._ctf_proc_write_enable`
- **风险评分：** 2.0
- **置信度：** 8.0
- **描述：** 函数处理 proc 文件系统写操作时，如果输入大小超过 4096 字节或内存分配失败，进入无限循环，导致拒绝服务。攻击者作为已认证用户，可通过写入 /proc/enable 文件并触发错误路径（如提供过大输入）消耗 CPU 资源，使设备不可用。触发条件简单，但无法用于代码执行或权限提升。
- **代码片段：**
  ```
  if (0x1000 < param_3) {
      do { /* infinite loop */ } while(true);
  }
  iVar1 = __kmalloc(param_3 + 1, 0x20);
  if (iVar1 == NULL) {
      do { /* infinite loop */ } while(true);
  }
  ```
- **关键词：** proc文件系统: /proc/enable
- **备注：** 此漏洞易于触发，但影响有限。建议监控 proc 文件系统的访问控制。无关联其他文件或函数。

---
