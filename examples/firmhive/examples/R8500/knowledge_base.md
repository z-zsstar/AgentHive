# R8500 (8 个发现)

---

### AuthBypass-utelnetd

- **文件/目录路径：** `bin/utelnetd`
- **位置：** `utelnetd:0x000090a4 main function (child process code after fork)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** utelnetd 缺少身份验证机制，在处理 telnet 连接时直接执行登录 shell，且以 utelnetd 的进程权限运行（通常为 root）。攻击者（已登录的非 root 用户）可通过连接到 telnet 服务获得 root shell，实现权限提升。触发条件：utelnetd 以 root 权限运行（常见于嵌入式系统以绑定特权端口），且攻击者能访问 telnet 端口。利用方式：攻击者使用 telnet 客户端连接至设备，系统直接执行登录 shell 而不验证用户身份，从而授予 root 权限。代码逻辑中，在 fork 后的子进程内调用 execv 执行登录 shell，无任何身份验证检查。
- **代码片段：**
  ```
  iVar15 = sym.imp.fork();
  // ...
  if (iVar15 == 0) {
      // child process
      // ... 
      sym.imp.execv((*0x9aec)[2],*0x9aec + 3);
  }
  ```
- **关键词：** network interface (telnet port), command-line option -l for login shell path
- **备注：** 此漏洞依赖 utelnetd 以高权限（如 root）运行。默认配置中，utelnetd 常以 root 启动以绑定端口 23。建议检查运行时环境确认权限设置。未发现其他可利用漏洞（如缓冲区溢出），因为代码中的 strcpy/strncpy 使用受限或数据不可控（如 ptsname 长度固定）。

---
### CommandInjection-minidlna-fcn.0000bd6c

- **文件/目录路径：** `usr/sbin/minidlna.exe`
- **位置：** `minidlna.exe:0xbd6c fcn.0000bd6c`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the minidlna.exe binary due to the use of the `system` function with user-controlled input. In function fcn.0000bd6c (likely a configuration parser or command-line handler), the `system` function is called with a string constructed from input parameters (case 6 in the switch statement). An attacker can exploit this by providing crafted input that includes shell metacharacters, leading to arbitrary command execution. This is triggered when processing specific command-line options or configuration settings, allowing a local user (with valid credentials) to escalate privileges or execute unauthorized commands. The vulnerability is directly reachable via command-line arguments or configuration files, and exploitation does not require root access.
- **代码片段：**
  ```
  // From decompilation at 0xc0bc (case 6):
  sym.imp.snprintf(*(puVar24 + -0x10b8),0x1000,*0xcdf0);
  sym.imp.system(*(puVar24 + -0x10b8));
  ```
- **关键词：** system, argv, minidlna.conf
- **备注：** This vulnerability requires the attacker to have access to the command-line interface or ability to modify configuration files. Since the user is non-root but has login credentials, they can likely invoke minidlna.exe with malicious arguments or modify configuration in their scope. Further analysis is needed to confirm if network-based input can trigger this, but local exploitation is feasible. Recommend checking for other instances of `system` calls and input validation throughout the code.

---
### Command-Injection-hd-idle-main

- **文件/目录路径：** `sbin/hd-idle`
- **位置：** `hd-idle:0x00009430 main (sprintf 调用), hd-idle:0x00009438 main (system 调用)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'hd-idle' 程序中发现命令注入漏洞，允许攻击者通过命令行参数执行任意命令。程序使用 sprintf 格式化用户提供的磁盘名称到命令字符串 'hdparm -y /dev/%s'，然后通过 system 调用执行。由于输入未经过滤，攻击者可以注入恶意命令分隔符（如分号或反引号）来执行任意系统命令。触发条件：当程序以特权（如 root）运行时，攻击者通过 -a 或 -t 选项提供恶意参数。利用方式：例如，执行 'hd-idle -a "disk; malicious_command"' 可在设备上运行恶意命令。
- **代码片段：**
  ```
  0x0000941c      b8119fe5       ldr r1, str.hdparm__y__dev__s ; [0x98df:4]=0x61706468 ; "hdparm -y /dev/%s"
  0x00009420      013083e3       orr r3, r3, 1
  0x00009424      4830c4e5       strb r3, [r4, 0x48]
  0x00009428      124e8de2       add r4, string
  0x0000942c      0400a0e1       mov r0, r4                  ; char *s
  0x00009430      acfdffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  0x00009434      0400a0e1       mov r0, r4                  ; const char *string
  0x00009438      6bfdffeb       bl sym.imp.system           ; int system(const char *string)
  ```
- **关键词：** 命令行参数（-a, -t）, 磁盘名称字符串, system 调用, sprintf 格式化字符串
- **备注：** 漏洞利用需要程序以足够权限运行（如 root）。在固件环境中，hd-idle 通常以 root 权限运行以管理磁盘，因此攻击链完整。建议验证程序在目标系统中的权限设置。后续可检查其他输入点（如配置文件或环境变量）是否也存在类似问题。

---
### BufferOverflow-SOAP-Upnpd

- **文件/目录路径：** `usr/sbin/upnpd`
- **位置：** `sbin/upnpd:0x0001d680 fcn.0001d680`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在函数 fcn.0001d680（处理 SOAP 请求）中，存在多个不安全的字符串操作，如 strcpy 和 strncpy，用于将用户控制的输入复制到固定大小的栈缓冲区中，缺少适当的边界检查。具体触发条件：当处理恶意的 UPnP SOAP 请求时，如果请求数据（如 XML 内容或头部）超过目标缓冲区大小，可导致栈缓冲区溢出。这可能覆盖返回地址或关键变量，允许攻击者控制程序执行流。潜在攻击方式：攻击者可以构造一个特制的 UPnP 请求发送到 upnpd 服务（通常监听 1900/5000 端口），触发溢出并执行任意代码。由于 upnpd 通常以 root 权限运行，成功利用可能导致设备完全妥协。攻击链完整：输入点（网络接口）→数据流（SOAP 处理）→缓冲区溢出→任意代码执行。
- **代码片段：**
  ```
  sym.imp.strcpy(puVar19 + -0x294, param_1); // 潜在溢出点
  sym.imp.strncpy(puVar19 + -0x54, iVar4, iVar5); // 可能溢出
  ```
- **关键词：** upnp_turn_on, lan_ipaddr, wan_ipaddr, UPnP protocol, fcn.0001d680, fcn.0001bb00, fcn.0001bf7c
- **备注：** 建议进一步验证：通过动态测试（如发送超长 SOAP 请求）确认崩溃和利用可能性。关联文件：/etc/config/upnpd（配置可能影响服务行为）。后续分析方向：检查其他函数（如 fcn.00024360 用于 UPnP 事件处理）是否类似漏洞，并分析系统调用（如 system）是否可能用于命令注入。攻击者是已连接到设备并拥有有效登录凭据的非root用户，可能通过网络访问触发漏洞。

---
### Command-Injection-main

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0xc050 main函数`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** 命令注入漏洞存在于主函数中，当程序读取NVRAM变量并使用sprintf将其插入到格式字符串中，然后通过system函数执行。攻击者可以通过设置恶意NVRAM变量值（如包含分号或反引号的命令）注入任意命令。由于程序可能以root权限运行，成功利用可导致远程代码执行和权限提升。触发条件：攻击者能够修改特定的NVRAM变量（如wan_ipaddr），并触发acos_service执行相关代码路径。
- **代码片段：**
  ```
  uVar5 = sym.imp.acosNvramConfig_get(*0xd460);
  sym.imp.sprintf(iVar9, *0xd39c, uVar5);
  sym.imp.system(iVar9);
  ```
- **关键词：** NVRAM变量指向*0xd460（例如wan_ipaddr）, 格式字符串指向*0xd39c
- **备注：** 需要验证NVRAM变量是否可通过用户接口（如web UI）设置。建议进一步分析格式字符串内容以确认注入点。攻击链完整：输入点（NVRAM）→数据流（sprintf）→危险操作（system）。

---
### Stack-Buffer-Overflow-fcn.0000c99c

- **文件/目录路径：** `bin/wps_monitor`
- **位置：** `wps_monitor:0xc99c fcn.0000c99c`
- **风险评分：** 8.0
- **置信度：** 7.0
- **描述：** 在函数 fcn.0000c99c 中，存在栈缓冲区溢出漏洞，由于使用 strcat 将来自 NVRAM 的字符串拼接到固定大小的栈缓冲区（256 字节）时未进行长度检查。攻击者作为已认证用户可以通过设置恶意的 NVRAM 变量（如长字符串）来触发溢出，覆盖栈上的返回地址，从而可能执行任意代码。漏洞触发条件包括：攻击者控制 NVRAM 变量值（例如通过 nvram_set 或其他接口）、函数被调用（可能通过 WPS 相关网络请求或系统操作）。利用方式包括：构造长字符串覆盖返回地址，指向栈上的 shellcode 或利用现有代码片段。代码逻辑中，循环内的 strcat 操作可能导致多次拼接，加剧溢出风险。约束条件包括缓冲区大小固定（256 字节），但缺乏边界检查。
- **代码片段：**
  ```
  反编译代码片段（基于 Radare2 输出）：
  if (*(puVar27 + -0x304) != '\0') {
      iVar6 = sym.imp.strlen(puVar27 + -0x304);
      sym.imp.memcpy(puVar27 + iVar6 + -0x304, *0xda88, 2);
  }
  sym.imp.strcat(puVar27 + -0x304, iVar5);  // iVar5 来自 NVRAM 数据，未检查长度
  ```
- **关键词：** NVRAM 变量通过指针 *0xd9b8、*0xda4c 等访问（具体变量名需进一步验证，但可能涉及 WPS 配置如 'wps_mode' 或 'wps_uuid'）, 栈缓冲区地址 puVar27 + -0x304 和 puVar27 + -0x404
- **备注：** 漏洞可能被用于本地权限提升或远程代码执行（如果函数可通过网络触发）。需要进一步验证具体 NVRAM 变量名和函数触发机制（例如通过分析调用 fcn.0000c99c 的代码路径）。栈布局和保护机制（如 ASLR、栈保护）在嵌入式设备中可能较弱，增加可利用性。建议后续分析关联组件（如 HTTP 服务或 IPC）以确认输入点传播。

---
### Buffer-Overflow-main

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0xc050 main函数`
- **风险评分：** 7.0
- **置信度：** 7.0
- **描述：** 栈缓冲区溢出漏洞存在于主函数中，当程序使用strcpy将NVRAM变量值复制到栈缓冲区时，未进行边界检查。攻击者可以通过设置过长的NVRAM变量值溢出缓冲区，可能覆盖返回地址并执行任意代码。由于程序可能以root权限运行，成功利用可导致权限提升。触发条件：攻击者能够修改特定的NVRAM变量（如http_passwd）为长字符串，并触发acos_service执行相关代码路径。
- **代码片段：**
  ```
  uVar5 = sym.imp.acosNvramConfig_get(*0xd13c);
  sym.imp.strcpy(iVar20 + -0xab0, uVar5);
  ```
- **关键词：** NVRAM变量指向*0xd13c（例如http_passwd）, 文件路径/tmp/opendns.flag
- **备注：** 需要确认栈布局和偏移以精确计算溢出点。建议测试缓冲区大小和覆盖可能性。攻击链完整：输入点（NVRAM）→数据流（strcpy）→危险操作（缓冲区溢出）。

---
### BufferOverflow-nvram-version

- **文件/目录路径：** `usr/sbin/nvram`
- **位置：** `sbin/nvram:0x00008924 (函数 fcn.00008924 中的 'version' 命令分支)`
- **风险评分：** 6.5
- **置信度：** 7.5
- **描述：** 在 'sbin/nvram' 二进制文件中发现一个缓冲区溢出漏洞，位于 'version' 命令处理逻辑中。当执行 'nvram version' 命令时，程序从 NVRAM 检索变量（如 'pmon_ver' 和 'os_version'）并使用 strcat 函数将它们连接到固定大小的栈缓冲区（0x20000 字节）中，缺少边界检查。如果攻击者通过 'nvram set' 命令将这些变量设置为长字符串（总长度超过 0x20000 字节），将导致栈缓冲区溢出。攻击者可以精心构造溢出数据，覆盖返回地址并执行任意代码。触发条件：攻击者拥有有效登录凭据（非 root 用户），先设置 'pmon_ver' 和 'os_version' 为恶意长字符串，然后执行 'nvram version'。潜在利用方式包括执行 shellcode 或系统命令，但由于二进制文件以用户权限运行，无法直接提升权限，可能用于逃避受限 shell 或执行未授权操作。
- **代码片段：**
  ```
  从反编译代码提取的相关片段：
  puVar19 = iVar20 + -0x20000 + -4;
  sym.imp.memset(puVar19, 0, 0x20000);
  iVar1 = sym.imp.nvram_get(iVar10 + *0x8ef8); // 获取 'pmon_ver'
  if (iVar1 == 0) {
      iVar1 = iVar10 + *0x8f0c; // 默认字符串
  }
  sym.imp.strcat(puVar19, iVar1); // 无边界检查的字符串连接
  // 后续还有多个 strcat 和 memcpy 操作
  ```
- **关键词：** pmon_ver, os_version, version, set
- **备注：** 漏洞利用需要攻击者能设置 NVRAM 变量，而 'nvram' 文件权限为 -rwxrwxrwx，允许任何用户执行，因此可能可行。进一步验证需要确认栈布局和偏移量，以及设备是否启用 ASLR。建议测试溢出是否确实能覆盖返回地址。

---
