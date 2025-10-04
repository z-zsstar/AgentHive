# _US_AC9V1.0BR_V15.03.05.14_multi_TD01.bin.extracted (10 个发现)

---

### CommandInjection-tpi_sys_cfg_download

- **文件/目录路径：** `lib/libtpi.so`
- **位置：** `libtpi.so:0x00009994 (tpi_sys_cfg_download)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** The function `tpi_sys_cfg_download` contains a command injection vulnerability due to improper sanitization of user-provided input. Attackers can inject arbitrary commands by controlling the input parameters, which are used in shell commands via `sprintf` and executed with `doSystemCmd`. This function is typically accessed through configuration management features (e.g., file upload/download in web interfaces), and successful exploitation allows root-level command execution. The vulnerability is triggered when user input contains shell metacharacters (e.g., ;, &, |) that are not filtered before command construction.
- **代码片段：**
  ```
  Key vulnerable code sections:
  - \`sprintf\` used to format commands with user input: e.g., 'grep -Ev "%s" /etc/tmp_cfg > /etc/tmp.cfg'
  - \`doSystemCmd\` executing the constructed commands without sanitization
  Example from disassembly:
    sym.imp.sprintf(buffer, "grep -Ev \"%s\" /etc/tmp_cfg > /etc/tmp.cfg", user_input);
    loc.imp.doSystemCmd(buffer);
  ```
- **关键词：** NVRAM variables used in command patterns (e.g., from `GetValue` calls), File paths: /etc/tmp.cfg, /etc/tmp_cfg, /etc/tmp_url.cfg, IPC or web interface calls to `tpi_sys_cfg_download`
- **备注：** This vulnerability is highly exploitable due to the direct use of user input in shell commands. Attackers with valid login credentials (non-root) can trigger it via network services. Further analysis should verify the input sources and context in calling applications. The function `tpi_upfile_handle` may serve as an entry point when called with type=1.

---
### StackOverflow-tcpConnector

- **文件/目录路径：** `lib/modules/NetUSB.ko`
- **位置：** `NetUSB.ko:0x0800ffac sym.tcpConnector`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A stack buffer overflow vulnerability exists in the 'sym.tcpConnector' function. The function copies input data using memcpy without proper bounds checking after calling strlen on the input. The destination buffer is only 32 bytes (0x20), but the copy length is determined solely by strlen, allowing overflow if input exceeds 32 bytes. This can lead to arbitrary code execution or privilege escalation by overwriting return addresses or other stack data. The function handles TCP connections, making it remotely accessible. Attackers can exploit this by sending crafted network packets to the service, potentially gaining kernel-level access.
- **代码片段：**
  ```
  0x0800ff98      0500a0e1       mov r0, r5                  ; int32_t arg1
  0x0800ff9c      feffffeb       bl strlen                   ; RELOC 24 strlen
  0x0800ffa0      0510a0e1       mov r1, r5                  ; int32_t arg_e4h
  0x0800ffa4      0020a0e1       mov r2, r0
  0x0800ffa8      0400a0e1       mov r0, r4                  ; int32_t arg1
  0x0800ffac      feffffeb       bl memcpy                   ; RELOC 24 memcpy
  ```
- **关键词：** sym.tcpConnector, memcpy, strlen, ks_accept
- **备注：** The function 'sym.tcpConnector' is likely called during TCP connection handling, but no direct cross-references were found within the module. Further analysis of module initialization or external callers is needed to confirm the exact trigger. The vulnerability is highly exploitable due to the clear lack of bounds checking and the network-accessible nature of the function.

---
### stack-buffer-overflow-fcn.0000a7e0

- **文件/目录路径：** `usr/bin/app_data_center`
- **位置：** `app_data_center:0xa954 (sprintf call in function fcn.0000a7e0)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在函数 fcn.0000a7e0 中，存在栈缓冲区溢出漏洞，源于不安全使用 sprintf 处理文件 '/tmp/usb/UsbVolumeInfo' 的内容。文件内容被读入栈缓冲区（大小 2047 字节），并解析以分号分隔的令牌。一个令牌（var_28h）用于 sprintf 调用，格式为 '%s%s' 和固定字符串 '/var/etc/upan/'，未进行长度验证。sprintf 缓冲区位于栈上偏移 0x17bc 处，大小约 236 字节。如果令牌超过 221 字节（236 - len('/var/etc/upan/')），将溢出缓冲区，覆盖相邻栈数据包括保存的返回地址（pc）。触发条件：攻击者通过登录凭据写入恶意文件到 '/tmp/usb/UsbVolumeInfo'，包含长令牌；当函数处理该文件时（可能通过 USB 相关服务调用），溢出发生，导致任意代码执行。潜在攻击方式包括覆盖返回地址以控制程序流。约束条件：缓冲区大小固定，但令牌长度无限制；缺少边界检查。
- **代码片段：**
  ```
  0x0000a944      062b4be2       sub r2, var_1800h
  0x0000a948      0c2042e2       sub r2, r2, 0xc
  0x0000a94c      382042e2       sub r2, r2, 0x38
  0x0000a950      0200a0e1       mov r0, r2                  ; char *s
  0x0000a954      0310a0e1       mov r1, r3                  ; 0x1af04 ; "%s%s" ; const char *format
  0x0000a958      0c2f0ae3       movw r2, 0xaf0c
  0x0000a95c      012040e3       movt r2, 1                  ; 0x1af0c ; "/var/etc/upan/"
  0x0000a960      28301be5       ldr r3, [var_28h]           ; 0x28 ; 40
  0x0000a964      85fbffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  ```
- **关键词：** /tmp/usb/UsbVolumeInfo, fcn.0000a7e0, sprintf, fcn.00012488, fcn.00012a8c
- **备注：** 函数被 fcn.00009de8 调用（通过 XREF 在 0x9e5c），建议进一步分析以确认调用上下文。二进制可能缺乏 ASLR 或其他嵌入式系统常见保护，使利用更容易。攻击者需有写入 '/tmp/usb/UsbVolumeInfo' 的权限，这通过登录凭据可行。建议使用 snprintf 进行边界检查或验证令牌长度。

---
### integer-overflow-fcn.0000d6c0

- **文件/目录路径：** `usr/bin/app_data_center`
- **位置：** `app_data_center:0x0000c928 (strcpy call in function fcn.0000c928, via chain from fcn.0000d6c0)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在函数 fcn.0000d6c0 的调用链中，存在整数溢出导致缓冲区溢出的漏洞。污点数据从 fcn.0000d6c0 的参数（param_1、param_2、param_3、param_4）传播，通过子函数 fcn.0000ce54 和 fcn.0000c928。在 fcn.0000c928 中，内存分配大小计算为 ppuVar5[-3] + 3，如果 ppuVar5[-3]（派生自污点数据）值很大（如 0xFFFFFFFD），会发生整数溢出，导致分配过小缓冲区。随后，strcpy 操作将污点数据复制到该缓冲区，造成缓冲区溢出。触发条件：攻击者通过不可信输入（如网络数据）控制参数，使长度值溢出。利用方式：通过精心构造的输入，攻击者可覆盖内存，执行任意代码或提升权限。约束条件：分配大小计算易受整数溢出影响；缺少输入验证。
- **代码片段：**
  ```
  从 fcn.0000c928 反编译代码：
  puVar1 = (**(0x4050 | 0x20000))(ppuVar5[-3] + 3);  // 整数溢出可能发生
  sym.imp.strcpy(ppuVar5[-1], ppuVar5[-6]);      // 缓冲区溢出
  ```
- **关键词：** param_1, param_2, param_3, param_4, fcn.0000d290, fcn.0000ce54, fcn.0000c928
- **备注：** 需要验证输入参数是否来自网络接口或用户输入；建议分析 fcn.0000d6c0 的调用上下文以确认可控性。关联文件可能涉及 HTTP 处理组件。整数溢出路径风险较高，建议优先修复。

---
### 无标题的发现

- **文件/目录路径：** `sbin/udevd`
- **位置：** `dbg.main:0x0000b35c (case 6) and dbg.udev_event_process:0x00009f84 (call to run_program)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** The udevd daemon processes socket messages that allow setting environment variables via a specific message type (case 6 in main function). These environment variables are later used in command execution through the `run_program` function when applying udev rules. The `udev_rules_apply_format` function expands environment variables in rule commands without sufficient sanitization, allowing an attacker to inject malicious commands. An attacker with access to the udevd socket (e.g., as a non-root user with appropriate permissions) can send crafted messages to set environment variables that contain command injection payloads. When udevd processes device events and executes rules, these variables are expanded and executed via `execv` in `run_program`, leading to arbitrary command execution with the privileges of the udevd process (typically root).
- **代码片段：**
  ```
  // From main function, case 6 in switch statement
  case 6:
      iVar12 = puVar24 + 0xfffffc48;
      puVar3 = sym.imp.strchr(iVar12,0x3d); // Find '=' in input
      if (puVar3 == NULL) {
          iVar1 = iVar8 + *0xb728;
          goto code_r0x0000b30c;
      }
      *puVar3 = 0; // Null-terminate key
      if (puVar3[1] != '\0') {
          *(puVar24 + 0xfffffbbc) = puVar3 + 1; // Value
          dbg.log_message(6,iVar8 + *0xb730, iVar16 + 0x48,iVar12);
          sym.imp.setenv(iVar12,puVar3 + 1,1); // Set environment variable
      } else {
          dbg.log_message(6,iVar8 + *0xb72c, iVar16 + 0x48,iVar12);
          sym.imp.unsetenv(iVar12);
      }
      break;
  
  // From udev_event_process, calling run_program
  iVar1 = dbg.run_program(iVar8,iVar1 + 0x20c,iVar2,iVar2); // iVar8 is from expanded rules
  ```
- **关键词：** UDEVD_SOCKET_PATH (from socket bind in main), ENV variables set via setenv in main case 6, dbg.run_program, dbg.udev_rules_apply_format
- **备注：** This attack requires the attacker to have access to the udevd socket, which may be restricted to root or specific users in some configurations. Further analysis of udev_rules_apply_format is recommended to confirm the exact injection mechanism. The exploit chain involves sending a crafted socket message to set a malicious environment variable, which is then used in a udev rule command. Testing in a real environment is needed to validate exploitability.

---
### heap-buffer-overflow-fcn.0000dfb0

- **文件/目录路径：** `usr/bin/app_data_center`
- **位置：** `app_data_center:0x0000e9e0 (strcpy call in function fcn.0000dfb0)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在函数 fcn.0000dfb0 中，存在堆缓冲区溢出漏洞，源于不安全使用 strcpy 函数。strcpy 被调用以将源字符串（来自动态分配的数组 [s]）复制到目标缓冲区（[dest]），该缓冲区通过 malloc 基于 var_18h 大小分配。然而，复制过程中未检查目标缓冲区剩余大小，如果源字符串过长，将溢出目标缓冲区。触发条件：攻击者通过不可信输入（如 HTTP 请求或 API 参数）控制输入数据，这些数据被处理并存储在 [s] 数组中；当函数构建输出响应时，使用 strcpy 复制这些字符串。潜在攻击方式包括溢出覆盖堆元数据或相邻内存，导致任意代码执行或崩溃。约束条件：目标缓冲区大小基于 var_18h，但源字符串长度无限制；缺少边界检查。
- **代码片段：**
  ```
  0x0000e9d8      1c301be5       ldr r3, [var_1ch]           ; 0x1c ; 28
  0x0000e9dc      0331a0e1       lsl r3, r3, 2
  0x0000e9e0      30201be5       ldr r2, [s]                 ; 0x30 ; 48
  0x0000e9e4      033082e0       add r3, r2, r3
  0x0000e9e8      003093e5       ldr r3, [r3]
  0x0000e9ec      14001be5       ldr r0, [dest]              ; 0x14 ; 20 ; char *dest
  0x0000e9f0      0310a0e1       mov r1, r3                  ; const char *src
  0x0000e9f4      abebffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **关键词：** 参数 arg1 (r0), 参数 arg2 (r1), 参数 r2 (存储在 var_50h), 参数 r3 (存储在 var_54h), 动态数组 [s] (var_30h), 输出缓冲区 [dest] (var_14h)
- **备注：** 漏洞需要攻击者控制输入数据，例如通过网络接口。建议分析函数 fcn.0000d290 以确认数据来源和可控性。堆溢出可能被利用于代码执行，尤其在嵌入式设备缺乏缓解措施时。

---
### command-injection-eapd

- **文件/目录路径：** `usr/bin/eapd`
- **位置：** `bin/eapd:0xb168 (fcn.0000abb8, recv call), bin/eapd:0xa464 (fcn.0000a354, _eval call), bin/eapd:0xa4cc (fcn.0000a354, _eval call)`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** A command injection vulnerability exists in 'eapd' due to improper handling of network input. The attack chain begins when network data is received via the recv function in fcn.0000abb8. This data is passed to fcn.0000a354, where it is used directly as an argument in _eval calls without validation or sanitization. Specifically, at addresses 0xa464 and 0xa4cc in fcn.0000a354, _eval is called with an argument array that includes the uncontrolled network data. An attacker with network access to the socket (likely local, based on strings like '127.0.0.1') can craft malicious input containing shell metacharacters to execute arbitrary commands. Since eapd may run with root privileges, this could lead to privilege escalation. The vulnerability is triggered when specific network packets are processed, and exploitation requires the attacker to have login credentials to access the socket.
- **代码片段：**
  ```
  // From fcn.0000abb8 (network handling):
  param_1 = sym.imp.recv(*(piVar4[-7] + 0x420), piVar4[-4], piVar4[-5], 0);
  // ... then call to fcn.0000a354:
  param_1 = fcn.0000a354(piVar4[-0x34], piVar4[-0xd]);
  
  // From fcn.0000a354 (command execution):
  *(puVar5 + -0x4c) = iVar4 + *0xa588; // e.g., 'wl'
  *(puVar5 + -0x48) = *(puVar5 + -0x54); // network data (param_2)
  *(puVar5 + -0x44) = iVar4 + *0xa58c; // e.g., another string
  *(puVar5 + -0x40) = 0; // null terminator
  sym.imp._eval(puVar5 + iVar2 + -0x54, iVar4 + *0xa590, 0, 0); // command injection point
  ```
- **关键词：** socket:127.0.0.1 (inferred from strings), recv data buffer, _eval command arguments
- **备注：** The exact socket port and accessibility need further verification. The strings at iVar4 offsets (e.g., *0xa590) are likely hardcoded command paths, but their values were not extracted due to binary stripping. Additional analysis of socket setup in fcn.0000abb8 is recommended. This finding is based on static code analysis; dynamic testing could confirm exploitability.

---
### memcpy-buffer-overflow-fcn.0000ba28

- **文件/目录路径：** `usr/bin/app_data_center`
- **位置：** `app_data_center:0x0000bb3c (memcpy call in function fcn.0000ba28, via chain from fcn.0000d6c0)`
- **风险评分：** 8.0
- **置信度：** 8.5
- **描述：** 在函数 fcn.0000d6c0 的调用链中，存在 memcpy 缓冲区溢出漏洞。污点数据从 fcn.0000d6c0 的参数 param_4 传播到 fcn.0000ba28 中的 memcpy 操作。memcpy 的源指针（*param_1）和大小参数（*(param_1 + 4)）都来自污点数据。如果攻击者控制 param_4（例如通过用户输入），可操纵这些值导致 memcpy 缓冲区溢出。触发条件：param_4 指向攻击者控制的数据结构，其中 *param_1 和 *(param_1 + 4) 被设置为恶意值。利用方式：攻击者可使 memcpy 复制过多数据，覆盖相邻内存，实现代码执行。在 fcn.0000d6c0 中，fcn.0000ba28 被多次调用（如 with param_4 和常量大小），但 param_4 可控时漏洞可触发。约束条件：memcpy 参数未验证；缺少边界检查。
- **代码片段：**
  ```
  从 fcn.0000ba28 反编译代码：
  mov r1, r2  // r2 = *param_1 (污点源)
  mov r2, r3  // r3 = *(param_1 + 4) (污点大小)
  bl sym.imp.memcpy  // 危险操作
  ```
- **关键词：** param_4, fcn.0000ba28
- **备注：** 需要确认 param_4 在 fcn.0000d6c0 中的来源；建议检查所有 fcn.0000ba28 调用点。关联函数包括 fcn.0000b990，但当前路径完整。

---
### Permission-Vulnerability-shadow

- **文件/目录路径：** `etc_ro/shadow`
- **位置：** `shadow`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** shadow 文件对所有用户可读（权限为 -rwxrwxrwx），泄露了 root 用户的密码哈希（MD5 格式：$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1）。攻击者（非 root 用户但拥有有效登录凭据）可以轻松读取该文件，获取哈希值，并使用离线破解工具（如 John the Ripper）尝试破解密码。触发条件是攻击者具有文件读取权限，无需特殊条件。约束条件是密码必须足够弱以便在合理时间内破解；如果密码强度高，利用可能失败。潜在攻击包括权限提升：一旦破解 root 密码，攻击者可以执行任意命令作为 root。攻击链完整：输入点（文件读取） -> 数据流（哈希泄露） -> 危险操作（密码使用用于认证和权限提升）。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **关键词：** shadow
- **备注：** 密码哈希使用 MD5，这是一种相对较弱的哈希算法，易于破解如果密码简单。攻击链依赖于密码强度，但文件权限不当是明确的漏洞。建议修复文件权限（例如，设置为仅 root 可读）并强制使用强密码或更安全的哈希算法（如 SHA-512）。后续分析可验证密码实际强度或检查其他敏感文件是否存在类似权限问题。

---
### PrivEsc-passwd

- **文件/目录路径：** `etc_ro/passwd`
- **位置：** `passwd`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** passwd 文件包含用户密码哈希，且这些哈希暴露给非特权用户。攻击者作为已登录的非 root 用户（拥有有效凭据）可以读取 /etc/passwd 文件获取哈希。哈希使用弱加密算法（如 DES 用于 admin、support、user、nobody 用户，root 使用 MD5），可能对应默认或弱密码，易于离线破解。一旦破解，攻击者可使用 'su' 命令切换到 root 或 admin 用户，获得完全系统权限。触发条件：攻击者拥有 shell 访问权限且 /etc/passwd 文件可读（通常全局可读）。潜在利用方式包括使用工具如 John the Ripper 破解哈希后执行权限提升。
- **代码片段：**
  ```
  root:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:root:/:/bin/sh
  admin:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **关键词：** /etc/passwd
- **备注：** 需要进一步验证密码哈希是否对应弱或默认密码（例如使用密码破解工具）。建议检查系统是否使用 /etc/shadow 用于安全存储，并分析其他组件（如 FTP 服务使用 'nobody' 用户）是否加剧风险。后续分析方向：测试哈希破解并检查 su 权限配置。

---
