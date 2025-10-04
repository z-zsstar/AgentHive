# Archer_C3200_V1_150831 (8 个发现)

---

### command-injection-eapd-fcn.0000a1b0

- **文件/目录路径：** `sbin/eapd`
- **位置：** `eapd:0x0000a1b0 fcn.0000a1b0`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the 'eapd' binary where user-controlled input from a network socket is incorporated into a command executed via _eval without proper sanitization. The vulnerability is triggered when data is received on a specific socket (handled in fcn.0000b0f0) and passed to fcn.0000a1b0, which uses the input in an _eval call. The command is constructed using strings like 'wl%d' and user input, allowing an attacker to inject arbitrary commands by including shell metacharacters. The attack requires the attacker to send malicious data to the vulnerable socket, which is accessible to non-root users with valid login credentials, as the daemon binds to a network port. This leads to full command execution with the privileges of the 'eapd' process, which is typically root, enabling complete system compromise.
- **代码片段：**
  ```
  In fcn.0000a1b0:
      *(puVar3 + -0x38) = param_2;  // param_2 is user input from recv
      *(puVar3 + -0x3c) = *0xa31c;  // points to 'wl%d'
      *(puVar3 + -0x34) = *0xa324;  // points to another string
      sym.imp._eval(puVar3 + -0x3c, *0xa320, iVar1, iVar1);  // command execution with user input
  ```
- **关键词：** Socket descriptor from recv in fcn.0000b0f0, NVRAM variable via nvram_get in fcn.0000c558, IPC via _eval command execution
- **备注：** The vulnerability is highly exploitable due to the direct use of user input in a command execution function. The attack chain is verified from network input to command execution. Further analysis could identify the exact socket port and protocol, but the vulnerability is clear. Additional vulnerabilities may exist, but this is the most critical and exploitable one found.

---
### Command-Injection-UPnP-AddPortMapping

- **文件/目录路径：** `usr/bin/upnpd`
- **位置：** `upnpd:0xbca8 fcn.0000bca8, upnpd:0xecb0 fcn.0000ecb0, upnpd:0xe20c fcn.0000e20c`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 命令注入漏洞存在于 UPnP AddPortMapping 动作处理中。攻击者可以构造恶意的 UPnP 请求，在参数（如 NewExternalPort、NewProtocol、NewInternalClient、NewPortMappingDescription）中注入 shell 元字符（例如 '; malicious_command'）。当程序处理请求时，使用 snprintf 构建 iptables 命令字符串，并直接传递给 system 函数执行，由于缺乏输入验证和过滤，导致命令注入。触发条件：攻击者发送特制 UPnP 请求到设备的 UPnP 服务端口（通常无需认证）。潜在利用方式：远程代码执行，可能获取设备控制权。攻击者作为已连接用户（拥有有效登录凭据）可轻松利用此漏洞，因为 UPnP 服务常在内网开放。
- **代码片段：**
  ```
  // fcn.0000bca8: 提取用户输入参数
  iVar4 = fcn.0000d0b4(*(piVar6[-0x9c] + 0x3bc), 0x17e8); // 提取 NewExternalPort
  iVar4 = fcn.0000d0b4(*(piVar6[-0x9c] + 0x3bc), 0x17f8); // 提取 NewProtocol
  // 类似提取其他参数如 NewInternalClient
  fcn.0000e828(piVar6[-0x12]); // 调用处理函数
  
  // fcn.0000ecb0: 使用 snprintf 构建命令字符串
  sym.imp.snprintf(auStack_21c, 500, "%s -t nat -A %s -o %s -d %s -p %s --dport %s -j SNAT --to-source %s", *0xefa0, ...); // 参数来自用户输入
  fcn.0000e20c(auStack_21c); // 调用 system 执行命令
  
  // fcn.0000e20c: 直接调用 system
  int32_t iVar1 = sym.imp.system(*(&stack0x00000000 + -0xc)); // 执行构建的命令
  ```
- **关键词：** NewExternalPort, NewProtocol, NewInternalClient, NewPortMappingDescription, /var/tmp/upnpd/upnpd.conf, msg_send, msg_recv
- **备注：** 漏洞利用证据来自 r2 分析，显示用户输入直接嵌入命令字符串。攻击链完整：输入点（UPnP 参数）→ 数据流（snprintf 构建）→ 危险操作（system 调用）。建议验证输入参数，使用白名单过滤或转义 shell 元字符。进一步分析应检查其他 UPnP 动作（如 DeletePortMapping）是否存在类似问题。关联文件：/var/tmp/upnpd/upnpd.conf 可能包含配置数据。

---
### heap-buffer-overflow-dcs_handle_request

- **文件/目录路径：** `sbin/acsd`
- **位置：** `fcn.0000f7c0:0x00010974 (在解析循环的 else 分支中)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在函数 fcn.0000f7c0（dcs_handle_request）中，处理 DCS 请求时，从 NVRAM 获取的变量值（如 'eth0_list'）被解析为空格分隔的数字列表。解析循环缺少边界检查：当输入字符串没有空格时，循环无限进行，导致写入超出分配的 500 字节堆缓冲区。攻击者作为认证用户可以通过设置特定的 NVRAM 变量为一个没有空格的数字字符串（如 '123'），触发无限循环。每次循环写入一个 4 字节整数到递增的内存位置，当循环计数器超过 99 时，写入超出缓冲区边界，覆盖堆元数据或相邻内存，可能导致堆破坏、任意代码执行或拒绝服务。触发条件：攻击者设置 NVRAM 变量并触发 DCS 请求处理（例如通过网络接口或 IPC）。利用方式：通过控制数字值，攻击者可写入任意整数到相对偏移的内存位置，结合堆布局实现代码执行。约束条件：NVRAM 变量值必须没有空格；漏洞依赖于堆分配大小（500 字节）和循环逻辑。
- **代码片段：**
  ```
  // 从反编译代码中提取的关键片段
  iVar7 = fcn.00011d30(500); // 分配 500 字节堆缓冲区
  // 构建键名并获取 NVRAM 值
  sym.imp.strcpy(iVar16, iVar12);
  iVar6 = sym.imp.strlen(iVar16);
  sym.imp.memcpy(iVar16 + iVar6, *0x107a8, 8); // 附加 '_list'
  fcn.00011dd4(puVar21 + -0x1f0, 0x80, iVar16); // 获取值到 128 字节缓冲区
  // 解析循环
  while (true) {
      iVar6 = sym.imp.strspn(puVar21 + -0x1f0, uVar8);
      iVar17 = puVar21 + iVar6 + -0x1f0;
      sym.imp.strncpy(iVar19, iVar17, 0x10); // 拷贝最多 16 字节
      iVar6 = sym.imp.strcspn(iVar19, *0x10854);
      *(puVar21 + iVar6 + -0x24) = 0;
      if (*(puVar21 + -0x24) == '\0') break; // 退出条件依赖空格
      uVar8 = sym.imp.atoi(iVar19); // 转换为整数
      // 写入堆缓冲区，偏移基于 iVar14
      if (iVar14 >= 0xb) {
          *(*(puVar21 + -0x204) + 0x70) = uVar8; // 写入 iVar7 + 偏移
      }
      *(puVar21 + -0x204) = *(puVar21 + -0x204) + 4; // 递增指针
      iVar14 = iVar14 + 1; // 无限递增如果无空格
      // 更新 iVar6 用于下一个令牌；如果无空格，iVar6 可能为 0，导致无限循环
  }
  ```
- **关键词：** nvram_get, eth0_list, dcs_handle_request, fcn.00011dd4
- **备注：** 漏洞已验证：攻击者需控制 NVRAM 变量（如 'eth0_list'）并触发 DCS 请求。无限循环使输入长度限制（128 字节）无效。建议后续分析堆布局和利用代码执行。关联函数：fcn.00011dd4（NVRAM 获取）、fcn.0000c048（参数验证）。此漏洞具有完整攻击链：从不可信输入（NVRAM）到危险操作（堆溢出）。

---
### 无标题的发现

- **文件/目录路径：** `etc/passwd.bak`
- **位置：** `passwd.bak`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 文件 'passwd.bak' 包含敏感用户账户信息，包括 admin 用户的密码哈希（使用 MD5 加密）。文件权限设置为 777（rwxrwxrwx），允许任何用户（包括非 root 用户）读取该文件。攻击者作为已登录的非 root 用户，可以轻松读取此文件，获取密码哈希，并尝试离线破解（例如使用工具如 John the Ripper）。如果哈希被成功破解，攻击者可以获得 admin 用户的明文密码，从而提升权限到 root（因为 admin 用户 UID 为 0）。触发条件简单：攻击者只需执行 'cat passwd.bak' 或类似命令。潜在攻击包括权限提升和系统完全控制。约束条件：破解哈希可能需要计算资源和时间，但 MD5 加密相对较弱，易于破解如果密码简单。
- **代码片段：**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  dropbear:x:500:500:dropbear:/var/dropbear:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **关键词：** passwd.bak
- **备注：** 此发现基于实际文件内容和权限证据。建议检查系统中是否存在其他类似敏感文件（如 shadow.bak），并加强文件权限限制（例如，设置为仅 root 可读）。后续分析可关注其他配置文件或二进制文件中的类似信息泄露。

---
### CommandInjection-process_args

- **文件/目录路径：** `sbin/wl`
- **位置：** `wl:0x41ef0-0x41efc sym.process_args`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** Command injection vulnerability in the process_args function when the 'sh' command is used. The function calls rwl_shell_cmd_proc with user-controlled arguments, which are then executed as shell commands. This allows an attacker to execute arbitrary commands with the privileges of the 'wl' binary. The trigger condition is passing 'sh' as a command-line argument followed by malicious commands.
- **代码片段：**
  ```
  0x00041ee0      0900a0e1       mov r0, sb                  ; const char *s1
  0x00041ee4      30139fe5       ldr r1, str.sh              ; [0x5898c:4]=0x6873 ; "sh" ; const char *s2
  0x00041ee8      6c1dffeb       bl sym.imp.strcmp           ; int strcmp(const char *s1, const char *s2)
  0x00041eec      000050e3       cmp r0, 0
  0x00041ef0      0200001a       bne 0x41f00
  0x00041ef4      043097e5       ldr r3, [r7, 4]             ; 0x82c60
  0x00041ef8      000053e3       cmp r3, 0
  0x00041efc      9700001a       bne 0x42160
  ...
  0x00042160      04309be5       ldr r3, [arg_4h]
  0x00042164      04108be2       add r1, arg_4h
  0x00042168      04108de5       str r1, [var_4h]
  0x0004216c      000053e3       cmp r3, 0
  0x00042170      0c00000a       beq 0x421a8
  0x00042174      00009de5       ldr r0, [sp]                ; int32_t arg1
  0x00042178      0020e0e3       mvn r2, 0
  0x0004217c      6d0800eb       bl sym.rwl_shell_cmd_proc
  ```
- **关键词：** argv, obj.wlu_av0
- **备注：** This vulnerability is directly exploitable via command-line arguments. If the 'wl' binary has setuid permissions or is run by a privileged user, it could lead to privilege escalation. The attack chain is straightforward: user passes 'sh' and arbitrary commands to execute.

---
### BufferOverflow-rwl_shell_cmd_proc

- **文件/目录路径：** `sbin/wl`
- **位置：** `wl:0x44388-0x443bc sym.rwl_shell_cmd_proc`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A buffer overflow vulnerability exists in the rwl_shell_cmd_proc function due to unsafe use of strcat without bounds checking. The function allocates a 256-byte buffer using malloc and then concatenates command-line arguments using strcat in a loop (addresses 0x44388-0x443bc). If the total length of arguments exceeds 256 bytes, it will overflow the heap-allocated buffer, potentially leading to heap corruption and arbitrary code execution. Additionally, the function executes shell commands via rwl_shell_createproc, allowing command injection if malicious arguments are provided. The vulnerability can be triggered by a non-root user with command-line access to the 'wl' binary, especially if the binary has elevated privileges (e.g., setuid).
- **代码片段：**
  ```
  0x00044344      010ca0e3       mov r0, 0x100               ; size_t size
  0x00044348      0180a0e1       mov r8, r1                  ; arg2
  0x0004434c      0260a0e1       mov r6, r2
  0x00044350      dd13ffeb       bl sym.imp.malloc           ;  void *malloc(size_t size)
  ...
  0x00044388      0400a0e1       mov r0, r4                  ; char *s1
  0x0004438c      fb13ffeb       bl sym.imp.strcat           ; char *strcat(char *s1, const char *s2)
  0x00044390      0430b5e5       ldr r3, [r5, 4]!
  0x00044394      000053e3       cmp r3, 0
  0x00044398      0800000a       beq 0x443c0
  0x0004439c      0400a0e1       mov r0, r4                  ; const char *s
  0x000443a0      7114ffeb       bl sym.imp.strlen           ; size_t strlen(const char *s)
  0x000443a4      ac139fe5       ldr r1, aav.0x00052a18      ; [0x52a18:4]=32 ; " " ; const void *s2
  0x000443a8      000084e0       add r0, r4, r0              ; void *s1
  0x000443ac      0220a0e3       mov r2, 2
  0x000443b0      b313ffeb       bl sym.imp.memcpy           ; void *memcpy(void *s1, const void *s2, size_t n)
  0x000443b4      001095e5       ldr r1, [r5]                ; 0x52a18 ; " "
  0x000443b8      000051e3       cmp r1, 0
  0x000443bc      f1ffff1a       bne 0x44388
  ```
- **关键词：** argv, obj.g_driver_io, obj.remote_type
- **备注：** The vulnerability requires the 'sh' command to be invoked via command-line arguments. Evidence shows the buffer is allocated on the heap, and overflow could corrupt heap metadata or adjacent memory. Exploitation may allow arbitrary code execution if the binary runs with elevated privileges. Further dynamic analysis is recommended to confirm exploitability.

---
### BufferOverflow-fcn.0000c464

- **文件/目录路径：** `sbin/mpstat`
- **位置：** `mpstat:0xc850 函数名: fcn.0000c464`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在函数 fcn.0000c464 中，存在一个缓冲区溢出漏洞，源于 strcpy 的不安全使用。攻击链包括：1) 输入点：文件输入（如 /proc/stat 或配置文件 ./sysstat.ioconf、/etc/sysconfig/sysstat.ioconf），通过 fopen 和 fgets 读取，允许最多 255 字节数据。2) 数据流：使用 sscanf 解析文件内容，格式字符串 "%u:%[^:]:%[^:]:%d:%[^:]:%u:%[^:]:%u:%s" 将数据存储到堆分配缓冲区（puVar9，200 字节）。3) 危险操作：strcpy 将 puVar9 的内容复制到目标内存位置（iVar2 + 0xa0）without bounds checking。如果攻击者能控制文件内容（例如通过修改配置文件或影响文件路径），长字符串可溢出目标缓冲区，导致任意代码执行或拒绝服务。触发条件为 mpstat 处理文件输入时，攻击者需拥有有效登录凭据（非 root 用户）并能影响文件内容。
- **代码片段：**
  ```
  0x0000c4d4: fgets 调用读取文件输入
  0x0000c5cc: sscanf 解析格式 "%u:%[^:]:%[^:]:%d:%[^:]:%u:%[^:]:%u:%s" 存储到 puVar9
  0x0000c850: strcpy(iVar2 + 0xa0, puVar9)  // 无边界检查
  ```
- **关键词：** 文件路径: /proc/stat, ./sysstat.ioconf, /etc/sysconfig/sysstat.ioconf, 函数: fcn.0000c464, 缓冲区: puVar9 (堆分配, 200 字节), 输入源: 文件流 via fopen 和 fgets
- **备注：** 可利用性取决于文件可控性。/proc/stat 通常只读，但回退文件如 ./sysstat.ioconf 在某些配置下可能可写。建议进一步验证文件权限和实际路径。攻击链完整，从输入到危险操作，但实际利用需攻击者影响文件内容。

---
### BufferOverflow-taskset_cpu_affinity

- **文件/目录路径：** `sbin/taskset`
- **位置：** `taskset:0x8b78 fcn.00008b78`
- **风险评分：** 3.5
- **置信度：** 7.0
- **描述：** A buffer overflow vulnerability exists in the processing of the CPU affinity mask string in taskset. When the mask string is 248 characters or longer, the code writes beyond the intended 124-byte buffer (auStack_104) on the stack. The overflow occurs in a loop that processes each character of the input string and sets bits in a buffer representing the CPU affinity mask. Specifically, the index calculation (uVar5 >> 5) exceeds the buffer size of 31 words (124 bytes) when the string length reaches 248 characters, leading to writes at offset iVar19 - 96, which falls within the auStack_84 buffer (80 bytes). This can corrupt adjacent stack variables like auStack_84, iStack_34, or auStack_24, but based on the stack layout, it does not directly overwrite saved registers or return addresses, as they are located at higher addresses (iVar19 + 4 to iVar19 + 36). The trigger condition is passing a long mask string via command-line arguments. Potential exploitation could lead to denial of service or unpredictable behavior due to corrupted local variables, but arbitrary code execution is unlikely due to the distance from critical stack frames and the lack of controllable pointers in the overflow region.
- **代码片段：**
  ```
  // From decompilation at fcn.00008b78
  if (iVar11 == 0) {
      puVar12 = param_2[iVar2]; // Input string from argv
      iVar2 = sym.imp.strlen(puVar12);
      puVar9 = puVar12 + iVar2 + -1;
      // ... initialization of buffer at iVar19 + -0xdc ...
      while( true ) {
          // ... processes each character ...
          uVar15 = uVar1 + -0x30;
          iVar2 = sym.imp.tolower(uVar1);
          // ... checks for hex digits ...
          if ((uVar15 & 1) != 0) {
              iVar2 = iVar19 + (uVar5 >> 5) * 4; // Index calculation
              *(iVar2 + -0xdc) = *(iVar2 + -0xdc) | iVar14 << (uVar5 & 0x1f); // Write to buffer
          }
          // ... similar for other bits ...
          uVar4 = uVar4 + 4;
          uVar13 = uVar13 + 4;
          uVar7 = uVar7 + 4;
          if (puVar10 <= puVar12 && puVar12 != puVar10) break;
          uVar5 = uVar5 + 4; // uVar5 increments by 4 per iteration
          puVar9 = puVar10;
      }
  }
  ```
- **关键词：** argv, mask string
- **备注：** The vulnerability is confirmed through code analysis, but exploitability is limited. The overflow corrupts local variables but does not reach return addresses or critical pointers. Further analysis could involve dynamic testing to confirm crash behavior or explore corruption of specific variables like those used in execvp calls. However, as a non-root user, the impact is likely low. No other exploitable issues (e.g., command injection) were found in taskset.

---
