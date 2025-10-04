# TL-MR3040_V2_150921 (7 个发现)

---

### p2pgo_noa-stack-buffer-overflow

- **文件/目录路径：** `sbin/wlanconfig`
- **位置：** `wlanconfig:0x004031b8 main 函数（具体在参数解析循环中）`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'wlanconfig' 的 'p2pgo_noa' 子命令中，存在栈缓冲区溢出漏洞。当提供多个参数集（每个集包括迭代次数、偏移值和持续时间）时，程序使用固定大小的栈缓冲区 'auStack_173[11]' 存储解析后的数据，但缺少边界检查。攻击者可以通过提供两个或更多参数集触发溢出，写入超出缓冲区边界，覆盖相邻栈变量（如 'iStack_168'）。这可能导致任意代码执行，因为溢出可能覆盖返回地址或关键栈变量，控制程序流。触发条件：攻击者执行 'wlanconfig <interface> p2pgo_noa <iter1> <offset1> <duration1> <iter2> <offset2> <duration2>'，其中参数值由攻击者控制。利用方式：通过精心构造参数值，覆盖返回地址，跳转到攻击者控制的代码或 shellcode。
- **代码片段：**
  ```
  // 相关代码片段从反编译输出：
  pcVar18 = &cStack_174;
  piVar16 = param_2 + 0xc; // argv[3]
  iVar4 = 0;
  iVar3 = *piVar16;
  pcVar14 = pcVar18;
  while( true ) {
      if (iVar3 == 0) break;
      iVar3 = (**(pcVar20 + -0x7fcc))(iVar3); // strtoul 转换迭代次数
      ...
      iVar6 = iVar4 * 5; // 计算索引
      iVar4 = iVar4 + 1;
      uVar12 = (*pcVar19)(iVar6); // 转换偏移值
      ...
      auStack_173[iVar3] = (uVar12 & 0xffff) >> 8; // 存储偏移高字节
      auStack_173[iVar3 + 1] = uVar12 & 0xffff; // 存储偏移低字节（截断）
      ...
      uVar12 = (*pcVar19)(iVar6); // 转换持续时间
      auStack_173[iVar3 + 2] = uVar12 >> 8; // 存储持续时间高字节
      auStack_173[iVar3 + 3] = uVar12; // 存储持续时间低字节（截断）
      ...
      if ((iVar3 == 0) || (iVar4 == 2)) { // 最多处理 2 个集
          break;
      }
  }
  // 当 iVar4=2 时，iVar3=10，写入 auStack_173[10] 到 [13]，但缓冲区大小仅为 11，导致溢出
  ```
- **关键词：** 命令行参数 argv[3] 及后续参数（用于 'p2pgo_noa' 子命令）, 栈缓冲区 auStack_173, 局部变量 iStack_168
- **备注：** 漏洞已通过代码分析验证，存在完整的攻击链：从命令行输入点到缓冲区溢出，可能控制返回地址。实际利用可能需要绕过栈保护或 ASLR，但在嵌入式 MIPS 环境中保护可能较弱。建议进一步验证栈布局和利用可行性，例如通过动态测试或调试。关联函数：main、strtoul。后续分析方向：检查其他子命令（如 'create'）是否有类似漏洞，并分析 ioctl 调用的安全性。

---
### stack-buffer-overflow-get_string

- **文件/目录路径：** `usr/sbin/chat`
- **位置：** `chat:0x0040533c (get_string) 调用 memmove 处`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** 在 'chat' 程序的 get_string 函数中发现一个栈缓冲区溢出漏洞。该函数用于处理输入字符串，并使用一个固定大小的栈缓冲区（1024 字节）。当输入数据超过缓冲区容量时，代码会调用 memmove 来移动数据，但移动的大小参数（iVar1）基于输入字符串长度计算，且最小为 49 字节。如果攻击者提供长输入字符串（例如超过 1024 字节），当缓冲区满时，memmove 会从当前指针位置（可能已超出缓冲区）复制大量数据到缓冲区起始位置，导致栈溢出。这可能覆盖返回地址或其他关键栈数据，允许攻击者控制程序执行流。触发条件：攻击者通过命令行参数或输入文件提供超长字符串（>1024 字节）。利用方式：精心构造输入以覆盖返回地址，实现任意代码执行。
- **代码片段：**
  ```
  // 从 get_string 反编译代码片段
  if (puStack_20 <= puStack_1c) {
      // ...
      puStack_1c = puStack_1c - iVar1;
      (**(loc._gp + -0x7f3c))(auStack_424, puStack_1c, iVar1); // memmove call
      puStack_438 = puStack_438 + auStack_424 + -puStack_1c;
      puStack_1c = auStack_424 + iVar1;
  }
  // iVar1 计算: iVar1 = uStack_14 - 1, where uStack_14 = max(strlen(input), 0x32)
  ```
- **关键词：** stdin, chat-script, chat-file
- **备注：** 漏洞在 MIPS 架构上可能难以利用，但理论上的攻击链完整。建议进一步验证栈布局和利用可行性。相关函数：get_string、memmove。输入点包括标准输入和文件参数。攻击者上下文：拥有登录凭据的非root用户可能通过命令行或文件输入触发此漏洞，如果 'chat' 程序具有适当权限。需要确认程序的可访问性和架构特定利用难度。

---
### command-injection-modeSwitchByCmd-modeSwitchByCfgFile

- **文件/目录路径：** `usr/sbin/handle_card`
- **位置：** `handle_card:0x00408188 (modeSwitchByCmd), handle_card:0x004082dc (modeSwitchByCfgFile)`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** The handle_card binary contains a command injection vulnerability in the modeSwitchByCmd and modeSwitchByCfgFile functions. These functions construct a command string using sprintf with user-provided input from the -c command-line option (usb mode switch cmd) and execute it via system without proper sanitization. An attacker with access to the handle_card command can inject arbitrary commands by including shell metacharacters (e.g., ;, &, |) in the -c argument. This could lead to arbitrary command execution with the privileges of the handle_card process. Given that handle_card likely handles USB device operations, it may run with elevated privileges, potentially allowing privilege escalation. The vulnerability is triggered when the -c option is used with malicious input during add or delete operations. The attack chain is complete and exploitable: input from -c flows directly to system call without validation, enabling command injection.
- **代码片段：**
  ```
  // From modeSwitchByCmd function
  sprintf(auStack_188, "usb_modeswitch -v 0x%04x -p 0x%04x -I -W %s &", vid, pid, cmd);
  system(auStack_188);
  
  // From modeSwitchByCfgFile function  
  sprintf(auStack_88, "usb_modeswitch -v 0x%04x -p 0x%04x -I -W -c %s &", vid, pid, cfg_file);
  system(auStack_88);
  ```
- **关键词：** -c (command-line option for usb mode switch cmd)
- **备注：** The exploit requires the attacker to have valid login credentials and access to execute handle_card. The binary may be run via services or with elevated privileges, increasing the impact. Further investigation is recommended to determine the exact execution context and permissions of handle_card in the system. Additional analysis of other functions (e.g., card_del) may reveal similar vulnerabilities.

---
### buffer-overflow-wpatalk-fcn.00402470

- **文件/目录路径：** `sbin/wpatalk`
- **位置：** `wpatalk:0x402470 fcn.00402470`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A stack-based buffer overflow vulnerability exists in the function fcn.00402470, which processes command-line arguments for wpatalk. The function uses sprintf in a loop to concatenate user-provided arguments into a fixed-size stack buffer (at sp+0x24) without proper bounds checking. When an attacker supplies multiple long arguments, the buffer can be overflowed, potentially overwriting return addresses and allowing arbitrary code execution. The vulnerability is triggered when wpatalk is invoked with crafted arguments, such as in raw command mode or built-in commands like configme or configthem. As a non-root user with login credentials, an attacker could exploit this to achieve privilege escalation if wpatalk is executed with elevated privileges (e.g., setuid root). The overflow occurs due to the unbounded use of sprintf in a loop, with no size limits on the input arguments.
- **代码片段：**
  ```
  0x004024a0      8f998078       lw t9, -sym.imp.sprintf(gp) ; [0x4034a0:4]=0x8f998010
  0x004024a4      27b10024       addiu s1, sp, 0x24
  ...
  0x004024d0      0320f809       jalr t9
  0x004024d4      a073000c       sb s3, (var_24h)
  0x004024d8      8fbc0010       lw gp, (var_10h)
  0x004024dc      00511021       addu v0, v0, s1
  0x004024e0     .string "_Q" ; len=2
  0x004024e4      02821821       addu v1, s4, v0
  0x004024e8      8e020000       lw v0, (s0)
  0x004024ec      8f998078       lw t9, -sym.imp.sprintf(gp) ; [0x4034a0:4]=0x8f998010
  0x004024f0      02b12021       addu a0, s5, s1             ; arg1
  0x004024f4      26100004       addiu s0, s0, 4
  0x004024f8      1440fff5       bnez v0, 0x4024d0
  0x004024fc      00402821       move a1, v0
  ```
- **关键词：** argv, sp+0x24 (stack buffer), sprintf, CONFIGME, CONFIGTHEM
- **备注：** The vulnerability is in the command processing logic and is reachable via user input. Exploitability depends on the stack layout and mitigations; however, the use of sprintf without bounds checking makes it highly likely. Further analysis is needed to determine if wpatalk has setuid permissions or is called from privileged contexts. Additional functions like fcn.00401688 use fgets with a fixed buffer, which appears safe, but other parts should be reviewed for similar issues.

---
### buffer-overflow-arp-sym.arp_set

- **文件/目录路径：** `usr/arp`
- **位置：** `arp:0x004032c8 sym.arp_set`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 在 'arp' 二进制文件的 sym.arp_set 函数中，发现一个栈缓冲区溢出漏洞。漏洞源于处理 netmask 命令行参数时，使用 strcpy 函数将用户输入直接复制到固定大小的栈缓冲区（位于 fp + 0x1c）而不进行边界检查。攻击者可以通过提供超长的 netmask 字符串（例如，通过 -s 选项设置 ARP 条目时）触发溢出，覆盖栈上的返回地址或关键数据，可能导致任意代码执行。触发条件：攻击者以非 root 用户身份执行 'arp' 命令并控制 netmask 参数。约束条件：缓冲区大小未明确，但栈帧大小为 0x108 字节，输入长度仅受命令行参数限制。潜在攻击方式包括覆盖返回地址以跳转到恶意代码或执行 ROP 链。
- **代码片段：**
  ```
  0x004032c8      8c430000       lw v1, (v0)
  0x004032cc      27c2001c       addiu v0, fp, 0x1c
  0x004032d0      00402021       move a0, v0
  0x004032d4      00602821       move a1, v1
  0x004032d8      8f998024       lw t9, -sym.imp.strcpy(gp)  ; [0x405040:4]=0x8f998010
  0x004032dc      0320f809       jalr t9
  0x004032e0      00000000       nop
  ```
- **关键词：** netmask 命令行参数, obj.device, obj.sockfd
- **备注：** 漏洞在静态分析中确认，但缺乏动态验证以证明完整攻击链。建议进一步测试以验证可利用性，例如通过调试器检查栈布局和覆盖点。文件权限宽松（-rwxrwxrwx）允许非 root 用户利用，但需要攻击者具有命令行访问权限。关联函数：sym.INET_resolve 和 sym.arp_getdevhw 可能涉及其他输入处理，但未发现直接漏洞。

---
### command-injection-fcn.00401154

- **文件/目录路径：** `usr/sbin/modem_scan`
- **位置：** `文件:modem_scan 地址:0x00401154 函数名:fcn.00401154`
- **风险评分：** 6.0
- **置信度：** 9.0
- **描述：** 在 'modem_scan' 中发现命令注入漏洞。攻击者可通过命令行参数 '-f' 注入任意命令，该参数被直接传递给 execl 调用执行 '/bin/sh -c param_1'，没有输入验证或过滤。触发条件：运行 './modem_scan -f "恶意命令"'，其中恶意命令是任意 shell 命令。约束条件：程序无 setuid 位，命令以当前用户权限执行，无法获得 root 权限。潜在攻击：攻击者可作为非 root 用户执行任意命令，用于文件操作、网络访问或其他用户级恶意活动。利用方式简单，只需有效登录凭据和程序执行权限。
- **代码片段：**
  ```
  在 fcn.00401154 中：
  (**(loc._gp + -0x7f9c))("/bin/sh","sh","-c",param_1,0);
  其中 param_1 来自命令行参数 '-f'，被直接传递给 shell 执行。
  ```
- **关键词：** 命令行参数 '-f', 函数 fcn.00401154, execl 调用
- **备注：** 漏洞实际可利用，但无权限提升，风险限于用户级操作。建议验证程序是否被其他特权进程调用以评估潜在影响。后续分析可检查其他函数（如 fcn.00400c0c）或字符串以识别更多输入点。

---
### command-injection-apstart-topology-parsing

- **文件/目录路径：** `sbin/apstart`
- **位置：** `fcn.00400d0c (多个位置，例如在命令构建处：文件:反编译代码 函数 fcn.00400d0c)`
- **风险评分：** 5.0
- **置信度：** 8.0
- **描述：** 在 'apstart' 的拓扑文件解析过程中，使用 `sprintf` 构建命令字符串并调用 `system` 执行，但未对输入进行充分的消毒或转义。攻击者可以通过创建恶意拓扑文件，在接口名或其他字段中注入 shell 命令（如使用分号或反引号）。触发条件为：攻击者执行 `apstart` 并指定恶意拓扑文件路径，且未使用 `-dryrun` 模式。潜在利用方式包括执行任意命令作为当前用户（非 root），可能导致服务中断、数据泄露或横向移动，但无法直接提升权限，因为文件无 setuid 位且以当前用户权限运行。这是一个完整且可验证的攻击链：不可信输入（拓扑文件）→ 数据流（解析和命令构建）→ 危险操作（system 调用）。
- **代码片段：**
  ```
  从反编译代码中提取的示例：
  (**(loc._gp + -0x7fbc))(auStack_f8, "ifconfig %s down", iVar17);  // iVar17 来自拓扑文件
  iVar9 = fcn.00400c7c(auStack_f8, 0);  // 执行命令
  类似代码出现在 "brctl delbr %s"、"wlanconfig %s destroy" 等命令构建中。
  ```
- **关键词：** 拓扑文件路径, apstart, system, fcn.00400c7c, fcn.00400a4c
- **备注：** 需要进一步验证在实际部署中是否被以更高权限调用（如通过 sudo 或 setuid），建议检查系统配置。关联函数包括 fcn.00400c7c（命令执行）和 fcn.00400a4c（文件解析）。后续分析方向包括检查其他输入点（如环境变量）或与 IPC/NVRAM 的交互。基于当前分析，这是一个实际可利用的漏洞链。

---
