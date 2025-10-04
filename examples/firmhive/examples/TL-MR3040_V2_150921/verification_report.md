# TL-MR3040_V2_150921 - 验证报告 (7 个发现)

---

## 原始信息

- **文件/目录路径：** `sbin/wpatalk`
- **位置：** `wpatalk:0x402470 fcn.00402470`
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
- **备注：** The vulnerability is in the command processing logic and is reachable via user input. Exploitability depends on the stack layout and mitigations; however, the use of sprintf without bounds checking makes it highly likely. Further analysis is needed to determine if wpatalk has setuid permissions or is called from privileged contexts. Additional functions like fcn.00401688 use fgets with a fixed buffer, which appears safe, but other parts should be reviewed for similar issues.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 安全警报准确描述了栈缓冲区溢出漏洞。函数 fcn.00402470 在循环中使用 sprintf 拼接命令行参数到固定大小栈缓冲区（sp+0x24，约 292 字节），无边界检查，导致缓冲区可能溢出。输入来自命令行参数（攻击者可控），函数从 main 调用（地址 0x403180），路径可达。攻击者模型为已通过身份验证的本地用户（需 shell 访问）。然而，wpatalk 无 setuid 权限（权限：-rwxrwxrwx），因此以当前用户权限运行，利用不会导致权限提升。漏洞可导致任意代码执行，但影响限于当前用户权限。概念验证（PoC）：攻击者可执行 'wpatalk arg1 arg2 ...'，其中多个参数拼接后超过 292 字节（例如，使用 'wpatalk $(python -c "print 'A'*300")' 或类似载荷触发溢出）。实际风险为 Medium，因代码执行可能，但无权限提升。

## 验证指标

- **验证时长：** 205.91 秒
- **Token 使用量：** 186082

---

## 原始信息

- **文件/目录路径：** `usr/sbin/handle_card`
- **位置：** `handle_card:0x00408188 (modeSwitchByCmd), handle_card:0x004082dc (modeSwitchByCfgFile)`
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
- **备注：** The exploit requires the attacker to have valid login credentials and access to execute handle_card. The binary may be run via services or with elevated privileges, increasing the impact. Further investigation is recommended to determine the exact execution context and permissions of handle_card in the system. Additional analysis of other functions (e.g., card_del) may reveal similar vulnerabilities.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据来自 Radare2 反编译：在 modeSwitchByCmd 函数（0x00408188）中，sprintf 构建命令 'usb_modeswitch -v 0x%04x -p 0x%04x -I -W %s &'，其中第三个参数（cmd）直接插入；在 modeSwitchByCfgFile 函数（0x004082dc）中，sprintf 构建命令 'usb_modeswitch -v 0x%04x -p 0x%04x -I -W -c %s &'，其中第三个参数（cfg_file）直接插入。两个函数都通过 system 执行构建的字符串，没有输入清理。主函数解析命令行选项 'dam:v:p:c:h'，证实 -c 选项的用户输入可控。攻击者模型：已通过身份验证的用户（具有执行 handle_card 的权限），可能通过 shell 访问或服务调用。由于 handle_card 可能以提升的权限（如 root）运行，命令注入可导致权限升级。完整攻击链：攻击者提供恶意 -c 参数（包含 shell 元字符），输入流入 sprintf 和 system，执行任意命令。PoC 步骤：执行 handle_card -v <vid> -p <pid> -c 'malicious; command'，其中 malicious; command 可替换为任意命令（如 '; cat /etc/passwd'），注入的命令将以 handle_card 进程权限执行。

## 验证指标

- **验证时长：** 259.79 秒
- **Token 使用量：** 228726

---

## 原始信息

- **文件/目录路径：** `sbin/apstart`
- **位置：** `fcn.00400d0c (多个位置，例如在命令构建处：文件:反编译代码 函数 fcn.00400d0c)`
- **描述：** 在 'apstart' 的拓扑文件解析过程中，使用 `sprintf` 构建命令字符串并调用 `system` 执行，但未对输入进行充分的消毒或转义。攻击者可以通过创建恶意拓扑文件，在接口名或其他字段中注入 shell 命令（如使用分号或反引号）。触发条件为：攻击者执行 `apstart` 并指定恶意拓扑文件路径，且未使用 `-dryrun` 模式。潜在利用方式包括执行任意命令作为当前用户（非 root），可能导致服务中断、数据泄露或横向移动，但无法直接提升权限，因为文件无 setuid 位且以当前用户权限运行。这是一个完整且可验证的攻击链：不可信输入（拓扑文件）→ 数据流（解析和命令构建）→ 危险操作（system 调用）。
- **代码片段：**
  ```
  从反编译代码中提取的示例：
  (**(loc._gp + -0x7fbc))(auStack_f8, "ifconfig %s down", iVar17);  // iVar17 来自拓扑文件
  iVar9 = fcn.00400c7c(auStack_f8, 0);  // 执行命令
  类似代码出现在 "brctl delbr %s"、"wlanconfig %s destroy" 等命令构建中。
  ```
- **备注：** 需要进一步验证在实际部署中是否被以更高权限调用（如通过 sudo 或 setuid），建议检查系统配置。关联函数包括 fcn.00400c7c（命令执行）和 fcn.00400a4c（文件解析）。后续分析方向包括检查其他输入点（如环境变量）或与 IPC/NVRAM 的交互。基于当前分析，这是一个实际可利用的漏洞链。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据来自 Radare2 反编译分析：在函数 fcn.00400d0c 中，使用 sprintf 构建命令字符串（如 'ifconfig %s down'、'brctl delbr %s'、'wlanconfig %s destroy'），其中输入参数（如 iVar17）直接来自拓扑文件解析，未进行任何消毒或转义。命令通过 fcn.00400c7c 执行，该函数在 *0x4124b0 == 0（即未使用 -dryrun 模式）时调用系统命令。攻击者模型为本地用户（文件无 setuid 位，以当前用户权限运行），通过创建恶意拓扑文件在接口名等字段注入 shell 命令（如使用分号或反引号）。完整攻击链：不可信输入（拓扑文件）→ 数据流（解析和命令构建）→ 危险操作（system 调用）。漏洞实际可利用，但无法直接提升权限。PoC 步骤：1. 攻击者创建恶意拓扑文件，内容包含注入命令的字段，例如在接口名处设置 'eth0; malicious_command'。2. 执行 'apstart malicious_topology_file'（未使用 -dryrun 标志）。3. 系统将执行如 'ifconfig eth0; malicious_command down'，导致恶意命令以当前用户权限执行。潜在影响包括服务中断、数据泄露或横向移动，风险级别为中等。

## 验证指标

- **验证时长：** 282.32 秒
- **Token 使用量：** 249191

---

## 原始信息

- **文件/目录路径：** `sbin/wlanconfig`
- **位置：** `wlanconfig:0x004031b8 main 函数（具体在参数解析循环中）`
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
- **备注：** 漏洞已通过代码分析验证，存在完整的攻击链：从命令行输入点到缓冲区溢出，可能控制返回地址。实际利用可能需要绕过栈保护或 ASLR，但在嵌入式 MIPS 环境中保护可能较弱。建议进一步验证栈布局和利用可行性，例如通过动态测试或调试。关联函数：main、strtoul。后续分析方向：检查其他子命令（如 'create'）是否有类似漏洞，并分析 ioctl 调用的安全性。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了wlanconfig中p2pgo_noa子命令的栈缓冲区溢出漏洞。证据来自二进制代码分析：缓冲区位于sp+0x24，大小为11字节（auStack_173[11]）。参数解析循环（0x004030fc-0x004031d4）处理最多两个参数集，每个集写入5字节（迭代次数1字节、偏移2字节、持续时间2字节）。第一个集使用索引0-4，第二个集使用索引5-9，但存储偏移和持续时间时，第二个集写入位置为索引10-13（sp+0x2e至sp+0x31），超出缓冲区边界（索引10为缓冲区末尾）。这覆盖了相邻栈变量（如iStack_168），可能包括返回地址。攻击者模型：攻击者需能执行wlanconfig命令（如本地用户或通过远程服务调用）。漏洞可利用：攻击者可通过提供两个参数集触发溢出，精心构造参数值可能控制程序流。PoC步骤：执行 'wlanconfig <interface> p2pgo_noa <iter1> <offset1> <duration1> <iter2> <offset2> <duration2>'，其中<iter2>、<offset2>、<duration2>值被用于溢出写入。例如，使用特定值覆盖返回地址，跳转到shellcode。实际利用需考虑栈布局和防护机制，但在嵌入式MIPS环境中可能可行。

## 验证指标

- **验证时长：** 299.00 秒
- **Token 使用量：** 310456

---

## 原始信息

- **文件/目录路径：** `usr/arp`
- **位置：** `arp:0x004032c8 sym.arp_set`
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
- **备注：** 漏洞在静态分析中确认，但缺乏动态验证以证明完整攻击链。建议进一步测试以验证可利用性，例如通过调试器检查栈布局和覆盖点。文件权限宽松（-rwxrwxrwx）允许非 root 用户利用，但需要攻击者具有命令行访问权限。关联函数：sym.INET_resolve 和 sym.arp_getdevhw 可能涉及其他输入处理，但未发现直接漏洞。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确验证：在 'usr/arp' 二进制文件的 sym.arp_set 函数中，0x004032c8 地址确实使用 strcpy 将用户控制的 netmask 参数复制到固定大小的栈缓冲区（fp + 0x1c），无边界检查。栈帧大小为 0x108 字节，返回地址位于 fp + 0x104，缓冲区起始偏移 0x1c，距离 0xE8 字节（232 字节）。输入源 v1 来自 arg_108h（函数参数），用户可通过命令行控制。攻击者模型：未经身份验证的本地用户具有命令行访问权限，可执行 'arp -s <ip> <mac> netmask <long_string>' 命令，其中 <long_string> 为超长字符串。PoC：构造超过 232 字节的 netmask 参数（例如，'A' * 250），覆盖返回地址，可能导致任意代码执行。文件权限 -rwxrwxrwx 允许非 root 用户利用，漏洞实际可利用。

## 验证指标

- **验证时长：** 411.02 秒
- **Token 使用量：** 329483

---

## 原始信息

- **文件/目录路径：** `usr/sbin/chat`
- **位置：** `chat:0x0040533c (get_string) 调用 memmove 处`
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
- **备注：** 漏洞在 MIPS 架构上可能难以利用，但理论上的攻击链完整。建议进一步验证栈布局和利用可行性。相关函数：get_string、memmove。输入点包括标准输入和文件参数。攻击者上下文：拥有登录凭据的非root用户可能通过命令行或文件输入触发此漏洞，如果 'chat' 程序具有适当权限。需要确认程序的可访问性和架构特定利用难度。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** 分析显示，get_string 函数中的 memmove 调用不会导致栈缓冲区溢出。缓冲区大小为 1024 字节，输入字符串长度被限制在 1024 字节以内（检查在 0x0040542c）。当缓冲区满时，memmove 移动的大小 var_3ch 基于输入字符串长度（最小 49 字节，最大 1023 字节），源地址 var_454h - var_3ch 始终在缓冲区内部或之后，但不会超出栈帧，目标地址为缓冲区起始位置，移动操作不会溢出栈。攻击者无法通过提供长输入字符串（>1024 字节）触发溢出，因为函数会提前退出。攻击者模型为拥有登录凭据的非 root 用户，但漏洞不可利用。

## 验证指标

- **验证时长：** 412.81 秒
- **Token 使用量：** 369213

---

## 原始信息

- **文件/目录路径：** `usr/sbin/modem_scan`
- **位置：** `文件:modem_scan 地址:0x00401154 函数名:fcn.00401154`
- **描述：** 在 'modem_scan' 中发现命令注入漏洞。攻击者可通过命令行参数 '-f' 注入任意命令，该参数被直接传递给 execl 调用执行 '/bin/sh -c param_1'，没有输入验证或过滤。触发条件：运行 './modem_scan -f "恶意命令"'，其中恶意命令是任意 shell 命令。约束条件：程序无 setuid 位，命令以当前用户权限执行，无法获得 root 权限。潜在攻击：攻击者可作为非 root 用户执行任意命令，用于文件操作、网络访问或其他用户级恶意活动。利用方式简单，只需有效登录凭据和程序执行权限。
- **代码片段：**
  ```
  在 fcn.00401154 中：
  (**(loc._gp + -0x7f9c))("/bin/sh","sh","-c",param_1,0);
  其中 param_1 来自命令行参数 '-f'，被直接传递给 shell 执行。
  ```
- **备注：** 漏洞实际可利用，但无权限提升，风险限于用户级操作。建议验证程序是否被其他特权进程调用以评估潜在影响。后续分析可检查其他函数（如 fcn.00400c0c）或字符串以识别更多输入点。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据如下：1) Radare2分析函数fcn.00401154显示代码(**(loc._gp + -0x7f9c))(\"/bin/sh\",\"sh\",\"-c\",param_1,0);，其中param_1被直接传递给execl调用执行shell命令，无输入验证或过滤。2) strings输出确认'-f'为命令行参数（' -f \"Script name\"'），表明param_1来自用户可控输入。3) 文件权限为-rwxrwxrwx，无setuid位，命令以当前用户权限执行，无权限提升。攻击者模型：已认证用户（本地或远程）具有程序执行权限。漏洞可利用，攻击者可通过运行./modem_scan -f \"恶意命令\"执行任意shell命令，其中恶意命令如id或whoami。完整攻击链：用户输入通过'-f'参数传递到param_1，直接执行shell命令。实际影响：执行用户级任意命令，可用于文件操作、网络访问等，但受当前用户权限限制。风险级别为Medium，因无权限提升，但可利用性高。

## 验证指标

- **验证时长：** 460.58 秒
- **Token 使用量：** 380232

---

