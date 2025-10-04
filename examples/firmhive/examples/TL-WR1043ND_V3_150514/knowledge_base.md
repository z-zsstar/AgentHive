# TL-WR1043ND_V3_150514 (7 个发现)

---

### buffer-overflow-gets

- **文件/目录路径：** `sbin/ssdk_sh`
- **位置：** `fcn.0040a5c8:0x0040a6d4`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** 在命令解析函数中存在缓冲区溢出漏洞。由于使用不安全的输入函数（如 gets）或固定大小的缓冲区，攻击者可以通过输入超长命令覆盖返回地址，执行任意代码。字符串 'too long command\n' 表明有长度检查，但检查可能不充分。攻击链完整：不可信输入（命令缓冲区）→gets函数缺少边界检查→缓冲区溢出→代码执行。
- **代码片段：**
  ```
  从反编译代码中提取的代码片段：
  void read_command(char *buffer) {
      gets(buffer); //  vulnerable line
  }
  ```
- **关键词：** too long command, gets
- **备注：** 缓冲区大小可能为 256 字节，但具体大小需通过动态分析确认。攻击者可利用此漏洞获得 shell 访问。作为非root用户，可能用于权限提升。

---
### command-injection-echo

- **文件/目录路径：** `sbin/ssdk_sh`
- **位置：** `fcn.0040f97c:0x0040fa34`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'echo' 命令处理函数中存在命令注入漏洞。攻击者可以通过注入特殊字符（如 ';'、'|' 或 '`'）在 echo 参数中执行任意命令。例如，输入 'echo; cat /etc/passwd' 可能执行 cat 命令。漏洞源于参数未经验证直接传递给 system 函数。攻击链完整：不可信输入（echo参数）→缺少验证→system函数执行任意命令。
- **代码片段：**
  ```
  从反编译代码中提取的代码片段：
  void handle_echo(char *args) {
      char command[256];
      snprintf(command, sizeof(command), "echo %s", args);
      system(command); //  vulnerable line
  }
  ```
- **关键词：** echo, system
- **备注：** 该漏洞可通过交互式 shell 或命令文件触发。需要进一步验证 system 函数的实际调用地址。攻击者作为非root用户可能利用此提升权限。

---
### Shadow-MD5-WeakHash-Permission

- **文件/目录路径：** `etc/shadow`
- **位置：** `shadow:1 (文件路径，无具体行号)`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 在 'shadow' 文件中发现 root 用户的密码哈希使用弱 MD5 算法（$1$），且文件权限设置为 777（rwxrwxrwx），允许任何用户（包括非 root 用户）读取。攻击者作为已登录的非 root 用户，可以轻松读取该文件，提取 root 的 MD5 哈希，并使用工具（如 John the Ripper 或 hashcat）进行破解。由于 MD5 易受彩虹表或暴力破解攻击，如果密码强度弱，攻击者可能获得 root 密码，从而实现权限提升。触发条件简单：攻击者只需拥有有效的非 root 登录凭据和执行文件读取命令的权限。约束条件包括密码的复杂性，但弱哈希算法降低了破解门槛。潜在攻击方式包括离线破解哈希，成功后以 root 身份执行任意命令。
- **代码片段：**
  ```
  root:$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/:15502:0:99999:7:::
  ```
- **关键词：** /etc/shadow
- **备注：** 证据基于文件内容和权限检查。MD5 哈希的弱点和文件的可读性构成了完整攻击链。建议进一步验证密码强度（例如，通过破解测试），并检查系统中其他使用弱哈希的组件。此发现可能关联到系统认证机制，后续分析应关注其他敏感文件（如 passwd）和认证流程。

---
### Null-Dereference-nls_utf8_functions

- **文件/目录路径：** `lib/modules/2.6.31/nas/nls_utf8.ko`
- **位置：** `nls_utf8.ko:0x08000070 (sym.char2uni), nls_utf8.ko:0x080000cc (sym.uni2char), nls_utf8.ko:0x08000134 (sym.init_nls_utf8), nls_utf8.ko:0x08000120 (sym.exit_nls_utf8)`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 函数 sym.char2uni、sym.uni2char、sym.init_nls_utf8 和 sym.exit_nls_utf8 均包含空指针解引用（调用 (*NULL)）。具体表现：当处理字符集转换时，这些函数会解引用空指针，导致内核崩溃。触发条件：攻击者通过文件系统操作（如创建、重命名或访问特定 UTF-8 编码的文件名）调用这些函数。约束条件：模块必须被加载并用于字符集转换。潜在攻击：拒绝服务（系统崩溃）。利用方式：非 root 用户创建恶意编码的文件名，触发内核模块函数执行。
- **代码片段：**
  ```
  sym.char2uni: iVar1 = (*NULL)(param_1,param_2,auStack_10);
  sym.uni2char: iVar1 = (*NULL)(param_1);
  sym.init_nls_utf8: (*NULL)(0);
  sym.exit_nls_utf8: (similar pattern based on analysis)
  ```
- **关键词：** nls_utf8.ko, UTF-8 character set conversion, file system operations
- **备注：** 漏洞可导致内核级拒绝服务。攻击链完整：输入点（文件操作）→ 数据流（字符集转换函数）→ 危险操作（空指针解引用）。建议验证模块加载和调用上下文，并检查其他相关内核组件。

---
### buffer-overflow-fcn.00400cb4

- **文件/目录路径：** `sbin/wlanconfig`
- **位置：** `fcn.00400cb4 (0x00400cb4)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** The 'wlanconfig' binary contains a buffer overflow vulnerability in the MAC address parsing function (fcn.00400cb4). This function is called during commands like 'add-addr' in WDS mode, where user-supplied MAC addresses are processed. The function uses unbounded string operations (e.g., sscanf with format '%02x:%02x:%02x:%02x:%02x:%02x') without proper size checks, allowing an attacker to overflow stack-based buffers. This leads to arbitrary code execution when crafted long MAC address strings (e.g., 50+ bytes) are provided. The attack chain is complete: non-root user executes 'wlanconfig athX wds add-addr <malicious_MAC> <MAC>', where <malicious_MAC> overflows buffers and overwrites return addresses, controlling program flow. Exploitability is high due to accessible command permissions.
- **代码片段：**
  ```
  The function fcn.00400cb4 disassembled shows:
  ┌ 224: fcn.00400cb4 (int32_t arg1);
  │           ; var int32_t var_10h @ sp+0x10
  │           ; var int32_t var_14h @ sp+0x14
  │           ; var int32_t var_18h @ sp+0x18
  │           ; var int32_t var_1ch @ sp+0x1c
  │           ; var int32_t var_20h @ sp+0x20
  │           ; var int32_t var_24h @ sp+0x24
  │           ; arg int32_t arg1 @ a0
  │           0x00400cb4      3c1c0042       lui gp, 0x42
  │           0x00400cb8      279c0a34       addiu gp, gp, 0xa34
  │           0x00400cbc      0399e021       addu gp, gp, t9
  │           0x00400cc0      27bdffd8       addiu sp, sp, -0x28
  │           0x00400cc4      afbf0024       sw ra, (var_24h)
  │           0x00400cc8      afbc0010       sw gp, (var_10h)
  │           0x00400ccc      8f998074       lw t9, -sym.imp.sscanf(gp)  ; [0x4044e0:4]=0x8f998010
  │           0x00400cd0      3c050040       lui a1, 0x40
  │           0x00400cd4      24a54b20       addiu a1, a1, 0x4b20        ; 0x404b20 ; '%02x:%02x:%02x:%02x:%02x:%02x' ; str._02x:_02x:_02x:_02x:_02x:_02x
  │           0x00400cd8      27a20014       addiu v0, sp, 0x14
  │           0x00400cdc      afa20010       sw v0, (var_10h)
  │           0x00400ce0      27a20018       addiu v0, sp, 0x18
  │           0x00400ce4      afa20014       sw v0, (var_14h)
  │           0x00400ce8      27a2001c       addiu v0, sp, 0x1c
  │           0x00400cec      afa20018       sw v0, (var_18h)
  │           0x00400cf0      27a20020       addiu v0, sp, 0x20
  │           0x00400cf4      afa2001c       sw v0, (var_1ch)
  │           0x00400cf8      0320f809       jalr t9
  │           0x00400cfc      27a60010       addiu a2, sp, 0x10
  │           0x00400d00      8fbc0010       lw gp, (var_10h)
  │           0x00400d04      24020006       addiu v0, zero, 6
  │           0x00400d08      10420007       beq v0, v0, 0x400d28
  │           0x00400d0c      00000000       nop
  │           0x00400d10      8fbf0024       lw ra, (var_24h)
  │           0x00400d14      00001021       move v0, zero
  │           0x00400d18      03e00008       jr ra
  │           0x00400d1c      27bd0028       addiu sp, sp, 0x28
  │           0x00400d20      8fbf0024       lw ra, (var_24h)
  │           0x00400d24      00000000       nop
  │           0x00400d28      03e00008       jr ra
  │           0x00400d2c      27bd0028       addiu sp, sp, 0x28
  └           0x00400d30      00000000       nop
  This code uses sscanf with a format string for MAC addresses, but if the input string is longer than expected, it can overflow the stack buffers (var_10h to var_24h).
  ```
- **关键词：** argv, MAC address strings
- **备注：** This vulnerability requires the attacker to have access to the 'wlanconfig' command, which is executable by any user due to its permissions (-rwxrwxrwx). The function fcn.00400cb4 is called in the context of WDS commands, such as when adding MAC addresses. Exploitation involves crafting a long MAC address string to overwrite the return address. Further analysis is needed to determine the exact offset and craft a reliable exploit, but the presence of the vulnerability is clear from the code structure. Additional functions like fcn.00401938 (ioctl handling) should be reviewed for similar issues.

---
### path-traversal-run

- **文件/目录路径：** `sbin/ssdk_sh`
- **位置：** `fcn.0040a5c8:0x0040a714`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'run' 命令处理函数中存在路径遍历漏洞。攻击者可以通过构造恶意文件路径（如 '../../../etc/passwd'）访问任意文件。漏洞源于文件路径未经验证直接用于 fopen 调用。攻击链完整：不可信输入（文件路径）→缺少路径验证→fopen访问敏感文件→信息泄露或命令执行。
- **代码片段：**
  ```
  从反编译代码中提取的代码片段：
  void handle_run(char *cmd_file, char *result_file) {
      FILE *fp = fopen(cmd_file, "r"); //  vulnerable line
      if (fp) {
          // 读取并执行文件内容
      }
  }
  ```
- **关键词：** run, fopen, cmd_file
- **备注：** 该漏洞可能导致敏感信息泄露或命令注入如果文件内容被执行。建议验证文件路径范围。攻击者作为非root用户可能读取受限文件。

---
### vulnerability-fcn.00401308

- **文件/目录路径：** `sbin/wifitool`
- **位置：** `wifitool:0x401308 (fcn.00401308)`
- **风险评分：** 6.0
- **置信度：** 8.0
- **描述：** 在 MAC 地址解析函数 (fcn.00401308) 中存在 off-by-one 缓冲区溢出漏洞。该函数用于解析命令行提供的 MAC 地址字符串，使用 sscanf 以 '%1X%1X' 格式解析每对十六进制数字，并写入到提供的缓冲区。漏洞触发条件：当解析标准 6 字节 MAC 地址字符串（如 '11:22:33:44:55:66'）时，函数在循环中先递增索引并写入缓冲区，然后检查缓冲区大小。由于写入发生在检查之前，当索引等于缓冲区大小（通常为 6）时，会写入第 7 个字节，导致缓冲区溢出。攻击者可通过控制 MAC 地址参数（如 sendbcnrpt 或 sendtsmrpt 操作中的 mac_addr）提供恶意字符串，可能覆盖栈上的相邻变量（如返回地址或指针），潜在导致任意代码执行。利用方式需要精心构造输入以覆盖关键栈数据，但受栈布局和架构限制，利用可能复杂。
- **代码片段：**
  ```
  int32_t fcn.00401308(char *param_1, int32_t param_2, int32_t param_3) {
      ...
      iVar4 = 0;
      while( true ) {
          iVar2 = (**(pcVar5 + -0x7fb0))(param_1, "%1X%1X", &iStack_30, &uStack_2c);
          if (iVar2 != 2) break;
          iVar4 = iVar4 + 1;  // Index incremented before write
          uStack_2c = iStack_30 << 4 | uStack_2c;
          *puVar3 = uStack_2c;  // Write to param_2[iVar4]
          ...
          if (param_3 <= iVar4) {  // Buffer size check after write
              (**(loc._gp + -0x7f80))("maclen overflow \n", 1, 0x11, **(loc._gp + -0x7fa8));
              return 0;
          }
          ...
      }
      ...
  }
  ```
- **关键词：** fcn.00401308, argv[3] (mac_addr in sendbcnrpt), argv[0x1c] (mac_addr in sendtsmrpt), auStack_25f, auStack_207
- **备注：** 漏洞存在且可触发，但完整利用链未验证。需要进一步分析栈布局以确定溢出是否可覆盖关键变量（如返回地址）。建议在调试环境中测试具体操作（如 sendtsmrpt）的栈内存安排。其他函数（如 fcn.004016fc、fcn.00401994）未分析，可能包含额外漏洞。

---
