# TX-VG1530 (25 个发现)

---

### File-Permission-sa2

- **文件/目录路径：** `usr/lib/sa/sa2`
- **位置：** `sa2:1 (整个文件，权限设置)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 文件 'sa2' 具有全局读、写、执行权限（-rwxrwxrwx），允许任何用户（包括非root用户）修改脚本内容。如果脚本被系统以更高权限（如 root）执行（例如通过 cron job），非root用户可以通过插入恶意代码（如 'rm -rf /' 或反向 shell）获得 root 权限。触发条件是非root用户修改脚本并等待计划任务执行；约束条件是脚本必须被以 root 权限调用，这在典型 sysstat 设置中常见。潜在攻击方式包括直接编辑脚本添加恶意命令，利用简单且可靠。
- **代码片段：**
  ```
  文件权限：-rwxrwxrwx
  脚本部分内容：
  #!/bin/sh
  # /usr/lib/sa/sa2
  ...
  ${ENDIR}/sar $* -f ${DFILE} > ${RPT}
  ...
  ```
- **关键词：** /usr/lib/sa/sa2
- **备注：** 此漏洞依赖于脚本被更高权限执行；建议检查系统 cron jobs（如 /etc/cron.d/sysstat）以确认执行上下文。攻击链完整且可验证：非root用户修改脚本 -> cron 以 root 执行 -> 权限提升。无其他明显输入点（如命令行参数或环境变量）能直接导致注入，因为参数传递给 'sar' 命令且未引用，但 'sar' 可能安全处理；配置文件不可写，因此不构成直接威胁。

---
### Config-DefaultAdminCredentials

- **文件/目录路径：** `etc/default_config.xml`
- **位置：** `default_config.xml (在 Services.StorageService.UserAccount instance=1 部分)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 默认管理员凭据（用户名: admin, 密码: admin）在 StorageService 部分配置。攻击者（已拥有有效登录凭据的非 root 用户）可能使用这些凭据登录管理界面，提升权限到超级用户（X_TP_SupperUser val=1），从而执行危险操作如修改系统配置、启用服务或访问敏感数据。触发条件包括管理界面可访问且凭据未更改。潜在利用方式包括权限提升和系统完全控制。
- **代码片段：**
  ```
  <UserAccount instance=1 >
    <Enable val=1 />
    <Username val=admin />
    <Password val=admin />
    <X_TP_Reference val=0 />
    <X_TP_SupperUser val=1 />
  </UserAccount>
  ```
- **关键词：** StorageService.UserAccount.instance=1.Username, StorageService.UserAccount.instance=1.Password, StorageService.UserAccount.instance=1.X_TP_SupperUser
- **备注：** 证据明确显示默认凭据。攻击链需要验证管理界面的可访问性，但假设攻击者已连接设备，可能从内部网络利用。建议检查其他文件（如 web 界面脚本）以确认攻击路径。

---
### BufferOverflow-Midware_cli_insert_entry

- **文件/目录路径：** `usr/lib/libmidware_mipc_client.so`
- **位置：** `libmidware_mipc_client.so:0x1838 (Midware_cli_insert_entry), strcpy calls at 0x186c and 0x1898`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** Buffer overflow vulnerability in `Midware_cli_insert_entry` function due to unsafe use of `strcpy` on user-controlled inputs `name` and `arg` without bounds checking. The function copies these inputs to fixed-size stack buffers (256 bytes each) using `strcpy`, which does not validate length. If `name` or `arg` exceed 255 bytes (plus null terminator), it will overflow the buffer, corrupting the stack. This can overwrite saved registers, including the return address, leading to arbitrary code execution. The function is exposed via CLI or IPC interfaces, and an authenticated non-root user can trigger this by providing overly long strings. The vulnerability is triggered when the function is called with long inputs, and exploitation involves crafting input to overwrite the return address and execute shellcode.
- **代码片段：**
  ```
  if (*(puVar2 + -0x20c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x208, *(puVar2 + -0x20c)); // Copies 'name' to stack buffer
  }
  ...
  if (*(puVar2 + -0x214) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x104, *(puVar2 + -0x214)); // Copies 'arg' to stack buffer
  }
  ```
- **关键词：** Midware_cli_insert_entry, name, arg, mipc_send_cli_msg
- **备注：** This finding is based on decompilation evidence from Radare2. The function lacks any length checks on inputs before copying. Similar vulnerabilities likely exist in other CLI functions (e.g., `Midware_cli_update_entry`, `Midware_cli_remove_entry`) due to repeated `strcpy` usage. Further analysis should verify the exact stack layout and potential mitigations (e.g., stack canaries), but the absence of bounds checking makes exploitation feasible. Recommend testing with long inputs to confirm crash and code execution.

---
### BufferOverflow-omci_api_call

- **文件/目录路径：** `usr/lib/libomci_mipc_client.so`
- **位置：** `libomci_mipc_client.so:0x0000524c dbg.omci_api_call`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** The function 'dbg.omci_api_call' contains a buffer overflow vulnerability due to the use of 'memcpy' without bounds checking. The function copies data from 'param_2' (user-controlled input) to a stack buffer of fixed size (2048 bytes) using 'param_3' (length) without validating if 'param_3' exceeds the buffer size. This can lead to stack-based buffer overflow, allowing an attacker to overwrite return addresses and execute arbitrary code. The function is central to API handling and is called with untrusted data from IPC or CLI sources. An attacker with login credentials could craft a malicious IPC message or API call with a large 'param_3' to trigger the overflow. The vulnerability is triggered when 'param_2' is non-null and 'param_3' is larger than 2048 bytes.
- **代码片段：**
  ```
  sym.imp.memcpy(puVar2 + 0 + -0x800, *(puVar2 + *0x53c4 + 4), *(puVar2 + *0x53c8 + 4));
  ```
- **关键词：** omci_api_call, mipc_send_sync_msg
- **备注：** The vulnerability is directly in the code and can be exploited if the calling process passes untrusted input. Further analysis of callers is needed to confirm the full attack chain, but the library's use in IPC and CLI contexts makes exploitation likely. Recommend analyzing processes that use this library for input validation flaws.

---
### DHCPv6-StackOverflow-fcn.0001a284

- **文件/目录路径：** `usr/sbin/dhcp6s`
- **位置：** `dhcp6s:0x0001ae70 fcn.0001a284`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 dhcp6s 二进制文件的 fcn.0001a284 函数中，处理 DHCPv6 选项类型 5（请求选项）时存在栈缓冲区溢出漏洞。攻击者可以通过网络发送特制的 DHCPv6 数据包，其中选项类型为 5 且长度字段（r8）被设置为一个较大的偶数值（例如 >= 10），触发漏洞。代码首先检查选项长度是否为偶数，然后右移一位得到项目数，但未对项目数进行边界检查。在循环中，使用 memcpy 每次拷贝 2 字节数据到栈缓冲区 var_194h（仅 8 字节空间），当项目数超过 4 时，会溢出栈帧，覆盖返回地址或关键变量。攻击者可精心构造选项数据，控制溢出内容，劫持控制流实现任意代码执行。触发条件：攻击者已连接到设备并拥有有效登录凭据（非 root 用户），发送恶意 DHCPv6 数据包到 dhcp6s 服务。利用方式：通过覆盖返回地址，跳转到 shellcode 或 ROP 链，可能提升权限（因 dhcp6s 可能以 root 权限运行）。
- **代码片段：**
  ```
  0x0001ae14      000058e3       cmp r8, 0                   ; 检查选项长度
  0x0001ae18      0830a011       movne r3, r8
  0x0001ae1c      01308803       orreq r3, r8, 1
  0x0001ae20      010013e3       tst r3, 1                   ; 检查是否为偶数
  0x0001ae24      1101001a       bne 0x1b270                 ; 不是则跳转到错误处理
  0x0001ae28      c880b0e1       asrs r8, r8, 1             ; 右移一位，得到项目数
  0x0001ae2c      54feff0a       beq 0x1a784                 ; 如果为0则跳过循环
  ...
  0x0001ae70      650f8de2       add r0, var_194h            ; 目标缓冲区地址
  0x0001ae74      0510a0e1       mov r1, r5                  ; 源数据指针
  0x0001ae78      0220a0e3       mov r2, 2                   ; 拷贝2字节
  0x0001ae7c      020080e2       add r0, r0, 2               ; 递增目标地址
  0x0001ae80      c6d8ffeb       bl sym.imp.memcpy           ; 执行拷贝
  0x0001ae64      025085e2       add r5, r5, 2               ; 递增源指针
  0x0001ae68      060055e1       cmp r5, r6                  ; 检查循环条件
  0x0001ae6c      44feff0a       beq 0x1a784                 ; 结束循环
  ```
- **关键词：** DHCPv6 选项类型 5, var_194h (栈缓冲区), r8 (选项长度寄存器), sym.imp.memcpy
- **备注：** 漏洞位于 dhcp6s 的 DHCPv6 选项处理逻辑中，输入点通过 recvmsg 从网络接收。攻击链完整：从不可信网络输入到危险操作（memcpy 溢出）。需验证 dhcp6s 是否以 root 权限运行（常见于 DHCP 服务器），若否，利用可能受限。建议后续测试实际利用，包括构造数据包和检查缓解措施（如 ASLR、栈保护）。关联函数：fcn.0001411c（主消息处理）调用 fcn.0001a284。

---
### BufferOverflow-iptvCliMgShowAll_mipc

- **文件/目录路径：** `usr/lib/libigmp_mipc_client.so`
- **位置：** `libigmp_mipc_client.so:0x1910 in dbg.iptvCliMgShowAll_mipc`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** The function iptvCliMgShowAll_mipc uses strcpy to copy a user-controlled string (passed as an argument) into a fixed-size stack buffer without any bounds checking. This occurs in the code at address 0x1910, where strcpy is called with the source directly from the function argument and the destination as a local stack buffer. The stack buffer is allocated with a size of approximately 288 bytes, but the specific destination buffer is at an offset that allows overflow after 268 bytes, enabling overwrite of the saved return address at fp+4. An attacker with CLI access can trigger this by providing a long string as the argument, leading to stack buffer overflow and potential arbitrary code execution. The vulnerability is directly exploitable due to the lack of input validation and the attacker's ability to control the input via CLI commands.
- **代码片段：**
  ```
  0x000018f4      10311be5       ldr r3, [src]               ; igmp_mipc_client.c:288 ; 0x110
  0x000018f8      000053e3       cmp r3, 0
  0x000018fc      0400000a       beq 0x1914
  0x00001900      10311be5       ldr r3, [src]               ; igmp_mipc_client.c:289 ; 0x110
  0x00001904      412f4be2       sub r2, dest
  0x00001908      0200a0e1       mov r0, r2                  ; char *dest
  0x0000190c      0310a0e1       mov r1, r3                  ; const char *src
  0x00001910      d8fcffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **关键词：** iptvCliMgShowAll_mipc, mipc_send_cli_msg, strcpy
- **备注：** This finding is representative of multiple similar vulnerabilities in other CLI functions (e.g., iptvCliMgShowValid_mipc, iptvCliHostShowAll_mipc) that also use strcpy without bounds checking. The exploitability depends on the attacker having access to invoke these CLI commands, which is plausible given the user context. Further analysis could involve tracing the data flow from input sources to these functions, but the current evidence supports a viable attack chain. Additional functions using memcpy or other dangerous operations should be investigated for completeness.

---
### BufferOverflow-oam_cli_cmd_voip_sip_user_config_set

- **文件/目录路径：** `usr/lib/liboam_mipc_client.so`
- **位置：** `liboam_mipc_client.so:0x000051f0 oam_cli_cmd_voip_sip_user_config_set`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** Function `oam_cli_cmd_voip_sip_user_config_set` contains multiple stack buffer overflow vulnerabilities due to the use of `strcpy` without input length validation. The function copies up to five user-controlled parameters (param_1 to param_4) into fixed-size stack buffers (each 256 bytes). If any parameter exceeds 256 bytes, `strcpy` will overflow the buffer, overwriting adjacent stack data including saved registers and return addresses. Trigger condition: An authenticated user executes a CLI command with parameters longer than 256 bytes. Potential attack: By carefully crafting long strings, an attacker can overwrite the return address to control program execution flow, leading to arbitrary code execution. The function uses `mipc_send_cli_msg` to send messages after copying, but the overflow occurs locally before any IPC communication.
- **代码片段：**
  ```
  if (*(puVar2 + -0x50c) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x508, *(puVar2 + -0x50c));
  }
  if (*(puVar2 + -0x514) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x404, *(puVar2 + -0x514));
  }
  if (*(puVar2 + -0x518) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x304, *(puVar2 + -0x518));
  }
  if (*(puVar2 + 8) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x204, *(puVar2 + 8));
  }
  if (*(puVar2 + 0xc) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x104, *(puVar2 + 0xc));
  }
  ```
- **关键词：** param_1, param_2, param_3, param_4, mipc_send_cli_msg
- **备注：** The vulnerability is confirmed through decompilation, but the full attack chain depends on external factors: the function must be accessible to authenticated users via CLI or IPC, and the system must lack stack protection (e.g., stack canaries). Further analysis should verify the calling context in components like CLI handlers and check for mitigations. This function is a high-priority target due to multiple input points.

---
### Command-Injection-upnpd-UPnP

- **文件/目录路径：** `usr/bin/upnpd`
- **位置：** `fcn.00016694:0x166a4 (system call), fcn.00018380:0x183bc (system call), 可能的事件处理函数如 fcn.00017ac0`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** 在 'upnpd' 二进制文件中，发现一个潜在的 command injection 漏洞链。攻击者可以通过发送恶意的 UPnP 请求（如 AddPortMapping 或 DeletePortMapping）来注入命令。具体地，函数 fcn.00016694 直接调用 'system' 函数，其参数 param_1 可能来自外部输入且未经验证。此外，函数 fcn.00018380 使用 snprintf 构建命令字符串后调用 'system'，但输入来源可能未充分过滤。UPnP 请求通过网络接口接收，解析后传递给这些函数。攻击者作为已认证的非 root 用户，可以构造特制请求，在参数中嵌入 shell 元字符（如 ';'、'|' 或 '`'），从而执行任意命令。触发条件包括发送包含恶意参数的 UPnP SOAP 请求。利用方式可能包括在 'NewPortMappingDescription' 或类似字段中注入命令，导致权限提升或设备控制。
- **代码片段：**
  ```
  // fcn.00016694 代码片段
  uint fcn.00016694(uint param_1) {
      int32_t iVar1;
      iVar1 = sym.imp.system(param_1); // 直接调用 system，param_1 可能来自外部输入
      // ...
  }
  
  // fcn.00018380 代码片段（部分）
  sym.imp.snprintf(piVar6 + -0xb, 0x20, *0x18708, *0x1870c); // 构建命令字符串
  iVar1 = sym.imp.system(piVar6 + -0xb); // 执行系统命令
  // 类似模式在其他地方重复
  ```
- **关键词：** NewPortMappingDescription, NewInternalClient, NewProtocol, /var/tmp/upnpd/pm.db, urn:upnp-org:serviceId:WANIPConn1
- **备注：** 证据基于静态分析，显示 'system' 调用与潜在的外部输入关联。但需要动态验证以确认输入源和可利用性。建议进一步分析 UPnP 请求解析函数（如 fcn.00017ac0）和数据流。关联文件包括 /var/tmp/upnpd/pm.db（端口映射数据库）和配置文件 /var/tmp/upnpd/upnpd.conf。攻击链可能涉及多个组件，包括 XML 解析和动作处理。

---
### command-injection-fcn.00013094

- **文件/目录路径：** `usr/bin/voip`
- **位置：** `voip:0x13094 fcn.00013094 (multiple addresses: 0x134e0, 0x135d0, 0x136e0, 0x1381c, 0x139a8, 0x13b04, 0x13c64)`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** The vulnerability arises from the handling of IPC messages in the voip process. IPC messages received via mipc_receive_msg are processed in fcn.00015194, which dispatches to various functions based on message ID. Cases 1 and 2 call fcn.00013d5c and fcn.00013eb8, respectively, which in turn call fcn.00013094. fcn.00013094 constructs shell commands using sprintf and strcat with parameters derived directly from IPC messages (e.g., IP addresses, netmasks, gateways) and executes them via system calls. The lack of input sanitization allows command injection if an attacker controls these parameters. For example, parameters like IP addresses could contain shell metacharacters (e.g., ';' or '|') to inject additional commands. The trigger condition is sending a crafted IPC message with malicious data to the voip process, which is accessible to authenticated users.
- **代码片段：**
  ```
  // Example from fcn.00013094 showing command construction and system call
  sym.imp.sprintf(piVar6 + -0x14, *0x13d28, piVar6[-0x9b]);  // Format string with parameter
  sym.imp.strcat(piVar6 + -0x25c, piVar6 + -0x14);          // Append to command buffer
  iVar1 = sym.imp.system(piVar6 + -0x25c);                   // Execute command
  ```
- **关键词：** mipc_receive_msg, mipc_response_msg, VOIP_setGlobalParam_F, VOIP_updateHostIpAddr_F, voice_ip_mode, iad_ip_addr, iad_net_mask, iad_def_gw
- **备注：** The vulnerability requires further validation through dynamic testing to confirm exploitability. The attack chain involves IPC communication, which may have access controls. Assumed that authenticated users can send IPC messages to the voip process. Recommended to analyze the IPC mechanism and message structure for precise exploitation. Related functions: fcn.00013d5c, fcn.00013eb8, fcn.00015194, fcn.00015c9c.

---
### BufferOverflow-I2c_cli_show_xvr_a2d_values

- **文件/目录路径：** `usr/lib/libi2c_mipc_client.so`
- **位置：** `libi2c_mipc_client.so:0x990 I2c_cli_show_xvr_a2d_values`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** The function I2c_cli_show_xvr_a2d_values contains a stack-based buffer overflow vulnerability due to the use of strcpy without bounds checking. The function copies the input parameter 'param_1' directly into a fixed-size stack buffer (248 bytes) using strcpy. If 'param_1' is longer than 248 bytes, it will overflow the buffer, potentially overwriting the return address and allowing arbitrary code execution. The function is called via CLI commands through IPC (mipc_send_cli_msg), and since the attacker has valid login credentials, they can trigger this function with a maliciously long input. The lack of stack canaries or other mitigations in the binary increases the exploitability.
- **代码片段：**
  ```
  if (*(puVar2 + -0x10c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x104, *(puVar2 + -0x10c));
  }
  ```
- **关键词：** param_1, mipc_send_cli_msg
- **备注：** The input source 'param_1' is likely controlled via CLI commands. Further analysis is needed to trace the exact data flow from user input to this function. The binary lacks stack canaries based on r2 analysis, but ASLR might be enabled on the system, which could affect exploit reliability.

---
### BufferOverflow-I2c_cli_show_xvr_thresholds

- **文件/目录路径：** `usr/lib/libi2c_mipc_client.so`
- **位置：** `libi2c_mipc_client.so:0xa2c I2c_cli_show_xvr_thresholds`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** The function I2c_cli_show_xvr_thresholds exhibits the same stack-based buffer overflow vulnerability as I2c_cli_show_xvr_a2d_values. It uses strcpy to copy 'param_1' into a 248-byte stack buffer without bounds checking. An attacker with CLI access can provide a long input to overflow the buffer and potentially execute arbitrary code. The function is part of IPC communication via mipc_send_cli_msg.
- **代码片段：**
  ```
  if (*(puVar2 + -0x10c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x104, *(puVar2 + -0x10c));
  }
  ```
- **关键词：** param_1, mipc_send_cli_msg
- **备注：** Similar to I2c_cli_show_xvr_a2d_values, this function is vulnerable. The consistency across multiple CLI functions suggests a pattern of insecure coding. Verification of the input context is recommended.

---
### BufferOverflow-I2c_cli_show_xvr_alarms_and_warnings

- **文件/目录路径：** `usr/lib/libi2c_mipc_client.so`
- **位置：** `libi2c_mipc_client.so:0xac8 I2c_cli_show_xvr_alarms_and_warnings`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** The function I2c_cli_show_xvr_alarms_and_warnings also contains a stack-based buffer overflow due to strcpy without bounds checking. The input 'param_1' is copied into a 248-byte stack buffer, and overflow can lead to code execution. This function is accessible via CLI commands through IPC.
- **代码片段：**
  ```
  if (*(puVar2 + -0x10c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x104, *(puVar2 + -0x10c));
  }
  ```
- **关键词：** param_1, mipc_send_cli_msg
- **备注：** This function follows the same vulnerable pattern. Analysis of I2c_cli_show_xvr_inventory and I2c_cli_show_xvr_capability reveals identical issues, indicating widespread insecurity in the library.

---
### 无标题的发现

- **文件/目录路径：** `usr/lib/libpm_mipc_client.so`
- **位置：** `libpm_mipc_client.so:0x1370 dbg.Apm_cli_set_pm_interval`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** 函数 dbg.Apm_cli_set_pm_interval 中存在栈缓冲区溢出漏洞。由于使用 strcpy 函数将用户控制的参数 param_1 复制到固定大小的栈缓冲区（估计 256 字节）而没有长度验证，攻击者可以通过提供超过缓冲区大小的字符串覆盖栈上的返回地址、帧指针或其他关键数据，导致任意代码执行。触发条件：攻击者（拥有有效登录凭据的非 root 用户）能够通过 CLI 命令或 IPC 接口调用该函数并控制 param_1 参数（例如，通过传递长字符串）。利用方式：构造长字符串包含 shellcode 或覆盖返回地址以跳转到攻击者控制的代码，从而提升权限或执行恶意操作。漏洞缺少边界检查，仅验证 param_1 非零，但未检查长度，使得攻击者可以轻松触发溢出。
- **代码片段：**
  ```
  uchar dbg.Apm_cli_set_pm_interval(uint param_1,uint param_2) { ... if (puVar2[-0x42] != 0) { sym.imp.strcpy(puVar2 + -0x100, puVar2[-0x42]); } ... }
  ```
- **关键词：** dbg.Apm_cli_set_pm_interval, param_1, strcpy, mipc_send_cli_msg, Apm_cli_set_pm_interval
- **备注：** 缓冲区大小和栈布局需要进一步验证（例如，使用调试器确认溢出点）；函数可能通过 IPC 或 CLI 命令调用，攻击者需有权限；建议分析调用上下文（如网络服务或 CLI 处理程序）和实际测试可利用性；关联文件可能包括调用此函数的组件（如 apm 或网络守护进程）。

---
### BufferOverflow-zread_ipv4_add

- **文件/目录路径：** `usr/sbin/zebra`
- **位置：** `zebra:0x0001250c dbg.zread_ipv4_add`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** A buffer overflow vulnerability exists in the zread_ipv4_add function when handling IPv4 route addition requests from clients. The function reads a prefix length value (iVar5) from the client stream, which is attacker-controlled, and uses it to calculate the size for reading data into a fixed-size stack buffer (auStack_1c, 28 bytes). The calculation (iVar5 + 7) >> 3 can result in a size of up to 32 bytes when iVar5 is 255, causing a 4-byte overflow. This overflow can overwrite saved registers or the return address on the stack, potentially leading to arbitrary code execution. The vulnerability is triggered when a client sends a message of type 6 (IPv4 add) with a crafted large prefix length value. As zebra typically runs with root privileges to manage kernel routing tables, successful exploitation could grant root access to the attacker.
- **代码片段：**
  ```
  iVar5 = dbg.stream_getc(uVar7);
  dbg.stream_get(puVar11 + -0xc, uVar7, iVar5 + 7U >> 3);
  ```
- **关键词：** client stream data, iVar5 (prefix length field), IPC socket for zebra communication
- **备注：** The vulnerability was identified through static analysis using Radare2 decompilation. The exact stack layout and exploitability would benefit from dynamic analysis or further verification. Additional input points like other zread_* functions or netlink handlers should be examined for similar issues. The IPC socket path for zebra is not hardcoded in the binary but is typically configured in system files, which should be identified for complete attack chain validation.

---
### strcpy-stack-overflow-fcn.0001e05c

- **文件/目录路径：** `usr/bin/vsftpd`
- **位置：** `vsftpd:0x1e0b0 fcn.0001e05c`
- **风险评分：** 8.0
- **置信度：** 8.5
- **描述：** 函数 fcn.0001e05c 在地址 0x1e0b0 和 0x1e138 也调用 strcpy，类似地缺少边界检查。该函数处理用户输入或配置数据，可能通过 FTP 命令（如 USER 或 PASS）触发。攻击者可通过发送超长用户名或密码导致缓冲区溢出。触发条件：攻击者已认证，能发送恶意 FTP 命令；输入数据需超过缓冲区大小。利用方式包括覆盖栈上的返回地址或函数指针。
- **代码片段：**
  ```
  0x0001e0b0      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  0x0001e138      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **关键词：** USER, PASS
- **备注：** FTP 命令处理是常见攻击向量。需要测试实际输入长度限制和缓冲区大小。可能受 vsftpd 配置影响（如 max_clients）。

---
### StackOverflow-client6_recv

- **文件/目录路径：** `usr/sbin/dhcp6c`
- **位置：** `dhcp6c:0x000196a0 client6_recv（具体在 case 0xfc 处理部分）`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** 在 client6_recv 函数处理 DHCPv6 消息类型 252（0xfc）时，使用不安全的字符串复制操作（strncpy 但缺少长度参数限制）将网络数据复制到固定大小的栈缓冲区（256 字节）。由于缺少输入长度验证，攻击者可发送长于 256 字节的字符串数据导致栈缓冲区溢出。溢出可能覆盖返回地址或其他关键栈数据，允许远程代码执行。触发条件包括：攻击者拥有有效登录凭据（非 root 用户），能够发送特制 DHCPv6 消息到目标设备。潜在利用方式包括控制网络输入覆盖返回地址，执行任意 shellcode 或跳转到恶意代码。约束条件包括消息长度检查不充分（uVar12 应等于 15，但条件允许其他值），且复制操作未使用长度参数限制。
- **代码片段：**
  ```
  case 0xfc:
      iVar7 = puVar17 + -0x17c;  // 指向栈缓冲区 auStack_1a0 [256]
      sym.imp.memset(iVar7, 0, 0x100);  // 清零 256 字节缓冲区
      sym.imp.strncpy(iVar7, puVar9);   // 不安全复制网络数据 puVar9，缺少长度参数
      iVar4 = sym.imp.strlen(iVar7);    // 获取字符串长度
      *(puVar17 + -0x20) = iVar7;
      *(puVar17 + -0x24) = iVar4 + 1;
      // 后续调用 fcn.00017e04
  ```
- **关键词：** DHCPv6 消息输入（类型 252）, sym.imp.strncpy, client6_recv 函数, 栈缓冲区 auStack_1a0
- **备注：** 栈缓冲区溢出漏洞需要进一步验证栈布局（如返回地址偏移）以确认可利用性。攻击者需能发送 DHCPv6 消息，可能通过本地网络接口。建议动态测试以重现漏洞。关联函数 fcn.00017e04 可能涉及后续处理，但未发现额外漏洞。

---
### BufferOverflow-oam_cli_cmd_set_onu_loid

- **文件/目录路径：** `usr/lib/liboam_mipc_client.so`
- **位置：** `liboam_mipc_client.so:0x00003234 oam_cli_cmd_set_onu_loid`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** Function `oam_cli_cmd_set_onu_loid` uses `strcpy` to copy three user-controlled parameters into fixed-size stack buffers (256 bytes each) without bounds checks. If any parameter length exceeds 256 bytes, a buffer overflow occurs, potentially overwriting the return address. Trigger condition: An authenticated user provides long strings via CLI commands. Potential attack: Overflow can lead to arbitrary code execution by hijacking the return address. The function calls `mipc_send_cli_msg` after copying, but the overflow happens locally.
- **代码片段：**
  ```
  if (*(puVar2 + -0x30c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x304, *(puVar2 + -0x30c));
  }
  if (*(puVar2 + -0x310) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x204, *(puVar2 + -0x310));
  }
  if (*(puVar2 + -0x314) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x104, *(puVar2 + -0x314));
  }
  ```
- **关键词：** param_1, param_2, param_3, mipc_send_cli_msg
- **备注：** The stack layout suggests the buffers are adjacent, increasing the risk of overwriting critical data. Exploitability is high if the function is exposed to user input. Recommend analyzing the CLI interface to confirm accessibility.

---
### BufferOverflow-omci_cli_debug_set_frame_dump

- **文件/目录路径：** `usr/lib/libomci_mipc_client.so`
- **位置：** `libomci_mipc_client.so:0x00001c80 dbg.omci_cli_debug_set_frame_dump`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** Multiple CLI functions (e.g., 'dbg.omci_cli_debug_set_frame_dump') use 'strcpy' to copy input strings to fixed-size stack buffers without bounds checking, leading to buffer overflows. For instance, 'dbg.omci_cli_debug_set_frame_dump' copies 'param_1' (a string) to a 256-byte stack buffer using 'strcpy'. If 'param_1' is longer than 256 bytes, it overflows the buffer, potentially allowing code execution. These functions are invoked via CLI commands, and an attacker with login credentials can provide crafted long strings to trigger the overflow. The vulnerability is triggered when the input string exceeds the buffer size, and the function sends the data via IPC using 'mipc_send_cli_msg'.
- **代码片段：**
  ```
  if (puVar2[-0x42] != 0) {
      sym.imp.strcpy(puVar2 + -0x100, puVar2[-0x42]);
  }
  ```
- **关键词：** omci_cli_debug_set_frame_dump, mipc_send_cli_msg
- **备注：** This vulnerability affects numerous CLI functions (over 70 instances of 'strcpy' found). Exploitation depends on CLI accessibility to non-root users. Recommend reviewing command injection points in system services that use these functions.

---
### command-injection-hotplug

- **文件/目录路径：** `sbin/hotplug`
- **位置：** `hotplug:0x10db8 system_call`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'hotplug' 程序中发现一个潜在的命令注入漏洞。程序从环境变量 'ACTION' 获取输入，并在处理 'remove' 事件时，使用 'snprintf' 构建命令字符串，然后通过 'system' 函数执行。环境变量 'ACTION' 是用户可控的输入点，但程序未对输入进行充分的验证或过滤，攻击者可以通过注入恶意命令来执行任意代码。触发条件：当热插拔事件触发 'remove' 动作时，程序会执行构建的命令。利用方式：攻击者可以设置 'ACTION' 环境变量为包含 shell 元字符（如 ';'、'|' 或 '`'）的值，从而注入并执行任意命令。
- **代码片段：**
  ```
  0x00010db8      9bfeffeb       bl sym.imp.system           ; int system(const char *string)
  ...
  0x00010d90      40019fe5       ldr r0, str.ACTION          ; [0x10dd8:4]=0x11060 str.ACTION
  0x00010d94      6cfeffeb       bl sym.imp.getenv           ; char *getenv(const char *name)
  0x00010d98      10000be5       str r0, [fp, -0x10]         ; 16
  0x00010d9c      10301be5       ldr r3, [fp, -0x10]         ; 16
  0x00010da0      000053e3       cmp r3, 0
  0x00010da4      0100001a       bne 0x10db0
  ...
  0x00010db0      492f4be2       sub r2, fp, 0x124
  0x00010db4      24104be2       sub r1, fp, -0x24
  0x00010db8      9bfeffeb       bl sym.imp.system           ; int system(const char *string)
  ```
- **关键词：** ACTION
- **备注：** 该漏洞的利用需要攻击者能够控制环境变量 'ACTION'，这可能通过登录用户或网络请求实现。建议进一步验证环境变量的设置方式和程序执行上下文，以确认可利用性。关联文件可能包括启动脚本或网络服务组件。

---
### strcpy-stack-overflow-fcn.0001bf54

- **文件/目录路径：** `usr/bin/vsftpd`
- **位置：** `vsftpd:0x1c1cc fcn.0001bf54`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 vsftpd 的 fcn.0001bf54 函数中，地址 0x1c1cc 处使用 strcpy 复制数据，缺少边界检查。目标缓冲区是栈上的局部变量，源数据从文件读取（如 '/var/vsftp/var/%s'）。如果攻击者能控制文件内容（例如通过上传或修改用户配置文件），可能触发栈缓冲区溢出，导致代码执行。触发条件包括：攻击者拥有有效登录凭据，能访问并修改相关文件；文件内容需足够长以覆盖返回地址。利用方式可能包括精心构造文件内容，注入 shellcode 或 ROP 链。
- **代码片段：**
  ```
  0x0001c1c4      add r0, dest                ; char *dest
  0x0001c1c8      add r1, src                 ; const char *src
  0x0001c1cc      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **关键词：** /var/vsftp/var/%s, /proc/%s/cmdline
- **备注：** 需要进一步验证文件路径的可写性和具体利用条件。攻击者可能通过 FTP 命令（如 STOR）上传恶意文件，或利用其他漏洞修改文件。建议检查 vsftpd 配置和文件权限。

---
### BufferOverflow-oam_cli_cmd_llid_queue_strcmd_parse

- **文件/目录路径：** `usr/lib/liboam_mipc_client.so`
- **位置：** `liboam_mipc_client.so:0x000041e0 oam_cli_cmd_llid_queue_strcmd_parse`
- **风险评分：** 6.5
- **置信度：** 8.5
- **描述：** Function `oam_cli_cmd_llid_queue_strcmd_parse` uses `strcpy` to copy two user-controlled parameters into 256-byte stack buffers without validation. Overflow can occur if inputs exceed 256 bytes, potentially leading to code execution. Trigger condition: User provides long strings via CLI. The function uses `mipc_send_cli_msg` for IPC, but the overflow is local.
- **代码片段：**
  ```
  if (*(puVar2 + -0x22c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x228, *(puVar2 + -0x22c));
  }
  if (*(puVar2 + -0x230) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x128, *(puVar2 + -0x230));
  }
  ```
- **关键词：** param_1, param_2, mipc_send_cli_msg
- **备注：** The vulnerability is clear, but the function's specific use case might limit exploitability. Further analysis should determine how parameters are passed and if the function is called directly from user input.

---
### XSS-xml.js-functions

- **文件/目录路径：** `web/omci/xml.js`
- **位置：** `xml.js 函数 createInput, createbridge, creategemport, gemhtml`
- **风险评分：** 6.5
- **置信度：** 8.0
- **描述：** 多个函数（如 `createInput`、`createbridge`、`creategemport`、`gemhtml`）将从 XML 文件 'me_mib.xml' 加载的数据直接写入 DOM 使用 `document.writeln` 或 `innerHTML`，未对数据内容进行消毒或编码。这允许攻击者注入恶意 JavaScript 代码。具体表现：当用户通过 UI 元素（如按钮点击）触发这些函数时，如果 XML 数据包含脚本标签（例如 `<script>alert('XSS')</script>`），它将在新窗口或当前页面中执行。触发条件包括：攻击者能修改 'me_mib.xml' 文件内容（例如通过文件上传或配置漏洞），且受害者用户访问相关页面并交互。潜在利用方式：会话窃取、权限提升或执行任意操作。代码逻辑中，数据通过 `mib.getElementsByTagName` 获取，并直接拼接为 HTML 字符串写入。
- **代码片段：**
  ```
  // 示例来自 createInput 函数
  function createInput(name,type)
  {
      myWindow=window.open();
      var a="";
      try {
          node=mib.getElementsByTagName(name)[0];
          father=node.childNodes;
      } catch(e) {
          alert(e.message);
          type.disabled="disabled";
          return;
      }
      if(father==null) return;
      for(var j=0;j<father.length;j++) {
          child=father[j].childNodes;
          n=j+1;
          var b="ME number: "+n+"<br>";
          for(var i=0;i<25;i++) {
              try { a=child[i].text+"\n"; } catch(e) { break; }
              b=b+"<div>"+a+"</div>"; // 未消毒数据直接拼接
          }
          myWindow.document.writeln(b,"<br>"); // 直接写入 DOM，可能执行脚本
      }
      type.title=a;
  }
  ```
- **关键词：** me_mib.xml, createInput, createbridge, creategemport, gemhtml, mouseover, mouseover2
- **备注：** 攻击链完整但依赖攻击者能修改 'me_mib.xml' 文件。建议验证文件系统权限和上传机制。关联文件可能包括 Web 界面相关 HTML/JS。后续应分析文件上传功能或 XML 解析配置。

---
### DoS-FTP-Port-Conflict

- **文件/目录路径：** `web/main/ftpSrv.htm`
- **位置：** `ftpSrv.htm: checkConflictPort function and doApply function`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在 'ftpSrv.htm' 文件中发现一个潜在的拒绝服务（DoS）攻击链。攻击者可以通过修改 FTP 服务端口号触发 `checkConflictPort` 函数，导致其他网络服务（如端口映射、DMZ、UPnP）被禁用。具体攻击步骤：1) 攻击者以非 root 用户身份登录 Web 界面；2) 导航到 FTP 设置页面；3) 将端口号修改为与现有服务冲突的端口（例如 80 用于 HTTP 服务）；4) 点击 'Apply' 按钮触发 `doApply` 函数；5) `checkConflictPort` 函数检测到冲突并弹出确认对话框；6) 如果用户确认（或通过自动化工具绕过），则通过 `$.act` 调用禁用冲突服务。这可能导致服务中断，影响网络功能。攻击依赖于用户交互（确认对话框），但可通过浏览器自动化工具（如 Selenium）绕过。
- **代码片段：**
  ```
  function checkConflictPort(port) {
    // ... 检查端口冲突逻辑
    if (confirm(c_str.ftp_vs_conflict)) {
      $.act(ACT_SET, WAN_IP_CONN_PORTMAPPING, this.__stack, null, ["portMappingEnabled=0"]);
    } else {
      ret = false;
      return;
    }
    // ... 类似逻辑用于其他服务
  }
  
  function doApply() {
    // ... 端口验证
    if ($.id("inetAccess_en").checked) {
      if(0 == checkConflictPort(port)) {
        return;
      }
      $.act(ACT_SET,FTP_SERVER,null,null,["accessFromInternet=1"]);
    }
    // ... 设置端口
  }
  ```
- **关键词：** FTP_SERVER, WAN_IP_CONN_PORTMAPPING, WAN_PPP_CONN_PORTMAPPING, IP_CONN_PORTTRIGGERING, PPP_CONN_PORTTRIGGERING, DMZ_HOST_CFG, UPNP_CFG, UPNP_PORTMAPPING
- **备注：** 攻击链完整但需要用户交互（确认对话框）。实际可利用性取决于攻击者能否自动化 Web 交互。建议进一步分析后端处理函数（如 `$.act` 的实现）以确认权限检查和服务修改的影响。关联文件可能包括其他配置页面（如 'usbFolderBrowse.htm'）和后端组件。

---
### BufferOverflow-Apm_cli_set_avc_value_str

- **文件/目录路径：** `usr/lib/libavc_mipc_client.so`
- **位置：** `libavc_mipc_client.so:0x11f8 and 0x122c in function Apm_cli_set_avc_value_str`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** The function Apm_cli_set_avc_value_str uses strcpy to copy user-controlled input parameters ('name' and 'value') into fixed-size stack buffers (256 bytes) without any bounds checking. This can lead to stack-based buffer overflows if the input exceeds the buffer size. An attacker with valid non-root credentials could trigger this by providing overly long strings via CLI or IPC mechanisms, potentially overwriting the return address and achieving arbitrary code execution. The trigger condition is when the 'name' or 'value' parameters are non-null and longer than 256 bytes. The function lacks any input validation or size checks, making it highly susceptible to exploitation.
- **代码片段：**
  ```
  From decompilation:
  if (*(puVar2 + -0x214) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x20c, *(puVar2 + -0x214)); // Copies 'name' into buffer auStack_210 [256]
  }
  if (*(puVar2 + -0x220) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x104, *(puVar2 + -0x220)); // Copies 'value' into buffer auStack_108 [256]
  }
  ```
- **关键词：** mipc_send_cli_msg
- **备注：** This vulnerability is shared across multiple exported functions (e.g., Apm_cli_create_avc_entity, Apm_cli_delete_avc_entity) as identified via cross-references to strcpy. Further analysis is recommended to trace how user input reaches these functions via IPC or CLI interfaces, and to assess the exploitation feasibility in the broader system context. The library's role in AVC and IPC communication suggests potential impact on system stability and security if exploited.

---
### CodeExecution-ALSA_MIXER_SIMPLE_MODULES

- **文件/目录路径：** `usr/lib/alsa-lib/smixer/smixer-ac97.so`
- **位置：** `smixer-ac97.so:0x98c mixer_simple_basic_dlopen`
- **风险评分：** 6.0
- **置信度：** 8.0
- **描述：** The mixer_simple_basic_dlopen function in smixer-ac97.so uses the environment variable ALSA_MIXER_SIMPLE_MODULES to dynamically construct a library path that is passed to snd_dlopen for loading. An attacker with local login credentials can set this environment variable to point to a malicious shared library in a directory they control. When the ALSA mixer is initialized (e.g., by running ALSA commands like 'amixer' or 'aplay'), the function is triggered, loading the malicious library and executing arbitrary code in the context of the user. The attack requires the attacker to: 1) craft a malicious shared library, 2) set ALSA_MIXER_SIMPLE_MODULES to the library's path, and 3) trigger mixer initialization through ALSA utilities. The code lacks validation of the environment variable content, and the buffer allocation (based on strlen + 0x11) is sufficient to prevent overflow due to fixed append strings, but the uncontrolled path leads to arbitrary library loading. This provides a reliable code execution mechanism for local attackers, though it does not inherently escalate privileges beyond the user's existing access.
- **代码片段：**
  ```
  iVar3 = sym.imp.getenv(*0xc2c + 0x9d4); // Get ALSA_MIXER_SIMPLE_MODULES
  bVar13 = iVar3 == 0;
  if (bVar13) {
      iVar3 = *0xc30; // Use default if not set
  }
  if (bVar13) {
      iVar3 = iVar3 + 0x9e4;
  }
  iVar4 = sym.imp.strlen(iVar3);
  iVar4 = sym.imp.malloc(iVar4 + 0x11); // Allocate buffer
  iVar8 = iVar4 + 0;
  if (iVar8 != 0) {
      sym.imp.strcpy(iVar4, iVar3); // Copy environment variable value
      sym.imp.strcat(iVar8, *0xc34 + 0xa24); // Append first string (e.g., "/")
      sym.imp.strcat(iVar8, *0xc38 + 0xa34); // Append second string (e.g., "smixer-sbase.so")
      iVar3 = sym.imp.snd_dlopen(iVar8, 2); // Load library
      // ... (error handling omitted)
  }
  ```
- **关键词：** ALSA_MIXER_SIMPLE_MODULES
- **备注：** The vulnerability is directly exploitable by local users for code execution but does not provide privilege escalation without additional context. Further analysis could investigate if privileged processes (e.g., system daemons) use this mixer, which might increase the risk. The strings 'ALSA_MIXER_SIMPLE_MODULES', '/usr/lib/alsa-lib/smixer', and 'smixer-sbase.so' were identified in the binary, confirming the data flow. No buffer overflow was detected due to proper allocation sizes, but the lack of path validation remains the key issue.

---
