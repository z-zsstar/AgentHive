# _US_WH450AV1BR_WH450A_V1.0.0.18_EN.bin.extracted (19 个发现)

---

### 无标题的发现

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd:0x44dd90 sym.fromCheckTools`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the 'fromCheckTools' function of the httpd binary. The function handles network diagnostic commands (ping and traceroute) by taking user-controlled 'ipaddress' and 'selectcmd' parameters from HTTP requests and constructing system commands without proper sanitization. Specifically, when 'selectcmd' is 'ping', it executes 'ping -c 3 -s 16 [ipaddress] > /var/log.txt', and when 'selectcmd' is 'traceroute', it executes 'traceroute -n [ipaddress] > /var/log.txt'. The 'ipaddress' parameter is directly embedded into the command string, allowing an attacker to inject arbitrary commands using shell metacharacters (e.g., ;, &, |). An authenticated user can exploit this by sending a crafted HTTP request to the vulnerable endpoint, leading to remote code execution with the privileges of the httpd process (often root).
- **代码片段：**
  ```
  // From decompiled sym.fromCheckTools
  // str.ping__c_3__s_16__s____var_log.txt_
  (**(iStack_4b8 + -0x7a6c))(*(iStack_4b8 + -0x7fe4) + -0xf4,pcVar4);
  // str.traceroute__n__s____var_log.txt_
  (**(iStack_4b8 + -0x7a6c))(*(iStack_4b8 + -0x7fe4) + -0xd0,pcVar4);
  // Where pcVar4 is user-controlled ipaddress
  ```
- **关键词：** ipaddress (HTTP parameter), selectcmd (HTTP parameter), sym.fromCheckTools, sym.imp.doSystemCmd
- **备注：** The vulnerability is highly exploitable as it requires only authenticated access and no special privileges. The attack chain is straightforward: user input flows directly to system command execution. Further analysis should verify the exact HTTP endpoint and test exploitation in a controlled environment. Other functions using doSystemCmd may have similar issues and should be reviewed.

---
### Command-Injection-sym.sendJoinLeaveUpstream

- **文件/目录路径：** `sbin/igmpproxy`
- **位置：** `igmpproxy:0x40468c (sym.sendJoinLeaveUpstream) and 0x404758 (sym.sendJoinLeaveUpstream) for system calls; data flow originates from IGMP input handlers like sym.acceptIgmp at 0x406164`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in igmpproxy's sym.sendJoinLeaveUpstream function, where IGMP group addresses from untrusted network inputs are used unsanitized in system() calls. Attackers with valid login credentials (non-root) can send crafted IGMP messages (e.g., Join/Leave reports) that inject malicious commands into iptables rules executed via system(). The vulnerability is triggered when IGMP messages are processed, leading to routes being added or removed, and the group address is incorporated into commands like 'iptables -t filter -I FORWARD -i %s -d %s -j ACCEPT 2>/dev/null
' without validation. This allows arbitrary command execution with the privileges of the igmpproxy process (typically root), potentially leading to full device compromise. Constraints include the need for IGMP message handling to be active, but no additional boundary checks are present. Potential attacks involve crafting IGMP packets with malicious group addresses that include shell metacharacters to execute arbitrary commands.
- **代码片段：**
  ```
  From sym.sendJoinLeaveUpstream decompilation and disassembly:
    0x00404644: lw a0, 8(s4)              # Load tainted group address from route structure
    0x00404654: lw t9, -sym.inetFmt(gp); jalr t9  # Format the address
    0x00404668: lw t9, -sym.imp.sprintf(gp); jalr t9   # Build iptables command string with formatted address
    0x0040468c: lw t9, -sym.imp.system(gp); jalr t9    # Execute the command via system call
    The command string is constructed using sprintf with a fixed format, but the group address is inserted without sanitization.
  ```
- **关键词：** IGMP group address, sym.imp.system, sym.sendJoinLeaveUpstream, sym.insertRoute, sym.removeRoute, sym.setRouteLastMemberMode, sym.clearAllRoutes, sym.acceptGroupReport, sym.acceptIgmp, sym.inetFmt, sym.imp.sprintf
- **备注：** The vulnerability is exploitable via multiple paths (e.g., through sym.insertRoute, sym.removeRoute), all converging on sym.sendJoinLeaveUpstream. Attack requires IGMP messaging capability, which is accessible to authenticated users on the network. Further analysis could verify exploitability in a lab environment, and patches should sanitize all inputs used in command construction. No other exploitable vulnerabilities were found in sprintf, strncpy, or other functions analyzed.

---
### stack-buffer-overflow-apmng_svr-main

- **文件/目录路径：** `bin/apmng_svr`
- **位置：** `apmng_svr:0x004036f4 main`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'apmng_svr' 程序的 main 函数中，存在一个栈缓冲区溢出漏洞。程序使用 `recvfrom` 接收 UDP 数据包，并将数据复制到固定大小的缓冲区（100 字节）中。在复制之前，程序检查输入字符串的长度（通过 `strlen`），但检查条件允许最多 300 字节的输入，而目标缓冲区只有 100 字节。当输入数据长度超过 100 字节时，`strcpy` 操作会导致栈缓冲区溢出，覆盖返回地址和其他栈数据。攻击者可以精心构造一个长度在 101 到 300 字节之间的 UDP 数据包发送到端口 20560，触发溢出并控制程序执行流，实现任意代码执行。漏洞触发条件简单，无需认证，因为程序监听网络接口。
- **代码片段：**
  ```
  0x004036f4      0c82998f       lw t9, -sym.imp.strcpy(gp)  ; [0x407db0:4]=0x8f998010
  0x004036f8      00000000       nop
  0x004036fc      09f82003       jalr t9
  0x00403700      21208002       move a0, s4  ; 目标缓冲区（100 字节）
  0x00403704      2128c003       move a1, fp  ; 源数据（用户输入）
  ; 前置检查：strlen(fp) - 0xf < 0x11e（即 strlen(fp) < 301）
  0x004036cc      6080998f       lw t9, -sym.imp.strlen(gp)  ; [0x408030:4]=0x8f998010
  0x004036d0      00000000       nop
  0x004036d4      09f82003       jalr t9
  0x004036d8      2120c003       move a0, fp
  0x004036dc      21984000       move s3, v0  ; 输入长度
  0x004036e0      f1ff4224       addiu v0, v0, -0xf
  0x004036e4      1e01422c       sltiu v0, v0, 0x11e
  0x004036e8      6000bc8f       lw gp, (var_60h)
  0x004036ec      c6ff4010       beqz v0, 0x403608  ; 如果长度超过 300，跳过 strcpy
  ```
- **关键词：** UDP port 20560, socket, recvfrom, strcpy
- **备注：** 漏洞存在于 main 函数的通用输入处理路径中，影响所有接收到的 UDP 数据包。程序是 MIPS 架构的嵌入式二进制文件，可能缺乏 ASLR 或栈保护等缓解措施，增加了可利用性。建议进一步验证漏洞利用链，例如通过构造 ROP 链或 shellcode。关联函数包括 `recvfrom` 和 `strcpy`，输入点来自网络接口。

---
### BufferOverflow-handle_socket

- **文件/目录路径：** `bin/cfmd`
- **位置：** `cfmd:0x00401920 sym.handle_socket`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 handle_socket 函数中，使用 read 系统调用从套接字读取 1028 字节数据到仅 260 字节的栈缓冲区 aiStack_818[65]（int32_t 数组，65*4=260 字节），导致栈缓冲区溢出。攻击者作为已认证非 root 用户，可通过向 /var/cfm_socket 发送特制数据包覆盖返回地址和执行任意代码。触发条件：发送超过 260 字节的数据到套接字。利用方式：构造恶意负载控制程序流，实现权限提升或系统接管。
- **代码片段：**
  ```
  iVar1 = (**(iVar9 + -0x7f18))(param_1,aiStack_818);
  if (iVar1 != 0x404) { return 0; }
  ```
- **关键词：** /var/cfm_socket, cfmd
- **备注：** 漏洞存在于网络输入处理路径，无需依赖其他组件。建议检查套接字权限是否允许非 root 用户访问。后续可分析漏洞利用细节，如计算偏移和构造 ROP 链。

---
### command-injection-do_script_run

- **文件/目录路径：** `bin/dhcps`
- **位置：** `dhcps:0x0040b06c sym.create_helper (函数 do_script_run 调用链)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 do_script_run 函数（通过 create_helper）中，存在命令注入漏洞。用户控制的 DHCP 包数据（如主机名、客户端标识符）被传递给 execl 函数执行脚本，缺少输入验证和过滤。攻击者可构造恶意 DHCP 包，在字段中嵌入 shell 元字符或命令，当 dnsmasq 处理 DHCP 事件（如租约分配）时触发脚本执行，导致任意命令以 dnsmasq 进程权限运行（通常为 root）。触发条件：攻击者发送特制 DHCP 请求包；利用方式：通过注入命令获得 shell 访问或执行特权操作。漏洞提供从网络输入到命令执行的完整攻击链。
- **代码片段：**
  ```
  从反编译代码中提取的关键片段：
  0x0040b06c      lw t9, -sym.imp.execl(gp)   ; 加载 execl 函数
  0x0040b070      move a0, s1                 ; 参数1: 脚本路径
  0x0040b074      move a1, s2                 ; 参数2: 用户可控数据（如主机名）
  0x0040b078      move a3, s0                 ; 其他参数
  0x0040b07c      sw v0, (var_10h)           ; 存储变量
  0x0040b084      jalr t9                     ; 调用 execl，执行脚本
  用户数据通过参数传递，未经验证即用于命令执行。
  ```
- **关键词：** DHCP 包网络接口, 环境变量：DNSMASQ_CLIENT_ID、DNSMASQ_SUPPLIED_HOSTNAME 等, IPC 套接字路径：未直接标识，但通过 DHCP 通信, 自定义共享函数符号：execl
- **备注：** 证据基于反编译和函数调用追踪，显示完整数据流：DHCP 包 → 全局数据结构 → execl 调用。漏洞高度可利用，因为 dnsmasq 常以 root 运行，允许权限提升。建议验证 dnsmasq 进程权限和脚本执行上下文。其他函数（如 dhcp_packet）的缓冲区溢出漏洞可能辅助攻击，但未构成独立完整链。

---
### buffer-overflow-parse_url

- **文件/目录路径：** `usr/sbin/ufilter`
- **位置：** `ufilter:0x00404350 sym.parse_url (指令地址: 0x004043e4 用于 strcpy, 0x00404448 用于 memcpy)`
- **风险评分：** 8.5
- **置信度：** 8.5
- **描述：** 在 parse_url 函数中，用户提供的 URL 数据（来自 set_url 的 param_2[2]）被处理时缺少边界检查，导致栈缓冲区溢出。具体表现：函数使用 strchr 查找逗号分隔符，然后根据结果调用 memcpy 或 strcpy 复制数据到固定大小的栈缓冲区（64 字节）。攻击者可通过提供不含逗号的超长字符串（触发 strcpy 路径）或含逗号的字符串（控制 memcpy 长度）溢出缓冲区。触发条件：攻击者已登录并调用 set_url 相关功能（如通过命令行工具），提供恶意 URL 数据。潜在利用方式：覆盖返回地址或关键变量，实现代码执行或权限提升。
- **代码片段：**
  ```
  从反编译代码中提取的关键片段：
  - strcpy 路径 (0x004043e4): lw a1, (var_20h); lw t9, -sym.imp.strcpy(gp); jalr t9; // 污点数据在 a1，直接复制到缓冲区
  - memcpy 路径 (0x00404448): lw a1, (var_20h); move a2, v0; lw t9, -sym.imp.memcpy(gp); jalr t9; // 污点数据在 a1 和 a2（长度由输入控制）
  - 缓冲区大小: 固定 64 字节，但输入长度未检查
  ```
- **关键词：** set_url, parse_url, param_2[2], memcpy, strcpy, main
- **备注：** 漏洞通过 set_url 函数传入用户输入，形成完整攻击链。攻击者最有可能通过命令行工具调用 ufilter 相关功能（如 URL 过滤设置）触发此漏洞。建议进一步验证溢出利用的可行性，例如测试缓冲区布局和跳转地址。关联文件：ufilter（主二进制）。

---
### 无标题的发现

- **文件/目录路径：** `bin/tenda_wifid`
- **位置：** `tenda_wifid:0x400a6c (GetValue call), 0x400a88 (doSystemCmd call) in main function`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** A command injection vulnerability exists in 'tenda_wifid' where NVRAM variables '_ifname' and '_closed' are used unsanitized in system commands. The program retrieves these values via 'GetValue' and constructs commands like 'wl -i %s closed 1' using 'strcat_r' or similar functions, then executes them with 'doSystemCmd'. An attacker with valid login credentials (non-root) can set these NVRAM variables through vulnerable interfaces (e.g., web UI), allowing command injection by including shell metacharacters (e.g., semicolons) in the values. This can lead to arbitrary command execution with the privileges of the 'tenda_wifid' process, which may be elevated. The vulnerability is triggered when the daemon processes the NVRAM values in its main loop, which runs periodically.
- **代码片段：**
  ```
  From decompilation at main:
  pcVar5 = *(iVar7 + -0x7fcc); // strcat_r
  uVar1 = (*pcVar5)(&uStack_d0, iVar9 + 0xe10, auStack_78); // _ifname
  (*pcVar6)(uVar1, &uStack_c8); // Build string
  (**(iVar7 + -0x7fb4))(*(iVar7 + -0x7fe4) + 0xe18, &uStack_c8); // doSystemCmd with "wl -i %s closed 1"
  
  Disassembly around 0x400a60:
  0x400a60      lw t9, -0x7fcc(gp)
  0x400a64      nop
  0x400a68      jalr t9
  0x400a6c      nop
  0x400a70      lw t9, -0x7fa4(gp)
  0x400a74      nop
  0x400a78      jalr t9
  0x400a7c      nop
  0x400a80      lw t9, -0x7fb4(gp)
  0x400a84      nop
  0x400a88      jalr t9
  0x400a8c      nop
  ```
- **关键词：** NVRAM:_ifname, NVRAM:_closed, NVRAM:_maxassoc, function:GetValue, function:doSystemCmd, function:strcat_r
- **备注：** The attack chain requires the attacker to set NVRAM variables, which may be possible via web interfaces or other services. Further analysis could identify specific interfaces that allow NVRAM modification. The vulnerability is repeatable and has a high probability of exploitation if NVRAM access is granted. No buffer overflow was identified in this analysis, but command injection is confirmed.

---
### BufferOverflow-wl-command-functions

- **文件/目录路径：** `usr/sbin/wl`
- **位置：** `文件:wl 地址:0x426540 函数:sym.wlu_var_setbuf; 文件:wl 地址:0x40d1d0 函数:sym.wlu_var_getbuf_med`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** 在 'wl' 二进制文件中发现多个缓冲区溢出漏洞，源于使用无边界检查的 strcpy 函数。攻击者可以通过命令行参数（如 'wl set' 或 'wl nvset' 命令）提供超长字符串，触发堆栈或堆缓冲区溢出。具体地，sym.wlu_var_setbuf 函数使用固定大小 0x2000 字节的缓冲区，但未验证输入参数 param_2 和 param_3 的长度；类似地，sym.wlu_var_getbuf_med 使用 0x600 字节缓冲区。由于攻击者已拥有登录凭据，可执行这些命令，溢出可能覆盖返回地址或关键数据结构，导致任意代码执行。漏洞触发条件包括：用户提供超过缓冲区大小的输入参数，且命令处理流程未进行适当过滤。
- **代码片段：**
  ```
  // sym.wlu_var_setbuf 部分代码
  int32_t iVar2 = *(*(iVar3 + -0x7fe4) + 0x6014);
  (**(iVar3 + -0x7edc))(iVar2, 0, 0x2000); // memset 缓冲区 0x2000 字节
  (**(iVar3 + -0x7d84))(iVar2, param_2); // strcpy(param_2 到缓冲区)
  if (param_4 != 0) {
      (**(iVar3 + -0x7df4))(iVar2 + iVar1 + 1, param_3, param_4); // strcpy(param_3 到缓冲区偏移)
  }
  // sym.wlu_var_getbuf_med 部分代码
  int32_t iVar2 = *(*(iVar4 + -0x7fe4) + 0x6014);
  (**(iVar4 + -0x7edc))(iVar2, 0, 0x600); // memset 缓冲区 0x600 字节
  (**(iVar4 + -0x7d84))(iVar2, param_2); // strcpy(param_2 到缓冲区)
  ```
- **关键词：** param_2, param_3, 命令行参数, wl set, wl nvset, NVRAM 变量
- **备注：** 证据基于反编译代码中的 strcpy 调用和缓冲区大小固定。攻击链完整：用户输入通过命令行 -> process_args 分发 -> 命令函数（如 wl set）-> 脆弱函数（如 wlu_var_setbuf）-> strcpy 溢出。建议进一步验证具体命令的输入路径和利用可行性，例如测试 'wl set' 命令与长参数。关联函数包括 main、process_args 和命令处理函数。由于二进制被剥离，动态分析或测试可能需实际设备环境。

---
### StackBufferOverflow-fcn.00400fb4

- **文件/目录路径：** `usr/sbin/igs`
- **位置：** `igs:0x00400ff8 fcn.00400fb4`
- **风险评分：** 8.0
- **置信度：** 8.5
- **描述：** 在 'igs' 文件的 fcn.00400fb4 函数中，存在栈缓冲区溢出漏洞。该函数使用 strcpy 将用户提供的命令行参数（如 <bridge>）复制到固定大小的栈缓冲区（大小 0x420 字节），未进行任何边界检查。攻击者可通过执行 'igs' 命令并提供超长参数（超过 0x420 字节）触发溢出，覆盖栈上的返回地址（位于偏移 0x428 处），可能导致任意代码执行。触发条件：攻击者拥有有效登录凭据（非root用户），并执行命令如 'igs add bridge <long_string>'。潜在攻击方式包括控制流劫持以提升权限或执行恶意代码。相关代码逻辑涉及命令行参数解析、数据传递到 fcn.00400fb4，以及危险的 strcpy 操作。
- **代码片段：**
  ```
  从 Radare2 反编译和汇编代码：
  - 在 fcn.00400fb4 中：
    0x00400fe0: addiu a2, zero, 0x420       ; 缓冲区大小
    0x00400ff4: lw a1, 0xc(s1)             ; 从参数加载输入
    0x00400ff8: lw t9, -sym.imp.strcpy(gp) ; 加载 strcpy 地址
    0x00401000: jalr t9                    ; 调用 strcpy，复制输入到栈缓冲区
  栈缓冲区 auStack_430 起始于 sp+0x18，返回地址存储在 sp+0x440。
  ```
- **关键词：** 命令行参数 <bridge>, 函数 fcn.00400fb4, 函数 sym.igs_cfg_request_send, NVRAM/环境变量：无, 文件路径：/sbin/igs, IPC 套接字：netlink socket（在 sym.igs_cfg_request_send 中）
- **备注：** 漏洞基于代码证据验证，但未在实际环境中测试利用；偏移计算（0x428）来自汇编分析，建议进一步验证以确认精确的溢出点；关联文件包括 main 函数（处理命令行）和 sym.igs_cfg_request_send（网络操作）；后续分析方向：测试具体参数长度以触发崩溃，检查 ASLR 和其他缓解措施的影响。

---
### XSS-wirelessBasic-SSID

- **文件/目录路径：** `webroot/status_wireless.asp`
- **位置：** `status_wireless.asp: (script section, data.ssid definition), wireless_basic.asp: (form input for SSID), js/status.js: (innerHTML usage in wireless section)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A stored cross-site scripting (XSS) vulnerability exists due to improper handling of user-controlled SSID input. The attack chain begins in 'wireless_basic.asp', where an attacker can set the SSID field to a malicious payload (e.g., `'; alert('XSS'); //`). This input is submitted to '/goform/wirelessBasic' and stored in NVRAM. When 'status_wireless.asp' is loaded, the SSID value is retrieved via `<%get_wireless_basiclist('SSIDlist');%>` and embedded directly into a JavaScript string without encoding. The payload breaks out of the string context and executes arbitrary JavaScript code during page load. The vulnerability is triggered when any user with active session views 'status_wireless.asp', allowing code execution in their browser context. This can lead to session cookie theft, unauthorized actions, or privilege escalation if the user has higher privileges. Client-side validation in 'wireless_basic.asp' (regex `/^[^\n\r,;%&]+$/` and length checks) can be bypassed by sending direct POST requests or disabling JavaScript.
- **代码片段：**
  ```
  From status_wireless.asp:
  \`\`\`javascript
  ssid: '<%get_wireless_basiclist("SSIDlist");%>'.split('\t',8),
  \`\`\`
  From wireless_basic.asp:
  \`\`\`html
  <input type="text" name="ssid" id="ssid" size="20" maxlength="32" value="" />
  \`\`\`
  From js/status.js:
  \`\`\`javascript
  tabTb.rows[i].insertCell(1).innerHTML = data["ssid"][i];
  \`\`\`
  ```
- **关键词：** SSIDlist, /goform/wirelessBasic, status_wireless.asp, wireless_basic.asp, js/status.js
- **备注：** The attack requires the attacker to have permissions to modify wireless settings (assumed based on login credentials). Server-side validation for SSID input is not visible in the provided files and may be insufficient. Further analysis of server-side GoForm handlers (e.g., '/goform/wirelessBasic') could confirm exploitability. The vulnerability is stored XSS, affecting all users viewing the status page. Recommended mitigation includes output encoding in ASP and input validation on the server.

---
### XSS-WDS-Scan-initScan

- **文件/目录路径：** `webroot/wireless_wds.asp`
- **位置：** `js/wl_wds.js: initScan function (approximately lines 50-70)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A cross-site scripting (XSS) vulnerability exists in the WDS scan functionality due to unsanitized user input from wireless scan results being directly inserted into the DOM. The vulnerability is triggered when an authenticated user scans for WDS APs via the 'Scan' button on the 'wireless_wds.asp' page. The 'initScan' function in 'js/wl_wds.js' processes the scan results from '/goform/WDSScan' and uses innerHTML to dynamically build table rows without sanitizing the SSID field. An attacker can set up a malicious wireless AP with a crafted SSID containing JavaScript code (e.g., '<script>alert("XSS")</script>'). When the user scans, the malicious code executes in the user's browser context, potentially leading to session hijacking, credential theft, or other client-side attacks. The vulnerability bypasses client-side validation as the 'checkMAC' function only validates MAC address inputs, not SSID fields from scan results. Constraints include the need for the attacker to be within wireless range and the user to perform a scan while authenticated.
- **代码片段：**
  ```
  function initScan(scanInfo) {
  	//scanInfo="Test_ssid,c8:3a:35:c8:cc:20,1,NONE,0;";
  	var len = scanInfo.split("\r").length,
  		str1 = scanInfo.split("\r"),
  		i = 0,
  		infos = '';
  
  	document.getElementById("wdsScanTab").style.display = "";
  	var tbl = document.getElementById("wdsScanTab").getElementsByTagName('tbody')[0];
  	while (tbl.childNodes.length != 0) {
  		tbl.removeChild(tbl.childNodes[0]);
  	}
  
  	for (; i < len; i++) {
  		var str = str1[i].split("\t");
  		if(str.length !== 5) continue;
  		infos += '<tr><td><input type="radio" name="wlsSlt" onclick="macAcc()"/></td><td>' + str[0]
  			+ '</td><td>' + str[1] + '</td><td>' + str[2] + '</td><td>' + str[3] + '</td><td>' + str[4] + '</td></tr>'; 
  	}
  	$(tbl).html(infos);
  }
  ```
- **关键词：** wireless_wds.asp, js/wl_wds.js, /goform/WDSScan, wds_list, ssid
- **备注：** The vulnerability is verifiable through code analysis, and the attack chain is complete: attacker controls SSID via malicious AP -> user scans -> XSS executes. However, server-side validation of '/goform/WDSScan' was not analyzed, which might mitigate the risk if sanitization occurs there. Additional analysis of server-side components (e.g., binaries handling '/goform' endpoints) is recommended to confirm exploitability. The user must be authenticated and perform a scan, which is a realistic scenario given the attack context.

---
### Heap-Overflow-Process_upnphttp

- **文件/目录路径：** `bin/miniupnpd`
- **位置：** `miniupnpd:0x004054fc sym.Process_upnphttp`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 Process_upnphttp 函数中存在一个堆缓冲区溢出漏洞，由于整数溢出在 realloc 大小计算中。当处理 HTTP 请求时，函数使用 param_1[8]（总读取数据大小）来动态调整缓冲区大小。如果攻击者发送一个 Content-Length 头设置为 4294967295（uint32_t 最大值）的 HTTP 请求，并分块发送数据直到 param_1[8] 接近该值，后续的 recv 调用会导致 iVar1 + param_1[8] 在 realloc 中回绕为一个较小值，从而分配一个过小的缓冲区。随后的 memcpy 操作使用较大的 param_1[8] 偏移将数据复制到缓冲区之外，导致堆内存损坏。触发条件包括：1) 攻击者拥有有效登录凭据并连接到设备；2) 发送恶意 UPnP HTTP 请求，Content-Length 设置为 4294967295；3) 分块发送数据，使总读取大小达到 4294967295；4) 在下一个 recv 时触发整数溢出和堆溢出。潜在利用方式包括远程代码执行（通过覆盖堆元数据或函数指针）或拒绝服务。漏洞的约束条件包括需要发送约 4GB 数据，这在持久攻击或受控环境中可行。
- **代码片段：**
  ```
  // 从 Process_upnphttp 反编译代码的关键片段（状态 1 处理）
  iVar1 = (**(iVar13 + -0x7c78))(*param_1, auStack_830, 0x800, 0); // recv 调用，读取数据
  if (-1 < iVar1) {
      if (iVar1 != 0) {
          iVar2 = (**(iVar13 + -0x7e30))(param_1[7], iVar1 + param_1[8]); // realloc 调用，大小计算为 iVar1 + param_1[8]
          pcVar12 = *(iVar13 + -0x7ce8); // memcpy 函数指针
          param_1[7] = iVar2;
          (*pcVar12)(iVar2 + param_1[8], auStack_830, iVar1); // memcpy 操作，目标地址为 iVar2 + param_1[8]
          iVar2 = param_1[8];
          param_1[8] = iVar1 + iVar2; // 更新总读取大小 param_1[8]
          if ((iVar1 + iVar2) - param_1[10] < param_1[9]) { // 检查请求体是否完整
              return;
          }
          // 其他处理逻辑
      }
  }
  ```
- **关键词：** Content-Length HTTP header, UPnP HTTP request processing, HTTP_socket
- **备注：** 该漏洞需要攻击者发送大量数据（约 4GB）来触发整数溢出，可能在资源受限的设备上导致拒绝服务，但也可被用于代码执行。进一步分析下游函数（如 ExecuteSoapAction）可能揭示额外的攻击向量。建议验证实际利用的可行性，包括堆布局和利用载荷的开发。函数使用间接调用（通过 iVar13 偏移），可能对应库函数如 recv、realloc 和 memcpy。

---
### CSRF-SystemToolFunctions

- **文件/目录路径：** `webroot/js/system_tool.js`
- **位置：** `system_tool.js: functions submitSystemReboot (approx. line 70), submitSystemPassword (approx. line 100), submitSystemRestore (approx. line 50), etc.`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** The JavaScript code handles critical system operations (e.g., reboot, password change, configuration backup/restore) without CSRF protection. An attacker can craft a malicious web page that, when visited by a logged-in user, triggers unauthorized requests to server endpoints. For example, the submitSystemReboot function sends a POST request to "/goform/SysToolReboot" with data "reboot" via AJAX, lacking CSRF tokens. This could lead to denial of service (via reboot) or privilege escalation (via password change) if the user has permissions. Trigger condition: User visits a malicious page while authenticated. Constraints: Requires user interaction and authentication; no client-side or evident server-side CSRF checks. Potential attack: Attacker creates a page with JavaScript that sends forged requests to critical endpoints.
- **代码片段：**
  ```
  From submitSystemReboot: $.ajax({ type : "POST", url : "/goform/SysToolReboot", data : "reboot", success : function (msg) {} });
  ```
- **关键词：** /goform/SysToolReboot, system_reboot.asp, system_password.asp, system_backup.asp, system_restore.asp
- **备注：** This finding is based on client-side code analysis; server-side verification is recommended to confirm the absence of CSRF protection on endpoints. Additional analysis of server-side components (e.g., "/goform" handlers) is suggested to validate exploitability. No other exploitable vulnerabilities with full attack chains were identified in this file.

---
### 无标题的发现

- **文件/目录路径：** `webroot/status_wirelesslist.asp`
- **位置：** `Multiple files: wireless_basic.asp (SSID input), status_wirelesslist.asp (data embedding), js/status.js (data insertion via innerHTML)`
- **风险评分：** 7.0
- **置信度：** 7.5
- **描述：** 存储型跨站脚本（XSS）漏洞存在于无线客户端列表显示功能中。攻击链如下：1) 攻击者使用有效登录凭据访问 'wireless_basic.asp' 并修改 SSID 字段为恶意 JavaScript 代码（如 `<script>alert('XSS')</script>`）。2) 数据通过 '/goform/wirelessBasic' 端点提交并存储到后端（可能 NVRAM）。3) 当用户访问 'status_wirelesslist.asp' 时，服务器端函数 `get_wireless_basiclist` 从存储中获取 SSID 数据并嵌入到 JavaScript 变量（如 `wirelessList`）。4) 在 'js/status.js' 中，数据通过 `innerHTML` 动态插入到页面，导致恶意脚本执行。触发条件：攻击者修改 SSID 后，任何用户访问无线客户端列表页面。约束条件：客户端验证（如 `preSubmit` 函数中的正则表达式 `/^[^\n\r,;%&]+$/`）可被绕过，攻击者可直接发送恶意数据到服务器。潜在攻击方式：窃取会话 cookies、执行任意 JavaScript、重定向用户到恶意网站。
- **代码片段：**
  ```
  // From wireless_basic.asp - SSID input field
  <input type="text" name="ssid" id="ssid" size="20" maxlength="32" value="" />
  
  // From status_wirelesslist.asp - data embedding
  wirelessList = '<%get_wireless_basiclist("WirelessEnablelist");%>',
  
  // From js/status.js - dangerous innerHTML usage
  for (var i = 0; i < str_len.length; i++) {
      tabTb.rows[i].insertCell(1).innerHTML = mac[i]; // Direct insertion of unescaped data
  }
  ```
- **关键词：** SSID input field in wireless_basic.asp, /goform/wirelessBasic, get_wireless_basiclist, wirelessList variable, innerHTML in js/status.js
- **备注：** 此攻击链完整且可验证：输入点（SSID）、数据流（后端存储）、危险操作（innerHTML）均存在。但缺少后端处理程序（如 '/goform/wirelessBasic'）的代码验证，建议进一步分析后端以确认输入过滤情况。关联文件：wireless_basic.asp, status_wirelesslist.asp, js/status.js, public/gozila.js（包含客户端验证函数）。

---
### XSS-initList

- **文件/目录路径：** `webroot/js/log_setting.js`
- **位置：** `log_setting.js initList function`
- **风险评分：** 7.0
- **置信度：** 6.0
- **描述：** 在 `initList` 函数中，从 `reqStr` 解析的日志服务器 IP 和端口值直接插入 HTML 而未转义，导致 XSS 漏洞。当页面加载时，如果 `reqStr` 包含恶意 JavaScript 代码，它将在用户浏览器中执行。触发条件包括：攻击者能够控制 `reqStr` 内容（例如通过添加或修改日志条目），且用户访问日志设置页面。潜在攻击包括窃取会话 cookie、执行任意操作或权限提升。约束在于 `reqStr` 必须包含恶意脚本，且攻击者需能通过其他界面（如 `log_addsetting.asp`）设置它。
- **代码片段：**
  ```
  for (var i = 0; i < itms.length; i++) { var cl = itms[i].split(';'); strtmp += '<td>' + cl[0] + '</td>'; strtmp += '<td>' + cl[1] + '</td>'; }
  ```
- **关键词：** reqStr, log_setting.asp, log_addsetting.asp
- **备注：** 需要进一步分析 `log_addsetting.asp` 或其他相关文件以确认攻击者如何控制 `reqStr`。建议追踪数据流从输入点到输出点，以验证可利用性。

---
### stack-buffer-overflow-wlconf-start

- **文件/目录路径：** `bin/wlconf`
- **位置：** `bin/wlconf:0x00401b24 (strncpy), bin/wlconf:0x00401cb0 (strcpy), bin/wlconf:0x00401fbc (strncpy), bin/wlconf:0x00402094 (strncpy) in sym.wlconf_start`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在 'wlconf' 文件的 sym.wlconf_start 函数中，发现多个栈缓冲区溢出漏洞，涉及命令行参数 argv[1]（接口名）。污点数据从命令行参数传播到不安全的字符串操作：
- 使用 strncpy 复制到 255 字节缓冲区时指定 256 字节大小，导致 off-by-one 溢出。
- 使用 strcpy 复制到 100 字节缓冲区时无大小限制，易导致溢出。
- 使用 strncpy 复制到 79 字节缓冲区时指定 80 字节大小，导致 off-by-one 溢出。
触发条件：攻击者通过命令行执行 'wlconf <ifname> up|down' 并提供恶意的长接口名（长度超过目标缓冲区大小）。约束条件：参数需通过命令行传递，且长度需精确计算以覆盖返回地址或关键变量。潜在攻击方式：溢出可覆盖栈上的返回地址或局部变量，可能导致任意代码执行（如 shellcode 注入）或拒绝服务（崩溃）。相关代码逻辑在字符串复制前缺少边界检查，且涉及间接函数调用（如 wl_iovar_get），可能增加利用复杂性但未完全阻止利用。
- **代码片段：**
  ```
  // 基于反编译代码的示例片段（显示不安全操作）
  // 在 0x00401b24: strncpy(acStack_258, argv[1], 0x100); // acStack_258 大小为 255 字节，off-by-one 溢出
  // 在 0x00401cb0: strcpy(auStack_3bc, argv[1]); // auStack_3bc 大小为 100 字节，无大小限制
  // 在 0x00401fbc: strncpy(acStack_40c, argv[1], 0x50); // acStack_40c 大小为 79 字节，off-by-one 溢出
  // 在 0x00402094: strncpy(acStack_40c, argv[1], 0x50); // 重复操作
  ```
- **关键词：** argv[1], acStack_258, auStack_3bc, acStack_40c, strncpy, strcpy, wl_iovar_get
- **备注：** 漏洞存在且攻击链完整：输入点（命令行参数）→ 数据流（未经验证复制）→ 危险操作（缓冲区溢出）。可利用性需动态验证（如测试崩溃或覆盖控制流），但证据支持理论上的攻击路径。非 root 用户可执行 wlconf，但无 setuid 权限，因此利用可能限于当前用户权限，除非结合其他漏洞提升权限。建议后续分析其他二进制文件（如 httpd）以寻找更直接的攻击链或权限提升机会。

---
### BufferOverflow-fcn.004013b4

- **文件/目录路径：** `usr/sbin/emf`
- **位置：** `emf:0x00401400 fcn.004013b4`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** The function fcn.004013b4 contains a buffer overflow vulnerability due to the unsafe use of strcpy to copy user-input from argv[2] (e.g., the <bridge> parameter) into a fixed-size stack buffer of 0x420 bytes without bounds checking. The overflow occurs when the emf command is executed with subcommands like 'start', 'stop', 'status', etc., and the <bridge> parameter (argv[2]) is provided with a length exceeding 0x420 bytes. This can be triggered by a non-root user with command-line access. An attacker can craft a long string to overwrite the return address on the stack, potentially leading to arbitrary code execution in the context of the user running the binary. The attack chain is complete and verifiable: from input (argv[2]) to overflow via strcpy, with no size checks.
- **代码片段：**
  ```
  From disassembly:
  - 0x004013f4: lw a1, 8(s1)    # Load argv[2] into a1
  - 0x004013f8: lw t9, -sym.imp.strcpy # Load strcpy function
  - 0x00401400: jalr t9          # Call strcpy(s0, a1), where s0 is the buffer
  ```
- **关键词：** argv[2], bridge parameter, emf command, strcpy
- **备注：** The binary has world-writable permissions (-rwxrwxrwx), which could allow unauthorized modification but is separate from this code vulnerability. Further analysis could involve testing exploitability on a target system or examining other functions for additional issues. No other exploitable vulnerabilities were identified in the main or emf_cfg_request_send functions.

---
### stack-buffer-overflow-sntp_start

- **文件/目录路径：** `bin/sntp`
- **位置：** `sntp:0x00400de0 sym.sntp_start`
- **风险评分：** 5.5
- **置信度：** 7.0
- **描述：** 在 sntp 程序的 sntp_start 函数中发现栈缓冲区溢出漏洞。该函数处理 SNTP 网络通信，使用 recvfrom 接收最多 128 字节的数据包，但随后使用 memcpy 将数据复制到仅 40 字节的栈缓冲区 (auStack_204)。攻击者可通过发送长度大于 40 字节的恶意 SNTP 响应包触发溢出。溢出可能覆盖栈上的其他变量（如保存的寄存器或局部指针），导致拒绝服务或潜在代码执行。漏洞触发条件包括：设备运行 sntp 客户端、攻击者能发送恶意网络数据包。程序若以 root 权限运行，可能提升特权，但由于返回地址距离溢出点较远（512 字节），直接利用难度较高。
- **代码片段：**
  ```
  // 从 recvfrom 接收数据，长度可能达 0x80 字节
  iVar3 = recvfrom(uVar4, puVar11, 0x80, 0, auStack_c0, puStack_34);
  ...
  // memcpy 复制数据到固定大小缓冲区，长度 iVar3 攻击者可控
  memcpy(puStack_3c, &uStack_140, iVar3); // puStack_3c 指向 auStack_204 (40 字节)
  ```
- **关键词：** sys.timesyn, sys.timezone, sys.timefixper
- **备注：** 溢出存在但直接覆盖返回地址的可能性低，因距离为 512 字节。建议进一步测试堆栈布局和利用可行性。程序可能以 root 权限运行，但攻击者需已登录且能发送网络包。关联函数：main 中调用 sntp_start，依赖 NVRAM 配置。

---
### 无标题的发现

- **文件/目录路径：** `bin/netctrl`
- **位置：** `netctrl:0x00403498 NetCtrlMsgHandle`
- **风险评分：** 3.0
- **置信度：** 7.0
- **描述：** The NetCtrlMsgHandle function in 'netctrl' processes incoming messages and uses the input string length as an index into a jump table of function pointers. The function checks that the length is not greater than 0x2b (43), ensuring the index is within bounds (0-43). However, the jump table at address 0x00411260 contains all invalid entries (0xffffffff), meaning any valid index would attempt to call an invalid function pointer, leading to a crash. This constitutes a denial-of-service vulnerability, as an attacker with valid login credentials could send a crafted message to trigger the crash. However, there is no evidence of arbitrary code execution or privilege escalation, as the bounds check prevents out-of-bounds access and the invalid pointers do not allow control over executed code. The vulnerability requires the attacker to be able to send messages to the 'netctrl' process, which likely involves IPC or network interfaces, but the exact mechanism is not detailed in the binary.
- **代码片段：**
  ```
  // From decompilation:
  uVar2 = (**(iVar8 + -0x7f78))(param_2); // Get string length
  if (0x2b < uVar2) {
      return 1; // Bounds check
  }
  uVar3 = (*(*(uVar2 * 4 + *(iVar8 + -0x7fe4) + 0x1260) + iVar8))(); // Jump table call
  
  // Jump table at 0x00411260 contains 0xffffffff for all entries
  ```
- **关键词：** netctrl, NetCtrlMsgHandle, IPC communication
- **备注：** The jump table is uninitialized, leading to crashes but not code execution. Further analysis is needed to determine how messages are delivered to 'netctrl' (e.g., via IPC sockets or network interfaces). No other exploitable vulnerabilities were found in the analyzed functions. Recommend verifying the message delivery mechanism and checking for other input points in the system.

---
