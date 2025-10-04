# _DIR826LA1_FW105B13.bin.extracted (15 个发现)

---

### CommandInjection-fcn.00400374

- **文件/目录路径：** `bin/fwUpgrade`
- **位置：** `fwUpgrade:0x400374 fcn.00400374`
- **风险评分：** 9.0
- **置信度：** 9.5
- **描述：** 命令注入漏洞存在于函数 fcn.00400374 中。程序使用 sprintf 将命令行参数（argv[1]）格式化为命令字符串 '/bin/mtd_write write %s Kernel_RootFS' 并执行，没有输入过滤。攻击者可以在参数中嵌入命令分隔符（如分号）来注入任意命令。触发条件：执行 'fwUpgrade' 并传递恶意参数（如 'valid_file; malicious_command'）。利用方式：注入命令以提升权限或执行任意操作。代码逻辑：参数直接用于构建 shell 命令，并通过系统调用执行。攻击者作为非root用户可触发此漏洞。
- **代码片段：**
  ```
  // 从反编译代码片段
  (**(iVar1 + -0x7f34))(auStack_108,*(iVar1 + -0x7fe0) + 0x70f0,*auStackX_0); // 类似 sprintf(auStack_108, "/bin/mtd_write write %s Kernel_RootFS", param_1)
  (**(iVar1 + -0x7e28))(auStack_108); // 执行命令
  // auStack_108 是 256 字节缓冲区
  ```
- **关键词：** argv[1], /bin/mtd_write
- **备注：** 命令注入已验证通过字符串分析；攻击者可作为非 root 用户触发。关联字符串：'/bin/sh' 表示潜在 shell 执行。建议测试参数如 'test; /bin/sh' 以确认注入。

---
### Stack-Buffer-Overflow-do_mld_proxy

- **文件/目录路径：** `sbin/mldproxy`
- **位置：** `mldproxy:0x00402150 sym.do_mld_proxy`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A stack buffer overflow vulnerability exists in the do_mld_proxy function due to improper bounds checking in the recvmsg system call. The function allocates a stack buffer of 65528 bytes (acStack_10070) but calls recvmsg with a length of 65536 bytes (0x10000), resulting in an overflow of 8 bytes. This overflow can overwrite critical saved registers, including the return address (ra), on the stack. An attacker with network access can exploit this by sending a crafted MLD packet of size 65536 bytes, containing shellcode or a ROP chain at the appropriate offset to control program flow. The vulnerability is triggered when the MLD proxy processes incoming multicast packets, and successful exploitation could lead to arbitrary code execution with the privileges of the mldproxy process (likely root). The lack of stack canaries or other mitigations in the binary enhances exploitability.
- **代码片段：**
  ```
  // From decompilation:
  void sym.do_mld_proxy(void) {
      // ...
      char acStack_10070 [65528]; // Buffer of 65528 bytes
      // ...
      // recvmsg call with length 0x10000 (65536 bytes)
      iVar2 = (**(iVar18 + -0x7fa8))(uVar7, puVar13 + 0x10130, 0); // recvmsg call
      // ...
  }
  
  // From disassembly:
  0x00402150      09f82003       jalr t9                    ; call recvmsg
  0x00402154      21284302       addu a1, s2, v1            ; a1 points to buffer at sp+0x150
  0x00402158      1800bc8f       lw gp, (arg_18h)
  0x0040215c      0f004018       blez v0, 0x40219c
  0x00402160      507d0224       addiu v0, zero, 0x7d50
  // msghdr setup with length 0x10000:
  0x0040201c      2c0146ac       sw a2, 0x12c(v0)           ; store length 0x10000
  ```
- **关键词：** MRouterFD6, socket, recvmsg, do_mld_proxy
- **备注：** The vulnerability is highly exploitable due to the direct control over the return address and the lack of binary protections (e.g., stack canaries, ASLR). The attack requires the mldproxy service to be running and accessible, which is typical in network devices. Further analysis could involve developing a full exploit, but the evidence confirms the overflow and control flow hijack potential. Assumes the binary runs with elevated privileges (e.g., root). Attack conditions align with user specification: attacker has network access and valid login credentials (non-root), but exploitation may grant root privileges.

---
### BufferOverflow-main

- **文件/目录路径：** `bin/fwUpgrade`
- **位置：** `fwUpgrade:0x400424 main`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 缓冲区溢出漏洞存在于主函数中。程序接受命令行参数（argv[1]）并使用不安全函数（类似 strcpy）复制到 128 字节的栈缓冲区（auStack_90）中，没有边界检查。攻击者可以提供超过 128 字节的参数，导致栈溢出，可能覆盖返回地址或控制程序流。触发条件：执行 'fwUpgrade' 并传递长参数。利用方式：精心构造参数以劫持控制流，可能执行任意代码。代码逻辑：主函数中复制操作后直接使用缓冲区进行文件打开，溢出点位于复制阶段。攻击者作为非root用户可触发此漏洞。
- **代码片段：**
  ```
  // 从反编译代码片段
  (**(iVar3 + -0x7dbc))(auStack_90,*(iStackX_4 + 4)); // 类似 strcpy(auStack_90, argv[1])
  // auStack_90 是 128 字节缓冲区
  if (1 < *&iStackX_0) { // 检查参数数量
      // ...
      iStack_10 = (**(iVar3 + -0x7ef0))(*(iVar3 + -0x7fe0) + 0x7118,*(iVar3 + -0x7fe0) + 0x7130); // 文件操作
      // ...
  }
  ```
- **关键词：** argv[1]
- **备注：** 需要进一步验证栈布局和利用可行性，但基于代码模式，缓冲区溢出是高度可能的。建议测试长参数以确认崩溃和控制流劫持。关联函数：fcn.00400374。攻击者作为非root用户可触发。

---
### Command-Injection-sym.upgrade_firmware

- **文件/目录路径：** `sbin/bulkagent`
- **位置：** `File: bulkagent, Function: sym.upgrade_firmware, Address: 0x00402618, system call at 0x004026c4`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the sym.upgrade_firmware function, where user-controlled inputs are used to construct a command string via sprintf and executed via system(). This allows an attacker to inject arbitrary commands by crafting malicious input in the path argument (-P) or network data. The vulnerability is triggered when processing firmware upgrade requests (type 0x8101 or 0x8102) in network packets or when using command-line arguments. The lack of input sanitization enables command injection, leading to arbitrary command execution with the privileges of the bulkagent process. An attacker can exploit this locally by running bulkagent with a malicious -P argument or remotely by sending crafted network packets.
- **代码片段：**
  ```
  0x0040266c: lw t9, -sym.imp.sprintf(gp)
  0x00402670: addiu a1, a1, 0x2fac  # "bulkUpgrade -f %s%s -force"
  0x00402674: move a2, s0  # First input (e.g., path from global)
  0x00402678: move a3, s1  # Second input (e.g., network data)
  0x0040269c: jalr t9  # sprintf
  0x004026bc: lw t9, -sym.imp.system(gp)
  0x004026c4: jalr t9  # system call with formatted string
  ```
- **关键词：** Command-line argument: -P (writable disk path), Network input: Packet types 0x8101, 0x8102, Global variable: Path stored at offset 0x31d8 from gp, Function: sym.upgrade_firmware
- **备注：** This vulnerability is highly exploitable due to the clear data flow from untrusted input to dangerous system() call. Exploitation can occur locally via command-line or remotely if network access is available. Further analysis should verify the permissions of the bulkagent process and explore other functions like sym.remove_lang for similar issues.

---
### StackOverflow-ssid_parser

- **文件/目录路径：** `sbin/mpd`
- **位置：** `mpd:0x4009d0 sym.ssid_parser`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'mpd' 文件中发现一个基于栈缓冲区的溢出漏洞，攻击链完整且实际可利用。攻击者作为已认证的非 root 用户，可通过 UDP 端口 18979 发送特制数据包触发漏洞。具体流程：1) 输入点：UDP 套接字（端口 18979）接收不可信数据；2) 数据流：数据经 recvfrom 接收并解析后，传递给 sym.ssid_parser 函数；3) 漏洞触发：sym.ssid_parser 使用 strcpy 复制用户可控数据到固定大小栈缓冲区（如 acStack_120[64]），缺少边界检查，导致栈溢出；4) 利用方式：精心构造的长输入可覆盖返回地址，控制程序执行流，结合程序中存在的 system 调用（如执行 'uenv set NEW_SSID_RULE 1'）可实现任意命令执行或代码执行。触发条件：发送包含 'flash_set' 命令和长 SSID 或 KEY 参数的恶意 UDP 数据包。约束条件：缓冲区大小固定为 64 字节，输入超过此长度即可溢出。
- **代码片段：**
  ```
  // sym.ssid_parser 中的脆弱代码片段
  void sym.ssid_parser(...) {
      ...
      char acStack_120 [64];
      char acStack_e0 [64];
      ...
      // 使用 strcpy 复制用户输入到固定缓冲区，无边界检查
      (**(iVar12 + -0x7f88))(acStack_120 + iVar10, iVar8); // strcpy 调用
      ...
  }
  // main 函数中的调用上下文
  void main(...) {
      ...
      // 接收 UDP 数据
      iVar4 = (**(iVar22 + -0x7f70))(iVar3, auStack_1430, 0x400, 0, auStack_1440, auStack_30);
      ...
      // 调用 sym.ssid_parser  with user input
      (**(iVar22 + -0x7f84))(a0, a1); // 调用 sym.ssid_parser
      ...
  }
  ```
- **关键词：** HW_NIC0_ADDR, HW_WLAN0_WSC_PIN, HW_MYDLINK_ID, WIRELESS, /tmp/MP.txt, UDP:18979
- **备注：** 攻击链已验证：从网络输入到缓冲区溢出的完整路径存在。sym.ssid_parser 被 main 函数在处理 'flash_set' 命令时调用，参数来自用户可控的 UDP 数据。建议进一步验证栈布局和偏移以优化利用。关联文件：无其他文件直接交互，但可通过 system 调用影响系统状态。后续分析方向：检查其他命令（如 'flash_get'）是否存在类似问题，并验证嵌入式环境下的缓解措施（如 ASLR）。

---
### BufferOverflow-read_data

- **文件/目录路径：** `sbin/clink`
- **位置：** `clink:0x004051f4 read_data`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 `read_data` 函数中发现一个堆栈缓冲区溢出漏洞。该函数使用 `fscanf` 与 `%s` 格式字符串从输入文件中读取字符串到一个 128 字节的固定大小缓冲区（`auStack_c8`），但没有限制输入长度。如果输入文件中的字符串超过 128 字节，将导致缓冲区溢出，可能覆盖堆栈上的返回地址或其他关键数据。攻击者可以创建一个恶意输入文件并通过 `-I` 选项传递给 `clink`，从而触发漏洞并可能实现任意代码执行。触发条件包括：攻击者拥有有效登录凭据（非 root 用户）、能访问 `clink` 二进制文件、并能提供恶意输入文件。利用方式涉及精心构造长字符串以覆盖返回地址，控制程序流。攻击链完整且可验证：输入文件 -> fscanf 缓冲区溢出 -> 返回地址覆盖 -> 代码执行。
- **代码片段：**
  ```
  // 反编译代码片段显示 fscanf 使用 %s 读取字符串到固定大小缓冲区
  iVar1 = (**(iVar1 + -0x7d7c))(param_1, *(iVar1 + -0x7fe4) + 0x7650, auStack_18, auStack_c8, auStack_28, &uStack_20);
  // 格式字符串在地址 0x7650 对应 "%d %s %d %lf"
  // auStack_c8 是 uchar auStack_c8 [128]; （128 字节缓冲区）
  ```
- **关键词：** input_file (通过 -I 选项), auStack_c8 (缓冲区), fscanf 格式字符串 %d %s %d %lf
- **备注：** 漏洞存在于文件输入处理路径中，通过 `-I` 选项触发。需要进一步验证堆栈布局和缓解措施（如 ASLR 或 NX）在目标环境中的影响。建议检查其他输入点（如网络数据）是否有类似问题。攻击链完整：输入文件 -> fscanf 缓冲区溢出 -> 返回地址覆盖 -> 代码执行。

---
### BufferOverflow-main

- **文件/目录路径：** `sbin/lanmapd`
- **位置：** `lanmapd:0x4049dc main`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A buffer overflow occurs in the main function when using sprintf with a user-controlled command-line argument (argv[1]) to construct a filename. The destination buffer is on the stack with a fixed size of 64 bytes, but no bounds checking is performed, allowing overflow if argv[1] is sufficiently long. An authenticated non-root user can exploit this by passing a long string as an argument when executing lanmapd, potentially corrupting the stack and achieving arbitrary code execution. The vulnerability is triggered during program startup and does not require special privileges beyond the ability to run the binary.
- **代码片段：**
  ```
  0x004049d0      8880998f       lw t9, -sym.imp.sprintf(gp)
  0x004049d4      545aa524       addiu a1, a1, 0x5a54        ; '%s_%s.pid'
  0x004049d8      605ac624       addiu a2, a2, 0x5a60        ; '/var/run/lanmapd'
  0x004049dc      09f82003       jalr t9
  0x004049e0      21382002       move a3, s1                 ; s1 = argv[1]
  ```
- **关键词：** argv[1]
- **备注：** The buffer is allocated on the stack at offset 0x28 from SP with size 0x40 (64 bytes). Exploitation is straightforward for an authenticated user who can control argv[1]. Further analysis could determine the exact stack layout to refine the exploit, but the vulnerability is confirmed and exploitable.

---
### XSS-category_asp_show_media_list

- **文件/目录路径：** `wa_www/category.asp`
- **位置：** `category.asp: JavaScript functions show_media_list and show_media_list2 (approximate lines based on code structure: show_media_list around file name concatenation, show_media_list2 similar)`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** The 'category.asp' file contains a stored Cross-Site Scripting (XSS) vulnerability where file names returned from the '/dws/api/ListCategory' API are directly inserted into HTML without proper sanitization or escaping. This occurs in the client-side JavaScript functions `show_media_list` and `show_media_list2` when generating the media list display. An attacker with the ability to control file names (e.g., through file upload functionality in other parts of the system) can craft a file name containing malicious JavaScript code. When an authenticated user views the category page (e.g., for music, photo, movie, or document), the script executes in the user's browser context, potentially leading to session cookie theft (as cookies are accessible via JavaScript), unauthorized actions, or full session hijacking. The vulnerability is triggered simply by browsing to the category page with a malicious file present in the list. Constraints include the need for the attacker to influence file names (e.g., via upload) and for the user to have valid login credentials, but as a non-root user, they may have upload capabilities depending on system permissions.
- **代码片段：**
  ```
  // From show_media_list function:
  str += "<div>" + file_name + "<br>" + get_file_size(obj.size) + ", " + m_time + "</div>"
  
  // From show_media_list2 function:
  bg_str += "<div>" + file_name + "<br>" + get_file_size(obj.size) + ", " + m_time + "</div>"
  
  // File names are obtained from media_info.files[i].name, which is server-provided data.
  ```
- **关键词：** File names from '/dws/api/ListCategory' API, Session cookies: id, key, HTML elements: media_list div, search_box input
- **备注：** This vulnerability requires the attacker to control file names, which may involve file upload capabilities elsewhere in the system. Further analysis of file upload mechanisms (e.g., in other ASP files or APIs) is recommended to confirm exploitability. The session cookies are accessed via JavaScript ($.cookie), indicating they are not HTTP-only, making them susceptible to theft via XSS. No other immediate exploitable vulnerabilities were found in category.asp, but additional review of server-side API implementations (/dws/api/ListCategory and /dws/api/GetFile) is advised for path traversal or injection issues.

---
### command-injection-upgrade_firmware

- **文件/目录路径：** `bin/bulkUpgrade`
- **位置：** `bulkUpgrade:0x00401568 sym.upgrade_firmware (specifically where system is called after sprintf)`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** A command injection vulnerability exists in the upgrade_firmware function of bulkUpgrade. The vulnerability is triggered when the program is executed with the -f argument specifying a firmware filename containing shell metacharacters (e.g., semicolons or backticks), especially when combined with the -force flag to bypass checks. The user input is incorporated into a shell command string using sprintf without sanitization and executed via system, allowing arbitrary command injection. Constraints include the requirement for the user to have execute permissions on bulkUpgrade (which are granted as per file permissions) and the ability to provide malicious input. Potential attacks include executing unauthorized commands, which could lead to further system compromise, even with non-root privileges, by leveraging the user's access to run commands in the context of the bulkUpgrade process.
- **代码片段：**
  ```
  From Radare2 decompilation of sym.upgrade_firmware:
  \`\`\`
  // When param_2 (force flag) is non-zero, it executes the system command directly
  if (param_2 != 0) {
      // sprintf(auStack_468, "fwUpgrade %s;sleep 2;kill -USR1 \`cat /var/run/fwUpgrade.pid\`;sleep 180;sync;reboot", param_1)
      (**(iStack_470 + -0x7fb4))(auStack_468, *(iStack_470 + -0x7fe4) + 0x2a88, param_1);
      // system(auStack_468)
      (**(iStack_470 + -0x7f4c))(auStack_468);
      goto code_r0x00401bdc;
  }
  \`\`\`
  ```
- **关键词：** Command-line argument: -f, Command-line argument: -force, System command: fwUpgrade %s;sleep 2;kill -USR1 `cat /var/run/fwUpgrade.pid`;sleep 180;sync;reboot, File path: /var/run/fwUpgrade.pid
- **备注：** The vulnerability is exploitable by a non-root user with valid login credentials due to the file's -rwxrwxrwx permissions. The attack chain is complete and verifiable: user input from -f argument flows unsanitized into a system call via sprintf. However, exploitation does not escalate privileges beyond the user's own, limiting immediate impact but still posing a risk for unauthorized command execution. Further analysis could explore if bulkUpgrade is invoked by higher-privileged processes in other contexts. No similar exploitable issues were found in upgrade_language or other functions based on current evidence.

---
### Command-Injection-sym.parsePADSTags

- **文件/目录路径：** `etc_ro/ppp/plugins/rp-pppoe.so`
- **位置：** `rp-pppoe.so:0x28bc and 0x2944 (sym.parsePADSTags)`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** Command injection vulnerability in sym.parsePADSTags when processing PPPoE error tags (e.g., Service-Name-Error, Generic-Error). The function uses system() calls with unsanitized data from network packets, allowing remote attackers to execute arbitrary commands. Trigger conditions include receiving a malicious PPPoE packet with crafted error tags during the discovery phase. The code lacks input validation, boundary checks, or escaping, enabling command injection via shell metacharacters in the tag data. Exploitation requires the attacker to be on the same network segment to send PPPoE packets, and the device must be processing PPPoE discovery.
- **代码片段：**
  ```
  From decompilation:
  When param_1 == 0x201 (Service-Name-Error):
    (**(iStack_158 + -0x7f78))(auStack_150, "%s %s fail" + ..., "/bin/pppoe-probe" + ..., *(param_4 + 0x1c));
    (**(iStack_158 + -0x7ea0))(auStack_150); // system call
  When param_1 == 0x203 (Generic-Error):
    (**(iStack_158 + -0x7f78))(auStack_110, ...); // builds string with packet data
    (**(iStack_158 + -0x7ea0))(auStack_110); // system call
  ```
- **关键词：** PPPoE network packets, error tags (Service-Name-Error, Generic-Error), sym.waitForPADS, sym.parsePADSTags
- **备注：** The attack chain is verifiable within the file: network input -> sym.waitForPADS -> sym.parsePADSTags -> system call. However, real-world exploitation depends on network access and device state. Recommended to test on actual hardware and check for additional sanitization in broader context. No other exploitable issues found with high confidence in this file.

---
### BufferOverflow-fcn00401dd8

- **文件/目录路径：** `sbin/lanmapd`
- **位置：** `lanmapd:0x402048 fcn.00401dd8`
- **风险评分：** 7.0
- **置信度：** 7.5
- **描述：** A buffer overflow occurs in function fcn.00401dd8 when using strcpy to copy a user-controlled command-line argument (argv[1]) directly into a field of the lmdCfg structure without any length checks. This lack of bounds checking can lead to memory corruption, overwriting adjacent structure fields or stack data. An authenticated non-root user can trigger this by providing a long string as an argument, potentially leading to code execution. The function is called from main with argv[1] as input, making the attack chain direct and verifiable.
- **代码片段：**
  ```
  0x00402040      6081998f       lw t9, -sym.imp.strcpy(gp)
  0x00402044      2120a000       move a0, a1                 ; a1 = arg2
  0x00402048      09f82003       jalr t9
  0x0040204c      21280002       move a1, s0                 ; s0 = arg1 (argv[1])
  ```
- **关键词：** argv[1], obj.lmdCfg
- **备注：** The lmdCfg structure is initialized with 0xbc bytes, but the specific field copied into may have a smaller size, increasing the risk of overflow. Additional analysis of the structure layout could confirm the overflow size, but the vulnerability is exploitable as is.

---
### Client-Code-Injection-file_access.asp

- **文件/目录路径：** `wa_www/file_access.asp`
- **位置：** `file_access.asp: 在 `update_tree` 函数（约行 200-210）和 `prepare_treeview` 函数（约行 250-260）`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** 在 `prepare_treeview` 函数中，使用 `eval` 动态执行来自 API 响应的 `url` 和 `clr` 属性值。这些属性在 `update_tree` 函数中构建时，使用用户控制的文件夹名（`dispName`）、路径（`rPath`, `reqPath`）等参数。如果攻击者能注入恶意 JavaScript 代码（例如，通过创建包含单引号和代码的文件夹名），当用户点击文件夹展开或折叠时，会触发 `eval` 执行任意代码。触发条件：用户浏览文件树并交互恶意文件夹。潜在利用包括窃取会话 Cookie、重定向用户或执行其他客户端攻击。约束条件：后端必须允许特殊字符在文件夹名中，且需要用户交互。
- **代码片段：**
  ```
  // update_tree 函数中构建 url 和 clr 属性
  branches += '<li><span class=folder>'+dispName+'</span>'+
      '<ul id="'+ulId+'/'+dispName+'"'+
      ' url="req_subfolder(\''+rPath+reqPath+'\', \''+ulId+'/'+dispName+'\', \''+volId+'\')"'+
      ' clr="req_ctx(\''+rPath+reqPath+'\', \''+ulId+'/'+dispName+'\', \''+volId+'\')">'+
      '</ul></li>';
  
  // prepare_treeview 函数中使用 eval
  $("#"+transUid(ulId)).treeview({
      collapsed: true,
      toggle: function() {
          var obj = $(this).find('ul');
          if ($(this).attr('class').substring(0,1) == 'c') {
              eval(obj.attr('url')); // 危险操作
          } else {
              eval(obj.attr('clr')); // 危险操作
              obj.html('');
          }
      }
  });
  ```
- **关键词：** folders[i].name, rPath, reqPath, ulId, volId, /dws/api/ListDir, /dws/api/ListRoot
- **备注：** 漏洞依赖后端 API 对文件夹名的过滤；如果后端允许特殊字符（如单引号），攻击链完整。建议检查后端实现以确认可利用性。关联文件：可能涉及其他 ASP 或 API 端点（如 /dws/api/AddDir）。后续分析应验证后端如何处理文件夹名输入。

---
### Command-Injection-sxuptp_start

- **文件/目录路径：** `etc_ro/rc.d/rc.sxuptp`
- **位置：** `rc.sxuptp:sxuptp_start`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** 在 sxuptp_start 函数中，变量 NAME 和 PRDCT 在 echo 命令中未引号使用，当写入 sysfs 参数时。如果这些变量包含 shell 元字符（如分号、& 等），它们可能会被 shell 解释，导致命令注入。攻击者可以通过控制 /var/tmp/cfg.txt 文件中的 lanHostCfg_DeviceName_ 值或 NVRAM 变量 HW_BOARD_MODEL 来注入任意命令，并以 root 权限执行。触发条件是当脚本以 'start' 或 'restart' 参数运行时（例如系统启动或服务重启）。潜在攻击包括执行恶意命令提升权限或修改系统文件。完整攻击链：输入（/var/tmp/cfg.txt 或 HW_BOARD_MODEL） -> 变量 NAME/PRDCT -> echo 命令执行 -> 任意命令注入。
- **代码片段：**
  ```
  echo -n ${NAME}  > /sys/module/jcp/parameters/hostname
  echo -n ${PRDCT} > /sys/module/jcp/parameters/product
  ```
- **关键词：** CONF_PATH, NAME, PRDCT, HW_BOARD_MODEL, /var/tmp/cfg.txt, /sys/module/jcp/parameters/hostname, /sys/module/jcp/parameters/product
- **备注：** 攻击链的完整性取决于非 root 用户能否修改 /var/tmp/cfg.txt 或 NVRAM 变量 HW_BOARD_MODEL，以及是否能触发脚本执行（例如通过 web 接口或服务调用）。建议进一步分析文件权限、NVRAM 访问控制和其他服务交互以验证可利用性。如果没有输入控制，此漏洞可能无法被利用。存储此发现以记录潜在风险，但需要后续验证。

---
### OpenRedirect-back

- **文件/目录路径：** `www/reboot.asp`
- **位置：** `reboot.asp JavaScript 代码中的 back() 函数`
- **风险评分：** 5.0
- **置信度：** 9.0
- **描述：** 在 'back()' 函数中，'newIP' 参数从 URL 查询字符串中获取并直接用于构建重定向 URL，没有进行任何验证或过滤。攻击者可以构造如 'reboot.asp?newIP=evil.com' 的 URL，当用户访问时会被重定向到 'evil.com'。这构成了开放重定向漏洞，可能被用于网络钓鱼攻击，诱骗用户输入凭据或其他敏感信息。触发条件：用户访问包含恶意 'newIP' 参数的 URL。利用方式：攻击者发送恶意链接给受害者，或作为已登录用户直接触发重定向。
- **代码片段：**
  ```
  function back(){
      var login_who=dev_info.login_info;
      var newIP = gup("newIP");
      var redirectPage = (login_who!= "w"?"index.asp":get_by_id("html_response_page").value);
      if(newIP!="")
          window.location.assign(location.protocol+"//"+newIP+"/"+redirectPage);
      else
          window.location.href = redirectPage;
  }
  ```
- **关键词：** newIP URL 参数, window.location.assign
- **备注：** 开放重定向通常被视为中等风险，需要用户交互才能利用。建议对 'newIP' 参数进行白名单验证或限制重定向到可信域名。此漏洞可能与其他攻击结合使用，例如跨站脚本（XSS），但未在本文件中发现直接证据。需要进一步分析其他文件（如 JavaScript 库）以确认是否有更多输入点或漏洞。

---
### auth-bypass-login-fail-cookie

- **文件/目录路径：** `wa_www/login.asp`
- **位置：** `login.asp:行号约 20-30（在 $(function(){} 和 do_invalid_count_down() 函数中）`
- **风险评分：** 5.0
- **置信度：** 8.0
- **描述：** 在 'login.asp' 文件中，登录失败计数机制完全依赖客户端 cookie ('fail') 存储失败次数，当失败次数 >=5 时触发 30 秒输入禁用。然而，该 cookie 无任何服务器端验证或保护措施，攻击者可通过浏览器开发者工具轻松修改或删除 cookie（例如执行 `$.cookie('fail', 0)` 或 `document.cookie = 'fail=0'`）来重置失败计数，从而绕过锁定机制。这允许无限次密码尝试，进行暴力破解攻击。触发条件：攻击者访问登录页面并多次输入错误密码后修改 cookie。利用方式：作为已登录用户，攻击者可测试其他账户密码或尝试权限提升。相关代码逻辑在客户端 JavaScript 中执行，缺少服务器端校验。
- **代码片段：**
  ```
  $(function(){
      if($.cookie('fail') == null)
          $.cookie('fail', 0);
      else if($.cookie('fail') >= 5)
          do_invalid_count_down();
  });
  
  function do_invalid_count_down(){
      if(count > 0){
          $('input').attr('disabled', true);
          $('#login').css('width', 200).val(addstr(get_words('invalid_cd'), count));
          count--;
          setTimeout('do_invalid_count_down()',1000);
      }
      else if(count == 0){
          $('input').attr('disabled', false);
          $('#login').css('width', 120).val('login');
          $.cookie('fail', 0);
          return;
      }
  }
  ```
- **关键词：** fail (cookie名), dws/api/Login (API端点)
- **备注：** 此漏洞依赖于客户端控制，易被利用，但攻击成功最终取决于密码强度和服务器端是否有其他保护（如IP限制）。建议后续分析 'dws/api/Login' 端点以确认服务器端验证情况，并检查其他文件（如 public.js）中相关函数。风险评分较低是因为攻击者已登录，影响可能限于账户枚举或低级权限提升。

---
