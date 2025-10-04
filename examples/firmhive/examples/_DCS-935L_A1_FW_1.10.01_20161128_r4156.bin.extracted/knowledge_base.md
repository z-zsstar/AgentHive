# _DCS-935L_A1_FW_1.10.01_20161128_r4156.bin.extracted (17 个发现)

---

### Command-Injection-write_param_to_flash

- **文件/目录路径：** `bin/wscd`
- **位置：** `File: wscd, Function: write_param_to_flash, Address: 0x00419518`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the 'wscd' binary via the '-w' command-line argument. The argument value is copied unsanitized into a buffer and used in a system call within the 'write_param_to_flash' function. An attacker with valid login credentials can exploit this by providing a malicious interface name containing shell metacharacters (e.g., semicolons) to execute arbitrary commands with root privileges. The vulnerability is triggered during the WPS configuration process when 'write_param_to_flash' is called, typically after initialization or during event processing.
- **代码片段：**
  ```
  Relevant code from write_param_to_flash:
  (**(loc._gp + -0x7eac))(auStack_a8,"%s -param_file %s %s","flash",param_1 + 0x188,"/tmp/flash_param");
  (**(loc._gp + -0x7bfc))(auStack_a8);
  Here, param_1 + 0x188 points to user-controlled data from the '-w' argument, and auStack_a8 is a stack buffer of 120 bytes. The system call executes the constructed string without validation.
  ```
- **关键词：** Command-line argument: -w (wlan interface), NVRAM/ENV variables: None directly, but derived from command-line input, Function: write_param_to_flash, Dangerous operation: system call
- **备注：** This vulnerability requires the attacker to have shell access and permissions to execute 'wscd'. The attack chain is straightforward and reliably exploitable. Additional analysis should check for similar issues in other command-line arguments (e.g., -br, -fi) and in network handling functions like ExecuteSoapAction. The buffer size (120 bytes) may limit the length of injected commands but is sufficient for most payloads.

---
### Command-Injection-PushDCHEventNotifyCheck

- **文件/目录路径：** `usr/sbin/hnap_push_service`
- **位置：** `hnap_push_service:0x00407210 PushDCHEventNotifyCheck`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the PushDCHEventNotifyCheck function where unsanitized input from XML policy files is used in system commands. The function reads policy data from '/mnt/flash/config/hnap_policy.xml' and uses values like DeviceMacID, ModuleID, etc., in formatted strings passed to system(). For example, when handling event 422015 (ACTION_ID_SNAP_NOTIFY), the code executes: '/usr/sbin/msger eventd 0 eiotsnapshottrigger 1 "%d %s %d %d %s" 2>/dev/null 1>/dev/null' with data from XML. If an attacker can set malicious values in the policy (e.g., via HNAP requests), they can inject shell metacharacters to execute arbitrary commands. The service runs as root, so command execution occurs with root privileges. Triggering requires an event that matches the policy, but an attacker can set the policy to trigger on specific events.
- **代码片段：**
  ```
  // From decompilation at ~0x00408a00 in PushDCHEventNotifyCheck
  (**(iVar28 + -0x7f60)) (*(&stack0x0004df9c + iVar5), "/usr/sbin/msger eventd 0 eiotsnapshottrigger 1 \"%d %s %d %d %s\" 2>/dev/null 1>/dev/null", 0, *(&stack0x0004dfc0 + iVar5));
  (**(*(apcStack_7fc8 + iVar5) + -0x7e48)) (*(&stack0x0004df9c + iVar5)); // system call
  // *(&stack0x0004dfc0 + iVar5) contains data from XML tags like DeviceMacID
  ```
- **关键词：** /mnt/flash/config/hnap_policy.xml, DeviceMacID, ModuleID, EventID, ActionID
- **备注：** The vulnerability requires the attacker to set the policy via HNAP or other means, which may be feasible with login credentials. Other events (e.g., 422017, 422019) have similar code patterns. Further analysis should verify HNAP handlers in other binaries that write the policy file.

---
### CommandInjection-param.cgi-PanTilt

- **文件/目录路径：** `web/cgi-bin/cgi/param.cgi`
- **位置：** `param.cgi:0x0040365c (fcn.0040365c) - PanTilt parameter handling`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the PanTilt configuration update functionality of param.cgi. When an authenticated admin user submits a request with action='update', group='PanTilt', and name='Position1' (or similar position names), the user-provided value is directly incorporated into a system command without proper sanitization. This allows an attacker to inject arbitrary commands by including shell metacharacters (e.g., semicolons or backticks) in the value parameter. The vulnerable code uses a sprintf-like function to format a command string and then executes it via system(), leading to remote command execution with the privileges of the CGI process.
- **代码片段：**
  ```
  // From fcn.0040365c decompilation
  iVar1 = (**(loc._gp + -0x7f68))(param_4, "Position1");
  if (iVar1 == 0) {
      (**(loc._gp + -0x7f78))(&uStack_21c, "/usr/sbin/ptctrl -setpreset0=%s 2>/dev/null 1>/dev/null", param_5);
      (**(loc._gp + -0x7ef4))(&uStack_21c);
  }
  ```
- **关键词：** action, group, name, value
- **备注：** This vulnerability requires admin-level authentication, as the code checks *0x431d60 == 1 before processing. The attack chain is complete from input (CGI parameters) to dangerous operation (system call). No evidence of input sanitization was found. Additional positions (Position2 to Position8) are similarly vulnerable. Exploitation could lead to full device compromise.

---
### Command-Injection-sym.usrAdd

- **文件/目录路径：** `usr/lib/libweb.so`
- **位置：** `libweb.so.0:0x75c0 sym.usrAdd`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** The function sym.usrAdd in libweb.so.0 constructs a shell command using system to execute /usr/sbin/set_passwd for adding users. The username parameter (param_2) is directly incorporated into the command string without any sanitization or escaping, while only the password parameter (param_3) is escaped for a limited set of characters (", `, \, $). This allows an attacker to inject arbitrary shell commands by including metacharacters (e.g., ;, |, &) in the username parameter. For example, a username like " ; echo injected ; " would break the command string and execute echo injected. The vulnerability is triggered when a user addition request is processed, typically via a web API. Attackers with valid non-root credentials can exploit this if the web interface lacks proper authorization checks, leading to arbitrary command execution with the privileges of the web server process (which may be root).
- **代码片段：**
  ```
  // Decompilation snippet showing the vulnerable code
  (**(iVar11 + -0x7f34))(&cStack_230, *(iVar11 + -0x7fdc) + -0x1dc, param_2, acStack_130);
  (**(iVar11 + -0x7e10))(&cStack_230); // system call
  
  // Assembly at 0x75c0:
  // 0x000075c0      8f9981f0       lw t9, -sym.imp.system(gp)
  // 0x000075c4      0320f809       jalr t9
  // 0x000075c8      02202021       move a0, s1
  // Where s1 contains the command string with unsanitized username.
  ```
- **关键词：** param_2 (username input), /usr/sbin/set_passwd (command executed), system function call, usrAdd
- **备注：** This vulnerability requires the attacker to have access to the user addition functionality, which may be restricted to administrative users in some configurations. However, if the web interface has improper access control, non-admin users could trigger it. The web server process privileges determine the impact; if running as root, full system compromise is possible. Further analysis should verify the access control mechanisms in the web application using this library. Other functions like sym.calculateSDUsedSize and sym.dropCache also use system but were not fully analyzed for similar issues. Associated with existing finding in user_mod.cgi via 'usrAdd' identifier.

---
### StackOverflow-user_del.cgi-fcn.00400a90

- **文件/目录路径：** `web/cgi-bin/config/user_del.cgi`
- **位置：** `user_del.cgi:未知行号 fcn.00400a90 地址 0x00400a90`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** 在 'user_del.cgi' 的 fcn.00400a90 函数中，发现一个栈缓冲区溢出漏洞。该函数处理 HTTP 请求中的 'name' 参数，使用 strcpy 将其复制到栈上的固定地址 &cStack_420，没有进行任何大小检查或边界验证。攻击者作为已登录的非 root 用户，可以通过发送恶意的长 'name' 参数（例如，通过 CGI 请求）溢出缓冲区，覆盖栈上的返回地址，从而可能实现任意代码执行。漏洞触发条件是发送包含超长 'name' 值的 HTTP 请求，利用链完整：从输入点（HTTP 'name' 参数）到危险操作（strcpy 到栈缓冲区）。代码逻辑显示，在比较参数为 'name' 后，直接使用 strcpy 复制数据，缺乏过滤。
- **代码片段：**
  ```
  // 从反编译代码片段：
  if (iVar1 == 0) {
      (**(loc._gp + -0x7f84))(&cStack_420,piVar6[iVar2 + 0x81]); // strcpy 调用，目标为 &cStack_420，源为用户输入
      if (cStack_420 != '\0') {
          // ... 后续处理
      }
  }
  ```
- **关键词：** name
- **备注：** 缓冲区大小未明确指定，但从栈变量 'cStack_420' 和 'auStack_41f [1023]' 的布局推断，溢出可能覆盖返回地址。建议进一步动态测试以验证利用可行性，并检查其他函数（如 usrDelByName）是否涉及更多交互。由于文件为 stripped ELF，行号不可用，地址基于反编译。注意：'name' 标识符也出现在 param.cgi 的命令注入漏洞中，但两者独立。

---
### File-Permission-rcS

- **文件/目录路径：** `etc/rc.d/rcS`
- **位置：** `rcS:1 (file permissions) - 权限设置为 777，允许所有用户访问`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 文件 'rcS' 具有全局读写执行权限（-rwxrwxrwx），允许任何用户（包括非root用户）修改该启动脚本。攻击者可以注入恶意命令（如反向shell或权限提升代码），这些命令将在系统启动时以root权限执行。触发条件为攻击者修改文件并等待系统重启（或主动触发重启）。缺少边界检查或验证，因为脚本以root身份无条件执行。潜在攻击方式包括添加持久化后门或直接获取root shell。
- **代码片段：**
  ```
  文件权限: -rwxrwxrwx 1 user user 1226 11月 28  2016 rcS
  文件内容包含启动时执行的命令，如 mount_jffs2 函数和 /etc/init.d/ 脚本执行。
  ```
- **关键词：** /etc/rc.d/rcS
- **备注：** 此漏洞依赖于系统重启来触发恶意代码执行。建议检查系统是否有自动重启机制或攻击者是否能触发重启。后续分析应验证其他启动脚本的权限和内容，以确认是否存在类似问题。

---
### 命令注入-httpd-runcgi

- **文件/目录路径：** `web/httpd`
- **位置：** `httpd:0x00402104 fcn.00402040 (execve 调用), httpd:0x004036ac fcn.00403038 (调用 fcn.00402040)`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** 在 httpd 二进制文件的 fcn.00402040 函数（标记为 'runcgi'）中，发现一个命令注入漏洞，允许攻击者通过 HTTP 请求执行任意命令。漏洞根源在于：HTTP 请求中的路径参数（以 '.cgi' 结尾）被直接传递给 execve 系统调用，而缺少适当的路径消毒或验证。攻击者需拥有有效登录凭据（非 root 用户），可构造恶意 HTTP 请求，路径指向任意可执行文件（例如，通过路径遍历如 '/../../../bin/sh' 或上传的恶意脚本）。触发条件为发送 HTTP 请求到 CGI 端点，路径以 '.cgi' 结尾。数据流从 HTTP 请求输入（通过 reqInit 解析）传播到 execve 调用，缺少边界检查，导致任意代码执行。利用概率高，因为攻击者可直接控制执行路径。
- **代码片段：**
  ```
  从反编译代码：
  - 在 fcn.00403038 的 0x004036ac：iVar7 = strcmp(piStack_40, ".cgi"); if (iVar7 == 0) { fcn.00402040(&ppiStack_458, param_4, &uStack_454); }
  - 在 fcn.00402040 的 0x00402104：execve(*(*param_1 + 0x1c), uVar2, uVar1); // 其中 *(*param_1 + 0x1c) 是用户控制的路径
  ```
- **关键词：** HTTP 请求路径, reqInit 函数, execve 系统调用, struct offset 0x1c, NVRAM: 用户认证数据（如 USER_ADMIN、Password1）
- **备注：** 污点分析确认了从 HTTP 用户输入到 execve 的直接数据流。需要进一步验证 reqInit 中的路径构造细节和文件系统限制（如 web 根目录约束）。建议在完整固件环境中测试以确认利用性。关联函数包括 reqMakeArg 和 reqMakeEnv，可能引入额外漏洞如果用户输入流入参数或环境变量。

---
### 无标题的发现

- **文件/目录路径：** `web/cgi-bin/config/user_mod.cgi`
- **位置：** `user_mod.cgi:0x00400ad0 fcn.00400ad0`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** 在 'user_mod.cgi' 的 fcn.00400ad0 函数中，存在栈缓冲区溢出漏洞。问题表现为使用 strcpy 函数将用户控制的 CGI 参数（name、newname、password、group）直接复制到固定大小的栈缓冲区，缺乏长度验证。触发条件为攻击者提交 CGI 请求，其中任一参数长度超过缓冲区大小（name、newname、group 为 64 字节，password 为 256 字节）。约束条件包括参数不能为空，但无长度限制。潜在攻击方式包括构造超长参数覆盖返回地址，注入 shellcode 并控制执行流，可能提升权限（CGI 通常以 root 运行）。相关代码逻辑涉及循环解析 CGI 参数并使用 strcpy 复制数据。
- **代码片段：**
  ```
  // 示例 strcpy 调用用于 'name' 参数
  iVar1 = (**(loc._gp + -0x7fb8))(uVar4, "name");
  if (iVar1 == 0) {
      (**(loc._gp + -0x7f7c))(pcStack_44, piVar2[iVar3 + 0x81]); // strcpy 调用，pcStack_44 指向 64 字节缓冲区
  }
  // 类似代码用于 'newname', 'password', 'group' 参数
  // 缓冲区声明：
  // char cStack_288; uchar auStack_287[63]; // 64 字节缓冲区 for name
  // char cStack_248; uchar auStack_247[63]; // 64 字节缓冲区 for newname
  // uchar uStack_148; uchar auStack_147[255]; // 256 字节缓冲区 for password
  // char cStack_1c8; uchar auStack_1c7[63]; // 64 字节缓冲区 for group
  ```
- **关键词：** name, newname, password, group, sym.imp.strcpy, fcn.00400ad0, usrAdd, usrDelByName
- **备注：** 漏洞基于静态代码分析，显示完整的攻击链：不可信输入（CGI 参数）-> 无验证数据流（strcpy）-> 危险操作（缓冲区溢出）。建议进一步验证栈偏移量和利用可行性，例如通过动态测试或计算具体偏移。关联函数包括 usrAdd 和 usrDelByName，可能涉及用户管理操作。

---
### Command-Injection-pppoe-status

- **文件/目录路径：** `sbin/pppoe-status`
- **位置：** `pppoe-status:行号 22-28（命令行参数处理）和行号 31（配置文件加载）`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 'pppoe-status' 脚本中发现一个命令注入漏洞，允许攻击者通过恶意配置文件执行任意命令。具体表现：脚本接受一个可选的配置文件路径作为命令行参数，并使用 'source' 命令加载该文件。如果攻击者能控制配置文件路径和内容，他们可以注入恶意 shell 代码。触发条件：攻击者运行 'pppoe-status /path/to/malicious/config'，其中恶意配置文件包含任意命令（如 'malicious_command'）。脚本以当前用户权限执行这些命令，导致权限提升或系统破坏。边界检查：脚本仅验证配置文件是否存在且可读（'[ ! -f "$CONFIG" -o ! -r "$CONFIG" ]'），但未对内容进行验证。潜在攻击：攻击者创建恶意配置文件并执行，可能获取敏感信息、修改文件或进一步提权。
- **代码片段：**
  ```
  case "$#" in
      1)
  	CONFIG="$1"
  	;;
  esac
  
  if [ ! -f "$CONFIG" -o ! -r "$CONFIG" ] ; then
      echo "$0: Cannot read configuration file '$CONFIG'" >& 2
      exit 1
  fi
  
  . $CONFIG
  ```
- **关键词：** CONFIG（环境变量/命令行参数）, /etc/ppp/pppoe.conf（默认配置文件路径）, PIDFILE（从配置文件加载的变量）, PPPOE_PIDFILE, PPPD_PIDFILE
- **备注：** 攻击链完整且可验证：输入点（命令行参数）→ 数据流（CONFIG 变量）→ 危险操作（source 命令）。需要进一步验证攻击者是否能创建恶意配置文件（例如，在用户可写目录中）。建议检查系统权限和配置文件默认位置。关联文件：/etc/ppp/pppoe.conf（默认配置）。后续分析方向：检查其他脚本是否类似使用配置文件加载机制。

---
### BufferOverflow-cfg-main

- **文件/目录路径：** `usr/sbin/cfg`
- **位置：** `cfg:0x004008e0 main (反编译代码中 sprintf 和 strcat 调用点)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'cfg' 程序中发现缓冲区溢出漏洞。程序使用 sprintf 和 strcat 构建文件路径时，用户通过命令行参数控制的路径（-p 选项）和配置文件名称未经验证长度。栈缓冲区 auStack_13c 大小为 260 字节，如果用户提供的路径和文件名组合超过 260 字节，将溢出到相邻栈变量（如 uStack_38、pcStack_34）和可能的返回地址。攻击者作为已登录非 root 用户，可通过执行 'cfg -p <长路径> <长文件名> ...' 触发溢出，精心构造输入可覆盖返回地址，导致任意代码执行。漏洞触发条件：命令行参数总长度超过 260 字节，且路径和文件名可控。利用方式：通过溢出覆盖返回地址，跳转到 shellcode 或现有代码片段，实现权限提升或命令执行。
- **代码片段：**
  ```
  // 关键代码片段从反编译 main 函数中提取
  (**(loc._gp + -0x7fb8))(auStack_13c, "%s/", pcStack_34); // sprintf 构建路径，pcStack_34 是用户输入的路径
  (**(loc._gp + -0x7fa4))(auStack_13c, pcVar5); // strcat 追加文件名，pcVar5 是用户输入的 conf_file
  // 缓冲区 auStack_13c 大小为 260 字节，无长度检查
  if (溢出发生) {
      // 可能覆盖 uStack_38（action 参数）、pcStack_34（路径指针）等，进而影响控制流
  }
  ```
- **关键词：** 命令行参数, CfgGetField, CfgSetField, CfgRemoveField
- **备注：** 漏洞基于实际代码分析，栈布局通过反编译确认。需要进一步验证返回地址偏移和利用可行性，例如通过动态测试或更详细的栈分析。建议后续分析：检查其他函数（如 CfgGetField）是否也存在类似问题，并评估在真实环境中的利用难度。攻击链完整：从用户输入（命令行）到危险操作（缓冲区溢出），可能导致代码执行。

---
### BufferOverflow-RTSP-RequestProcess

- **文件/目录路径：** `usr/sbin/rtsp/rtspd`
- **位置：** `rtspd:0x40443c RequestProcess`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** In the RequestProcess function, when handling RTSP PLAY requests, the code uses sprintf to format a URI string from user-controlled inputs without proper bounds checking. Specifically, at address 0x40443c, sprintf is called with a destination buffer that may be fixed-size, and the inputs include scheme, host, port, and path from the RTSP request. An attacker can craft a long URI in a PLAY request to overflow the buffer, potentially leading to arbitrary code execution. The trigger condition is sending a malicious PLAY request with an overly long URI. Constraints include the buffer size not being verified, and the attack can be performed by an authenticated non-root user via the RTSP interface.
- **代码片段：**
  ```
  // From RequestProcess decompilation
  if (*(param_1 + 0x4c) < 1) {
      sprintf(iVar11, "%s://%s/%s", *(param_1 + 0x3c), *(param_1 + 0x48), *(param_1 + 0x50));
  } else {
      sprintf(iVar11, "%s://%s:%d/%s", *(param_1 + 0x3c), *(param_1 + 0x48), *(param_1 + 0x4c), *(param_1 + 0x50));
  }
  ```
- **关键词：** RTSP PLAY method, URI parameters
- **备注：** This vulnerability is highly exploitable due to the use of sprintf without bounds checking. The destination buffer iVar11 is likely on the stack, making it susceptible to stack-based buffer overflow. Further analysis is needed to determine the exact buffer size and exploitability, but the presence of this pattern in a network-facing function makes it a prime target. Recommend testing with long URIs to confirm overflow.

---
### Command-Injection-userconfig-restore

- **文件/目录路径：** `usr/sbin/userconfig`
- **位置：** `文件:userconfig 行号:未指定（二进制文件） 函数名:fcn.004014ec 地址:0x004014ec`
- **风险评分：** 6.5
- **置信度：** 8.5
- **描述：** 在 'userconfig' 程序的 -restore 功能中发现命令注入漏洞。攻击者可以创建一个恶意文件，其中组名或项名包含命令注入字符（如 ;、|、&、$ 等），然后执行 'userconfig -restore <file_path>'。程序在构建命令字符串时使用 sprintf，并将组名和项名直接嵌入命令中，而没有充分转义或验证。尽管值被转义了双引号、反引号和反斜杠，但组名和项名没有转义，导致命令注入。例如，如果组名为 '; rm -rf /'，则构建的命令可能变为 'userconfig -write "; rm -rf /" "item" "value"'，从而执行任意命令。攻击者需有文件写入权限来创建恶意文件，但作为已登录用户，这通常可行。漏洞允许执行任意命令，但以当前用户权限运行，因此不会直接提升权限，但可能用于信息泄露、横向移动或进一步攻击。
- **代码片段：**
  ```
  关键代码片段来自反编译：
  (**(loc._gp + -0x7f9c))(puStack_34, "%s -write \"%s\" \"%s\" \"%s\" 2>/dev/null 1>/dev/null", *&uStackX_0, iStack_44, iStack_40, pcStack_38);
  (**(loc._gp + -0x7f38))(puStack_34); // system call
  其中 iStack_44（组名）和 iStack_40（项名）来自用户提供的文件内容，未转义；pcStack_38 是值，已转义。
  ```
- **关键词：** NVRAM 变量: HW_NIC0_ADDR, HW_NIC1_ADDR, HW_WLAN0_WLAN_ADDR, Region, 文件路径: /etc/userconfig.ini, /tmp/sys_env, 命令字符串: "%s -write \"%s\" \"%s\" \"%s\" 2>/dev/null 1>/dev/null"
- **备注：** 漏洞已验证通过代码分析：组名和项名未转义，直接用于命令构建。攻击链完整：用户创建恶意文件 → 执行 userconfig -restore → 命令注入。建议检查其他功能（如 -backup）是否有类似问题，但当前焦点已确认。由于以用户权限运行，无直接权限提升，但可结合其他漏洞使用。

---
### buffer-overflow-msger-main

- **文件/目录路径：** `usr/sbin/msger`
- **位置：** `msger:main (0x00401150), approximate address 0x00401310 for strcpy call`
- **风险评分：** 6.5
- **置信度：** 7.5
- **描述：** A buffer overflow vulnerability exists in the 'msger' binary when processing command-line arguments in inform mode (MsgType 0). The vulnerability occurs due to the use of strcpy to copy user-controlled input from argv[5] to a fixed-size stack buffer (auStack_12c, 65 uint elements, 260 bytes) without bounds checking. Additionally, a loop copies subsequent arguments using strtol, which may further contribute to buffer overflow. Trigger conditions include running the program with at least 6 arguments in inform mode, where the fifth argument is a string. An attacker can craft long arguments to overflow the buffer, overwrite the return address, and achieve code execution. The program's world-executable permissions (rwxrwxrwx) allow any user to exploit this vulnerability.
- **代码片段：**
  ```
  From main function decompilation:
  if (uVar1 == 0) { // Inform mode
      // ...
      iVar4 = (**(pcVar10 + -0x7fc4))(*(param_2 + 0x10)); // strlen(argv[4])
      if (iVar4 == 0) {
          (**(pcVar10 + -0x7f64))(auStack_12c, *(param_2 + 0x14)); // strcpy(auStack_12c, argv[5])
          // ...
      } else {
          // Loop for additional arguments
          puVar6 = auStack_12c;
          iVar7 = 5;
          do {
              uVar5 = (**(loc._gp + -0x7f84))(*(param_2 + 0x14), 0, 0); // strtol
              *puVar6 = uVar5;
              iVar7 = iVar7 + 1;
              param_2 = param_2 + 4;
              puVar6 = puVar6 + 1;
          } while (iVar7 < param_1);
      }
  }
  ```
- **关键词：** argv, strcpy, msgInformEventStr, msgQueryParam, camsvr, eventd, sinfo, hwmon, netmgr
- **备注：** The vulnerability is clear from static code analysis, but dynamic verification is needed to confirm exploitability on MIPS architecture. The binary interacts with various message servers (e.g., via msgInformEventStr), but the vulnerability is local to argument processing. Assumption: attacker has login credentials and can execute the binary. Further analysis should focus on crafting a working exploit and checking if the binary is called by other services with elevated privileges.

---
### 无标题的发现

- **文件/目录路径：** `web/cgi-bin/config/system_reboot.cgi`
- **位置：** `system_reboot.cgi:0x00400a20 main`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在 'system_reboot.cgi' 的 main 函数中，存在参数检查逻辑漏洞，允许攻击者通过精心构造的 HTTP 请求触发系统重启。漏洞触发条件：攻击者必须发送至少 130 个参数的 HTTP 请求，其中第 4 个参数（argv[3]）必须为 'reboot'，第 129 个参数（argv[128]）必须为 'go'。代码使用 strcmp 比较参数，但访问了 argv 数组的越界位置（如 piVar3[iVar4 + 0x81]）。如果条件满足且全局变量 *0x4110d4（由 readUpFwStatus 设置）不为 1，则调用 safeReboot(3) 执行系统重启。潜在攻击方式：攻击者作为已认证用户发送特制请求，导致设备重启，造成拒绝服务。漏洞利用依赖于 web 服务器对参数数量的限制，但理论上可行。
- **代码片段：**
  ```
  uint main(void)
  {
      // ... 代码省略 ...
      iVar2 = 0;
      do {
          iVar2 = strcmp(*(piVar3 + iVar2 + 4), "reboot");
          if (iVar2 == 0) {
              iVar2 = strcmp(piVar3[iVar4 + 0x81], "go");
              if (iVar2 == 0) {
                  *0x4110d0 = 1;
                  // ... 输出 HTTP 响应 ...
              }
          }
          iVar4 = iVar4 + 1;
          piVar3 = *(iVar1 + 0x58);
          iVar2 = iVar4 * 4;
      } while (iVar4 < *piVar3);
      // ... 代码省略 ...
      if ((*0x4110d0 != 0) && (*0x4110d4 != 1)) {
          safeReboot(3);
      }
      return 0;
  }
  ```
- **关键词：** system_reboot.cgi, HTTP 请求参数 'reboot', HTTP 请求参数 'go', NVRAM 变量（通过 readUpFwStatus 读取）
- **备注：** 漏洞利用需要 web 服务器允许大量参数，可能受实际配置限制。建议进一步验证 web 服务器的参数数量限制和 readUpFwStatus 的行为。关联函数：cgiInit, safeReboot, readUpFwStatus。后续分析方向：检查 web 服务器配置和 NVRAM 设置以确认可利用性。

---
### OOB-Read-Auth-Bypass-ACAS-main

- **文件/目录路径：** `web/cgi-bin/audio/ACAS.cgi`
- **位置：** `ACAS.cgi:main (address 0x00400c80, specifically around the out-of-bounds access)`
- **风险评分：** 6.0
- **置信度：** 8.0
- **描述：** The vulnerability occurs in the main function when processing CGI arguments. If the number of arguments (argc) is 1, the code checks if the first argument is "profileid". If true, it accesses argv[129] (0x81 index) via atoi without bounds checking, which is out-of-bounds for typical CGI requests. An attacker can exploit this by providing 130 or more arguments, with argv[1] as "profileid" and argv[129] as "2", to bypass the authentication check and proceed to audio streaming. The streaming then depends on the NVRAM variable 'MicEnable' being set to 1, which could lead to unauthorized audio streaming and information disclosure. Trigger conditions include: argc=1, argv[1]="profileid", argv[129]="2", and 'MicEnable'=1. Potential attack involves sending a crafted CGI request with many arguments to bypass checks and access audio data.
- **代码片段：**
  ```
  if (*piVar6 == 1) {
      iVar3 = strcmp(piVar6[1],"profileid");
      if (iVar3 == 0) {
          iVar3 = atoi(piVar6[0x81]);
          bVar1 = iVar3 == 2;
          goto code_r0x00400d18;
      }
  }
  ```
- **关键词：** CGI arguments (argv), NVRAM variables: AUDIO_PROFILE0, NVRAM variables: MicEnable, NVRAM variables: QoS, NVRAM variables: AudioDSCP
- **备注：** The exploit requires the attacker to have valid login credentials (as per scenario) and the ability to send CGI requests with many arguments. The success also depends on the 'MicEnable' NVRAM variable being set to 1, which may not be under attacker control if they are non-root. Web server argument limits could affect exploitability. Further analysis could explore other functions in ACAS.cgi for additional vulnerabilities, but this was the primary finding.

---
### CGI-Args-Null-Deref-main

- **文件/目录路径：** `web/cgi-bin/audio/ACAS-AAC.cgi`
- **位置：** `main function (0x00400c80) at addresses where piVar6[1] and piVar6[0x81] are accessed`
- **风险评分：** 5.5
- **置信度：** 8.0
- **描述：** The main function accesses CGI arguments without proper bounds checking. When argc is 1 (no arguments provided), the code calls strcmp on argv[1], which is NULL, leading to a segmentation fault and denial-of-service. Additionally, if argc is 2 and argv[1] is 'profileid', the code accesses argv[129] using atoi, which is always out-of-bounds for normal CGI requests. This could read arbitrary stack memory, potentially disclosing sensitive information like environment variables or return addresses. An attacker can trigger this by crafting a CGI request with 'profileid' as the first argument and no additional arguments, causing a crash or memory leak. However, full code execution is unlikely without control over memory layout.
- **代码片段：**
  ```
  if (*piVar6 == 1) {
      iVar3 = strcmp(piVar6[1], "profileid");
      if (iVar3 == 0) {
          iVar3 = atoi(piVar6[0x81]);
          // ...
      }
  }
  ```
- **关键词：** profileid, argv
- **备注：** This vulnerability is reliably triggered with specific CGI arguments but requires further analysis to determine if information disclosure can be leveraged for privilege escalation. The web server's handling of argc/argv may affect exploitability.

---
### Audio-Stream-OOB-Read-main

- **文件/目录路径：** `web/cgi-bin/audio/ACAS-AAC.cgi`
- **位置：** `main function (0x00400c80) in the loop after pfRead calls`
- **风险评分：** 4.5
- **置信度：** 7.0
- **描述：** In the audio streaming loop, the program uses pfRead to read data and then calls skAsyncWrite with fixed offsets (0x1c and 0x44) and sizes. If pfRead returns less than 0x44 bytes, the second skAsyncWrite call may read beyond the buffer boundaries, leading to an out-of-bounds read. This could result in memory disclosure (e.g., heap or stack data) or a crash. An attacker might exploit this by controlling the input source to pfRead (e.g., via a malicious audio file or stream), but practical exploitation requires influence over the audio data source. The vulnerability is conditional on pfRead behavior and may not directly lead to code execution.
- **代码片段：**
  ```
  do {
      iVar5 = pfRead(iVar3);
      if (0 < iVar5) break;
      // ...
      iVar4 = skAsyncWrite(1, *(iVar3 + 8) + 0x1c, 0x28, 0x3c);
      if (iVar4 < 0) break;
      iVar5 = skAsyncWrite(1, *(iVar3 + 8) + 0x44, iVar5 - 0x44, 0x3c);
  } while (-1 < iVar5);
  ```
- **关键词：** pfRead, skAsyncWrite
- **备注：** The exploitability depends on the implementation of pfRead and skAsyncWrite, and whether an attacker can control the audio stream. Further analysis of these functions and the audio source is recommended to assess full impact.

---
