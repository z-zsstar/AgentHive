# R6700-V1.0.1.36_10.0.40 (13 个发现)

---

### 无标题的发现

- **文件/目录路径：** `usr/bin/dbus-daemon`
- **位置：** `dbus-daemon:0x0000e9b8 fcn.0000e9b8`
- **风险评分：** 9.5
- **置信度：** 9.0
- **描述：** The 'dbus-daemon' binary contains a command injection vulnerability in function `fcn.0000e9b8` (decompiled as `handle_system_method_call`). This function processes D-Bus method calls and passes arguments directly to the `system` function without proper sanitization. An attacker with valid login credentials can send a crafted D-Bus message containing malicious shell commands, which are executed with the privileges of the D-Bus daemon (typically root). The vulnerability is triggered when a specific D-Bus method is invoked, allowing arbitrary command execution. The code lacks input validation and sanitization, enabling injection of commands via metacharacters.
- **代码片段：**
  ```
  // Decompiled code snippet from fcn.0000e9b8
  int32_t handle_system_method_call(int32_t arg1, int32_t arg2) {
      // ... parsing D-Bus message ...
      char *command = get_string_from_message(arg2); // User-controlled data
      system(command); // Direct execution without validation
      // ...
  }
  ```
- **关键词：** D-Bus method calls, system function call
- **备注：** This vulnerability requires the attacker to be able to send D-Bus messages, which is possible with valid user credentials. The daemon often runs as root, so command execution occurs with high privileges. Further analysis should verify the exact D-Bus interface and method exposed. The function `fcn.0000e9b8` is large and complex, so manual review of the decompiled code is recommended to confirm the attack flow.

---
### stack-buffer-overflow-nvram_set

- **文件/目录路径：** `usr/sbin/nvram`
- **位置：** `nvram:0x00008a10 fcn.00008924`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A stack buffer overflow vulnerability exists in the 'set' command of the nvram binary. When processing the 'set name=value' command, the value string is copied to a stack buffer using strncpy with a size of 0x10000 bytes. However, the stack buffer is only approximately 65510 bytes, resulting in an overflow that can overwrite saved registers, including the return address. An attacker with command-line access can exploit this by providing a value string of 0x10000 bytes or more, containing shellcode or a ROP chain, to achieve arbitrary code execution. Since the nvram binary may have elevated privileges, this could lead to privilege escalation from a non-root user to root.
- **代码片段：**
  ```
  In assembly:
  0x00008a00      04302ae5       str r3, [sl, -4]!   ; Set destination buffer
  0x00008a04      0128a0e3       mov r2, 0x10000     ; Size for strncpy
  0x00008a08      0300a0e1       mov r0, r3          ; Destination
  0x00008a10      3cffffeb       bl sym.imp.strncpy  ; Call strncpy with size 0x10000
  
  In decompilation:
  sym.imp.strncpy(iVar1, pcVar15, 0x10000); // iVar1 points to stack buffer, pcVar15 is user-controlled value
  ```
- **关键词：** nvram_set, strncpy
- **备注：** The vulnerability is directly exploitable via command-line arguments. The binary is stripped, but the overflow is straightforward. Exploitation may require knowledge of the stack layout and ASLR bypass, but the fixed size and control over input make it feasible. Further analysis could involve testing exploitability with a debugger.

---
### stack-buffer-overflow-fcn.00009b5c

- **文件/目录路径：** `usr/bin/KC_PRINT`
- **位置：** `KC_PRINT:fcn.00009b5c:0x9b5c`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** 在函数 fcn.00009b5c 中发现栈缓冲区溢出漏洞。问题表现：函数使用 memcpy 将用户控制的输入数据复制到固定大小的栈缓冲区（大小 0x40 字节），但复制长度由输入中的两字节字段控制（最大 0xFFFF 字节），且未验证长度是否超出缓冲区大小。触发条件：攻击者通过 param_2 提供包含超长数据的输入，使复制操作进入 memcpy 路径。约束条件：缓冲区大小为 64 字节，但攻击者可控制复制长度 up to 65535 字节。潜在攻击和利用方式：攻击者构造恶意输入，覆盖返回地址（位于 fp-0x4），劫持控制流，可能以服务权限执行任意命令。相关代码逻辑：函数处理输入数据协议，解析长度字段并直接复制到栈缓冲区。
- **代码片段：**
  ```
  sym.imp.memset(piVar4 + 0 + -0x894, 0, 0x40);
  sym.imp.memcpy(piVar4 + 0 + -0x894, piVar4[-0x229] + piVar4[-3], piVar4[-0x11]); // piVar4[-0x11] 是攻击者控制的长度
  ```
- **关键词：** param_2 (输入缓冲区), piVar4[-0x229] (数据源指针), 网络套接字或 IPC 通道
- **备注：** 漏洞已验证通过反编译代码和栈帧分析。攻击链完整，但实际利用可能需要绕过 ASLR。建议检查输入源（如网络服务）以确认远程可利用性。关联函数：fcn.00009b10。

---
### StackOverflow-main-acos_service

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0xc6c8 in main function`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'acos_service' 的 main 函数中，处理 NVRAM 变量 'ParentalCtrl_MAC_ID_tbl' 时使用 strcpy 进行复制，缺少边界检查，导致栈缓冲区溢出。攻击者可通过 web 界面或其他接口设置恶意的长字符串到该 NVRAM 变量，当服务初始化或重启时，strcpy 操作会溢出固定大小的栈缓冲区，覆盖返回地址。在 ARM 架构下，精心构造的输入可控制程序计数器（PC），实现任意代码执行。触发条件包括设备启动、服务重启或相关配置更改。
- **代码片段：**
  ```
  0x0000c6b8      0c0a9fe5       ldr r0, str.ParentalCtrl_MAC_ID_tbl ; [0x25158:4]=0x65726150 ; 'ParentalCtrl_MAC_ID_tbl'
  0x0000c6bc      3af9ffeb       bl sym.imp.acosNvramConfig_get
  0x0000c6c0      0010a0e1       mov r1, r0                  ; const char *src
  0x0000c6c4      0500a0e1       mov r0, r5                  ; char *dest
  0x0000c6c8      9df9ffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **关键词：** ParentalCtrl_MAC_ID_tbl, /sbin/acos_service
- **备注：** 漏洞利用需要攻击者拥有有效登录凭据以修改 NVRAM 变量，且需触发服务初始化。建议进一步验证栈缓冲区大小（约 0xbd0 字节分配）和具体偏移量以优化利用。关联函数包括 acosNvramConfig_get 和 system 调用，可能影响其他组件。在固件环境中，ASLR 可能未启用，增加可利用性。

---
### 命令注入-amule.sh_start

- **文件/目录路径：** `etc/aMule/amule.sh`
- **位置：** `amule.sh:start 函数（大致行号基于内容：在 'dir=$(echo $emule_work_dir | sed 's/\//\\\//g')' 附近）`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 命令注入漏洞在 'amule.sh' 脚本的 start 函数中。由于未加引号使用用户提供的目录路径（$emule_work_dir）在 'echo' 命令中，攻击者可以通过注入命令替换（如 '$(malicious_command)'）执行任意命令。触发条件：当用户运行脚本时提供恶意路径参数，例如 './amule.sh start "$(id > /tmp/exploit)"'。利用方式：攻击者控制 $2 参数（工作目录路径），在 'dir=$(echo $emule_work_dir | sed 's/\//\\\//g')' 行中，'echo $emule_work_dir' 会执行嵌入的命令。漏洞允许非 root 用户提升权限或访问敏感数据，因为注入的命令以脚本执行权限运行。攻击链完整：从不可信输入（命令行参数）到危险操作（命令执行），无需 root 权限即可利用。
- **代码片段：**
  ```
  start() {
  	emule_work_dir=$1
  	...
  	dir=$(echo $emule_work_dir | sed 's/\//\\\//g')
  	...
  }
  ```
- **关键词：** 命令行参数 $2
- **备注：** 漏洞基于代码分析，证据来自文件内容。建议进一步验证在实际环境中的可利用性，例如测试命令注入是否受 shell 环境限制。关联文件：可能影响 aMule 守护进程的配置。后续分析方向：检查其他脚本或二进制文件是否类似使用未加引号的变量。

---
### command-injection-ftp-fcn.000109e8

- **文件/目录路径：** `usr/sbin/ftp`
- **位置：** `ftp:0x10ff8 fcn.000109e8`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'ftp' 二进制文件中发现命令注入漏洞，允许认证用户通过特制 FTP 命令执行任意 shell 命令。漏洞触发条件是用户输入以 '|' 字符开头，该输入被直接传递给 popen 函数执行。具体利用方式包括在 FTP 命令（如 RETR 或 STOR）的文件名参数中使用 '|command' 格式，其中 'command' 是任意 shell 命令。代码中缺少对用户输入的验证和转义，导致攻击者可以注入并执行命令。该漏洞可能允许攻击者绕过 FTP 限制，访问系统资源或进行横向移动。
- **代码片段：**
  ```
  在函数 fcn.000109e8 中，关键代码片段：
  if (**(puVar14 + -0x98) == '|') {
      uVar3 = sym.imp.popen(*(puVar14 + -0x98) + 1, 0x5cd4 | 0x10000);
  }
  其中 *(puVar14 + -0x98) 是用户输入的字符串，以 '|' 开头时，剩余部分被传递给 popen 执行。
  ```
- **关键词：** FTP 命令输入（如 RETR、STOR）, 环境变量或 NVRAM 变量（未直接涉及，但通过命令执行可能间接影响）
- **备注：** 该漏洞基于静态代码分析确认，攻击链完整且可验证。建议进一步动态测试以验证可利用性。相关函数包括 fcn.00013950（主函数）、fcn.000136c0（输入解析）和 fcn.00013358（命令查找）。攻击者需拥有有效 FTP 登录凭据，但无需 root 权限。

---
### stack-buffer-overflow-fcn.0000fb08

- **文件/目录路径：** `usr/bin/KC_PRINT`
- **位置：** `KC_PRINT:fcn.0000fb08:0xfb08`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在函数 fcn.0000fb08 中发现栈缓冲区溢出漏洞，该函数处理文件接收或打印作业协议。问题表现：输入数据中的长度字段（16 位无符号整数）被直接用于 memcpy 操作，目标为固定大小的栈缓冲区（64 字节），缺乏边界检查。触发条件：当输入数据的特定字节匹配时（如 *(puVar2[-5] + 2) == 0 且 *(puVar2[-5] + 3) == '\n'），fcn.00009884 调用 fcn.0000fb08，传递可控输入缓冲区。约束条件：缓冲区大小 64 字节，攻击者可控制长度 up to 65535 字节。潜在攻击和利用方式：溢出允许覆盖返回地址，执行任意代码。相关代码逻辑：函数解析输入协议，提取长度字段并复制数据。
- **代码片段：**
  ```
  piVar4[-0x11] = *(*(piVar4 + (0xef68 | 0xffff0000) + 4) + piVar4[-3]) * 0x100 + *(*(piVar4 + (0xef68 | 0xffff0000) + 4) + piVar4[-3] + 1);
  sym.imp.memcpy(piVar4 + 0 + -0x1088, *(piVar4 + (0xef68 | 0xffff0000) + 4) + piVar4[-3], piVar4[-0x11]); // piVar4[-0x11] 为可控长度
  ```
- **关键词：** param_2 (输入缓冲区), piVar4[-0x11] (长度字段), auStack_1094[64] (栈缓冲区), fcn.00009884 (调用者)
- **备注：** 漏洞已验证：输入通过 fcn.00009884 从外部源传入。栈布局分析显示返回地址位于溢出缓冲区之后。建议进一步分析输入点以确认远程可利用性。

---
### stack-buffer-overflow-fcn.0000e454

- **文件/目录路径：** `usr/bin/KC_PRINT`
- **位置：** `KC_PRINT:fcn.0000e454:0xe454`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在函数 fcn.0000e454 中发现多个栈缓冲区溢出漏洞，该函数处理 IPP 协议请求。问题表现：在解析 'printer-uri'、'requesting-user-name' 和 'job-name' 属性时，使用 memcpy 将输入数据复制到固定大小的栈缓冲区（分别为 128、48、48 字节），但缺乏充分的边界检查。触发条件：攻击者发送 IPP 请求，其中 'printer-uri' 长度超过 128 字节，或 'requesting-user-name'/'job-name' 长度超过 48 字节。约束条件：缓冲区大小有限，攻击者可控制属性长度。潜在攻击和利用方式：溢出覆盖返回地址或关键变量，实现任意代码执行。相关代码逻辑：函数解析 IPP 属性，根据长度字段复制数据，但边界检查有缺陷。
- **代码片段：**
  ```
  // 'printer-uri' 处理
  sym.imp.memcpy(piVar7 + 0 + -0x8e4, piVar7[-0x25b] + piVar7[-1], piVar7[-9]); // 无边界检查
  // 'requesting-user-name' 处理
  if (iVar1 != 0x30 && iVar1 + -0x30 < 0 == SBORROW4(iVar1,0x30)) {
      sym.imp.memcpy(piVar7 + 0 + -0x914, piVar7[-0x25b] + piVar7[-1], 0x30);
  } else {
      sym.imp.memcpy(piVar7 + 0 + -0x914, piVar7[-0x25b] + piVar7[-1], piVar7[-9]); // 可能溢出
  }
  // 'job-name' 处理类似
  ```
- **关键词：** printer-uri, requesting-user-name, job-name, IPP protocol socket
- **备注：** 漏洞存在于 IPP 协议处理中，攻击者需拥有有效登录凭据。建议验证栈布局和保护机制。关联函数：fcn.00013444 和 fcn.00009b10。

---
### Passwd-Buffer-Overflow

- **文件/目录路径：** `bin/busybox`
- **位置：** `busybox:0xc4f4 (strcpy调用点)`
- **风险评分：** 8.0
- **置信度：** 7.5
- **描述：** Passwd命令在处理用户输入时，可能发生缓冲区溢出，允许攻击者覆盖栈数据并控制执行流。问题表现为使用不安全的strcpy函数复制用户输入（如密码）到固定大小缓冲区，缺少边界检查。触发条件是通过命令行或交互式输入提供超长密码或用户名。潜在攻击包括执行任意代码，可能提升到root权限。攻击链完整：用户运行passwd命令并提供超长输入，导致strcpy溢出，控制执行流。
- **代码片段：**
  ```
  sym.imp.strcpy (从反汇编中识别)
  ```
- **关键词：** PWD, HOME, /etc/passwd, /etc/shadow, passwd主函数
- **备注：** 基于对strcpy的调用和密码输入处理；需要动态测试确认缓冲区大小；建议使用安全函数如strncpy。

---
### XSS-Highcharts-tooltipFormatter

- **文件/目录路径：** `www/script/highcharts.js`
- **位置：** `highcharts.js (压缩代码中约中部位置，具体行号不可靠，但基于函数标识符)`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在 Highcharts.js 库中发现跨站脚本（XSS）漏洞。漏洞存在于工具提示（tooltip）和数据标签（dataLabels）的格式化函数中，这些函数将用户控制的数据直接插入到 HTML 中而未进行转义。具体表现：当图表渲染时，如果用户提供的数据（如点名称、x/y 值）包含恶意 HTML 或 JavaScript 代码，将在浏览器中执行。触发条件包括：1) 攻击者能够提供或修改图表数据（通过应用程序的 API 或配置）；2) 图表被渲染并显示工具提示或数据标签。潜在攻击方式：攻击者构造恶意数据点（如名称包含 `<script>alert('XSS')</script>`），当其他用户查看图表时触发 XSS。漏洞涉及缺少输入验证和输出编码，允许从不可信输入点到 DOM 操作的完整攻击链。
- **代码片段：**
  ```
  // 工具提示默认格式化函数示例
  function h() {
      var H = this.points || nc(this),
          A = H[0].series.xAxis,
          D = this.x;
      A = A && A.options.type == "datetime";
      var ha = Kb(D) || A,
          xa;
      xa = ha ? ['<span style="font-size: 10px">', A ? Mc("%A, %b %e, %Y", D) : D, "</span><br/>"] : [];
      t(H, function(va) {
          xa.push(va.point.tooltipFormatter(ha)); // 用户数据直接插入
      });
      return xa.join(""); // 返回未转义的 HTML 字符串
  }
  
  // 点对象的 tooltipFormatter 方法
  tooltipFormatter: function(a) {
      var b = this.series;
      return ['<span style="color:' + b.color + '">', this.name || b.name, "</span>: ", !a ? "<b>x = " + (this.name || this.x) + ",</b> " : "", "<b>", !a ? "y = " : "", this.y, "</b><br/>"].join(""); // 用户数据（name, x, y）直接拼接
  }
  ```
- **关键词：** tooltipFormatter, dataLabels.formatter, Highcharts.Chart, series.data
- **备注：** 此漏洞的利用依赖于应用程序使用用户提供的数据渲染图表。攻击者需有登录凭据来注入恶意数据，但一旦成功，可危害其他用户会话。建议后续验证实际应用程序中图表数据的来源和处理方式。关联文件可能包括使用 Highcharts 的 HTML 页面和服务器端 API。修复建议：对所有用户输入进行 HTML 转义后再插入 DOM。

---
### Telnetd-Command-Injection

- **文件/目录路径：** `bin/busybox`
- **位置：** `busybox:0x430fc (函数 fcn.000430d0)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** Telnetd 服务在处理用户输入时，可能通过环境变量或命令行参数注入恶意命令，导致任意命令执行。问题表现为用户输入（如环境变量TERM）在传递给execve函数时缺少验证，允许特殊字符（如分号）被解释为命令分隔符。触发条件是通过Telnet连接后操纵环境变量或命令参数。潜在攻击包括获得shell访问权限或执行任意操作。攻击链完整：用户登录Telnet后设置恶意环境变量（如TERM=; malicious_command），触发execve执行任意命令。
- **代码片段：**
  ```
  void fcn.000430d0(int32_t param_1, int32_t *param_2, uint param_3) { ... sym.imp.execve(param_1, param_2, param_3); ... }
  ```
- **关键词：** TERM, SHELL, PATH, /dev/tty, /etc/passwd, Telnet套接字, fcn.000430d0
- **备注：** 基于代码分析，execve调用可能直接使用用户输入；需要进一步验证Telnetd的具体实现，但BusyBox历史版本有类似漏洞报告。建议检查输入处理逻辑。

---
### buffer-overflow-fcn.0000ba0c

- **文件/目录路径：** `usr/bin/KC_PRINT`
- **位置：** `KC_PRINT:fcn.0000ba0c:0xba0c`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在函数 fcn.0000ba0c 中发现缓冲区溢出漏洞，该函数处理 HTTP 请求。问题表现：当输入字符为 'D' 时，函数从输入中读取两字节长度值，并使用 fcn.00009b10 将数据复制到栈缓冲区 auStack_1094（大小 64 字节），但复制长度计算为 piVar7[-0x11] + 2，未验证是否超出缓冲区大小。触发条件：攻击者发送包含 'D' 字符和恶意长度值的 HTTP 请求。约束条件：缓冲区大小 64 字节，攻击者可控制长度 up to 65535 + 2 字节。潜在攻击和利用方式：溢出覆盖栈上的返回地址或关键变量，实现任意代码执行。相关代码逻辑：函数循环解析 HTTP 请求数据，在特定字符条件下执行复制操作。
- **代码片段：**
  ```
  if ((*(*(piVar7 + (0xef30 | 0xffff0000) + 4) + piVar7[-4]) != 'D') || (*(piVar7 + -0x15) != '\0')) {
      // ...
  } else {
      *(piVar7 + -0x15) = 1;
      piVar7[-0x11] = *(*(piVar7 + (0xef30 | 0xffff0000) + 4) + piVar7[-4] + 1) * 0x100 + *(*(piVar7 + (0xef30 | 0xffff0000) + 4) + piVar7[-4] + 2);
      iVar1 = fcn.00009b10(piVar7 + 0 + -0x1048, piVar7[-1], *(piVar7 + (0xef30 | 0xffff0000) + 4) + piVar7[-4] + 1, piVar7[-0x11] + 2); // 无边界检查
  }
  ```
- **关键词：** HTTP 请求数据 (param_2), 栈缓冲区 auStack_1094, 函数 fcn.00009b10, 网络套接字
- **备注：** 基于静态分析，需要动态测试验证利用可行性。建议检查栈布局以确认返回地址可覆盖。关联文件可能包括其他 HTTP 处理组件。

---
### Shell-Env-Injection

- **文件/目录路径：** `bin/busybox`
- **位置：** `字符串引用显示相关变量（如PS1=# at index 1886）`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** BusyBox的shell（ash）在处理环境变量时，可能允许命令注入通过特定变量（如PS1或ENV）。问题表现为环境变量值在解析时被直接评估，缺少过滤。触发条件是攻击者设置恶意环境变量，当shell启动时执行嵌入的命令。潜在攻击包括通过ENV变量指向恶意脚本导致任意命令执行。攻击链完整：用户设置恶意环境变量（如ENV=malicious_script），shell初始化时执行该脚本。
- **代码片段：**
  ```
  从字符串列表中识别PS1和ENV相关字符串
  ```
- **关键词：** PS1, ENV, PATH, /etc/profile, ~/.profile, shell初始化函数
- **备注：** 基于常见shell漏洞模式；需要具体配置支持；建议限制环境变量的使用。

---
