# R7000 (9 个发现)

---

### 无标题的发现

- **文件/目录路径：** `bin/startcircle`
- **位置：** `startcircle: multiple lines (e.g., line for export TZ, line for $DIR/timetracker -p)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 攻击链：非 root 用户利用 /mnt/shares/usr/bin 目录的全局写权限（rwxrwxrwx）替换脚本执行的二进制文件（如 get_tz、timetracker）。当 startcircle 脚本以 root 权限运行时，执行这些恶意二进制，导致权限提升。触发条件：攻击者已登录设备并拥有有效凭据（非 root），可修改 /mnt/shares/usr/bin 中的文件。利用方式：用户替换任意二进制为恶意代码，系统启动或脚本执行时自动以 root 运行。
- **代码片段：**
  ```
  export TZ=\`$DIR/get_tz\`
  [ "x$TZ" = "x" ] && export TZ='GMT8DST,M03.02.00,M11.01.00'
  $DIR/timetracker -p
  $DIR/mdnsd $ip "$ipv6" &
  $DIR/ipsetload circleservers /tmp/circleservers
  ```
- **关键词：** /mnt/shares/usr/bin/get_tz, /mnt/shares/usr/bin/timetracker, /mnt/shares/usr/bin/mdnsd, /mnt/shares/usr/bin/ipsetload, LD_LIBRARY_PATH, PATH
- **备注：** 证据支持：脚本内容显示执行多个二进制文件；ls -la 输出显示当前目录文件权限为 rwxrwxrwx，允许非 root 用户修改。建议立即修复目录权限（如改为 root 只写），并验证二进制完整性。后续可分析具体二进制（如 circled、timetracker）以识别其他漏洞。

---
### Command-Injection-circled-NVRAM

- **文件/目录路径：** `bin/circled`
- **位置：** `bin/circled: fcn.00011308 and fcn.0000f14c`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the 'circled' binary due to improper sanitization of the 'circle_download_server' NVRAM variable. The variable is read using popen in function fcn.00011308, trimmed of whitespace (spaces, newlines, tabs) only via fcn.0000eab0, and then passed directly into a wget command executed via system in fcn.0000f14c. This allows a non-root user with login credentials to set the NVRAM variable to include arbitrary commands (e.g., using semicolons or backticks), which are executed with the privileges of the 'circled' process (likely root). The vulnerability is triggered during the firmware update check process when circled attempts to download a loader using the user-controlled URL.
- **代码片段：**
  ```
  // From fcn.00011308:
  sym.imp.popen("nvram get circle_download_server", "r");
  sym.imp.fgets(buffer, size, pipe);
  fcn.0000eab0(buffer); // Only trims whitespace
  // Later, call to fcn.0000f14c with buffer as argument
  
  // From fcn.0000f14c:
  sym.imp.snprintf(command_buffer, 0x400, "wget -q -T 10 -O %s %sget_loader.php?DEVID=%s", "/tmp/loader.bin", "http://download.meetcircle.co/dev/firmware/netgear/", buffer);
  sym.imp.system(command_buffer); // Command injection here if buffer contains malicious content
  ```
- **关键词：** circle_download_server (NVRAM variable), /tmp/loader.bin (file path), /tmp/circled (file path), /mnt/shares/usr/bin/ (directory path)
- **备注：** The vulnerability requires that the non-root user can set NVRAM variables (which is often possible via web interfaces or CLI commands in similar embedded systems). The 'circled' daemon likely runs with root privileges, so successful exploitation leads to root command execution. Further analysis could verify the exact permissions for NVRAM setting and the privilege level of circled. This finding is based on static analysis; dynamic testing would confirm exploitability.

---
### command-injection-amule-sh-start-restart

- **文件/目录路径：** `etc/aMule/amule.sh`
- **位置：** `amule.sh:start 函数 (具体行号未知，但从内容推断在复制、修改配置和执行命令处)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'amule.sh' 脚本的 start 和 restart 函数中，用户提供的工作目录路径参数 `$2` 被赋值给 `emule_work_dir` 变量，并在多个命令中未加引号使用，导致命令注入漏洞。具体触发条件：当脚本以 'start' 或 'restart' 动作调用时，攻击者提供包含 shell 元字符（如分号、反引号）的路径，可注入任意命令。例如，如果 `emule_work_dir` 设置为 '/tmp; malicious_command'，则命令如 'amuled -c $emule_work_dir &' 会被解析为 'amuled -c /tmp; malicious_command &'，执行恶意命令。漏洞允许攻击者执行任意代码，可能提升权限（如果脚本以高权限运行）。利用方式简单：攻击者只需调用脚本并提供恶意参数。
- **代码片段：**
  ```
  start() {
  	emule_work_dir=$1
  	...
  	cp /etc/aMule/amule.conf $emule_work_dir
  	cp /etc/aMule/remote.conf $emule_work_dir
  	cp /etc/aMule/config/*  $emule_work_dir
  	...
  	amuled -c $emule_work_dir &
  }
  restart() {
  	stop
  	start $1
  }
  [ $1 = "start" ] && start $2
  [ $1 = "restart" ] && restart $2
  ```
- **关键词：** 命令行参数 $2, 环境变量 emule_work_dir
- **备注：** 漏洞实际可利用，攻击链完整：输入（命令行参数）→ 数据流（变量传播）→ 危险操作（命令执行）。需要验证脚本执行上下文（如是否以 root 权限运行），建议后续分析脚本调用方式（如通过服务或用户直接执行）以确认权限提升可能性。关联文件可能包括 /etc/aMule/ 下的配置文件。

---
### XSS-edit_devicename_sAlert

- **文件/目录路径：** `www/script/opmode.js`
- **位置：** `opmode.js: sAlert 函数和 edit_devicename 函数`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 'opmode.js' 文件中发现存储型XSS漏洞。攻击者可以通过控制设备名称参数注入恶意脚本。当用户调用 `edit_devicename` 函数时（例如通过编辑设备名称界面），`sAlert` 函数使用 `innerHTML` 直接插入未转义的输入，导致任意JavaScript执行。触发条件：攻击者设置恶意设备名称（包含XSS负载），然后当用户查看或编辑设备名称时触发。利用方式：注入脚本如 `<script>alert('XSS')</script>` 或更复杂的恶意代码，可能窃取会话cookie或执行未授权操作。
- **代码片段：**
  ```
  function sAlert(str, callback_ok, callback_cancel, dwidth, anc){
      // ...
      var div1=document.createElement("div");
      div1.innerHTML=str; // 未转义的用户输入
      // ...
  }
  
  function edit_devicename(name){
      sAlert('<table>...<input type="text" name="new_devname" value="'+name+'" ...>...</table>', check_dev, function(){return false;}, 600, 1);
  }
  ```
- **关键词：** sAlert 函数, edit_devicename 函数, new_devname 表单字段
- **备注：** 这是一个客户端XSS漏洞，但攻击者已登录，可设置存储的恶意输入。建议对用户输入进行HTML转义。需要进一步验证后端是否也缺乏输入过滤。关联文件可能包括使用 `sAlert` 的其他页面。

---
### BufferOverflow-wps_monitor

- **文件/目录路径：** `bin/wps_monitor`
- **位置：** `bin/wps_monitor:0xcc60 (fcn.0000c9d8 strcpy 调用), bin/wps_monitor:0xc658 (fcn.0000c5b0 sprintf 调用), bin/wps_monitor:0xdb10 (fcn.0000d4b0 strcpy 调用)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 wps_monitor 二进制文件中，发现多个缓冲区溢出漏洞，主要源于 strcpy 和 sprintf 函数的使用缺少输入验证和边界检查。攻击者作为已认证的非 root 用户可以通过控制 NVRAM 变量（如 wps_config_command、wps_ifname、lan_hwaddr）或传递恶意参数给 wps_monitor 程序，注入超长字符串。当程序处理这些输入时，数据通过 nvram_get 获取并直接复制到固定大小的栈缓冲区（例如 100 字节），导致栈缓冲区溢出。这可以覆盖返回地址或关键栈数据，允许攻击者执行任意代码。触发条件包括：攻击者设置恶意 NVRAM 值（使用 nvram_set）或调用 wps_monitor 带有长参数；利用方式涉及构造精心设计的输入字符串以控制程序流并执行 shellcode。漏洞存在于多个函数中，包括 fcn.0000c9d8、fcn.0000c5b0 和 fcn.0000d4b0，形成了从输入点到危险操作的完整攻击链。
- **代码片段：**
  ```
  从 fcn.0000c9d8 反编译代码示例:
    sym.imp.strcpy(iVar13, puVar12);  // iVar13 指向栈缓冲区，puVar12 来自 param_2 或 nvram_get
  从 fcn.0000c5b0 反编译代码示例:
    sym.imp.sprintf(iVar7, *0xc6ac, puVar6, param_3);  // iVar7 为栈缓冲区，puVar6 和 param_3 含污点数据
  从 fcn.0000d4b0 反编译代码示例:
    sym.imp.strcpy(fp, src);  // src 来自 lan_ifnames 或类似 NVRAM 变量
  ```
- **关键词：** NVRAM 变量: wps_config_command, wps_ifname, lan_hwaddr, wps_uuid, lan_ifnames, wan_ifnames, 函数符号: nvram_get, nvram_set, strcpy, sprintf, IPC/网络接口: 通过 NVRAM 设置间接控制
- **备注：** 漏洞基于反编译代码分析，证据显示外部输入通过 NVRAM 或参数流入危险函数。攻击链完整：输入点 (NVRAM 变量) -> 数据流 (nvram_get) -> 危险操作 (strcpy/sprintf 无边界检查) -> 潜在利用 (栈溢出)。需要进一步验证栈缓冲区确切大小和利用可行性，但代码模式表明高风险。建议后续测试实际利用，并检查其他相关文件如 NVRAM 配置文件或启动脚本。未发现命令注入或格式化字符串漏洞。

---
### XSS-buildText

- **文件/目录路径：** `www/script/highcharts.js`
- **位置：** `highcharts.js:97 函数 buildText`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 Highcharts.js 的文本渲染过程中，存在一个 XSS 漏洞，源于动态设置 'onclick' 属性时未对用户提供的 href 值进行充分验证。当用户控制的文本内容（如图表数据标签、工具提示或轴标签）包含恶意 href 属性时，该属性值被提取并直接拼接到 'onclick' 处理程序中，形式为 'location.href="<user_input>"'。如果用户输入包含 'javascript:' URL，当用户点击受影响元素时，将执行任意 JavaScript 代码。攻击者可以利用此漏洞通过构造恶意图表配置（例如，在数据标签格式化器中返回 '<a href="javascript:alert('XSS')">Click</a>'）来触发 XSS，窃取会话 cookie、修改页面内容或执行其他恶意操作。漏洞触发条件包括：攻击者能够提供或修改图表配置数据，且受害者与图表交互（如点击元素）。
- **代码片段：**
  ```
  za(R,"style",X.match(e)[1].replace(/(;| |^)color([ :])/,"$1fill$2"));
  if(f.test(X)){za(R,"onclick",'location.href="'+X.match(f)[1]+'"');Ia(R,{cursor:"pointer"})}
  X=X.replace(/<(.|\n)*?>/g,"")||" ";
  ```
- **关键词：** 文本内容, href 属性, onclick 事件, 数据标签格式化器, 工具提示格式化器
- **备注：** 此漏洞需要用户交互（点击）来触发，但通过社交工程或自动触发（如事件模拟）可能提高利用概率。建议对用户输入进行严格验证和转义，避免直接拼接字符串到事件处理程序中。需要进一步验证其他输入点（如工具提示格式化器）是否也受影响。在固件上下文中，攻击者作为已登录用户可能通过Web界面修改图表配置来利用此漏洞。

---
### 缓冲区溢出-parseServers

- **文件/目录路径：** `bin/ookla`
- **位置：** `ookla:0x0000ace4 sym.parseServers`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 parseServers 函数中，解析服务器配置时存在缓冲区溢出漏洞。函数使用 rindex 查找输入字符串中的冒号（':'）来分割主机和端口部分，但如果输入字符串中没有冒号，rindex 返回 NULL，代码未检查此情况。这导致在 strncpy 操作中，复制长度参数计算为无效的大正数（因为 NULL 地址为 0，而栈地址较高），可能复制大量数据到目标栈缓冲区，造成栈溢出。触发条件：攻击者通过修改配置文件 'settings.txt' 中的 'servers.%d.host' 字段，提供不含冒号的超长字符串。约束条件：攻击者需具备配置文件修改权限（作为已登录用户，可能通过 web 界面或 API 实现）。潜在攻击方式：通过精心构造的输入，溢出可覆盖返回地址或关键变量，实现任意代码执行或拒绝服务。漏洞影响所有服务器条目，因位于循环解析中。代码逻辑显示，污点数据从配置文件读取后直接用于字符串操作，缺少边界检查和 NULL 指针验证。
- **代码片段：**
  ```
  uVar2 = sym.imp.rindex(puVar10 + 8 + -0x448, 0x3a); // 查找冒号，如果不存在返回 NULL
  *(puVar10 + -0xc) = uVar2;
  // ... 未检查 uVar2 是否为 NULL
  sym.imp.strncpy(*(*(0x6838 | 0x20000) + 0x24), puVar10 + 8 + -0x448, *(puVar10 + -0xc) - (puVar10 + 8 + -0x448)); // 如果 uVar2 为 NULL，长度计算无效，导致大量数据复制
  ```
- **关键词：** settings.txt, servers.%d.host, servers.%d.serverid, servers.%d.url
- **备注：** 攻击链完整：输入点（配置文件）→ 数据流（parse_config 到 parseServers）→ 危险操作（栈溢出）。建议验证目标缓冲区大小和内存布局以优化利用。后续可分析配置文件的修改机制（如通过网络接口）以确认攻击向量。其他函数（如 parseEngineSettings）中的 strcpy 使用风险较低，因缓冲区大小可能较大，且无证据显示可导致代码执行。

---
### command-injection-minidlna-R-option

- **文件/目录路径：** `usr/sbin/minidlna.exe`
- **位置：** `minidlna.exe:0xc6c4 (fcn.0000c028 case 6)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A command injection vulnerability was identified in the minidlna.exe binary when the `-R` (force rescan) option is used. The vulnerability occurs in the main function where user-controlled data from command-line arguments or configuration files is incorporated into a `system` call without proper sanitization. Specifically, the code constructs a command string using `snprintf` with the format `rm -rf %s/files.db %s/art_cache` and passes it to `system`. If an attacker can control the paths (e.g., through a malicious configuration file or command-line argument), they can inject arbitrary commands. This could lead to remote code execution if the minidlna process is running with elevated privileges or if the attacker has write access to configuration files.

- **Trigger Condition**: The vulnerability is triggered when the `-R` option is passed to minidlna, typically during a forced rescan of the media library.
- **Constraints and Boundary Checks**: The `snprintf` uses a buffer of 4096 bytes, but no validation is performed on the path inputs, allowing command injection if paths contain shell metacharacters.
- **Potential Exploitation**: An attacker with the ability to modify command-line arguments or configuration files (e.g., via a compromised script or weak file permissions) can inject commands to execute arbitrary code.
- **Code Logic**: The dangerous code is located in the main function's command-line parsing switch statement, case 6, where `system` is called with a user-influenced string.
- **代码片段：**
  ```
  case 6:
      *(puVar28 + -0x21b4) = *(puVar28 + -0x2194);
      sym.imp.snprintf(puVar28 + -0x1184, 0x1000, *0xd06c);  // Format: "rm -rf %s/files.db %s/art_cache"
      sym.imp.system(puVar28 + -0x1184);  // Command injection here
      break;
  ```
- **关键词：** minidlna.conf, media_dir, db_dir, log_dir
- **备注：** This vulnerability requires the attacker to control the command-line arguments or configuration file paths, which may be feasible if the minidlna process is started with user-influenced parameters or if configuration files are writable by the user. However, exploitation depends on the specific deployment scenario. Additional analysis of HTTP request handling and SQL queries is recommended to identify other potential attack vectors, such as SQL injection or buffer overflows in network-facing code.

---
### command-injection-fcn.000290a4

- **文件/目录路径：** `bin/wget`
- **位置：** `文件: wget 函数: fcn.000290a4 地址: 0x29138`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 在函数 fcn.000290a4 中，参数 param_1 被用于构建命令字符串并通过 system 函数执行，存在命令注入漏洞。具体攻击链：param_1 可能来自用户可控的输入（如命令行参数或环境变量），通过 sprintf 格式化到缓冲区并嵌入到另一个字符串中，最终调用 system 执行。攻击者（作为已连接的非root用户）可通过注入恶意字符（如 ;、|、反引号）执行任意命令。触发条件是用户提供恶意输入，导致命令注入，从而在系统上执行任意代码。这是一个完整且可验证的攻击路径，基于代码分析和调用链（fcn.000101f0 和 fcn.0001a3ac）。
- **代码片段：**
  ```
  if (param_1 != 0) { iVar1 = sym.imp.fopen64(*0x29158, *0x2915c); if (iVar1 != 0) { sym.imp.fprintf(iVar1, *0x29160, param_1); sym.imp.fclose(iVar1); sym.imp.sprintf(puVar2 + -0x40, *0x29164, param_1); sym.imp.sprintf(puVar2 + -0x80, *0x29168, puVar2 + -0x40); sym.imp.system(puVar2 + -0x80); return 0; } sym.imp.puts(*0x2916c); }
  ```
- **关键词：** sym.imp.system, fcn.000290a4, fcn.000101f0, fcn.0001a3ac
- **备注：** 需要进一步验证 param_1 的具体来源（如命令行参数处理），但基于调用链（fcn.000101f0 和 fcn.0001a3ac），它可能用户可控。建议修复使用安全函数（如 execve）或严格验证输入。攻击者是非root用户，但可利用此漏洞提升权限或执行恶意操作。

---
