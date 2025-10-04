# R7000 - 验证报告 (9 个发现)

---

## 原始信息

- **文件/目录路径：** `etc/aMule/amule.sh`
- **位置：** `amule.sh:start 函数 (具体行号未知，但从内容推断在复制、修改配置和执行命令处)`
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
- **备注：** 漏洞实际可利用，攻击链完整：输入（命令行参数）→ 数据流（变量传播）→ 危险操作（命令执行）。需要验证脚本执行上下文（如是否以 root 权限运行），建议后续分析脚本调用方式（如通过服务或用户直接执行）以确认权限提升可能性。关联文件可能包括 /etc/aMule/ 下的配置文件。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。在 'etc/aMule/amule.sh' 脚本中，start 和 restart 函数将用户提供的第二个参数 (`$2`) 赋值给 `emule_work_dir` 变量，并在多个命令中未加引号使用（如 `amuled -c $emule_work_dir &`）。攻击者模型为本地攻击者（例如，通过命令行或系统服务调用脚本），他们可以控制输入参数。如果参数包含 shell 元字符（如分号），可注入任意命令。例如，调用 `./amule.sh start "/tmp; malicious_command"` 会解析为 `amuled -c /tmp; malicious_command &`，执行 `malicious_command`。漏洞链完整：输入（命令行参数）→ 数据流（变量传播）→ 危险操作（命令执行）。证据来自脚本内容，显示未加引号的变量使用。因此，漏洞真实可利用，风险高，可能导致权限提升（如果脚本以高权限运行）。

## 验证指标

- **验证时长：** 158.85 秒
- **Token 使用量：** 199976

---

## 原始信息

- **文件/目录路径：** `bin/wget`
- **位置：** `文件: wget 函数: fcn.000290a4 地址: 0x29138`
- **描述：** 在函数 fcn.000290a4 中，参数 param_1 被用于构建命令字符串并通过 system 函数执行，存在命令注入漏洞。具体攻击链：param_1 可能来自用户可控的输入（如命令行参数或环境变量），通过 sprintf 格式化到缓冲区并嵌入到另一个字符串中，最终调用 system 执行。攻击者（作为已连接的非root用户）可通过注入恶意字符（如 ;、|、反引号）执行任意命令。触发条件是用户提供恶意输入，导致命令注入，从而在系统上执行任意代码。这是一个完整且可验证的攻击路径，基于代码分析和调用链（fcn.000101f0 和 fcn.0001a3ac）。
- **代码片段：**
  ```
  if (param_1 != 0) { iVar1 = sym.imp.fopen64(*0x29158, *0x2915c); if (iVar1 != 0) { sym.imp.fprintf(iVar1, *0x29160, param_1); sym.imp.fclose(iVar1); sym.imp.sprintf(puVar2 + -0x40, *0x29164, param_1); sym.imp.sprintf(puVar2 + -0x80, *0x29168, puVar2 + -0x40); sym.imp.system(puVar2 + -0x80); return 0; } sym.imp.puts(*0x2916c); }
  ```
- **备注：** 需要进一步验证 param_1 的具体来源（如命令行参数处理），但基于调用链（fcn.000101f0 和 fcn.0001a3ac），它可能用户可控。建议修复使用安全函数（如 execve）或严格验证输入。攻击者是非root用户，但可利用此漏洞提升权限或执行恶意操作。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `Low`
- **详细原因：** 基于对函数fcn.000290a4及其调用链（fcn.000101f0和fcn.0001a3ac）的深入分析，参数param_1被确认为进程PID（来自getpid()系统调用），而不是用户可控的输入。在fcn.000101f0中，param_1直接来自getpid()的返回值（0x00010218处调用getpid，结果存储在r5中并传递给fcn.000290a4）。同样，在fcn.0001a3ac中，param_1也来自getpid()（0x0001a410处调用getpid，结果存储在var_20ch中并传递给fcn.000290a4）。由于PID是系统生成的整数，攻击者无法控制其值，因此无法注入恶意字符（如;、|、反引号）来执行任意命令。警报中描述的输入可控性和完整攻击链不成立，漏洞不可利用。攻击者模型（如未经身份验证的远程攻击者或已通过身份验证的本地用户）在此场景下不适用，因为param_1非用户可控。

## 验证指标

- **验证时长：** 234.13 秒
- **Token 使用量：** 562864

---

## 原始信息

- **文件/目录路径：** `usr/sbin/minidlna.exe`
- **位置：** `minidlna.exe:0xc6c4 (fcn.0000c028 case 6)`
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
- **备注：** This vulnerability requires the attacker to control the command-line arguments or configuration file paths, which may be feasible if the minidlna process is started with user-influenced parameters or if configuration files are writable by the user. However, exploitation depends on the specific deployment scenario. Additional analysis of HTTP request handling and SQL queries is recommended to identify other potential attack vectors, such as SQL injection or buffer overflows in network-facing code.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报准确描述了在 minidlna.exe 的 fcn.0000c028 函数 case 6（地址 0xd0a8）中的命令注入漏洞。代码使用 snprintf 格式化字符串 'rm -rf %s/files.db %s/art_cache'（从地址 0xd06c 加载）并传递给 system 调用，路径输入来自用户控制的命令行参数或配置文件（var_20h），未进行输入清理或验证。攻击者模型假设为本地用户或有权影响命令行参数的用户（例如通过修改配置文件或启动脚本）。当使用 -R 选项触发强制重新扫描时，攻击者可控制路径输入，注入 shell 元字符（如 ;、&、|）执行任意命令。例如，路径设置为 ';/bin/sh' 时，命令变为 'rm -rf ;/bin/sh/files.db ;/bin/sh/art_cache'，导致执行 /bin/sh。漏洞完整路径可达：用户输入 → 路径变量 → snprintf 构建命令 → system 执行。由于 minidlna 可能以高权限运行（如 root），风险高，可导致远程代码执行。PoC 步骤：1. 作为攻击者，修改配置文件或命令行参数，设置路径为恶意值（如 ';/bin/sh' 或 '& touch /tmp/pwned'）。2. 启动 minidlna 进程并传递 -R 选项（例如 minidlna -R）。3. 观察命令注入结果（如 shell 执行或文件创建）。

## 验证指标

- **验证时长：** 241.92 秒
- **Token 使用量：** 633014

---

## 原始信息

- **文件/目录路径：** `www/script/opmode.js`
- **位置：** `opmode.js: sAlert 函数和 edit_devicename 函数`
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
- **备注：** 这是一个客户端XSS漏洞，但攻击者已登录，可设置存储的恶意输入。建议对用户输入进行HTML转义。需要进一步验证后端是否也缺乏输入过滤。关联文件可能包括使用 `sAlert` 的其他页面。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 警报描述准确。在 'www/script/opmode.js' 文件中，sAlert 函数（行2294）使用 `div1.innerHTML=str` 直接插入未转义的输入，而 edit_devicename 函数（行2458）将用户控制的设备名称参数 `name` 直接拼接进 HTML 字符串：`value="'+name+'"`。攻击者模型是已通过身份验证的用户（远程或本地），因为他们可以设置恶意设备名称。当用户（如管理员）调用 edit_devicename 函数（例如通过设备名称编辑界面）时，sAlert 函数会渲染未转义的输入，导致存储型XSS。完整攻击链：攻击者设置设备名称为恶意载荷（如 `"><script>alert('XSS')</script>`），然后当用户查看或编辑设备名称时，脚本执行。实际影响包括会话劫持或未授权操作。PoC步骤：1. 以已认证用户身份设置设备名称为 XSS 载荷；2. 触发设备名称编辑界面；3. 观察脚本执行。

## 验证指标

- **验证时长：** 247.97 秒
- **Token 使用量：** 667971

---

## 原始信息

- **文件/目录路径：** `bin/ookla`
- **位置：** `ookla:0x0000ace4 sym.parseServers`
- **描述：** 在 parseServers 函数中，解析服务器配置时存在缓冲区溢出漏洞。函数使用 rindex 查找输入字符串中的冒号（':'）来分割主机和端口部分，但如果输入字符串中没有冒号，rindex 返回 NULL，代码未检查此情况。这导致在 strncpy 操作中，复制长度参数计算为无效的大正数（因为 NULL 地址为 0，而栈地址较高），可能复制大量数据到目标栈缓冲区，造成栈溢出。触发条件：攻击者通过修改配置文件 'settings.txt' 中的 'servers.%d.host' 字段，提供不含冒号的超长字符串。约束条件：攻击者需具备配置文件修改权限（作为已登录用户，可能通过 web 界面或 API 实现）。潜在攻击方式：通过精心构造的输入，溢出可覆盖返回地址或关键变量，实现任意代码执行或拒绝服务。漏洞影响所有服务器条目，因位于循环解析中。代码逻辑显示，污点数据从配置文件读取后直接用于字符串操作，缺少边界检查和 NULL 指针验证。
- **代码片段：**
  ```
  uVar2 = sym.imp.rindex(puVar10 + 8 + -0x448, 0x3a); // 查找冒号，如果不存在返回 NULL
  *(puVar10 + -0xc) = uVar2;
  // ... 未检查 uVar2 是否为 NULL
  sym.imp.strncpy(*(*(0x6838 | 0x20000) + 0x24), puVar10 + 8 + -0x448, *(puVar10 + -0xc) - (puVar10 + 8 + -0x448)); // 如果 uVar2 为 NULL，长度计算无效，导致大量数据复制
  ```
- **备注：** 攻击链完整：输入点（配置文件）→ 数据流（parse_config 到 parseServers）→ 危险操作（栈溢出）。建议验证目标缓冲区大小和内存布局以优化利用。后续可分析配置文件的修改机制（如通过网络接口）以确认攻击向量。其他函数（如 parseEngineSettings）中的 strcpy 使用风险较低，因缓冲区大小可能较大，且无证据显示可导致代码执行。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了漏洞逻辑：在 parseServers 函数中，rindex 用于查找冒号，如果未找到（返回 NULL），代码未检查 NULL 指针，导致 strncpy 长度参数计算错误（大正数）。但警报错误声称目标为'栈缓冲区'，实际目标缓冲区是堆分配的（通过 malloc）。漏洞可利用性验证：攻击者模型为已通过身份验证的用户（例如通过 web 界面或 API 修改配置文件），可控制 'settings.txt' 中的 'servers.%d.host' 字段，提供不含冒号的超长字符串。路径可达：配置解析循环中，只要字段存在即执行易受攻击代码。实际影响：堆缓冲区溢出可能覆盖相邻内存，导致任意代码执行或拒绝服务。概念验证（PoC）步骤：1. 作为已认证用户，修改配置文件 'settings.txt'，设置 'servers.0.host' 字段为一个长字符串（例如 1000 个 'A'），不含冒号。2. 触发配置重新加载（如重启服务或通过接口）。3. 观察进程崩溃或异常行为，表明堆溢出发生。漏洞风险高，因可能实现代码执行。

## 验证指标

- **验证时长：** 249.70 秒
- **Token 使用量：** 693102

---

## 原始信息

- **文件/目录路径：** `bin/wps_monitor`
- **位置：** `bin/wps_monitor:0xcc60 (fcn.0000c9d8 strcpy 调用), bin/wps_monitor:0xc658 (fcn.0000c5b0 sprintf 调用), bin/wps_monitor:0xdb10 (fcn.0000d4b0 strcpy 调用)`
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
- **备注：** 漏洞基于反编译代码分析，证据显示外部输入通过 NVRAM 或参数流入危险函数。攻击链完整：输入点 (NVRAM 变量) -> 数据流 (nvram_get) -> 危险操作 (strcpy/sprintf 无边界检查) -> 潜在利用 (栈溢出)。需要进一步验证栈缓冲区确切大小和利用可行性，但代码模式表明高风险。建议后续测试实际利用，并检查其他相关文件如 NVRAM 配置文件或启动脚本。未发现命令注入或格式化字符串漏洞。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了 bin/wps_monitor 中的缓冲区溢出漏洞。证据如下：1) 在地址 0xcc60 (fcn.0000c9d8)、0xc658 (fcn.0000c5b0) 和 0xdb10 (fcn.0000d4b0) 处确认了 strcpy 和 sprintf 调用，且无边界检查；2) 反编译代码显示栈缓冲区大小固定（如 auStack_110 [100]），但输入通过 nvram_get（如获取 NVRAM 变量 wps_config_command、lan_hwaddr）或函数参数（param_2、param_3）传入，这些输入攻击者可控制；3) 攻击链完整：作为已认证的非 root 用户（例如通过 Web 界面或命令行），攻击者可使用 nvram_set 设置恶意 NVRAM 变量（如设置为超过 100 字节的长字符串）或调用 wps_monitor 带有长参数，当程序处理时，strcpy/sprintf 会溢出栈缓冲区，覆盖返回地址或关键数据，导致任意代码执行。PoC 步骤：a) 攻击者通过 nvram_set 设置 wps_config_command 为精心构造的长字符串（包含 shellcode 和覆盖地址）；b) 触发 wps_monitor 执行相关函数（如通过系统调用或事件）；c) 栈溢出后控制程序流执行 shellcode。风险高，因漏洞易利用且影响严重。

## 验证指标

- **验证时长：** 301.71 秒
- **Token 使用量：** 782196

---

## 原始信息

- **文件/目录路径：** `bin/startcircle`
- **位置：** `startcircle: multiple lines (e.g., line for export TZ, line for $DIR/timetracker -p)`
- **描述：** 攻击链：非 root 用户利用 /mnt/shares/usr/bin 目录的全局写权限（rwxrwxrwx）替换脚本执行的二进制文件（如 get_tz、timetracker）。当 startcircle 脚本以 root 权限运行时，执行这些恶意二进制，导致权限提升。触发条件：攻击者已登录设备并拥有有效凭据（非 root），可修改 /mnt/shares/usr/bin 中的文件。利用方式：用户替换任意二进制为恶意代码，系统启动或脚本执行时自动以 root 运行。
- **代码片段：**
  ```
  export TZ=\`$DIR/get_tz\`
  [ "x$TZ" = "x" ] && export TZ='GMT8DST,M03.02.00,M11.01.00'
  $DIR/timetracker -p
  $DIR/mdnsd $ip "$ipv6" &
  $DIR/ipsetload circleservers /tmp/circleservers
  ```
- **备注：** 证据支持：脚本内容显示执行多个二进制文件；ls -la 输出显示当前目录文件权限为 rwxrwxrwx，允许非 root 用户修改。建议立即修复目录权限（如改为 root 只写），并验证二进制完整性。后续可分析具体二进制（如 circled、timetracker）以识别其他漏洞。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `False`
- **风险级别：** `Low`
- **详细原因：** 警报部分准确：脚本/bin/startcircle确实以root权限执行/mnt/shares/usr/bin中的二进制文件（如get_tz、timetracker），这理论上可导致权限提升。然而，在静态固件分析中，目录/mnt/shares/usr/bin不存在，因此无法验证其权限是否为全局写（rwxrwxrwx）。没有证据支持该目录在静态环境中的存在或可写性，因此攻击链不完整，漏洞无法被确认可利用。攻击者模型为已认证的本地非root用户，但缺乏目录存在和可控输入的关键证据。

## 验证指标

- **验证时长：** 332.55 秒
- **Token 使用量：** 863775

---

## 原始信息

- **文件/目录路径：** `www/script/highcharts.js`
- **位置：** `highcharts.js:97 函数 buildText`
- **描述：** 在 Highcharts.js 的文本渲染过程中，存在一个 XSS 漏洞，源于动态设置 'onclick' 属性时未对用户提供的 href 值进行充分验证。当用户控制的文本内容（如图表数据标签、工具提示或轴标签）包含恶意 href 属性时，该属性值被提取并直接拼接到 'onclick' 处理程序中，形式为 'location.href="<user_input>"'。如果用户输入包含 'javascript:' URL，当用户点击受影响元素时，将执行任意 JavaScript 代码。攻击者可以利用此漏洞通过构造恶意图表配置（例如，在数据标签格式化器中返回 '<a href="javascript:alert('XSS')">Click</a>'）来触发 XSS，窃取会话 cookie、修改页面内容或执行其他恶意操作。漏洞触发条件包括：攻击者能够提供或修改图表配置数据，且受害者与图表交互（如点击元素）。
- **代码片段：**
  ```
  za(R,"style",X.match(e)[1].replace(/(;| |^)color([ :])/,"$1fill$2"));
  if(f.test(X)){za(R,"onclick",'location.href="'+X.match(f)[1]+'"');Ia(R,{cursor:"pointer"})}
  X=X.replace(/<(.|\n)*?>/g,"")||" ";
  ```
- **备注：** 此漏洞需要用户交互（点击）来触发，但通过社交工程或自动触发（如事件模拟）可能提高利用概率。建议对用户输入进行严格验证和转义，避免直接拼接字符串到事件处理程序中。需要进一步验证其他输入点（如工具提示格式化器）是否也受影响。在固件上下文中，攻击者作为已登录用户可能通过Web界面修改图表配置来利用此漏洞。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了 XSS 漏洞。证据显示在 highcharts.js 的 buildText 函数中，用户输入的文本内容（如来自图表数据标签）被处理时，如果包含 href 属性，其值通过正则表达式 /href="([^"]+)"/ 提取并直接拼接到 onclick 处理程序中（形式为 'location.href="<user_input>"'），且没有输入验证或转义。HTML 标签剥离（X=X.replace(/<(.|\n)*?>/g,"")）发生在之后，因此恶意输入如 'javascript:alert("XSS")' 不会被过滤。攻击者模型为已通过身份验证的远程用户（例如通过固件 Web 界面登录），他们可以修改图表配置（如在数据标签格式化器中返回 '<a href="javascript:alert(1)">Click</a>'）。受害者点击受影响元素时，任意 JavaScript 代码执行，导致会话窃取、页面篡改等实际损害。漏洞路径完整：输入可控（攻击者提供恶意配置）、路径可达（通过 Web 界面修改配置并交互点击）、实际影响（代码执行）。PoC 步骤：1. 攻击者登录固件 Web 界面；2. 修改图表配置，在数据标签中插入恶意内容，如 { dataLabels: { formatter: function() { return '<a href="javascript:alert(document.cookie)">Click Me</a>'; } } }；3. 受害者查看图表并点击该元素；4. 任意 JavaScript 执行（如窃取 cookie）。尽管需要用户交互，但通过社交工程或事件模拟可提高利用概率，因此风险高。

## 验证指标

- **验证时长：** 359.83 秒
- **Token 使用量：** 869539

---

## 原始信息

- **文件/目录路径：** `bin/circled`
- **位置：** `bin/circled: fcn.00011308 and fcn.0000f14c`
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
- **备注：** The vulnerability requires that the non-root user can set NVRAM variables (which is often possible via web interfaces or CLI commands in similar embedded systems). The 'circled' daemon likely runs with root privileges, so successful exploitation leads to root command execution. Further analysis could verify the exact permissions for NVRAM setting and the privilege level of circled. This finding is based on static analysis; dynamic testing would confirm exploitability.

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报部分准确：命令注入漏洞确实存在，但位置描述有误。漏洞实际在函数 fcn.0001062c 中，而非 fcn.00011308。证据如下：
- 在 fcn.0001062c（地址 0x00010a98），使用 `popen("nvram get circle_download_server", "r")` 读取 NVRAM 变量。
- 读取的值通过 fgets 存储到缓冲区，并调用 fcn.0000eab0（仅修剪空白字符，无其他过滤）。
- 在地址 0x00010c64，使用 snprintf 构建 wget 命令：`wget -q -T 10 -O /tmp/circleinfo.txt %s%s`，其中 %s 是用户控制的 NVRAM 值，然后通过 system 执行。
- 由于输入未正确清理（仅修剪空白），攻击者可注入命令（如使用 `;` 或 `` ` ``）。

攻击者模型：非 root 用户通过 web 接口或 CLI 设置 NVRAM 变量（在类似嵌入式系统中常见）。'circled' 进程以 root 权限运行，成功利用导致 root 命令执行。

PoC 步骤：
1. 作为非 root 用户，设置 NVRAM 变量：`nvram set circle_download_server="http://example.com/; malicious_command"`
2. 触发固件更新检查（例如，等待 circled 守护进程自动执行或重启服务）。
3. 恶意命令将以 root 权限执行，例如在 wget 命令中注入：`wget -q -T 10 -O /tmp/circleinfo.txt http://example.com/; malicious_command circleinfo.txt`

此漏洞已验证为实际可利用，风险高。

## 验证指标

- **验证时长：** 381.05 秒
- **Token 使用量：** 933375

---

