# R8900-V1.0.2.40 (27 个发现)

---

### PathTraversal-wpa_supplicant_setup_vif

- **文件/目录路径：** `lib/wifi/wpa_supplicant.sh`
- **位置：** `wpa_supplicant.sh:未知行号 (在函数 wpa_supplicant_setup_vif 中)`
- **风险评分：** 9.5
- **置信度：** 9.0
- **描述：** 在 'wpa_supplicant.sh' 脚本中，'ifname' 变量从配置系统获取并直接用于构建 'ctrl_interface' 路径，随后在 'rm -rf $ctrl_interface' 命令中使用。缺乏输入验证允许路径遍历攻击：如果攻击者设置 'ifname' 为恶意值（如 '../../etc'），则 'ctrl_interface' 路径可能解析为系统目录（如 '/etc'），导致 'rm -rf' 删除关键文件。触发条件包括攻击者通过配置接口（如 Web UI 或 CLI）修改无线配置并触发脚本执行（如重启网络接口）。利用方式包括设置 'ifname' 为路径遍历序列（如 '../../etc' 或 '/'), 导致任意文件删除，可能完全破坏系统。
- **代码片段：**
  ```
  ctrl_interface="/var/run/wpa_supplicant-$ifname"
  rm -rf $ctrl_interface
  ```
- **关键词：** ifname, ctrl_interface, /var/run/wpa_supplicant-$ifname, config_get
- **备注：** 攻击链完整：输入点（配置系统中的 'ifname'）-> 数据流（直接用于构建路径）-> 危险操作（'rm -rf'）。假设脚本以 root 权限运行，且攻击者能通过配置接口控制 'ifname'。需要进一步验证 'prepare_key_wep' 函数（未在脚本中定义）和其他配置变量是否引入额外风险。建议检查配置系统权限和输入过滤机制。

---
### CommandInjection-setup_interface_dhcp

- **文件/目录路径：** `etc/init.d/net-wan`
- **位置：** `net-wan: 函数 setup_interface_dhcp (大致行号 100-110，基于脚本内容)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 'net-wan' 脚本的多个函数中，通过 `$CONFIG get` 从 NVRAM 获取的配置值未加引号地用于 shell 命令执行，存在命令注入漏洞。具体在 `setup_interface_dhcp` 函数中，`u_hostname` 变量（来自 `wan_hostname` 或 `Device_name` 配置）直接用于 `udhcpc` 命令的 `-h` 选项。如果攻击者设置 `wan_hostname` 为恶意值（如 'example.com; malicious_command'），当脚本执行时，shell 会解析并执行注入的命令。攻击触发条件是攻击者通过 Web 界面或 API 修改 NVRAM 配置值，然后触发 WAN 接口重新连接（如通过重启网络服务）。利用方式简单，可获得 root 权限，因为脚本以 root 运行。
- **代码片段：**
  ```
  setup_interface_dhcp()
  {
  	local mtu
  	local u_hostname
  	local u_wan_domain=$($CONFIG get wan_domain)
  
  	mtu=$($CONFIG get wan_dhcp_mtu)
  	ifconfig $WAN_IF mtu ${mtu:-1500}
  	
  	if [ "x$($CONFIG get wan_hostname)" != "x" ];then
  		u_hostname=$($CONFIG get wan_hostname)
  	else
  		u_hostname=$($CONFIG get Device_name)
  	fi
  	if [ "$changing_mode" = "1" ]; then
  		udhcpc -b -i $WAN_IF -h $u_hostname -r $($CONFIG get wan_dhcp_ipaddr) -N $($CONFIG get wan_dhcp_oldip) ${u_wan_domain:+-d $u_wan_domain} &
      	else
  		udhcpc -b -i $WAN_IF -h $u_hostname -r $($CONFIG get wan_dhcp_ipaddr) -N $($CONFIG get wan_dhcp_oldip) ${u_wan_domain:+-d $u_wan_domain}
      	fi	
  }
  ```
- **关键词：** wan_hostname, Device_name, wan_dhcp_ipaddr, wan_dhcp_oldip, wan_domain, /www/cgi-bin/firewall.sh, udhcpc
- **备注：** 攻击链完整且可验证：攻击者修改 NVRAM 配置 -> 脚本执行时命令注入 -> 获得 root 权限。需要进一步验证 `$CONFIG` 命令是否确实从 NVRAM 获取值且攻击者可修改，但基于常见固件行为，这是合理的。建议检查其他类似函数（如 `setup_interface_ppp`）是否存在相同问题。

---
### Command-Injection-fcn.0000f064

- **文件/目录路径：** `usr/sbin/net-cgi`
- **位置：** `net-cgi:函数 fcn.0000f064 地址 0xf148, 0xf150, 0xf168, 0xf1ac, 0xf2cc, 0xf2d0`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在函数 fcn.0000f064 中，存在从 getenv("REMOTE_ADDR") 到 system 调用的命令注入漏洞。具体表现：REMOTE_ADDR 环境变量值被获取后，未经充分验证即用于构造 shell 命令字符串（通过 snprintf 和 sprintf），最终通过 system 调用执行。触发条件：当 net-cgi 处理 CGI 请求时，REMOTE_ADDR 环境变量被设置且包含恶意数据（如 shell 元字符）。约束条件：无明显的边界检查或输入过滤。潜在攻击：攻击者可通过伪造 HTTP 请求中的 REMOTE_ADDR 头注入任意命令（例如 '; rm -rf /'），导致远程代码执行。代码逻辑：getenv → 存储到内存 → 通过子函数处理 → 格式化到缓冲区 → 构造命令字符串 → system 执行。
- **代码片段：**
  ```
  污点传播路径代码：
  - 0x0000f148: bl sym.imp.getenv ; 获取 REMOTE_ADDR 环境变量
  - 0x0000f150: str r0, [r6] ; 存储到内存
  - 0x0000f168: bl fcn.0001cc48 ; 处理 REMOTE_ADDR 值
  - 0x0000f1ac: bl sym.imp.snprintf ; 格式化到缓冲区
  - 0x0000f2cc: bl sym.imp.sprintf ; 构造命令字符串 "echo %s >>/tmp/access_device_list"
  - 0x0000f2d0: bl sym.imp.system ; 执行命令
  ```
- **关键词：** REMOTE_ADDR, /tmp/access_device_list
- **备注：** REMOTE_ADDR 环境变量在 CGI 上下文中通常由 HTTP 请求控制，攻击者容易操纵。关联函数 fcn.0001cc48 可能涉及进一步处理。建议验证实际部署中该变量的可操纵性，并检查系统权限以评估影响范围。

---
### Arbitrary-Command-Execution-fcn.0003a08c

- **文件/目录路径：** `usr/sbin/net-cgi`
- **位置：** `net-cgi:函数 fcn.0003a08c 地址 0x3a0e8, 函数 fcn.000512cc 地址 0x513f4`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在函数 fcn.0003a08c 中，存在从 getenv("HTTP_USER_AGENT") 到 execve 调用的任意命令执行漏洞。具体表现：HTTP_USER_AGENT 环境变量值被获取后，传递给子函数 fcn.000512cc，并最终作为路径参数用于 execve 调用。触发条件：当 net-cgi 处理 CGI 请求时，HTTP_USER_AGENT 环境变量被设置且包含恶意命令路径。约束条件：无输入验证或路径检查。潜在攻击：攻击者可通过设置 HTTP_USER_AGENT 头指向恶意可执行文件路径，导致 execve 执行任意代码。代码逻辑：getenv → 传递到子函数 → 加载到寄存器 → execve 执行。
- **代码片段：**
  ```
  污点传播路径代码：
  - 0x0003a0e8: bl sym.imp.getenv ; 获取 HTTP_USER_AGENT 环境变量
  - 0x0003a1c4: bl fcn.000512cc ; 传递污点数据作为参数
  - 0x000513e4: ldr r0, [var_0h] ; 从栈加载污点数据到 r0
  - 0x000513f4: bl sym.imp.execve ; 执行污点数据中的命令
  ```
- **关键词：** HTTP_USER_AGENT
- **备注：** HTTP_USER_AGENT 环境变量通常由客户端完全控制，因此攻击者容易利用。需要验证 execve 调用是否在特权上下文中执行。关联函数 fcn.000512cc 可能涉及参数处理。建议检查系统路径和文件权限以评估影响范围。

---
### PrivEsc-setup.sh

- **文件/目录路径：** `iQoS/R9000/TM/setup.sh`
- **位置：** `setup.sh: start case (lines executing scripts with relative paths)`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** The 'setup.sh' script executes multiple external scripts using relative paths (e.g., ./iqos-setup.sh, ./dc_monitor.sh) in the 'start' and 'restart' cases. The current directory and all files have permissions 'drwxrwxrwx' and '-rwxrwxrwx', making them writable by any user, including non-root attackers. The script performs privileged operations (e.g., insmod, iptables, mknod), indicating it is designed to run as root. An attacker can modify any of the executed scripts (e.g., iqos-setup.sh, dc_monitor.sh) to inject malicious commands, which will run with root privileges when 'setup.sh' is triggered (e.g., during system startup or service restarts). This provides a direct path to privilege escalation.
- **代码片段：**
  ```
  Examples from script:
  - ./$iqos_setup restart  # where $iqos_setup='iqos-setup.sh'
  - ./dc_monitor.sh &
  - ./$wred_setup &  # where $wred_setup='wred-setup.sh'
  - ./clean-cache.sh > /dev/null 2>&1 &
  - In 'restart' case: $0 stop and $0 start  # self-referential execution
  ```
- **关键词：** ./iqos-setup.sh, ./dc_monitor.sh, ./wred-setup.sh, ./clean-cache.sh, ./lic-setup.sh, ./setup.sh
- **备注：** The risk is high due to the clear attack chain: writable directory + relative path execution + privileged context. However, direct evidence of root execution (e.g., process ownership) is inferred from privileged commands. Further verification is recommended on how 'setup.sh' is triggered in the system (e.g., via init scripts or services). Associated files include iqos-setup.sh, dc_monitor.sh, etc., which should be secured with proper permissions.

---
### Command-Injection-QoSControl-update

- **文件/目录路径：** `iQoS/R8900/TM/QoSControl`
- **位置：** `QoSControl: function update (approx lines after 'line=`cat /tmp/Trend_Micro.db | grep netgear-detection`')`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** 在 update 函数中存在命令注入漏洞。攻击者可以通过篡改 /tmp/Trend_Micro.db 文件内容来控制 $version 变量，该变量在 unzip 命令中未正确引用。当调用 QoSControl update（或相关函数如 auto_update、boot）时，脚本会解析 /tmp/Trend_Micro.db 并执行 `unzip -o /tmp/$version -d /tm_pattern/`。如果 $version 包含 shell 元字符（如分号），攻击者可注入任意命令。触发条件：攻击者需先创建或修改 /tmp/Trend_Micro.db 文件（由于 /tmp 通常全局可写），然后调用 QoSControl update。利用方式：在 $version 中嵌入恶意命令（例如 'malicious;id;'），导致命令以脚本运行用户（可能为 root）权限执行，实现权限提升。
- **代码片段：**
  ```
  line=\`cat /tmp/Trend_Micro.db | grep netgear-detection\`
  if [ "x$line" != "x" ] ; then
  	version=\`echo $line |awk -F " " '{print $9}'\`
  	...
  	curl ftp://updates1.netgear.com/sw-apps/dynamic-qos/trend/r9000/$version -o /tmp/$version 2>/dev/null
  	...
  	unzip -o /tmp/$version -d /tm_pattern/
  ```
- **关键词：** /tmp/Trend_Micro.db, trend_micro_enable, auto_update, first_boot_qos
- **备注：** 假设 QoSControl 脚本以 root 权限运行（常见于固件管理脚本）。需要进一步验证 /TM/priority 和 /tm_pattern/sample.bin 等其他组件的安全性，但此漏洞独立存在。建议检查脚本执行权限和 /tmp 目录的访问控制。

---
### CommandInjection-liblicop.so-sym.__read_cmd

- **文件/目录路径：** `iQoS/R9000/tm_key/liblicop.so`
- **位置：** `liblicop.so:0x3024 sym.__read_cmd`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'liblicop.so' 中发现一个命令注入漏洞，攻击链完整且实际可利用。攻击者可通过可控输入触发命令执行。具体细节：
- **输入点**：导出函数（如 'sym.get_dev_key'）的参数，可能来自外部调用（如网络接口或 IPC）。
- **数据流**：输入通过 'sym.__check_model' 传递到 'sym.__read_cmd'，其中命令字符串未经验证或转义。
- **危险操作**：'sym.__read_cmd' 使用 popen 执行系统命令，如果输入包含恶意命令（如分号或反引号），可导致任意命令执行。
- **触发条件**：攻击者需能调用相关导出函数并控制输入字符串（例如，通过修改 NVRAM 变量或发送恶意请求）。
- **利用方式**：注入命令如 '; rm -rf /' 或 '`cat /etc/passwd`'，可导致权限提升或系统破坏。
- **代码逻辑**：'sym.__read_cmd' 检查输入是否以 'r* ' 开头，决定使用 fopen 或 popen，但命令字符串直接来自输入，无过滤。
- **代码片段：**
  ```
  0x00003024      26f7ffeb       bl sym.imp.popen            ; file*popen(const char *filename, const char *mode)
  ; 前置代码：输入字符串通过参数传递，未经验证
  0x0000300c      30301be5       ldr r3, [var_30h]           ; 0x30
  0x00003010      003093e5       ldr r3, [r3]
  0x00003014      0300a0e1       mov r0, r3                  ; const char *filename
  0x00003018      ec319fe5       ldr r3, [0x0000320c]        ; [0x320c:4]=0x1fb8
  0x0000301c      03308fe0       add r3, pc, r3
  0x00003020      0310a0e1       mov r1, r3                  ; const char *mode
  ; 这里，r0 包含命令字符串，直接用于 popen
  ```
- **关键词：** sym.get_dev_key, sym.__check_model, sym.__read_cmd, sym.imp.popen
- **备注：** 攻击链完整：输入点（导出函数）→ 数据流（sym.__check_model）→ 危险操作（popen）。需要进一步验证导出函数的调用上下文，但基于代码证据，漏洞可利用。建议检查固件中调用 'liblicop.so' 导出函数的组件，以确认实际攻击面。

---
### stack-buffer-overflow-fcn.000086e8

- **文件/目录路径：** `iQoS/R9000/TM/priority`
- **位置：** `priority:0x000088f4 fcn.000086e8`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'priority' 二进制文件的 'set_info' 命令处理中，存在栈缓冲区溢出漏洞。触发条件：当攻击者以 'set_info' 模式运行程序并提供恶意优先级值时，程序使用 sprintf 将格式化字符串 '{%d}' 写入固定大小的栈缓冲区（仅10字节）。如果优先级值产生的字符串长度超过10字节（例如，优先级为 1000000000 时字符串为 '{1000000000}'，长度12字节），则会导致栈缓冲区溢出。溢出可能覆盖保存的寄存器（包括返回地址 lr），允许攻击者控制程序流并执行任意代码。利用方式：攻击者作为已登录用户运行 'priority set_info <MAC> <恶意优先级>'，其中恶意优先级被精心构造以溢出缓冲区并注入 shellcode 或覆盖返回地址。
- **代码片段：**
  ```
  0x000088f4      0d00a0e1       mov r0, sp                  ; char *s
  0x000088f8      68ffffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  ; 格式字符串为 "{%d}"，参数为优先级值 r4，目标缓冲区为 sp（大小仅10字节）
  ```
- **关键词：** 命令行参数 argv[2] (MAC 地址), 命令行参数 argv[3] (优先级值), 文件路径 /TM/qos.conf
- **备注：** 漏洞位于 'set_info' 分支的 sprintf 调用处。需要进一步验证实际利用可行性，例如测试具体优先级值以确认溢出长度和覆盖效果。建议检查二进制是否启用了栈保护（如 CANARY），但从反编译代码中未明显可见。关联函数 fcn.00008b88 负责文件读取，未发现直接漏洞。攻击链完整：输入点（命令行参数）→ 数据流（sprintf）→ 危险操作（栈溢出）。

---
### Arbitrary-Memory-Write-fcn.00011090

- **文件/目录路径：** `bin/ookla`
- **位置：** `fcn.00011090:0x00011090 (关键传播点位于子函数 fcn.00010b2c:0x00010b2c 和 fcn.00010b8c:0x00010b8c)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在函数 fcn.00011090 中，用户控制的输入参数 param_1 通过子函数 fcn.00010b2c 和 fcn.00010b8c 传播，最终控制 sym.imp.vsnprintf 的缓冲区指针，允许任意内存写入。触发条件是通过外部接口（如网络服务或API）调用 fcn.00011090 并传递恶意构造的 param_1。攻击者可通过操纵指针值覆盖关键内存区域，导致代码执行、权限提升或系统崩溃。代码逻辑涉及状态机解析和动态内存分配，污点数据在循环和条件分支中传播，缺少指针验证。约束条件包括需要精确控制指针值以指向有效内存地址，且攻击者需有权限调用该函数。
- **代码片段：**
  ```
  从 fcn.00011090 反编译代码中相关部分：
  - iVar2 = fcn.00010b2c(*(piVar6[-8] + 0xc));  // 污点数据传递到 fcn.00010b2c
  - iVar2 = fcn.00010b8c(*(piVar6[-8] + 0xc), piVar6 + -0x18);  // 污点数据传递到 fcn.00010b8c
  从污点传播路径，在 fcn.00011f5c 中：
  - sym.imp.vsnprintf(*(puVar1 + -0x10), 0xff, *(puVar1 + 8), *(puVar1 + -8));  // 污点数据作为缓冲区参数
  ```
- **关键词：** fcn.00011090, fcn.00010b2c, fcn.00010b8c, fcn.00011f5c, sym.imp.vsnprintf
- **备注：** 污点传播通过 FunctionDelegator 分析验证，显示从 param_1 到 vsnprintf 的完整路径。需要进一步验证 fcn.00011090 的调用上下文（例如，是否通过 HTTP 服务、IPC 或 NVRAM 接口调用）以确认输入点的可访问性。建议分析固件中调用此函数的组件，并测试实际利用条件。关联文件可能包括网络守护进程或配置解析器。

---
### StackBufferOverflow-priority_set_info

- **文件/目录路径：** `iQoS/R8900/TM/priority`
- **位置：** `priority:0x0000879c fcn.000086e8`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'priority' 二进制文件的 'set_info' 命令处理过程中，存在一个栈缓冲区溢出漏洞。当用户提供 MAC 地址参数时，程序使用 `sprintf` 将格式字符串 'mac=%s' 写入固定大小的栈缓冲区（28 字节），但未对输入长度进行验证。如果 MAC 地址长度超过 24 字节（扣除 'mac=' 前缀的 4 字节），就会导致缓冲区溢出，覆盖栈上的返回地址和其他保存的寄存器。攻击者作为已登录的非root用户，可以通过执行 'priority set_info "<long_mac_address>" "<priority>"' 命令触发此漏洞，其中 <long_mac_address> 是精心构造的超长字符串（超过 24 字节）。溢出允许控制程序计数器（pc），从而实现任意代码执行，可能提升权限或破坏系统稳定性。漏洞触发条件简单，仅需有效的命令行参数。
- **代码片段：**
  ```
  // 关键代码片段从反编译中提取
  sprintf(puVar17 + -0x1c, "mac=%s", uVar11); // uVar11 是用户提供的 MAC 地址
  // puVar17 + -0x1c 指向 28 字节栈缓冲区 auStack_3c
  // 无长度检查，直接使用 sprintf
  ```
- **关键词：** 命令行参数（argv[2]：MAC 地址）, 文件路径：/TM/qos.conf
- **备注：** 漏洞已通过代码分析验证，栈布局显示缓冲区紧邻保存的寄存器和返回地址。攻击链完整：从命令行输入到溢出再到代码执行。建议进一步测试以确认偏移量和利用稳定性。关联文件 /TM/qos.conf 可能被覆盖，但主要风险是代码执行。后续分析可检查其他函数或输入点是否有类似问题。

---
### command-injection-tcd-recvfrom

- **文件/目录路径：** `iQoS/R9000/TM/tcd`
- **位置：** `tcd:0x8fac fcn.00008fac`
- **风险评分：** 8.5
- **置信度：** 8.5
- **描述：** 命令注入漏洞存在于 'tcd' 的主循环中。程序使用 `recvfrom` 从网络套接字接收数据，并检查消息类型（nlmsg_type）。如果消息类型为 0x905，则从接收的数据中提取字符串（通过全局指针 `*0x9244`），并使用 `snprintf` 将其嵌入到 'tc %s' 命令字符串中，最后通过 `system` 执行。攻击者可以构造恶意网络消息，控制嵌入的字符串，从而注入任意命令。触发条件：攻击者发送类型为 0x905 的消息，且消息内容包含命令注入字符（如 ';'、'|' 或 '`'）。约束条件：缓冲区大小有限（0x103 字节），但足够用于常见注入；缺少输入验证和转义。潜在攻击：命令执行可能导致权限提升、信息泄露或系统控制。
- **代码片段：**
  ```
  // 从网络接收数据
  uVar2 = sym.imp.recvfrom(uVar3, 0x21dc | 0x10000, 0x110, 0);
  // 检查消息类型并设置全局变量
  if (*(puVar5[-1] + 4) == 0x905) {
      *(0x21d8 | 0x10000) = *0x9244;
  }
  // 构建命令字符串并执行
  sym.imp.snprintf(0x22ec | 0x10000, 0x103, "tc %s", *(0x21d8 | 0x10000));
  sym.imp.system(0x22ec | 0x10000);
  ```
- **关键词：** socket (recvfrom), NVRAM/ENV: *0x9244, command: tc
- **备注：** 攻击链完整：输入点（网络套接字）→ 数据流（全局变量设置）→ 危险操作（system 调用）。需要进一步验证套接字初始化（例如在 fcn.00008d7c 中）以确认攻击者可达性。建议测试实际利用，例如发送恶意消息到进程套接字。关联文件：可能涉及网络配置或其他组件，但当前分析限于 'tcd'。

---
### CommandInjection-dni-wifi-config

- **文件/目录路径：** `etc/dni-wifi-config`
- **位置：** `dni-wifi-config: 主要部分（在 'if [ -n "$DNI_CONFIG" ]; then' 块内）`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'dni-wifi-config' 脚本中，使用 `eval` 直接执行 `dniconfig get` 的输出（例如对于 `wl_hw_btn_state` 配置值），缺少输入验证和过滤。如果攻击者能控制配置值，可注入 shell 元字符（如分号）来执行任意命令。触发条件当脚本以 root 权限运行时（如在系统启动或 WiFi 配置更新时），且配置值包含恶意命令。攻击者作为非 root 用户但拥有登录凭据，可能通过管理接口（如 Web GUI）修改配置值，完成攻击链：修改配置 -> 脚本执行 -> 命令注入 -> 权限提升。
- **代码片段：**
  ```
  eval wl_hw_btn_state=\`dniconfig get wl_hw_btn_state\`
  [ -z "$wl_hw_btn_state" ] && {
      wl_hw_btn_state=on
      dniconfig set wl_hw_btn_state="on"
  }
  ```
- **关键词：** wl_hw_btn_state, endis_wl_radio, endis_wla_radio, wlg1_endis_guestNet, wla1_endis_guestNet
- **备注：** 脚本中其他类似 `eval` 使用（如对于 onoff 变量）也可能存在漏洞，但 'wl_hw_btn_state' 处最直接。建议验证 `dniconfig` 命令的输入过滤和权限设置，并检查脚本是否以 root 权限运行。后续可分析管理接口如何修改这些配置值。

---
### CommandInjection-statistic_mac80211

- **文件/目录路径：** `lib/wifi/mac80211.sh`
- **位置：** `mac80211.sh:statistic_mac80211`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 在 statistic_mac80211 函数中，ifname 配置值未加引号地用于 ifconfig 命令，允许命令注入。攻击者可以通过修改无线接口配置设置恶意 ifname（例如 'wlan0; malicious_command'），当 statistic_mac80211 被调用时（例如通过状态监控或统计查询），shell 会解析 ifname 中的分号并执行注入的命令。由于脚本通常以 root 权限运行，注入的命令将以 root 权限执行。触发条件包括：攻击者修改 ifname 配置，并触发 statistic_mac80211 执行（例如通过 Web UI 或 CLI 请求统计信息）。
- **代码片段：**
  ```
  config_get ifname "$vif" ifname
  [ -n "$ifname" ] || {
      [ $i -gt 0 ] && ifname="wlan${phy#phy}-$i" || ifname="wlan${phy#phy}"
  }
  tx_packets_tmp=\`ifconfig $ifname | grep "TX packets" | awk -F: '{print $2}' | awk '{print $1}'\`
  rx_packets_tmp=\`ifconfig $ifname | grep "RX packets" | awk -F: '{print $2}' | awk '{print $1}'\`
  tx_bytes_tmp=\`ifconfig $ifname | grep bytes: | awk -F: '{print $3}' | awk '{print $1}'\`
  rx_bytes_tmp=\`ifconfig $ifname | grep bytes: | awk -F: '{print $2}' | awk '{print $1}'\`
  ```
- **关键词：** ifname
- **备注：** 攻击链完整：从配置输入（ifname）到命令执行。需要攻击者能修改无线配置（例如 /etc/config/wireless）并触发函数执行。默认情况下，非 root 用户可能无法直接修改配置，但如果有 misconfiguration（如错误的文件权限）或通过其他服务（如 Web UI），可能可利用。建议检查配置文件的权限和访问控制。

---
### CommandInjection-wigigstainfo_mac80211

- **文件/目录路径：** `lib/wifi/mac80211.sh`
- **位置：** `mac80211.sh:wigigstainfo_mac80211`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 在 wigigstainfo_mac80211 函数中，ifname 配置值未加引号地用于 iw 命令，允许命令注入。攻击者可以通过修改无线接口配置设置恶意 ifname（例如 'wlan0; malicious_command'），当 wigigstainfo_mac80211 被调用时（例如通过客户端信息查询），shell 会解析 ifname 中的分号并执行注入的命令。由于脚本通常以 root 权限运行，注入的命令将以 root 权限执行。触发条件包括：攻击者修改 ifname 配置，并触发 wigigstainfo_mac80211 执行（例如通过状态检查或用户请求）。
- **代码片段：**
  ```
  config_get ifname "$vif" ifname
  iw $ifname station dump | \
      sed '/^\s*$/N; /\nStation/s/\(\nStation\)/\n\1/' \
      >> $tmpfile
  ```
- **关键词：** ifname
- **备注：** 攻击链完整：从配置输入（ifname）到命令执行。需要攻击者能修改无线配置并触发函数执行。与 statistic_mac80211 类似，可利用性依赖于配置修改能力。函数可能由网络管理工具定期调用或按需触发，增加了利用机会。

---
### 无标题的发现

- **文件/目录路径：** `sbin/hotplug2`
- **位置：** `hotplug2:0x00009270 fcn.00009270`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** The 'hotplug2' binary contains a command injection vulnerability where user-controlled command-line arguments are used directly in exec* functions without sanitization. In function fcn.00009270, command-line arguments are parsed using strcmp and strdup, and stored in global variables. Specifically, puVar1[8] is set from a command-line argument and later used in sym.imp.execlp(uVar9, uVar9, iVar11) where uVar9 is puVar1[8]. This allows an attacker to inject arbitrary commands by crafting malicious arguments. As a non-root user with login credentials, the attacker can execute hotplug2 with controlled arguments to run arbitrary commands with their privileges. The binary has permissions -rwxrwxrwx, making it executable by any user, and no setuid bit is set, so it runs with the user's privileges. This vulnerability is directly exploitable via command-line invocation.
- **代码片段：**
  ```
  // From fcn.00009270 decompilation
  iVar13 = sym.imp.strcmp(iVar12,*0x9840);
  if (iVar13 != 0) {
      iVar13 = sym.imp.strcmp(iVar12,*0x9844);
      if (iVar13 == 0) {
          iVar11 = iVar15 + 0;
          if (iVar11 == 0) break;
          uVar9 = sym.imp.strdup(piVar8[1]);
          puVar1[8] = uVar9; // User-controlled argument stored
          piVar8 = piVar14;
      }
      // ... other cases
  }
  // Later in the code
  if (iVar11 != 0) {
      sym.imp.waitpid(iVar11,puVar19 + 0xfffff5fc,0);
      goto code_r0x000095dc;
  }
  sym.imp.execlp(uVar9,uVar9,iVar11); // Direct use in execlp
  ```
- **关键词：** puVar1[8], sym.imp.execlp, command-line arguments
- **备注：** This vulnerability requires the user to have execution access to hotplug2, which is granted by the file permissions. No privilege escalation is achieved, but arbitrary command execution as the user is possible. Further analysis could reveal if network input or environment variables also lead to command injection, but the command-line argument path is already verifiable and exploitable.

---
### XSS-refresh_plex_status

- **文件/目录路径：** `www/plex_media.htm`
- **位置：** `plex_media.htm: JavaScript 函数 `refresh_plex_status` 中设置 `innerHTML` 的位置（具体在设置 `plex_usb` 元素内容时）`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在 'plex_media.htm' 中发现一个存储型跨站脚本（XSS）漏洞。攻击者作为拥有有效登录凭据的非 root 用户，可以通过添加网络驱动并设置设备名称为恶意 JavaScript 代码（例如 `<script>alert('xss')</script>`）来利用此漏洞。当用户访问 'plex_media.htm' 页面时，JavaScript 函数 `refresh_plex_status` 从 `plex_status.xml` 获取设备信息，并使用 `innerHTML` 直接设置页面元素内容，导致恶意代码执行。触发条件包括：攻击者成功添加恶意网络驱动，且受害者访问或刷新 'plex_media.htm' 页面。利用方式包括窃取会话 cookie、修改设备设置或执行其他恶意操作。漏洞由于缺少对设备名称的输入过滤和输出转义，使得攻击者能够注入任意脚本。
- **代码片段：**
  ```
  在 \`refresh_plex_status\` 函数中：
  if(names[sel_num].childNodes[0].nodeValue == "plex_device_name_null_mark")
      usb_msg = 'USB'+(sel_num+1)+' , '+types[sel_num].childNodes[0].nodeValue+' , '+'$plex_total'+t_size[sel_num].childNodes[0].nodeValue+' , '+'$plex_free'+f_size[sel_num].childNodes[0].nodeValue;
  else
      usb_msg = 'USB'+(sel_num+1)+' , '+types[sel_num].childNodes[0].nodeValue+' , '+names[sel_num].childNodes[0].nodeValue+' , '+'$plex_total'+t_size[sel_num].childNodes[0].nodeValue+' , '+'$plex_free'+f_size[sel_num].childNodes[0].nodeValue;
  document.getElementById("plex_usb").innerHTML=usb_msg;
  设备名称 \`names[sel_num].childNodes[0].nodeValue\` 未转义直接用于 \`innerHTML\`，允许 XSS。
  ```
- **关键词：** plex_net_scan.htm, plex_media, http_loginname, /tmp/plex_reset_result, apply.cgi
- **备注：** 此漏洞需要攻击者能添加网络驱动，但作为认证用户，这是允许的操作。攻击链完整：从输入点（网络驱动名称）到危险操作（脚本执行）。建议进一步分析 `plex_net_scan.htm` 以确认输入验证情况，并检查服务器端组件（如 `apply.cgi`）是否有其他漏洞。此外，其他类似 `innerHTML` 设置点（如 `plex_status` 元素）也可能存在相同问题，应全面审查。

---
### CommandInjection-enable_mac80211

- **文件/目录路径：** `lib/wifi/mac80211.sh`
- **位置：** `mac80211.sh:enable_mac80211`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在 enable_mac80211 函数中，txantenna 和 rxantenna 配置值未加引号地用于 iw phy set antenna 命令，允许命令注入。攻击者可以通过修改无线设备配置设置恶意 txantenna 或 rxantenna（例如 'all; malicious_command'），当 enable_mac80211 被调用时（例如在无线接口启用或重新配置时），shell 会解析变量中的分号并执行注入的命令。由于脚本以 root 权限运行，注入的命令将以 root 权限执行。触发条件包括：攻击者修改 txantenna 或 rxantenna 配置，并触发 enable_mac80211 执行（例如通过接口启用或配置重载）。
- **代码片段：**
  ```
  config_get txantenna "$device" txantenna all
  config_get rxantenna "$device" rxantenna all
  iw phy "$phy" set antenna $txantenna $rxantenna >/dev/null 2>&1
  ```
- **关键词：** txantenna, rxantenna
- **备注：** 攻击链完整：从配置输入（txantenna/rxantenna）到命令执行。需要攻击者能修改无线设备配置并触发 enable_mac80211 执行（例如通过 /etc/init.d/network reload）。由于 enable_mac80211 通常在接口启动时运行，触发频率较低，但仍然可利用。建议对所有配置变量使用引号以防止单词拆分和命令注入。

---
### Command-Injection-fcn.00012eb4

- **文件/目录路径：** `bin/busybox`
- **位置：** `busybox:0x12eb4 fcn.00012eb4`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** The function at address 0x12eb4 (fcn.00012eb4) uses the system() function to execute commands constructed from directory entries and parameters. Specifically, it reads directory entries via readdir64, constructs a path using fcn.0004244c, and passes it to system() without adequate validation. An attacker with control over the directory contents or parameters could inject arbitrary commands. The function also sets an environment variable using setenv, which might influence command execution. This could be triggered through a BusyBox applet that handles user input, such as one processing scripts or configurations.
- **代码片段：**
  ```
  uint fcn.00012eb4(uint *param_1) {
      // ... (setenv and directory processing)
      iVar2 = sym.imp.readdir64(iVar1);
      if (iVar2 != 0) {
          uVar3 = fcn.0004244c(*0x12f9c, param_1[1], iVar2 + 0x13);
          iVar4 = sym.imp.system(uVar3);  // First system call
          // ...
      }
      uVar3 = fcn.0004244c(*0x12fa0, param_1[1]);
      sym.imp.system();  // Second system call
      // ...
  }
  ```
- **关键词：** sym.imp.system, sym.imp.readdir64, sym.imp.setenv, fcn.0004244c
- **备注：** The function fcn.00012eb4 is likely part of a BusyBox applet (e.g., related to script execution or directory processing). Further analysis is needed to identify the exact applet and its usage context. The attack requires the attacker to influence the directory contents or parameters, which might be achievable through file uploads or manipulated environment variables. Verification of the applet's exposure to user input is recommended for full exploit chain validation.

---
### BufferOverflow-datalib-fcn.0000937c

- **文件/目录路径：** `bin/datalib`
- **位置：** `datalib:0x94a4 fcn.0000937c strcpy call`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'datalib' 中发现一个缓冲区溢出漏洞，源于函数 fcn.0000937c 中使用 strcpy 复制用户控制的字符串，而没有充分验证目标缓冲区大小。该函数被 fcn.000095a0 调用，后者解析来自 NVRAM 或配置输入的键值对字符串（格式为 'key=value'）。攻击者作为认证用户，可以通过 web 接口或 CLI 设置长的配置值（如 wl_ssid、wl_wpa_psk 或其他 NVRAM 变量），触发缓冲区溢出。溢出可能覆盖相邻内存，包括返回地址或函数指针，导致任意代码执行。漏洞触发条件包括：提供长度超过目标缓冲区的字符串；约束条件包括全局缓冲区大小限制（0x20000 字节），但 strcpy 操作无视具体边界。潜在攻击方式包括通过配置更新机制提交恶意长字符串，利用溢出控制程序流。
- **代码片段：**
  ```
  // From fcn.0000937c
  sym.imp.strcpy(puVar6 + 3, param_1); // Key copy
  puVar1 = sym.imp.strcpy(iVar7, param_2); // Value copy
  // From fcn.000095a0
  fcn.0000937c(puVar2, puVar3); // Called for each key-value pair
  ```
- **关键词：** wl_ssid, wl_wpa_psk, http_username, http_passwd, wan_pppoe_username, wan_pppoe_passwd, defaults_config, /dev/mtd_config
- **备注：** 漏洞需要攻击者拥有有效登录凭据（非root用户），但通过 web 接口配置更新是常见操作。攻击链完整：从用户输入（NVRAM 变量）到危险操作（strcpy）。建议进一步验证全局缓冲区的布局和溢出后果，例如通过动态测试或调试。关联函数包括 fcn.000095a0 和 fcn.0000937c。后续分析应关注其他输入点（如 recvfrom）和类似危险函数（如 sprintf）。

---
### Permission-OpenVPN-Script

- **文件/目录路径：** `etc/init.d/openvpn`
- **位置：** `init.d/openvpn (文件权限)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 脚本 'openvpn' 具有全局写权限（rwxrwxrwx），允许任何用户（包括非 root 用户）修改其内容。如果脚本以 root 权限执行（例如在系统启动时或通过服务管理命令），攻击者可以通过修改脚本注入恶意代码，从而获得 root 权限。触发条件包括：1) 非 root 用户修改脚本；2) 脚本随后以 root 权限执行（如系统重启或服务重启）。利用方式：攻击者写入任意命令（例如反向 shell 或文件操作）到脚本中，然后等待或触发执行。约束条件：攻击者需要能触发脚本执行，这可能依赖于系统配置（如是否允许非 root 用户控制服务）。
- **代码片段：**
  ```
  不适用（文件权限问题），但权限证据：-rwxrwxrwx 1 user user 4762 7月  13  2017 openvpn
  ```
- **关键词：** file_path:./openvpn
- **备注：** 风险评分基于文件权限和潜在的执行上下文（脚本可能在启动时以 root 运行）。置信度高，因为文件权限证据明确，但攻击链的完整性依赖于执行触发（需要进一步验证系统配置，如服务管理权限）。建议检查是否非 root 用户能执行或重启此服务（例如通过 /etc/init.d/openvpn）。关联文件：可能涉及服务管理机制或 cron 作业。后续分析方向：验证脚本的执行上下文和系统权限配置。

---
### Command-Injection-wifi_updown

- **文件/目录路径：** `sbin/wifi`
- **位置：** `wifi script, function wifi_updown`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 `wifi_updown` 函数中，使用 `eval` 执行动态生成的命令字符串，其中 `$driver` 和 `$iftype` 来自配置文件。如果攻击者能够修改无线配置（如通过 web 界面），注入 shell 元字符（如分号或反引号），可导致任意命令执行。触发条件：当 WiFi 启用或禁用时脚本以 root 权限运行。漏洞利用方式：非root用户修改配置中的 `driver` 或 `iftype` 值为恶意字符串（如 'a; malicious_command'），当 `eval` 执行时，注入的命令以 root 权限运行。边界检查：脚本未对 `$driver` 或 `$iftype` 进行过滤或验证。
- **代码片段：**
  ```
  for driver in ${DRIVERS}; do (
      if eval "type pre_${driver}" 2>/dev/null >/dev/null; then
          eval "pre_${driver}" ${1}
      fi
  ); done
  for device in ${2:-$DEVICES}; do (
      config_get iftype "$device" type
      if eval "type ${1}_$iftype" 2>/dev/null >/dev/null; then
          eval "${1}_$iftype" '$device' || echo "$device($iftype): ${1} failed"
      else
          echo "$device($iftype): Interface type not supported"
      fi
  ); done
  ```
- **关键词：** NVRAM/ENV: wireless configuration variables (driver, iftype), 文件路径: /etc/config/wireless, IPC: UCI configuration system, 函数符号: pre_${driver}, ${1}_$iftype
- **备注：** 攻击链依赖非root用户能修改无线配置，这在 OpenWrt 中可能通过 web 界面或 UCI 命令实现。建议验证配置文件的写权限和认证机制。关联文件：/lib/wifi（定义 DRIVERS）。

---
### Buffer-Overflow-set_info

- **文件/目录路径：** `iQoS/R8900/TM/priority`
- **位置：** `priority:0x00008798 fcn.000086e8`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'priority' 程序的 'set_info' 命令中，存在一个栈缓冲区溢出漏洞。当程序处理用户提供的 MAC 地址参数（argv[2]）时，使用 sprintf 函数将 'mac=%s' 格式化到栈缓冲区中。该缓冲区大小为 25 字节，但用户输入的 MAC 地址长度不受限制，导致溢出。触发条件：攻击者执行 'priority set_info <MAC> <priority>' 命令，其中 <MAC> 为长字符串（超过 21 字节）。溢出可覆盖保存的返回地址（lr 寄存器），允许控制流劫持和代码执行。潜在攻击方式包括注入 shellcode 或 ROP 链，前提是系统没有 ASLR 或栈保护（在嵌入式设备中常见）。约束条件：程序必须由用户执行，且 argc >= 4。
- **代码片段：**
  ```
  0x00008798: add r0, src                 ; char *s (buffer at sp+0x0c)
  0x0000879c: bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  ; Format string: "mac=%s" at address 0x8db8
  ; User input: r6 (argv[2])
  ```
- **关键词：** argv[2] (MAC address parameter), /TM/qos.conf
- **备注：** 漏洞已通过反汇编验证，利用链完整：用户控制输入 -> sprintf 缓冲区溢出 -> 返回地址覆盖 -> 代码执行。建议进一步测试利用可行性，并检查系统保护机制（如 ASLR、NX）。关联文件：/TM/qos.conf（程序写入的配置文件）。

---
### BufferOverflow-fcn.0000cf18

- **文件/目录路径：** `iQoS/R9000/tm_pattern/sample.bin`
- **位置：** `sample.bin:0xcf50 fcn.0000cf18`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在函数 fcn.0000cf18 中，使用 config_get 检索配置值后，通过 strcpy 复制到固定大小缓冲区，缺乏边界检查。攻击者可通过控制配置数据（如通过 NVRAM 设置或恶意配置文件）注入超长字符串，导致缓冲区溢出，可能覆盖相邻内存并执行任意代码。触发条件：当程序处理配置值时（例如，通过特定操作或初始化）。约束条件：缓冲区大小未知，但 strcpy 的使用表明无大小限制。潜在攻击方式：攻击者作为已登录用户可能修改配置变量，传递精心构造的输入以劫持控制流。
- **代码片段：**
  ```
  uVar2 = sym.imp.config_get(puVar10 + -0xa4);
  sym.imp.strcpy(puVar10 + -0x84, uVar2);
  ...
  sym.imp.strcpy(iVar6, uVar2);
  ...
  sym.imp.strcpy(iVar7 + 0x18, uVar3);
  ```
- **关键词：** config_get, trend_micro_enable, trendmicro_console_enable, /tm_pattern/bwdpi.devdb.db
- **备注：** 漏洞可利用性取决于配置数据来源（如 NVRAM 变量），建议进一步分析 config_get 的调用链以确认输入点。关联文件：/tm_pattern/bwdpi.devdb.db。后续方向：追踪 NVRAM 变量设置和数据流到该函数。

---
### 无标题的发现

- **文件/目录路径：** `iQoS/R9000/TM/sample.bin`
- **位置：** `sample.bin:0x0000ce90 fcn.0000ce90`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'sample.bin' 中发现一个命令注入漏洞，允许攻击者通过命令行选项 '-a' 注入恶意命令并执行任意系统命令。漏洞位于函数 fcn.0000ce90，该函数使用 sprintf 构建命令字符串 '/TM/QoSControl set_priority %s %d'，其中 %s 直接来自用户输入（通过参数 s1 的偏移 0x18）。输入仅与固定字符串（'HIGHEST'、'HIGH'、'MEDIUM'）进行比较，但未对输入进行过滤或转义，导致如果输入包含特殊字符（如分号、反引号），可注入额外命令。攻击者作为已认证非 root 用户，可通过执行二进制文件并提供恶意 '-a' 参数触发漏洞，可能获得命令执行权限（取决于二进制文件权限）。
- **代码片段：**
  ```
  0x0000cee8      24109fe5       ldr r1, str._TM_QoSControl_set_priority__s__d ; [0xf0b0:4]=0x2f4d542f ; "/TM/QoSControl set_priority %s %d" ; const char *format
  0x0000ceec      0520a0e1       mov r2, r5
  0x0000cef0      04008de2       add r0, string              ; char *s
  0x0000cef4      8cefffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  0x0000cef8      04008de2       add r0, string              ; const char *string
  0x0000cefc      3cefffeb       bl sym.imp.system           ; int system(const char *string)
  ```
- **关键词：** 命令行参数：-a, 环境变量：无, NVRAM 变量：无, 文件路径：/TM/QoSControl, IPC 套接字：无, 自定义共享函数符号：fcn.0000ce90
- **备注：** 漏洞利用链完整：输入点（命令行选项 '-a'）→ 数据流（通过主函数 fcn.00008dc8 传递到 fcn.0000ce90）→ 危险操作（system 调用）。攻击者需有执行权限，且二进制文件可能以较高权限运行（如 setuid），增加风险。建议进一步验证二进制文件在目标环境中的权限和输入传递路径。

---
### CommandInjection-fcn.0000ce90

- **文件/目录路径：** `iQoS/R8900/tm_pattern/sample.bin`
- **位置：** `sample.bin:0xcefc (fcn.0000ce90)`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** The analysis of 'sample.bin' revealed a potential command injection vulnerability in the function fcn.0000ce90, which constructs a command string using sprintf and executes it via system. The function is called from fcn.0000d904, which handles user-provided actions via the '-a' option. The input string is not sanitized before being used in the command, allowing an attacker to inject arbitrary commands. The attack chain involves: 1) A non-root user providing a malicious action string with command injection payloads via the '-a' option. 2) The string being passed to fcn.0000ce90 without validation. 3) The sprintf function building a command that includes the user input. 4) The system function executing the malicious command. This could lead to remote code execution or privilege escalation if the injected commands are executed with sufficient privileges. The vulnerability is triggered when specific actions like 'set_app_patrol' are used, but further analysis is needed to confirm the exact trigger conditions.
- **代码片段：**
  ```
  0x0000cee8      24109fe5       ldr r1, str._TM_QoSControl_set_priority__s__d ; [0xf0b0:4]=0x2f4d542f ; "/TM/QoSControl set_priority %s %d" ; const char *format
  0x0000ceec      0520a0e1       mov r2, r5
  0x0000cef0      04008de2       add r0, string              ; char *s
  0x0000cef4      8cefffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  0x0000cef8      04008de2       add r0, string              ; const char *string
  0x0000cefc      3cefffeb       bl sym.imp.system           ; int system(const char *string)
  ```
- **关键词：** action, set_app_patrol, /TM/QoSControl set_priority
- **备注：** The vulnerability requires further validation to confirm the complete data flow from user input to the system call. The function fcn.0000ce90 is called from fcn.0000d904, which is associated with actions like 'set_app_patrol'. Additional analysis of the action handlers is recommended to identify all potential input points. The exploitability depends on the permissions of the 'sample.bin' process when executed by a non-root user.

---
### CommandInjection-wps-hostapd-update-uci

- **文件/目录路径：** `lib/wifi/wps-hostapd-update-uci`
- **位置：** `wps-hostapd-update-uci (script), approximate lines based on content: command substitution around 'qca_hostapd_config_file=/var/run/hostapd-`echo $IFNAME`.conf' and 'local parent=$(cat /sys/class/net/${IFNAME}/parent)'`
- **风险评分：** 7.0
- **置信度：** 9.0
- **描述：** The script handles WPS events and takes IFNAME and CMD as arguments. Multiple instances of command substitution using IFNAME without sanitization allow arbitrary command execution. For example, if IFNAME is set to a string like 'ath0; id; #', it injects and executes the 'id' command during the evaluation of backticks or $(). The script has world-executable permissions, so a non-root user with valid login credentials can directly run it with controlled inputs. Trigger conditions include invoking the script with malicious IFNAME values, leading to command execution under the user's context. Constraints: The exploit requires the user to have access to execute the script, which is permitted due to permissions. Potential attacks include running arbitrary commands to disclose information, manipulate files, or escalate privileges if combined with other vulnerabilities. The code logic involves unsafe usage of IFNAME in shell command evaluations.
- **代码片段：**
  ```
  Example vulnerable code snippets:
    - \`qca_hostapd_config_file=/var/run/hostapd-\\`echo $IFNAME\\`.conf\`
    - \`local parent=$(cat /sys/class/net/${IFNAME}/parent)\`
  These allow command injection if IFNAME contains shell metacharacters like semicolons.
  ```
- **关键词：** IFNAME, CMD, /var/run/hostapd-*, /sys/class/net/${IFNAME}/parent, hostapd_cli, uci, /bin/config
- **备注：** The script may be invoked by other processes (e.g., hostapd or hotplug events) with higher privileges, which could increase impact, but this requires further cross-context analysis. Recommend reviewing how the script is triggered in the system and sanitizing all inputs. Additional analysis of related files (e.g., those calling this script) could reveal broader attack surfaces.

---
### 无标题的发现

- **文件/目录路径：** `etc/init.d/powerctl`
- **位置：** `powerctl: approximately lines 40-46, in the start() function`
- **风险评分：** 5.0
- **置信度：** 6.0
- **描述：** The script uses `eval` on the `mode` variable without proper sanitization, which could lead to command injection if the `mode` value is controlled by an attacker. The `mode` is obtained from a configuration system using `config_get`, and if an attacker can set it to a malicious string (e.g., including shell metacharacters), it might execute arbitrary commands with root privileges (assuming the script runs as root). The `type` check might limit some injections, but it could be bypassed if the attacker can define a function or craft the input appropriately. Trigger condition: Attacker controls the `powerctl mode` configuration value. Potential attack: Command injection to escalate privileges or perform unauthorized actions.
- **代码片段：**
  ```
  start() {
  	config_load system
  	config_get mode powerctl mode "auto"
  
  	if eval "type ipq806x_power_${mode}" 2>/dev/null >/dev/null; then
  		eval ipq806x_power_${mode}
  	else
  		echo "\"${mode}\" power mode not supported"
  	fi
  }
  ```
- **关键词：** powerctl mode (NVRAM or UCI configuration variable)
- **备注：** The exploitability depends on whether a non-root user can modify the 'powerctl mode' configuration. Further analysis is needed to verify the configuration source (e.g., UCI, NVRAM) and access controls. If the configuration is writable by non-root users or through exposed services, this could be a viable attack chain. Recommend investigating how the configuration is set and if there are any IPC or network interfaces that allow mode modification.

---
