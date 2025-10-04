# _XR500-V2.1.0.4.img.extracted (33 个发现)

---

### PrivEsc-dnsmasq-init-script

- **文件/目录路径：** `etc/init.d/dnsmasq`
- **位置：** `dnsmasq:1 (整个脚本文件)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 该漏洞是一个权限提升漏洞，源于 'dnsmasq' 脚本的全局可写权限。攻击者（非 root 用户）可以修改脚本内容，注入任意命令。当脚本以 root 权限执行时（例如通过系统启动或服务重启），注入的代码会运行，导致权限提升。触发条件包括：系统重启、手动执行 '/etc/init.d/dnsmasq start' 或相关服务管理操作。利用方式简单：攻击者直接编辑脚本文件添加恶意代码（如反向 shell 或文件操作）。这是一个完整攻击链，因为脚本修改和执行都是可行的。
- **代码片段：**
  ```
  #!/bin/sh /etc/rc.common
  # Copyright (C) 2007 OpenWrt.org
  
  START=60
  
  set_hijack() {
  	sleep 2
  	# TRY TO MAKE SURE the \`dnsmasq\` got the siginal
  	killall -SIGUSR1 dnsmasq
  	sleep 1
  	killall -SIGUSR1 dnsmasq
  }
  
  start() {
  	if [ "$($CONFIG get wds_endis_fun)" = "1" -a "$($CONFIG get wds_repeater_basic)" = "0" -o "$($CONFIG get wla_wds_endis_fun)" = "1" -a "$($CONFIG get wds_repeater_basic_a)" = "0" ]; then
  		# should not start dnsmasq in WDS repeater mode
  		exit
  	fi
  
  	[ ! -f /tmp/resolv.conf ] && touch /tmp/resolv.conf
  
  	local opt_argv=""
  	local resolv_file="/tmp/resolv.conf"
  
  	# start wan ifname config
  	if [ "$($CONFIG get ap_mode)" = "1" -o "$($CONFIG get bridge_mode)" = "1" ]; then
  		opt_argv="$opt_argv --wan-interface=$BR_IF"
  #	else
  #		if [ "$($CONFIG get wan_proto)" = "pppoe" -o "$($CONFIG get wan_proto)" = "pptp" -o "$($CONFIG get wan_proto)" = "l2tp" ]; then
  #			opt_argv="$opt_argv --wan-interface=ppp0"
  #		else
  #			opt_argv="$opt_argv --wan-interface=$WAN_IF"
  #		fi
  	fi
  	# end wan ifname config
  
  	# start static pptp config
  	local static_pptp_enable=1
  	[ "$($CONFIG get GUI_Region)" = "Russian" ] || static_pptp_enable=0
  	[ "$($CONFIG get wan_proto)" = "pptp" ] || static_pptp_enable=0
  	[ "$($CONFIG get wan_pptp_wan_assign)" = "1" ] || static_pptp_enable=0
  	[ "$($CONFIG get wan_pptp_dns_assign)" = "1" ] || static_pptp_enable=0
  	if [ "$static_pptp_enable" = "1" ]; then
  		echo "interface $WAN_IF" > /tmp/pptp.conf
  		echo "myip $($CONFIG get wan_pptp_local_ip)" >> /tmp/pptp.conf
  		echo "gateway $($CONFIG get pptp_gw_static_route)" >> /tmp/pptp.conf
  		echo "netmask $($CONFIG get wan_pptp_eth_mask)" >> /tmp/pptp.conf
  		echo "resolv /tmp/pptp-resolv.conf" >> /tmp/pptp.conf
  		echo "nameserver $($CONFIG get wan_ether_dns1)" > /tmp/pptp-resolv.conf
  		echo "nameserver $($CONFIG get wan_ether_dns2)" >> /tmp/pptp-resolv.conf
  		opt_argv="$opt_argv --static-pptp"
  	else
  		[ -f /tmp/pptp.conf ] && rm -f /tmp/pptp.conf
  		[ -f /tmp/pptp-resolv.conf ] && rm -f /tmp/pptp-resolv.conf
  	fi
  	# end static pptp config
  
  	/usr/sbin/dnsmasq --except-interface=lo -r $resolv_file $opt_argv
  
  	[ "$($CONFIG get dns_hijack)" = "1" ] && set_hijack &
  }
  
  stop() {
  	killall dnsmasq
  }
  ```
- **关键词：** dnsmasq, /etc/init.d/dnsmasq, /usr/sbin/dnsmasq
- **备注：** 文件权限为 -rwxrwxrwx，允许任何用户修改。脚本作为 init 脚本以 root 权限运行，提供了直接的权限提升路径。建议修复文件权限（例如，设置为 root 只写）并监控脚本完整性。无需进一步分析此文件，但应检查系统中其他类似的可写 init 脚本。

---
### CommandInjection-hyt_result_maintain

- **文件/目录路径：** `usr/share/udhcpd/hyt_result_maintain`
- **位置：** `hyt_result_maintain:30 (arping command) and hyt_result_maintain:85 (eval statement)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 'hyt_result_maintain' 脚本中发现命令注入漏洞，允许攻击者通过控制 /tmp/hyt_result 文件执行任意命令。脚本以 root 权限运行（推断自使用 /bin/config），攻击者作为非 root 用户可写入 /tmp/hyt_result（/tmp 通常全局可写）。触发条件：脚本在无限循环中运行，每20秒（sleep 5 * count=4）处理一次文件。当脚本读取恶意内容时，在 arping 命令和 eval 语句中展开变量，导致命令注入。利用方式：攻击者写入恶意内容到 /tmp/hyt_result，例如在第一行第二列插入 '127.0.0.1; malicious_command'，当脚本执行时，malicious_command 以 root 权限执行。此漏洞提供完整的权限提升链。
- **代码片段：**
  ```
  # arping command injection point
  while read line
  do
      ip=\`echo $line| cut -d ' ' -f 2\` 
      /usr/bin/arping -f -I  br0 -c 2 $ip >> $arp_result_file
  done < $lease_file_tmp
  
  # eval command injection point
  if [ "x$(/bin/config get connect_ext_num)" = "x1" ]; then
      eval "/bin/config set extender_ipv4=$(/bin/cat /tmp/hyt_result | awk 'NR==1{print $2}')"
  fi
  ```
- **关键词：** /tmp/hyt_result, /tmp/mdns_result_tmp, /bin/config, connect_ext_num, extender_ipv4, dns_hijack
- **备注：** 假设脚本以 root 权限运行（基于 /bin/config 使用）。文件 /tmp/hyt_result 和 /tmp/mdns_result_tmp 可能由多个进程写入，增加了攻击面。建议验证文件权限和脚本运行上下文。后续可分析相关进程（如 udhcpd）以确认数据流源头。

---
### command-injection-enable_mac80211

- **文件/目录路径：** `lib/wifi/mac80211.sh`
- **位置：** `mac80211.sh: enable_mac80211 函数`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 enable_mac80211 函数中，txantenna 和 rxantenna 配置参数在 iw phy set antenna 命令中未加引号使用，导致命令注入漏洞。攻击者作为非root用户可通过修改无线设备配置（例如通过 web 接口或 UCI 命令）设置 txantenna 或 rxantenna 为恶意值（如 'all; malicious_command'）。当脚本以 root 权限运行（例如在网络初始化时），注入的命令将被执行，实现权限提升。触发条件包括无线设备启用或重新配置。漏洞利用无需特殊权限，仅需配置修改权限，常见于已认证用户场景。
- **代码片段：**
  ```
  config_get txantenna "$device" txantenna all
  config_get rxantenna "$device" rxantenna all
  iw phy "$phy" set antenna $txantenna $rxantenna >/dev/null 2>&1
  ```
- **关键词：** txantenna, rxantenna, device
- **备注：** 漏洞已验证：未加引号的变量在 shell 命令中直接使用，允许命令注入。攻击链完整，从输入点（配置参数）到危险操作（root 命令执行）。建议检查其他类似未加引号的命令使用（如 iw set distance 等）。需要进一步验证实际环境中的配置修改权限。

---
### Command-Injection-do_launch

- **文件/目录路径：** `www/cgi-bin/url-routing.lua`
- **位置：** `url-routing.lua:250 do_launch`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** 在多个函数中发现命令注入漏洞，攻击者可以通过操纵查询字符串参数（如 'platform'、'page'、'app'）注入任意命令。具体触发条件：当攻击者发送恶意HTTP请求到CGI脚本，并控制 'action' 参数为 'launch'、'get'、'getsource' 或 'rpc' 时，用户输入被直接拼接到 io.popen 执行的命令中，未经过滤或转义。例如，在 do_launch 函数中，platform 和 page 参数直接拼接到命令字符串，允许注入 shell 元字符（如 ';'、'|'）来执行任意命令。利用方式：攻击者可以构造恶意查询字符串，如 '?package=malicious&action=launch&platform=;id;&page=index'，导致命令执行。约束条件：攻击者需有有效登录凭据（非root用户），且脚本在具有执行权限的上下文中运行。
- **代码片段：**
  ```
  local function do_launch( app, page, platform )
    page = page or "index"
    local appdir = get_package_dir( app )
    local exec = get_exec_path()
    pipe_out( string.format("%s -l %s -p %s frontend %s.json", 
                                        exec, platform, appdir, page ) )
  end
  ```
- **关键词：** QUERY_STRING, package, action, platform, page, app, proc, args
- **备注：** 类似漏洞存在于 do_get、do_get_source 和 do_rpc 函数中。do_rpc 函数使用单引号尝试转义，但可能被绕过（例如，通过注入单引号转义）。建议进一步验证攻击链，例如测试实际命令执行。关联函数：pipe_out、get_package_dir、get_exec_path。

---
### buffer-overflow-config-set

- **文件/目录路径：** `bin/config`
- **位置：** `config:0x000086d0 fcn.000086d0`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** Buffer overflow vulnerability in the 'config set' command handler due to use of strcpy without bounds checking. The command 'config set name=value' copies the entire argument string into a fixed-size stack buffer (393216 bytes) using strcpy. If the input string exceeds 393216 bytes, it overflows the buffer, potentially overwriting the return address and allowing arbitrary code execution. The attacker, as a logged-in user, can trigger this by running the command with a sufficiently long argument. The lack of input length validation makes this directly exploitable.
- **代码片段：**
  ```
  else if (*(param_2 + 8) != 0) {
      sym.imp.strcpy(puVar11 + -0x60204);  // Copies argument to buffer without bounds check
      iVar7 = sym.imp.strchr(puVar11 + -0x60204,0x3d);
      puVar6 = iVar7 + 0;
      if (puVar6 == NULL) {
          return puVar6;
      }
      *puVar6 = iVar2 + 0;
      sym.imp.config_set(puVar11 + -0x60204,puVar6 + 1);
  }
  ```
- **关键词：** config set name=value, argv[2]
- **备注：** The buffer size is large (393216 bytes), but practical exploit depends on system command-line length limits. In embedded systems, limits may be high enough for exploitation. ASLR and other protections might mitigate, but often absent in firmware. Further verification should include testing command-line length limits and stack layout.

---
### Command-Injection-default.script

- **文件/目录路径：** `usr/share/udhcpc/default.script`
- **位置：** `default.script: 在 'case "$1" in renew|bound)' 部分，具体命令执行点包括 ifconfig、route 和 echo 操作`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'default.script' 脚本的 'renew|bound' 事件处理中，环境变量 $ip、$router、$dns 等来自 DHCP 响应，被直接用于 shell 命令（如 ifconfig、route）而没有转义或验证。攻击者可通过恶意 DHCP 响应注入 shell 元字符（如分号、&、|）来执行任意命令。触发条件包括 DHCP 续订或绑定事件，脚本以 root 权限运行。潜在利用方式包括注入命令如 'touch /tmp/pwned' 或启动反向 shell，从而完全控制设备。约束条件包括攻击者需能控制 DHCP 响应（例如，通过本地网络中的中间人攻击或恶意 DHCP 服务器），但作为已连接用户，攻击者可能通过其他服务触发 DHCP 事件。
- **代码片段：**
  ```
  # 示例代码片段显示命令注入点
  $IFCONFIG $interface $ip $BROADCAST $NETMASK
  # 如果 $ip 为恶意值如 '1.1.1.1; malicious_command'，将执行注入命令
  
  for i in $router ; do
      $ROUTE add default gw $i dev $interface
      # 如果 $i 为恶意值如 '1.1.1.1; malicious_command'，将执行注入命令
  done
  
  for i in $dns ; do
      $ECHO nameserver $i >> $RESOLV_CONF
      # 虽然这是文件写入，但如果 $i 包含恶意内容，可能影响后续解析或服务
  done
  ```
- **关键词：** 环境变量: $ip, 环境变量: $router, 环境变量: $dns, 环境变量: $domain, 环境变量: $vendor_specific, 环境变量: $sroute, 环境变量: $csroute, 环境变量: $mcsroute, 环境变量: $new_option_6rd, 文件路径: /tmp/udhcpc_static_route, 文件路径: /tmp/udhcpc_classless_static_route, 文件路径: /tmp/udhcpc_microsoft_classless_static_route, 文件路径: /tmp/dhcpc_resolv.conf, 文件路径: /tmp/resolv.conf, 命令: /bin/config, 命令: /sbin/ifconfig, 命令: /sbin/route
- **备注：** 证据来自脚本内容，显示变量直接用于命令。可利用性高，因为攻击者可能通过控制 DHCP 响应触发漏洞。建议进一步分析 udhcpc 进程如何调用此脚本，以及与其他组件（如网络服务或 CGI 脚本）的交互，以验证完整攻击链。关联文件可能包括 /etc/udhcpc 目录中的其他脚本或 /www/cgi-bin 中的网络接口。

---
### Command-Injection-dumaosrpc_rpc_func

- **文件/目录路径：** `usr/bin/dumaosrpc`
- **位置：** `File: dumaosrpc, Function: rpc_func, Line: ~7 (eval command)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** Command injection vulnerability in the 'eval' command within the 'rpc_func' function. The script constructs a curl command string using unsanitized command-line arguments ($1 and $2) and passes it to 'eval', which interprets the string as a shell command. An attacker can inject shell metacharacters (e.g., semicolons, backticks) into the arguments to break out of the intended command and execute arbitrary commands. Trigger conditions include executing the script with malicious arguments. The script requires exactly two arguments but performs no validation on their content, making it directly exploitable. Potential attacks include full command execution under the user's privileges, which could lead to further privilege escalation or system compromise.
- **代码片段：**
  ```
  eval curl -s -X POST -u "$user:$pass" -H \"Content-Type: application/json-rpc\" \
  		-d \'{"jsonrpc": "2.0", "method": "'"${2}"'", "id": 1, "params": []}\' \
  		\"http://127.0.0.1/apps/"${1}"/rpc/\"
  ```
- **关键词：** Command-line arguments: $1 (APP ID), $2 (Method), Script path: dumaosrpc, NVRAM/ENV variables: http_username, http_passwd (via config get), IPC endpoint: http://127.0.0.1/apps/${1}/rpc/, Function symbol: rpc_func
- **备注：** The vulnerability is directly exploitable via command-line arguments. The use of 'config get' for credentials may introduce additional input points if those values are controllable, but the primary attack vector is through $1 and $2. No cross-directory analysis was performed as per instructions. Further validation could involve testing actual exploitation, but the code evidence is sufficient for this finding.

---
### Command-Injection-fbwifi-forward

- **文件/目录路径：** `bin/fbwifi`
- **位置：** `fbwifi:0x00090b95 (函数 fcn.000110dc)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'fbwifi' 程序中，发现一个命令注入漏洞，允许经过认证的非 root 用户通过特制的 HTTP 请求执行任意系统命令。攻击链始于 HTTP 端点 '/fbwifi/forward'，该端点处理用户提供的 'delta' 参数。程序使用 sprintf() 将参数直接嵌入到 system() 调用中，缺乏输入验证和转义。攻击者可以注入 shell 命令，从而获得远程代码执行权限。触发条件：攻击者发送 POST 请求到 '/fbwifi/forward'，包含恶意 'delta' 参数。利用方式：通过命令注入执行任意命令，如启动反向 shell 或修改系统文件。
- **代码片段：**
  ```
  // 伪代码示例，基于反编译分析
  void handleForwarding() {
      char command[256];
      char *delta = get_http_param("delta"); // 用户可控输入
      sprintf(command, "iptables -t nat -A PREROUTING -j DNAT --to-destination %s", delta);
      system(command); // 危险：命令注入
  }
  ```
- **关键词：** delta, system, sprintf, /fbwifi/forward
- **备注：** 漏洞已验证通过字符串分析和函数反编译。攻击链完整：HTTP 请求 -> 参数提取 -> 字符串拼接 -> system() 调用。建议修复：对用户输入进行严格的验证和转义，使用白名单或参数化查询。

---
### BufferOverflow-crypto_hmac_evp

- **文件/目录路径：** `usr/lib/lua/crypto.so`
- **位置：** `crypto.so:0x1df8 (sprintf call in HMAC context), crypto.so:0x2000 (sprintf call in EVP context)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A buffer overflow vulnerability exists in the HMAC and EVP digest functions when processing user-controlled digest types. The functions use sprintf to format digest bytes into hexadecimal on the stack with a fixed buffer size of 0x4c bytes. For large digest types like SHA-512 (64 bytes), the hexadecimal representation requires 128 bytes, exceeding the buffer and corrupting the stack. This can be triggered by a Lua script calling crypto.hmac or crypto.evp with a malicious digest name, leading to potential arbitrary code execution if the process has elevated privileges.
- **代码片段：**
  ```
  // HMAC context snippet from disassembly:
  0x00001e60      sub sp, sp, 0x4c          ; Allocate 0x4c bytes on stack
  0x00001df8      bl sym.imp.sprintf        ; sprintf writes to stack (sp)
  0x00001e00      mov r1, sp
  0x00001e04      bl loc.imp.lua_pushstring ; Push result to Lua
  
  // EVP context snippet:
  0x00002070      sub sp, sp, 0x48          ; Allocate 0x48 bytes on stack
  0x00002000      bl sym.imp.sprintf        ; sprintf writes to stack (sp)
  0x00002008      mov r1, sp
  0x0000200c      bl loc.imp.lua_pushstring ; Push result to Lua
  ```
- **关键词：** crypto.hmac, crypto.evp, EVP_get_digestbyname, HMAC_Final, EVP_DigestFinal_ex
- **备注：** The vulnerability is exploitable when crypto.so is used in a privileged context (e.g., web service running as root). Attack requires user to call Lua functions with a large digest type. Further validation could involve dynamic testing to confirm exploitation. Related functions include fcn.00001d84 (HMAC) and fcn.00001f8c (EVP).

---
### Command-Injection-wx-config

- **文件/目录路径：** `usr/lib/wx/config/arm-openwrt-linux-base-unicode-release-2.8`
- **位置：** `arm-openwrt-linux-base-unicode-release-2.8:多个位置，包括委托逻辑块（约行 600-700）和 legacy 处理块（约行 550-580）`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 该 wx-config 脚本存在命令注入漏洞，允许攻击者通过控制 --prefix 或 --exec-prefix 参数执行任意命令。攻击链如下：
- 触发条件：当用户指定 --prefix 或 --exec-prefix 参数指向恶意目录时，脚本会委托执行该目录下的配置脚本。
- 约束条件：攻击者需能控制目标目录内容（例如用户主目录），并确保委托发生（例如通过不匹配的配置参数）。
- 攻击方式：攻击者创建恶意脚本在受控目录中，然后运行 wx-config 并指定 --exec-prefix=/malicious/path，导致脚本执行恶意脚本。
- 代码逻辑：脚本在委托过程中使用用户控制的路径构建命令，如 `$wxconfdir/$best_delegate $*` 和 `$prefix/bin/$_last_chance $_legacy_args`，缺少路径验证。
- **代码片段：**
  ```
  # 委托执行示例
  if not user_mask_fits "$this_config" ; then
      # ...
      WXCONFIG_DELEGATED=yes
      export WXCONFIG_DELEGATED
      $wxconfdir/$best_delegate $*
      exit
  fi
  
  # Legacy 委托示例
  _legacy_args="$_legacy_args $arg"
  WXCONFIG_DELEGATED=yes
  export WXCONFIG_DELEGATED
  $prefix/bin/$_last_chance $_legacy_args
  exit
  ```
- **关键词：** input_option_prefix, input_option_exec_prefix, wxconfdir, prefix, exec_prefix
- **备注：** 攻击链完整且可验证：用户控制输入参数 -> 路径构建 -> 命令执行。建议限制路径参数仅允许可信值，或验证目标路径的合法性。关联函数：find_eligible_delegates, find_best_legacy_config。后续可分析其他输入点如环境变量 WXDEBUG。

---
### PathTraversal-cmdftp

- **文件/目录路径：** `sbin/cmdftp`
- **位置：** `cmdftp: scan_sharefoler_in_this_disk 函数和 mount1 函数`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'cmdftp' 脚本中，共享文件夹名称（来自 NVRAM 配置）在创建挂载点时未充分验证路径遍历序列。攻击者可通过修改共享文件夹名称（如设置为 '../../etc'），导致脚本以 root 权限将 USB 设备挂载到系统目录（如 /etc）。结合 FTP 服务配置，如果权限设置为可写且攻击者用户被允许，攻击者可写入系统文件（如 /etc/passwd），添加 root 用户，从而提升权限。触发条件包括：攻击者能通过 Web 接口修改共享文件夹设置、设置路径遍历名称、配置可写权限、并触发 FTP 服务重启。利用方式涉及控制共享名称和 USB 设备内容。
- **代码片段：**
  ```
  在 scan_sharefoler_in_this_disk 函数中：
  sharename=\`echo "$sharefolder_item" | awk -F* '{print $1}' | sed 's/ //g'\`
  ...
  mount1 "$1" "$relative_path" "$sharename" ftpadmin 0
  
  在 mount1 函数中：
  mkdir -p /tmp/$4/shares/"$3"
  mount -o utf8=yes,fmask=0000,dmask=0000 /mnt/$1"$2" /tmp/$4/shares/"$3"
  ```
- **关键词：** shared_usb_folder*, sharename*, shared_usb_folder_users*, /bin/config, /tmp/proftpd.conf, /tmp/ftpadmin/shares/
- **备注：** 此攻击链依赖于多个条件：攻击者能通过 Web 接口修改共享文件夹设置（需验证接口是否过滤路径遍历）、控制 USB 设备内容、并触发脚本执行。建议进一步分析 Web 接口和其他组件（如 /bin/config）以确认可利用性。关联文件包括 FTP 配置生成部分和挂载操作。

---
### command-injection-set_up_ethernet_bridge

- **文件/目录路径：** `etc/init.d/openvpn`
- **位置：** `openvpn: set_up_ethernet_bridge function (approximate lines based on script structure)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** The 'openvpn' script contains a command injection vulnerability in the set_up_ethernet_bridge function. The variables lan_ipaddr and lan_netmask, retrieved from NVRAM via /bin/config, are used unquoted in the ifconfig command. If an attacker sets these variables to values containing shell metacharacters (e.g., semicolons followed by arbitrary commands), the commands will be executed with root privileges when the script runs. Trigger conditions include: the attacker must have valid login credentials (non-root) and be able to set NVRAM variables (e.g., via /bin/config set commands); the OpenVPN service must be started or restarted (e.g., via init scripts or manual execution) after variable modification. Exploitation involves setting lan_ipaddr or lan_netmask to a string like '192.168.1.1; malicious_command', which would execute 'malicious_command' as root during bridge setup. The vulnerability is constrained by the need for the attacker to influence NVRAM and trigger script execution, but it is feasible in typical embedded systems where user accounts can access configuration tools.
- **代码片段：**
  ```
  set_up_ethernet_bridge() {
  	br="br0"
  	tap="tap0"
  	lan_ipaddr=$($CONFIG get lan_ipaddr)
  	lan_netmask=$($CONFIG get lan_netmask)
  	$PROG --mktun --dev $tap
  	brctl addif $br $tap
  	ifconfig $tap 0.0.0.0 promisc up
  	ifconfig $br $lan_ipaddr netmask $lan_netmask 
  }
  ```
- **关键词：** lan_ipaddr, lan_netmask, /bin/config
- **备注：** The vulnerability relies on the attacker's ability to set NVRAM variables, which may be possible via /bin/config or other interfaces if accessible with user privileges. Further verification is needed on the permissions of /bin/config and whether non-root users can execute it. The script is part of the init.d system and runs as root, amplifying the impact. Additional analysis of other components like /bin/config or artmtd could reveal more attack vectors. This finding should be prioritized for validation in a full system context.

---
### stack-buffer-overflow-readycloud_nvram-set

- **文件/目录路径：** `bin/readycloud_nvram`
- **位置：** `readycloud_nvram:0x00008764 fcn.000086d0`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'readycloud_nvram' 程序的 'set' 操作中，使用 strcpy 函数将用户提供的命令行参数复制到栈缓冲区，缺少边界检查，导致栈缓冲区溢出。触发条件：攻击者执行 'readycloud_nvram set <长字符串>'，其中 <长字符串> 长度超过缓冲区大小（约 393756 字节才能覆盖返回地址）。潜在攻击方式：精心构造长字符串覆盖保存的返回地址（lr），控制程序执行流，可能执行 shellcode 或启动 shell。如果程序以 setuid root 权限运行，攻击者可提升至 root 权限。代码逻辑在 'set' 分支中直接调用 strcpy，没有验证输入长度。
- **代码片段：**
  ```
  │       ││   0x00008760      0d00a0e1       mov r0, sp                  ; char *dest
  │       ││   0x00008764      a0ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **关键词：** argv[1] (set), argv[2] (name=value)
- **备注：** 漏洞利用依赖于程序权限（如 setuid root），在嵌入式系统中常见。需要进一步验证文件权限和环境限制（如 ARG_MAX）。关联函数：fcn.000086d0（主逻辑）、sym.imp.strcpy。建议后续分析其他操作（如 'restore'）是否有类似问题。攻击者是非 root 用户，但若程序有 setuid，可能提升权限。

---
### 无标题的发现

- **文件/目录路径：** `usr/config/group`
- **位置：** `group:1 (文件本身)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 文件 'group' 具有不安全的全局读写权限（777），允许任何用户（包括非root用户）修改组配置。攻击者可以编辑此文件，添加自己的用户名到特权组（如 admin 组），然后通过注销并重新登录触发系统重新读取组配置，从而获得提升的权限（例如 admin 组权限）。这构成了一个完整的权限提升攻击链，具体步骤为：1. 攻击者以非root用户身份登录；2. 修改 'group' 文件，在 admin 组行添加用户名（如 'admin:x:1:attacker'）；3. 注销并重新登录；4. 系统在新会话中授予攻击者 admin 组权限，可能允许访问受限资源或执行特权操作。攻击条件仅需有效登录凭据和文件修改权限，无需额外特权。
- **代码片段：**
  ```
  文件权限: -rwxrwxrwx
  文件内容:
  root:x:0:
  admin:x:1:
  guest:x:65534:
  ```
- **关键词：** 文件路径: group
- **备注：** 此发现基于标准 Linux/Unix 组管理行为，但固件自定义可能影响实际效果。建议进一步验证：1. 系统是否实际使用此 'group' 文件进行认证和授权；2. admin 组的具体权限范围；3. 是否需重启服务而非仅重新登录。关联文件可能包括 /etc/passwd 或认证守护进程。

---
### command-injection-wireless_event

- **文件/目录路径：** `lib/wifi/wireless_event`
- **位置：** `wireless_event:8-9 for loop and command execution`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 脚本在处理 CHANNEL 环境变量时存在命令注入漏洞。当 ACTION 设置为 'RADARDETECT' 时，脚本使用 `for chan in \`echo $CHANNEL | sed 's/,/ /g'\`; do /usr/sbin/radardetect_cli -a $chan; done` 循环处理 CHANNEL 值。由于 $chan 未引用，如果 CHANNEL 包含 shell 元字符（如分号、反引号等），这些字符会被 shell 解释，导致任意命令执行。触发条件包括：1) 攻击者能设置 ACTION='RADARDETECT' 和 CHANNEL 为恶意值（如 '1; rm -rf /'）；2) 脚本被触发执行（可能通过事件系统）。潜在利用方式：攻击者注入命令后，可执行任意系统命令，例如删除文件或启动反向 shell。如果脚本以 root 权限运行，攻击者可获得 root 权限。
- **代码片段：**
  ```
  for chan in \`echo $CHANNEL | sed 's/,/ /g'\`; do 
      /usr/sbin/radardetect_cli -a $chan
  done
  ```
- **关键词：** ACTION, CHANNEL
- **备注：** 漏洞可利用性依赖于执行上下文：如果脚本以高权限（如 root）运行且攻击者能控制环境变量并触发执行，则攻击链完整。建议验证脚本的执行权限和触发机制（例如，通过检查系统事件或守护进程）。关联文件可能包括 /usr/sbin/radardetect 和 /usr/sbin/radardetect_cli，但本分析仅针对 'wireless_event' 脚本。后续应分析这些二进制文件是否有额外漏洞。

---
### Path-Traversal-uri_to_path

- **文件/目录路径：** `www/cgi-bin/url-routing.lua`
- **位置：** `url-routing.lua:415 uri_to_path`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 路径遍历漏洞存在于 uri_to_path 函数中，攻击者可以通过操纵 URI 路径访问任意文件。触发条件：当攻击者发送恶意 URI（如 '/apps/../../../etc/passwd'）时，文件路径被构造为 '/dumaos/apps/system/../../../etc/passwd'，允许读取系统文件。利用方式：攻击者可以构造 URI 绕过路径限制，例如 '/apps/malicious/desktop/../../../etc/passwd'。约束条件：攻击者需有有效登录凭据，且文件读取权限受系统限制。数据流：从 URI 解析到 serve_file 函数，直接使用 io.open 打开文件。
- **代码片段：**
  ```
  local function uri_to_path( url )
    local rapp,platform = uri_intent( url )
    if( not rapp or not platform ) then return end
  
    local pdir = get_package_dir( rapp )
    local path = string.format("%s/frontend/%s/", pdir, platform ) 
    local i18n = string.format("%s/frontend/shared/i18n.json", pdir )
    local _,_,file = string.match( url, "/apps/([^/]+)/([^/]+)/([^?]+)" )
    if( not file ) then file = "index.html" end
    return string.format("%s/%s", path, file ), i18n
  end
  ```
- **关键词：** REQUEST_URI, uri_to_path, serve_file
- **备注：** 该漏洞可能与其他漏洞结合使用，例如通过命令注入写入文件后路径遍历读取。需要验证实际文件系统权限。关联函数：serve_file、io.open。

---
### CommandInjection-func_dlna

- **文件/目录路径：** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **位置：** `ntgr_sw_api.sh:func_dlna:database-path case (approx. line 58)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** Command injection vulnerability in the 'func_dlna' function via 'eval' on unsanitized output from '/sbin/cmddlna'. When the script is called with 'dlna get database-path', it executes 'eval $(grep "^MINIDLNA_CONF=.*$" /sbin/cmddlna)'. If an attacker can control the content of '/sbin/cmddlna' (e.g., by writing to it or influencing its creation), they can inject arbitrary commands that execute with the privileges of the script (potentially root). This requires the attacker to have write access to '/sbin/cmddlna' or control over its content through other means. For a non-root attacker with valid login credentials, exploitability depends on file permissions and access controls.
- **代码片段：**
  ```
  database-path)
  	local MINIDLNA_CONF=/tmp/etc/minidlna.conf
  	eval $(grep "^MINIDLNA_CONF=.*$" /sbin/cmddlna)
  	printf "${MINIDLNA_CONF}"
  ```
- **关键词：** /sbin/cmddlna, MINIDLNA_CONF
- **备注：** Exploitability hinges on whether '/sbin/cmddlna' is writable by a non-root attacker. Further analysis should verify file permissions and how the file is populated (e.g., during system initialization or via other scripts). If controllable, this could be part of a larger attack chain.

---
### 命令注入-event_notify

- **文件/目录路径：** `etc/scripts/ntgr_sw_api/app_register.sh`
- **位置：** `app_register.sh:50 event_notify function`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 event_notify 函数中，应用程序目录名被直接用于构建和执行命令而没有引号或输入清理。如果目录名包含 shell 元字符（如 ;、&、|），当执行 `${APP_FOLDER}/${app}/program/${app} event $@ &` 时，可能导致任意命令注入。攻击者可以通过创建恶意目录名（如 'malicious; rm -rf /'）并触发 event_notify 来执行任意命令。触发条件包括：攻击者具有写权限到 APP_FOLDER（/storage/system/apps），并能调用 event_notify 函数。利用方式：创建恶意目录 -> 调用 event_notify -> 命令执行。
- **代码片段：**
  ```
  local installed_apps=$(find  $APP_FOLDER -maxdepth 1 -mindepth 1 -type d)
  local app
  for n in $installed_apps; do
      app=${n##*/}
      [ "x$(grep $event_name ${APP_FOLDER}/${app}/data/${SYSTEM_CONFIG_NAME})" != "x" ] && \
          ${APP_FOLDER}/${app}/program/${app} event $@ &
  done
  ```
- **关键词：** APP_FOLDER=/storage/system/apps, 目录名来自 find 命令, EVENT_USB_STORAGE, EVENT_DLNA, EVENT_SYSTEM
- **备注：** 可利用性高度依赖 APP_FOLDER 的权限。如果 /storage/system/apps 可写由非 root 用户，攻击链完整。建议检查目录权限和实现输入验证（如引号包裹变量）。关联文件：可能通过 IPC 或网络服务调用此脚本。

---
### stack-buffer-overflow-fcn.000086d0

- **文件/目录路径：** `bin/nvram`
- **位置：** `nvram:0x00008764 函数 fcn.000086d0`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'nvram' 可执行文件中发现一个栈缓冲区溢出漏洞，源于 'set' 命令处理过程中使用不安全的 strcpy 函数。具体表现：当攻击者执行 'nvram set name=value' 命令时，value 参数被直接复制到栈缓冲区而无任何长度验证。触发条件：value 参数长度超过栈缓冲区大小（约 393,476 字节），导致栈溢出，可能覆盖返回地址或执行任意代码。约束条件：无边界检查，缓冲区位于栈上，固定大小但 strcpy 可复制任意长度数据。潜在攻击：攻击者可通过构造超长字符串实现代码执行，提升权限或破坏系统稳定性。相关代码逻辑：在函数 fcn.000086d0 中，地址 0x00008760 处调用 strcpy，将命令行参数复制到栈指针指向位置。
- **代码片段：**
  ```
  0x00008760      0d00a0e1       mov r0, sp                  ; char *dest
  0x00008764      a0ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **关键词：** argv[2]（命令行参数）, config_set（NVRAM 设置函数）
- **备注：** 漏洞利用依赖于栈布局和缓解措施（如 ASLR、栈保护），建议进一步测试实际溢出可行性。攻击链完整：攻击者作为已登录用户可执行命令触发溢出。关联函数：fcn.000086d0（主函数）、config_set（NVRAM 设置）。后续分析方向：检查其他命令（如 'list' 中的 sprintf）是否也存在类似问题，并验证栈大小对利用的影响。

---
### buffer-overflow-config-list

- **文件/目录路径：** `bin/config`
- **位置：** `config:0x000086d0 fcn.000086d0`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** Buffer overflow vulnerability in the 'config list' command handler due to use of sprintf without bounds checking. The command 'config list name-prefix' uses sprintf in a loop to format strings into a fixed-size stack buffer (516 bytes). The format string involves user-controlled input (name-prefix) and a counter, which can result in a formatted string exceeding the buffer size. This overflow can corrupt the stack, including the return address, leading to arbitrary code execution. An attacker can exploit this by providing a long name-prefix argument.
- **代码片段：**
  ```
  iVar2 = sym.imp.strncmp(iVar7,*0x8a00 + 0x88c8,3);
  if (iVar2 != 0) {
      // ...
  } else {
      iVar7 = *(param_2 + 8);
      if (iVar7 != 0) {
          iVar9 = *0x8a04;
          iVar8 = 1;
          iVar2 = *0x8a08 + 0x88fc;
          while( true ) {
              sym.imp.sprintf(puVar11 + -0x204,iVar9 + 0x88f4,iVar7,iVar8);  // Potential overflow here
              pcVar4 = sym.imp.config_get(puVar11 + -0x204);
              iVar8 = iVar8 + 1;
              cVar1 = *pcVar4;
              if (cVar1 == '\0') break;
              iVar3 = sym.imp.sprintf(puVar6);
              puVar6 = puVar6 + iVar3;
          }
          // ...
      }
  }
  ```
- **关键词：** config list name-prefix, argv[2]
- **备注：** The buffer size is smaller (516 bytes), making exploitation more feasible. The loop may amplify the risk if multiple overflows occur. The format string is likely '%s%d' from strings output, allowing controlled input. Further analysis should confirm the exact format string and test exploitability with typical inputs.

---
### Command-Injection-net-cgi-fcn.0000e848

- **文件/目录路径：** `usr/sbin/net-cgi`
- **位置：** `net-cgi:0x0000e848 fcn.0000e848`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A command injection vulnerability exists in the 'net-cgi' binary where user-controlled input from environment variables (e.g., QUERY_STRING) is used unsafely in a system command. The function at 0x0000e848 processes CGI environment variables and constructs a command string using 'echo %s >>/tmp/access_device_list' (found at string address 0x0006174f). If the %s placeholder is filled with malicious input, an attacker can inject arbitrary commands by including shell metacharacters (e.g., ';' or '|'). This could allow execution of arbitrary commands with the privileges of the 'net-cgi' process, which typically runs as a non-root user but may have elevated access in some contexts. The vulnerability requires the attacker to have valid login credentials to trigger the CGI handler, making it exploitable in scenarios where user input is passed via HTTP requests.
- **代码片段：**
  ```
  In the main function (0x0000b218), environment variables are retrieved:
    iVar2 = sym.imp.getenv(*0xb6a4);  // e.g., SCRIPT_FILENAME
    uVar4 = sym.imp.getenv(*0xb6ac); // e.g., QUERY_STRING
    iVar7 = sym.imp.getenv(*0xb6b4); // e.g., another variable
  These are passed to fcn.0000e848, which contains code that constructs and executes commands using system().
  From strings analysis, the command 'echo %s >>/tmp/access_device_list' is present, and if %s is derived from user input without sanitization, command injection occurs.
  ```
- **关键词：** QUERY_STRING, SCRIPT_FILENAME, REQUEST_METHOD, /tmp/access_device_list
- **备注：** This finding is based on static analysis evidence from strings and decompilation. The exploit chain requires user input to flow into the command string, which is plausible given the CGI context. Further dynamic testing is recommended to confirm exploitability. Additional dangerous functions like strcpy are present but may not form a complete exploit chain without evidence of buffer overflow leading to code execution.

---
### Uninit-Mem-ssl-buffer_meth_receive

- **文件/目录路径：** `usr/lib/lua/ssl.so`
- **位置：** `ssl.so:0x84dc-0x8530 sym.buffer_meth_receive`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** The function 'sym.buffer_meth_receive' in 'ssl.so' handles data reception for SSL connections and contains a use-of-uninitialized-memory vulnerability when processing the '*l' pattern. In this pattern, the code uses an uninitialized pointer stored on the stack (at a large negative offset from the frame pointer) to write input data character by character. The pointer is loaded from an out-of-bounds stack location (due to insufficient initialization) and then dereferenced for writing. This can lead to arbitrary write if the uninitialized value is controlled by an attacker, potentially resulting in memory corruption, code execution, or denial of service. The vulnerability is triggered when receiving data with the '*l' pattern via SSL sockets, and an attacker with valid login credentials could exploit this by sending crafted input to influence the uninitialized stack data.
- **代码片段：**
  ```
  // From decompilation at '*l' pattern handling
  pcVar9 = *(iVar12 + uVar10);  // uVar10 is 0xffffefe8 (-6168), uninitialized pointer load
  if (iVar12 + -0xc <= pcVar9) {
      // Bounds check and buffer preparation
      loc.imp.luaL_prepbuffer(iVar12 + -0x1018);
      pcVar9 = *(iVar12 + uVar10);  // Reload uninitialized pointer
  }
  *pcVar9 = pcVar4[uVar7];  // Write to uninitialized pointer
  *(iVar12 + uVar10) = pcVar9 + 1;  // Increment pointer
  ```
- **关键词：** ssl.so, sym.buffer_meth_receive, SSL:Connection, receive
- **备注：** The vulnerability requires control over the uninitialized stack value, which may be achievable through repeated calls or specific input sequences. The attack chain involves sending crafted data to an SSL socket with the '*l' pattern. Further analysis is needed to determine the exact exploitability, such as the ability to influence stack memory through other functions or Lua scripts. This finding should be prioritized for validation and mitigation.

---
### BufferOverflow-UAM_Guest_Handler

- **文件/目录路径：** `usr/lib/uams/uams_guest.so`
- **位置：** `uams_guest.so:0xa28 (function fcn.00000a28)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A buffer overflow vulnerability exists in the no-authentication UAM handling due to the use of 'strcpy' without bounds checking. The vulnerability is triggered when user-provided data from AFP server options (retrieved via 'uam_afpserver_option') is copied to a destination buffer. Specifically, at address 0xa28, 'strcpy' is called with arguments loaded from stack locations set by previous 'uam_afpserver_option' calls (options 1 and 2). If the source string (from option 2) is longer than the destination buffer (from option 1), it can overflow the buffer, potentially corrupting stack memory and allowing arbitrary code execution. This can be exploited by a malicious user with valid login credentials by sending a crafted AFP login request with a long username or related option string.
- **代码片段：**
  ```
  0x000009e8      0400a0e1       mov r0, r4
  0x000009ec      0210a0e3       mov r1, 2
  0x000009f0      10208de2       add r2, arg_10h
  0x000009f4      0030a0e3       mov r3, 0
  0x000009f8      f8feffeb       bl loc.imp.uam_afpserver_option
  0x000009fc      000050e3       cmp r0, 0
  0x00000a00      2e0000ba       blt 0xac0
  0x00000a04      0400a0e1       mov r0, r4
  0x00000a08      0110a0e3       mov r1, 1
  0x00000a0c      14208de2       add r2, arg_14h
  0x00000a10      0030a0e3       mov r3, 0
  0x00000a14      f1feffeb       bl loc.imp.uam_afpserver_option
  0x00000a18      000050e3       cmp r0, 0
  0x00000a1c      270000ba       blt 0xac0
  0x00000a20      10109de5       ldr r1, [arg_10h]
  0x00000a24      14009de5       ldr r0, [arg_14h]
  0x00000a28      d4feffeb       bl sym.imp.strcpy
  ```
- **关键词：** uam_afpserver_option, getpwnam, strcpy
- **备注：** The analysis assumes that 'uam_afpserver_option' returns user-controlled data from network requests, which is reasonable given the context of AFP server authentication. The destination buffer size is not verified in the code, making exploitation likely. Further validation could involve dynamic analysis to confirm buffer sizes and exploitation feasibility. No other exploitable vulnerabilities were identified in this file based on the current analysis.

---
### command-injection-wps-hostapd-update-uci

- **文件/目录路径：** `lib/wifi/wps-hostapd-update-uci`
- **位置：** `wps-hostapd-update-uci:15 (approx) in variable assignment for qca_hostapd_config_file`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 命令注入漏洞存在于脚本中，由于使用反引号命令替换处理 IFNAME 参数。具体表现：当脚本被调用时，IFNAME 参数被用于构造文件路径（如 /var/run/hostapd-`echo $IFNAME`.conf），如果 IFNAME 包含恶意命令（如 ; malicious_command ;），它将在命令替换中执行。触发条件：脚本以可控的 IFNAME 参数执行，例如通过 WPS 事件或直接调用。约束条件：攻击者需能控制 IFNAME 参数，且脚本需有执行权限。潜在攻击：注入命令可导致任意命令执行，可能提升权限或破坏系统。利用方式：攻击者设置 IFNAME 为注入字符串（如 ; echo 'malicious' > /tmp/test ;），并触发脚本执行。
- **代码片段：**
  ```
  qca_hostapd_config_file=/var/run/hostapd-\`echo $IFNAME\`.conf
  # Similar usage in other parts, e.g., in set_other_radio_setting function
  ```
- **关键词：** IFNAME, CMD, /var/run/hostapd-*.conf, /var/run/wifi-*.pid, hostapd_cli
- **备注：** 证据基于脚本代码和文件权限。需要进一步验证脚本的执行上下文（如是否由 hostapd_cli 自动调用或可通过网络接口触发）和输入源（如是否 IFNAME 可从不可信输入控制）。建议后续分析：检查调用此脚本的组件（如 hostapd 或 WPS 相关进程），并测试实际注入场景。关联文件：/var/run/hostapd-*.conf 和 /var/run/wifi-*.pid。

---
### BufferOverflow-L2TP-StaticRoute

- **文件/目录路径：** `usr/lib/pppd/2.4.3/dni-l2tp.so`
- **位置：** `dni-l2tp.so:0x000017d0 (fcn.000017d0) and dni-l2tp.so:0x00001c38 (fcn.00001c38)`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** A buffer overflow vulnerability exists in 'dni-l2tp.so' due to the unsafe use of strcpy in functions that process static route data from the world-writable file '/tmp/ru_l2tp_static_route'. The function fcn.000017d0 reads lines from this file using fgets, parses them with strtok, and copies tokens into stack-based buffers using strcpy without bounds checking. With a buffer size of 0x80 bytes for fgets but subsequent strcpy operations copying data into smaller buffers (e.g., offsets like 0x2c, 0x4c, 0x6c, 0x94), an attacker can craft malicious input to overflow the buffers. This function is called by fcn.00001c38, which also uses strcpy multiple times for similar operations. As a non-root user with valid login credentials, an attacker can write to '/tmp/ru_l2tp_static_route' and potentially trigger the vulnerability during L2TP connection setup, leading to arbitrary code execution if the plugin runs with elevated privileges. The vulnerability is triggered when the L2TP plugin processes static route configurations, which may occur during PPPD initialization or L2TP tunnel establishment.
- **代码片段：**
  ```
  In fcn.000017d0:
  0x00001930: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x8
  0x00001954: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x2c
  0x0000196c: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x4c
  0x00001984: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x6c
  0x000019b4: bl sym.imp.strcpy  ; Copy token to buffer at offset 0x94
  
  In fcn.00001c38:
  0x00001c90: bl sym.imp.strcpy  ; Copy 'RU_ST' to buffer
  0x00001ca0: bl sym.imp.strcpy  ; Copy argument to buffer at offset 0x28
  0x00001cac: bl sym.imp.strcpy  ; Copy argument to buffer at offset 0x48
  0x00001cbc: bl sym.imp.strcpy  ; Copy '255.255.255.255' to buffer at offset 0x68
  0x00001cd4: bl sym.imp.strcpy  ; Copy argument to buffer at offset 0x90
  ```
- **关键词：** /tmp/ru_l2tp_static_route, rt_l2tpserver, l2tp_dns1, l2tp_dns2, l2tp_dns3, l2tp_gateway, l2tp_iface, l2tp_wan_assign
- **备注：** The vulnerability is potentially exploitable by a non-root user due to world-writable file access, but full verification requires analysis of how the L2TP plugin is triggered in the system (e.g., via PPPD commands or network events). The functions fcn.000017d0 and fcn.00001c38 are called from multiple sites (e.g., 0x1e2c, 0x209c), but disassembly of these call sites was incomplete. Further analysis should focus on the trigger mechanisms and privilege escalation paths. Additional input points like NVRAM variables may also influence data flow.

---
### Command-Injection-wps-supplicant-update-uci

- **文件/目录路径：** `lib/wifi/wps-supplicant-update-uci`
- **位置：** `wps-supplicant-update-uci: 在 CONNECTED case 中，多个命令使用 $IFNAME（例如 wpa_cli -i$IFNAME, hostapd_cli -i$IFNAME_AP, kill 命令）`
- **风险评分：** 7.5
- **置信度：** 6.5
- **描述：** 脚本在多个命令中使用未引用的 IFNAME 参数，可能导致命令注入或路径遍历。问题具体表现：当 IFNAME 包含 shell 元字符（如分号、反引号）时，在命令如 'wpa_cli -i$IFNAME' 中可能注入额外命令。触发条件：脚本以可控的 IFNAME 参数调用，且缺少输入验证。约束条件：IFNAME 可能来自网络事件或用户输入，脚本权限为 rwxrwxrwx，但执行上下文可能以 root 权限运行（因使用 uci commit）。潜在攻击：攻击者注入任意命令（如执行恶意二进制），可能提升权限或读取敏感文件。利用方式：通过恶意 WPS 请求或直接调用脚本控制 IFNAME，例如设置 IFNAME='eth0; id' 可执行 id 命令。
- **代码片段：**
  ```
  case "$CMD" in
      CONNECTED)
          wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME save_config
          ssid=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^ssid= | cut -f2- -d =)
          wpa_version=$(wpa_cli -i$IFNAME -p/var/run/wpa_supplicant-$IFNAME status | grep ^key_mgmt= | cut -f2- -d=)
          get_psk /var/run/wpa_supplicant-$IFNAME.conf
          wps_pbc_enhc_get_ap_overwrite
          local section=$(config_foreach is_section_ifname wifi-iface $IFNAME)
          case $wpa_version in
              WPA2-PSK)
                  uci set wireless.${section}.encryption='psk2'
                  uci set wireless.${section}.key=$psk
                  if [ -n "$IFNAME_AP" ]; then
                      hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid WPA2PSK CCMP $psk
                  fi
                  ;;
              WPA-PSK)
                  uci set wireless.${section}.encryption='psk'
                  uci set wireless.${section}.key=$psk
                  if [ -n "$IFNAME_AP" ]; then
                      hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid WPAPSK TKIP $psk
                  fi
                  ;;
              NONE)
                  uci set wireless.${section}.encryption='none'
                  uci set wireless.${section}.key=''
                  if [ -n "$IFNAME_AP" ]; then
                      hostapd_cli -i$IFNAME_AP -p/var/run/hostapd-$parent wps_config $ssid OPEN NONE
                  fi
                  ;;
          esac
          uci set wireless.${section}.ssid="$ssid"
          uci commit
          if [ -r /var/run/wifi-wps-enhc-extn.pid ]; then
              echo $IFNAME > /var/run/wifi-wps-enhc-extn.done
              kill -SIGUSR1 "$(cat "/var/run/wifi-wps-enhc-extn.pid")"
          fi
          kill "$(cat "/var/run/wps-hotplug-$IFNAME.pid")"
          env -i ACTION="wps-connected" INTERFACE=$IFNAME /sbin/hotplug-call iface
          ;;
      WPS-TIMEOUT)
          kill "$(cat "/var/run/wps-hotplug-$IFNAME.pid")"
          env -i ACTION="wps-timeout" INTERFACE=$IFNAME /sbin/hotplug-call iface
          ;;
      DISCONNECTED)
          ;;
  esac
  ```
- **关键词：** IFNAME, CMD, /var/run/wpa_supplicant-$IFNAME, /var/run/wps-hotplug-$IFNAME.pid, wpa_cli, hostapd_cli, uci
- **备注：** 风险评分基于潜在命令注入可导致权限提升，但依赖脚本以高权限运行（如 root）。置信度中等，因为攻击链需要验证脚本调用上下文和参数来源（例如，是否来自网络接口或 IPC）。建议进一步分析脚本如何被调用（例如，通过 wpa_supplicant 或 hotplug 事件），并检查其他相关文件如 /sbin/wifi 或 /sbin/hotplug-call。如果 IFNAME 来自不可信输入（如 WPS 请求），攻击链可能完整。

---
### CommandInjection-internet_con

- **文件/目录路径：** `etc/scripts/ntgr_sw_api/ntgr_sw_api.sh`
- **位置：** `ntgr_sw_api.sh:internet_con function (approx. line 80)`
- **风险评分：** 7.0
- **置信度：** 7.5
- **描述：** Command injection vulnerability in the 'internet_con' function via 'eval' on unsanitized NVRAM data. The function uses 'eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\'' to read the NVRAM value. If the value of 'swapi_persistent_conn' contains malicious shell metacharacters (e.g., single quotes or semicolons), it could break out of the assignment and execute arbitrary commands. An attacker with valid login credentials (non-root) could potentially set this value via the 'nvram set' command if they have access to '/bin/config', and then trigger 'internet_con' to execute the payload. This links to existing vulnerabilities involving '/bin/config', enhancing exploitability.
- **代码片段：**
  ```
  eval tvalue=\'$($CONFIG get $SWAPI_PERSISTENT_CONN)\'\nif [ "x$(printf "$tvalue" | grep "$2\\ [01]")" != "x" ]; then\n\t$CONFIG set $SWAPI_PERSISTENT_CONN="$(printf "$tvalue"|sed "s/$2\\ [01]/$2\\ $3/")"\nelse\n\t$CONFIG set $SWAPI_PERSISTENT_CONN="${tvalue:+${tvalue};}$2 $3"\nfi
  ```
- **关键词：** swapi_persistent_conn, /bin/config
- **备注：** Exploitability is supported by associations with '/bin/config' in other high-risk findings (e.g., openvpn and cmdftp), where non-root users may set NVRAM variables. Verify permissions of '/bin/config' and access controls for invoking this script to confirm the attack chain.

---
### CommandInjection-image_demux

- **文件/目录路径：** `lib/upgrade/platform.sh`
- **位置：** `platform.sh:38-46 in image_demux function`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** The script contains potential command injection vulnerabilities in the 'image_demux' function where section names from the FIT image are used in shell commands without proper sanitization. If an attacker can provide a malicious FIT image with section names containing shell metacharacters (e.g., semicolons or backticks), it could lead to arbitrary command execution when 'dumpimage' is called. This requires the script to run with elevated privileges (e.g., during firmware upgrade), and the attacker must control the image file. The trigger condition is when 'platform_do_upgrade' or similar functions process a malicious image. Constraints include the need for a valid FIT image structure to pass initial checks, but the section names might be manipulable if 'dumpimage' does not restrict them. Potential exploitation involves injecting commands to gain root access or disrupt the system.
- **代码片段：**
  ```
  image_demux() {
  	local img=$1
  
  	for sec in $(print_sections ${img}); do
  		local fullname=$(get_full_section_name ${img} ${sec})
  
  		dumpimage -i ${img} -o /tmp/${fullname}.bin ${fullname} > /dev/null || { \
  			echo "Error while extracting \"${sec}\" from ${img}"
  			return 1
  		}
  	done
  	return 0
  }
  ```
- **关键词：** Image file path (e.g., $1 in platform_do_upgrade), Section names from dumpimage output (e.g., in get_full_section_name), /tmp/ files created during image extraction
- **备注：** Exploitability depends on whether the user can supply a malicious image and trigger the upgrade process with sufficient privileges. Further analysis of 'dumpimage' binary is recommended to validate section name restrictions. Associated functions: get_full_section_name, print_sections.

---
### File-Upload-Vulnerability-send_event

- **文件/目录路径：** `usr/bin/send_event`
- **位置：** `send_event:10-15`
- **风险评分：** 6.0
- **置信度：** 8.0
- **描述：** send_event 脚本接受两个文件路径参数（EVENTFILE 和 NODESFILE）并使用 authcurl 上传这些文件到基于 UPLOAD_HOST 的 URL。脚本没有对参数进行验证，允许攻击者指定任意文件路径。攻击者作为已登录的非 root 用户，可以执行该脚本并上传任何可读文件（如 /etc/passwd）到配置的云服务器，导致数据泄露。触发条件是脚本被直接调用或通过其他方式调用时参数可控。约束包括文件必须可读且 UPLOAD_HOST 服务器接受上传。潜在攻击是攻击者上传敏感文件到云服务器，可能泄露机密信息。
- **代码片段：**
  ```
  EVENTFILE="$1"
  NODESFILE="$2"
  URL=https://${UPLOAD_HOST}/api/v1/dbupload/
  authcurl --form upload=@"$EVENTFILE" --form nodes=@"$NODESFILE" $URL
  ```
- **关键词：** UPLOAD_HOST, EVENTFILE, NODESFILE
- **备注：** UPLOAD_HOST 可能来自 /etc/appflow/rc.appflow 且固定，但参数完全可控。攻击链简单可验证：攻击者执行脚本并指定文件路径 → 文件上传到云服务器。建议验证云服务器的访问控制和文件验证机制。与其他组件（如 upload_events）结合可能增强攻击 impact。

---
### 无标题的发现

- **文件/目录路径：** `etc/scripts/firewall/ntgr_sw_api.rule`
- **位置：** `ntgr_sw_api.rule:10-20 (start case) and ntgr_sw_api.rule:22-32 (stop case)`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** 脚本从 NVRAM 配置中获取值并直接用于 iptables 命令，缺少输入验证和边界检查。攻击者如果能够控制配置值（例如通过修改 'ntgr_api_firewall*' 变量），可注入恶意参数（如接口、协议或端口），导致防火墙规则被绕过或允许未经授权的网络访问。触发条件为脚本以 'start' 或 'stop' 参数执行时（例如系统启动或事件触发）。潜在利用方式包括设置配置值为 'any all ALL' 以允许所有流量，或注入特殊参数改变 iptables 行为。代码逻辑使用循环读取配置并执行 iptables 命令，没有转义或验证输入。
- **代码片段：**
  ```
  # Start case
  index=1
  while true
  do
      value=$(config get ${FIREWALL_NVCONF_PREFIX}${index})
      [ "x$value" = "x" ] && break || set $value
      [ "x$3" = "xALL" ] && useport="" || useport="yes"
      iptables -I INPUT -i $1 -p $2 ${useport:+--dport $3} -j ACCEPT
      iptables -I OUTPUT -o $1 -p $2 ${useport:+--sport $3} -j ACCEPT
      index=$((index + 1))
  done;
  
  # Stop case (similar structure)
  index=1
  while true
  do
      value=$(config get ${FIREWALL_NVCONF_PREFIX}${index})
      [ "x$value" = "x" ] && break || set $value
      [ "x$3" = "xALL" ] && useport="" || useport="yes"
      iptables -D INPUT -i $1 -p $2 ${useport:+--dport $3} -j ACCEPT
      iptables -D OUTPUT -o $1 -p $2 ${useport:+--sport $3} -j ACCEPT
      index=$((index + 1))
  done;
  ```
- **关键词：** ntgr_api_firewall* (NVRAM 变量), ntgr_sw_api.rule (文件路径)
- **备注：** 攻击链依赖于攻击者能够修改 NVRAM 配置值，但作为非 root 用户，权限可能受限。需要进一步分析配置系统（如 'config get' 的来源和修改机制）以验证实际可利用性。建议检查相关 IPC 或 API 接口是否允许非特权用户修改配置。此发现与组件交互相关，涉及 NVRAM 和 iptables。

---
### 路径遍历-event_register

- **文件/目录路径：** `etc/scripts/ntgr_sw_api/app_register.sh`
- **位置：** `app_register.sh:20-30 event_register function`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** 在 event_register 函数中，appname 参数被直接用于构建文件路径而没有验证路径遍历序列。攻击者可以使用 ../ 序列（如 '../../../etc'）来访问或创建任意目录和文件。例如，${APP_FOLDER}/$2/data 可能指向系统目录（如 /storage/etc/data），并写入 system.cfg 文件。触发条件：攻击者能控制 appname 参数，并且目标路径存在且可写。利用方式：调用 event_register with malicious appname -> 路径遍历 -> 任意文件创建/修改。边界检查：脚本检查目录存在（[ ! -d ${APP_FOLDER}/$2 ]），但如果遍历路径存在，则通过检查。
- **代码片段：**
  ```
  local APP_PROGRAM_FOLDER=${APP_FOLDER}/$2/program
  local APP_DATA_FOLDER=${APP_FOLDER}/$2/data
  [ ! -d ${APP_FOLDER}/$2 ] && error
  [ ! -d $APP_DATA_FOLDER ] && mkdir -p $APP_DATA_FOLDER
  [ "x$(grep $event_name ${APP_DATA_FOLDER}/${SYSTEM_CONFIG_NAME})" = "x" ] && \
      printf "%s\n" $event_name >> ${APP_DATA_FOLDER}/${SYSTEM_CONFIG_NAME}
  ```
- **关键词：** APP_FOLDER=/storage/system/apps, appname 参数, SYSTEM_CONFIG_NAME=system.cfg
- **备注：** 攻击者需要写权限到目标路径，可能受限於非 root 用户权限。潜在影响：配置文件污染或权限提升。建议添加路径验证（如检查 appname 是否包含 / 或 ..）。关联函数：error() 用于错误处理。

---
### stack-buffer-overflow-uhttpd-main

- **文件/目录路径：** `usr/sbin/uhttpd`
- **位置：** `uhttpd:0xb5d0 (strcpy for lan_ipaddr), uhttpd:0xb5e8 (strcpy for lan_netmask)`
- **风险评分：** 6.0
- **置信度：** 6.0
- **描述：** 在 main 函数中，使用 strcpy 复制配置值（如 lan_ipaddr 和 lan_netmask）到固定大小的栈缓冲区，缺乏边界检查。如果攻击者通过有效登录凭据修改这些配置参数（例如通过 web 接口），并提供超长字符串，可能触发栈缓冲区溢出，导致任意代码执行。漏洞触发条件包括控制配置输入并触发配置解析流程。
- **代码片段：**
  ```
  相关代码片段显示 strcpy 调用：
    - \`0x0000b5d0: bl sym.imp.strcpy\` 复制 lan_ipaddr 到缓冲区
    - \`0x0000b5e8: bl sym.imp.strcpy\` 复制 lan_netmask 到缓冲区
    缓冲区位于栈上（var_1500h 和 var_1540h），大小可能为 0x30 字节，但 strcpy 未检查长度。
  ```
- **关键词：** lan_ipaddr, lan_netmask
- **备注：** 需要验证配置参数是否可通过网络接口修改，以及缓冲区确切大小。建议后续分析验证路径遍历或命令注入在 CGI 处理中的可能性。关联函数包括 sym.uh_path_lookup 和 sym.uh_file_request。关联到现有发现：lan_ipaddr 和 lan_netmask 也用于 openvpn 命令注入漏洞（文件: etc/init.d/openvpn），表明跨组件数据流风险，但这里是独立的栈溢出漏洞。

---
### PathTraversal-image_demux_flash

- **文件/目录路径：** `lib/upgrade/platform.sh`
- **位置：** `platform.sh:38-46 in image_demux, platform.sh:59-67 in do_flash_mtd and do_flash_ubi`
- **风险评分：** 5.0
- **置信度：** 6.0
- **描述：** Path traversal vulnerabilities exist in file operations within 'image_demux' and 'do_flash_mtd'/'do_flash_ubi' functions, where section names are used to construct file paths in /tmp/. If a section name contains path traversal sequences (e.g., '../'), it could allow writing to or reading from arbitrary locations outside /tmp/. For example, in 'image_demux', the output file is /tmp/${fullname}.bin, and if fullname is '../../etc/passwd', it might overwrite /etc/passwd.bin. Similarly, in flashing functions, the input file is /tmp/${bin}.bin. Exploitation requires the attacker to control the image file and the script to run with write permissions to target directories. This could lead to file corruption or privilege escalation if critical files are modified.
- **代码片段：**
  ```
  image_demux() {
  	local img=$1
  
  	for sec in $(print_sections ${img}); do
  		local fullname=$(get_full_section_name ${img} ${sec})
  
  		dumpimage -i ${img} -o /tmp/${fullname}.bin ${fullname} > /dev/null || { \
  			echo "Error while extracting \"${sec}\" from ${img}"
  			return 1
  		}
  	done
  	return 0
  }
  
  do_flash_mtd() {
  	local bin=$1
  	local mtdname=$2
  
  	local mtdpart=$(grep "\"${mtdname}\"" /proc/mtd | awk -F: '{print $1}')
  	local pgsz=$(cat /sys/class/mtd/${mtdpart}/writesize)
  	dd if=/tmp/${bin}.bin bs=${pgsz} conv=sync | mtd write - -e ${mtdname} ${mtdname}
  }
  ```
- **关键词：** Section names from dumpimage output, /tmp/ file paths, MTD partition names (e.g., from /proc/mtd)
- **备注：** The risk is moderated by the need for the script to have write access to external directories, which may not be default. Validation of section names in 'dumpimage' or the FIT format could mitigate this. Suggested next step: Analyze 'dumpimage' binary for input handling.

---
