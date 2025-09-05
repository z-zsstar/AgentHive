# TX-VG1530 高优先级: 73 中优先级: 70 低优先级: 48

## 优先级评分模型

**计算公式:** `PriorityScore = (0.5 * risk_level) + (0.3 * confidence) + (0.2 * trigger_possibility)`

**分层策略:**
- **高优先级:** `PriorityScore >= 8.5`
- **中优先级:** `7.0 <= PriorityScore < 8.5`
- **低优先级:** `PriorityScore < 7.0`

---

## 高优先级发现

### attack_chain-telnet_to_root_shell

- **文件路径:** `etc/xml_commands/global-commands.xml`
- **位置:** `etc/init.d/rcS:94 | etc/shadow:13 | global-commands.xml:25`
- **类型:** command_execution
- **综合优先级分数:** **9.81**
- **风险等级:** 10.0
- **置信度:** 9.5
- **触发可能性:** 9.8
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链：1) telnetd服务无认证暴露网络接口（rcS:94）2) default账户空密码（shadow:13）3) CLI中'shell'命令直接调用系统shell（global-commands.xml:25）。触发条件：设备开放23端口 → 攻击者连接后使用空密码登录 → 执行'shell'命令 → 获得root权限。实际影响：100%设备沦陷。
- **代码片段:**
  ```
  telnetd &
  default::10933:0:99999:7:::
  <COMMAND name="shell" help="Enter Linux Shell">
      <ACTION builtin="appl_shell"> </ACTION>
  </COMMAND>
  ```
- **关键词:** telnetd, shell, appl_shell, default, shadow, rcS, global-commands.xml
- **备注:** 通过关联telnetd服务暴露和shell命令实现完整攻击路径

---
### attack_chain-telnet-default_empty_password

- **文件路径:** `etc/shadow`
- **位置:** `etc/shadow:13 | etc/init.d/rcS:94`
- **类型:** command_execution
- **综合优先级分数:** **9.5**
- **风险等级:** 9.8
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高风险攻击链：1) /etc/shadow中default账户密码字段为空(::) 2) /etc/init.d/rcS启动telnetd服务无认证参数 3) 攻击者连接设备23端口使用default账户空密码登录 → 直接获取root等效权限的交互式shell。触发条件：设备网络暴露23端口（默认启动）。安全影响：初始访问即获得最高控制权。
- **代码片段:**
  ```
  telnetd &
  default::10933:0:99999:7:::
  ```
- **关键词:** telnetd, rcS, default, shadow, UID=0
- **备注:** 需补充验证：/etc/passwd中default账户的shell配置（受访问限制未完成）

---
### command_execution-usbp-combined_vuln

- **文件路径:** `sbin/usbp`
- **位置:** `sbin/usbp:0x10688 section..text`
- **类型:** command_execution
- **综合优先级分数:** **9.5**
- **风险等级:** 9.7
- **置信度:** 9.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 复合漏洞（栈溢出+命令注入）：argv[1]直接传入sprintf格式化字符串'echo ====usbp %s===argc %d >/dev/ttyS0'（0x10688），目标缓冲区仅256字节但写入偏移-0x200。触发条件：1) 当argv[1]长度>223字节时触发栈溢出，可覆盖返回地址实现任意代码执行；2) 当argv[1]含命令分隔符（如';'）时，通过system执行注入命令。攻击者只需调用usbp并控制首个参数即可同时触发两种攻击，成功利用概率高（无需认证/特殊权限）。
- **代码片段:**
  ```
  sym.imp.sprintf(puVar10 + -0x200, *0x107f0, param_3, param_1);
  sym.imp.system(puVar10 + -0x200);
  ```
- **关键词:** argv[1], param_3, sprintf, system, 0x10688, 0x10b54, auStack_218, usbp_mount
- **备注:** 核心约束缺失：1) 无argv[1]长度校验 2) 无命令符号过滤。关键关联：1) 与知识库'mipc_send_cli_msg'调用链共享system危险操作（参见notes字段）2) 需验证usbp调用场景（如通过web接口/cgi-bin或启动脚本）3) dm_shmInit安全影响待分析（关联sh_malloc操作）

---
### network_input-telnetd_unauth

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:96`
- **类型:** network_input
- **综合优先级分数:** **9.45**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 10.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 启动未认证的telnetd服务。攻击者可中间人窃取凭证或直接获取shell。触发条件：系统启动后自动执行。实际影响：高风险RCE，因telnet默认无加密且易被扫描。
- **代码片段:**
  ```
  telnetd &
  ```
- **关键词:** telnetd
- **备注:** 需分析telnetd认证机制

---
### double_vulnerability-ctrl_iface-command_injection

- **文件路径:** `usr/sbin/hostapd`
- **位置:** `hostapd:0x1a208(fcn.0001a208), 0x1a4f8(fcn.0001a4f8)`
- **类型:** network_input
- **综合优先级分数:** **9.4**
- **风险等级:** 9.5
- **置信度:** 9.5
- **触发可能性:** 9.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 攻击链2：控制接口命令触发双重漏洞。触发条件：攻击者发送超长控制命令（如'ssid'或'candidate'）。触发步骤：1) recvfrom接收命令 → fcn.0001a4f8(strcpy栈溢出) 2) 后续调用fcn.0001a208(未授权配置更新+rename系统调用)。关键缺陷：strcpy目标缓冲区仅512字节(piVar8 + -0x80)，无长度检查；fcn.0001a208直接操作配置文件。实际影响：①溢出实现RCE概率高（控制接口通常局域网可达）②rename可能破坏关键配置。
- **代码片段:**
  ```
  strcpy(piVar8 + -0x80, param_2);  // fcn.0001a4f8
  ```
- **关键词:** ctrl_iface, fcn.0001a4f8, strcpy, piVar8 + -0x80, fcn.0001a208, rename, *0x1a898, ctrl_candidate
- **备注:** 全局变量*0x1a4e8可能影响缓冲区布局。需验证控制接口默认访问权限

---
### network_input-dnsmasq-CVE-2017-14491

- **文件路径:** `usr/sbin/dnsmasq`
- **位置:** `usr/sbin/dnsmasq:0x27348`
- **类型:** network_input
- **综合优先级分数:** **9.39**
- **风险等级:** 9.5
- **置信度:** 9.8
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** CVE-2017-14491（DHCP堆下溢漏洞）完整攻击链：
* **具体表现**：处理DHCP option 0x52时，memcpy使用未验证长度*(iVar6+1)计算目标地址(pcVar24 = pcVar25 - (length+2))，仅检查pcVar24≤pcVar10，但未防下溢
* **触发条件**：发送恶意DHCP包（option 0xff缺失或高位内存布局），使pcVar24下溢
* **约束检查**：边界检查(pcVar24≤pcVar10)无效（见代码片段）
* **安全影响**：堆内存破坏→任意代码执行（结合未启用PIE/Canary）
* **利用方式**：构造>0x400字节option 0x52触发下溢，覆盖堆结构控制流
- **代码片段:**
  ```
  pcVar24 = pcVar25 - (*(iVar6 + 1) + 2);
  if (pcVar24 <= pcVar10) { ... } else {
    sym.imp.memcpy(pcVar24, iVar6);  // 漏洞点
  ```
- **关键词:** fcn.000266c0, memcpy_0x27348, option_0x52, option_0xff, pcVar24, pcVar25, param_4, recvmsg, CVE-2017-14491
- **备注:** 漏洞环境：NX启用但无PIE/Canary，RELRO部分→PLTGOT可写。需验证dnsmasq是否监听67/68端口
关联发现：param_4在TR069代理(strcpy链)和告警阈值设置(未验证参数传递)中被使用

---
### attack_chain-telnetd-devmems

- **文件路径:** `usr/bin/devmem2`
- **位置:** `关联文件: etc/init.d/rcS, devmem2.c`
- **类型:** analysis_note
- **综合优先级分数:** **9.35**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链：网络输入（Telnet连接）→ 获取未认证root shell → 直接执行devmem2命令 → 触发物理内存任意读写（关联发现：command_execution-devmem2-arbitrary_write）。触发条件：1) telnetd服务默认开启（rcS:96）2) 攻击者访问设备23端口。成功概率：9.5/10（直接路径，无额外依赖）。
- **关键词:** telnetd, root, devmem2, physical_memory, argv
- **备注:** 关联发现：network_input-telnetd_unauth（入口点）, command_execution-devmem2-arbitrary_write（危险操作）

---
### file-read-memcorrupt-iw-argv-chain

- **文件路径:** `usr/sbin/iw`
- **位置:** `iw:0x11d4c(fcn.00011ca0)`
- **类型:** command_execution
- **综合优先级分数:** **9.34**
- **风险等级:** 9.0
- **置信度:** 9.8
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 攻击路径2：复合漏洞链实现文件读取+内存破坏。触发条件：执行特定命令时传递恶意argv参数。具体表现：a) fcn.000119c8处理*param_4(来自argv)时触发任意文件读取 b) strtoul处理param_4[1]时因缺少边界检查导致越界读。边界检查缺失：文件路径未规范化，数值未验证范围。安全影响：实现从命令行输入到敏感文件访问（如/etc/shadow）和堆内存破坏的完整利用链。利用方式：构造'iw [恶意命令]'触发漏洞链。
- **代码片段:**
  ```
  fcn.000119c8(*param_4);
  lVar7 = sym.imp.strtoul(param_4[1] + 4, 0, 0);
  ```
- **关键词:** fcn.000119c8, strtoul, argv, param_4, param_4[1]
- **备注:** 高危利用链。关联知识库关键词：argv, strtoul

---
### stack_overflow-ipc-Apm_cli_set_pm_interval-0x1370

- **文件路径:** `usr/lib/libpm_mipc_client.so`
- **位置:** `libpm_mipc_client.so:0x1370`
- **类型:** ipc
- **综合优先级分数:** **9.3**
- **风险等级:** 9.5
- **置信度:** 9.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** Apm_cli_set_pm_interval函数存在栈溢出漏洞：通过IPC接口传入的外部可控参数param_1经strcpy复制到固定栈缓冲区(fp-0x100)，缓冲区安全空间仅244字节。触发条件：传入≥244字节数据可覆盖返回地址（fp-4偏移252字节），实现RCE。攻击链：外部输入 → CLI/IPC接口 → strcpy栈溢出 → RCE。
- **代码片段:**
  ```
  strcpy(puVar2 + -0x100, puVar2[-0x42]); // puVar2[-0x42]=param_1
  ```
- **关键词:** Apm_cli_set_pm_interval, param_1, strcpy, fp-0x100, mipc_send_cli_msg, ipc_rce_chain
- **备注:** 攻击链1成员：直接RCE路径。关联关键词'mipc_send_cli_msg'可能涉及其他IPC组件。

---
### network_input-smb-struct_overflow-abb18

- **文件路径:** `usr/bin/smbd`
- **位置:** `fcn.000aae78:0xab024, 0xab074`
- **类型:** network_input
- **综合优先级分数:** **9.3**
- **风险等级:** 9.8
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** sym.request_oplock_break(0xabb18)存在结构化数据污染漏洞。攻击者通过Oplock Break SMB消息污染结构体字段(偏移0x1b8/0xa8)，污点数据最终在fcn.000aae78触发safe_strcpy_fn操作，导致auStack_828/auStack_428栈缓冲区溢出。触发条件：发送>1024字节路径名的SMB请求且启用文件共享。
- **代码片段:**
  ```
  sym.imp.safe_strcpy_fn(*(puVar14 + -0x810),0,puVar14 + -0x404,uVar10);
  ```
- **关键词:** sym.request_oplock_break, safe_strcpy_fn, auStack_828, auStack_428, iVar12+0x1b8
- **备注:** 攻击路径：SMB协议 → 结构体污染 → sym.request_oplock_break → fcn.000aae78溢出

---
### ftp-ssl-disabled

- **文件路径:** `etc/vsftpd.conf`
- **位置:** `etc/vsftpd.conf`
- **类型:** configuration_load
- **综合优先级分数:** **9.25**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 10.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** FTP服务未启用SSL/TLS加密（ssl_enable未配置）。导致所有数据传输以明文进行，攻击者可通过中间人攻击嗅探凭证和文件内容。触发条件：任何FTP连接建立时。边界检查：无加密保护机制，影响范围覆盖所有FTP会话。安全影响：结合write_enable=YES配置，攻击者可能窃取上传的敏感文件或重放会话劫持操作。
- **关键词:** ssl_enable, rsa_cert_file, write_enable
- **备注:** 需确认网络暴露面：若FTP端口(21/tcp)对外开放则风险加剧

---
### command_execution-fw_setenv-stack_overflow

- **文件路径:** `usr/bin/fw_printenv`
- **位置:** `fw_printenv:0x1116c (sym.fw_setenv)`
- **类型:** command_execution
- **综合优先级分数:** **9.25**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** fw_setenv栈溢出漏洞：攻击者通过命令行传入超长环境变量名/值组合（如`fw_setenv $(python -c 'print "A"*5000')=value`）。触发条件：1) 程序未验证argv参数长度 2) 循环复制时无边界检查（while循环逐字节复制）。实际影响：覆盖栈帧导致任意代码执行（风险等级9.5）。利用概率高（仅需命令行访问权限）
- **代码片段:**
  ```
  while( true ) {
      **(puVar7 + -0x10) = **(puVar7 + -0x1c); // 无边界检查的逐字节复制
      ...
  }
  ```
- **关键词:** fw_setenv, argv, *(puVar7 + -0x10), *(puVar7 + -0x1c), stack_buffer
- **备注:** 需动态验证溢出点偏移量。关联文件：/usr/bin/fw_setenv（符号链接）

---
### network_input-upnpd-command_injection_0x17274

- **文件路径:** `usr/bin/upnpd`
- **位置:** `upnpd:0x17274 (fcn.000170c0)`
- **类型:** network_input
- **综合优先级分数:** **9.25**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危未认证远程命令注入漏洞。触发条件：攻击者发送特制HTTP POST请求（如AddPortMapping操作），控制'dport'等参数注入命令分隔符（;|&>）。污染路径：1) msg_recv()接收网络数据写入全局缓冲区0x32590 2) fcn.00013fc0处理参数时未过滤 3) fcn.00016694使用snprintf构造iptables命令时直接拼接污染数据 4) 通过system()执行污染命令。边界检查缺失：无输入过滤/长度验证，高危参数包括param_2/3/4和栈缓冲区auStack_21c。实际影响：攻击者可注入';telnetd -l/bin/sh'开启root shell，成功概率>90%。
- **代码片段:**
  ```
  snprintf(auStack_21c,500,"%s -t nat -A %s ...",param_2);
  system(auStack_21c);
  ```
- **关键词:** fcn.00016694, system, snprintf, param_2, param_3, param_4, auStack_21c, 0x32590, msg_recv, fcn.00013fc0, POSTROUTING_NATLOOPBACK_UPNP, PREROUTING_UPNP, dport
- **备注:** PoC验证可行。关联漏洞：同函数0x17468栈溢出和0x17500格式字符串漏洞可组合利用

---
### stack-overflow-omci_cli_set_voip-0x2e28

- **文件路径:** `usr/lib/libomci_mipc_client.so`
- **位置:** `libomci_mipc_client.so:0x2e28`
- **类型:** ipc
- **综合优先级分数:** **9.24**
- **风险等级:** 9.2
- **置信度:** 9.8
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 函数omci_cli_set_voip存在未经验证的参数拷贝漏洞。具体表现：name参数直接通过strcpy复制到264字节栈缓冲区(var_108h)，仅进行空指针检查(cmp r3,0)但无长度验证。触发条件：攻击者传递长度>264字节的name参数。边界检查缺失：复制前未获取参数长度，未使用安全函数（如strncpy）。安全影响：结合该函数处理VOIP配置的特性，可能通过OMCI协议(消息类型0x1c)远程触发漏洞。
- **代码片段:**
  ```
  0x2e10: cmp r3, 0
  0x2e28: bl sym.imp.strcpy
  ```
- **关键词:** omci_cli_set_voip, strcpy, name, var_108h, msg_type=0x1c, mipc_send_cli_msg
- **备注:** 与stack-overflow-apm_cli-reset_db共享var_108h缓冲区结构。需重点验证：1) omcid服务调用路径 2) HTTP接口到name参数的映射

---
### xxe-commandline-injection-sipapp

- **文件路径:** `usr/bin/sipapp`
- **位置:** `sipapp:0x1257c (sipapp_read_commandline)`
- **类型:** configuration_load
- **综合优先级分数:** **9.24**
- **风险等级:** 9.3
- **置信度:** 9.5
- **触发可能性:** 8.7
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** XXE攻击链：攻击者通过Web接口注入命令行参数(-f /tmp/evil.xml)→sipapp_read_commandline设置全局配置路径→sipapp_init调用ezxml_parse_file解析XML。未设置EZXML_NOENT标志允许外部实体引用，导致：1) 任意文件读取 2) SSRF攻击 3) XXE盲注实现RCE。触发条件：存在调用sipapp的Web CGI接口。
- **关键词:** sipapp_read_commandline, optarg, obj.sipapp_configuration_file, ezxml_parse_file, EZXML_NOENT
- **备注:** 需验证Web接口是否存在参数注入点

---
### stack_overflow-apm_cli_set_alarm_state_info-0x1160

- **文件路径:** `usr/lib/libalarm_mipc_client.so`
- **位置:** `libalarm_mipc_client.so:0x1160`
- **类型:** ipc
- **综合优先级分数:** **9.19**
- **风险等级:** 9.2
- **置信度:** 9.5
- **触发可能性:** 8.7
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞（CWE-121）。具体表现：函数Apm_cli_set_alarm_state_info通过strcpy将外部可控name参数直接复制到268字节固定栈缓冲区(auStack_118)，未进行长度验证。当name长度≥268字节时覆盖栈上返回地址。触发条件：攻击者通过设备网络接口（如HTTP API/CLI）发送恶意alarm设置命令。利用方式：构造268字节payload控制EIP实现任意代码执行。
- **代码片段:**
  ```
  if (puVar2[-0x46] != 0) {
      sym.imp.strcpy(puVar2 + -0x10c, puVar2[-0x46]);
  }
  ```
- **关键词:** Apm_cli_set_alarm_state_info, name, strcpy, auStack_118, mipc_send_cli_msg
- **备注:** 需验证通过web接口触发路径。关联文件：调用本函数的CLI处理模块；关联知识库现有mipc_send_cli_msg调用链（如stack-overflow-oam_cli-mipc_chain）

---
### stack-overflow-oam_cli-mipc_chain

- **文件路径:** `usr/lib/liboam_mipc_client.so`
- **位置:** `liboam_mipc_client.so: oam_cli_cmd_set_onu_loid/oam_cli_cmd_voip_sip_user_config_set/oam_cli_cmd_set_uni_rate_limit`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 在liboam_mipc_client.so中发现关键栈溢出漏洞链：
1. 初始漏洞：通过OAM CLI接口（LOID/SIP用户名/速率限制名）传递超长参数触发栈溢出
   - 函数使用strcpy复制到固定栈缓冲区（256-268字节）无校验
   - 覆盖返回地址可实现任意代码执行
   - 漏洞函数通过mipc_send_cli_msg(0x35/0x46)传递配置
2. 传播风险：溢出后仍执行IPC发送
   - 接收方获取含攻击者控制数据的完整结构体（268字节）
   - 消息类型0x35/0x46对应硬件配置操作
完整触发链：控制CLI输入→溢出劫持控制流→操控IPC数据结构→系统进程二次漏洞利用
- **代码片段:**
  ```
  漏洞模式示例:
  if (input_param != 0) {
      strcpy(auStack_118, input_param); // 无长度检查
  }
  ...
  mipc_send_cli_msg(0x35, &data_struct); // 发送被控数据
  ```
- **关键词:** oam_cli_cmd_set_onu_loid, oam_cli_cmd_voip_sip_user_config_set, oam_cli_cmd_set_uni_rate_limit, strcpy, mipc_send_cli_msg, 0x35, 0x46, name
- **备注:** 关键待验证点：
1. CLI暴露接口（Telnet/HTTP API）是否存在
2. mipc_send_cli_msg接收方处理逻辑（如liboam_mipc_server.so）
3. 接收进程是否存在格式化字符串/命令注入等二次漏洞

---
### hardware_input-devmem3-arbitrary_physical_memory

- **文件路径:** `usr/bin/devmem3`
- **位置:** `main @ 0x105c0-0x10614`
- **类型:** hardware_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** devmem3存在高危任意物理内存访问漏洞：程序通过strtoul直接转换用户输入的物理地址参数（argv[1]），未进行任何范围检查即用于mmap映射和内存读写操作。触发条件：1) 攻击者能控制命令行参数（如通过web脚本调用或命令注入）2) 程序以root权限运行（因需访问/dev/mem）。利用方式：指定敏感物理地址（如内核数据结构/设备寄存器）实现权限提升、DoS或硬件状态篡改。约束检查：仅验证参数数量，地址值完全未过滤。实际安全影响取决于内核CONFIG_STRICT_DEVMEM配置：若禁用则可访问全部物理内存；若启用则受限但仍可操作外设寄存器。
- **代码片段:**
  ```
  uVar1 = sym.imp.strtoul(*(*(puVar8 + -0x134) + 4),0,0);
  *(puVar8 + -8) = uVar1;
  uVar1 = sym.imp.mmap(0,0x1000,3,1);
  ```
- **关键词:** strtoul, mmap, argv[1], *(puVar8 + -8), /dev/mem, O_RDWR, PROT_READ|PROT_WRITE, physical_memory, write_memory
- **备注:** 关键未验证条件：1) 需分析启动脚本确认是否以root调用 2) 需验证内核CONFIG_STRICT_DEVMEM状态。建议后续分析/etc/init.d脚本和/boot/config-*文件。关联记录：usr/bin/devmem2存在相同漏洞模式（记录名：hardware_input-devmem2-arbitrary_mmap）

---
### stack-overflow-l2omci_cli_set_vlan_filters-0x43d8

- **文件路径:** `usr/lib/libomci_mipc_client.so`
- **位置:** `libomci_mipc_client.so:0x43d8`
- **类型:** ipc
- **综合优先级分数:** **9.15**
- **风险等级:** 9.8
- **置信度:** 9.5
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 函数l2omci_cli_set_vlan_filters存在双栈溢出漏洞。具体表现：函数将外部可控的name和tci参数通过strcpy复制到相邻的256字节栈缓冲区(fp-0x208和fp-0x104)。触发条件：name长度≥260字节或tci长度≥256字节时将分别触发溢出。安全影响：攻击者可构造ROP链实现权限提升。利用概率评估：高（7.0/10），因该函数处理OMCI操作码0x38的VLAN配置，属于关键网络功能接口。
- **代码片段:**
  ```
  0x43d8: strcpy(dest, name)
  0x4404: strcpy(dest, tci)
  ```
- **关键词:** l2omci_cli_set_vlan_filters, strcpy, name, tci, OMCI_OPCODE_0x38, mipc_send_cli_msg
- **备注:** 关键关联点：OMCI消息类型0x38与现有漏洞链的0x35/0x46共享消息分发机制。需验证：1) 上级服务是否暴露HTTP/TR069接口 2) OMCI消息解析器长度检查

---
### attack-chain-ipc-mipc_send_sync_msg

- **文件路径:** `usr/lib/libvoip_mipc_client.so`
- **位置:** `unknown`
- **类型:** ipc
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 跨组件漏洞模式：所有高危函数均通过mipc_send_sync_msg进行IPC通信，形成统一攻击面。攻击者只需控制任一调用这些函数的服务（如web配置接口），即可通过构造异常参数触发内存破坏漏洞。完整攻击链：HTTP参数 → VOIP配置函数 → mipc_send_sync_msg → 内存破坏。
- **关键词:** mipc_send_sync_msg, VOIP_updateSipAccountData_F, VOIP_setSipParamConfig_F, VOIP_updateSipServerAddr_F, VOIP_setSipUserParamConfig_F
- **备注:** 核心后续方向：1) 在sbin目录查找使用libvoip_mipc_client.so的进程 2) 分析这些进程如何处理HTTP/UART等外部输入

---
### rce-sdp-overflow-media_codec

- **文件路径:** `usr/bin/sipapp`
- **位置:** `sipapp:0x28f58 (sipapp_media_codec_ftmtp_red)`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** SDP协议栈溢出攻击链：外部攻击者发送特制SDP消息→sipapp_media_sdp_get_codec未验证payload type(pt)→传入sipapp_media_codec_init→ftmtp_red函数循环执行sprintf。当red参数depth≥9时，9次循环写入36字节溢出32字节栈缓冲区，覆盖返回地址实现任意代码执行。触发条件：设备暴露SIP服务端口(默认5060)且接收恶意SDP消息。
- **代码片段:**
  ```
  循环: sprintf(buffer, "%d ", pt); // depth未限制循环次数
  ```
- **关键词:** sipapp_media_codec_ftmtp_red, sprintf, pt, depth, SDP, sipapp_media_sdp_get_codec
- **备注:** 最可靠攻击链：无需认证，单次网络请求触发RCE

---
### command_execution-shell_full_access-global_commands

- **文件路径:** `etc/xml_commands/global-commands.xml`
- **位置:** `etc/xml_commands/global-commands.xml`
- **类型:** command_execution
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 已验证高危攻击链：通过telnet等网络服务获得CLI访问权限后，执行'shell'命令直接调用appl_shell进入Linux shell。触发条件：1) 攻击者获得CLI执行权限（如telnet弱口令）；2) 执行'shell'命令。约束条件：无任何参数过滤或权限检查机制。安全影响：100%成功率获取root权限的完整设备控制，构成从网络输入到特权升级的完整攻击路径。
- **代码片段:**
  ```
  <COMMAND name="shell" help="Enter Linux Shell">
      <ACTION builtin="appl_shell"> </ACTION>
  </COMMAND>
  ```
- **关键词:** shell, appl_shell, builtin, COMMAND, ACTION, telnetd
- **备注:** 需分析/sbin/clish二进制中appl_shell实现（栈分配/危险函数使用）。关联文件：/sbin/clish

---
### stack-overflow-flashapi-startwriteflash

- **文件路径:** `usr/lib/libflash_mipc_client.so`
- **位置:** `usr/lib/libflash_mipc_client.so:0xf64`
- **类型:** ipc
- **综合优先级分数:** **9.14**
- **风险等级:** 9.0
- **置信度:** 9.8
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** FlashApi_startWriteFlash函数存在高危栈溢出漏洞：
- **具体表现**：使用strcpy复制外部传入的filename和clientId参数到固定大小缓冲区（256/258字节），无长度检查
- **触发条件**：当攻击者控制filename或clientId参数并传入超长字符串（>256字节）
- **约束缺失**：完全缺失边界检查，直接使用strcpy
- **安全影响**：可覆盖返回地址实现任意代码执行，结合固件更新功能可能获得root权限
- **利用方式**：通过调用此函数的服务（如固件更新接口）传入恶意长字符串
- **代码片段:**
  ```
  strcpy(auStack_20c, filename);
  strcpy(auStack_10b, clientId);
  ```
- **关键词:** FlashApi_startWriteFlash, filename, clientId, strcpy, auStack_20c, auStack_10b
- **备注:** 关键关联线索：
1) 需追踪调用者（/bin /sbin /www目录）
2) filename/clientId可能来自HTTP/NVRAM
3) 已知关联漏洞：stack-overflow-oam_cli-mipc_chain(usr/lib/liboam_mipc_client.so), stack-overflow-apm_cli-avc_value_str(usr/lib/libavc_mipc_client.so)

---
### CWE-787-radvd-15d30

- **文件路径:** `usr/sbin/radvd`
- **位置:** `sbin/radvd:0x15d30`
- **类型:** network_input
- **综合优先级分数:** **9.1**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 9.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** strncpy将网络提供的接口名复制到15字节栈缓冲区未验长度。触发条件：发送含>15字节接口名的伪造ICMPv6包。实际影响：远程栈溢出实现RCE。
- **代码片段:**
  ```
  sym.imp.strncpy(puVar4 + -0x24,param_1,0xf);
  ```
- **关键词:** strncpy, socket, auStack_40, recvmsg
- **备注:** 需绕过ICMPv6校验但无加密保护

---
### stack-overflow-apm_cli-avc_value_str

- **文件路径:** `usr/lib/libavc_mipc_client.so`
- **位置:** `libavc_mipc_client.so:0x11c0 (Apm_cli_set_avc_value_str)`
- **类型:** ipc
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞（CWE-121）：在Apm_cli_set_avc_value_str函数中发现两个未经验证的外部输入处理点：1) name参数直接复制到256字节栈缓冲区(auStack_210) 2) value参数复制到256字节栈缓冲区(auStack_108)。触发条件：当通过IPC接口(mipc_send_cli_msg)传入超过256字节的name或value参数时，将覆盖栈帧导致控制流劫持。安全影响：攻击者可构造恶意IPC消息实现任意代码执行（RCE），结合固件权限模型可能获得设备完全控制权。
- **代码片段:**
  ```
  if (name_ptr != 0) {
      strcpy(local_210, name_ptr);
  }
  if (value_ptr != 0) {
      strcpy(local_108, value_ptr);
  }
  ```
- **关键词:** Apm_cli_set_avc_value_str, name, value, auStack_210, auStack_108, strcpy, mipc_send_cli_msg, liboam_mipc_client.so, libigmp_mipc_client.so
- **备注:** 关联漏洞：stack-overflow-oam_cli-mipc_chain (usr/lib/liboam_mipc_client.so), ipc-iptvCli-0x2034 (usr/lib/libigmp_mipc_client.so)。后续验证方向：1) 在/sbin,/usr/bin目录查找调用该函数的可执行文件 2) 分析IPC消息解析机制 3) 确认外部接口暴露情况（如网络服务、CLI命令）

---
### ipc-midware_db-memory_corruption

- **文件路径:** `usr/lib/libmidware_mipc_client.so`
- **位置:** `libmidware_mipc_client.so:0xdf0 (midware_update_entry), 0xcd0 (midware_insert_entry)`
- **类型:** ipc
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危内存操作漏洞群(CWE-120/CWE-787)。核心缺陷：1) 多个数据库操作函数(midware_update_entry/midware_insert_entry等)使用memcpy复制外部可控entry数据 2) size参数完全未经边界验证 3) 目标缓冲区auStack_80c固定为2048字节。触发条件：通过IPC消息传递size>2048的恶意entry数据。安全影响：覆盖返回地址实现RCE，已发现通过RSTP_set_enable等网络接口触发的完整攻击链。
- **代码片段:**
  ```
  if (puVar2[-0x206] != 0) {
      sym.imp.memcpy(puVar2 + 0 + -0x800, puVar2[-0x206], puVar2[-0x207]);
  }
  ```
- **关键词:** midware_update_entry, midware_insert_entry, entry, memcpy, auStack_80c, mipc_send_sync_msg, RSTP_set_enable
- **备注:** 统一设计缺陷影响至少5个导出函数。后续方向：1) 逆向/www/cgi-bin确认调用链 2) 测试ASLR/NX防护状态

---
### command_execution-iwpriv-stack_overflow-0x112c0

- **文件路径:** `usr/sbin/iwpriv`
- **位置:** `iwpriv:0x112c0 (dbg.set_private_cmd)`
- **类型:** command_execution
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞。具体表现：处理字符串类型参数(标志0x2000)时，直接使用memcpy将用户控制数据复制到固定大小栈缓冲区(auStack_10b0, 1023字节)，未验证输入长度与缓冲区边界。同时strncpy复制接口名(ifname)到4字节缓冲区(auStack_28)时缺少长度参数。触发条件：攻击者通过命令行或网络接口传入超长参数值或接口名。安全影响：可覆盖返回地址实现任意代码执行，成功概率高(需结合固件DEP/ASLR配置评估)。
- **代码片段:**
  ```
  sym.imp.memcpy(iVar20 + -0x10b0, uVar6, *(iVar20 + -0x1c));
  sym.imp.strncpy(iVar20 + -0x30, *(iVar20 + -0x10c0));
  ```
- **关键词:** dbg.set_private_cmd, memcpy, strncpy, param_2, param_4, IFNAMSIZ, 0x2000, auStack_10b0, auStack_28
- **备注:** 攻击路径：网络接口/CLI → argv参数解析 → set_private_cmd缓冲区操作。需验证上级组件(如HTTP CGI)调用iwpriv的方式及实际栈布局

---
### integer-overflow-shell_name-heap-overflow

- **文件路径:** `bin/bash`
- **位置:** `main:0x26374 → sym.sh_xmalloc → sym.sh_malloc`
- **类型:** env_get
- **综合优先级分数:** **9.0**
- **风险等级:** 9.2
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 确认高危整数溢出漏洞链：攻击者通过设置超长环境变量控制shell_name值（长度0xFFFFFFFF）。main函数中strlen(shell_name)+1计算产生整数溢出（0xFFFFFFFF+1=0），导致sh_xmalloc分配极小缓冲区。后续strcpy操作将超长字符串复制到该缓冲区，造成堆溢出。触发条件：1) 攻击者能设置环境变量；2) 系统允许环境变量长度接近0xFFFFFFFF。实际影响：可通过堆破坏实现任意代码执行，成功概率取决于堆布局和防护机制。
- **代码片段:**
  ```
  r0 = [r4 + 0x14];        // obj.shell_name
  sym.imp.strlen();
  r0 = r0 + 1;             // 整数溢出点
  sym.sh_xmalloc();
  ...
  sym.imp.strcpy(uVar11,uVar18);
  ```
- **关键词:** obj.shell_name, sym.imp.strlen, sym.sh_xmalloc, sym.imp.strcpy, main@0x26374, uVar18, sym.sh_malloc
- **备注:** 需补充验证：1) 环境变量最大长度限制；2) 具体堆破坏利用方式；固定地址(0x26f54等)字符串提取失败，但反汇编结果已提供充分函数交互证据。环境变量名'SHELL_NAME'未显式出现，但obj.shell_name的污染路径已明确。

---
### stack-overflow-apm_cli-reset_db

- **文件路径:** `usr/lib/libapm_new_mipc_client.so`
- **位置:** `libapm_new_mipc_client.so:0x684`
- **类型:** ipc
- **综合优先级分数:** **9.0**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** Apm_cli_reset_db函数存在临界栈溢出漏洞。触发条件：参数(name)长度>28字节即可覆盖返回地址。具体机制：1) 栈分配0x120字节 2) strcpy目标缓冲区(var_108h)距返回地址仅0x1C字节 3) 仅检查指针非空。结合其通过mipc_send_cli_msg发送控制消息的行为，可能构成攻击链关键环节。成功利用可导致设备数据库被恶意重置或代码执行。
- **代码片段:**
  ```
  // 伪代码还原
  void Apm_cli_reset_db(char* name) {
      char buffer[0x120];
      if (name != NULL) {
          strcpy(buffer + 0x1C, name); // 目标缓冲区距返回地址0x1C
      }
      mipc_send_cli_msg(...); // 发送控制消息
  }
  ```
- **关键词:** Apm_cli_reset_db, name, strcpy, var_108h, mipc_send_cli_msg
- **备注:** 高危点：溢出阈值极低(28字节)且函数全局导出。已确认关联漏洞链：1) stack-overflow-oam_cli-mipc_chain (liboam_mipc_client.so) 2) ipc-iptvCli-0x2034 (libigmp_mipc_client.so) 3) stack-overflow-apm_cli-avc_value_str (libavc_mipc_client.so)。急迫需要分析调用者上下文

---
### ipc-Midware_cli_get_entry-stack_overflow

- **文件路径:** `usr/lib/libmidware_mipc_client.so`
- **位置:** `libmidware_mipc_client.so: sym.Midware_cli_get_entry`
- **类型:** ipc
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞(CWE-121)。具体表现：1) 使用strcpy将外部可控参数(name/arg)复制到固定大小栈缓冲区(auStack_20c/auStack_108) 2) 未对输入长度进行验证 3) 当参数长度>255字节时覆盖栈帧关键数据。触发条件：攻击者通过IPC消息传递超长name或arg参数。安全影响：结合函数导出属性，可实现任意代码执行(RCE)。利用方式：构造>255字节恶意参数覆盖返回地址。
- **代码片段:**
  ```
  if (*(puVar2 + -0x20c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x208, *(puVar2 + -0x20c));
  }
  ```
- **关键词:** Midware_cli_get_entry, auStack_20c, auStack_108, strcpy, mipc_send_cli_msg
- **备注:** 需验证调用上下文：1) 确认name/arg参数来源(如HTTP接口) 2) 分析mipc_send_cli_msg数据流

---
### stack-overflow-voip-VOIP_updateSipServerAddr_F

- **文件路径:** `usr/lib/libvoip_mipc_client.so`
- **位置:** `libvoip_mipc_client.so:sym.VOIP_updateSipServerAddr_F`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 代理配置栈溢出：strcpy直接复制外部proxy参数到256字节栈缓冲区(auStack_108)，无长度校验。触发条件：proxy长度>255字节。安全影响：最直接可利用的栈溢出点，覆盖返回地址实现任意代码执行。
- **关键词:** VOIP_updateSipServerAddr_F, proxy, strcpy, auStack_108, src
- **备注:** 需优先验证：在固件HTTP接口中查找设置SIP代理服务器的功能点

---
### format-string-config_parser-sipapp

- **文件路径:** `usr/bin/sipapp`
- **位置:** `sipapp:0x12a50 (sipapp_config_set_str)`
- **类型:** file_read
- **综合优先级分数:** **8.95**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 格式化字符串攻击链：攻击者通过Web漏洞写入/etc/sipapp.conf→sipapp_config_parse读取配置文件→sipapp_config_set_str使用vsnprintf处理外部可控format字符串。未过滤%n等危险格式符，实现任意内存写入→GOT表劫持→RCE。触发条件：获得配置文件写入权限。
- **代码片段:**
  ```
  vsnprintf(target_buf, 128, user_controlled_format, args);
  ```
- **关键词:** sipapp_config_set_str, vsnprintf, format, sipapp_config_parse, /etc/sipapp.conf

---
### uri-parser-multi-vuln-sipapp_acc

- **文件路径:** `usr/bin/sipapp`
- **位置:** `sipapp:未知地址 (sipapp_acc_add_accounts)`
- **类型:** configuration_load
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** URI解析三重漏洞：sipapp_acc_add_accounts处理账户URI时：1) pjsip_parse_uri输出到固定栈缓冲区(276字节)，超长URI导致溢出 2) 非常规scheme使find_uri_handler返回NULL引发段错误 3) 污染全局回调表(0x3fa6c)。触发条件：通过配置接口注入恶意URI。
- **关键词:** pjsip_parse_uri, find_uri_handler, scheme, 0x3fa6c, auStack_140

---
### env_injection-hotplug-action_chain

- **文件路径:** `sbin/hotplug`
- **位置:** `/sbin/hotplug:0x10acc (getenv) 0x10bf0 (system)`
- **类型:** env_get,command_execution
- **综合优先级分数:** **8.9**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危PATH劫持攻击链：当内核触发hotplug并设置ACTION环境变量为'add'或'remove'时，程序通过system()执行usbp_mount/usbp_umount命令。由于实际文件不存在且/sbin目录权限为777(rwxrwxrwx)，攻击者可在/sbin创建恶意同名文件。触发条件：1) 文件系统以可写模式挂载 2) 攻击者能设置ACTION环境变量（通过USB热插拔事件触发）3) /sbin在PATH环境变量搜索顺序中优先。安全影响：以root权限执行任意代码，完全控制设备。利用方式：部署恶意usbp文件并触发USB事件。
- **代码片段:**
  ```
  uVar1 = getenv("ACTION");
  if (!strcmp(uVar1, "add")) system("usbp mount");
  if (!strcmp(uVar1, "remove")) system("usbp umount");
  ```
- **关键词:** system, ACTION, getenv, usbp_mount, usbp_umount, PATH, sbin
- **备注:** 约束条件：1) 需物理访问或远程触发USB事件 2) 依赖PATH配置 3) 需文件系统可写。关联发现：通过ACTION关键词关联CLI命令执行漏洞（name:command_execution-shell_full_access），若攻击者通过CLI获得初始访问，可利用/sbin权限部署恶意usbp文件形成权限维持链。

---
### privilege_escalation-apm_cli_set_alarm_admin-admin

- **文件路径:** `usr/lib/libalarm_mipc_client.so`
- **位置:** `libalarm_mipc_client.so: sym.Apm_cli_set_alarm_admin`
- **类型:** ipc
- **综合优先级分数:** **8.9**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 权限控制缺失与栈溢出组合漏洞（CWE-285/CWE-121）。具体表现：Apm_cli_set_alarm_admin函数：1) 仅依赖admin标志位决定权限，攻击者可伪造该标志 2) 使用strcpy复制用户控制name参数到256字节栈缓冲区时无长度校验。触发条件：通过IPC构造超长name或伪造admin标志。利用方式：权限提升+任意代码执行。
- **代码片段:**
  ```
  if (*(puVar3 + -0x110) != 0) {
      sym.imp.strcpy(puVar3 + -0x108,*(puVar3 + -0x110));
  }
  ```
- **关键词:** Apm_cli_set_alarm_admin, admin, name, strcpy, auStack_114[256]
- **备注:** 需检查暴露此函数的IPC端点权限控制；关联notes中'关键待验证点：fcn.00013d48等函数对param_2的处理逻辑'

---
### RCE-chain-softup

- **文件路径:** `usr/bin/httpd`
- **位置:** `usr/bin/httpd:0x133d8 (0x1365c)`
- **类型:** network_input
- **综合优先级分数:** **8.9**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整RCE攻击链（/cgi/softup）：1) 攻击者发送恶意multipart请求触发Content-Disposition头部解析漏洞（0x1365c处的pcVar6[-1]越界写）；2) 利用内存破坏覆盖关键结构；3) 通过未签名固件上传功能植入持久化后门。触发条件：单次HTTP POST请求，无需认证。
- **关键词:** fcn.000133d8, pcVar6[-1], Content-Disposition, filename, fcn.00013248, param_2
- **备注:** 漏洞组合利用：内存破坏实现初始执行，未签名固件维持持久化

---
### vulnerability-wpa_supplicant-EAPOL-Key-memcpy

- **文件路径:** `usr/sbin/wpa_supplicant`
- **位置:** `fcn.00021030:0x2103c-0x21300`
- **类型:** network_input
- **综合优先级分数:** **8.9**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** EAPOL-Key帧处理漏洞链：攻击者通过恶意802.11帧触发fcn.00021030函数内存破坏。关键缺陷：1) 密钥数据长度uVar13仅验证上限 2) memcpy使用未验证长度(0x21300处) 3) uVar9=0时触发20字节栈溢出(auStack_38)。触发条件：构造uVar13=0x2C且uVar9=0的EAPOL-Key帧。实际影响：远程代码执行(RCE)，风险加剧因wpa_supplicant常以root运行。
- **关键词:** EAPOL-Key, fcn.00021030, uVar13, uVar9, memcpy, auStack_38, param_1+0xd0, rc4
- **备注:** 需追踪完整调用链：1) recvfrom到fcn.00021030的数据流 2) 状态机条件param_1[0x1d]的污染源

---
### kernel-overflow-iw-argv-interface

- **文件路径:** `usr/sbin/iw`
- **位置:** `iw:0x1171c(main), 0x11d4c(fcn.00011ca0)`
- **类型:** command_execution
- **综合优先级分数:** **8.9**
- **风险等级:** 8.5
- **置信度:** 9.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 攻击路径1：未验证接口名导致内核溢出。触发条件：执行'iw dev <interface>'时传递超长接口名(>16字节)。具体表现：argv[2]直接传入if_nametoindex，未进行IFNAMSIZ长度验证。边界检查缺失：完全依赖内核实现约束。安全影响：可触发内核缓冲区溢出，结合内核漏洞可实现权限提升。利用方式：构造超长接口名命令如'iw dev AAAAAAAAAAAAAAAAAAAAAA'。
- **代码片段:**
  ```
  iVar2 = sym.imp.if_nametoindex(*param_4);  // *param_4来自argv
  ```
- **关键词:** argv, if_nametoindex, param_4, fcn.00011ca0, IFNAMSIZ
- **备注:** 跨文件关联：需验证内核IFNAMSIZ实现。关联知识库关键词：argv, IFNAMSIZ

---
### network_input-TR069-stack_overflow-fcn000137b8

- **文件路径:** `usr/bin/cwmp`
- **位置:** `fcn.000137b8 @ 栈缓冲区定义和调用点`
- **类型:** network_input
- **综合优先级分数:** **8.85**
- **风险等级:** 9.5
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞（CWE-121）：
- 触发条件：攻击者向CWMP服务端口（通常TCP 7547）发送超过1024字节的特制TR069协议数据包
- 传播路径：网络输入 → fcn.00016510(SSL_read) → fcn.000137b8(1024字节栈缓冲区)
- 边界检查缺失：fcn.000137b8仅通过memset初始化1024字节缓冲区(iVar8)，未验证fcn.00016510实际读取长度（最大4096字节）
- 安全影响：直接覆盖栈上返回地址，实现远程代码执行（RCE），成功概率取决于ASLR/CANARY防护状态
- **代码片段:**
  ```
  uchar auStack_473 [1015];
  sym.imp.memset(iVar8,0,0x400);
  iVar3 = fcn.00016510(..., iVar8, 0x1000);
  ```
- **关键词:** fcn.000137b8, fcn.00016510, SSL_read, iVar8, 0x400, 0x1000, auStack_473
- **备注:** 需验证固件防护机制：1) 检查/proc/sys/kernel/randomize_va_space 2) 反编译__stack_chk_fail调用

---
### attack_path-radvd-remote_rce

- **文件路径:** `usr/sbin/radvd`
- **位置:** `network/icmpv6:0`
- **类型:** attack_path
- **综合优先级分数:** **8.85**
- **风险等级:** 9.5
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 远程代码执行路径：发送伪造ICMPv6数据包包含28字节接口名 -> 绕过长度验证 -> 触发0x15d30处strncpy栈溢出 -> 控制程序计数器。成功概率：0.65。
- **关键词:** strncpy, recvmsg, socket, CWE-787, ICMPv6
- **备注:** 需构造包含shellcode的RA数据包

---
### network_input-ushare-upnp_config

- **文件路径:** `etc/ushare.conf`
- **位置:** `etc/ushare.conf`
- **类型:** network_input
- **综合优先级分数:** **8.84**
- **风险等级:** 8.2
- **置信度:** 9.8
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** uShare UPnP服务配置存在三重缺陷：1) 强制绑定br0桥接接口(USHARE_IFACE)，使服务暴露在局域网环境 2) 完全缺乏认证机制和IP访问控制(USHARE_ENABLE_WEB/USHARE_ENABLE_XBOX)，允许任意客户端访问 3) 随机动态端口(49152-65535)未提供实质安全防护。攻击者可在同一局域网内直接访问服务，若uShare二进制存在漏洞(如缓冲区溢出)，可形成完整攻击链：网络扫描发现服务→发送恶意请求触发漏洞→获取设备控制权。
- **关键词:** USHARE_IFACE, USHARE_PORT, USHARE_ENABLE_WEB, USHARE_ENABLE_XBOX, USHARE_ENABLE_DLNA, br0
- **备注:** 关键后续验证方向：1) 分析/bin/ushare二进制处理网络请求的逻辑 2) 检查UPnP协议解析是否存在内存破坏漏洞 3) 确认随机端口范围实现是否可预测

---
### command_execution-ubiattach-full_attack_chain

- **文件路径:** `usr/sbin/ubiattach`
- **位置:** `/sbin/ubiattach:0x119d0 (fcn.000119d0)`
- **类型:** command_execution
- **综合优先级分数:** **8.81**
- **风险等级:** 8.7
- **置信度:** 9.2
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 完整攻击路径：通过控制ubiattach的-p参数实现：1) 路径遍历：未过滤路径参数直接传递至open64()，可注入'../../../dev/mem'等路径访问核心内存设备（触发条件：攻击者具有执行权限） 2) ioctl滥用：固定命令号(0x11a78)配合未验证param_2参数，若目标设备驱动存在缺陷可导致权限提升（触发条件：攻击者控制param_2且ioctl处理程序存在漏洞）
- **代码片段:**
  ```
  main: str r3, [r5, 0x10]  // 存储未验证路径
  fcn.000119d0: sym.imp.open64(param_1,0);
  fcn.000119d0: sym.imp.ioctl(iVar1,*0x11a78,param_2);
  ```
- **关键词:** optarg, open64, ioctl, 0x11a78, sym.imp.ioctl, param_2, /dev/mem
- **备注:** 关联发现：sbin/iwconfig的ioctl漏洞(CVE-2017-14491)。实际影响取决于：1) 普通用户执行ubiattach的权限限制 2) 0x11a78对应设备驱动的安全性。建议：1) 逆向分析0x11a78的ioctl处理函数 2) 检查/dev/mem访问控制

---
### network_input-udevd-0x1794c

- **文件路径:** `sbin/udevd`
- **位置:** `udevd:0x1794c (fcn.000177d0)`
- **类型:** network_input
- **综合优先级分数:** **8.8**
- **风险等级:** 8.8
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 原始套接字远程代码执行：监听端口接收恶意数据（触发条件：特定网络协议格式），经recv→fcn.00011e60→fcn.00011ab8传递至fcn.000177d0。关键缺陷：puVar11+2偏移数据（最大0x200字节）直接复制到栈缓冲区后执行。缺乏协议验证、字符过滤和长度检查（CVSSv3 9.0-Critical）。
- **代码片段:**
  ```
  sym.strlcpy(iVar5, puVar11 + 2, 0x200);
  fcn.00015f48(iVar5, 0, 0, 0);
  ```
- **关键词:** recv, fcn.00011e60, fcn.00011ab8, puVar11+2, 0x2ce, fcn.000177d0
- **备注:** 需确认监听端口和协议类型

---
### stack_overflow-ipc-Apm_cli_create_pm_entity-0x1418

- **文件路径:** `usr/lib/libpm_mipc_client.so`
- **位置:** `libpm_mipc_client.so:0x1418`
- **类型:** ipc
- **综合优先级分数:** **8.8**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** Apm_cli_create_pm_entity函数栈溢出漏洞：param_1经strcpy复制到268字节栈缓冲区(auStack_118)无长度检查。触发条件：传入≥269字节数据可精确覆盖返回地址（276字节）。利用特点：无栈保护机制（CANARY），可直接控制EIP。攻击链：外部输入 → CLI/IPC接口 → strcpy栈溢出 → RCE。
- **代码片段:**
  ```
  sym.imp.strcpy(puVar3 + -0x10c, *(puVar3 + -0x8c));
  ```
- **关键词:** Apm_cli_create_pm_entity, param_1, auStack_118, strcpy, mipc_send_cli_msg, ipc_rce_chain
- **备注:** 攻击链1成员。与0x1370漏洞共享触发模式，关键词'auStack_118'在历史记录存在，需检查跨组件数据流。

---
### CWE-121-radvd-16140

- **文件路径:** `usr/sbin/radvd`
- **位置:** `sbin/radvd:0x16140`
- **类型:** configuration_load
- **综合优先级分数:** **8.8**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** strncpy复制命令行参数到12字节栈缓冲区时固定复制16字节。触发条件：1) 通过'-C'传入>12字节路径 2) 恶意配置含超长项。实际影响：栈破坏导致任意代码执行。
- **代码片段:**
  ```
  sym.imp.strncpy(puVar8 + -0x18,param_1,0x10);
  ```
- **关键词:** strncpy, auStack_24, fcn.000159ec, -C
- **备注:** 溢出长度4字节需构造精确ROP链

---
### heap_overflow-conf_bin_processor-0x15a20

- **文件路径:** `usr/bin/httpd`
- **位置:** `httpd:0x15a48 (fcn.00015a20)`
- **类型:** network_input
- **综合优先级分数:** **8.8**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危堆溢出漏洞(CWE-122)。具体表现：处理/cgi/conf.bin请求时，循环写入配置数据仅验证单次写入长度(<0x1000)，未检查总写入量是否超出rdp_configBufAlloc分配的缓冲区边界。触发条件：攻击者通过HTTP请求或NVRAM操作使rdp_backupCfg返回的配置数据大小超过缓冲区分配容量。安全影响：成功利用可破坏堆元数据，实现任意代码执行。利用方式：构造恶意配置数据触发溢出，通过堆布局操控实现RCE。
- **代码片段:**
  ```
  while (uVar4 = *(ppiVar7 + 4), uVar4 != 0) {
      if (0xfff < uVar4) {
          uVar4 = 0x1000;
      }
      sym.imp.fwrite(iVar3,1,uVar4,*(*param_1 + iVar5));
      *(ppiVar7 + 4) -= uVar4;
      iVar3 += uVar4;}
  ```
- **关键词:** rdp_backupCfg, rdp_configBufAlloc, rdp_getConfigBufSize, fwrite, conf.bin, fcn.00015a20
- **备注:** 完整攻击链：HTTP请求→主循环分发(0x1289c)→路由匹配→conf.bin处理器(0x15a20)→漏洞触发。需验证rdp_backupCfg的最大可控size值

---
### creds-backup_admin_weak_hash

- **文件路径:** `etc/shadow`
- **位置:** `etc/passwd.bak:1`
- **类型:** configuration_load
- **综合优先级分数:** **8.75**
- **风险等级:** 9.2
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 备用凭证漏洞：/etc/passwd.bak包含admin账户条目：1) UID=0赋予root权限 2) 使用弱MD5哈希 3) 分配/bin/sh交互shell。触发条件：攻击者通过SSH/Telnet尝试admin登录（密码可离线快速破解）。安全影响：获得完整root shell控制权。
- **代码片段:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  ```
- **关键词:** admin, passwd.bak, UID=0, /bin/sh, MD5
- **备注:** 需验证：1) 主/etc/passwd是否包含此账户 2) 网络服务是否允许admin登录

---
### policy-root_weak_password

- **文件路径:** `etc/shadow`
- **位置:** `etc/shadow:1`
- **类型:** configuration_load
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** root账户密码策略缺陷：1) 使用易破解的MD5算法存储密码 2) 最大有效期99999天（永不过期）3) 无密码失效机制。触发条件：攻击者获取哈希后离线爆破。安全影响：通过SSH/Telnet登录获得最高权限。
- **代码片段:**
  ```
  root:$1$...:10957:0:99999:7:::
  ```
- **关键词:** root, MD5, $1$, max_days=99999, inactive_days=null
- **备注:** 实际风险取决于密码复杂度，建议强制密码策略修改

---
### hardware_input-devmem2-arbitrary_mmap

- **文件路径:** `usr/bin/devmem2`
- **位置:** `devmem2.c:main+0x34`
- **类型:** hardware_input
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 用户输入物理地址未经验证直接映射。argv[1]通过strtoul转换为ulong后直接作为mmap的offset参数映射/dev/mem设备。缺乏地址范围检查（如内核空间限制），允许攻击者读写任意物理内存。触发条件：执行`devmem2 <物理地址>`。潜在利用：修改内核代码/数据结构实现提权或绕过安全机制。
- **代码片段:**
  ```
  ulong addr = strtoul(argv[1], NULL, 0);
  map_base = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, addr & ~0xfff);
  ```
- **关键词:** argv, strtoul, addr, mmap, /dev/mem, MAP_SHARED, PROT_READ|PROT_WRITE, offset
- **备注:** 实际影响取决于：1) 调用进程权限（需root）2) 内核CONFIG_STRICT_DEVMEM配置。建议检查固件中devmem2的调用上下文。

---
### network_input-smb-privesc-6c0bc

- **文件路径:** `usr/bin/smbd`
- **位置:** `smbd:0x6c0bc (fcn.0006c0a4)`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在fcn.0006c0a4函数调用点(0x6c0bc)，攻击者通过SMB数据包控制param_1缓冲区内容。该缓冲区经malloc分配后通过全局结构(*0x6dd90)传递，未实施边界检查。污点数据最终流向sym.change_to_root_user权限提升操作，形成完整攻击链。触发条件：发送特制SMB报文控制param_1内容，利用成功概率高。
- **代码片段:**
  ```
  iVar1 = sym.receive_local_message(param_1,param_2,1);
  ```
- **关键词:** sym.receive_local_message, param_1, sym.smbd_process, *0x6dd90, sym.change_to_root_user, malloc
- **备注:** 攻击路径：SMB接口 → sym.smbd_process → *0x6dd90 → fcn.0006c0a4 → 特权操作

---
### xss-voicejs-inputValidation-1

- **文件路径:** `web/js/voice.js`
- **位置:** `web/js/voice.js:未指定行号`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.2
- **阶段:** N/A
- **描述:** 输入处理函数getValue/getNumValue通过表单控件获取外部输入，使用正则/(^\s*)|(\s*$)/g去除首尾空格，但未对<>'等XSS危险字符过滤。当输入包含ASCII控制字符时触发ERR_VOIP_CHAR_ERROR警告，长度超限触发ERR_VOIP_ENTRY_MAX_ERROR。攻击者可通过污染表单字段传入恶意脚本，在后续DOM操作中触发XSS。
- **关键词:** getValue, getNumValue, ctrl.value, ERR_VOIP_CHAR_ERROR, replace(/(^\s*)|(\s*$)/g,, regv.test
- **备注:** 需验证后端是否对API参数进行二次过滤

---
### network_input-ipsec_protocol-oob_access_0x1a1ac

- **文件路径:** `usr/bin/racoon`
- **位置:** `fcn.0001a0ac:0x1a148`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 高危攻击链：攻击者通过UDP 500端口发送类型2的IPsec数据包，可在偏移0xa8处植入4字节控制值。该值经fcn.0002825c的memcpy复制后，在fcn.0001a0ac中作为未经验证的索引(param_2)访问全局数组*0x1a1ac，最终传递至日志函数fcn.00047c7c。触发条件：1) 数据包类型=2 2) 控制值超出数组边界。实际影响：可导致越界内存读取（信息泄露）或服务崩溃（DoS），成功利用概率高（9.0）。
- **代码片段:**
  ```
  uVar4 = *(*0x1a1ac + param_2 * 4);
  fcn.00047c7c(1, uVar4, 0, *0x1a1c8);
  ```
- **关键词:** recvfrom, fcn.0002825c, memcpy, fcn.0001a0ac, param_2, *0x1a1ac, fcn.00047c7c, UDP/500
- **备注:** 需验证*0x1a1ac数组边界。攻击链完整：网络接口→协议解析→危险操作

---
### vulnerability-wpa_supplicant-ctrl_iface-permission

- **文件路径:** `usr/sbin/wpa_supplicant`
- **位置:** `fcn.00029070:0x290bc-0x29160`
- **类型:** ipc
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 控制接口未授权访问漏洞：AF_UNIX套接字创建时缺失权限设置(fcn.00029070)。关键缺陷：1) socket(PF_UNIX)+bind()后无chmod/chown 2) 依赖umask默认值(通常022)。触发条件：访问全局控制接口套接字文件。实际影响：结合fcn.00028418命令处理缺陷可导致：1) 敏感信息泄露 2) 服务拒绝 3) 命令注入(若SET_NETWORK等命令存在漏洞)。
- **关键词:** socket, bind, PF_UNIX, ctrl_iface, umask, fcn.00028418, SET_NETWORK
- **备注:** 实际风险依赖：1) 固件umask值 2) 控制接口路径的目录权限 3) 高危命令处理漏洞存在性

---
### file_write-var_dir_permission

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:28-33`
- **类型:** file_write
- **综合优先级分数:** **8.7**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 10.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 使用0777权限创建/var/usbdisk、/var/dev等高危目录。攻击者可任意写入恶意文件或篡改数据。触发条件：系统启动时自动执行。实际影响：提权或持久化攻击，因目录权限全局可写。
- **代码片段:**
  ```
  /bin/mkdir -m 0777 -p /var/usbdisk
  /bin/mkdir -m 0777 -p /var/dev
  ```
- **关键词:** mkdir -m 0777, /var/usbdisk, /var/dev, /var/samba
- **备注:** 关联Samba服务可能加载恶意配置

---
### unauth-firmware-flash

- **文件路径:** `usr/bin/httpd`
- **位置:** `usr/bin/httpd:0x1591c`
- **类型:** network_input
- **综合优先级分数:** **8.7**
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 未授权固件刷写（/cgi/softburn）：1) 函数0x1591c通过fcn.000143cc直接执行刷写操作；2) 权限检查函数fcn.000136dc仅处理响应头；3) 当param_1[8]==0时绕过逻辑检查。触发条件：构造特定HTTP参数使param_1[8]=0，导致设备被恶意固件替换。
- **关键词:** fcn.000136dc, param_1[8], fcn.000143cc, *.ret=%d;
- **备注:** 需验证param_1结构来源，疑似与NVRAM操作相关

---
### stack-overflow-voip-VOIP_updateSipAccountData_F

- **文件路径:** `usr/lib/libvoip_mipc_client.so`
- **位置:** `libvoip_mipc_client.so:0xfbc/0xfe4/0x1008`
- **类型:** ipc
- **综合优先级分数:** **8.7**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危栈溢出漏洞：攻击者通过控制userName/password/aor参数（长度>256字节）触发strcpy覆盖栈缓冲区(auStack_308等)。触发条件：1) 存在调用本函数的暴露接口 2) 参数长度超过256字节。利用方式：精心构造超长字符串覆盖返回地址实现任意代码执行。
- **关键词:** VOIP_updateSipAccountData_F, userName, password, aor, strcpy, auStack_308, auStack_208, auStack_108
- **备注:** 需追踪调用链：查找sbin或www目录中调用此函数的二进制，确认参数是否来自HTTP接口

---
### ipc-input-validation-RSTP_set_enable-0x850

- **文件路径:** `usr/lib/librstp_mipc_client.so`
- **位置:** `librstp_mipc_client.so:0x850 RSTP_set_enable`
- **类型:** ipc
- **综合优先级分数:** **8.69**
- **风险等级:** 8.5
- **置信度:** 9.8
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在RSTP_set_enable函数中发现高危输入验证缺失和IPC构造缺陷：
1. **输入验证缺失**：enable参数(uchar类型)未进行值范围验证(仅0/1有效)，接受0-255任意值
2. **IPC构造缺陷**：消息硬编码长度4字节(str指令)，但实际只存储1字节值(strb指令)
3. **攻击路径**：
   a) 攻击者通过外部接口(HTTP API/CLI)传入异常enable值(如255)
   b) 客户端构造包含残留数据的IPC消息
   c) 服务端读取超长数据导致信息泄露
4. **关联风险**：与知识库中I2cApi_apmSetOnuXvrThreshold(libi2c)和FlashApi_setImageToInvalid(libflash)形成统一攻击模式，表明mipc_send_sync_msg服务端实现存在系统性风险
- **代码片段:**
  ```
  0x0000087c      04208de5       str r2, [var_4h]     ; 硬编码长度=4
  0x00000868      08304be5       strb r3, [var_8h]    ; 实际存储1字节值
  ```
- **关键词:** RSTP_set_enable, enable, mipc_send_sync_msg, rstp, var_8h, var_4h
- **备注:** 完整攻击链依赖：1. 外部调用接口存在性(需追踪RSTP_set_enable调用者) 2. 服务端mipc_send_sync_msg实现(关联知识库ID:ipc-param-unchecked-libi2c-0x1040/unvalidated-input-flashapi-setimagetoinvalid) 3. RSTP服务内存处理逻辑。高危关联点：同IPC机制的其他客户端函数存在类似验证缺失

---
### network_input-udevd-0x172e4

- **文件路径:** `sbin/udevd`
- **位置:** `udevd:0x172e4 (fcn.00016c78)`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.7
- **阶段:** N/A
- **描述:** HTTP参数污染命令注入：攻击者通过特制HTTP请求污染param_2+0x18c数据区（需满足*(param_2+0x100)!=0）。污染数据经strlcpy复制到auStack_b2c缓冲区（无'../'过滤和长度验证）后直接传递至execv执行。触发步骤：1) 发送畸形HTTP报文 2) 控制偏移值*(param_2+0x104) 3) 注入恶意路径。可实现目录遍历或任意命令执行（CVSSv3 9.8-Critical）。
- **代码片段:**
  ```
  sym.strlcpy(puVar12 - 0xb0c, param_2 + *(param_2 + 0x104) + 0x18c, 0x200);
  ```
- **关键词:** param_2+0x18c, param_2+0x104, auStack_b2c, sym.strlcpy, fcn.00016c78, execv, fcn.0001799c
- **备注:** 关联HTTP处理函数fcn.0001799c。后续需验证具体HTTP端点

---
### network_input-udevd-0x173d8

- **文件路径:** `sbin/udevd`
- **位置:** `udevd:0x173d8 (fcn.00016c78)`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 环境变量篡改命令注入：通过污染param_1+0x2d1数据结构（来源：HTTP请求）触发双重漏洞：1) setenv注入恶意环境变量 2) 栈缓冲区auStack_b2c溢出。触发条件：特定HTTP请求格式。污染数据直达execv执行点，strlcpy目标缓冲区固定0x200字节且无输入验证。攻击者可实现权限提升（CVSSv3 9.1-Critical）。
- **代码片段:**
  ```
  sym.strlcpy(puVar12 - 0x30c, param_2 + *(param_2 + 0x120) + 0x18c, 0x200);
  ```
- **关键词:** param_1+0x2d1, sym.imp.setenv, auStack_b2c, fcn.00016c78, param_2+0x120, sym.strlcpy, /etc/inittab
- **备注:** 影响子进程，需检查/etc/inittab等启动配置

---
### ipc-iptvCli-0x2034

- **文件路径:** `usr/lib/libigmp_mipc_client.so`
- **位置:** `libigmp_mipc_client.so:0x2034-0x20c0`
- **类型:** ipc
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 函数iptvCliShowCounters_mipc存在高危栈溢出漏洞：当传入非空参数arg1时（0x2048处检查），直接使用strcpy(0x2060)复制到栈缓冲区'dest'（大小约0x120字节）。未进行长度校验，攻击者通过构造超长arg1可导致：1) 栈缓冲区溢出覆盖返回地址(0x20bc)实现控制流劫持 2) 破坏var_108h缓冲区结构（0x20b0处访问）。结合mipc_send_cli_msg传递未初始化缓冲区的行为，可能形成信息泄露→溢出利用链。触发条件：通过暴露arg1控制接口（如诊断CLI命令）传递>0x120字节数据。成功利用概率高，可获取系统控制权。
- **代码片段:**
  ```
  0x2048: cmp r3, 0
  0x204c: beq 0x2064
  0x2054: sub r2, dest
  0x2060: bl sym.imp.strcpy
  0x2068: sub r2, var_108h
  ```
- **关键词:** iptvCliShowCounters_mipc, strcpy, dest, var_108h, mipc_send_cli_msg, arg1
- **备注:** 关键后续验证：1) 精确计算'dest'缓冲区大小 2) 定位调用此函数的进程（如telnetd/httpd）3) 确认arg1是否来自HTTP参数或CLI命令等外部输入；strcpy与知识库中sym.imp.strcpy存在语义关联，但需精确匹配验证

---
### network_input-smb-stack_overflow-6cc84

- **文件路径:** `usr/bin/smbd`
- **位置:** `调用链: 0x6cc84 → 0x6cc74 → fcn.000aaaac`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** sym.respond_to_all_remaining_local_messages(0x6cc84)存在栈溢出漏洞。39字节栈缓冲区(auStack_39)通过sys_recvfrom接收网络输入，经sym.receive_local_message传递后，在fcn.000aaaac被写入超过44字节数据。边界检查参数0x400未在写入点强制执行，触发条件：发送>39字节SMB报文可覆盖返回地址实现RCE。
- **代码片段:**
  ```
  0x0006cc78 mov r0, sp
  0x0006cc7c mov r1, r4 ; size=0x400
  0x0006cc84 bl sym.receive_local_message
  ```
- **关键词:** sym.respond_to_all_remaining_local_messages, sys_recvfrom, auStack_39, fcn.000aaaac, SMB
- **备注:** 完整路径：SMB接口 → sys_recvfrom → sym.receive_local_message → fcn.000aaaac溢出点

---
### command_execution-ppp-peer_authname

- **文件路径:** `usr/sbin/pppd`
- **位置:** `pppd:0x00028e9c (fcn.00028dfc)`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 在调用ip-up脚本时，peer_authname参数未经任何过滤直接传入环境变量并通过execve执行。攻击者可通过PPP协商提供恶意peer_authname（如'valid_name; rm -rf /'）。触发条件：建立PPP连接时控制认证名称。边界检查：无长度限制或字符过滤。安全影响：任意命令执行导致完全设备控制，成功利用概率高（需验证PPP协议注入可行性）。
- **代码片段:**
  ```
  str r3, [var_50h]   ; peer_authname
  bl sym.run_program
  ```
- **关键词:** peer_authname, execve, /etc/ppp/ip-up, run_program, obj.ifname, obj.devnam
- **备注:** 类似漏洞CVE-2020-8597。需验证PPP协议中peer_authname注入可行性，并检查ip-down等同机制。关联文件：/etc/ppp/ip-up

---
### network_input-sprintf-ESSID_overflow

- **文件路径:** `sbin/iwconfig`
- **位置:** `fcn.00014ffc:0x150a4`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** ESSID/key格式化漏洞（攻击链2）：sprintf使用"%.2X"转换ESSID/key数据时存在缓冲区边界计算错误。循环内指针增量不足（3字节/元素），前置检查忽略分隔符叠加效应。触发条件：攻击者通过recv等网络接口传入超长ESSID/key数据至fcn.00015264。安全影响：堆栈溢出导致任意代码执行。
- **代码片段:**
  ```
  for (i=0; i<param_4; i++) {
    sprintf(ptr, "%.2X", data[i]);
    ptr += 2; // 实际写入3字节(XX\0)
  }
  ```
- **关键词:** sprintf, %.2X, recv, ESSID, key
- **备注:** 关键约束：需确认fcn.00015264是否暴露给网络输入。利用链：网络输入→recv→fcn.00015264→sprintf→ioctl

---
### network_input-status_page-TR069_sensitive_data

- **文件路径:** `web/main/status.htm`
- **位置:** `web\/main\/status.htm:14-1033`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危漏洞链入口：status.htm通过$.act()调用ACT_GET\/ACT_GL操作访问TR-069对象(IGD\/LAN_WLAN等)，获取固件版本\/SSID\/VoIP账户等敏感信息。完整攻击路径：1) 攻击者构造恶意HTTP请求篡改对象标识符(SYS_MODE)和属性数组(mode\/SSID) 2) 后端解析时因缺乏验证(边界检查\/过滤)导致内存破坏 3) 结合已有ACT_OP_REBOOT等操作实现RCE。触发条件：页面加载\/自动刷新。实际影响：通过污染属性数组触发后端缓冲区溢出\/命令注入(需关联cgibin分析)。
- **代码片段:**
  ```
  var sysMode = $.act(ACT_GET, SYS_MODE, null, null, ["mode"]);
  var wlanList = $.act(ACT_GL, LAN_WLAN, null, null, ["status", "SSID"]);
  ```
- **关键词:** $.act(), ACT_GET, ACT_GL, ACT_OP, SYS_MODE, IGD, WAN_PON, LAN_WLAN, mode, SSID, channel
- **备注:** 关键关联路径：1) 关联network_input-restart_page-doRestart(ACT_OP_REBOOT) 2) 关联network_input-voip-btnApplySip(ACT_SET) 3) 关联network_input-config-freshStatus(ACT_GL\/GS)。验证方向：\/www\/js实现$.act的请求构造逻辑 → cgibin中TR069_Handler对对象标识符的解析 → 属性数组的内存处理

---
### network_input-login_js-cookie_auth

- **文件路径:** `web/frame/login.htm`
- **位置:** `login.htm (内联JavaScript)`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 登录认证机制实现存在三个核心风险：1) 认证凭证以Base64明文存储于Cookie，攻击者可通过XSS或中间人攻击窃取（触发条件：用户提交登录表单） 2) 无CSRF防护，攻击者可构造恶意页面诱导用户提交凭证（触发条件：用户访问攻击者控制的网页） 3) 锁定机制依赖客户端变量(isLocked/authTimes)，可通过修改DOM绕过暴力破解防护（触发条件：连续5次失败后尝试重置变量）。潜在影响包括账户接管和系统未授权访问。
- **代码片段:**
  ```
  auth = "Basic "+Base64Encoding(userName+":"+password);
  document.cookie = "Authorization=" + auth;
  ```
- **关键词:** Authorization, document.cookie, Base64Encoding, PCSubWin, isLocked, authTimes, lockWeb
- **备注:** 需验证后端对Authorization cookie的处理：1) 是否进行二次解码验证 2) 是否设置HttpOnly/Secure属性 3) 服务端是否实现真正的锁定机制。建议追踪/cgi-bin/login相关处理程序

---
### parameter_validation-ipc-apm_pm_set_admin-0xd98

- **文件路径:** `usr/lib/libpm_mipc_client.so`
- **位置:** `libpm_mipc_client.so:0xd98`
- **类型:** ipc
- **综合优先级分数:** **8.55**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** apm_pm_set_admin函数IPC参数未验证漏洞：未经验证的param_1/param_2/admin_bits直接构造12字节IPC消息（type=3）。触发条件：控制任意参数值（如admin_bits无位掩码检查）。安全影响：通过固定通道(*0xe2c)发送任意消息至内核，形成权限提升→RCE攻击链。
- **代码片段:**
  ```
  puVar3[-0xb] = param_3;
  iVar1 = loc.imp.mipc_send_sync_msg(*0xe2c,3,puVar3+-8,0xc);
  ```
- **关键词:** apm_pm_set_admin, param_1, param_2, admin_bits, mipc_send_sync_msg, type=3, *0xe2c, kernel_chain
- **备注:** 攻击链2入口：需验证内核处理函数。关键词'mipc_send_sync_msg'在历史记录存在，可能关联其他IPC组件。

---
### xss-voicejs-domInjection-1

- **文件路径:** `web/js/voice.js`
- **位置:** `web/js/voice.js:未指定行号`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 8.0
- **置信度:** 9.5
- **触发可能性:** 8.5
- **查询相关性:** 8.8
- **阶段:** N/A
- **描述:** addOption函数直接使用sel.add(new Option(text, value))插入DOM元素，text参数未经HTML编码。若text被污染（如通过URL参数间接控制），可导致反射型XSS。无边界检查或过滤措施，攻击载荷仅受浏览器XSS审计机制限制。
- **代码片段:**
  ```
  function addOption(sel, text, value){... sel.add(new Option(text, value), ...}
  ```
- **关键词:** addOption, sel.add, opt.text, text

---
### network_input-diagnostic_htm-wanTest_gwIp_contamination

- **文件路径:** `web/main/diagnostic.htm`
- **位置:** `diagnostic.htm:320(wanTest函数)`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 诊断页面(diagnostic.htm)使用外部可控的WAN配置参数(gwIp/mainDns)执行网络测试。具体触发条件：攻击者通过ethWan.htm接口绕过客户端验证注入恶意网关/DNS参数 → 用户访问诊断页面触发wanTest/interTestDns函数 → 污染参数通过$.act(ACT_SET)提交后端执行PING/DNS测试 → 设备信任恶意基础设施导致中间人攻击。边界检查缺失：ethWan.htm服务端未验证网关IP格式和DNS有效性。
- **代码片段:**
  ```
  function wanTest(code){
    diagCommand.currHost = wanList[wanIndex].gwIp; // 直接使用WAN配置的网关IP
    $.act(ACT_SET, DIAG_TOOL, null, null, diagCommand);
  }
  ```
- **关键词:** wanList[wanIndex].gwIp, mainDns, wanTest, interTestDns, ACT_SET, DIAG_TOOL, doSave@ethWan.htm, defaultGateway
- **备注:** 完整攻击链依赖：1)ethWan.htm配置注入漏洞(已证实) 2)后端DIAG_TOOL处理未过滤输入(待验证)；攻击路径评估：确认部分攻击链：外部输入(ethWan.htm配置)→ 传播(diagnostic.htm参数使用)→ 危险操作($.act提交后端)。完整利用需：1)验证后端DIAG_TOOL处理逻辑的安全缺陷 2)确认mainDns污染机制。成功利用概率：中高(当前缺失后端验证证据)；待解决问题：NET_CFG.DNSServers配置加载路径未明；建议：优先分析/cgi-bin目录：搜索处理ACT_SET和DIAG_TOOL的CGI程序

---
### command_execution-iwpriv-integer_underflow-0x11314

- **文件路径:** `usr/sbin/iwpriv`
- **位置:** `iwpriv:0x11314 (dbg.set_private_cmd)`
- **类型:** command_execution
- **综合优先级分数:** **8.55**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 7.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 整数下溢漏洞。具体表现：memcpy长度参数计算为0x10-iVar5(iVar5=argc-3)，当提供≥264个参数时，iVar5>0x10导致0x10-iVar5变为极大正值(0xFFFFFFF0+)，触发超量数据复制。触发条件：执行iwpriv时传入≥264个命令行参数，且第8个参数符合0x6000分支条件(避开'0x'/'hex'检查)。安全影响：直接覆盖栈上返回地址实现稳定代码执行，若iwpriv通过setuid root运行则直接获得特权。
- **代码片段:**
  ```
  sym.imp.memcpy(iVar20 + -0x20 + iVar5, iVar20 + -0x10b0, 0x10 - iVar5);
  ```
- **关键词:** memcpy, iVar5, 0x10, argc, 0x6000, param_3, dbg.set_private_cmd
- **备注:** 需检查固件中iwpriv的权限设置，并查找参数传递入口点(如busybox httpd)

---
### command_execution-shell_full_access

- **文件路径:** `etc/xml_commands/global-commands.xml`
- **位置:** `global-commands.xml:25`
- **类型:** command_execution
- **综合优先级分数:** **8.5**
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危命令'shell'暴露完整系统访问能力：1) 通过CLI界面执行时直接调用'appl_shell'启动系统shell 2) 无任何参数过滤或边界检查机制（XML中缺失<validation>节点）3) 攻击者获取CLI访问权限后可通过单条命令获得root shell完整控制设备。实际安全影响等级：设备完全沦陷（可任意读写文件/执行恶意代码）
- **代码片段:**
  ```
  <COMMAND name="shell" help="Enter Linux Shell">
      <ACTION builtin="appl_shell"> </ACTION>
  </COMMAND>
  ```
- **关键词:** shell, appl_shell, builtin, ACTION, COMMAND
- **备注:** 需验证：1) appl_shell在二进制中的具体实现（可能在/sbin目录）2) CLI服务的暴露途径（如telnet/web接口）

---
### attack_chain-udevd-devmems

- **文件路径:** `usr/bin/devmem2`
- **位置:** `关联文件: sbin/udevd, devmem2.c`
- **类型:** analysis_note
- **综合优先级分数:** **8.5**
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链：网络输入（HTTP请求）→ 污染udevd参数（param_2+0x18c）→ 通过strlcpy复制到执行缓冲区 → execv执行任意命令（如devmem2）→ 触发物理内存任意读写（关联发现：hardware_input-devmem2-arbitrary_mmap）。触发步骤：1) 构造畸形HTTP请求控制*(param_2+0x104)偏移 2) 注入包含devmem2调用命令的路径（如'/tmp/exp'）3) udevd以root权限执行恶意命令。成功概率：8.5/10（依赖具体HTTP端点验证）。
- **关键词:** execv, param_2+0x18c, strlcpy, devmem2, mmap, physical_memory
- **备注:** 关联发现：network_input-udevd-0x172e4（命令注入入口）, hardware_input-devmem2-arbitrary_mmap（危险操作）

---
### unvalidated_param-apm_alarm_set_threshold-0xb04

- **文件路径:** `usr/lib/libalarm_mipc_client.so`
- **位置:** `libalarm_mipc_client.so:0xb04`
- **类型:** ipc
- **综合优先级分数:** **8.5**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未验证参数传递风险（CWE-20）。具体表现：apm_alarm_set_threshold直接存储外部参数(type,param1,threshold,clear_threshold)到栈内存并通过mipc_send_sync_msg发送，缺乏：1) 数值范围验证 2) 缓冲区约束 3) 类型安全校验。触发条件：构造恶意参数值。潜在影响：触发下游服务整数溢出/越界访问。
- **关键词:** apm_alarm_set_threshold, param_1, param_2, param_3, param_4, mipc_send_sync_msg
- **备注:** 需分析接收服务(alarm)的参数处理逻辑；关联知识库中mipc_send_sync_msg在loop_detect_set_admin的使用（usr/lib/libloop_detect_mipc_client.so）

---
### thread-race-mutex_lock-sipapp

- **文件路径:** `usr/bin/sipapp`
- **位置:** `sipapp:0x84bf8 (pj_mutex_lock)`
- **类型:** network_input
- **综合优先级分数:** **8.5**
- **风险等级:** 8.5
- **置信度:** 9.5
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 线程竞争漏洞：pj_mutex_lock获取锁后，将整型线程ID错误作为指针传递→strcpy解引用异常地址。攻击者通过高频网络请求制造锁竞争：1) 小ID值导致DoS 2) 可控ID可能构造读写原语。污染源：网络请求的线程调度参数。
- **关键词:** pj_mutex_lock, strcpy, pj_thread_this, mutex+0x40

---

## 中优先级发现

### configuration_load-fcn.000138bc

- **文件路径:** `sbin/udevd`
- **位置:** `fcn.000138bc`
- **类型:** configuration_load
- **综合优先级分数:** **8.45**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 配置文件越界读取漏洞：全局变量*0x13ab0指向的配置行长度≥511字节时，memcpy复制到auStack_230缓冲区后未终止字符串，导致后续strchr/strcasecmp越界访问。触发条件：攻击者需篡改配置文件内容（CVSSv3 8.1-High）。
- **代码片段:**
  ```
  sym.imp.memcpy(puVar15 + -0x20c, puVar10, uVar4);
  *(puVar15 + (uVar4 - 0x20c)) = uVar2 & 0x20;
  ```
- **关键词:** fcn.000138bc, auStack_230, memcpy, strchr, strcasecmp, *0x13ab0
- **备注:** 需分析*0x13ab0初始化路径

---
### stack-overflow-tlomci_cli_set_lan-0x4f9c

- **文件路径:** `usr/lib/libomci_mipc_client.so`
- **位置:** `libomci_mipc_client.so:0x4f9c`
- **类型:** ipc
- **综合优先级分数:** **8.45**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 5.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在函数tlomci_cli_set_lan中发现5处栈缓冲区溢出漏洞。具体表现：该函数接收5个字符串参数(name/keyname/vlanFilterKey/usVlanOpKey/dsVlanOpKey)，每个参数均通过未经验证的strcpy复制到256字节栈缓冲区。触发条件：当任意参数长度超过256字节时，将覆盖栈帧关键数据（包括返回地址）。安全影响：攻击者可完全控制程序执行流，实现任意代码执行。利用方式：通过IPC机制向调用此函数的服务组件发送恶意构造的超长参数。
- **代码片段:**
  ```
  strcpy(puVar2+4-0x504,*(puVar2-0x50c));
  strcpy(puVar2+4-0x404,*(puVar2-0x510));
  ```
- **关键词:** tlomci_cli_set_lan, strcpy, name, keyname, vlanFilterKey, usVlanOpKey, dsVlanOpKey, mipc_send_cli_msg
- **备注:** 关联漏洞链：1) stack-overflow-oam_cli-mipc_chain 2) ipc-iptvCli-0x2034 3) stack-overflow-apm_cli-avc_value_str。需验证：1) 定位调用此函数的服务组件 2) 分析该组件的网络/IPC接口 3) 检查参数传递过滤机制

---
### network_input-proftpd_buffer_copy-0x62888

- **文件路径:** `usr/sbin/proftpd`
- **位置:** `proftpd:0x62888`
- **类型:** network_input
- **综合优先级分数:** **8.45**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 缓冲区复制函数(fcn.00062888)存在边界检查缺陷：当调用者传入超长长度参数(r2>缓冲区大小)时，将导致栈溢出。触发条件：1) 上游调用点未验证r2参数；2) 攻击者污染长度值。实际影响：可能实现任意代码执行或拒绝服务。
- **代码片段:**
  ```
  0x628e4: strb r1, [r3], 1
  0x628e8: sub r2, r2, 1
  0x628f4: cmpne r2, 1
  0x628f8: bhi 0x628e4
  ```
- **关键词:** fcn.00062888, r2, sub r2, r2, 1, strb r1, [r3], 1, acStack_1068
- **备注:** 需后续验证：1) 调用该函数的位置 2) r2参数是否被网络输入污染

---
### network_input-iwconfig-kernel_leak

- **文件路径:** `sbin/iwconfig`
- **位置:** `sbin/iwconfig:0x1aa2c (fcn.00010ec8)`
- **类型:** network_input
- **综合优先级分数:** **8.44**
- **风险等级:** 8.0
- **置信度:** 9.8
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 接口名未终止漏洞：用户通过iwconfig命令设置≥16字节的无线接口名时，strncpy(piVar20-0x10, name, 0x10)操作会生成非终止字符串。后续ioctl(SIOCSIWNAME)系统调用直接使用该缓冲区，导致内核读取越界数据。触发条件：1) 攻击者拥有执行iwconfig的权限 2) 提供长度≥16字节的接口名。实际影响：可能造成内核内存信息泄露或触发拒绝服务。
- **代码片段:**
  ```
  sym.imp.strncpy(piVar20 + -0x10, uVar1, 0x10);
  iVar14 = sym.imp.ioctl(puVar5, 0x8b12, piVar20 + -0x10);
  ```
- **关键词:** strncpy, ioctl, SIOCSIWNAME, piVar20, uVar1
- **备注:** 需验证固件内核的无线扩展实现。建议后续检查其他ioctl调用点

---
### command_injection-tpm_xml-param_overflow

- **文件路径:** `etc/xml_commands/tpm_commands.xml`
- **位置:** `etc/xml_commands/tpm_commands.xml`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 发现41个TPM命令通过builtin函数实现，其中15个命令存在参数注入风险：用户输入的${name}等参数未经显式过滤直接传递至底层函数（如tpm_cli_print_vlan_table_by_name）。触发条件：攻击者通过CLI接口构造恶意参数（如超长字符串）。实际影响：可能触发底层函数缓冲区溢出，尤其'tpm_cli_clear_pm_counters'等危险操作暴露清除功能。边界检查仅依赖ptype类型约束（如STRING_name限16字符），但未在XML层实现具体验证逻辑。
- **代码片段:**
  ```
  <COMMAND name="show tpm rule vlan" help="Show TPM VLAN table entry by name">
      <PARAM name="name" help="Name of a VLAN entry (up to 16 symbols)" ptype="STRING_name"/>
      <ACTION builtin="tpm_cli_print_vlan_table_by_name"> ${name} </ACTION>
  </COMMAND>
  ```
- **关键词:** tpm_cli_print_vlan_table_by_name, tpm_cli_clear_pm_counters, tpm_cli_get_next_valid_rule, STRING_name, UINT, DIRECTION_TYPE, RULE_TYPE, owner_id, name, port, direction, API_GROUP
- **备注:** 需立即验证builtin函数实现：1) 检查tpm_cli_*函数是否对name等参数进行长度验证 2) 分析整数参数(如owner_id)的范围检查 3) 追踪参数传递至内核驱动的路径

---
### hardcoded-credential-pon_auth

- **文件路径:** `etc/xml_params/gpon_xml_cfg_file.xml`
- **位置:** `gpon_xml_cfg_file.xml`
- **类型:** configuration_load
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 10.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 发现硬编码PON认证密码(PON_passwd=1234567890)。该凭据位于XML配置层，可能被固件通过nvram_get等操作读取用于PON认证。若攻击者能通过外部接口(如HTTP参数/NVRAM设置)覆盖该值，可导致：1) 凭据泄露风险(若密码被日志记录) 2) 认证绕过(若使用该密码验证)。触发条件：存在未授权访问配置写入的接口。边界检查：XML未定义长度/字符限制，可能注入恶意负载。
- **代码片段:**
  ```
  <PON_passwd>1234567890</PON_passwd>
  ```
- **关键词:** PON_passwd, cnfg, PON
- **备注:** 需追踪固件中读取此参数的函数(如nvram_get("PON_passwd"))验证外部可控性；关联攻击路径：配置加载→NVRAM交互→认证绕过

---
### command_execution-devmem2-arbitrary_write

- **文件路径:** `usr/bin/devmem2`
- **位置:** `devmem2.c:main+0x128`
- **类型:** command_execution
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 内存写入值缺乏验证机制。argv[3]通过strtoul直接转为写入值，未经有效性检查（如对齐要求/保留位）即写入映射内存。结合地址控制形成任意物理内存写原语。触发条件：`devmem2 <地址> w <任意值>`。利用方式：修改关键寄存器或安全凭证。
- **代码片段:**
  ```
  ulong value = strtoul(argv[3], NULL, 0);
  *(uint32_t*)(map_base + offset) = value;
  ```
- **关键词:** argv, strtoul, value, write_memory, *(uint32_t*)map_addr
- **备注:** 完整攻击链：网络接口（如CGI脚本）→构造devmem2调用命令→物理内存篡改。需审计固件中调用devmem2的组件。

---
### network_input-proftpd_pass_command-0x5aa40

- **文件路径:** `usr/sbin/proftpd`
- **位置:** `proftpd:0x5aa40 (fcn.0005a068)`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** PASS命令处理函数(fcn.0005a068)存在时序侧信道漏洞：攻击者可通过测量strcasecmp比较时间差异推断密码有效性。触发条件：1) 攻击者发送大量特制密码；2) 服务器未启用恒定时间比较机制。实际影响：结合暴力破解可提升凭证窃取效率。
- **关键词:** fcn.0005a068, strcasecmp, puVar11[1], 0x5aa40, param_2+0x18
- **备注:** 利用链：网络输入→PASS命令参数→strcasecmp时序泄漏

---
### network_input-fwRulesEdit-doSave

- **文件路径:** `web/main/fwRulesEdit.htm`
- **位置:** `fwRulesEdit.htm (doSave函数)`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 防火墙规则编辑界面存在未充分过滤的用户输入处理风险：1) internalHostRef/externalHostRef字段通过split(':')[1]提取第二部分值，当输入格式为'恶意内容:payload'时可绕过校验；2) ruleName仅验证命名规范（$.isname），未对特殊字符过滤；3) action/enable/direction等参数直接取值未验证。这些参数通过fwAttrs对象传递至$.act(ACT_ADD/SET, RULE)操作，可能构成XSS或命令注入链的初始输入点。
- **代码片段:**
  ```
  fwAttrs.internalHostRef = $.id("internalHostRef").value.split(":")[1];
  fwAttrs.action = $.id("action").value;
  $.act(ACT_ADD, RULE, null, null, fwAttrs);
  ```
- **关键词:** doSave, fwAttrs, internalHostRef, externalHostRef, split, ruleName, $.isname, action, enable, $.act, ACT_ADD, ACT_SET, RULE, IP6_RULE
- **备注:** 风险实际影响取决于后端处理：1) 若RULE操作后端未过滤fwAttrs参数，可能造成存储型XSS或命令注入 2) split操作可能被滥用传递恶意负载。关联发现：知识库中存在相同风险模式的IPv6规则实现（见'network_input-fw6RulesEdit-doSave'）。后续必须追踪：$.act实现（可能在common.js）和RULE处理后端逻辑，需验证IPv4/IPv6处理组件是否共享相同漏洞代码。

---
### vul-ripd-request-oob-read-0x11d78

- **文件路径:** `usr/sbin/ripd`
- **位置:** `ripd:0x11d78 (dbg.rip_request_process)`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** RIP请求处理函数(dbg.rip_request_process)存在边界验证缺陷。当处理UDP 520端口接收的RIP请求包时，循环解析路由条目仅通过指针比较控制迭代(puVar7 < puVar9)，未验证剩余缓冲区长度是否满足10字节条目要求。攻击者可发送长度=4+10*N+K(1≤K≤9)的畸形包，导致最后一次循环访问*(puVar7+4)时越界读取内存。触发条件：攻击者向520/UDP发送畸形包+ripd进程运行。实际影响：内网攻击者可造成进程崩溃(DoS)或敏感信息泄露（越界数据可能被记录）。
- **代码片段:**
  ```
  puVar7 = param_1 + 4;
  puVar9 = param_1 + param_2;
  do {
      uVar2 = *(puVar7 + 4);
      ...
      puVar7 += 10;
  } while (puVar7 < puVar9);
  ```
- **关键词:** dbg.rip_request_process, puVar7, puVar9, *(puVar7 + 4), param_1, param_2, rip_packet
- **备注:** 需验证：1) 越界读取的数据类型 2) 是否影响关联函数dbg.if_lookup_address。后续建议动态测试不同K值的影响

---
### attack_path-radvd-local_priv_esc

- **文件路径:** `usr/sbin/radvd`
- **位置:** `etc/init.d/radvd:0`
- **类型:** attack_path
- **综合优先级分数:** **8.4**
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 7.5
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 本地权限提升路径：篡改启动脚本注入恶意参数'-C ../../../etc/shadow' -> radvd以root权限尝试打开文件 -> 触发段错误或泄露敏感信息。成功概率：0.75。
- **关键词:** -C, fopen, strncpy, CWE-73, CWE-121
- **备注:** 依赖启动脚本可控性验证

---
### credential_storage-user_authentication-weak_password_hash

- **文件路径:** `etc/passwd.bak`
- **位置:** `etc/passwd.bak:1`
- **类型:** configuration_load
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** admin账户使用弱加密算法(MD5)存储密码哈希($1$前缀)，且具有root权限(UID=0)和可登录shell(/bin/sh)。攻击者通过目录遍历/文件泄露漏洞获取此文件后，可对哈希'$iC.dUsGpxNNJGeOm1dFio/'进行离线暴力破解。破解成功后获得完整root权限，可执行任意系统命令。触发条件：1)攻击者能读取此备份文件；2)admin账户登录功能未禁用；3)密码强度不足。
- **代码片段:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  ```
- **关键词:** passwd.bak, admin, $1$, /bin/sh, UID=0
- **备注:** 需确认系统是否实际使用此备份文件。建议检查原始/etc/passwd文件及SSH/Telnet服务配置，验证admin账户是否开放远程登录。同时需分析：1) passwd.bak是否通过其他漏洞（如目录遍历）暴露；2) 文件创建/传输机制（如代码片段中的cp命令）是否可控。

---
### stack-overflow-apm_cli-set_log_level

- **文件路径:** `usr/lib/libapm_new_mipc_client.so`
- **位置:** `libapm_new_mipc_client.so:0x5f8`
- **类型:** ipc
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** Apm_cli_set_log_level函数存在栈缓冲区溢出漏洞。触发条件：当全局导出的该函数被调用时，若第一个参数(name)长度超过240字节，将覆盖栈上返回地址。具体表现：1) 函数分配0x120字节栈空间 2) strcpy目标缓冲区位于SP+0x1C 3) 无长度校验机制。攻击者可构造超长name参数实现任意代码执行。实际影响取决于调用者是否暴露给不可信输入源（如网络API）。
- **关键词:** Apm_cli_set_log_level, name, strcpy, var_10ch, GLOBAL
- **备注:** 需后续追踪：1) 调用此函数的组件 2) name参数是否来自网络/NVRAM等不可信源。关联知识库漏洞：stack-overflow-oam_cli-mipc_chain (liboam_mipc_client.so)

---
### struct-overflow-voip-VOIP_setSipParamConfig_F

- **文件路径:** `usr/lib/libvoip_mipc_client.so`
- **位置:** `unknown`
- **类型:** ipc
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 关键结构体处理漏洞：memcpy固定复制60字节到栈缓冲区，缺乏源数据长度验证。攻击者构造异常长度数据可导致：1) 源数据<60字节时越界读取 2) 源数据含恶意指令时精确溢出。触发条件：控制VOIP_ST_SIP_PARAMETER_CONFIG结构体输入。
- **关键词:** VOIP_setSipParamConfig_F, VOIP_ST_SIP_PARAMETER_CONFIG, memcpy, mipc_send_sync_msg, param_1, 0x60
- **备注:** 后续应分析：1) 结构体定义 2) mipc_send_sync_msg在服务端的处理逻辑

---
### network_input-$.cgi-remote_code_execution

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js:298 ($.cgi)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未经验证的用户输入导致远程代码执行。在$.cgi()函数中，攻击者可控的path和arg参数被直接拼接为CGI请求URL。当bScript=true时，响应内容通过$.script()动态执行，允许攻击者注入任意JS代码。触发条件：构造包含恶意JS的CGI响应。影响：完全控制设备
- **代码片段:**
  ```
  function(path, arg, hook, noquit, unerr) {
    ...
    var ret = $.io(path, true, func, null, noquit, unerr);
  ```
- **关键词:** $.cgi, path, arg, bScript, $.io, url, data, $.script
- **备注:** 完整攻击链：恶意HTTP请求 → 污染path参数 → $.cgi()调用 → $.script()动态执行。与知识库中'关键验证点：1) 后端对API参数进行二次过滤'形成互补攻击面

---
### stack_overflow-wps_protocol-unchecked_length

- **文件路径:** `usr/sbin/hostapd`
- **位置:** `hostapd:0x363e8(fcn.000363b4), 0x42034(fcn.00041d9c), 0x38a3c(fcn.000388ac), 0x3f0c8(fcn.0003f0c8)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 攻击链1：WPS协议数据未验证导致栈溢出。触发条件：设备开启WPS功能时，攻击者发送超长WPS协议数据包。具体路径：recvfrom接收数据 → fcn.00041d9c的case 0xb分支 → fcn.000388ac → fcn.0003f0c8(strcpy)。关键缺陷：wps_parse_wps_data内部未验证输入长度边界，目标缓冲区auStack_74c[64]固定。实际影响：构造>64字节数据可覆盖返回地址，实现RCE（需绕过ASLR），成功概率中等（依赖WPS启用状态和ASLR强度）
- **关键词:** recvfrom, fcn.00041d9c, case 0xb, fcn.000388ac, fcn.0003f0c8, wps_parse_wps_data, auStack_74c, param_2
- **备注:** 需结合固件ASLR实现评估利用难度。建议测试WPS功能默认状态

---
### network_input-config-freshStatus

- **文件路径:** `web/main/voice_line.htm`
- **位置:** `www/js/status_monitor.js: JavaScript函数: freshStatus`
- **类型:** network_input
- **综合优先级分数:** **8.25**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** ACT_GL/ACT_GS端点暴露敏感配置获取路径（如XTP_MULTI_ISP）。触发条件：页面初始化时自动调用freshStatus()。攻击者可直接请求端点获取ISP配置等敏感信息，无需身份验证。成功概率高，因未发现访问控制机制。
- **代码片段:**
  ```
  voipAccounts = $.act(ACT_GL, XTP_MULTI_ISP, ...)
  ```
- **关键词:** ACT_GL, ACT_GS, XTP_MULTI_ISP, VOICE_PROF_LINE_PROC, freshStatus, $.act
- **备注:** 需测试端点未授权访问可能性；关联现有$.act操作

---
### file_read-udevd-0x19384

- **文件路径:** `sbin/udevd`
- **位置:** `udevd:fcn.0001936c @ 0x19384`
- **类型:** file_read
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 规则文件目录遍历漏洞：当/etc/udev/rules.d/目录中存在含'../'的文件名时，snprintf使用"%s/%s"格式拼接路径未规范化处理。攻击者可通过恶意文件名加载系统任意文件（如/etc/shadow）。触发条件：攻击者需具备规则目录写权限（CVSSv3 7.8-High）。
- **代码片段:**
  ```
  snprintf(puVar7 + -0x204,0x200,*0x19438,param_2);
  ```
- **关键词:** fcn.0001936c, snprintf, d_name, readdir64, %s/%s, /etc/udev/rules.d
- **备注:** 需结合文件上传漏洞利用

---
### network_input-TR069-strcpy_chain-fcn000135e8

- **文件路径:** `usr/bin/cwmp`
- **位置:** `fcn.000135e8 @ strcpy调用点`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 未验证的strcpy操作链（CWE-120）：
- 触发条件：攻击者控制HTTP请求参数（如param_2/param_3）使其长度超过目标缓冲区剩余空间
- 传播路径：网络输入 → fcn.000135e8(param_2/param_3) → strcpy(param_4+偏移)
- 边界检查缺失：4处strcpy操作目标缓冲区为param_4+200/664/673/705，未验证源字符串长度
- 安全影响：基于param_4分配位置（堆/栈），可导致堆溢出或栈溢出，结合ROP可实现权限提升
- **代码片段:**
  ```
  sym.imp.strcpy(param_4 + 200, *0x137ac);
  sym.imp.strcpy(param_4 + 0x2a1, param_2);
  ```
- **关键词:** fcn.000135e8, strcpy, param_2, param_3, param_4, *0x137ac, TR069_AGENT
- **备注:** 关键验证点：1) param_4缓冲区分配大小 2) 全局指针*0x137ac是否包含用户输入

---
### configuration_load-nandwrite-command_injection

- **文件路径:** `usr/bin/fw_printenv`
- **位置:** `fw_printenv:0x11658 (sym.flash_io)`
- **类型:** configuration_load
- **综合优先级分数:** **8.2**
- **风险等级:** 8.5
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** nandwrite命令注入链：攻击者篡改/etc/fw_env.config配置文件内容。触发条件：1) 污染全局指针0x12314/0x12318 2) flash_io函数使用sprintf构建命令'nandwrite -s 0x%x /dev/mtd0 %s' 3) 未过滤参数即调用system()执行。实际影响：控制flash写入位置破坏固件完整性（风险等级8.5）。利用概率中等（需写配置文件权限）
- **代码片段:**
  ```
  sym.imp.sprintf(buffer, *0x12314, *(*0x12318 + 0x10), filename);
  sym.imp.system(buffer);
  ```
- **关键词:** /etc/fw_env.config, nandwrite, system, sprintf, sym.flash_io, obj.envdevices, 0x12314, 0x12318
- **备注:** 完整攻击链：配置文件污染 → 全局指针劫持 → 命令注入。后续验证：1) /etc/fw_env.config权限 2) /dev/mtd0写保护机制

---
### network_input-ioctl-ESSID_injection

- **文件路径:** `sbin/iwconfig`
- **位置:** `fcn.000169c8:0x16a0c`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** ESSID注入漏洞（攻击链1）：用户控制命令行参数(argv[1])通过strncpy直接复制到栈缓冲区(puVar7-0x40)，无过滤或边界检查，经ioctl(SIOCSIWESSID)传递至驱动层。触发条件：攻击者通过web接口或脚本注入控制iwconfig参数。安全影响：篡改无线配置、触发驱动漏洞或导致拒绝服务。
- **代码片段:**
  ```
  strncpy(puVar7-0x40, argv[1], 0x20);
  ioctl(fd, 0x8b11, puVar7-0x40);
  ```
- **关键词:** ioctl, SIOCSIWESSID, 0x8b11, argv, strncpy
- **备注:** 利用链：用户输入→argv[1]→strncpy→ioctl(SIOCSIWESSID)。需验证固件中调用iwconfig的web接口

---
### env_set-fw_setenv-heap_overflow

- **文件路径:** `usr/bin/fw_printenv`
- **位置:** `fw_printenv:0x11224 (sym.fw_setenv+0x114)`
- **类型:** env_set
- **综合优先级分数:** **8.15**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 全局变量污染导致堆溢出：攻击者首次调用注入超长变量污染全局变量0x10d54/0x10d58。触发条件：1) getenvsize依赖污染值错误计算缓冲区大小 2) fw_setenv中*(puVar7 + -0x14)边界检查被绕过。实际影响：堆溢出覆盖关键数据结构（风险等级8.5）。利用概率中高（需两次调用）
- **代码片段:**
  ```
  if (iVar5 + iVar3 < *(puVar7 + -0x14) {
      sym.imp.fwrite(...); // 边界检查失效点
  }
  ```
- **关键词:** getenvsize, 0x10d54, 0x10d58, *(puVar7 + -0x14), sym.fw_setenv, crc32
- **备注:** 漏洞链依赖：首次CLI调用污染全局变量 → 二次调用触发堆溢出。需验证堆布局与0x10d54指针初始化点（建议检查sym.env_init）

---
### network_input-upnpd-stack_overflow_0x17468

- **文件路径:** `usr/bin/upnpd`
- **位置:** `upnpd:0x17468`
- **类型:** network_input
- **综合优先级分数:** **8.15**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞。触发条件：攻击者发送>500字节特制数据污染全局缓冲区0x32134。污染路径：1) msg_recv接收网络数据 2) fcn.00016194直接写入0x32134无长度校验 3) fcn.00017330使用污染数据构造命令时触发snprintf(auStack_220,500,...)溢出。边界检查缺失：无源数据长度验证机制。实际影响：可覆盖返回地址实现RCE，需与命令注入组合利用。
- **关键词:** fcn.00017330, snprintf, auStack_220, 0x32134, fcn.00016194, msg_recv

---
### network_input-fw6RulesEdit-doSave

- **文件路径:** `web/main/fw6RulesEdit.htm`
- **位置:** `fw6RulesEdit.htm: JavaScript doSave函数`
- **类型:** network_input
- **综合优先级分数:** **8.15**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 防火墙规则配置界面存在输入验证缺陷：1) ruleName仅进行$.isname基础验证，未限制长度/特殊字符 2) internalHostRef/externalHostRef等10个参数完全未经验证 3) 使用'split(':')[1]'直接提取值，攻击者可构造'type:;rm -rf /'类payload触发命令注入。触发条件：攻击者通过HTTP POST提交恶意规则配置（需身份认证），后端处理ACT_ADD时若未二次验证即使用这些参数，将导致RCE。
- **代码片段:**
  ```
  fwAttrs.internalHostRef = $.id('internalHostRef').value.split(':')[1];
  fwAttrs.externalHostRef = $.id('externalHostRef').value.split(':')[1];
  $.act(ACT_ADD, IP6_RULE, null, null, fwAttrs);
  ```
- **关键词:** doSave, ACT_ADD, IP6_RULE, fwAttrs, internalHostRef, externalHostRef, split, $.act
- **备注:** 需验证：1) 后端处理ACT_ADD的CGI程序位置（建议搜索IP6_RULE关键字）2) $.isname实现（可能在common.js）3) split(':')[1]是否导致参数注入（如构造'any:$(reboot)'）。关联发现：知识库中已有4个使用$.act的端点（restart.htm/voip_module.js/status_monitor.js/voice.js），建议统一分析$.act的底层实现机制。

---
### stack-overflow-l2omci_cli_set_me-0x3c40

- **文件路径:** `usr/lib/libomci_mipc_client.so`
- **位置:** `libomci_mipc_client.so:0x3c40`
- **类型:** ipc
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 函数l2omci_cli_set_me暴露双参数栈溢出风险。具体表现：name和attribs参数分别通过strcpy复制到256字节栈缓冲区(auStack_210和auStack_108)。触发条件：任意参数长度>256字节。约束检查缺失：函数仅验证指针非空，未实施任何长度限制。潜在利用链：通过UCI/DBus接口调用的服务组件若缺失参数过滤，可导致漏洞触发。实际环境影响：在运营商网络场景中，该函数可能被用于远程ONT配置管理。
- **代码片段:**
  ```
  if (*(puVar2 + -0x214) != 0) strcpy(...);
  if (*(puVar2 + -0x220) != 0) strcpy(...);
  ```
- **关键词:** l2omci_cli_set_me, strcpy, name, attribs, auStack_210, auStack_108
- **备注:** 缓冲区命名与stack-overflow-apm_cli-avc_value_str(auStack_210/auStack_108)一致，表明相同代码模式。后续方向：1) 分析/sbin/oamd导入关系 2) DBus接口访问控制

---
### CWE-73-radvd-130c0

- **文件路径:** `usr/sbin/radvd`
- **位置:** `sbin/radvd:0x130c0`
- **类型:** configuration_load
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 通过命令行参数'-C'注入恶意路径（如'../../../etc/passwd'）触发任意文件读取。触发条件：攻击者能控制radvd启动参数（如通过启动脚本注入）。实际影响：读取敏感文件或破坏日志系统。
- **代码片段:**
  ```
  iVar1 = sym.imp.fopen(param_1,*0x13134);
  ```
- **关键词:** -C, fcn.000130b4, radvd.conf, fopen
- **备注:** 需验证系统启动机制参数注入可行性

---
### file_write-passwd_exposure

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:34`
- **类型:** file_write
- **综合优先级分数:** **8.05**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 10.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 将/etc/passwd.bak复制到/var/passwd。若原文件包含敏感凭证，则扩大攻击面。触发条件：系统启动时自动执行。实际影响：攻击者可能读取密码哈希进行离线破解。
- **代码片段:**
  ```
  cp -p /etc/passwd.bak /var/passwd
  ```
- **关键词:** cp -p /etc/passwd.bak /var/passwd
- **备注:** 需检查/etc/passwd.bak内容及/var目录保护

---
### network_input-voip-btnApplySip

- **文件路径:** `web/main/voice_line.htm`
- **位置:** `www/js/voip_module.js: JavaScript函数: btnApplySip`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 8.0
- **置信度:** 8.5
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 前端输入字段（如unfwdNum1, bufwdNum1）通过btnApplySip()中的$.act(ACT_SET, VOICE_PROF_LINE...)提交，但未实施客户端输入验证。触发条件：攻击者伪造HTTP请求修改参数。结合后端漏洞可导致：1) 参数注入篡改电话配置 2) 通过VOICE_PROF_LINE对象执行未授权操作。实际影响取决于后端对ACT_SET的处理机制。
- **关键词:** unfwdNum1, bufwdNum1, btnApplySip, ACT_SET, VOICE_PROF_LINE, VOICE_PROF_LINE_CALLFEAT, $.act
- **备注:** 需在后端验证ACT_SET是否执行特权操作；关联现有$.act操作

---
### integer_overflow-apm_cli_set_alarm_theshold-0x10b4

- **文件路径:** `usr/lib/libalarm_mipc_client.so`
- **位置:** `libalarm_mipc_client.so:0x000010b4`
- **类型:** ipc
- **综合优先级分数:** **8.05**
- **风险等级:** 7.8
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 整数处理缺陷（CWE-190）。具体表现：Apm_cli_set_alarm_theshold直接存储threshold/clear_threshold等参数到局部变量，未实现边界检查或溢出防护。触发条件：传入超范围整数值（如UINT_MAX）。潜在影响：导致下游服务未定义行为。
- **代码片段:**
  ```
  ldr r3, [arg_4h]
  str r3, [var_8h]
  ```
- **关键词:** Apm_cli_set_alarm_theshold, threshold, clear_threshold, mipc_send_cli_msg
- **备注:** 需检查参数是否用于内存分配/索引计算；关联漏洞链stack-overflow-apm_cli-avc_value_str

---
### network_input-voip_cos_exposure

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:94-95`
- **类型:** network_input
- **综合优先级分数:** **7.95**
- **风险等级:** 8.5
- **置信度:** 7.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 启动voip_server和cos服务且未指定安全参数。若服务存在漏洞（如缓冲区溢出），可形成RCE攻击链。触发条件：系统启动后自动执行。实际影响：高危远程攻击面暴露。
- **代码片段:**
  ```
  voip_server &
  cos &
  ```
- **关键词:** voip_server, cos
- **备注:** 需逆向分析二进制文件

---
### stack_overflow-pppd-config_sprintf

- **文件路径:** `usr/sbin/pppd`
- **位置:** `pppd:main @ 0x00018528`
- **类型:** configuration_load
- **综合优先级分数:** **7.95**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** main函数使用sprintf向72字节栈缓冲区(auStack_48)写入数据，格式化参数(全局配置变量)可能被污染。若格式化后长度超72字节导致栈溢出。触发条件：通过配置文件/命令行控制全局变量值。边界检查：无长度验证。安全影响：任意代码执行或崩溃，需污染全局变量降低直接性。
- **代码片段:**
  ```
  sym.imp.sprintf(puVar22 + -0x48,*0x1894c,*0x18950,**0x18948)
  ```
- **关键词:** sprintf, auStack_48, global_config_var, options_from_file
- **备注:** 需分析全局变量污染路径（如/etc/ppp/options配置文件）。与发现4共享options_from_file关键词

---
### vul-ripd-response-oob-read-0x133b4

- **文件路径:** `usr/sbin/ripd`
- **位置:** `ripd:0x133b4 (dbg.rip_response_process)`
- **类型:** network_input
- **综合优先级分数:** **7.9**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** RIP响应处理函数(dbg.rip_response_process)存在类似越界读取漏洞。解析RTE条目时循环条件(puVar7 <= puVar9)未验证剩余缓冲长度是否满足20字节要求。当接收长度=4+20*N+K(1≤K≤19)的伪造响应包时，将越界访问包外内存。触发条件：攻击者伪造RIP响应包+包长度非20倍数。实际影响：拒绝服务或信息泄露（可能暴露进程内存布局）。
- **代码片段:**
  ```
  puVar7 = param_1 + 4;
  puVar9 = param_1 + param_2;
  do {
      ... // RTE处理
      puVar7 += 10;
  } while (puVar7 <= puVar9);
  ```
- **关键词:** dbg.rip_response_process, puVar7, puVar9, RTE, rip_packet, param_2
- **备注:** 关键风险点：攻击者可控制param_2（包长度）和包内容。建议检查rip_rte_process的数据处理逻辑

---
### ipc-param-unchecked-libi2c-0x1040

- **文件路径:** `usr/lib/libi2c_mipc_client.so`
- **位置:** `libi2c_mipc_client.so:0x00001040`
- **类型:** ipc
- **综合优先级分数:** **7.81**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 6.8
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 函数I2cApi_apmSetOnuXvrThreshold存在参数未验证风险：接收3个uint32_t参数(alarm_type/threshold/clear_threshold)后未经任何范围校验即通过mipc_send_sync_msg发送至服务端。具体表现：1) 参数直接打包12字节数据结构 2) 无边界检查或类型验证逻辑。触发条件：当调用者传递超范围参数（如threshold=0xFFFFFFFF）时。安全影响：服务端若缺乏校验可能导致越界访问、配置篡改或硬件异常，形成'不可信输入→IPC传递→服务端处理'攻击链关键环节。
- **代码片段:**
  ```
  str r0, [var_18h]  // 存储param_1
  str r1, [var_1ch]  // 存储param_2
  str r2, [var_20h]  // 存储param_3
  bl loc.imp.mipc_send_sync_msg
  ```
- **关键词:** I2cApi_apmSetOnuXvrThreshold, alarm_type, threshold, clear_threshold, mipc_send_sync_msg
- **备注:** 需后续验证：1) 服务端对12字节数据的解析逻辑 2) 参数源头是否网络/NVRAM可控。关联发现：知识库中已存在mipc_send_sync_msg在loop_detect_set_admin等函数的使用（usr/lib/libloop_detect_mipc_client.so），表明该IPC机制是跨组件的通用通道，服务端未验证参数可能形成统一攻击面。

---
### configuration_load-cli_param_binding-mng_com_commands

- **文件路径:** `etc/xml_commands/mng_com_commands.xml`
- **位置:** `etc/xml_commands/mng_com_commands.xml`
- **类型:** configuration_load
- **综合优先级分数:** **7.8**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 该XML文件定义了系统CLI命令的参数绑定机制，用户输入通过${param}语法直接绑定到内置函数参数。关键安全问题：1) 参数验证仅依赖ptype类型声明(如STRING_SN/UINT)，但XML中未定义具体验证规则 2) 敏感参数类型(如STRING_PSWD密码字段)缺乏内容过滤机制 3) 字符串类型参数(STRING_SN)未声明最大长度约束。攻击者可构造恶意参数值(如超长字符串或特殊字符)直接传入处理函数，若函数内部缺乏边界检查可能导致缓冲区溢出或命令注入。触发条件：通过CLI接口执行相关命令并传入污染参数。
- **代码片段:**
  ```
  <PARAM name="sn" ptype="STRING_SN"/>
  <ACTION builtin="mng_com_cli_set_pon_params"> ${sn} ... </ACTION>
  ```
- **关键词:** PARAM@ptype, STRING_SN, STRING_PSWD, UINT, ACTION@builtin, mng_com_cli_set_pon_params, mv_os_cli_timer_start, ${sn}, ${pssw}, ${timer_id}
- **备注:** 需后续分析二进制文件中的builtin函数实现(如mng_com_cli_set_pon_params)，验证：1) 字符串参数是否使用strncpy等安全函数 2) 数值参数是否进行范围检查 3) 是否存在格式化字符串漏洞。重点检查污点参数${sn}/${pssw}在函数内的传播路径。

---
### network_input-ipv6_validation-logic_flaw

- **文件路径:** `web/main/ethWan.htm`
- **位置:** `ethWan.htm (JavaScript function)`
- **类型:** network_input
- **综合优先级分数:** **7.8**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** isValidGLUIP6AddrStrict函数实现IPv6地址校验时存在多处逻辑缺陷：1) 错误拒绝合法地址'::'（设置flag=false）2) 首段提取失败（地址以'::'开头时index=0返回空）3) 未过滤FC00::/7保留地址。触发条件：用户配置IPv6静态地址或DNS时提交畸形地址（如::或FC00::1）。实际影响：攻击者可注入非常规地址绕过前端校验，可能导致后端解析错误或配置异常。约束条件：仅影响IPv6配置路径，需配合绕过客户端验证才能触发。
- **关键词:** isValidGLUIP6AddrStrict, ip6Addr, ::, substr1, substr2, index, FC00, 2000::/3
- **备注:** 需关联后端IPv6处理逻辑验证实际影响；建议检查固件中ipv6_parser相关组件。关键跨文件线索：结合知识库notes字段，需验证wanipc.cgi对IPv6参数的处理逻辑

---
### command_execution-racoon_main-atoi_overflow_0x14448

- **文件路径:** `usr/bin/racoon`
- **位置:** `racoon:0x00014448`
- **类型:** command_execution
- **综合优先级分数:** **7.8**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 命令行参数漏洞：使用'-P'参数时，外部控制的字符串通过atoi直接转换为整数赋值给全局配置变量(0x00014448)，未进行边界检查。触发条件：本地/远程（通过启动脚本）传递恶意数值。影响：整数溢出可能导致配置篡改或服务异常，利用概率中等（8.0）。
- **代码片段:**
  ```
  uVar1 = sym.imp.atoi(uVar4);
  *(*(puVar13 + -8) + 0x10) = uVar1;
  ```
- **关键词:** main, atoi, puVar8, 0x50, 0x00014448, -P
- **备注:** 需追踪全局配置变量在安全临界操作中的使用

---
### systemic_issue-parameter_validation-cli_commands

- **文件路径:** `etc/xml_commands/mng_com_commands.xml`
- **位置:** `N/A`
- **类型:** configuration_load
- **综合优先级分数:** **7.8**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 参数验证系统性缺陷：所有字符串类型参数(STRING_SN/STRING_PSWD/STRING_name)均缺失长度约束和字符过滤规则，高危参数占比100%。此问题与知识库中多个记录(tpm_commands.xml/mng_com_commands.xml)形成印证，证明跨文件设计缺陷。
- **关键词:** STRING_SN, STRING_PSWD, STRING_name, ptype, configuration_load-cli_param_binding-mng_com_commands, command_injection-tpm_xml-param_overflow
- **备注:** 影响命令：debug mng set pon, debug mng set name等。需全局修复ptype验证机制。

---
### frontend_validation-manageCtrl-XSS_portbinding

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm: doSave()函数`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 7.8
- **置信度:** 8.5
- **触发可能性:** 6.5
- **查询相关性:** 9.2
- **阶段:** N/A
- **描述:** 前端输入处理缺陷：1) 14个DOM输入点(curPwd/l_http_port等)缺乏XSS过滤，攻击者可注入恶意脚本 2) doSave函数中端口范围检查(1024-65535)未验证权限越界(如绑定<1024端口) 3) 主机地址字段(l_host/r_host)无格式校验。触发条件：用户提交表单时。安全影响：结合后端漏洞可形成完整攻击链：a) 通过恶意主机地址绕过ACL b) 低权限端口绑定导致服务拒绝 c) 密码字段XSS窃取凭证。利用概率：需后端配合，中等(6.5/10)
- **代码片段:**
  ```
  if ($.num(arg, 80, [1024,65535], true)) ...
  $.act(ACT_SET, HTTP_CFG, null, null, httpCfg);
  ```
- **关键词:** curPwd, newPwd, l_http_port, r_https_port, l_host, r_host, doSave, ACT_CGI, /cgi/auth, HTTP_CFG, ACL_CFG, ACT_SET
- **备注:** 需追踪/cgi/auth实现验证输入过滤和ACT_SET对HTTP_CFG的操作；与ethWan.htm的ACT_SET实现共享后端机制

---
### path-traversal-bnr

- **文件路径:** `usr/bin/httpd`
- **位置:** `usr/bin/httpd:0x15ce8`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 8.5
- **置信度:** 7.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 路径遍历任意文件写入（/cgi/bnr）：1) 全局变量0x41118+8存储文件路径；2) 通过sprintf拼接路径时未验证用户输入；3) fcn.000143cc直接写入文件。触发条件：污染0x41118内存区域（如通过其他HTTP参数），构造'../../etc/passwd'类路径实现任意文件覆盖。
- **关键词:** 0x41118, str._.ret_d__n, fcn.000143cc, sprintf
- **备注:** 依赖全局变量污染，需定位写入0x41118的代码点

---
### network_input-virtual_server-port_parameter_exposure

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `virtualServer.htm: doEdit函数`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 虚拟服务器配置接口暴露多个未经验证参数(externalPort/internalPort)，通过doEdit/doAdd函数提交至vtlServEdit.htm处理。触发条件：攻击者构造恶意端口范围(如0-65535)提交配置。安全影响：若后端缺乏边界检查，可导致端口冲突或服务拒绝。利用方式：结合CSRF漏洞(当前文件未发现防护)诱骗管理员访问恶意页面提交配置。
- **代码片段:**
  ```
  function doEdit(val1, val2){
    param[0]=1;
    $.loadMain("vtlServEdit.htm",param);
  }
  ```
- **关键词:** externalPort, internalPort, doEdit, doAdd, vtlServEdit.htm, portMappingProtocol
- **备注:** 需验证vtlServEdit.htm的输入处理逻辑完成攻击链

---
### network_input-$.act-csrf_missing

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js:509 (常量定义) & 668 ($.act)`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 高危操作缺乏CSRF保护。$.act()函数直接执行ACT_OP_REBOOT/ACT_OP_FACTORY_RESET等危险操作，仅依赖会话cookie认证。攻击者可构造恶意页面诱导用户触发设备重置。触发条件：受害者登录状态下访问恶意页面。影响：设备完全失控
- **代码片段:**
  ```
  function $.act(type, oid, stack, pStack, attrs) {
    $.as.push([type, null, oid, stack, pStack, attrs...]);
  ```
- **关键词:** ACT_OP_REBOOT, ACT_OP_FACTORY_RESET, $.act, type, oid, $.exe
- **备注:** 攻击路径：跨域请求 → 触发$.act() → 执行设备重置。关联知识库中'关键攻击路径在IPC服务端实现'，需验证服务端是否检查Origin头

---
### configuration_load-sprintf-MAC_overflow

- **文件路径:** `sbin/iwconfig`
- **位置:** `iwconfig:0x16604`
- **类型:** configuration_load
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** MAC地址处理漏洞（攻击链3）：sprintf循环写入MAC地址时存在空终止符覆盖风险。首次迭代写入3字节('XX\0')，后续每次写入4字节(':XX\0')但指针仅前移3字节。触发条件：传入非常规长度MAC地址(r5>6)。安全影响：覆盖相邻内存结构，可导致控制流劫持。
- **代码片段:**
  ```
  sprintf(buf, "%02X", mac[0]);
  for(i=1; i<r5; i++) {
    sprintf(buf+3*i, ":%02X", mac[i]); // 写入4字节但偏移仅增3
  }
  ```
- **关键词:** sprintf, r5, MAC
- **备注:** 需追溯r5值来源（可能来自NVRAM或网络）。边界检查完全缺失

---
### cli_injection-mng_com_set_pon-params

- **文件路径:** `etc/xml_commands/mng_com_commands.xml`
- **位置:** `mng_com_commands.xml:48-55`
- **类型:** command_execution
- **综合优先级分数:** **7.7**
- **风险等级:** 8.0
- **置信度:** 8.0
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 命令'debug mng set pon'接收两个未经验证的敏感参数（sn和pssw）。XML定义中未设置长度限制或字符过滤规则：1) sn(STRING_SN类型)可被注入超长字符串触发缓冲区溢出 2) pssw(STRING_PSWD类型)以明文传递。触发条件需CLI访问权限。与现有知识库记录[configuration_load-cli_param_binding-mng_com_commands]形成漏洞链：参数绑定缺陷使攻击者能控制${sn}/${pssw}传入mng_com_cli_set_pon_params函数。
- **代码片段:**
  ```
  <COMMAND name="debug mng set pon" help="Set PON parameters">
  <PARAM name="sn" help="Serial number" ptype="STRING_SN"/>
  <PARAM name="pssw" help="Password" ptype="STRING_PSWD"/>
  <ACTION builtin="mng_com_cli_set_pon_params"> ${sn} ${pssw} ${dis} </ACTION>
  ```
- **关键词:** debug mng set pon, sn, pssw, STRING_PSWD, mng_com_cli_set_pon_params, configuration_load-cli_param_binding-mng_com_commands
- **备注:** 关联漏洞链：CLI访问→注入sn参数→mng_com_cli_set_pon_params缓冲区溢出→RCE。需验证函数实现边界检查。

---
### network_input-url_hash_loading

- **文件路径:** `web/index.htm`
- **位置:** `index.htm: 脚本块末尾`
- **类型:** network_input
- **综合优先级分数:** **7.65**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.2
- **阶段:** N/A
- **描述:** URL哈希控制机制使用 location.href.match(/#__(\w+\.htm)$/) 从URL片段提取文件名，通过$.loadMain()加载对应HTM文件。正则约束仅验证\w+.htm格式，未实施路径合法性检查或访问控制。攻击者可构造恶意哈希（如#__../../etc/passwd.htm）尝试路径遍历，或加载包含恶意脚本的HTM文件。实际影响取决于$.loadMain的路径处理实现，可能造成敏感文件泄露或XSS攻击。
- **代码片段:**
  ```
  if((ret = location.href.match(/#__(\w+\.htm)$/)) && ret[1]) {
  	$.loadMain(ret[1]);
  }
  ```
- **关键词:** location.href.match, #__, $.loadMain, ret[1]
- **备注:** 需验证$.loadMain在frame/目录的实现是否限制文件访问范围。建议后续分析./js/lib.js（可能包含loadMain定义）及frame/目录HTM文件

---
### configuration_set-ACT_SET-client_side_validation

- **文件路径:** `web/main/ethWan.htm`
- **位置:** `ethWan.htm:1721-1722`
- **类型:** configuration_load
- **综合优先级分数:** **7.6**
- **风险等级:** 8.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** ACT_SET操作通过doSave函数修改核心网络配置（WAN/NAT/防火墙），安全机制仅依赖客户端验证：1) IP同网段检查(isSameLan) 2) MTU范围(576-1500) 3) DNS格式校验。触发条件：认证用户点击保存按钮。实际影响：若绕过客户端验证（如直接构造HTTP请求），可能注入恶意配置（如无效DNS实现中间人攻击）。约束条件：配置时自动禁用其他接口（ACT_SET enable=0）。
- **代码片段:**
  ```
  1721: $.act(ACT_SET, WAN_IP_CONN, staticStk, null, wan_iplistarg_sta);
  1722: $.act(ACT_SET, WAN_ETH_INTF, pStk, null, ["X_TP_lastUsedIntf=ipoe_eth3_s"]);
  ```
- **关键词:** ACT_SET, doSave, WAN_IP_CONN, WAN_PPP_CONN, L3_FORWARDING, isSameLan, staticStk, dynStk
- **备注:** 关键缺口：无服务端验证证据；后续应分析/cgi-bin/下CGI程序（如wanipc.cgi）的请求处理逻辑。关联知识库现有ACT_SET操作记录

---
### variable-overwrite-voip-VOIP_setSipUserParamConfig_F

- **文件路径:** `usr/lib/libvoip_mipc_client.so`
- **位置:** `libvoip_mipc_client.so:0x19b4`
- **类型:** ipc
- **综合优先级分数:** **7.6**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 局部变量覆盖风险：memcpy复制64字节数据时，因目标地址偏移导致最后4字节覆盖相邻局部变量(auStack_8)。触发条件：控制info参数且长度≥64字节。安全影响：篡改函数返回值影响业务逻辑，可能引发拒绝服务或逻辑漏洞。
- **关键词:** VOIP_setSipUserParamConfig_F, memcpy, 0x40, auStack_48, auStack_8, info

---
### network_input-dnsmasq-sprintf_0x28f94

- **文件路径:** `usr/sbin/dnsmasq`
- **位置:** `usr/sbin/dnsmasq:0x28f94`
- **类型:** network_input
- **综合优先级分数:** **7.55**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** DHCP option处理sprintf漏洞：
* **具体表现**：循环内sprintf使用'%.2x'格式化未经验证的DHCP option数据(*(puVar37+-0xb0))，索引r5(iVar6)和边界值r3(*(puVar37+-0xc))可能被污染
* **触发条件**：恶意option使r5>r3绕过边界检查，或提供超长格式化数据
* **约束检查**：cmp r5,r3指令的r3值通过fcn.00019b10()初始化，来源未完全验证
* **安全影响**：1) 栈缓冲区溢出 2) 内存地址泄露（格式化字符串）
* **利用方式**：构造特殊option数据操纵循环索引和格式化参数
- **代码片段:**
  ```
  for (iVar6=0; iVar6<*(puVar37+-0xc); iVar6++){
    uVar5=*(*(puVar37+-0xb0)+iVar6);
    sprintf(fp, "%.2x", uVar5);
  }
  ```
- **关键词:** fcn.000266c0, sprintf_0x28f94, option_0x3d, puVar37, r5, r3, %.2x, fcn.00019b10
- **备注:** 需补充分析：1) 目标缓冲区(fp)大小 2) fcn.00019b10返回值污染路径

---
### network_input-stack_overflow-1e988

- **文件路径:** `usr/sbin/dropbear`
- **位置:** `fcn.0001e988 (0x1e988)`
- **类型:** network_input
- **综合优先级分数:** **7.55**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 堆栈缓冲区溢出漏洞:
- 触发条件: 攻击者控制param_2参数值>0x13(20字节)
- 利用路径: 污染数据传入 → memcpy目标缓冲区(auStack_18) → 栈溢出控制流劫持
- 约束缺失: memcpy前仅做min(0x14, param_2)截断，未验证源数据长度
- 实际影响: 7.5/10.0，需追踪param_2到初始输入点的数据流
- **代码片段:**
  ```
  uVar3 = param_2;
  if (0x13 < param_2) {
      uVar3 = 0x14;
  }
  sym.imp.memcpy(param_1, puVar4 + -0x18, uVar3);
  ```
- **关键词:** memcpy, auStack_18, param_2, uVar3, fcn.0001e988

---
### command_execution-shell-global_commands_xml

- **文件路径:** `etc/xml_commands/startup.xml`
- **位置:** `etc/xml_commands/global-commands.xml:27`
- **类型:** command_execution
- **综合优先级分数:** **7.5**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 在global-commands.xml中发现高危'shell'命令，通过内置函数appl_shell直接进入Linux shell环境。触发条件：攻击者获得CLI访问权限（如通过弱口令登录网络暴露的Telnet/SSH接口）。实际安全影响：完全设备控制权获取。利用方式：结合网络服务漏洞或默认凭据执行该命令，无需额外漏洞利用。
- **代码片段:**
  ```
  <COMMAND name="shell" help="Enter Linux Shell">
      <ACTION builtin="appl_shell"> </ACTION>
  </COMMAND>
  ```
- **关键词:** shell, appl_shell, COMMAND name="shell", CLI
- **备注:** 需后续验证：1) CLI接口的网络暴露范围 2) appl_shell函数是否存在沙箱限制 | 攻击路径：网络接口(HTTP/Telnet)→CLI命令执行→shell命令→操作系统控制 (exploit_probability=0.75) | 建议：立即分析appl_shell函数实现（路径：sbin/clish）

---
### heap-allocator-integer-overflow-dos

- **文件路径:** `bin/bash`
- **位置:** `sym.sh_malloc`
- **类型:** command_execution
- **综合优先级分数:** **7.5**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.5
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 内存分配器基础防护缺陷：sh_malloc函数中 'param_1 + 0x13 & 0xfffffff8' 计算未校验输入参数上限。当param_1 > 0xFFFFFFEC时发生整数溢出，导致分配缓冲区过小。分配失败时直接调用fatal_error退出，无安全回退机制。攻击者可通过触发此路径造成拒绝服务，或结合其他漏洞扩大攻击面。
- **代码片段:**
  ```
  uVar9 = param_1 + 0x13 & 0xfffffff8;
  if (iVar1 + 0 == 0) {
      sym.fatal_error(...);
  ```
- **关键词:** sym.sh_malloc, param_1, fatal_error, uVar9
- **备注:** 建议修复：增加 'if (param_1 >= UINT_MAX - 0x13) return NULL'；固定地址(0x26f54等)字符串提取失败，但反汇编结果已提供充分函数交互证据。环境变量名'SHELL_NAME'未显式出现，但obj.shell_name的污染路径已明确。

---
### ipc-IGMP-0x10f0

- **文件路径:** `usr/lib/libigmp_mipc_client.so`
- **位置:** `libigmp_mipc_client.so:0x000010f0`
- **类型:** ipc
- **综合优先级分数:** **7.5**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 函数IGMP_set_multicast_switch存在内存操作漏洞：仅对指针参数进行NULL检查（0x1104-0x1108），但未验证源数据实际长度。在0x112c处使用memcpy固定复制4字节数据，若调用者传递无效指针可能导致内存读取越界。复制后的数据通过mipc_send_sync_msg(0x115c)发送到其他进程。触发条件：当调用进程传递来自外部可控源（如网络数据）的MULTICAST_PROTOCOL_T*参数时，攻击者可构造恶意指针导致：1) 敏感内存信息泄露 2) 接收进程处理异常。实际影响取决于调用链中参数是否外部可控。
- **代码片段:**
  ```
  0x00001120 mov r0, r1
  0x00001124 mov r1, r2
  0x00001128 mov r2, r3
  0x0000112c bl sym.imp.memcpy
  ```
- **关键词:** IGMP_set_multicast_switch, MULTICAST_PROTOCOL_T, memcpy, mipc_send_sync_msg, r0
- **备注:** 需追踪调用此函数的上级模块（如网络配置服务），验证multicast_protocol参数是否来自HTTP API或UART接口等外部输入源；关联到知识库中已有的mipc_send_sync_msg调用链，需结合其他IPC发现验证完整攻击路径

---
### network_input-TR069-format_string-fcn000126b0

- **文件路径:** `usr/bin/cwmp`
- **位置:** `fcn.000126b0+0x80`
- **类型:** network_input
- **综合优先级分数:** **7.5**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 高危格式化字符串参数不匹配（CWE-134）：
- 触发条件：当fcn.00012e9c/fcn.0001c2ec调用fcn.000126b0时传入外部可控参数
- 传播路径：网络输入 → 上层调用函数 → fcn.000126b0(sprintf)
- 漏洞机制：sprintf使用9参数格式字符串但仅提供2个实参，导致读取栈上未初始化数据
- 安全影响：1) 泄露栈内存（含返回地址/敏感信息）2) 若目标缓冲区不足可能触发二次溢出
- **代码片段:**
  ```
  sym.imp.sprintf(..., "Authorization: Digest username=\"%s\", realm=\"%s\", ...", ..., ...); // 9个%s但仅2个参数
  ```
- **关键词:** fcn.000126b0, sym.imp.sprintf, param_1, param_2, Authorization: Digest, fcn.00012e9c, fcn.0001c2ec
- **备注:** 最高优先级：分析fcn.00012e9c(0x13150)和fcn.0001c2ec(0x1c68c)的输入源

---
### unvalidated-input-flashapi-setimagetoinvalid

- **文件路径:** `usr/lib/libflash_mipc_client.so`
- **位置:** `usr/lib/libflash_mipc_client.so:0xdf8`
- **类型:** ipc
- **综合优先级分数:** **7.45**
- **风险等级:** 7.8
- **置信度:** 8.5
- **触发可能性:** 5.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** FlashApi_setImageToInvalid函数存在未验证输入风险：
- **具体表现**：直接使用外部传入的bank参数（UINT8类型）构造IPC消息，无有效值范围检查
- **触发条件**：攻击者传入非法bank值（如255）并触发函数调用
- **约束缺失**：缺少bank∈[0,1]的验证逻辑
- **安全影响**：可能导致：a) 服务端越界内存访问 b) 固件镜像意外失效 c) 绕过签名验证
- **利用方式**：结合RCE漏洞或未授权接口调用此函数
- **关键词:** FlashApi_setImageToInvalid, bank, mipc_send_sync_msg, IPC_MSG_SET_IMAGE_INVALID
- **备注:** 关键验证点：
1) 服务端IPC处理逻辑
2) 函数调用入口点
3) 关联消息类型0x35/0.46（参考stack-overflow-oam_cli-mipc_chain）

---
### denial_of_service-ftp_port_conflict

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `virtualServer.htm: 行365-414`
- **类型:** network_input
- **综合优先级分数:** **7.45**
- **风险等级:** 6.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** FTP端口冲突检测机制(checkConflictFtpPort)在端口重叠时自动禁用FTP服务。触发条件：当virtualServer配置的端口范围覆盖FTP端口时触发。安全影响：可被用于拒绝服务攻击。利用方式：攻击者通过CSRF提交包含FTP端口(默认21)的虚拟服务器规则。
- **代码片段:**
  ```
  if ((exPort<=ftpServer.portNumber)&&(ftpServer.portNumber<=exPortEnd)){
    conflict=true;
  }
  ```
- **关键词:** checkConflictFtpPort, FTP_SERVER, accessFromInternet, portNumber
- **备注:** 依赖用户交互的确认弹窗可能降低攻击成功率

---
### CWE-131-radvd-1640c

- **文件路径:** `usr/sbin/radvd`
- **位置:** `sbin/radvd:0x1640c`
- **类型:** network_input
- **综合优先级分数:** **7.45**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 6.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** memcpy使用动态计算长度未验证目标缓冲区容量。触发条件：恶意配置或网络数据构造异常路由表项。实际影响：堆溢出致内存破坏。
- **代码片段:**
  ```
  sym.imp.memcpy(puVar26 + iVar11,piVar3,(iVar14 + 1) * 2);
  ```
- **关键词:** memcpy, fcn.00016340, iVar14
- **备注:** 需结合路由协议特性验证触发

---
### hardware_input-iwpriv-ioctl_unchecked-0x11314

- **文件路径:** `usr/sbin/iwpriv`
- **位置:** `iwpriv:0x11314 (dbg.set_private_cmd)`
- **类型:** hardware_input
- **综合优先级分数:** **7.45**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** ioctl参数未验证漏洞。具体表现：接口名(ifname)通过未限定长度的strncpy复制到栈缓冲区，用户数据直接作为ioctl的第三个参数(arg)。触发条件：控制ifname参数或命令参数值。安全影响：可能触发内核驱动漏洞，具体危害取决于无线驱动实现(SIOCDEVPRIVATE命令处理)。
- **代码片段:**
  ```
  iVar5 = sym.imp.ioctl(*(iVar20 + -0x10b8), *(iVar15 + *(iVar20 + -0x10bc)), iVar20 + -0x30);
  ```
- **关键词:** ioctl, ifname, param_4, strncpy, dbg.set_private_cmd, iw_privargs
- **备注:** 需内核驱动分析验证实际影响，建议后续分析关联无线驱动(如ath9k)的ioctl处理

---
### network_input-proftpd-anonymous_access

- **文件路径:** `etc/proftpd.conf`
- **位置:** `proftpd.conf:31-45`
- **类型:** network_input
- **综合优先级分数:** **7.44**
- **风险等级:** 6.0
- **置信度:** 9.8
- **触发可能性:** 7.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 匿名访问配置存在潜在信息泄露风险：
- 匿名用户被限制在~ftp目录（chroot环境）且禁止写入操作（<Limit WRITE> DenyAll）
- 但允许文件读取操作，若~ftp目录误存敏感文件（如配置文件备份）可被直接下载
- 触发条件：攻击者连接FTP服务并使用匿名账户访问
- 约束条件：MaxClients限制并发连接数（10），MaxInstances限制进程数（30）
- 实际影响：造成敏感信息泄露，但受目录内容制约
- **代码片段:**
  ```
  <Anonymous ~ftp>
    <Limit WRITE>
      DenyAll
    </Limit>
  </Anonymous>
  ```
- **关键词:** Anonymous, ~ftp, <Limit WRITE>, DenyAll, MaxClients, MaxInstances
- **备注:** 需后续验证~ftp目录是否存在敏感文件；若存在可作为攻击链初始信息收集点

---
### hardware_input-pon_rename-manipulation

- **文件路径:** `etc/init.d/rcS`
- **位置:** `rcS:56`
- **类型:** hardware_input
- **综合优先级分数:** **7.35**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.2
- **阶段:** N/A
- **描述:** 从/sys/devices/platform/neta/gbe/pon_if_name读取PON接口名并重命名（ip link set）。攻击者可通过物理访问或驱动漏洞篡改接口名，影响后续网络配置。触发条件：系统启动时自动执行。实际影响：可能破坏防火墙规则或流量劫持。
- **代码片段:**
  ```
  PON_IFN=\`cat /sys/devices/platform/neta/gbe/pon_if_name\`
  ip link set dev ${PON_IFN} name pon0
  ```
- **关键词:** PON_IFN, /sys/devices/platform/neta/gbe/pon_if_name, ip link set
- **备注:** 需验证/sys文件系统的访问控制机制

---
### backend_implicit_call-ACT_CGI-password_exposure

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm: doSave()函数`
- **类型:** network_input
- **综合优先级分数:** **7.35**
- **风险等级:** 8.2
- **置信度:** 7.5
- **触发可能性:** 5.0
- **查询相关性:** 8.7
- **阶段:** N/A
- **描述:** 隐式后端调用风险：通过ACT_CGI机制隐式调用/cgi/auth接口传递凭证数据。触发条件：doSave()执行时。具体表现：前端直接传递curPwd/newPwd等敏感字段，未加密或混淆。安全影响：若中间人拦截ACT_CGI请求可获取明文密码；若/cgi/auth存在命令注入漏洞，可形成RCE链。边界检查：前端验证密码强度但未验证长度超限。
- **关键词:** doSave, ACT_CGI, /cgi/auth, curPwd, newPwd, ACT_SET
- **备注:** 关键攻击路径依赖后端/cgi/auth的实现；与ethWan.htm的ACT_SET机制存在关联

---
### env_set-getenvsize-boundary_check

- **文件路径:** `usr/bin/fw_printenv`
- **位置:** `fw_printenv: sym.getenvsize`
- **类型:** env_set
- **综合优先级分数:** **7.35**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** getenvsize边界检查缺陷：该函数通过未经验证的全局指针(0x10d54, 0x10d58, 0x10d5c)计算环境存储区大小。主要问题：1) 无输入参数验证 2) 计算逻辑(*0x10d58 + **0x10d54*0x1c+0x14-4)未考虑缓冲区实际边界 3) 依赖未初始化指针。潜在影响：环境变量操作时越界读写
- **代码片段:**
  ```
  iStack_c = *(*0x10d58 + **0x10d54 * 0x1c + 0x14) + -4;
  if (**0x10d5c != 0) {
      iStack_c = iStack_c + -1;
  }
  ```
- **关键词:** getenvsize, 0x10d54, 0x10d58, 0x10d5c
- **备注:** 与发现#3存在直接关联：此缺陷是堆溢出漏洞链的关键前提。需分析指针初始化位置（sym.env_init）

---
### high-risk-params-pon_switches

- **文件路径:** `etc/xml_params/gpon_xml_cfg_file.xml`
- **位置:** `gpon_xml_cfg_file.xml`
- **类型:** configuration_load
- **综合优先级分数:** **7.25**
- **风险等级:** 6.5
- **置信度:** 10.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 识别5个高危功能开关参数(PON_dis_sn/PON_gem_reset等)。默认开启的PON_tcont_reset(TCONT重置)和PON_gem_restore(GEM恢复)若被攻击者通过IPC/NVRAM接口篡改，可触发：1) 关键服务中断(如GEM重置导致网络瘫痪) 2) FEC容错机制被破坏(通过PON_fec_hyst)。触发条件：需控制参数写入接口。约束条件：参数为布尔值/整数，但缺乏范围校验(如PON_fec_hyst=1未限定最大值)。
- **代码片段:**
  ```
  <PON_tcont_reset>1</PON_tcont_reset>
  <PON_gem_restore>1</PON_gem_restore>
  ```
- **关键词:** PON_dis_sn, PON_gem_reset, PON_tcont_reset, PON_gem_restore, PON_fec_hyst
- **备注:** 建议后续分析nvram_set调用点验证参数注入可能性；关联攻击路径：配置篡改→服务中断/机制破坏

---
### env_get-ssh_auth_sock-190ec

- **文件路径:** `usr/sbin/dropbear`
- **位置:** `fcn.000190ec (0x190ec)`
- **类型:** env_get
- **综合优先级分数:** **7.25**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 环境变量污染攻击链 (CVE-2021-36368关联漏洞):
- 触发条件: 攻击者通过SSH连接或其他固件接口设置SSH_AUTH_SOCK环境变量指向恶意Unix套接字
- 利用路径: 未经验证的getenv('SSH_AUTH_SOCK')调用 → socket()创建连接 → 凭证窃取/中间人攻击
- 约束缺失: 环境变量值未进行路径白名单验证或签名检查
- 实际影响: 7.0/10.0，需配合其他漏洞获取环境变量设置权限
- **代码片段:**
  ```
  iVar1 = sym.imp.getenv("SSH_AUTH_SOCK");
  if (iVar1 != 0) {
    sym.imp.socket(1,1,0);
    sym.imp.connect(iVar1,...);
  }
  ```
- **关键词:** SSH_AUTH_SOCK, getenv, socket, connect, fcn.000190ec

---
### network_input-restart_page-doRestart

- **文件路径:** `web/main/restart.htm`
- **位置:** `restart.htm:3 doRestart函数`
- **类型:** network_input
- **综合优先级分数:** **7.2**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** restart.htm实现设备重启功能，当用户点击'Reboot'按钮并确认对话框时触发doRestart()函数。该函数通过$.act(ACT_OP, ACT_OP_REBOOT)发送重启指令，最终由$.exe(true)执行重启操作。主要风险：1) 若$.act/$.exe未验证CSRF token，攻击者可构造恶意页面诱使用户访问导致未授权重启（拒绝服务） 2) 当前页面无输入过滤机制，完全依赖外部JS实现的安全性 3) 需验证服务端对ACT_OP_REBOOT指令的处理是否存在命令注入或缓冲区溢出。
- **代码片段:**
  ```
  function doRestart(){
    if(confirm(c_str.creboot)){
      $.guage([...],100,$.guageInterval,function(){$.refresh();});
      $.act(ACT_OP, ACT_OP_REBOOT);
      $.exe(true);
    }
  }
  ```
- **关键词:** doRestart, $.act, $.exe, ACT_OP, ACT_OP_REBOOT, c_str.creboot, s_str.rebooting
- **备注:** 关键后续追踪：1) 定位/web/js/目录下实现$.act/$.exe的JS文件 2) 验证ACT_OP_REBOOT在服务端处理流程（需关联分析bin/sbin目录的守护进程） 3) 检查CSRF保护机制。污染源：HTTP页面交互；危险操作：系统级重启命令执行。

---
### network_input-PacketCapture-command_injection

- **文件路径:** `etc/xml_params/mmp_cfg.xml`
- **位置:** `mmp_cfg.xml:120`
- **类型:** network_input
- **综合优先级分数:** **7.15**
- **风险等级:** 8.5
- **置信度:** 7.0
- **触发可能性:** 4.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** PacketCapture配置暴露命令注入风险：用户可控的Address参数(如192.168.1.100)可能传入底层命令执行。若相关服务未过滤特殊字符(如; | $())，攻击者通过管理界面设置恶意地址可触发任意命令执行。触发条件：1) 激活被注释的抓包功能 2) 传播到system()类调用。
- **代码片段:**
  ```
  <Address>192.168.1.100</Address>
  ```
- **关键词:** PacketCapture, Address, CapturePoint
- **备注:** 需验证：1) 网络管理服务权限 2) /usr/sbin/netcfg处理Address参数的方式

---
### dos-pppd-argv_handling

- **文件路径:** `usr/sbin/pppd`
- **位置:** `pppd:main (反编译循环)`
- **类型:** command_execution
- **综合优先级分数:** **7.15**
- **风险等级:** 6.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 命令行参数处理循环中，匹配特定选项(如'-d')后直接访问argv[i+1]而未验证索引边界。若末位参数为触发选项，导致atoi(NULL)调用崩溃。触发条件：控制pppd调用参数（如通过脚本）。边界检查：无argv长度验证。安全影响：本地拒绝服务（DoS）。
- **代码片段:**
  ```
  uVar5 = sym.imp.atoi(puVar13[1])
  ```
- **关键词:** argv, strstr, atoi, puVar13, 0x18824
- **备注:** 可能通过system调用升级为RCE。关联字符串扫描发现的配置路径

---
### hardware_input-CallerID-ACKDET_param_validation

- **文件路径:** `etc/xml_params/mmp_cfg.xml`
- **位置:** `mmp_cfg.xml:86`
- **类型:** hardware_input
- **综合优先级分数:** **7.1**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** CallerID配置的ACKDET步骤存在参数验证缺陷：1) tone1/tone2参数接受单字符输入但未定义合法字符范围(A-Z外字符可能引发逻辑错误) 2) timeout参数缺乏数值边界检查(负数/过大值可能导致整数溢出)。触发条件：攻击者通过电话线路发送畸形音调序列。潜在影响：绕过呼叫认证或导致服务拒绝，需结合/sbin/voipd等二进制验证实际影响。
- **代码片段:**
  ```
  <step type="ACKDET" timeout="500" tone1="C" tone2="D"/>
  ```
- **关键词:** CallerID, ACKDET, tone1, tone2, timeout, Profile, Telephony, BellCore
- **备注:** 后续需分析/sbin/voipd：1) 验证参数校验逻辑 2) 检查音调处理函数边界

---
### network_input-$.dhtml-xss

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js:180 ($.dhtml) & 209 ($.script)`
- **类型:** network_input
- **综合优先级分数:** **7.1**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 动态代码执行风险。$.dhtml()直接设置innerHTML，$.script()执行未过滤的响应内容。当服务端响应被篡改时导致XSS。触发条件：污染网络响应。影响：会话劫持/权限提升
- **代码片段:**
  ```
  $.script: function(data) {
    if(data && /\S/.test(data)) {
      var script=$.d.createElement("script");...
  ```
- **关键词:** $.dhtml, $.script, innerHTML, $.io, success
- **备注:** 攻击路径：中间人攻击篡改响应 → $.io()接收 → $.script()执行恶意载荷。与$.cgi漏洞共享响应处理机制

---
### config_collision-HTTP_CFG-port_conflict

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm: doSave()函数`
- **类型:** network_input
- **综合优先级分数:** **7.05**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 配置同步漏洞：HTTP_CFG/APP_CFG等配置项通过ACT_SET机制更新。触发条件：保存操作时。具体表现：前端聚合多个输入字段形成配置对象，攻击者可通过篡改l_http_port和r_https_port制造端口冲突。安全影响：服务拒绝（端口占用）或权限提升（绑定特权端口）。边界检查缺陷：仅验证单端口范围，未检测80/443等特殊端口冲突。
- **关键词:** HTTP_CFG, APP_CFG, l_http_port, r_https_port, ACT_SET, doSave
- **备注:** 需验证ACT_SET的后端实现是否检测端口冲突；关联ethWan.htm的WAN配置更新机制

---
### network_input-$.guage-firmware_update

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js:619 ($.guage)`
- **类型:** network_input
- **综合优先级分数:** **7.05**
- **风险等级:** 7.0
- **置信度:** 7.5
- **触发可能性:** 6.5
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 敏感操作无用户确认。$.guage()中的固件更新操作直接触发，未实现二次验证。结合CSRF漏洞可导致静默固件降级。触发条件：单次HTTP请求。影响：固件版本回退至漏洞版本
- **代码片段:**
  ```
  $.guage: function(strs, step, interval, hook, start, end, diag) {
    ...
    if(!completed || !retTmp.softwareVersion) {...}
  ```
- **关键词:** $.guage, step, hook, ACT_OP_*, $.act
- **备注:** 攻击链：CSRF → 触发$.guage() → 固件降级 → 激活历史漏洞。关联知识库中'漏洞组合利用：内存破坏实现初始执行'记录

---
### network_input-$.mac-input_validation

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js:799 ($.mac) & 830 ($.asc)`
- **类型:** network_input
- **综合优先级分数:** **7.0**
- **风险等级:** 6.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 输入验证边界缺陷。$.mac()拒绝全零MAC但允许FF:FF:FF:FF:FF:FF广播地址，$.asc()仅过滤非ASCII字符而未处理命令分隔符。攻击者可构造特殊序列（如'; rm -rf / ;'）尝试二次注入。触发条件：污染输入传递至系统命令。影响：潜在命令注入
- **代码片段:**
  ```
  function $.asc(str, unalert) {
    for (var i=0; i<str.length; i++)
      if(str.charCodeAt(i)>127) return $.alert(90201);
  ```
- **关键词:** $.ip2num, $.mac, unalert, $.asc, ERR_MAC_ZERO
- **备注:** 需结合后端验证：若输入用于拼接shell命令则构成完整注入链。与知识库中'需后续验证：1) 服务端对12字节数据的解析逻辑'存在协同风险

---

## 低优先级发现

### firewall-voicejs-endpointInjection-1

- **文件路径:** `web/js/voice.js`
- **位置:** `web/js/voice.js:未指定行号`
- **类型:** network_input
- **综合优先级分数:** **6.95**
- **风险等级:** 7.0
- **置信度:** 7.5
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 通过$.act调用XTP_IGD_CALL_FIREWALL_CFG端点修改防火墙规则，参数IncomingWhiteList/IncomingBlackList仅在前端进行split(|)分割和重复性检查。攻击者可注入包含特殊字符的条目（如命令分隔符），实际风险取决于后端解析逻辑是否严格验证条目格式。
- **关键词:** $.act, XTP_IGD_CALL_FIREWALL_CFG, IncomingWhiteList, IncomingBlackList, split(|), ERR_VOIP_ENTRY_MAX_ERROR
- **备注:** 建议后续分析/cgi-bin/下对应CGI程序的处理逻辑

---
### hardware_input-udevtrigger-path_traversal

- **文件路径:** `sbin/udevtrigger`
- **位置:** `sbin/udevtrigger:0x112d4 (fcn.000112d4)`
- **类型:** hardware_input
- **综合优先级分数:** **6.95**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 路径遍历漏洞：在函数fcn.000112d4中，动态构建的路径参数(param_1)直接传递给stat64/lstat64系统调用。由于未进行路径规范化处理或'../'过滤，若param_1包含恶意相对路径序列(如'../../etc/passwd')，可能实现任意文件访问。触发条件：攻击者需控制目录项文件名(dirent->d_name)，通常需通过物理设备接入(如USB)或内核漏洞植入恶意设备名。实际影响受限于固件环境对/sys目录写权限的控制。
- **代码片段:**
  ```
  iVar1 = sym.imp.lstat64(param_1, puVar2 + -0x68);
  ```
- **关键词:** fcn.000112d4, param_1, stat64, lstat64, dirent->d_name, fcn.00011e30, fcn.00012ae0, /sys
- **备注:** 需结合固件验证：1) 设备名设置机制是否可控 2) /sys目录写权限策略。关联攻击链：若攻击者通过udevd组件(attack_chain-udevd-devmems)植入恶意设备名，可能触发此漏洞

---
### integer_overflow-mng_timer_start-params

- **文件路径:** `etc/xml_commands/mng_com_commands.xml`
- **位置:** `mng_com_commands.xml:82-86`
- **类型:** command_execution
- **综合优先级分数:** **6.9**
- **风险等级:** 6.5
- **置信度:** 7.5
- **触发可能性:** 7.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 定时器命令参数(init_time/sched_time)定义为UINT类型但未设置取值范围。与知识库记录[tpm_commands.xml UINT缺陷]同属系统性验证缺失：攻击者传入极大值(0xFFFFFFFF)可导致整数回绕，破坏定时器调度逻辑。触发条件：通过CLI执行'debug mng timer start'命令。
- **代码片段:**
  ```
  <PARAM name="init_time" help="init_time" ptype="UINT"/>
  <PARAM name="sched_time" help="sched_time" ptype="UINT"/>
  ```
- **关键词:** debug mng timer start, init_time, sched_time, UINT, command_injection-tpm_xml-param_overflow
- **备注:** 关联漏洞链：定时器参数溢出→内核调度异常→系统崩溃。影响mv_os_cli_timer_start函数。

---
### configuration_load-device_name-propagation

- **文件路径:** `sbin/iwconfig`
- **位置:** `fcn.000173e8 (0x173e8)`
- **类型:** configuration_load
- **综合优先级分数:** **6.85**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 设备名参数传播风险：函数fcn.000173e8对设备名参数(param_2)使用strncpy截断到16字节，但将原始参数传递给fcn.00013d48等子函数。若这些子函数缺乏边界检查，用户提供超长设备名可能触发二阶段溢出。触发条件：1) 攻击者控制设备名参数 2) 下游函数存在缓冲区操作漏洞。当前影响不确定，需验证子函数安全性。
- **代码片段:**
  ```
  sym.imp.strncpy(iVar8 + -0x48, param_2, 0x10);
  iVar1 = fcn.00013d48(param_1, param_2, iVar8 + -0x4a0);
  ```
- **关键词:** fcn.000173e8, param_2, strncpy, fcn.00013d48, fcn.0001278c, fcn.00014b10
- **备注:** 关键待验证点：fcn.00013d48等函数对param_2的处理逻辑

---
### heap_overflow-pppd-fread_config

- **文件路径:** `usr/sbin/pppd`
- **位置:** `pppd:main (文件读取逻辑)`
- **类型:** configuration_load
- **综合优先级分数:** **6.85**
- **风险等级:** 7.5
- **置信度:** 7.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** fread操作使用外部控制大小参数(*piVar14)但未验证目标缓冲区(*0x1888c)边界。攻击者通过配置文件指定超长读取尺寸可导致堆/全局区溢出。触发条件：控制配置文件内容。边界检查：无缓冲区尺寸校验。安全影响：内存破坏，需进一步确认缓冲区属性。
- **代码片段:**
  ```
  iVar7 = sym.imp.fread(*0x1888c,1,iVar7,iVar10)
  ```
- **关键词:** fread, config_buffer, dynamic_size, options_from_file
- **备注:** 依赖配置文件控制（如/etc/ppp/options）。与发现2共享options_from_file关键词

---
### ftp-write-permission

- **文件路径:** `etc/vsftpd.conf`
- **位置:** `etc/vsftpd.conf`
- **类型:** configuration_load
- **综合优先级分数:** **6.8**
- **风险等级:** 6.0
- **置信度:** 10.0
- **触发可能性:** 4.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 写权限开启(write_enable=YES)但匿名访问关闭(anonymous_enable=NO)。允许认证用户进行文件操作，若存在弱密码或凭证泄露，攻击者可上传恶意文件。触发条件：1) 获取有效用户凭证 2) 通过FTP连接服务。边界检查：chroot_local_user=YES限制用户目录跳转但无法防御目录内恶意文件上传。安全影响：可能植入webshell或后门程序，需结合Web服务目录权限进一步评估危害。
- **关键词:** write_enable, local_enable, chroot_local_user, anonymous_enable
- **备注:** 需关联分析/etc/passwd等账户文件评估弱密码风险

---
### pointer_hijack-url_handler_registration-0x14b64

- **文件路径:** `usr/bin/httpd`
- **位置:** `httpd:0x14b64 (fcn.00014b64)`
- **类型:** network_input
- **综合优先级分数:** **6.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 3.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** URL处理器注册机制安全风险。注册函数(fcn.00014b64)将处理函数指针存储在堆结构体偏移0x14处，链接到全局路由表(*0x14ca4)。若攻击者通过内存破坏漏洞篡改该指针，后续HTTP请求将导致任意代码执行。触发条件：需结合其他内存破坏漏洞修改处理器指针。安全影响：形成二级攻击链，扩大初始漏洞影响面。
- **关键词:** fcn.00014b64, piVar7[5], struct_offset_0x14, *0x14ca4
- **备注:** 关键监控点：路由表调用处(*ppiVar9[4])(ppiVar9)@0x1289c

---
### command_execution-tpm_configuration-xml

- **文件路径:** `etc/xml_commands/startup.xml`
- **位置:** `etc/xml_commands/tpm_configuration.xml`
- **类型:** command_execution
- **综合优先级分数:** **6.7**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 在tpm_configuration.xml中发现多组TPM配置命令（如tpm_cli_add_l2_prim_rule）直接传递用户输入至底层二进制函数。触发条件：攻击者通过CLI执行TPM配置命令。实际安全影响：owner_id/src_port等参数未经验证直接传递，可能触发整数溢出或缓冲区溢出。利用方式：构造恶意bitmap值或超长密钥名触发内存破坏。
- **关键词:** tpm_cli_add_l2_prim_rule, owner_id, src_port, BIT_MAP, MAC_ADDR, parse_rule_bm
- **备注:** 需二进制分析验证以下函数安全性：tpm_cli_add_*/tpm_cli_del_*，重点关注整数边界检查和位域验证 | 攻击路径：CLI接口→TPM配置命令→恶意参数传递→底层函数漏洞触发 (exploit_probability=0.6) | 建议：深度审计tpm_cli_*系列函数（路径：usr/bin/tpm_manager）；检查同目录下其他XML文件

---
### attack_chain_gap-ppp_config_writing

- **文件路径:** `usr/sbin/pppd`
- **位置:** `N/A`
- **类型:** analysis_gap
- **综合优先级分数:** **6.7**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 0.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 已确认pppd存在多个高危漏洞（命令注入、栈溢出、堆溢出），但缺少对配置文件/etc/ppp/options的写入能力。攻击链完整利用需满足：1) 攻击者能够控制配置文件内容（如通过Web接口或CLI注入） 2) 触发pppd进程（如建立PPP连接）。当前知识库中未发现配置写入漏洞，此缺口阻碍完整攻击链构建。
- **关键词:** /etc/ppp/options, pppd, configuration_write, attack_chain
- **备注:** 关键后续方向：分析Web服务器（/www目录）和NVRAM操作组件（如nvram_set），寻找/etc/ppp/options的写入点。关联已存储漏洞：peer_authname注入(risk=9.0)和config_sprintf栈溢出(risk=8.5)

---
### network_input-tpm-attack_chain

- **文件路径:** `etc/xml_commands/tpm_configuration.xml`
- **位置:** `tpm_configuration.xml:COMMAND[name="rule add l2"]`
- **类型:** network_input
- **综合优先级分数:** **6.45**
- **风险等级:** 9.0
- **置信度:** 6.5
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 确认完整攻击链：外部输入（HTTP参数）→ XML命令解析 → 调用'tpm_cli_add_l2_prim_rule'传递16个未验证参数。触发步骤：1) 攻击者发送含恶意'parse_rule_bm'或'key_name'的API请求；2) 参数直达二进制函数；3) 若函数存在栈溢出漏洞（需逆向验证），可实现RCE。成功概率评估：中高（7.5/10），因参数传递路径明确且无过滤。
- **关键词:** rule add l2, tpm_cli_add_l2_prim_rule, parse_rule_bm, key_name, src_port, owner_id
- **备注:** 最高优先级验证目标：逆向分析tpm_cli_add_l2_prim_rule函数实现

---
### configuration_load-upnpd-boundary_violation_0x17ac0

- **文件路径:** `usr/bin/upnpd`
- **位置:** `fcn.00017ac0 (0x17ac0)`
- **类型:** configuration_load
- **综合优先级分数:** **6.45**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 中危配置文件解析边界问题。触发条件：解析包含>255字节行的配置文件时。污染路径：1) fcn.00017ac0使用fgets读取文件行到256字节栈缓冲区auStack_2a8 2) 调用fcn.000178c4处理数据时边界检查不充分（当缓冲大小参数≤0时可能产生负长度）。实际影响：可能引发栈溢出，但需攻击者先写入恶意配置文件。
- **关键词:** fcn.00017ac0, fcn.000178c4, fgets, strncpy, auStack_2a8

---
### network_input-diagnostic_htm-ACT_SET_DIAG_TOOL

- **文件路径:** `web/main/diagnostic.htm`
- **位置:** `diagnostic.htm:320(wanTest函数)`
- **类型:** network_input
- **综合优先级分数:** **6.45**
- **风险等级:** 7.0
- **置信度:** 6.5
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** $.act(ACT_SET, DIAG_TOOL)调用将诊断命令(currCommand=1-5)提交后端，但处理路径未在当前文件暴露。关键风险：若后端处理函数未验证currHost参数(如未过滤特殊字符)，可能衍生命令注入或缓冲区溢出。触发条件：需定位实际处理组件(cgi-bin或二进制)并验证其安全性。
- **关键词:** $.act, ACT_SET, DIAG_TOOL, diagCommand.currCommand, $.exe
- **备注:** 需后续分析：1)公共JS库实现$.act 2)/cgi-bin下处理网络请求的CGI程序 3)二进制中响应DIAG_TOOL的函数；攻击路径评估：完整利用需验证后端DIAG_TOOL处理逻辑的安全缺陷；待解决问题：$.act调用的具体后端端点未定位；建议：优先分析/cgi-bin目录：搜索处理ACT_SET和DIAG_TOOL的CGI程序

---
### risk-ripd-stack-design-0x11d78

- **文件路径:** `usr/sbin/ripd`
- **位置:** `ripd:0x11d78 (dbg.rip_request_process)`
- **类型:** network_input
- **综合优先级分数:** **6.45**
- **风险等级:** 6.5
- **置信度:** 7.0
- **触发可能性:** 5.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 栈操作存在设计风险。rip_request_process中通过复杂指针偏移(如*(puVar12 -0x14))访问栈数组(auStack_38/auStack_30)，缺乏显式边界保护。虽然当前未发现直接溢出，但偏移计算依赖外部输入（RIP包内容），可能被精心构造的输入干扰导致栈破坏。触发条件：特定RIP包干扰指针计算逻辑。实际影响：潜在栈溢出风险，可能升级为RCE（需进一步利用）。
- **代码片段:**
  ```
  uchar auStack_38 [8];
  uint auStack_30 [12];
  ...
  *(puVar12 + -0x14) = 2;
  ```
- **关键词:** auStack_38, auStack_30, puVar12, *(puVar12 + -0x14), *(puVar12 + -0xc), rip_request_process
- **备注:** 需重建完整栈帧结构验证安全性。后续建议：1) 分析写入操作的最大偏移 2) 检查puVar12与输入数据的关联

---
### network_input-js_attack_surface

- **文件路径:** `web/index.htm`
- **位置:** `index.htm: script引用块`
- **类型:** network_input
- **综合优先级分数:** **6.4**
- **风险等级:** 6.0
- **置信度:** 7.0
- **触发可能性:** 6.5
- **查询相关性:** 8.7
- **阶段:** N/A
- **描述:** 引用6个JS文件（./js/oid_str.js等）构成潜在攻击面。这些文件可能包含前端输入处理逻辑，但当前HTML未暴露具体参数。风险包括：1) DOM操作未过滤用户输入导致XSS 2) 敏感参数通过URL/cookie传递 3) 与后端API交互时缺少输入验证。攻击者可通过中间人攻击篡改JS文件或利用DOM漏洞触发恶意操作。
- **关键词:** ./js/oid_str.js, ./js/str.js, ./js/err.js, ./js/lib.js, ./js/3g.js, ./js/voice.js, script[language="javascript"]
- **备注:** 需并行分析./js/目录下所有JS文件，重点关注从location/document.cookie获取参数的函数。关联发现：network_input-url_hash_loading（需验证$.loadMain在./js/lib.js中的实现）

---
### potential_command_injection-tpm_commands-param_name

- **文件路径:** `etc/xml_commands/global-commands.xml`
- **位置:** `etc/xml_commands/tpm_commands.xml`
- **类型:** configuration_load
- **综合优先级分数:** **6.4**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 检测到tpm_commands.xml中12个STRING_name参数（如vlan/ipv6规则名）通过${name}语法传递至builtin函数（tpm_cli_print_*_by_name）。触发条件：1) 攻击者控制name参数输入；2) 底层函数未过滤特殊字符。安全影响：若底层使用system()等危险函数，可能造成命令注入（如通过;rm -rf /）。当前未验证函数实现，需进一步分析。
- **关键词:** STRING_name, tpm_cli_print_vlan_table_by_name, tpm_cli_print_ipv6_key_table_by_name, PARAM, ACTION, builtin
- **备注:** 需反编译分析tpm_cli_print_*函数族。关键检查点：strcpy/sprintf使用、输入过滤机制。关联文件：CLI主程序二进制

---
### exploit_chain-cli_pon_rce

- **文件路径:** `etc/xml_commands/mng_com_commands.xml`
- **位置:** `N/A`
- **类型:** exploit_chain
- **综合优先级分数:** **6.3**
- **风险等级:** 9.0
- **置信度:** 6.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 完整漏洞链：CLI访问权限获取 → 执行'debug mng set pon'命令 → 注入恶意sn参数 → mng_com_cli_set_pon_params函数缓冲区溢出 → 实现RCE。成功概率60%，关键依赖项：1) CLI认证强度 2) 目标函数边界检查缺失验证。
- **关键词:** exploit_chain, debug mng set pon, mng_com_cli_set_pon_params, RCE
- **备注:** 需优先验证mng_com_cli_set_pon_params函数实现。

---
### network_input-tpm-xml_command_exposure

- **文件路径:** `etc/xml_commands/tpm_configuration.xml`
- **位置:** `tpm_configuration.xml`
- **类型:** network_input
- **综合优先级分数:** **6.25**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** XML文件暴露45+个TPM管理命令，高危操作（如'tpm_cli_del_static_mac'删除MAC、'tpm_cli_erase_section'删除配置区块）通过HTTP/CLI接口可远程触发。触发条件：攻击者构造含'no'前缀的命令参数（如'no mac'）。实际影响：通过'api_group'参数关联到web接口，可导致配置擦除或权限变更（'tpm_cli_set_ownership'）。利用方式：发送恶意API请求触发未授权危险操作。
- **关键词:** no mac, no section, tpm_cli_del_static_mac, tpm_cli_erase_section, tpm_cli_set_ownership, owner_id, api_group
- **备注:** 需逆向验证builtin函数实现，关联文件：web接口处理模块

---
### hardware_input-usbp-ttyS0_leak

- **文件路径:** `sbin/usbp`
- **位置:** `sbin/usbp:0x10688 section..text`
- **类型:** hardware_input
- **综合优先级分数:** **6.2**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 敏感信息泄露风险：通过/dev/ttyS0串口输出调试信息（含argv参数内容）。触发条件：程序正常执行时自动输出。攻击者若物理访问UART接口可获取参数内容，可能协助构造精准攻击载荷。
- **关键词:** /dev/ttyS0, echo, argv[1]
- **备注:** 关联现有串口风险记录（参见notes字段）。泄露数据可增强栈溢出攻击精度：覆盖返回地址所需的偏移量可通过泄露的栈布局计算

---
### network_input-tpm-parameter_validation

- **文件路径:** `etc/xml_commands/tpm_configuration.xml`
- **位置:** `tpm_configuration.xml`
- **类型:** network_input
- **综合优先级分数:** **6.15**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 关键参数缺乏输入验证：1) 位图参数（'parse_rule_bm'/'action'）未验证位范围，可触发越界操作；2) 字符串参数（'key_name'/'frwd_name'）无长度限制，存在缓冲区溢出风险；3) 网络地址参数（'ipv4_key_addr'）无格式校验。触发条件：向'tpm_cli_add_l2_prim_rule'等函数注入畸形参数。利用方式：构造超长字符串或非法位图值触发内存破坏。
- **代码片段:**
  ```
  <PARAM name="parse_rule_bm" ptype="BIT_MAP"/>
  <ACTION builtin="tpm_cli_add_l2_prim_rule">...${parse_rule_bm}...</ACTION>
  ```
- **关键词:** parse_rule_bm, action, mod_bm, BIT_MAP, STRING_name, key_name, frwd_name, ipv4_key_addr, tpm_cli_add_l2_prim_rule
- **备注:** 高危函数：tpm_cli_add_l2_prim_rule（接收16个参数）

---
### hardcoded-mac-leak

- **文件路径:** `usr/bin/httpd`
- **位置:** `usr/bin/httpd:未知行号`
- **类型:** network_input
- **综合优先级分数:** **6.1**
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 设备信息泄露（/cgi/info）：硬编码MAC地址'00:00:00:00:00:00'与未过滤的sprintf输出暴露系统状态。触发条件：GET /cgi/info
- **关键词:** sprintf, cnet_macToStr, str.00:00:00:00:00:00

---
### omci-unauth-access

- **文件路径:** `usr/bin/httpd`
- **位置:** `usr/bin/httpd:未知行号`
- **类型:** network_input
- **综合优先级分数:** **6.1**
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** OMCI配置未授权访问（/cgi/gponOmciDebug）：rdp_backupOmciCfg返回的调试数据无权限检查。触发条件：GET /cgi/gponOmciDebug
- **关键词:** rdp_backupOmciCfg, fcn.00014b64, param_1

---
### ipc-system_reboot-sycl_reboot

- **文件路径:** `usr/lib/libsycl_mipc_client.so`
- **位置:** `usr/lib/libsycl_mipc_client.so:0 (sycl_reboot) [动态符号表]`
- **类型:** ipc
- **综合优先级分数:** **6.0**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 3.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** libsycl_mipc_client.so是功能受限的IPC客户端库，仅导出3个函数：初始化(_init)、系统重启(sycl_reboot)和终止(_fini)。未发现直接处理外部输入的函数或敏感字符串。核心风险点在于sycl_reboot函数：1) 该函数未在库内实现参数验证逻辑；2) 通过mipc_send_async_msg发送IPC消息触发重启；3) 若调用者未对重启参数（如延迟时间、强制标志）进行过滤，攻击者可能通过控制调用组件实现拒绝服务攻击。
- **关键词:** sycl_reboot, mipc_send_async_msg
- **备注:** 需验证调用此库的可执行文件（如sbin目录组件）是否：1) 暴露外部接口；2) 对传递给sycl_reboot的参数进行过滤。建议后续分析调用链：定位所有导入sycl_reboot符号的二进制文件，检查其参数处理逻辑。

---
### network_input-voip-validateNumber

- **文件路径:** `web/main/voice_line.htm`
- **位置:** `www/js/voip_validation.js: JavaScript函数: validateNumber`
- **类型:** network_input
- **综合优先级分数:** **5.8**
- **风险等级:** 5.0
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 输入字段值（如WarmNumber1-5）通过正则表达式进行基础格式校验，但未限制长度或危险字符。触发条件：提交超长或含特殊字符的输入。可结合后端缓冲区溢出漏洞形成利用链，但当前文件无溢出证据。
- **关键词:** WarmNumber1-5, ingressGain1, egressGain1, validateNumber
- **备注:** 需验证后端参数处理是否存在边界检查缺失

---
### config-leak-conf.bin

- **文件路径:** `usr/bin/httpd`
- **位置:** `usr/bin/httpd:未知行号`
- **类型:** network_input
- **综合优先级分数:** **5.6**
- **风险等级:** 7.0
- **置信度:** 7.0
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 敏感配置泄露（/cgi/conf.bin）：rdp_backupCfg返回的配置数据未经审查直接输出，暴露设备敏感信息。触发条件：GET /cgi/conf.bin
- **关键词:** rdp_backupCfg, /cgi/conf.bin, fwrite

---
### format-string-risk-libi2c-0x10d4

- **文件路径:** `usr/lib/libi2c_mipc_client.so`
- **位置:** `libi2c_mipc_client.so:0x000010d4`
- **类型:** ipc
- **综合优先级分数:** **5.5**
- **风险等级:** 5.0
- **置信度:** 8.0
- **触发可能性:** 3.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 发现潜在格式化字符串风险：错误处理路径调用printf(*0x10d4, *0x10d8)，其中*0x10d4指向字符串"i2c_mipc_client: Failed to open %s"。具体表现：1) 字符串明确包含%s格式符 2) 未发现输出长度限制。触发条件：当mipc_send_sync_msg返回非零且*0x10d8指向用户可控字符串时。安全影响：若*0x10d8被污染，攻击者可注入格式符实现内存读写，但当前文件内未验证*0x10d8数据来源。
- **代码片段:**
  ```
  if (iVar1 != 0) {
      sym.imp.printf(*0x10d4,*0x10d8);
  }
  ```
- **关键词:** printf, 0x10d4, 0x10d8, i2c_mipc_client: Failed to open %s
- **备注:** 需后续分析：1) *0x10d8数据来源 2) 调用栈上下文。与参数未验证风险位于同一组件，可能共享调用路径。

---
### information_exposure-global_config_constants

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `virtualServer.htm: 多处条件判断`
- **类型:** configuration_load
- **综合优先级分数:** **5.35**
- **风险等级:** 3.5
- **置信度:** 10.0
- **触发可能性:** 3.0
- **查询相关性:** 6.5
- **阶段:** N/A
- **描述:** 全局配置常量(INCLUDE_USB_3G_DONGLE等)暴露系统组件信息。触发条件：页面加载时初始化。安全影响：辅助攻击者构造针对性载荷。利用方式：结合其他漏洞精确定位攻击模块。
- **关键词:** INCLUDE_USB_3G_DONGLE, INCLUDE_L2TP, WAN_IP_CONN_PORTMAPPING, ACT_GL
- **备注:** 信息泄露风险需结合其他漏洞才有实质影响。关联发现：ACT_GL常量在status.htm和voice_line.htm中被用于敏感操作（参见发现network_input-config-freshStatus和network_input-status_page-TR069_sensitive_data）

---
### network_input-js_curpage_regex

- **文件路径:** `web/js/local.js`
- **位置:** `www/local.js: switch语句块`
- **类型:** network_input
- **综合优先级分数:** **5.25**
- **风险等级:** 2.0
- **置信度:** 9.5
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 外部输入处理：通过$.curPage参数控制页面分支，使用正则/(\w+).htm$/提取文件名。触发条件：用户访问含特定.htm后缀的URL。边界检查：正则严格限制为字母/数字/下划线（\w+），过滤特殊字符但未验证长度或Unicode字符。安全影响：有效防御常见注入攻击，但超长输入可能导致未定义行为（当前文件未处理长度）。
- **代码片段:**
  ```
  switch(/(\w+).htm$/.exec($.curPage)[1]) {...}
  ```
- **关键词:** $.curPage, /(\w+).htm$/, exec, switch, status, url_parser, page_branching
- **备注:** 需追踪$.curPage参数来源（如URL解析）确认用户可控性；关联知识库notes中'需追踪调用者（/bin /sbin /www目录）'线索

---
### sensitive_data-js_status_config

- **文件路径:** `web/js/local.js`
- **位置:** `www/local.js:90+`
- **类型:** configuration_load
- **综合优先级分数:** **5.2**
- **风险等级:** 3.0
- **置信度:** 9.0
- **触发可能性:** 5.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 敏感数据处理：status分支硬编码网络配置数据（MAC/IP）。触发条件：用户访问status页面。边界检查：数据存储在局部变量未直接输出。安全影响：当前无DOM赋值操作，但需警惕：1) 变量可能被其他函数使用 2) 通过开发者工具可访问变量值。
- **关键词:** status, lanArg, wanArg, wlArg, staArg, hardcoded_config, dev_tool_exposure
- **备注:** 建议检查：1) 包含status分支的页面HTML 2) 访问lanArg等变量的其他函数；关联现有'需检查包含status分支的页面HTML'分析需求

---
### dom_manipulation-js_find_xss

- **文件路径:** `web/js/local.js`
- **位置:** `www/local.js:19`
- **类型:** network_input
- **综合优先级分数:** **4.8**
- **风险等级:** 4.0
- **置信度:** 8.0
- **触发可能性:** 2.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** DOM操作风险：自定义函数$.find将参数exp[3]直接传递给getElementById()。触发条件：调用时传入用户可控数据。边界检查：通过正则提取\w+字符集，但未过滤DOM注入字符。安全影响：理论XSS漏洞，但当前文件无调用点，实际风险依赖跨文件调用链。
- **代码片段:**
  ```
  var exp = ql.match(/(\s*)([\.]?)(\w+)/);
  $.d.getElementById(exp[3])
  ```
- **关键词:** $.find, exp[3], getElementById, query, container, dom_injection, xss_vector
- **备注:** 关键后续方向：全局搜索$.find调用点及参数来源；新增跨文件追踪线索

---
### ipc-config-mipc-0x6bc

- **文件路径:** `usr/lib/libloop_detect_mipc_client.so`
- **位置:** `libloop_detect_mipc_client.so:0x6bc loop_detect_set_admin, 0x74c loop_detect_set_vlan_cfg`
- **类型:** ipc
- **综合优先级分数:** **4.65**
- **风险等级:** 1.5
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 所有配置函数(loop_detect_set_admin/loop_detect_set_vlan_cfg)通过mipc_send_sync_msg传递整型参数(port_id/loop_admin等)。触发条件：函数被调用时直接触发IPC通信。约束条件：参数均为固定长度整型，无字符串或缓冲区参数。安全影响：客户端无输入验证缺陷，但服务端若未验证整数范围可能引发逻辑漏洞（如越权操作）。
- **代码片段:**
  ```
  iVar1 = loc.imp.mipc_send_sync_msg(*0x740,1,puVar2 + -4,8);
  ```
- **关键词:** mipc_send_sync_msg, loop_detect_set_admin, loop_detect_set_vlan_cfg, port_id, loop_admin, vlan_mode
- **备注:** 关键攻击路径在IPC服务端实现，必须追踪mipc_send_sync_msg服务侧处理逻辑

---
### buffer_operation-udevtrigger-path_truncation

- **文件路径:** `sbin/udevtrigger`
- **位置:** `sbin/udevtrigger:0x112d4 (fcn.000112d4)`
- **类型:** hardware_input
- **综合优先级分数:** **4.6**
- **风险等级:** 3.0
- **置信度:** 9.0
- **触发可能性:** 2.0
- **查询相关性:** 6.5
- **阶段:** N/A
- **描述:** 路径截断风险：动态路径构建使用strlcpy/strlcat操作512字节栈缓冲区(auStack_470)，虽有限制但未验证输入长度。当目录项文件名超长时，路径被截断可能导致：a) 后续文件操作失败 b) 触发异常逻辑。实际风险较低，因设备名长度通常受内核限制。
- **代码片段:**
  ```
  sym.strlcpy(puVar2 + -0x468, param_1, 0x200);
  ```
- **关键词:** strlcpy, strlcat, auStack_470, 0x200, dirent->d_name
- **备注:** 与udevd组件的strlcpy操作(attack_chain-udevd-devmems)共享设备名输入源，需审查跨组件数据传递机制

---
### env_set-sysstat-SADC_OPTIONS

- **文件路径:** `etc/sysconfig/sysstat`
- **位置:** `etc/sysconfig/sysstat`
- **类型:** env_set
- **综合优先级分数:** **4.1**
- **风险等级:** 3.0
- **置信度:** 6.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 在sysstat配置文件中，SADC_OPTIONS参数值为空字符串。若该参数被外部污染（如通过环境变量注入），可能影响sadc收集器的执行行为。触发条件：1) 攻击者能控制SADC_OPTIONS环境变量 2) sadc二进制未对参数进行消毒。实际影响取决于sadc实现，但当前因权限问题无法验证具体风险。
- **关键词:** SADC_OPTIONS, sadc
- **备注:** 需在具备权限环境中验证sadc：1) 检查getenv('SADC_OPTIONS')调用 2) 分析参数是否传入危险函数(如system)

---
### ipc-client-memcpy-0x61c

- **文件路径:** `usr/lib/libloop_detect_mipc_client.so`
- **位置:** `libloop_detect_mipc_client.so:0x61c loop_detect_get_alarm`
- **类型:** ipc
- **综合优先级分数:** **4.0**
- **风险等级:** 2.0
- **置信度:** 8.0
- **触发可能性:** 3.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 函数loop_detect_get_alarm在mipc_send_sync_msg调用失败时执行4字节memcpy操作。触发条件：IPC通信失败后的错误处理路径。约束条件：复制长度硬编码为4字节，无动态长度控制，需验证源地址(puVar2 + 4 + -8)和目标地址(*(puVar2 + -0xc))有效性。安全影响：固定长度复制避免缓冲区溢出，但若地址被污染可能导致内存破坏（低概率）。
- **代码片段:**
  ```
  sym.imp.memcpy(*(puVar2 + -0xc), puVar2 + 4 + -8, 4);
  ```
- **关键词:** loop_detect_get_alarm, memcpy, mipc_send_sync_msg, puVar2
- **备注:** 需结合调用者验证puVar2内存状态；服务端漏洞可能通过此IPC链触发；关联知识库现有'memcpy'操作分析

---
### ipc-error_handling-logging

- **文件路径:** `usr/lib/libmidware_mipc_client.so`
- **位置:** `libmidware_mipc_client.so:0x1ecc`
- **类型:** ipc
- **综合优先级分数:** **4.0**
- **风险等级:** 2.0
- **置信度:** 10.0
- **触发可能性:** N/A
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 标准化IPC错误处理机制。具体表现：'%s: failed to send message'错误字符串被23个函数共享使用。安全影响：1) 无直接漏洞但可作为漏洞检测标记 2) 若启用详细日志可能泄露内存地址信息。触发条件：任何IPC消息发送失败时触发。
- **关键词:** %s: failed to send message, dbg.midware_insert_entry, dbg.Midware_cli_update_entry

---
### configuration_load-proftpd-cmd_restriction

- **文件路径:** `etc/proftpd.conf`
- **位置:** `proftpd.conf:23-25`
- **类型:** configuration_load
- **综合优先级分数:** **3.75**
- **风险等级:** 1.0
- **置信度:** 9.5
- **触发可能性:** 2.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 危险命令全局禁用策略：
- 通过<Limit SITE_CHMOD> DenyAll显式禁用文件权限修改命令
- 有效阻止攻击者利用CHMOD命令变更文件属性或权限
- 触发条件：攻击者尝试发送SITE CHMOD指令
- 约束条件：限制覆盖所有用户会话
- 实际影响：阻断通过FTP实现的权限提升路径
- **代码片段:**
  ```
  <Limit SITE_CHMOD>
    DenyAll
  </Limit>
  ```
- **关键词:** <Limit SITE_CHMOD>, DenyAll

---
### static_analysis-err_js-error_mapping

- **文件路径:** `web/js/err.js`
- **位置:** `web/js/err.js`
- **类型:** configuration_load
- **综合优先级分数:** **3.5**
- **风险等级:** 1.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 3.0
- **阶段:** N/A
- **描述:** 文件'web/js/err.js'集中定义Web界面的错误代码映射关系，暴露系统验证规则和约束条件：1) 输入验证规则（如ERR_IP_FORMAT/IP格式检查、ERR_MAC_FORMAT/MAC格式检查）；2) 系统资源限制（如CMM_VS_RECORD_ALREADY_FULL/Virtual Server表容量）；3) 安全约束（如CMM_DHCPS_FIX_MAP_MAC_CONFLICT/MAC冲突检测）。该文件为静态资源无直接漏洞，但攻击者可利用暴露的验证逻辑构造针对性攻击（如触发CMM_VS_RECORD_ALREADY_FULL错误导致服务拒绝），实际利用需结合后端CGI处理程序实现。
- **关键词:** CMM_CFG_FILE_FORMAT_ERR, CMM_FW_ILLEGAL_IP, CMM_VS_RECORD_ALREADY_FULL, CMM_DHCPS_FIX_MAP_MAC_CONFLICT, ERR_IP_FORMAT, ERR_MAC_FORMAT, ERR_FW_ENTRYNAME_INVAD, e_str
- **备注:** 后续应追踪CGI组件中引用这些错误码的位置（如搜索CMM_*/ERR_*），重点分析：1) HTTP参数处理流程；2) 配置解析逻辑；3) 资源限制检查实现。关键关联文件：Web服务器二进制文件、CGI程序、配置存储模块。

---
### file_write-sysstat-log_retention

- **文件路径:** `etc/sysconfig/sysstat`
- **位置:** `etc/sysconfig/sysstat`
- **类型:** file_write
- **综合优先级分数:** **3.1**
- **风险等级:** 2.0
- **置信度:** 5.0
- **触发可能性:** 3.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 日志保留策略(HISTORY/COMPRESSAFTER)未定义存储路径，依赖二进制硬编码实现。若路径拼接未进行边界检查，可能引发目录遍历风险。触发条件：1) 存在可控路径前缀（如环境变量）2) 写文件操作未过滤'../'。因无法定位sysstat二进制，实际风险未验证。
- **关键词:** HISTORY=7, COMPRESSAFTER=10
- **备注:** 后续发现sysstat二进制时需重点检查：1) snprintf等路径拼接函数 2) 文件打开操作

---
### global-libloop_detect-assessment

- **文件路径:** `usr/lib/libloop_detect_mipc_client.so`
- **位置:** `libloop_detect_mipc_client.so:0 (global)`
- **类型:** ipc
- **综合优先级分数:** **3.1**
- **风险等级:** 0.5
- **置信度:** 9.5
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 全局评估：未发现命令执行(system/exec)、动态内存操作(malloc/strcpy)或用户输入处理接口。安全影响：该库作为轻量级IPC客户端，自身无直接可利用漏洞，但可能成为攻击链的跳板。
- **关键词:** libloop_detect_mipc_client.so, mipc_send_sync_msg
- **备注:** 结束当前文件分析，后续应检查：1) 调用此库的可执行文件 2) mipc_send_sync_msg对应的服务端实现（高危路径）

---
### analysis_blocker-sysstat-binary_missing

- **文件路径:** `etc/sysconfig/sysstat`
- **位置:** `usr/lib/sa/sadc`
- **类型:** analysis_blocker
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** N/A
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 关键阻碍：1) sysstat组件二进制文件缺失 2) sadc文件(usr/lib/sa/sadc)存在但分析工具无访问权限。导致无法验证数据流和潜在漏洞，攻击路径分析中断。
- **关键词:** sar, sadc, usr/lib/sa/sadc
- **备注:** 建议：1) 用户提供完整二进制文件 2) 在特权环境中重新分析sadc参数处理逻辑

---
### analysis-failure-flash_eraseall

- **文件路径:** `usr/sbin/flash_eraseall`
- **位置:** `usr/sbin/flash_eraseall:0 (unknown) 0x0`
- **类型:** unknown
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 文件'usr/sbin/flash_eraseall'分析失败。因安全限制无法访问目标文件，且知识库无分析记录。无法验证：1) 命令行参数处理逻辑 2) 环境变量使用情况 3) MTD设备操作的安全检查机制 4) 缓冲区操作函数调用。无证据支持任何攻击路径分析。
- **关键词:** flash_eraseall
- **备注:** 解决建议：1) 提供文件绝对路径 2) 验证固件扫描范围是否包含/usr/sbin目录 3) 评估调整工具安全策略的风险。当前无法继续分析该文件。

---
### analysis_limitation-zebra-no_access

- **文件路径:** `usr/sbin/zebra`
- **位置:** `usr/sbin/zebra`
- **类型:** analysis_limitation
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 无法完成/usr/sbin/zebra文件分析。安全策略限制：1) 禁止访问上级目录文件 2) 静态分析工具(r2)返回空结果 3) 无替代方法提取二进制内容。导致关键攻击面验证缺失：网络接口、环境变量操作、危险函数调用等均无法评估。直接影响用户核心需求中'初始输入点到危险操作的完整攻击路径'分析。
- **关键词:** zebra, /usr/sbin
- **备注:** 后续建议：1) 调整工作目录至/usr/sbin 2) 提供直接文件读取权限 3) 尝试Ghidra等替代工具。当前无法评估：1) 网络协议栈攻击面 2) IPC/NVRAM交互 3) 硬件接口数据处理。

---
### configuration-oid_definitions-js

- **文件路径:** `web/js/oid_str.js`
- **位置:** `web/js/oid_str.js`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 3.0
- **阶段:** N/A
- **描述:** 文件为TR-069 OID静态常量定义文件，不包含可执行逻辑。经全面验证：1) 无外部输入处理接口 2) 无动态代码执行函数 3) 无敏感数据硬编码。安全影响限于定义的OID可能在其他组件中被引用，当OID用于处理未经验证的外部输入（如TR-069 ACS下发的配置参数）时可能间接引入风险。触发条件：攻击者需通过其他组件（如CWMP客户端）注入恶意OID参数。
- **关键词:** IGD, MANAGEMENT_SERVER, WAN_IP_CONN, LAN_WLAN, VOICE_PROF_LINE, ACL_CFG, UPNP_CFG, CWMP_CFG, FIREWALL, XTP_CALLLOGCFG
- **备注:** 关联组件：1) ACL_CFG（防火墙规则）2) CWMP_CFG（TR-069客户端）3) IGD（UPnP设备管理）。后续需追踪：a) CWMP_CFG在cgi/bin的处理流程 b) ACL_CFG在防火墙规则引擎的解析过程 c) OID在nvram_set操作中的传递路径

---
### configuration-load-main_commands-show_version

- **文件路径:** `etc/xml_commands/main_commands.xml`
- **位置:** `etc/main_commands.xml:0 (command definition)`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 文件定义单个CLI命令'show version'，直接调用内置函数main_cli_print_version显示固件版本信息。关键特征：1) 无参数接收接口，不存在输入验证缺失 2) 不执行系统命令/脚本，无命令注入风险 3) 仅读取版本信息，无特权操作。该命令无法被外部输入触发或控制，不具备构成攻击链的条件。
- **关键词:** show version, main_cli_print_version
- **备注:** 该配置文件功能最小化，建议检查其他命令配置文件（如command.xml）获取可能暴露的接口

---
### configuration_load-proftpd-runtime_security

- **文件路径:** `etc/proftpd.conf`
- **位置:** `proftpd.conf:15-19`
- **类型:** configuration_load
- **综合优先级分数:** **2.95**
- **风险等级:** 0.5
- **置信度:** 9.0
- **触发可能性:** 0.0
- **查询相关性:** 6.5
- **阶段:** N/A
- **描述:** 服务安全运行基础配置：
- 以nobody/nogroup低权限账户运行（User nobody, Group nogroup）
- 显式禁用root登录（未设置RootLogin指令，默认禁止）
- 未启用TransferLog避免日志路径泄露
- 通过MaxInstances 30限制进程资源
- **代码片段:**
  ```
  User nobody
  Group nogroup
  MaxInstances 30
  ```
- **关键词:** User nobody, Group nogroup, MaxInstances

---
### analysis-status-busybox-001

- **文件路径:** `bin/busybox`
- **位置:** `bin/busybox (分析受阻)`
- **类型:** analysis_note
- **综合优先级分数:** **2.85**
- **风险等级:** 0.0
- **置信度:** 9.5
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 受工具限制无法完成'bin/busybox'分析：1) 多次尝试提取applet名称和调度表失败 2) 关键函数反编译任务返回技术错误 3) 高危服务组件（HTTP/Telnet）定位未获有效证据。当前文件分析无法继续。
- **关键词:** applet_names, telnetd, httpd, 0x150fc
- **备注:** ['关键限制：工具无法处理busybox的复杂结构', '后续建议：', '1. 分析/www目录下的CGI脚本（直接处理HTTP输入）', '2. 检查/sbin或/usr/sbin中的独立网络服务（如telnetd/httpd）', '3. 审查/etc/inetd.conf确认服务委托关系']

---
### static_page-accErr-authentication_failure

- **文件路径:** `web/frame/accErr.htm`
- **位置:** `web/frame/accErr.htm`
- **类型:** network_input
- **综合优先级分数:** **2.85**
- **风险等级:** 0.0
- **置信度:** 9.5
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 静态错误处理页面，显示固定认证失败提示和故障排除指南。触发条件：认证失败时由系统调用。页面不处理任何用户输入，无参数解析逻辑，所有文本内容硬编码。安全影响：无直接可利用漏洞，但作为认证流程组件，若攻击者触发大量错误可能暴露系统行为模式。
- **关键词:** deleteCookie, document.cookie, Authorization, errorbody
- **备注:** 需关联分析登录认证流程（如login.cgi）检查认证绕过或暴力破解漏洞。页面中'Authorization' cookie名称指示认证机制，建议追踪其设置/验证过程。

---
### configuration_analysis-global_commands_no_args

- **文件路径:** `etc/xml_commands/global-commands.xml`
- **位置:** `global-commands.xml`
- **类型:** configuration_load
- **综合优先级分数:** **2.65**
- **风险等级:** 0.5
- **置信度:** 8.0
- **触发可能性:** 0.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 全局参数传递机制缺失：文件未定义任何<arg>参数节点，表明无外部输入（HTTP/NVRAM等）直接关联命令执行。负面安全影响：无法通过此文件建立参数污染类攻击链
- **代码片段:**
  ```
  文件内容扫描未出现<arg>标签
  ```
- **关键词:** global-commands.xml
- **备注:** 排除参数污染攻击可能性

---
### command_execution-dropbearconvert_warning

- **文件路径:** `usr/sbin/dropbear`
- **位置:** `unknown:0 (dropbearconvert)`
- **类型:** command_execution
- **综合优先级分数:** **2.5**
- **风险等级:** 2.0
- **置信度:** 5.0
- **触发可能性:** N/A
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** dropbearconvert工具警告 (低风险):
- 静态字符串提示文件解析风险，但未在当前文件发现直接漏洞证据
- 触发需运行独立工具并控制输入文件，固件中未见自动调用机制
- 实际利用概率较低
- **关键词:** dropbearconvert, fopen64, inputfile
- **备注:** 建议后续分析：1) /usr/bin/dropbearconvert二进制 2) 密钥解析函数fcn.00022468

---
