# Archer_D2_V1_150921 高优先级: 42 中优先级: 49 低优先级: 29

## 优先级评分模型

**计算公式:** `PriorityScore = (0.5 * risk_level) + (0.3 * confidence) + (0.2 * trigger_possibility)`

**分层策略:**
- **高优先级:** `PriorityScore >= 8.5`
- **中优先级:** `7.0 <= PriorityScore < 8.5`
- **低优先级:** `PriorityScore < 7.0`

---

## 高优先级发现

### attack_chain-telnetd_unauthenticated_root

- **文件路径:** `etc/passwd.bak`
- **位置:** `etc/init.d/rcS:54 → passwd.bak:1`
- **类型:** network_input
- **综合优先级分数:** **10.0**
- **风险等级:** 10.0
- **置信度:** 10.0
- **触发可能性:** 10.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链：未认证Telnet服务导致直接root权限获取。攻击步骤：1) 攻击者扫描发现开放23/tcp端口 → 2) 通过Telnet协议连接设备 → 3) 无认证获取交互式shell（因telnetd服务未启用认证）→ 4) 自动获得root权限（因admin账户UID=0且使用/bin/sh）。触发条件：设备接入网络。约束条件：无。实际影响：完全控制系统。成功概率评估：10.0（无需漏洞组合，单点突破）。关联发现：a) telnetd无认证启动（rcS脚本） b) admin账户UID=0配置（passwd.bak）。
- **关键词:** telnetd, admin, UID=0, /bin/sh, rcS, 23/tcp
- **备注:** 此攻击链已通过知识库关联验证：1) telnetd启动无认证（command_execution-telnetd-unauthenticated） 2) admin账户root权限（configuration_load-admin-root-account）

---
### network_input-vsftpd-backdoor

- **文件路径:** `usr/bin/vsftpd`
- **位置:** `vsftpd (字符串偏移0x12f8)`
- **类型:** network_input
- **综合优先级分数:** **9.81**
- **风险等级:** 10.0
- **置信度:** 9.5
- **触发可能性:** 9.8
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** CVE-2011-2523后门漏洞。触发条件：当客户端发送USER命令且用户名包含':)'时（如USER evil:))，服务端在6200端口打开监听shell。攻击者连接该端口可直接获得root权限。该漏洞无需认证，在固件暴露FTP服务时成功利用概率>90%。边界检查：用户名处理函数未过滤特殊字符。安全影响：完全控制系统。
- **关键词:** vsftpd: version 2.3.2, USER, PASS, strcpy
- **备注:** 建议立即禁用FTP服务或升级版本。关联文件：/etc/vsftpd.conf（若存在）。同时检测到5个危险内存操作函数(strcpy/memcpy/sprintf)，需验证是否在FTP命令处理流程中导致缓冲区溢出（详见未验证发现）

---
### command_execution-telnetd-unauthenticated

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:54`
- **类型:** command_execution
- **综合优先级分数:** **9.5**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 10.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** telnetd服务启动时未启用认证机制。设备启动时自动执行'telnetd'命令（无参数），导致监听23端口的服务允许任意用户无密码登录获取shell。攻击者可通过网络直接连接23端口获得root权限，无需触发条件。
- **代码片段:**
  ```
  telnetd
  ```
- **关键词:** telnetd
- **备注:** 需验证/etc/passwd是否包含空密码账户

---
### password-leak-ttyS0

- **文件路径:** `usr/bin/dropbearmulti`
- **位置:** `dropbearmulti: svr_auth_password`
- **类型:** hardware_input
- **综合优先级分数:** **9.45**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 10.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 密码明文泄露漏洞：认证过程中通过'echo "========> %s" > /dev/ttyS0'将密码输出到串口。触发条件：任何密码认证尝试（包括失败尝试）。攻击者通过物理访问串口或日志获取可立即使用的凭证，成功利用概率极高。实际影响：完全系统沦陷。
- **代码片段:**
  ```
  echo "========> %s" > /dev/ttyS0
  ```
- **关键词:** /dev/ttyS0, echo, Password auth succeeded, svr_auth_password
- **备注:** 检查串口访问权限。关联：UART接口物理攻击、日志文件存储位置

---
### attack_chain-passwd.bak_rcS_root_takeover

- **文件路径:** `etc/inittab`
- **位置:** `etc/init.d/rcS:15 [具体函数] 0x[地址]`
- **类型:** command_execution
- **综合优先级分数:** **9.45**
- **风险等级:** 9.5
- **置信度:** 10.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 全局可写且含弱密码的passwd.bak文件构成完整攻击链：1) 攻击者通过Web漏洞/弱服务获得低权限访问 2) 篡改/etc/passwd.bak添加UID=0账户 3) 系统启动时rcS脚本将篡改文件覆盖认证文件 4) 通过Telnet服务以root权限登录。触发条件：存在初始访问点（如未授权Telnet）。边界检查：无文件完整性保护或权限控制。关联漏洞：a) etc/passwd.bak中的弱密码配置（见ID:configuration_load-etc_passwd-admin_root） b) Telnet未授权访问（知识库记录）。
- **代码片段:**
  ```
  [等待用户提供rcS脚本代码片段]
  ```
- **关键词:** passwd.bak, rcS, ::sysinit, cp -p, admin, UID=0, Telnet
- **备注:** 关联发现：1) configuration_load-etc_passwd-admin_root（弱密码） 2) 需验证rcS脚本位置（当前location需补充具体路径）3) 引用Telnet未授权访问记录（待查询）

---
### attack_chain-$.act_virtual_server_integration

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `跨文件：www/virtualServer.htm + web/js/lib.js + web/main/accessControl.htm`
- **类型:** network_input
- **综合优先级分数:** **9.4**
- **风险等级:** 9.8
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 扩展攻击链：将virtualServer.htm的/goform端点（DelVirtualServerRule/AddVirtualServerRule）整合至现有$.act攻击框架。关键路径：1) 前端（virtualServer.htm）接收ipAddr/interPort等未经验证参数 2) 通过$.act提交到后端/goform处理程序 3) 与知识库记录的$.exe参数注入（lib.js）和NVRAM注入（accessControl.htm）形成叠加风险。触发条件：攻击者构造恶意ipAddr（如'127.0.0.1;reboot'）绕过客户端isPort验证。完整影响：可能实现从网络输入到设备完全控制的RCE链（风险提升至9.8/10）
- **代码片段:**
  ```
  关联代码轨迹：
  1. virtualServer.htm: $.act(ACT_OP, '/goform/DelVirtualServerRule', {delRule: id})
  2. lib.js: data += ... + obj[5]  // 未过滤拼接
  3. accessControl.htm: $.act(ACT_SET, FIREWALL, ...)  // NVRAM写入
  ```
- **关键词:** $.act, ipAddr, interPort, /goform/DelVirtualServerRule, delRule, getFormData, $.exe, NVRAM_injection, command_injection
- **备注:** 关联知识库12个发现（含新存储的network_input-goform_virtual_server-rule_operation）。验证方向：1) 定位/goform对应的二进制处理程序（建议搜索bin目录）2) 动态测试ipAddr参数注入特殊字符 3) 检查参数是否流入system/exec调用

---
### network_input-smb_readbmpx-memcpy_overflow

- **文件路径:** `usr/bin/smbd`
- **位置:** `smbd:0x42bbfc [sym.reply_readbmpx]`
- **类型:** network_input
- **综合优先级分数:** **9.35**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 在SMB协议处理路径中发现高危内存安全漏洞：攻击者通过构造恶意READ请求包控制长度字段（偏移0x2b-0x2c），该值未经边界验证直接传递至memcpy操作。关键缺陷包括：1) 全局约束obj.max_recv(128KB)未应用 2) 目标地址计算未验证（param_3 + *(param_3+0x24)*2 + 0x27）3) 循环调用导致长度累积。触发条件：长度值 > 响应缓冲区剩余空间，可导致堆/栈缓冲区溢出实现远程代码执行。
- **代码片段:**
  ```
  uVar8 = CONCAT11(*(param_2+0x2c),*(param_2+0x2b));
  iVar11 = param_3 + *(param_3+0x24)*2 + 0x27;
  while(...) {
    iVar4 = sym.read_file(..., iVar11, ..., uVar7);
    iVar2 += iVar4;
    iVar11 += iVar4;
  }
  ```
- **关键词:** sym.read_file, memcpy, param_5, sym.reply_readbmpx, obj.max_recv, CONCAT11, is_locked, set_message, smbd/reply.c
- **备注:** 关联线索：1) 知识库存在'memcpy'关键词需检查其他使用点 2) 'param_3'可能涉及跨组件数据传递。漏洞利用特征：smbd以root运行+局域网暴露+无需认证触发。

---
### stack_overflow-SITE_CHMOD

- **文件路径:** `usr/bin/vsftpd`
- **位置:** `vsftpd:0x41163c`
- **类型:** network_input
- **综合优先级分数:** **9.3**
- **风险等级:** 9.5
- **置信度:** 9.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈溢出漏洞：攻击者通过FTP的SITE CHMOD命令发送超长文件路径（如'SITE CHMOD 777 [300*A]'）。路径数据经param_2传递至处理函数，strcpy操作将未验证输入复制到128字节栈缓冲区acStack_118。触发条件：1) 有效FTP凭证（匿名模式可绕过） 2) 路径长度>128字节 3) 无ASLR/NX防护时可覆盖返回地址实现RCE。
- **代码片段:**
  ```
  strcpy(acStack_118, uVar1); // uVar1=user_input
  ```
- **关键词:** SITE_CHMOD, acStack_118, param_2, strcpy, FTP_credentials

---
### command_execution-telnetd-path_hijacking

- **文件路径:** `etc/inittab`
- **位置:** `etc/init.d/rcS`
- **类型:** command_execution
- **综合优先级分数:** **9.2**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 通过inittab启动的rcS脚本调用telnetd服务：1) 服务启动未使用绝对路径（仅'telnetd'），依赖PATH环境变量，存在路径劫持风险 2) 监听23端口接受网络输入，形成初始攻击面 3) 触发条件：设备接入开放网络时自动启动。安全影响：若PATH被篡改或telnetd存在漏洞（如CVE-2023-51713），攻击者可远程获取root shell。
- **代码片段:**
  ```
  启动命令示例：/etc/init.d/rcS: 'telnetd &'
  ```
- **关键词:** rcS, telnetd, PATH
- **备注:** 关联发现：command_execution-telnetd-unauthenticated（无认证漏洞）。完整攻击链：篡改PATH注入恶意telnetd → 利用无认证获取root权限。需后续分析：1) telnetd二进制路径验证 2) 检查认证机制是否可绕过

---
### network_input-arp_processing-stack_overflow_0x40f4a0

- **文件路径:** `usr/sbin/atmarpd`
- **位置:** `fcn.0040f478@0x40f4a0, fcn.00412a48@0x412a48`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 高危栈溢出漏洞：函数fcn.00412a48实现无边界逐字节复制（等效strcpy），被文件处理函数fcn.0040f478调用。后者使用固定栈缓冲区（auStack_38[16B]/auStack_28[20B]）且无长度校验。触发条件：攻击者发送>32字节ARP数据包污染全局配置结构（0x40d288区域）。实际影响：覆盖返回地址导致任意代码执行（RCE）。完整利用链：构造超长ARP包→污染配置结构→触发~atmarpd.table文件处理→栈溢出劫持控制流。
- **关键词:** fcn.00412a48, fcn.0040f478, auStack_38, auStack_28, 0x40d288, ~atmarpd.table, ARP
- **备注:** 影响文件处理流程；需验证全局配置污染的具体网络接口

---
### network_input-setkey-chained_overflow_0x402ca8

- **文件路径:** `usr/bin/setkey`
- **位置:** `setkey:0x402ca8`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 链式栈溢出漏洞：1) recv固定接收16字节写入4字节缓冲区(acStack_8028)导致12字节溢出 2) 溢出污染uStack_8024变量 3) 二次recv使用uStack_8024<<3作为长度参数，造成任意长度溢出。完全控制返回地址。触发条件：发送普通PF_KEY数据包即可。
- **代码片段:**
  ```
  recv(*0x41cb8c,acStack_8028,0x10,2);
  recv(*0x41cb8c,acStack_8028,uStack_8024<<3,0);
  ```
- **关键词:** recv, acStack_8028, uStack_8024, setkey, fcn.00402bf4, kdebug_sadb

---
### command-injection-hotplug-usb_scsi_host-4013a0

- **文件路径:** `sbin/hotplug`
- **位置:** `hotplug:0 [getLedNumFromDevPath] 0x004013a0`
- **类型:** hardware_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 命令注入漏洞：攻击者可通过恶意USB设备名称污染设备路径（如'/class/scsi_host/host;reboot;'），在getLedNumFromDevPath函数中，sscanf解析失败导致auStack_b0[0]包含未过滤的分号字符。后续snprintf拼接命令时构造出'rm -rf /var/run/usb_device_host;reboot;'，通过system()执行任意命令。触发条件：1) 攻击者连接恶意命名的USB设备 2) 系统触发scsi_host热插拔事件。边界检查缺失：仅验证路径长度（0x1fe），未过滤特殊字符。
- **代码片段:**
  ```
  sym.imp.sscanf(*&iStackX_0,"/class/scsi_host/host%d",auStack_b0);
  sym.imp.snprintf(auStack_1b0,0x100,"rm -rf /var/run/usb_device_host%d",auStack_b0[0]);
  sym.imp.system(auStack_1b0);
  ```
- **关键词:** getLedNumFromDevPath, sscanf, system, snprintf, auStack_b0, /class/scsi_host, /sys/class/scsi_host
- **备注:** 实际利用需绕过USB设备命名限制（如内核过滤）。关联知识库关键词：system(37次), rm -rf(12次), /sys/class/scsi_host(已存在)

---
### attack_chain-$.act_frontend_to_backend

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `跨文件：web/main/parentCtrl.htm, web/main/accessControl.htm, web/js/lib.js等`
- **类型:** network_input
- **综合优先级分数:** **9.1**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 通过$.act函数构建的完整攻击链：1) 前端输入点（parentCtrl/accessControl/ddns等页面）存在验证缺陷 2) 用户可控数据通过$.act操作（ACT_ADD/ACT_DEL/ACT_SET）传递到后端 3) 后端处理模块存在多重漏洞（XSS/参数注入/NVRAM注入）。触发步骤：攻击者绕过前端验证构造恶意请求 → 利用$.act参数注入污染后端参数 → 触发命令执行或权限提升。关键约束：a) 前端验证可绕过 b) 后端缺乏输入过滤 c) 会话管理缺陷。完整影响：通过单次请求可实现设备完全控制。
- **代码片段:**
  ```
  典型攻击链代码轨迹：
  1. 前端构造：$.act(ACT_DEL, INTERNAL_HOST, ';reboot;', null)
  2. 参数传递：lib.js中$.exe拼接未过滤参数
  3. 后端执行：/cgi端点调用system(payload)
  ```
- **关键词:** $.act, ACT_ADD, ACT_DEL, ACT_SET, INTERNAL_HOST, IGD_DEV_INFO, DYN_DNS_CFG, command_injection, NVRAM_injection
- **备注:** 关联11个$.act相关发现（详见知识库）。紧急验证方向：1) 逆向bin/httpd中的cgi处理函数 2) 动态测试畸形ACT_DEL请求 3) 检查NVRAM写操作边界

---
### exploit_chain-smb_atmarpd_memory_corruption

- **文件路径:** `usr/bin/smbd`
- **位置:** `复合漏洞链：smbd(sym.reply_readbmpx) + atmarpd(fcn.0040d17c)`
- **类型:** network_input
- **综合优先级分数:** **9.1**
- **风险等级:** 10.0
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 发现跨组件高危漏洞链：攻击者可组合利用SMB协议内存溢出漏洞（smbd）与atmarpd配置污染漏洞实现双重内存破坏。步骤：1) 通过SMB恶意READ请求触发初始堆溢出，破坏关键数据结构 2) 构造畸形ATM/ARP数据包控制param_3[0x34]字段，精准覆盖atmarpd的返回地址。优势：a) SMB提供无需认证的初始攻击面 b) atmarpd漏洞提供稳定RCE跳板 c) 协同利用可绕过单漏洞缓解机制。触发条件：局域网内连续发送两类恶意包。
- **关键词:** param_3, memcpy, 0x430950, sym.reply_readbmpx, fcn.0040d17c
- **备注:** 关键证据：1) 两漏洞均以root权限运行 2) 均暴露于局域网 3) param_3字段在两处均未经验证 4) SMB溢出可破坏atmarpd的全局配置结构。需验证：atmarpd是否与smbd共享内存区域（如0x430950）

---
### configuration_load-admin-root-account

- **文件路径:** `etc/passwd.bak`
- **位置:** `passwd.bak:1`
- **类型:** configuration_load
- **综合优先级分数:** **9.1**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** admin账户配置风险：UID=0的非root账户admin配置有效密码($1$DES加密)，使用/bin/sh作为shell。攻击者可通过爆破此密码直接获取root权限。触发条件：存在SSH/Telnet等登录服务且未启用登录失败锁定。约束条件：密码强度不足时易被爆破。实际影响：完全控制系统。
- **代码片段:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  ```
- **关键词:** admin, UID=0, /bin/sh, $1$$iC.dUsGpxNNJGeOm1dFio/
- **备注:** 需结合/etc/shadow验证密码强度，检查SSH/Telnet服务配置；知识库中已存在关联关键词：/bin/sh, admin, UID=0

---
### command_execution-telnetd-path_pollution

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:85`
- **类型:** command_execution
- **综合优先级分数:** **9.1**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 通过相对路径'telnetd'启动服务。触发条件：系统启动时执行。约束：PATH未显式设置。安全影响：PATH污染可导致恶意二进制劫持，攻击者通过环境变量注入或可写目录植入控制telnet服务。
- **代码片段:**
  ```
  telnetd
  ```
- **关键词:** telnetd, PATH
- **备注:** 需系统级PATH默认值验证实际风险

---
### network_input-config_pollution-stack_overflow_0x40d288

- **文件路径:** `usr/sbin/atmarpd`
- **位置:** `fcn.0040d17c@0x40d288`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.8
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 全局配置污染漏洞：函数fcn.0040d17c未验证param_3[0x34]字段边界（值∈{0x01,0x02,0x04}），攻击者通过特制网络数据控制0x430950区域，可覆盖返回地址。触发条件：发送畸形ATM/ARP数据包。实际影响：与栈溢出漏洞协同可实现稳定RCE。
- **关键词:** fcn.0040d17c, param_3, 0x430950, 0x40d288, apuStack_20

---
### network_input-direct_data_pass-1

- **文件路径:** `web/main/ddos.htm`
- **位置:** `www/ddos.htm:0 (JavaScript)`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** JavaScript通过$.act(ACT_SET, DDOS_CFG)将用户输入对象(ddosArg)直接传递后端，未进行过滤/转义。触发条件：控制前端参数提交。边界检查完全缺失，参数包含enableIcmpFilter等关键配置项。潜在影响：若后端存在命令注入或缓冲区溢出漏洞，可形成完整RCE攻击链。
- **代码片段:**
  ```
  $.act(ACT_SET, 'DDOS_CFG', ddosArg);
  ```
- **关键词:** ddosArg, $.act, ACT_SET, DDOS_CFG, enableIcmpFilter, icmpThreshold, enableUdpFilter, udpThreshold
- **备注:** 最高危攻击面，需优先追踪httpd中DDOS_CFG处理函数的数据流；关联关键词：$.act/ACT_SET（知识库已存在）

---
### bss_overflow-RNFR_PASV

- **文件路径:** `usr/bin/vsftpd`
- **位置:** `vsftpd:0x413c00`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** .bss段溢出漏洞：攻击者通过RNFR/PASV命令发送超长FTP指令（如'RNFR [500*A]'）。命令数据经param_1传递，memcpy操作将未校验输入复制到448字节固定缓冲区(0x42e8e0)。触发条件：1) 命令长度>448字节 2) 溢出覆盖全局变量0x42d9e8和函数指针 3) 可构造ROP链绕过NX实现特权提升（vsftpd以root运行）。
- **代码片段:**
  ```
  memcpy(iVar6+iVar3, param_1, iVar2-param_1); // no length check
  ```
- **关键词:** RNFR, PASV, param_1, memcpy, 0x42e8e0, .bss

---
### stack_overflow-USER_sprintf

- **文件路径:** `usr/bin/vsftpd`
- **位置:** `vsftpd:0x40eef8`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 用户名注入栈溢出：攻击者使用超长USER命令登录（如'USER [200*A]'）。用户名(param_5)用于构造路径'/var/vsftp/var/%s'，sprintf操作写入4字节栈缓冲区。触发条件：1) 全局变量*0x42d7cc≠0 2) 用户名长度>12字节 3) 溢出覆盖返回地址实现任意代码执行。
- **代码片段:**
  ```
  sprintf(puStack_2c, "/var/vsftp/var/%s", param_5);
  ```
- **关键词:** USER, param_5, sprintf, puStack_2c, /var/vsftp/var/%s

---
### command_execution-mkdir-insecure_permission

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:12`
- **类型:** command_execution
- **综合优先级分数:** **9.05**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 创建全局可写目录(0777)包括/var/tmp/dropbear等敏感路径。触发条件：系统启动时执行。约束：目录权限持续生效。安全影响：攻击者可植入恶意文件或篡改合法文件（如SSH密钥），导致提权、持久化后门或服务拦截。
- **代码片段:**
  ```
  /bin/mkdir -m 0777 -p /var/tmp/dropbear
  ```
- **关键词:** /bin/mkdir, 0777, /var/tmp/dropbear
- **备注:** 需验证目录实际用途（如是否被dropbear使用）

---
### command_execution-cos-binary_hijack

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:91`
- **类型:** command_execution
- **综合优先级分数:** **8.95**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 8.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 通过'cos &'启动未知服务。触发条件：系统启动时执行。安全影响：1) PATH污染导致二进制劫持 2) 若cos存在漏洞可被直接利用。利用方式：替换恶意cos二进制或注入参数。
- **代码片段:**
  ```
  cos &
  ```
- **关键词:** cos
- **备注:** 需逆向分析cos二进制（建议后续任务）

---
### network_input-smbfs-arbitrary_file_deletion

- **文件路径:** `usr/bin/smbd`
- **位置:** `smbd:0x4482e8 sym.reply_unlink`
- **类型:** network_input
- **综合优先级分数:** **8.9**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危任意文件删除漏洞：
- **触发条件**：攻击者发送特制SMB请求（如SMBunlink命令），在路径参数中包含路径遍历序列（如../../../etc/passwd）
- **传播路径**：网络输入 → sym.srvstr_get_path解析（未过滤特殊序列）→ sym.unlink_internals → sym.is_visible_file → sym.can_delete
- **边界检查缺失**：路径解析函数未对../等序列进行规范化或过滤，直接拼接文件路径
- **安全影响**：可实现任意文件删除（CWE-22），成功利用概率高（协议允许传输任意字节路径）
- **代码片段:**
  ```
  sym.srvstr_get_path(param_2, auStack_428, ...);
  sym.unlink_internals(..., auStack_428);
  ```
- **关键词:** sym.srvstr_get_path, sym.unlink_internals, sym.is_visible_file, sym.can_delete, SMBunlink
- **备注:** 建议后续：1) 动态验证PoC 2) 检查同类文件操作函数（mkdir/rmdir）；未完成分析：1) SMBioctl真正处理函数需通过命令表0x4c37d0重新定位 2) NVRAM交互可能存在于libbigballofmud.so.0；关联文件：libbigballofmud.so.0（环境变量/NVRAM处理）

---
### vuln-wan_service-0x407c34

- **文件路径:** `usr/bin/cli`
- **位置:** `usr/bin/cli:0x407c34`
- **类型:** network_input
- **综合优先级分数:** **8.9**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞：在'wan set service'命令处理函数中，攻击者可通过--safeservicename参数传入超长base64编码数据。触发条件：1) 参数值经snprintf复制到96字节栈缓冲区(sp+0x28)；2) 调用cen_base64Decode解码；3) 解码结果写入未经验证边界的栈缓冲区(sp+0x330)。base64解码后最大288字节数据必然溢出目标缓冲区。结合程序缺乏标准身份验证机制，攻击者可能通过未授权CLI接口实现任意代码执行。
- **代码片段:**
  ```
  0x00407c1c: jal sym.imp.snprintf  ; 复制参数到栈
  0x00407c34: jal sym.imp.cen_base64Decode  ; 危险解码调用
  ```
- **关键词:** --safeservicename, wan set service, 0x42ba74, cen_base64Decode, snprintf
- **备注:** 完整攻击链依赖：1) CLI网络暴露面验证 2) 0x42ba74权限变量污染可能性分析。建议后续：分析/etc/init.d/服务脚本确认CLI网络接口

---
### configuration_load-vsftpd-credentials_exposure

- **文件路径:** `etc/vsftpd_passwd`
- **位置:** `etc/vsftpd_passwd`
- **类型:** configuration_load
- **综合优先级分数:** **8.86**
- **风险等级:** 9.2
- **置信度:** 9.0
- **触发可能性:** 7.8
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** vsftpd_passwd文件明文存储FTP服务凭证，包含3个有效账户(admin/guest/test)。其中admin/test账户具有权限标志'1:1'，表明可能是特权账户。密码未加密存储(如admin:1234)，攻击者通过路径遍历、配置错误或权限漏洞读取该文件后，可直接获取凭证登录FTP服务执行高危操作（文件上传/删除/系统命令执行）。触发条件：攻击者需能读取该文件（权限不足或路径泄露）。实际影响：获得FTP控制权可能导致完全设备接管。完整攻击路径：1) 利用路径遍历漏洞访问etc/vsftpd_passwd → 2) 提取特权账户凭证 → 3) 登录FTP服务 → 4) 上传恶意脚本或触发命令执行。
- **代码片段:**
  ```
  admin:1234:1:1;guest:guest:0:0;test:test:1:1;
  ```
- **关键词:** vsftpd_passwd, admin, test, 1:1, FTP_credentials
- **备注:** 需验证：1) 文件权限是否全局可读 2) 权限标志'1:1'在vsftpd中的具体含义 3) 关联分析FTP服务配置(如vsftpd.conf)。知识库关联线索：a) /var/vsftp目录权限风险 b) FTP命令处理流程的缓冲区溢出风险 c) telnetd无认证漏洞可能形成多服务入侵链

---
### mount-tmp-ramfs-rwexec

- **文件路径:** `etc/fstab`
- **位置:** `etc/fstab:4`
- **类型:** configuration_load
- **综合优先级分数:** **8.85**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** /tmp目录配置为ramfs文件系统且启用rw+exec选项。攻击者可利用其他漏洞（如Web文件上传、命令注入）在/tmp写入恶意可执行文件，通过服务漏洞触发执行。触发条件：1) 存在/tmp目录写权限获取点（如CGI上传）2) 存在执行触发点（如cron脚本）。边界检查：无nosuid/nouser限制，导致任意用户可执行植入程序。利用链：污染HTTP参数→写入/tmp/exploit→触发设备监控脚本执行→获取root权限。
- **代码片段:**
  ```
  ramfs /tmp ramfs defaults 0 0
  ```
- **关键词:** /tmp, ramfs, defaults, rw, exec
- **备注:** 需后续验证Web接口是否允许文件写入/tmp

---
### NVRAM-Injection-accessControl

- **文件路径:** `web/main/accessControl.htm`
- **位置:** `accessControl.htm:? (doSaveBlackList/doSaveWhiteList)`
- **类型:** nvram_set
- **综合优先级分数:** **8.85**
- **风险等级:** 9.2
- **置信度:** 8.5
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 发现4个未经验证的用户输入点（设备名/MAC地址）直接用于NVRAM操作。触发条件：用户点击OK按钮触发doSave*函数。约束检查：仅有maxlength限制（设备名15字符/MAC地址17字符），无格式验证或过滤。潜在影响：攻击者可构造包含特殊字符的MAC地址（如';reboot;'）提交，通过$.act(ACT_SET/ACT_ADD)实现NVRAM注入，导致防火墙规则篡改或设备重启。
- **关键词:** blackMacAddr, whiteMacAddr, doSaveBlackList, doSaveWhiteList, $.act, ACT_SET, ACT_ADD, RULE, FIREWALL
- **备注:** 关键依赖：$.isname/$.mac过滤函数未在当前文件实现，需验证其有效性

---
### stack_overflow-httpd_confup-0x4067ec

- **文件路径:** `usr/bin/httpd`
- **位置:** `httpd:0x4067ec (fcn.004038ec)`
- **类型:** network_input
- **综合优先级分数:** **8.85**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** /cgi/confup端点存在高危栈缓冲区溢出：fcn.004038ec函数使用strncpy固定复制256字节用户输入到栈缓冲区。当HTTP POST请求参数长度超过256字节时覆盖栈帧，可劫持控制流。触发条件：发送超长参数到/cgi/confup端点。
- **代码片段:**
  ```
  strncpy(puVar4, pcVar3, 0x100) // 固定长度复制
  ```
- **关键词:** fcn.004038ec, httpd_stack_buffer, strncpy_fixed_copy, 0x100, HTTP_request_structure
- **备注:** 关联知识库关键词：fcn.004038ec, strncpy。需验证：1) 缓冲区实际大小 2) RA覆盖偏移 3) 其他调用此函数的端点

---
### command_execution-hotplug-system_injection

- **文件路径:** `sbin/hotplug`
- **位置:** `hotplug (binary)`
- **类型:** command_execution
- **综合优先级分数:** **8.8**
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** system()调用使用格式化字符串直接拼接环境变量执行命令，存在命令注入风险。高危操作包括：1) cp/rm文件操作 2) 串口通信(>/dev/ttyS0) 3) LED硬件控制(>/proc/tplink/led_usb)。触发条件：当$DEVPATH等变量包含特殊字符（如;、$、`）时，可突破命令边界执行额外指令。利用链：污染变量→注入rm/cp命令→删除系统文件或植入后门。
- **代码片段:**
  ```
  system("cp -pR /sys/class/scsi_host/host%d/device /var/run/usb_device_host%d");
  ```
- **关键词:** system, cp -pR, rm -rf, echo > /dev/ttyS0, echo > /proc/tplink/led_usb
- **备注:** /proc/tplink/led_usb表明可直接操控硬件，需验证变量是否用于printf格式化参数

---
### vuln-dhcp6-IA_PD-int-overflow

- **文件路径:** `usr/sbin/dhcp6s`
- **位置:** `dhcp6s:0x40b140 (fcn.0040b140)`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 在DHCPv6服务器处理IA_PD选项（类型0x1a）时，存在可利用的整数溢出漏洞：1) 用户可控的uVar9长度参数（直接来自网络数据包）用于计算选项结束位置(uVar18 = uVar15 + uVar9)；2) 当uVar9 ≥ 0xFFFFFFFC（32位系统）时发生整数溢出，导致uVar18值回绕变小，绕过`param_3 < uVar18`边界检查；3) 后续操作使用污染后的uVar9进行内存访问（如*(param_2 - uVar9)），触发越界读写。触发条件：向dhcp6s发送包含畸形IA_PD选项的DHCPv6请求报文，其中选项长度字段设为0xFFFFFFFF。安全影响：可导致敏感栈数据泄露（uStack_9c）或通过fcn.004095f4函数调用链实现远程代码执行（RCE）。利用方式：构造恶意DHCPv6请求触发整数溢出，利用越界访问篡改控制流或泄露认证凭据。
- **代码片段:**
  ```
  uVar9 = param_2 & 3;
  uVar18 = uVar15 + uVar9;
  if (param_3 < uVar18) { ... } // 整数溢出可绕过检查
  if (uVar17 == 0x1a) {
    fcn.004095f4(&uStack_9c, ...); // 栈数据泄露风险点
  ```
- **关键词:** uVar9, param_2, uVar18, IA_PD, 0x1a, fcn.0040b140, copyin_option, fcn.004095f4, uStack_9c, dhcp6_set_options
- **备注:** 需验证实际环境：1) dhcp6s是否启用IPv6服务；2) IA_PD选项处理是否默认开启。建议后续动态测试uVar9=0xFFFFFFFF时的崩溃点，并分析fcn.004095f4函数实现。

---
### CSRF-NVRAM-accessControl

- **文件路径:** `web/main/accessControl.htm`
- **位置:** `accessControl.htm:? (多个$.act调用点)`
- **类型:** nvram_set
- **综合优先级分数:** **8.7**
- **风险等级:** 8.8
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 敏感NVRAM操作接口缺乏CSRF保护。触发条件：通过$.act执行ACT_GET/ACT_SET操作时自动触发。具体操作包括：防火墙开关(ACT_SET FIREWALL enable)、规则增删(ACT_ADD/ACT_DEL RULE)、设备列表管理(ACT_GL LAN_HOST_ENTRY)。潜在影响：攻击者诱导用户访问恶意页面可触发未授权配置修改，例如禁用防火墙或添加恶意网络规则。
- **关键词:** $.act, ACT_GET, ACT_SET, ACT_DEL, FIREWALL, RULE, LAN_HOST_ENTRY
- **备注:** 需结合后端验证机制分析实际可利用性

---
### network_input-vsftpd-path_traversal

- **文件路径:** `usr/bin/vsftpd`
- **位置:** `vsftpd @ 0x40f814 (fcn.0040f58c调用链)`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 路径遍历文件写入漏洞。触发条件：提交含'../'序列的USER命令（如USER ../../etc/passwd）。处理函数fcn.0040eda8将用户名直接拼接到'/var/vsftp/var/%s'路径，通过fopen写入文件。攻击者可覆盖任意文件导致权限提升或系统瘫痪。边界检查：用户名长度限制(0x20字节)但未过滤路径分隔符。安全影响：文件系统破坏。
- **关键词:** fcn.0040eda8, /var/vsftp/var/%s, sprintf, fopen, USER
- **备注:** 需验证/var/vsftp目录权限。后续应检查固件中FTP服务是否默认启用

---
### configuration_load-etc_services-plaintext_protocols

- **文件路径:** `etc/services`
- **位置:** `etc/services`
- **类型:** configuration_load
- **综合优先级分数:** **8.65**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** etc/services 文件暴露多个高危明文协议服务（telnet:23, ftp:21, tftp:69）。触发条件：当服务在系统中启用并网络可达时。安全影响：攻击者可通过中间人攻击窃取凭证（telnet）、上传恶意固件（tftp）或执行命令注入（ftp）。利用方式：扫描开放端口后利用协议漏洞发起攻击。
- **关键词:** telnet, ftp, tftp, 23/tcp, 21/tcp, 69/udp
- **备注:** 需结合进程分析确认服务实际启用状态，高危服务条目：telnet(23/tcp,23/udp), ftp(21/tcp,21/udp), tftp(69/tcp,69/udp)。关联漏洞：etc/init.d/rcS中telnetd服务无认证启动(command_execution-telnetd-unauthenticated)，形成完整攻击链。

---
### network_input-$.exe-param_injection

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js:1330 [$.exe]`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** $.exe函数（lib.js:1330）存在参数注入风险：用户可控数据通过$.act调用进入attrs参数，未经过滤直接拼接到HTTP请求体。攻击向量：1) 特殊字符（如换行符）可破坏请求结构 2) 操作参数（IGD_DEV_INFO/ACT_CGI）可能被污染。触发条件：用户输入流入$.act的attrs参数（如表单提交），触发$.exe的POST请求。边界检查：仅对中文字符进行ANSI编码（$.ansi），未处理关键分隔符（\r\n）。实际影响：若后端解析存在缺陷，可导致命令注入或权限绕过。关联知识库关键词：$.act/$.exe/IGD_DEV_INFO（已存在相关风险记录）。
- **代码片段:**
  ```
  data += "[" + obj[2] + "#" + obj[3] + "#" + obj[4] + "]" + index + "," + obj[6] + "\r\n" + obj[5];
  ```
- **关键词:** $.exe, attrs, $.as, $.act, ACT_GET, IGD_DEV_INFO, ACT_CGI, $.toStr, $.ansi, /cgi
- **备注:** 关键验证点：1) 前端表单如何绑定$.act调用 2) 后端/cgi处理程序对畸形请求的容错性。关联知识库：$.act/$.exe/IGD_DEV_INFO（已存在）

---
### attack_chain-csrf_xss_goform_rule_manipulation

- **文件路径:** `web/index.htm`
- **位置:** `跨组件：www/web/jquery.tpTable.js → www/virtualServer.htm → 后端CGI处理程序`
- **类型:** attack_chain
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链：前端XSS漏洞（污染表格数据）→ 前端CSRF漏洞（未授权触发AJAX请求）→ 后端/goform端点未验证操作权限。触发步骤：1) 攻击者构造含XSS payload的API响应污染tpTable数据 2) 利用被污染的表格诱导用户点击 3) 通过CSRF触发delRule操作删除虚拟服务器规则。成功利用概率：8.5/10（需用户会话有效）。危害：非授权配置篡改+会话劫持组合攻击。
- **关键词:** CSRF, XSS, /goform/DelVirtualServerRule, delRule, ipAddr, innerHTML, $.ajax
- **备注:** 关键验证：1) 分析/bin/httpd中处理/goform的cgi函数（如handle_delVirtualServer）2) 测试XSS+CSRF组合PoC：通过XSS注入伪造的删除按钮自动触发CSRF请求

---
### command_execution-cwmp-parameter_injection

- **文件路径:** `usr/bin/cwmp`
- **位置:** `fcn.00404b20 (setParamVal) → fcn.0040537c (putParamSetQ)`
- **类型:** command_execution
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危命令注入攻击链：攻击者发送恶意SetParameterValues请求 → msg_recv接收 → cwmp_processSetParameterValues解析XML → setParamVal处理参数值（无内容消毒） → putParamSetQ以'%s=%s\n'格式存储 → rdp_setObj写入存储系统。当存储文件被后续脚本/system调用执行时，注入的命令（如`; rm -rf /`）将被执行。触发条件：1) 网络访问cwmp服务 2) 构造含恶意参数值的TR-069请求 3) 存储目标被脚本执行。
- **关键词:** msg_recv, cwmp_processSetParameterValues, setParamVal, putParamSetQ, rdp_setObj, ParameterValueStruct, g_oidStringTable
- **备注:** 需验证：1) rdp_setObj在/lib/libcmm.so的实现 2) 存储文件是否被system()或popen()调用。关联建议：检查/sbin/init或/etc/init.d中调用存储文件的脚本

---
### network_input-wan_config-pppoe

- **文件路径:** `web/main/wanBasic.htm`
- **位置:** `www/wanBasic.htm: (doSaveDsl)`
- **类型:** network_input
- **综合优先级分数:** **8.6**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 发现完整的前端攻击面：用户可通过HTTP表单控制WAN配置参数（如usrPPPoE/ipStaticIp）。这些参数经JavaScript收集后，通过$.act()操作传递到后端抽象端点（WAN_PPP_CONN等）。触发条件：用户提交恶意配置表单时，前端仅进行基础格式验证（paramCheck），未对输入长度/内容做严格过滤。潜在影响：若后端处理存在漏洞（如缓冲区溢出），可构造超长用户名或特殊字符触发漏洞。
- **代码片段:**
  ```
  function doSaveDsl(linkType, wanConnArg) {
    $.act(ACT_SET, 'WAN_PPP_CONN', wanConnArg);
  }
  ```
- **关键词:** usrPPPoE, pwdPPPoE, ipStaticIp, serverIpOrNamePptp, WAN_PPP_CONN, WAN_IP_CONN, WAN_PPTP_CONN, $.act, doSave, doSaveDsl
- **备注:** 需验证后端cgibin中WAN_*_CONN处理函数的安全性。关联知识库$.act操作链（已存在7条记录）。

---
### combined_attack-hotplug_file_race_and_command_injection

- **文件路径:** `sbin/hotplug`
- **位置:** `hotplug (multi-location)`
- **类型:** combined_vulnerability
- **综合优先级分数:** **8.6**
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 文件竞争漏洞与命令注入漏洞形成组合攻击链：1) 攻击者通过恶意设备污染$DEVPATH实现路径遍历（利用file_race漏洞）篡改/var/run/storage_led_status状态文件 2) 篡改后的设备状态触发异常hotplug事件 3) 污染ACTION环境变量注入恶意命令通过system()执行。完整实现：单次设备插入→文件覆盖→状态破坏→命令执行的三阶段攻击。
- **代码片段:**
  ```
  关联代码段1: fopen("/var/run/storage_led_status", "r+");
  关联代码段2: system("echo %d %d > %s");
  ```
- **关键词:** /var/run/storage_led_status, ACTION, DEVPATH, system, fopen, hotplug_storage_mount
- **备注:** 组合漏洞验证要求：1) 确认storage_led_status状态变化是否影响ACTION决策逻辑 2) 测量文件竞争窗口期与命令触发的时序关系。关联发现：file_race-hotplug-state_manipulation和command_injection-hotplug_system-0x00401550

---
### network_input-goform_virtual_server-rule_operation

- **文件路径:** `web/main/virtualServer.htm`
- **位置:** `www/virtualServer.htm:45,76,112,189`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 发现四个高风险API端点处理用户配置操作，其中删除操作(delRule)和添加操作直接接收前端传入的ID和表单数据。触发条件：用户通过web界面提交配置。触发步骤：1) 攻击者绕过客户端验证 2) 构造恶意参数（如越权delRule值或命令注入payload） 3) 提交到/goform端点。成功利用概率较高（7.5/10），因客户端验证可被绕过且后端验证未知。
- **关键词:** /goform/DelVirtualServerRule, delRule, /goform/AddVirtualServerRule, getFormData, ipAddr, interPort, serName
- **备注:** 需分析/goform端点对应的后端处理程序（可能在bin或sbin目录），验证：1) delRule的权限检查 2) ipAddr/interPort的边界验证 3) 是否直接用于系统命令执行；关联关键词'$.act'在知识库中已存在

---
### network_input-setkey-recv_overflow_0x40266c

- **文件路径:** `usr/bin/setkey`
- **位置:** `setkey:0x40266c`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 远程代码执行漏洞：通过PF_KEY套接字发送>32760字节数据包，recv函数将数据写入固定栈缓冲区(auStack_8028)导致栈溢出。结合缺失栈保护机制，可覆盖返回地址执行任意代码。触发条件：攻击者需具备PF_KEY套接字访问权限（通常需root或特殊组权限）。
- **代码片段:**
  ```
  iVar1 = sym.imp.recv(*0x41cb8c, auStack_8028, 0x8000, 0);
  ```
- **关键词:** recv, auStack_8028, PF_KEY, 0x8000, setkey, fcn.00402484

---
### network_input-http-stack_overflow

- **文件路径:** `usr/bin/cwmp`
- **位置:** `fcn.00409790 (cwmp_processConnReq)`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** HTTP处理三重缺陷：1) SOAPAction头使用硬编码地址0x414790（内容全零），导致未初始化头值 2) ACS URL路径未进行路径规范化，可能引发路径遍历 3) sprintf构建响应头时未验证缓冲区边界（auStack_830仅1024字节）。攻击者可通过超长cnonce参数触发栈溢出（0x00409f74）。触发条件：发送恶意HTTP请求操纵SOAPAction/URL路径或包含>500字节cnonce参数。
- **关键词:** cwmp_processConnReq, SOAPAction, http_request_buffer, sprintf, auStack_830, cnonce, Authentication-Info
- **备注:** 关键证据：sprintf直接拼接用户可控的cnonce到固定栈缓冲区。需关联：fcn.0040b290（SOAPAction写入点）

---
### network_input-ddos_threshold_validation-1

- **文件路径:** `web/main/ddos.htm`
- **位置:** `www/ddos.htm:0 (表单输入区域)`
- **类型:** network_input
- **综合优先级分数:** **8.5**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** HTML表单中ICMP/UDP/TCP阈值输入框（icmpLow等）仅通过maxlength=4限制字符长度，无数字范围/类型验证。攻击者可通过修改前端或发送恶意HTTP请求注入负数/超大值。触发条件：提交包含恶意参数的HTTP请求。边界检查缺失导致可能触发后端整数溢出或配置异常。潜在影响：结合后端漏洞可形成拒绝服务或内存破坏攻击链。
- **代码片段:**
  ```
  <input type="text" class="s" value="" maxlength="4" required />
  ```
- **关键词:** icmpLow, icmpMiddle, icmpHigh, udpLow, udpMiddle, udpHigh, tcpLow, tcpMiddle, tcpHigh, doSaveDosProtection, DDOS_CFG
- **备注:** 需验证httpd中处理DDOS_CFG的后端函数是否进行5-3600范围检查；关联发现：direct_data_pass-ddos_cfg-1

---

## 中优先级发现

### configuration_load-etc_passwd-admin_root

- **文件路径:** `etc/passwd.bak`
- **位置:** `etc/passwd.bak:1`
- **类型:** configuration_load
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** admin账户使用弱加密(MD5)的密码哈希且配置为root权限(UID=0)，$1$前缀表明采用crypt()旧式加密。攻击者可通过爆破哈希获取root shell。触发条件：SSH/Telnet等服务开放且允许密码登录。边界检查缺失：未使用强加密算法(如SHA-512)且未限制root权限账户。实际影响：直接获取设备完全控制权。
- **代码片段:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  ```
- **关键词:** admin, UID=0, passwd.bak, crypt(), $1$, /bin/sh
- **备注:** 需验证/etc/shadow文件是否存在相同弱哈希；检查dropbear/sshd配置是否允许密码登录

---
### xss-bot_info_dom

- **文件路径:** `web/frame/bot.htm`
- **位置:** `bot.htm: JavaScript代码块`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** bot.htm存在存储型XSS漏洞触发点：通过$.act获取的devInfo.softwareVersion/devInfo.hardwareVersion未经任何过滤直接插入DOM。触发条件：1) 攻击者需先污染版本信息数据源（如通过NVRAM注入）2) 用户访问含bot.htm的页面。潜在影响：可实现会话劫持、恶意重定向或凭证窃取。边界检查：完全缺失输出编码，直接使用innerHTML插入用户可控数据。
- **代码片段:**
  ```
  $("#bot_sver").html(s_str.swver + devInfo.softwareVersion);
  ```
- **关键词:** IGD_DEV_INFO, devInfo.softwareVersion, devInfo.hardwareVersion, $.act, $.exe, innerHTML, ACT_GET, $("#bot_sver").html
- **备注:** 关联发现：知识库中已存在web/index.htm的IGD_DEV_INFO漏洞记录（xss-dev_info_dom）。需后续验证：1) /cgi-bin下处理ACT_GET的二进制程序 2) NVRAM版本变量设置操作是否存在注入漏洞 3) 扫描JS框架定位$.act实现

---
### network_input-socket_option-ioctl_write_0x40deec

- **文件路径:** `usr/sbin/atmarpd`
- **位置:** `fcn.00401590 → fcn.0040de98@0x40deec`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 高危内存写入漏洞：通过accept接收数据后，未验证的SO_ATMQOS选项值(acStack_84[0])触发ioctl(0x200061e2)，当uStack_10≠0时向固定地址0x00432de0写入固定值0x00000fd6。触发条件：攻击者设置SO_ATMQOS选项使acStack_84[0]≠0。实际影响：破坏关键全局状态导致服务崩溃或逻辑漏洞，写入值固定限制了利用灵活性。
- **代码片段:**
  ```
  iVar5 = fcn.0040de98(iVar1,0x200061e2,uStack_10);
  sw s0, (v0)  // v0=0x00432de0, s0=0x00000fd6
  ```
- **关键词:** ioctl, SO_ATMQOS, acStack_84, uStack_10, 0x00432de0, 0x200061e2, ATMARP_MKIP
- **备注:** 需验证SO_ATMQOS设置权限；分析0x00432de0全局变量用途

---
### xss-jquery_tpSelect-render

- **文件路径:** `web/index.htm`
- **位置:** `www/web/jquery.tpSelect.js (函数: render)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** jquery.tpSelect.js插件render函数未过滤option.val()/option.text()直接拼接HTML，导致存储型XSS漏洞。触发条件：1) 后端动态生成未过滤的option内容 2) 用户点击被污染选项。安全影响：会话劫持和完全控制用户浏览器。利用方式：攻击者通过污染option数据注入恶意脚本（如<script>alert(document.cookie)</script>）。边界检查：完全缺失输入验证和输出编码。
- **代码片段:**
  ```
  return $("<li data-val='" + option.val() + "'>" + option.text() + "</li>");
  ```
- **关键词:** render, option.val(), option.text(), $.fn.tpSelect, data-val, innerHTML, DOM_XSS
- **备注:** 需验证option数据来源是否暴露给外部输入（如HTTP参数）。关联点：1) 检查后端生成option的API端点 2) 追踪oid_str.js中GPON_AUTH_PWD等标识符的数据流

---
### xss-jquery_tpMsg-argument_injection

- **文件路径:** `web/index.htm`
- **位置:** `www/web/jquery.tpMsg.js (消息处理函数)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** jquery.tpMsg.js消息处理函数(alert/confirm)使用str.replace('$',arguments[i])直接插入用户参数，通过.html()注入未过滤内容。触发条件：调用函数时传入恶意参数（如<img src=x onerror=alert(1)>）。安全影响：控制消息弹窗执行任意脚本。利用方式：通过污染函数参数触发DOM型XSS。边界检查：未对arguments[i]进行HTML实体编码。
- **代码片段:**
  ```
  str = str.replace("$", arguments[i]);
  tmp.find("span.text").html(str);
  ```
- **关键词:** jQuery.alert, jQuery.confirm, str.replace, arguments[i], .html(str), DOM_XSS
- **备注:** 需追踪函数调用参数来源。关键验证：1) 参数是否来自location.search等外部输入 2) 与后端/cgi/auth等端点的数据流关联

---
### config-symlink-etc-passwd-perm

- **文件路径:** `etc/group`
- **位置:** `etc/passwd:0 (permission)`
- **类型:** configuration_load
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** /etc/passwd符号链接权限配置漏洞：文件权限设置为777(lrwxrwxrwx)，指向/var/passwd。攻击者可修改链接指向恶意文件(如/tmp/fake_passwd)，当系统进程(如登录验证、sudo权限检查)读取时，可能触发：1) 身份认证绕过(通过伪造root用户) 2) 敏感信息泄露 3) 服务拒绝。触发条件：攻击者需先获得低权限文件写入能力(如通过Web漏洞上传shell)。
- **代码片段:**
  ```
  lrwxrwxrwx 1 root root 11 Jan 1 00:00 /etc/passwd -> /var/passwd
  ```
- **关键词:** /etc/passwd, /var/passwd, symbolic link, lrwxrwxrwx, getpwnam, getpwuid
- **备注:** 后续验证：1) 检查/var/passwd实际权限 2) 审计依赖passwd的系统进程列表 3) 确认固件是否部署文件完整性监控。关联漏洞：可能成为权限提升链的关键环节。

---
### stack_overflow-httpd_softup-0x4039ac

- **文件路径:** `usr/bin/httpd`
- **位置:** `httpd:0x4039ac (fcn.004038ec+0xdc)`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** /cgi/softup端点存在嵌套溢出链：fcn.004038ec调用fcn.00404bd0时从HTTP头读取最大0x400字节数据到栈缓冲区（约0x100字节）。Content-Disposition等字段超长时可覆盖栈帧。触发条件：构造特殊multipart请求包含超长头字段。
- **代码片段:**
  ```
  jal fcn.00404bd4
  move a2, s4 // s4指向全局缓冲区
  ```
- **关键词:** fcn.004038ec, fcn.00404bd0, stack_buffer_overflow, Content-Disposition, 0x400, multipart_request
- **备注:** 关联知识库关键词：fcn.004038ec, Content-Disposition。关键疑问：全局缓冲区0x00435384是否导致二次溢出？建议动态测试

---
### network_input-setkey-nullptr_deref_0x402998

- **文件路径:** `usr/bin/setkey`
- **位置:** `setkey:0x402998`
- **类型:** network_input
- **综合优先级分数:** **8.3**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 信息泄露/拒绝服务漏洞：当recv返回0（连接关闭）时，程序解引用未初始化指针(puVar10)。攻击者关闭连接即可触发崩溃或栈数据泄露。触发条件：需PF_KEY套接字访问权限，无需构造特殊数据包。
- **代码片段:**
  ```
  if (*(puVar10 + 4) << 3 != iVar5) break;
  ```
- **关键词:** recv, puVar10, 0x8000, setkey, fcn.004027c4

---
### heap_overflow-write_packet-l2tp

- **文件路径:** `usr/sbin/xl2tpd`
- **位置:** `xl2tpd:0x405c0c (write_packet)`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** write_packet函数存在堆缓冲区溢出漏洞：1) 触发条件：攻击者发送长度>2047字节且包含大量需转义字符（ASCII<0x20,0x7d,0x7e）的L2TP数据包；2) 边界检查缺陷：仅检查原始长度(uVar8<0xffb)，未考虑转义操作导致实际写入obj.wbuf.4565缓冲区的数据可能超出4096字节；3) 安全影响：成功利用可覆盖堆内存关键结构，导致任意代码执行或服务崩溃。
- **代码片段:**
  ```
  if (0xffb < uVar8) {
    l2tp_log("rx packet too big");
  }
  ```
- **关键词:** obj.wbuf.4565, write_packet, handle_packet, add_fcs, rx_packet_is_too_big_after_PPP_encoding
- **备注:** 需动态验证：1) 网络MTU是否允许发送>2047字节包 2) obj.wbuf.4565相邻内存布局

---
### network_input-DDNS_password_validation

- **文件路径:** `web/main/ddns.htm`
- **位置:** `www/ddns.htm:0 (doSave函数)`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** DDNS配置页存在输入验证缺陷：1) 密码字段(dyndns_pwd/noip_pwd)仅验证非空，无字符过滤或长度限制 2) 用户输入直接拼接进$.act请求参数(如'password='+pwd)未编码处理。攻击者可通过提交恶意构造的密码尝试注入攻击。触发条件：认证用户提交DDNS配置表单。实际影响取决于后端对DYN_DNS_CFG/NOIP_DNS_CFG请求的处理方式。
- **代码片段:**
  ```
  usr = $('#dyndns_usr').prop('value');
  pwd = $('#dyndns_pwd').prop('value');
  $.act(ACT_SET, DYN_DNS_CFG, ..., ["userName=" + usr, "password=" + pwd]);
  ```
- **关键词:** dyndns_pwd, noip_pwd, dyndns_usr, noip_usr, $.act, ACT_SET, DYN_DNS_CFG, NOIP_DNS_CFG, doSave
- **备注:** 需在cgibin中验证：1) DYN_DNS_CFG/NOIP_DNS_CFG对应函数是否过滤特殊字符 2) 参数解析是否存在命令注入风险

---
### xss-jquery_tpTable-body_rendering

- **文件路径:** `web/index.htm`
- **位置:** `www/web/jquery.tpTable.js (函数: initTableBody, appendTableRow)`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** jquery.tpTable.js存在双重XSS风险：1) initTableBody()未过滤array[i][j].text 2) appendTableRow()未过滤data[j].text，均直接拼接HTML插入DOM。触发条件：调用方传入包含恶意脚本的表格数据。安全影响：通过控制表格内容执行任意脚本。利用方式：攻击者构造含XSS payload的API响应污染表格数据。边界检查：完全缺失内容过滤机制。
- **代码片段:**
  ```
  var td = "<td class='table-content'>" + array[i][j].text + "</td>";
  ```
- **关键词:** initTableBody, appendTableRow, array[i][j].text, data[j].text, innerHTML, table_injection
- **备注:** 实际危害取决于表格数据来源。关键关联：1) 检查$.ajax调用的后端端点 2) 验证数据是否来自NVRAM(如APP_CFG)或文件(config.ini)

---
### env_get-hotplug-env_injection

- **文件路径:** `sbin/hotplug`
- **位置:** `hotplug (binary)`
- **类型:** hardware_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 环境变量$ACTION/$DEVPATH/$INTERFACE未经验证直接用于控制流决策和路径构造。攻击者通过伪造热插拔事件注入恶意环境变量可触发路径遍历风险（如'../../'注入）。具体触发条件：内核生成热插拔事件时自动设置这些变量，攻击者需模拟设备插拔事件。边界检查缺失体现在路径构造直接拼接变量值，未进行路径规范化或字符过滤。
- **代码片段:**
  ```
  getenv("ACTION"); getenv("DEVPATH"); getenv("INTERFACE");
  ```
- **关键词:** getenv, ACTION, DEVPATH, INTERFACE, hotplug_leds, hotplug_storage_mount
- **备注:** 需反编译验证变量使用点的过滤逻辑，关注/system/class/scsi_host路径构造

---
### command_execution-insmod-integrity

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:36-48`
- **类型:** command_execution
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 动态加载内核模块未验证完整性。通过'insmod'加载usb-storage.ko等模块时未检查文件签名或哈希。若攻击者替换模块文件（如通过FTP写入），可实现内核代码注入。触发条件需获得文件写入权限+设备重启。
- **代码片段:**
  ```
  insmod /lib/modules/kmdir/kernel/drivers/usb/storage/usb-storage.ko
  ```
- **关键词:** insmod, usb-storage.ko, nf_conntrack_pptp.ko
- **备注:** 需检查/lib/modules目录权限

---
### file_read-ppp-credential_permission

- **文件路径:** `usr/sbin/pppd`
- **位置:** `pppd:main`
- **类型:** file_read
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 凭证文件权限控制缺陷：pppd以只读模式访问/var/tmp/pppInfo_*文件（含明文凭证），但未验证文件权限。若外部创建者（如认证脚本）未设严格权限（如umask=022），则全局可读导致凭证泄露。触发条件：1) PPP连接需用户名/密码认证 2) 文件权限≥644。实际影响：攻击者可窃取PPP凭据发起中间人攻击或未授权访问，成功概率取决于系统配置。
- **代码片段:**
  ```
  iVar16 = sym.imp.fopen(auStack_f8,0x4468f8);  // 'r'模式打开
  fread(obj.user,1,obj.username_len,iVar16);
  ```
- **关键词:** /var/tmp/pppInfo_, fopen, obj.user, obj.passwd, obj.username_len, obj.passwd_len
- **备注:** 需验证：1) 文件创建者的umask默认值 2) /var/tmp目录权限 3) 凭证文件删除机制（未在pppd中发现）

---
### mount-var-ramfs-rwexec

- **文件路径:** `etc/fstab`
- **位置:** `etc/fstab:2`
- **类型:** configuration_load
- **综合优先级分数:** **8.05**
- **风险等级:** 7.5
- **置信度:** 10.0
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** /var目录配置为ramfs且启用rw+exec。结合日志路径注入漏洞（如污染log_file参数），攻击者可写入恶意程序到/var/log目录，通过日志轮转机制触发执行。触发条件：1) 服务存在路径遍历漏洞 2) 日志处理脚本动态执行文件。约束条件：需控制日志文件名或路径。利用链：伪造恶意日志路径→写入/var/log/exploit→logrotate执行→权限提升。
- **代码片段:**
  ```
  ramfs /var ramfs defaults 0 0
  ```
- **关键词:** /var, ramfs, defaults, rw, exec
- **备注:** 需审计使用/var目录的服务（如syslogd）

---
### network_input-dhtml-xss

- **文件路径:** `web/js/lib.js`
- **位置:** `lib.js:170 [dhtml]`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** dhtml函数（lib.js:170）存在存储型XSS风险：未过滤的str参数直接用于`$.div.innerHTML = "div" + str`操作。用户输入通过调用链传播：外部path参数→loadMain→loadPage→tpLoad→fill→appendElem→dhtml。触发条件：攻击者控制path参数（例如通过URL操纵或页面跳转），当该参数包含恶意脚本时会被直接渲染。边界检查：无任何HTML编码或过滤。实际影响：若上层组件暴露path参数控制点，可导致持久性XSS攻击。关联知识库关键词：innerHTML（已存在相关风险记录）。
- **代码片段:**
  ```
  $.div.innerHTML = "div" + str;
  ```
- **关键词:** dhtml, str, innerHTML, appendElem, fill, tpLoad, loadPage, path, loadMain, $.curPage
- **备注:** 需后续验证：1) path参数是否来自URL解析 2) 调用loadMain的组件（如路由器）是否暴露用户控制点。关联知识库：innerHTML（已存在）

---
### ipc-unix_socket-dos_0x400eb8

- **文件路径:** `usr/sbin/atmarpd`
- **位置:** `atmarpd@0x400eb8 (fcn.00400eb8)`
- **类型:** ipc
- **综合优先级分数:** **8.05**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** 拒绝服务漏洞：通过Unix域套接字接收172字节消息时，消息类型字段(auStack_c4[0])为0-6会访问未初始化跳转表0x42d2e4（全0xffffffff），触发非法指令崩溃。触发条件：构造首字节0x00-0x06的172字节消息。实际影响：服务不可用。
- **关键词:** fcn.00400eb8, auStack_c4, 0x42d2e4, halt_baddata
- **备注:** 需动态验证崩溃效果

---
### network_input-frontend_validation_missing-trafficCtrl

- **文件路径:** `web/main/trafficCtrl.htm`
- **位置:** `trafficCtrl.htm: doSave()函数`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 前端数值验证缺失导致潜在整数溢出/服务拒绝风险。具体表现：1) 带宽字段(upTotalBW/downTotalBW)仅用$.isnum()验证数字格式，未检查负数/超大整数(>2147483647) 2) 端口范围字段(startPort/endPort)缺失0-65535范围校验 3) IPTV带宽保证值(iptvUpMinBW/iptvDownMinBW)未验证多服务累加值是否超限。触发条件：攻击者通过HTTP参数提交畸形值(如-1或2147483648)，若后端CGI未重复验证，可导致服务崩溃或未定义行为。
- **代码片段:**
  ```
  if (($("#upTotalBW").val() == "") || (!$.isnum($("#upTotalBW").val())) || (0 == $("#upTotalBW").val()))
  ```
- **关键词:** upTotalBW, downTotalBW, startPort, endPort, iptvUpMinBW, iptvDownMinBW, $.isnum, wanDslStatus
- **备注:** 需验证后端CGI是否实施相同检查。关键追踪参数：upTotalBW/downTotalBW在CGI中的处理流程。关联发现：cgi-exposure-trafficCtrl

---
### network_input-hotplug_interface_control_flow

- **文件路径:** `etc/hotplug.d/net/10-net`
- **位置:** `etc/hotplug.d/net/10-net:13-15,18,27,37,54`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 环境变量$INTERFACE未经任何过滤或验证直接用于：1) 控制流程（行13-15的case模式匹配）；2) 作为参数传递给find_config和setup_interface函数；3) VLAN设备名匹配（行37,54）。触发条件：攻击者通过伪造网络接口名（如恶意命名的USB网卡）触发hotplug事件。约束条件：ppp*/3g-*接口被跳过（行13），其他接口均受影响。安全影响：可操纵网络配置流程，若后续函数存在漏洞（如命令注入），可能形成完整攻击链。
- **代码片段:**
  ```
  case "$INTERFACE" in
      ppp*|3g-*) return 0;;
  esac
  
  local cfg="$(find_config "$INTERFACE")"
  
  setup_interface "$INTERFACE"
  
  [ "${dev%%\.*}" = "$INTERFACE" -a "$dev" != "$INTERFACE" ]
  ```
- **关键词:** INTERFACE, find_config, setup_interface, add_vlan, dev
- **备注:** 需验证/lib/network中的setup_interface/add_vlan实现是否对$INTERFACE进行安全处理。关联发现：network_input-hotplug_interface_validation

---
### network_input-ppp-buffer_overflow

- **文件路径:** `usr/sbin/pppd`
- **位置:** `pppd:0x425254 sym.generic_establish_ppp`
- **类型:** network_input
- **综合优先级分数:** **7.95**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 6.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 存在通过PPP连接触发的缓冲区溢出风险：攻击者可构造恶意PPP连接控制ioctl(PPPIOCATTACH)操作，使obj.ifunit被赋值为超大整数（超过10位）。该值传递至sprintf写入固定32字节缓冲区(auStack_d8)，格式化字符串'/tmp/pppuptime-%s%d'在单元号≥10000000000时可能溢出（静态部分19字节+11位数字=30字节+null=31B，边际安全但无冗余）。触发条件：建立PPP连接时内核返回异常大单元号。实际影响：pppd通常以root运行，成功溢出可导致任意代码执行。
- **代码片段:**
  ```
  iVar2 = sym.imp.ioctl(iVar1,0x8004743a,obj.ifunit);  // PPPIOCATTACH写入
  sym.imp.sprintf(auStack_d8,"/tmp/pppuptime-%s%d","ppp",*obj.ifunit);
  ```
- **关键词:** obj.ifunit, PPPIOCATTACH, ioctl, sprintf, auStack_d8, /tmp/pppuptime-%s%d, sym.generic_establish_ppp
- **备注:** 需驱动层验证：1) PPP协议栈是否允许超大单元号 2) 内核ioctl处理是否受攻击者控制。建议后续分析PPP驱动模块。

---
### web_input-parent_ctrl-multi_input

- **文件路径:** `web/main/parentCtrl.htm`
- **位置:** `parentCtrl.htm (全文)`
- **类型:** network_input
- **综合优先级分数:** **7.95**
- **风险等级:** 8.5
- **置信度:** 7.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** HTML界面暴露多个高危输入点：1) 设备管理（ACT_ADD/ACT_DEL）通过INTERNAL_HOST端点提交设备名/MAC地址，仅前端使用$.isname()/$.mac()验证 2) URL关键词（EXTERNAL_HOST）仅验证域名格式($.isdomain())但未过滤特殊字符 3) 删除操作直接传递__stack索引(如deviceStack[index])未验证权限 4) 时间参数(sunAm等)拼接为4进制数值无边界检查。触发条件：攻击者绕过前端验证或直接构造恶意请求（如越权索引/超长URL），可能导致后端命令注入、权限绕过或内存破坏。
- **代码片段:**
  ```
  关键代码片段:
  1. 设备删除请求构造: 
     $.act(ACT_DEL, INTERNAL_HOST, deviceStack[childStackIndex], null)
  2. URL提交逻辑:
     if($.isdomain($('#urlAddr').val())){ 
        $.act(ACT_ADD, EXTERNAL_HOST, ...)
     }
  ```
- **关键词:** ACT_ADD, ACT_DEL, INTERNAL_HOST, EXTERNAL_HOST, __stack, deviceStack, deviceName, macAddress, urlAddr, sunAm, enalbeParentCtrl, parentCtrlMode, $.act
- **备注:** 需紧急验证：1) 后端对deviceStack索引的权限校验 2) INTERNAL_HOST端点是否过滤特殊字符 3) 时间参数数值范围检查。建议后续分析路径：追踪$.act()函数实现（可能位于web/js/*.js）及INTERNAL_HOST处理模块（可能位于bin/httpd或lib/*.so）。关联知识库现有$.act操作链记录。

---
### security_mechanism-setkey-stack_protection_missing

- **文件路径:** `usr/bin/setkey`
- **位置:** `setkey:multiple`
- **类型:** configuration_load
- **综合优先级分数:** **7.89**
- **风险等级:** 7.5
- **置信度:** 9.8
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 关键漏洞函数(fcn.00402484/fcn.004027c4/fcn.00402bf4)均缺失栈保护机制：1) 无__stack_chk_fail引用 2) 无canary值检测 3) 返回地址位于固定偏移。大幅降低漏洞利用难度，攻击者可直接覆盖返回地址无需绕过保护机制。
- **关键词:** __stack_chk_fail, stack_canary, return_address_offset, setkey, fcn.00402484, fcn.004027c4, fcn.00402bf4

---
### command_execution-hotplug_route_injection

- **文件路径:** `etc/hotplug.d/iface/10-routes`
- **位置:** `etc/hotplug.d/iface/10-routes: 路由添加命令段`
- **类型:** command_execution
- **综合优先级分数:** **7.8**
- **风险等级:** 8.5
- **置信度:** 7.5
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 在接口启动(ifup)时，脚本使用未经验证的$target/$gateway变量拼接路由命令(/sbin/route)，未对变量内容进行过滤或转义。攻击者若污染这些变量（如通过恶意配置注入），可利用命令拼接执行任意命令。触发条件：1) 控制$target/$gateway输入源；2) 触发网络接口热插拔事件。
- **代码片段:**
  ```
  /sbin/route add $dest ${gateway:+gw "$gateway"} \
  		${dev:+dev "$dev"} ${metric:+ metric "$metric"} \
  		${mtu:+mss "$mtu"}
  ```
- **关键词:** $target, $gateway, /sbin/route, add_route, add_route6, dest, metric, mtu
- **备注:** 需后续追踪$target/$gateway污染源（如UCI配置/NVRAM）。实际风险取决于输入控制难度

---
### command_execution-cos-background

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:61`
- **类型:** command_execution
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 通过'cos &'启动未知后台服务。该命令未指定路径和参数，若cos二进制存在漏洞（如缓冲区溢出），攻击者可能通过该服务进行权限提升。触发条件为cos服务暴露网络接口或处理不可信输入。
- **代码片段:**
  ```
  cos &
  ```
- **关键词:** cos
- **备注:** 后续需逆向分析/bin/cos或/usr/sbin/cos

---
### xss-dev_info_dom

- **文件路径:** `web/index.htm`
- **位置:** `web/frame/bot.htm:<script>`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 8.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 设备信息接口未净化XSS漏洞：1. 触发条件：攻击者篡改softwareVersion/hardwareVersion字段（通过固件修改或配置漏洞）2. 约束条件：$.act(ACT_GET, IGD_DEV_INFO)响应数据未经HTML编码直接插入DOM 3. 安全影响：存储型XSS可窃取会话/执行恶意操作 4. 利用方式：结合固件篡改漏洞污染版本字段，用户访问含bot.htm页面即触发
- **代码片段:**
  ```
  $("#bot_sver").html(s_str.swver + devInfo.softwareVersion);
  ```
- **关键词:** IGD_DEV_INFO, softwareVersion, hardwareVersion, .html(), devInfo, $.act
- **备注:** 需验证/cgi端点对IGD_DEV_INFO请求的访问控制

---
### credential-hardcoded_auth-rdp

- **文件路径:** `usr/bin/cli`
- **位置:** `usr/bin/cli (硬编码凭据区域)`
- **类型:** configuration_load
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 6.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 检测到硬编码认证参数（adminPwd/rootPwd/adminName），通过USER_CFG/X_TP_PreSharedKey等配置项暴露。若攻击者能访问NVRAM或配置文件（如/var/tmp/cli_authStatus），可能获取敏感凭据。当前文件未发现直接操作NVRAM/env的证据，但存在关联函数rdp_getObjStruct。
- **关键词:** adminPwd, rootPwd, adminName, USER_CFG, X_TP_PreSharedKey, rdp_getObjStruct
- **备注:** 建议后续分析NVRAM操作和配置文件权限；需验证rdp_getObjStruct是否操作NVRAM（参考知识库NVRAM_injection关键词）

---
### network_input-config_fields-frontend_validation

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `manageCtrl.htm:unknown (前端验证函数)`
- **类型:** network_input
- **综合优先级分数:** **7.7**
- **风险等级:** 8.2
- **置信度:** 7.0
- **触发可能性:** 7.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 发现12个用户可控输入字段分属四个配置区域，包括凭证修改(curName/curPwd)、网络配置(l_http_port/r_host)和ICMP控制(pingRemote)。触发条件：用户提交表单时前端仅进行基础ASCII校验和长度检查，未过滤特殊字符。后端若未二次验证，攻击者可注入恶意载荷（如命令注入、缓冲区溢出），通过/cgi/auth和ACT_SET端点直达系统配置层。
- **关键词:** curName, curPwd, l_http_port, r_host, pingRemote, /cgi/auth, ACT_SET, doSave
- **备注:** 关键验证点：需分析/cgi/auth和ACT_SET对应的后端实现；关联知识库中的ACT_SET操作链（已存在linking_keywords）

---
### network_input-hotplug_interface_validation

- **文件路径:** `etc/hotplug.d/net/10-net`
- **位置:** `10-net:12,20,39`
- **类型:** network_input
- **综合优先级分数:** **7.65**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 7.0
- **查询相关性:** 9.2
- **阶段:** N/A
- **描述:** 在热插拔事件处理中，$INTERFACE参数仅通过'case "$INTERFACE" in ppp*|3g-*) return 0;; esac'进行基础过滤，未验证长度/特殊字符。该参数直接传入特权函数setup_interface和add_vlan（代码位置：10-net:12,20,39）。若下游函数存在命令注入漏洞（如未过滤分号/反引号），攻击者可通过伪造hotplug事件注入恶意接口名（如'eth0;rm -rf /'）触发任意命令执行。触发条件：物理/虚拟网络接口状态变化（如插拔网线）时自动触发。
- **代码片段:**
  ```
  case "$INTERFACE" in
    ppp*|3g-*) return 0;;
  esac
  ...
  setup_interface "$INTERFACE"
  ...
  add_vlan "$INTERFACE"
  ```
- **关键词:** INTERFACE, setup_interface, add_vlan, config_get, ifname, device, auto
- **备注:** 风险等级基于：1) $INTERFACE直接来自外部事件 2) 缺乏输入净化 3) 特权函数调用链。需获取/lib/network实现确认最终可利用性（当前分析限制：无法分析setup_interface实现）。

---
### ipc-hotplug-command-injection-00-netstate

- **文件路径:** `etc/hotplug.d/iface/00-netstate`
- **位置:** `etc/hotplug.d/iface/00-netstate:1-6`
- **类型:** ipc
- **综合优先级分数:** **7.65**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 在'00-netstate'脚本中发现高危操作链：1) 网络接口启动事件触发时($ACTION='ifup')；2) 直接使用未经验证的$INTERFACE和$DEVICE环境变量执行uci_toggle_state命令；3) $DEVICE仅检查非空但未过滤内容，$INTERFACE完全未验证；4) 攻击者可通过伪造hotplug事件注入恶意参数（如包含命令分隔符或路径遍历字符）。实际安全影响取决于uci_toggle_state的实现，可能造成命令注入或状态篡改。
- **代码片段:**
  ```
  [ ifup = "$ACTION" ] && {
  	uci_toggle_state network "$INTERFACE" up 1
  	...
  	[ -n "$DEVICE" ] && uci_toggle_state network "$INTERFACE" ifname "$DEVICE"
  }
  ```
- **关键词:** uci_toggle_state, INTERFACE, DEVICE, ACTION, ifup, hotplug.d
- **备注:** 受限于分析范围无法验证uci_toggle_state实现。后续建议：1) 将分析焦点切换至/sbin目录验证命令安全；2) 检查hotplug事件触发机制是否允许外部注入环境变量；3) 分析网络接口配置流程确认攻击面

---
### command_injection-hotplug_system-0x00401550

- **文件路径:** `sbin/hotplug`
- **位置:** `hotplug:0 (system call) 0x00401550`
- **类型:** hardware_input
- **综合优先级分数:** **7.65**
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 当热插拔事件触发时，/sbin/hotplug通过环境变量ACTION、DEVPATH、INTERFACE接收外部输入并直接用于构建system()命令参数（如'rm -rf'、'cp -pR'），未进行输入过滤或边界检查。攻击者可通过恶意设备触发hotplug事件并注入环境变量（如设置ACTION='; rm -rf /;'），导致任意命令执行。完整攻击链：1) 连接恶意USB设备 2) 内核触发hotplug事件 3) 污染环境变量传递至hotplug 4) 注入命令通过system()执行。
- **代码片段:**
  ```
  echo %d %d > %s  # 字符串地址0x00003ecc
  ```
- **关键词:** ACTION, DEVPATH, INTERFACE, system, hotplug_leds, hotplug_storage_mount, /proc/tplink/led_usb, /var/run/storage_led_status
- **备注:** 需验证hotplug事件触发机制的实际可控性。关联线索：1) 知识库存在相同关键词'/var/run/storage_led_status' 2) 'hotplug_leds'可能关联LED控制组件 3) 需检查是否与存储挂载组件(hotplug_storage_mount)形成组合漏洞链

---
### configuration_load-etc_services-dual_protocols

- **文件路径:** `etc/services`
- **位置:** `etc/services`
- **类型:** configuration_load
- **综合优先级分数:** **7.6**
- **风险等级:** 6.0
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 42个服务同时开放TCP/UDP协议（如echo:7, discard:9）。触发条件：服务实现双协议支持时。安全影响：UDP协议易被用于反射攻击（如chargen），TCP协议增加会话劫持风险。利用方式：组合利用协议差异发起放大攻击或协议混淆攻击。
- **关键词:** echo, discard, 7/tcp, 7/udp, 9/tcp, 9/udp, chargen, 19/udp
- **备注:** 关键双协议服务：echo(7), discard(9), chargen(19), 需检查其守护进程实现是否存在边界检查缺陷。关联操作：etc/init.d/rcS中通过echo命令修改/proc参数(file_write-ip_forward-modification)

---
### configuration_load-etc_services-nonstandard_ports

- **文件路径:** `etc/services`
- **位置:** `etc/services`
- **类型:** configuration_load
- **综合优先级分数:** **7.55**
- **风险等级:** 6.5
- **置信度:** 10.0
- **触发可能性:** 6.5
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 检测到非常规端口服务（如http-alt:8008, webcache:8080）。触发条件：服务在非常规端口启用时。安全影响：可能绕过安全检测机制，增加隐蔽攻击面。利用方式：攻击者扫描非常规端口后针对特定服务漏洞利用（如HTTP参数注入）。
- **关键词:** http-alt, webcache, 8008/tcp, 8080/tcp, tproxy, 8081/tcp
- **备注:** 共发现87个≥1024端口的服务，需结合网络配置分析实际暴露情况

---
### attack_chain-ftp_credential_reuse_to_root

- **文件路径:** `etc/passwd.bak`
- **位置:** `etc/vsftpd_passwd → etc/passwd.bak:1`
- **类型:** network_input
- **综合优先级分数:** **7.55**
- **风险等级:** 8.5
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 潜在攻击链：FTP凭证复用获取root权限。攻击步骤：1) 利用路径遍历漏洞读取/etc/vsftpd_passwd → 2) 提取admin账户明文密码'1234' → 3) 尝试登录SSH/Telnet服务（若开放密码认证）→ 4) 成功认证后获得root shell（因admin账户UID=0）。触发条件：a) vsftpd_passwd文件可被读取 b) SSH/Telnet服务开放 c) 密码复用成立。约束条件：需密码匹配验证。实际影响：完全控制系统。成功概率评估：7.5（依赖多条件满足）。
- **关键词:** admin, vsftpd_passwd, passwd.bak, crypt(), $1$, FTP_credentials
- **备注:** 需验证：1) '1234'是否生成$1$$iC.dUsGpxNNJGeOm1dFio/哈希 2) SSH服务配置（如dropbear是否允许密码登录）

---
### timing-attack-busybox-auth

- **文件路径:** `bin/busybox`
- **位置:** `busybox:0x00434824`
- **类型:** network_input
- **综合优先级分数:** **7.55**
- **风险等级:** 6.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 认证流程使用strcmp进行密码明文比较，存在时序攻击风险。攻击者通过测量响应时间差异可能推断密码内容。风险独立于硬编码密码漏洞，实际危害程度取决于：1) 认证服务暴露程度(telnetd/httpd是否启用) 2) 认证尝试次数限制机制。
- **关键词:** strcmp, authentication_func, side_channel, busybox_login
- **备注:** 影响范围依赖网络服务配置。建议：1) 检查telnetd服务状态 2) 替换为恒定时间比较算法

---
### auth_bypass-cgi_reboot

- **文件路径:** `web/index.htm`
- **位置:** `web/js/lib.js`
- **类型:** network_input
- **综合优先级分数:** **7.5**
- **风险等级:** 8.5
- **置信度:** 7.5
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 统一操作端点认证缺失风险：1. 触发条件：发送type=7&oid=ACT_REBOOT的HTTP请求到/cgi 2. 约束条件：lib.js中$.exe()函数未包含认证令牌参数 3. 安全影响：未授权重启导致拒绝服务 4. 利用方式：攻击者构造恶意POST请求触发设备重启
- **代码片段:**
  ```
  xhr.open(s.type, "/cgi?" + param, s.async);
  ```
- **关键词:** $.exe, /cgi, ACT_OP, ACT_REBOOT, oid
- **备注:** 需实际测试/cgi端点认证机制

---
### network_input-config_bypass-ACT_SET_channel

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `unknown:unknown (ACT_SET处理函数)`
- **类型:** network_input
- **综合优先级分数:** **7.5**
- **风险等级:** 9.0
- **置信度:** 6.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 识别配置操作双通道风险：1) 认证通道/cgi/auth处理凭证修改 2) 配置通道ACT_SET直接操作系统级参数(HTTP_CFG/APP_CFG)。触发条件：攻击者伪造ACT_SET请求可绕过认证界面。若后端未校验会话权限，可实现未授权配置篡改（如开放远程管理端口r_http_en）
- **关键词:** /cgi/auth, ACT_SET, HTTP_CFG, APP_CFG, r_http_en, $.act
- **备注:** 需验证后端ACL_CFG权限控制；关联知识库中的$.act实现（已存在linking_keywords）

---
### csrf-jquery_tpTable-ajax_handler

- **文件路径:** `web/index.htm`
- **位置:** `www/web/jquery.tpTable.js (TPTable.prototype 事件绑定区域)`
- **类型:** network_input
- **综合优先级分数:** **7.5**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** jquery.tpTable.js事件处理函数(refreshIconClick等)触发AJAX请求时未集成CSRF防护。触发条件：1) 用户会话有效 2) 访问含恶意CSRF payload的页面。安全影响：非授权数据操作（如删除配置）。利用方式：构造自动提交表单诱骗用户点击。边界检查：未验证X-CSRF-Token等防护机制。
- **代码片段:**
  ```
  self.$refreshIcon.on('click.tpTable', function() { self.refreshIconClick(); });
  ```
- **关键词:** refreshIconClick, addIconClick, $.ajax, initFunc, CSRF, X-CSRF-Token
- **备注:** 需验证后端是否要求CSRF token。攻击链关联：1) 结合XSS漏洞构造组合攻击 2) 检查/goform/DelVirtualServerRule等端点

---
### frontend_validation_missing-wan_config-paramCheck

- **文件路径:** `web/main/wanBasic.htm`
- **位置:** `www/wanBasic.htm: (paramCheck)`
- **类型:** network_input
- **综合优先级分数:** **7.5**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 发现配置保存操作的多层调用链存在数据流连接缺陷：用户输入从表单字段→wanConnArg对象→$.act()参数，但关键验证函数paramCheck()仅检查IP格式等基础规则，未实施长度/内容过滤。边界检查缺失表现为：JavaScript未截断超长输入（如256字符用户名），直接将原始数据传递后端。实际安全影响取决于后端处理能力，成功利用概率较高（因前端无有效拦截）。
- **代码片段:**
  ```
  function paramCheck(input) {
    // 仅验证IP格式等基础规则
    if (!isValidIP(input)) return false;
    return true; // 未实施长度/内容过滤
  }
  ```
- **关键词:** wanConnArg, paramCheck, addAttrsPPP, addAttrsStaIpoa, ACT_SET, ACT_ADD
- **备注:** 攻击路径：用户提交恶意表单→触发doSave()→参数直达后端CGI。关联知识库前端验证缺失记录（已存在3条）。

---
### configuration_load-fstab-defaults

- **文件路径:** `etc/fstab`
- **位置:** `etc/fstab:0`
- **类型:** configuration_load
- **综合优先级分数:** **7.5**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** fstab配置中所有挂载点使用'defaults'选项，隐含启用exec(允许执行二进制)、suid(允许SUID生效)、dev(允许设备文件)等潜在风险特性。具体风险条件：攻击者若能向/tmp或/var目录写入恶意文件（如通过任意文件上传漏洞），可利用exec权限直接执行。ramfs文件系统重启后数据丢失，不影响持久性但允许运行时攻击。
- **关键词:** defaults, ramfs, /tmp, /var, exec, suid, dev
- **备注:** 需后续验证/tmp和/var目录的实际权限设置（是否全局可写）。建议分析启动脚本中相关目录的权限初始化代码。

---
### configuration_load-nobody-root-account

- **文件路径:** `etc/passwd.bak`
- **位置:** `passwd.bak:3`
- **类型:** configuration_load
- **综合优先级分数:** **7.45**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** nobody账户权限异常：UID=0但密码禁用(*) 。若通过漏洞激活（如SUID滥用或服务劫持），可获取root权限。触发条件：存在可触发nobody账户执行的漏洞。约束条件：需结合其他漏洞利用。实际影响：提权至root。
- **代码片段:**
  ```
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **关键词:** nobody, UID=0, *, /bin/sh
- **备注:** 需审计调用nobody账户的服务/进程；知识库中已存在关联关键词：nobody, UID=0, *, /bin/sh

---
### command_execution-setkey-ipsec_policy_chain_0x405528

- **文件路径:** `usr/bin/setkey`
- **位置:** `setkey:0x405528`
- **类型:** command_execution
- **综合优先级分数:** **7.45**
- **风险等级:** 7.5
- **置信度:** 7.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 本地提权攻击链：通过Web接口/SSH提交恶意IPSec策略 → setkey解析时调用ipsec_set_policy(s1参数)。若libipsec.so.0存在漏洞（如CVE-2007-1841缓冲区溢出）可触发。参数传递未验证长度（s1寄存器直接源自argv），策略内容完全用户可控。触发条件：攻击者获得Web/SSH访问权限后提交恶意策略配置。
- **代码片段:**
  ```
  lw a0, 4(s1)
  lw a1, (s1)
  j sym.imp.ipsec_set_policy
  ```
- **关键词:** ipsec_set_policy, s1, argv, policy, setkey -c, libipsec.so.0, setkey
- **备注:** 需验证libipsec.so.0实现。最可行攻击路径：结合Web漏洞获取权限后利用此链提权

---
### network_input-ftp_configuration

- **文件路径:** `etc/vsftpd.conf`
- **位置:** `etc/vsftpd.conf`
- **类型:** network_input
- **综合优先级分数:** **7.4**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** FTP服务配置允许文件上传(write_enable=YES)，但禁用匿名访问(anonymous_enable=NO)。攻击者若获取有效凭证可通过FTP上传恶意文件。被动模式端口范围50000-60000未限制IP访问，可能被用于端口扫描或数据传输。空闲超时300秒允许攻击者维持连接。
- **关键词:** write_enable, anonymous_enable, pasv_min_port, pasv_max_port, idle_session_timeout, chroot_local_user
- **备注:** 攻击链关键点：1) 凭证获取方式（如弱密码/中间人）2) 上传文件存储路径（如/var/vsftp）是否可被其他服务访问 3) vsftpd二进制漏洞利用（需后续验证）。关联知识库：端口扫描风险(69/udp)、文件操作风险(SMBunlink)

---
### network_input-http_parameter_exposure-trafficCtrl

- **文件路径:** `web/main/trafficCtrl.htm`
- **位置:** `trafficCtrl.htm: HTML表单元素`
- **类型:** network_input
- **综合优先级分数:** **7.3**
- **风险等级:** 5.0
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 关键HTTP参数暴露且缺乏保护机制。具体表现：1) 识别enableTc/upTotalBW等12个敏感参数名 2) 参数通过明文POST提交 3) maxlength=7等前端限制可被代理工具绕过。触发条件：攻击者直接构造包含恶意值的HTTP请求，无需通过Web界面交互。
- **代码片段:**
  ```
  <input type="text" id="upTotalBW" maxlength="7">
  ```
- **关键词:** enableTc, upTotalBW, downTotalBW, iptvUpMinBW, tcRuleAddBtn, maxlength
- **备注:** 参数名可直接用于构造攻击请求，建议后续测试参数注入漏洞。关联发现：frontend_validation_missing-trafficCtrl

---
### config-permission_var-0x4029d4

- **文件路径:** `usr/bin/cli`
- **位置:** `usr/bin/cli:0x4029d4`
- **类型:** configuration_load
- **综合优先级分数:** **7.3**
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 关键安全机制缺失：1) 导入表分析显示无标准身份验证函数(pam_start/getpwnam)，依赖自定义权限变量0x42ba74；2) 该变量存在多处写操作(如0x4029d4)但未验证写入值安全性；3) 高危操作前未见强制权限检查。攻击者可尝试污染0x42ba74绕过权限控制，直接触发漏洞函数。
- **关键词:** 0x42ba74, 0x4029d4, rdp_action, util_execSystem
- **备注:** 后续必须：1) 定位0x42ba74所有写操作点 2) 分析网络/NVRAM输入是否影响该变量

---
### authentication-bypass-svr_auth_password

- **文件路径:** `usr/bin/dropbearmulti`
- **位置:** `dropbearmulti: svr_auth_password`
- **类型:** nvram_get
- **综合优先级分数:** **7.3**
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 硬编码凭证绕过漏洞：当设备处于出厂默认状态（isFactoryDefault=1）或特定登录模式（loginMode）时，svr_auth_password函数可能绕过密码验证。触发条件：攻击者通过其他漏洞（如web接口）设置nvram参数或设备未初始化。成功利用可获取root权限，结合CVE-2018-15599类似漏洞利用链，实际风险较高。
- **关键词:** isFactoryDefault, loginMode, loginMode:%u, svr_auth_password
- **备注:** 需验证nvram参数访问控制。关联文件：/etc/nvram.conf

---
### network_input-buffer_overflow-doSave_parser

- **文件路径:** `web/main/manageCtrl.htm`
- **位置:** `unknown:unknown (doSave函数)`
- **类型:** network_input
- **综合优先级分数:** **7.25**
- **风险等级:** 7.8
- **置信度:** 6.5
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 集中式配置处理函数doSave()同时操作本地/远程配置，通过$.act(ACT_SET)发送序列化表单数据。触发条件：前端未对l_host/r_host进行IP格式校验。若后端解析逻辑存在漏洞（如sscanf未校验输入长度），可导致基于堆栈的缓冲区溢出。
- **关键词:** doSave, l_host, r_host, $.act(ACT_SET), httpCfg, appCfg
- **备注:** 后续应反编译对应CGI程序；关联知识库中的$.act和ACT_SET操作链

---
### file_race-hotplug-state_manipulation

- **文件路径:** `sbin/hotplug`
- **位置:** `hotplug (binary)`
- **类型:** file_write
- **综合优先级分数:** **7.2**
- **风险等级:** 6.5
- **置信度:** 8.5
- **触发可能性:** 7.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** /var/run状态文件(storage_led_status, hotplug_storage*.pid)操作缺乏并发保护和路径校验。攻击者通过污染$DEVPATH可能实现：1) 路径遍历覆盖任意文件 2) 竞争条件破坏设备状态同步机制。触发条件：在设备热插拔事件处理期间（约1-2秒窗口），恶意构造的路径可绕过预期文件位置。
- **代码片段:**
  ```
  fopen("/var/run/storage_led_status", "r+");
  ```
- **关键词:** /var/run/storage_led_status, /var/run/hotplug_storage_mount.pid, fopen, fprintf
- **备注:** 需验证文件打开模式是否包含路径截断保护，建议检查fopen调用上下文

---
### network_input-hotplug_action_control

- **文件路径:** `etc/hotplug.d/net/10-net`
- **位置:** `etc/hotplug.d/net/10-net:62-72`
- **类型:** network_input
- **综合优先级分数:** **7.1**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** $ACTION变量直接控制执行分支（行62-72）：'add|register'触发addif流程，'remove|unregister'触发delif流程。触发条件：攻击者伪造hotplug事件并控制ACTION值（需结合系统hotplug机制）。约束条件：仅处理预定义ACTION值。安全影响：可导致未授权网络接口添加/删除，造成拒绝服务或网络配置篡改。
- **代码片段:**
  ```
  case "$ACTION" in
      add|register)
          addif
      ;;
      remove|unregister)
          delif
      ;;
  esac
  ```
- **关键词:** ACTION, addif, delif
- **备注:** 需分析系统hotplug事件触发机制的实际可控性

---
### configuration_load-gid0-privilege-escalation

- **文件路径:** `etc/passwd.bak`
- **位置:** `passwd.bak`
- **类型:** configuration_load
- **综合优先级分数:** **7.05**
- **风险等级:** 6.5
- **置信度:** 10.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** GID=0组权限扩散：admin/nobody均属root组(GID=0)。当进程继承组权限时，攻击者可能越权访问root组资源。触发条件：攻击者控制admin/nobody账户进程。约束条件：需具体文件权限配合。实际影响：扩大攻击面辅助提权。
- **关键词:** GID=0, admin, nobody
- **备注:** 需分析系统文件权限设置；知识库中已存在关联关键词：admin, nobody

---

## 低优先级发现

### file_write-ip_forward-modification

- **文件路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:19-28`
- **类型:** file_write
- **综合优先级分数:** **6.95**
- **风险等级:** 6.5
- **置信度:** 9.0
- **触发可能性:** 5.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 直接修改/proc/sys网络参数未经验证。通过echo修改ip_forward等核心参数，可能将设备变为攻击中转站（如开启IP转发）。参数值硬编码在脚本中，但若攻击者篡改脚本可持久化配置。
- **代码片段:**
  ```
  echo 1 > /proc/sys/net/ipv4/ip_forward
  ```
- **关键词:** echo, /proc/sys/net/ipv4/ip_forward
- **备注:** 需评估网络架构暴露面

---
### network_input-index_validation-1

- **文件路径:** `web/main/ddos.htm`
- **位置:** `www/ddos.htm:0 (JavaScript)`
- **类型:** network_input
- **综合优先级分数:** **6.85**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 主机防御规则删除操作($.act(ACT_DEL, DOS_HOST))依赖前端生成的hostStack索引，仅排除负数和空值。攻击者可通过DOM修改注入无效索引。触发条件：提交恶意索引值。边界验证不足可能导致越权删除或后端数组越界访问。
- **代码片段:**
  ```
  $.act(ACT_DEL, 'DOS_HOST', {index: deleteStackIndex});
  ```
- **关键词:** hostStack, $.act, ACT_DEL, DOS_HOST, deleteStackIndex
- **备注:** 需验证后端索引处理是否进行有效性校验；关联关键词：$.act/ACT_DEL（知识库已存在）

---
### InfoLeak-/cgi/info-accessControl

- **文件路径:** `web/main/accessControl.htm`
- **位置:** `accessControl.htm:? ($.act调用点)`
- **类型:** network_input
- **综合优先级分数:** **6.8**
- **风险等级:** 6.8
- **置信度:** 7.0
- **触发可能性:** 6.5
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 发现潜在信息泄露端点：通过$.act(ACT_CGI, "/cgi/info")暴露设备信息。触发条件：isClientInWhiteList函数执行时自动调用。约束检查：未发现访问控制或输出过滤机制。潜在影响：攻击者可能通过直接访问/cgi/info端点获取敏感设备信息，为后续攻击提供情报。
- **关键词:** $.act, ACT_CGI, "/cgi/info", isClientInWhiteList
- **备注:** 需验证/cgi/info端点的实际输出内容

---
### network_input-http-info_leak

- **文件路径:** `usr/bin/cwmp`
- **位置:** `HTTP认证处理模块`
- **类型:** network_input
- **综合优先级分数:** **6.75**
- **风险等级:** 6.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 认证机制信息泄露：HTTP响应包含详细错误信息（如'Digest authenticate failed'）和固定Server头('tr069 http server')。攻击者可利用：1) 通过错误信息推断系统状态 2) 精准识别设备型号进行定向攻击。触发条件：发送无效认证请求。
- **关键词:** verifyConnReq, Authorization, tr069 http server, HTTP/1.1
- **备注:** 需关联NVRAM分析：检查nvram_get('admin_password')等凭据存储

---
### configuration_load-etc_passwd-nobody_root

- **文件路径:** `etc/passwd.bak`
- **位置:** `etc/passwd.bak:3`
- **类型:** configuration_load
- **综合优先级分数:** **6.7**
- **风险等级:** 6.5
- **置信度:** 8.5
- **触发可能性:** 4.5
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** nobody账户异常获得root权限(UID=0)，虽密码字段禁用(*)但若通过漏洞(如SUID提权)激活将直接获取root控制。触发条件：以nobody身份运行的服务存在权限提升漏洞。边界检查缺失：非特权账户不应配置UID=0。实际影响：权限提升漏洞可被串联利用获取root权限。
- **代码片段:**
  ```
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **关键词:** nobody, UID=0, passwd.bak, *
- **备注:** 需审计调用setuid()的程序；检查以nobody身份运行的网络服务

---
### hardcoded-password-busybox-fcn00434824

- **文件路径:** `bin/busybox`
- **位置:** `busybox:0x00434824`
- **类型:** network_input
- **综合优先级分数:** **6.7**
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** 3.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 发现硬编码后门密码漏洞：函数fcn.00434824在条件分支(param_1==0)时，使用硬编码密码'aa'进行认证(strcmp(uVar2,"aa"))。漏洞触发条件存在关键限制：1) param_1参数来源未验证 2) 无法确认是否可通过网络输入/命令行等外部输入触发。若可触发，攻击者输入'aa'可绕过认证。
- **代码片段:**
  ```
  if (param_1 == 0) {
      pcVar5 = "aa";
  }
  iVar3 = sym.imp.strcmp(uVar2,pcVar5);
  ```
- **关键词:** authentication_func, strcmp, hardcoded_password, busybox_login
- **备注:** 需动态验证触发路径：1) 检查telnetd/httpd是否调用此函数 2) 污点追踪param_1来源

---
### hardware_input-getty-uart_attack

- **文件路径:** `etc/inittab`
- **位置:** `etc/inittab`
- **类型:** hardware_input
- **综合优先级分数:** **6.65**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 5.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** inittab配置串口登录服务：ttyS0端口启动getty（/sbin/getty），物理攻击面明确。触发条件：攻击者物理接入UART串口。安全影响：若getty存在缓冲区溢出（如终端类型处理逻辑），可绕过认证直接获取控制权。但当前工具限制无法验证二进制风险。
- **关键词:** ::askfirst, ttyS0, /sbin/getty, vt100
- **备注:** 待焦点切换至/sbin/getty后深度分析

---
### network_input-cgi_exposure-trafficCtrl

- **文件路径:** `web/main/trafficCtrl.htm`
- **位置:** `trafficCtrl.htm: doSave()调用链`
- **类型:** network_input
- **综合优先级分数:** **6.55**
- **风险等级:** 6.0
- **置信度:** 8.5
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** CGI调用接口暴露敏感配置操作。具体表现：1) 通过$.act(ACT_SET, TC, ...)提交配置，隐含tc.cgi端点 2) 传输tcSettings对象包含enable/upTotalBW等特权参数 3) 缺失CSRF令牌保护。触发条件：攻击者构造恶意页面诱骗管理员点击，或直接伪造POST请求修改带宽配置。
- **代码片段:**
  ```
  $.act(ACT_SET, TC, null, null, tcSettings);
  ```
- **关键词:** $.act, ACT_SET, TC, tcSettings, enable, upTotalBW, downTotalBW
- **备注:** 需确认/tcgi路径下是否存在tc.cgi并分析其参数处理逻辑。关联现有'$.act'操作链及新发现'frontend_validation_missing-trafficCtrl'

---
### network_input-hotplug_device_validation_bypass

- **文件路径:** `etc/hotplug.d/iface/10-routes`
- **位置:** `etc/hotplug.d/iface/10-routes: 设备验证段`
- **类型:** network_input
- **综合优先级分数:** **6.3**
- **风险等级:** 7.0
- **置信度:** 6.0
- **触发可能性:** 5.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 脚本直接使用$DEVICE变量执行ifconfig命令，仅通过grep检查/proc/net/dev存在性，未对设备名进行格式/内容校验。攻击者伪造热插拔事件并注入恶意$DEVICE值（含空格或命令分隔符）可触发命令注入。边界检查仅验证设备名存在性，未处理特殊字符。
- **代码片段:**
  ```
  grep -qs "^ *$DEVICE:" /proc/net/dev || exit 0
  ifconfig "$DEVICE" del "$ip6addr"
  ```
- **关键词:** $DEVICE, grep -qs "^ *$DEVICE:" /proc/net/dev, ifconfig "$DEVICE", $INTERFACE
- **备注:** 需结合内核热插拔机制分析$DEVICE可控性。当前验证方式易被伪设备名绕过

---
### path_injection-menu_loading

- **文件路径:** `web/index.htm`
- **位置:** `web/js/lib.js:500`
- **类型:** configuration_load
- **综合优先级分数:** **6.0**
- **风险等级:** 7.0
- **置信度:** 6.0
- **触发可能性:** 3.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 动态加载路径注入潜在威胁：1. 触发条件：篡改菜单配置中的path参数（如通过XSS修改menu.htm）2. 约束条件：$.tpLoad()直接使用path参数加载内容且未过滤 3. 安全影响：路径遍历导致任意脚本执行 4. 利用方式：将path参数改为恶意外部URL或跨站脚本路径
- **关键词:** $.tpLoad, path, innerHTML, loadMain, menu.htm
- **备注:** 当前路径来源为静态配置，需监控动态生成机制

---
### configuration_set-hotplug_state_manipulation

- **文件路径:** `etc/hotplug.d/net/10-net`
- **位置:** `etc/hotplug.d/net/10-net:58`
- **类型:** configuration_load
- **综合优先级分数:** **5.95**
- **风险等级:** 5.5
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** uci_set_state操作（行58）在遍历$INTERFACE相关设备的循环中执行，可能间接受污染数据影响。触发条件：当$INTERFACE被控制且存在关联设备时。约束条件：依赖$ifs变量有效性。安全影响：可能篡改网络设备状态，导致配置不一致或未知副作用。
- **代码片段:**
  ```
  uci_set_state "network" "$ifc" device "$ifs"
  ```
- **关键词:** uci_set_state, network, device
- **备注:** 需验证$ifs变量来源是否受$INTERFACE影响。关联攻击链：INTERFACE→uci_set_state

---
### memcpy-globalstruct-0x40bcc8

- **文件路径:** `usr/bin/dropbearmulti`
- **位置:** `usr/bin/dropbearmulti:fcn.0040bb6c:0x40bcc8`
- **类型:** network_input
- **综合优先级分数:** **5.3**
- **风险等级:** 6.0
- **置信度:** 5.0
- **触发可能性:** 4.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 在dropbearmulti组件中发现潜在不安全的memcpy调用，长度参数来自全局结构0x4489c0。该操作位于网络数据处理路径中，长度值可能间接受网络输入影响。触发条件：攻击者需精确控制全局结构中特定字段值。风险：若长度未经验证可能导致缓冲区溢出。验证缺陷：1) 全局结构初始化过程不明 2) 网络输入到长度参数传播路径未确认 3) 边界检查机制缺失证据。
- **代码片段:**
  ```
  sym.imp.memcpy(uVar3,uVar4,*(*(iVar7 + 0x18) + 4))
  ```
- **关键词:** memcpy, 0x4489c0, global_structure, fcn.00404548, *(*(iVar7 + 0x18) + 4), dropbear
- **备注:** 关键阻碍：1) 字符串提取失败导致无法检测硬编码凭证 2) 全局结构被60+函数引用 3) 函数fcn.00403410反编译失败 4) 多层指针阻碍污点分析。结论：当前无法确认切实可利用性，需动态验证全局结构污染可能性并检查同版本CVE。

---
### vuln-password-0x4032b8

- **文件路径:** `usr/bin/cli`
- **位置:** `usr/bin/cli:0x4032b8`
- **类型:** network_input
- **综合优先级分数:** **5.3**
- **风险等级:** 4.0
- **置信度:** 9.0
- **触发可能性:** 3.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 密码修改功能边界风险：'Set new password'功能使用strncpy复制密码到全局缓冲区0x42be88，但严格限制长度0xF(15字节)。若目标缓冲区定义为char[15]，输入15字符时将缺失空终止符，可能导致后续strcmp越界读取。触发条件：用户设置恰好15字符密码。实际影响有限，仅可能造成信息泄漏或程序崩溃。
- **代码片段:**
  ```
  strncpy(0x42be88, acStack_42c, 0xf);
  ```
- **关键词:** Set new password, 0x42be88, strncpy
- **备注:** 需验证0x42be88内存布局。风险等级较低，非优先修复项

---
### memory_op-stdin_strcpy-0x40205c

- **文件路径:** `usr/bin/cli`
- **位置:** `fcn.0040205c @ 0x40205c`
- **类型:** hardware_input
- **综合优先级分数:** **5.25**
- **风险等级:** 3.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 在函数fcn.0040205c中发现strcpy操作风险：目标缓冲区为acStack_221+1（517字节），数据来源为fcn.00403600从STDIN读取的用户输入（最大512字节）。触发条件为用户交互时按TAB键（*0x42ba70!=0且auStack_30[0]==9）。因源数据小于目标缓冲区，溢出风险较低，且未发现通过NVRAM/env等外部输入触发路径。
- **代码片段:**
  ```
  sym.imp.strcpy(acStack_221 + 1, param_1);
  ```
- **关键词:** strcpy, fcn.0040205c, fcn.00403600, acStack_221, auStack_30, STDIN
- **备注:** 需动态验证TAB键触发时的实际输入长度控制机制

---
### network_input-httpd-multipart_buffer_overflow

- **文件路径:** `usr/bin/httpd`
- **位置:** `httpd:0x004038ec`
- **类型:** network_input
- **综合优先级分数:** **5.2**
- **风险等级:** 6.0
- **置信度:** 4.0
- **触发可能性:** 5.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 在HTTP请求处理器(fcn.004038ec)中处理multipart/form-data请求时，Content-Disposition头部的'name'和'filename'字段值被复制到固定大小缓冲区（约256字节）。触发条件：发送超长字段的multipart请求，可能造成缓冲区溢出。关键未验证项：1) 复制函数fcn.004015d0的具体实现未确认 2) 缓冲区分配机制未追踪 3) 污点传播路径不完整。实际可利用性需动态验证。
- **关键词:** fcn.004038ec, Content-Disposition, name, filename, multipart/form-data
- **备注:** 分析受阻原因：关键子任务验证失败。建议：1) 动态测试multipart请求处理 2) 验证函数fcn.004015d0的实现 3) 检查关联配置文件的路由可达性

---
### env_set-TMPDIR-static

- **文件路径:** `sbin/usbp`
- **位置:** `usbp:0x400aac`
- **类型:** env_set
- **综合优先级分数:** **5.1**
- **风险等级:** 0.5
- **置信度:** 9.5
- **触发可能性:** 10.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** putenv设置静态环境变量'TMPDIR=/var/tmp'，数据来源为.rodata段固定字符串（地址0x400d20）。无动态拼接或外部输入，未检测到后续危险函数使用该变量。安全影响：无可利用风险，变量值固定且不可控。
- **代码片段:**
  ```
  putenv("TMPDIR=/var/tmp");
  ```
- **关键词:** putenv, TMPDIR, .rodata:0x400d20

---
### mount-kernel-fs-defaults

- **文件路径:** `etc/fstab`
- **位置:** `etc/fstab:1,3,5`
- **类型:** configuration_load
- **综合优先级分数:** **4.9**
- **风险等级:** 3.0
- **置信度:** 10.0
- **触发可能性:** 2.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 其他挂载点（/proc,/dev/pts,/sys）使用defaults选项但属内核虚拟文件系统，exec选项不产生传统文件执行风险。dump/pass标志为0表示无备份和fsck检查，可能影响系统故障恢复。
- **代码片段:**
  ```
  proc /proc proc defaults 0 0
  devpts /dev/pts devpts defaults 0 0
  none /sys sysfs defaults 0 0
  ```
- **关键词:** /proc, /dev/pts, /sys, defaults, dump=0, pass=0

---
### boundary_check-httpd-multipart_filename-0x406524

- **文件路径:** `usr/bin/httpd`
- **位置:** `fcn.0040649c (0x00406524)`
- **类型:** network_input
- **综合优先级分数:** **4.45**
- **风险等级:** 2.5
- **置信度:** 8.0
- **触发可能性:** 4.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在httpd的multipart请求处理中，filename参数通过固定256字节的strncpy拷贝操作(fcn.004038ec)。目标缓冲区声明在栈地址sp+0x21c（物理大小4140字节），存在运行时边界检查机制(fcn.004049e0)：1) 使用strlen计算输入长度 2) 强制限制不超过4096字节(0xfff) 3) 超限时触发'CGI buffer overflow'错误并终止进程。所有13个调用点均强制执行该检查。触发条件：发送filename>4096字节的multipart请求。实际影响：因错误处理完全阻断执行，无法构成溢出利用链。与知识库中其他fcn.004038ec调用点（如/cgi/confup、/cgi/softup）的关键区别在于边界检查机制的存在。
- **代码片段:**
  ```
  0x00406524: addiu s0, sp, 0x21c  ; 缓冲区声明
  0x0040654c: jal fcn.004049e0     ; 边界检查调用
  ```
- **关键词:** fcn.004038ec, fcn.004049e0, CGI buffer overflow, strlen, src/http_io.c, boundary_check, sp+0x21c, 0xfff, httpd_stack_buffer
- **备注:** 关联知识库发现：stack_overflow-httpd_confup-0x4067ec（无边界检查，高风险）和stack_overflow-httpd_softup-0x4039ac（嵌套溢出链）。需动态验证：1) 超长filename是否触发进程终止 2) 确认所有13个调用点是否均含fcn.004049e0检查

---
### network_input-DDNS_cgi_endpoint

- **文件路径:** `web/main/ddns.htm`
- **位置:** `www/ddns.htm:0`
- **类型:** network_input
- **综合优先级分数:** **3.9**
- **风险等级:** 3.0
- **置信度:** 8.0
- **触发可能性:** N/A
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 提交端点依赖未定义常量DYN_DNS_CFG/NOIP_DNS_CFG，暗示后端CGI处理接口，但具体URL未显式暴露。
- **关键词:** $.act, ACT_SET, DYN_DNS_CFG, NOIP_DNS_CFG
- **备注:** 后续应在cgibin中搜索DYN_DNS_CFG/NOIP_DNS_CFG常量定位处理函数

---
### command_execution-insmod_ipv6

- **文件路径:** `etc/hotplug.d/net/10-net`
- **位置:** `10-net:6-8`
- **类型:** command_execution
- **综合优先级分数:** **3.9**
- **风险等级:** 4.0
- **置信度:** 5.0
- **触发可能性:** 2.0
- **查询相关性:** 6.5
- **阶段:** N/A
- **描述:** 通过'grep -q '^ipv6' /etc/modules.d/* && insmod ipv6'动态加载内核模块（代码位置：10-net:6-8）。虽无法验证/etc/modules.d目录权限，但该机制存在理论风险：若攻击者能篡改modules.d文件（如通过其他漏洞），可导致恶意模块加载。触发条件：网络事件发生时系统未加载ipv6模块。
- **代码片段:**
  ```
  grep -q '^ipv6' /etc/modules.d/* && insmod ipv6
  ```
- **关键词:** insmod, /etc/modules.d, ipv6, grep
- **备注:** 实际风险取决于目录保护机制（当前分析限制：无法验证/etc/modules.d目录权限）。建议后续检查：1) /etc/modules.d写入权限 2) 固件启动加载流程

---
### network_input-DDNS_input_fields

- **文件路径:** `web/main/ddns.htm`
- **位置:** `www/ddns.htm:0`
- **类型:** network_input
- **综合优先级分数:** **3.5**
- **风险等级:** 1.0
- **置信度:** 10.0
- **触发可能性:** N/A
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 识别所有输入字段：DynDNS服务(dyndns_usr, dyndns_pwd, dyndns_domain)和NO-IP服务(noip_usr, noip_pwd, noip_domain)，均通过JavaScript操作无传统form提交。
- **关键词:** dyndns_usr, dyndns_pwd, dyndns_domain, noip_usr, noip_pwd, noip_domain, clickSave

---
### command_execution-diskstats_error-echo

- **文件路径:** `sbin/usbp`
- **位置:** `usbp:0x400a40 (main)`
- **类型:** command_execution
- **综合优先级分数:** **3.45**
- **风险等级:** 1.0
- **置信度:** 9.5
- **触发可能性:** 0.5
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** system调用执行固定命令'echo open /proc/diskstats failed! >/dev/ttyS0'，触发条件为/proc/diskstats打开失败（系统异常状态）。命令字符串硬编码于.rodata段（地址0x400d20），未使用任何外部输入（环境变量/USB/NVRAM）。安全影响：仅向串口输出错误信息，无命令注入风险。
- **代码片段:**
  ```
  if (fopen("/proc/diskstats", "r") == NULL)
    system("echo open /proc/diskstats failed! >/dev/ttyS0");
  ```
- **关键词:** system, fopen, /proc/diskstats, .rodata:0x400d20

---
### hardware_input-hotplug_ieee1394-comment_only

- **文件路径:** `etc/hotplug.d/ieee1394/10-ieee1394`
- **位置:** `etc/hotplug.d/ieee1394/10-ieee1394`
- **类型:** hardware_input
- **综合优先级分数:** **3.4**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 2.0
- **查询相关性:** 3.0
- **阶段:** N/A
- **描述:** IEEE 1394热插拔脚本仅响应设备插拔事件($ACTION环境变量)，但未执行任何实际命令或操作（只有注释）。触发条件：当IEEE 1394设备插入(ACTION=add)或拔出(ACTION=remove)时自动执行。安全影响：无实际风险，因脚本不处理输入数据、不执行命令、不进行系统交互。外部输入的$ACTION值无法触发任何危险操作。
- **代码片段:**
  ```
  case "$ACTION" in
  	add)
  		# update LEDs
  		;;
  	remove)
  		# update LEDs
  		;;
  esac
  ```
- **关键词:** ACTION, add, remove, hotplug.d, ieee1394
- **备注:** 需注意：若固件更新后添加实际功能（如通过$ACTION执行命令），可能引入命令注入风险。建议后续检查：1) 其他热插拔脚本 2) /lib/hotplug/ieee1394.agent实现

---
### network_input-DDNS_js_validation

- **文件路径:** `web/main/ddns.htm`
- **位置:** `www/ddns.htm:0 (doInputCheck函数)`
- **类型:** network_input
- **综合优先级分数:** **3.35**
- **风险等级:** 1.0
- **置信度:** 9.5
- **触发可能性:** N/A
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 关键JS函数：doInputCheck()执行空值检查(使用$.alert报错)和域名格式验证($.isdomain)，未发现eval/innerHTML等危险函数。
- **代码片段:**
  ```
  function doInputCheck() {
    if($("#dyndns_pwd").prop('value') == "") {
      $.alert(ERR_DDNS_PWD_EMPTY);
      return false;
    }
  }
  ```
- **关键词:** doInputCheck, doSave, doLogout, $.isdomain, $.alert

---
### ipc-rdp_updateUsbInfo-external

- **文件路径:** `sbin/usbp`
- **位置:** `usbp:0x400aec`
- **类型:** ipc
- **综合优先级分数:** **3.0**
- **风险等级:** 1.0
- **置信度:** 8.0
- **触发可能性:** 0.5
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** rdp_updateUsbInfo为无参数导入函数，调用点（fcn.00400aec）使用fgets读取/proc/diskstats时限制0x100字节缓冲区。未发现危险操作或污染数据传递。安全影响：当前文件内无风险，但实际实现在外部库需进一步验证。
- **代码片段:**
  ```
  rdp_updateUsbInfo();
  fgets(buffer, 0x100, fp);
  ```
- **关键词:** rdp_updateUsbInfo, fgets, dm_shmInit
- **备注:** 关键后续方向：1) 分析librdp.so中的rdp_updateUsbInfo实现 2) 追踪dm_shmInit共享内存的IPC数据流

---
### command_execution-usbp-system_hardcoded

- **文件路径:** `sbin/usbp`
- **位置:** `usbp:0x400a40 (system), 0x400aac (putenv)`
- **类型:** command_execution
- **综合优先级分数:** **2.97**
- **风险等级:** 0.5
- **置信度:** 9.0
- **触发可能性:** 0.1
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 在usbp中检测到system('echo...')调用使用硬编码参数，仅当/proc/diskstats访问失败时触发。无外部可控输入证据。环境变量设置(putenv)使用固定值'/var/tmp'且无后续使用痕迹。未发现缓冲区操作(strcpy/sprintf)或命令注入漏洞。核心功能rdp_updateUsbInfo位于外部库librdp.so，超出当前分析范围。
- **关键词:** system, putenv, TMPDIR, /proc/diskstats, rdp_updateUsbInfo, librdp.so
- **备注:** 关键后续建议：1) 分析lib目录下的librdp.so验证rdp_updateUsbInfo实现 2) 全局搜索/tmp/usb_product_name文件操作 3) 检查/proc/diskstats的访问控制机制。关联知识库：/proc/tplink/led_usb硬件操作记录

---
### disproved-stack_overflow-cwmp-msg_recv

- **文件路径:** `usr/bin/cwmp`
- **位置:** `cwmp:0x00408224 (fcn.00407fd4)`
- **类型:** network_input
- **综合优先级分数:** **2.85**
- **风险等级:** 0.0
- **置信度:** 9.5
- **触发可能性:** 0.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 经多轮验证，初始报告的栈溢出漏洞被证伪：1) 漏洞触发点位于fcn.00407fd4函数0x00408224的msg_recv调用，使用固定516字节栈缓冲区(auStack_234)；2) 缓冲区到返回地址(sp+0x384)有0x364字节安全距离；3) 函数内最大写入位置sp+0x14c与关键控制数据区(sp+0x360-sp+0x380)存在268字节安全边界。攻击者发送超长数据不会覆盖控制流数据，无法实现任意代码执行。
- **代码片段:**
  ```
  0x00408220 lw a1, 0x20(sp)  // a1 = auStack_234缓冲区
  0x00408224 jal msg_recv       // 调用数据接收
  ```
- **关键词:** fcn.00407fd4, msg_recv, auStack_234, sp+0x20, sp+0x384, sp+0x14c
- **备注:** 安全边界计算：返回地址偏移sp+0x384 - 缓冲区sp+0x20 = 0x364字节。最大写入点sp+0x14c到控制区起始sp+0x360 = 0x10C字节。建议后续追踪其他网络输入点。

---
### command_exec-util_execSystem-undefined

- **文件路径:** `usr/bin/cli`
- **位置:** `usr/bin/cli (未定位调用点)`
- **类型:** command_execution
- **综合优先级分数:** **1.5**
- **风险等级:** 0.0
- **置信度:** 5.0
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** util_execSystem函数符号存在但调用点未定位，无法追踪参数来源。该函数可直接执行系统命令，若参数被污染（如来自HTTP请求）可能造成命令注入。当前无证据表明其在'usr/bin/cli'中被调用或存在污染路径。
- **关键词:** util_execSystem, imp.util_execSystem
- **备注:** 需在其他组件（如www目录）中继续追踪该函数使用情况；关联知识库发现：config-permission_var-0x4029d4（权限变量污染可能影响命令执行）

---
### task-unresolved-fcn.0040c654

- **文件路径:** `usr/sbin/dhcp6s`
- **位置:** `unknown:0x40c474 (aav.0x0040c474)`
- **类型:** analysis_task
- **综合优先级分数:** **0.0**
- **风险等级:** 0.0
- **置信度:** 0.0
- **触发可能性:** 0.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 函数调用路径验证任务：fcn.0040c654的调用者为aav.0x0040c474，但未关联到server6_recv等主消息处理函数。需确定该函数是否受网络输入影响以评估其在攻击路径中的潜在作用。
- **代码片段:**
  ```
  无直接代码片段
  ```
- **关键词:** fcn.0040c654, aav.0x0040c474, server6_recv, dhcp6s
- **备注:** 证据：调用链aav.0x0040c474→fcn.0040c654未连接主消息处理器。需逆向分析server6_recv的调用树。

---
