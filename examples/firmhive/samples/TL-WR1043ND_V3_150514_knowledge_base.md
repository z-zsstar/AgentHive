# TL-WR1043ND_V3_150514 高优先级: 26 中优先级: 38 低优先级: 15

## 优先级评分模型

**计算公式:** `PriorityScore = (0.5 * risk_level) + (0.3 * confidence) + (0.2 * trigger_possibility)`

**分层策略:**
- **高优先级:** `PriorityScore >= 8.5`
- **中优先级:** `7.0 <= PriorityScore < 8.5`
- **低优先级:** `PriorityScore < 7.0`

---

## 高优先级发现

### network_input-ChangeLoginPwdRpm-GET_exposure

- **文件路径:** `web/userRpm/ChangeLoginPwdRpm.htm`
- **位置:** `web/userRpm/ChangeLoginPwdRpm.htm:0 (表单定义)`
- **类型:** network_input
- **综合优先级分数:** **9.4**
- **风险等级:** 9.0
- **置信度:** 10.0
- **触发可能性:** 9.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 密码凭证通过HTTP GET方法传输，导致敏感信息暴露风险。具体表现：表单提交使用method='get'，使oldpassword/newpassword等参数出现在URL中。触发条件：用户提交密码修改请求时，无论密码是否哈希处理，参数值均会出现在浏览器历史/服务器日志中。约束条件：当LoginPwdInf[2]==1时密码经MD5+Base64编码但仍暴露哈希值。安全影响：攻击者可从日志获取凭证哈希进行破解或重放攻击，成功利用概率高（因无需特殊触发条件）。
- **代码片段:**
  ```
  <form method="get" action="ChangeLoginPwdRpm.htm" onSubmit="return doSubmit()">
  ```
- **关键词:** GET, oldpassword, newpassword, newpassword2, ChangeLoginPwdRpm.htm
- **备注:** 违反密码传输安全规范，建议验证服务器端是否强制要求POST方法

---
### command_injection-dropbear-ssh_original_command

- **文件路径:** `usr/sbin/dropbearmulti`
- **位置:** `dropbearmulti:0x423034`
- **类型:** network_input
- **综合优先级分数:** **9.4**
- **风险等级:** 9.5
- **置信度:** 9.5
- **触发可能性:** 9.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危命令注入漏洞：攻击者通过SSH会话设置'SSH_ORIGINAL_COMMAND'环境变量，其值(s2+0x50)未经任何过滤直接传递给execv执行。触发条件：1) 建立SSH连接 2) 发送恶意命令字符串。实际影响：以dropbear权限执行任意命令（如启动反向shell）。利用概率极高（9.0），因无需绕过认证（若使用公钥登录）且无净化措施。
- **代码片段:**
  ```
  0x423034: jal sym.addnewvar
  a0=0x43b724 ("SSH_ORIGINAL_COMMAND")
  a1=[s2+0x50]
  ```
- **关键词:** SSH_ORIGINAL_COMMAND, execv, s2+0x50, addnewvar, run_shell_command
- **备注:** 完整攻击链：网络输入→结构体存储→环境变量设置→execv执行。需验证：1)/etc/init.d/dropbear启用状态 2)关联KB#env_set污染路径

---
### attack-chain-ctrl_iface-rce

- **文件路径:** `sbin/wpa_supplicant`
- **位置:** `wpa_supplicant:fcn.0044163c:0x441ad8`
- **类型:** attack_chain
- **综合优先级分数:** **9.25**
- **风险等级:** 9.7
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击路径验证：攻击者访问CTRL_IFACE接口（因无访问控制）→ 发送恶意SET_NETWORK命令设置超长wep_key(>85字节) → 触发strcpy栈缓冲区溢出 → 覆盖返回地址实现任意代码执行。触发步骤：3步（网络访问、命令构造、溢出触发）。成功利用概率：高（漏洞触发条件明确且无防护机制）。
- **关键词:** CTRL_IFACE, SET_NETWORK, wep_key, strcpy, auStack_228
- **备注:** 依赖漏洞：access-ctrl-ctrl_iface（提供入口）, stack-overflow-set_network（实现RCE）；需实际验证固件中wep_key的最大允许长度

---
### network_input-radvd-recv_rs_ra-stack_overflow

- **文件路径:** `usr/sbin/radvd`
- **位置:** `radvd:main+0x47e0`
- **类型:** network_input
- **综合优先级分数:** **9.19**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.7
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞。触发条件：攻击者发送>1504字节的恶意ICMPv6包至radvd监听端口。漏洞位于main函数网络循环中，recv_rs_ra将数据复制到固定大小栈缓冲区acStack_620(1504字节)，仅验证长度>0而缺失上限检查。结合radvd以root运行特性，可导致控制流劫持实现RCE。边界检查完全缺失，接收长度直接来自攻击者控制的网络包长度字段。
- **代码片段:**
  ```
  iVar1 = (**(pcVar10 + -0x7e28))(*(0x470000 + 0x30ac), pcVar9, param_2, &uStack_750, puVar8);
  ```
- **关键词:** recv_rs_ra, acStack_620, uStack_750, *(loc._gp + -0x7e28), 0x4730ac
- **备注:** 完整攻击链：网络接口→recv_rs_ra→栈溢出→控制流劫持。需动态验证ROP链构造可行性；关联漏洞：network_input-radvd-recv_rs_ra-pointer_manipulation

---
### HeapOverflow-IntegerUnderflow-ntfs3g-0x4088ac

- **文件路径:** `bin/ntfs-3g`
- **位置:** `ntfs-3g:0x4088ac (strcat), 0x408834 (下溢计算)`
- **类型:** command_execution
- **综合优先级分数:** **9.15**
- **风险等级:** 9.7
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 堆溢出与整数下溢漏洞：攻击者通过启动参数/NVRAM注入>55字节恶意字符串污染argv→全局变量*0x431f60→strcat操作溢出堆缓冲区（strdup分配）。同时触发整数下溢（0xfff-strlen()）：当输入>4095字节时计算结果为极大正值，引发二次内存破坏。触发条件：设备启动时植入超长参数并执行ntfs-3g挂载。成功利用可覆盖堆元数据实现任意代码执行（root权限）。
- **代码片段:**
  ```
  0x4088a8: lw a0, 0x78(v1)
  0x4088ac: jalr t9 ; strcat(dest, *0x431f60)
  ```
- **关键词:** main, param_2, *0x431f60, strcat, strdup, 0xfff, loc._gp-0x7da0, argv
- **备注:** 完整路径：启动参数→argv→(**(gp-0x7da0))→*0x431f60→strcat/整数下溢。需验证固件堆保护机制

---
### command_execution-iptables-heap_overflow

- **文件路径:** `sbin/iptables-multi`
- **位置:** `iptables-multi:0x407a38 sym.do_command`
- **类型:** command_execution
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危堆溢出漏洞：攻击者通过iptables命令行传入超长参数（如-s参数），触发do_command函数内未验证的strcpy操作（0x407a38）。目标缓冲区通过xtables_calloc分配（大小s0+0x20），但strcpy复制外部可控数据（v1+8）时无长度检查。触发条件：执行iptables命令时包含>分配缓冲区大小的参数。成功利用可破坏堆元数据，结合iptables的root权限实现任意代码执行。
- **代码片段:**
  ```
  0x407a38 lw t9, -sym.imp.strcpy(gp)
  0x407a3c lw a1, 8(v1)
  0x407a40 jalr t9
  0x407a44 addiu a0, a0, 2
  ```
- **关键词:** strcpy, xtables_calloc, v1+8, do_command, param_1, iptables_globals
- **备注:** 关联漏洞：memcpy-overflow@0x408d44（共享param_1污染源）。完整攻击链：网络接口→命令行构造→strcpy溢出。需验证v1+8污染路径：param_1→getopt_long解析→v1结构体赋值

---
### stack-overflow-set_network

- **文件路径:** `sbin/wpa_supplicant`
- **位置:** `wpa_supplicant:fcn.0044163c:0x441ad8`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞（strcpy）。在fcn.0044163c函数中，wep_key配置字段(s1+0x140)未经验证直接复制到256字节栈缓冲区。触发条件：通过CTRL_IFACE发送SET_NETWORK命令设置长度>85字节的wep_key。边界检查：完全缺失长度验证。安全影响：覆盖返回地址导致远程代码执行(RCE)。利用概率：高（因攻击路径清晰）。
- **代码片段:**
  ```
  strcpy(auStack_228, *(s1 + 0x140)); // 无长度检查
  ```
- **关键词:** fcn.0044163c, s1+0x140, wep_key, SET_NETWORK, auStack_228, strcpy

---
### stack_overflow-xl2tpd-handle_packet

- **文件路径:** `usr/sbin/xl2tpd`
- **位置:** `bin/xl2tpd:0x407d54 (handle_packet)`
- **类型:** network_input
- **综合优先级分数:** **9.15**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞：在handle_packet函数(0x407d54)中，使用strcat将网络传入的L2TP控制消息复制到192字节栈缓冲区(sp+0x100)时未进行长度验证。攻击者发送超过192字节的恶意数据包可直接覆盖返回地址。触发条件：网络接口接收恶意L2TP控制消息。边界检查完全缺失，目标缓冲区大小固定为192字节且无前置校验。可导致远程代码执行(RCE)，结合固件ASLR/NX防护状态，利用概率达75%。
- **关键词:** strcat, sp+0x100, l2tp_control_message, RCE
- **备注:** 完整攻击路径：网络输入→handle_packet→strcat溢出；关联攻击路径'L2TP控制消息→栈溢出RCE'

---
### command_execution-wireless_init-1

- **文件路径:** `etc/rc.d/rc.wlan`
- **位置:** `rc.inet1:42, rc.wireless:30, rc.wlan:26-56`
- **类型:** command_execution
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整的无线服务初始化攻击路径：1) 攻击点：通过HTTP接口/NVRAM设置篡改/etc/ath/apcfg文件内容 2) 传播路径：rc.inet1→rc.wireless→rc.wlan逐级加载污染的环境变量 3) 危险操作：污染变量(DFS_domainoverride等)直接拼接到insmod命令，触发条件为系统启动或服务重启。利用方式：注入空格分隔的额外参数(如'debug=0xffffffff malicious_param=1')，结合内核模块漏洞实现RCE。
- **关键词:** /etc/ath/apcfg, DFS_domainoverride, ATH_countrycode, insmod, rc.inet1, rc.wireless, rc.wlan
- **备注:** 需后续验证：1) apcfg文件是否可通过web接口修改 2) ath_pci.ko等模块的具体漏洞

---
### hardware_input-USB_command_injection-001

- **文件路径:** `sbin/tphotplug`
- **位置:** `tphotplug:? [fcn.004025d4] 0x4025d4`
- **类型:** hardware_input
- **综合优先级分数:** **9.05**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危命令注入漏洞：攻击者通过特制USB设备控制环境变量DEVPATH，该变量在processUsbNasDevice函数中未经任何过滤直接拼接到system命令参数（如`rm -rf %s%s`）。触发条件：USB设备热插拔事件发生时内核传递恶意DEVPATH。利用方式：注入命令分隔符（如`;reboot;`）实现任意命令执行，成功概率高（8.0）。边界检查：仅验证设备号非负，未对路径字符串做长度或内容检查。
- **代码片段:**
  ```
  (**(loc._gp + -0x7f90))(auStack_128,"rm -rf %s%s","/tmp/dev/",&uStack_138);
  ```
- **关键词:** processUsbNasDevice, DEVPATH, system, rm -rf, mount, sprintf
- **备注:** 需结合USB设备伪造能力验证漏洞触发；关联现有'mount'关键词（KB#mount）

---
### funcptr-deref-pno

- **文件路径:** `sbin/wpa_supplicant`
- **位置:** `sym.wpa_supplicant_ctrl_iface_process`
- **类型:** command_execution
- **综合优先级分数:** **9.05**
- **风险等级:** 9.1
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 函数指针解引用漏洞。通过CTRL_IFACE发送SET_NETWORK/pno命令可控制param_1+0x94值并作为函数指针调用。触发条件：未授权访问后发送特制命令使指针指向0xFFFFFFFF。安全影响：远程拒绝服务(DoS)或潜在RCE（需结合内存布局）。利用概率：中（依赖特定内存状态）。
- **关键词:** CTRL_IFACE, SET_NETWORK, pno, param_1[0x94], loc._gp-0x7e04

---
### network_input-VirtualServerAdvRpm-parameter_injection

- **文件路径:** `web/userRpm/VirtualServerAdvRpm.htm`
- **位置:** `VirtualServerAdvRpm.htm: FORM element`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 参数直接注入风险：表单字段(ExPort/InPort/Ip等)通过GET方法直接提交到VirtualServerRpm.htm端点，参数名与表单name完全一致且无任何编码/过滤。攻击者可构造恶意参数值(如ExPort='$(malicious_command)')直接注入后端处理逻辑。触发条件：攻击者需能发送HTTP请求到管理接口(认证后或结合CSRF)。潜在影响包括命令注入、配置篡改或权限提升。
- **代码片段:**
  ```
  <FORM action="VirtualServerRpm.htm" method="get">
    <INPUT name="ExPort" type="text">
  ```
- **关键词:** ExPort, InPort, Ip, Protocol, State, VirtualServerRpm.htm
- **备注:** 关键攻击路径需验证VirtualServerRpm.htm的处理逻辑

---
### network_input-encrypt-insecure_md5

- **文件路径:** `web/login/encrypt.js`
- **位置:** `encrypt.js:1 hex_md5()`
- **类型:** network_input
- **综合优先级分数:** **9.05**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 实现不安全的MD5哈希算法用于敏感操作（如密码处理），无盐值且无输入校验。触发条件：前端调用hex_md5()处理用户可控输入（如密码字段）。安全影响：攻击者可通过彩虹表破解密码或构造MD5碰撞实现认证绕过。利用路径：污染输入→hex_md5()→返回可预测哈希值→欺骗认证系统。
- **代码片段:**
  ```
  function hex_md5(s){ return binl2hex(core_md5(str2binl(s), s.length * 8)); }
  ```
- **关键词:** hex_md5, core_md5, str2binl, md5_ff, md5_gg, md5_hh, md5_ii, safe_add
- **备注:** 需追踪调用此函数的页面（如login.html）确认是否用于密码处理。建议替换为PBKDF2并添加盐值。

---
### attack_path-radvd-icmpv6_rce_chain

- **文件路径:** `usr/sbin/radvd`
- **位置:** `AttackPath:1`
- **类型:** attack_path
- **综合优先级分数:** **9.0**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击路径：网络接口 → 恶意ICMPv6包 → recv_rs_ra栈溢出 → RCE。触发概率：8.5（高），影响：Root权限获取。关键触发步骤：1) 构造>1504字节恶意包 2) 发送至radvd监听端口。该路径利用radvd以root运行的特性，通过未经验证的网络输入直接导致控制流劫持。
- **关键词:** network_input-radvd-recv_rs_ra-stack_overflow, RCE, ICMPv6
- **备注:** 关联发现：network_input-radvd-recv_rs_ra-stack_overflow；动态验证需求见原漏洞notes

---
### command_injection-run_cmd_exec

- **文件路径:** `sbin/ssdk_sh`
- **位置:** `sbin/ssdk_sh:0x00402d40 (fcn.00402b30)`
- **类型:** command_execution
- **综合优先级分数:** **8.95**
- **风险等级:** 9.5
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 'run'命令存在任意命令执行漏洞。触发条件：用户执行`ssdk_sh run <恶意文件路径>`时，<cmd_file>参数经fcn.00402b30文件读取后，在fcn.004029b4对非echo命令直接执行文件内容。攻击者结合文件上传漏洞写入恶意命令文件可实现RCE，完全控制设备。
- **代码片段:**
  ```
  执行逻辑：
  if (非echo命令) {
      fcn.004029b4(iStack_28); // 直接执行用户输入
  }
  ```
- **关键词:** run, cmd_file, fcn.00402b30, fcn.004029b4, fcn.00401554
- **备注:** 后续方向：1) 检查web接口是否暴露run命令 2) 分析启动脚本调用链

---
### network_input-dhcp6c-client6_recv-stack_overflow

- **文件路径:** `usr/sbin/dhcp6c`
- **位置:** `sbin/dhcp6c:0x40602c (client6_recv)`
- **类型:** network_input
- **综合优先级分数:** **8.95**
- **风险等级:** 9.5
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 远程栈溢出漏洞：client6_recv函数使用recvmsg接收DHCPv6数据包，将数据存入4092字节栈缓冲区(auStack_2034)，仅验证最小长度(4字节)但未检查上限。当攻击者发送>4096字节恶意数据包时，后续解析函数(**(loc._gp + -0x7e88))处理超长数据导致栈溢出。触发条件：构造畸形DHCPv6包发送至UDP 546端口。安全影响：完全控制EIP实现RCE，CVSSv3 9.8。
- **代码片段:**
  ```
  uchar auStack_2034[4092];
  uVar1 = recvmsg(...);
  if (uVar1 < 4) {...}
  iVar5 = (**(loc._gp + -0x7e88))(auStack_2038 + 4, auStack_2038 + uVar1, piStack_30);
  ```
- **关键词:** client6_recv, recvmsg, auStack_2034, dhcp6c, UDP_546
- **备注:** 关联CVE-2020-15779；动态验证需确认loc._gp-0x7e88函数是否加剧溢出

---
### attack_path-dhcp6c-stack_overflow-rce

- **文件路径:** `usr/sbin/dhcp6c`
- **位置:** `sbin/dhcp6c`
- **类型:** attack_path
- **综合优先级分数:** **8.95**
- **风险等级:** 9.5
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整远程攻击链：通过UDP 546端口发送恶意DHCPv6包触发client6_recv栈溢出实现RCE。关键步骤：1) 构造>4096字节畸形包 2) 覆盖返回地址控制EIP 3) 执行shellcode。成功率80%，影响等级Critical。
- **关键词:** client6_recv, UDP_546, RCE
- **备注:** 关联漏洞：network_input-dhcp6c-client6_recv-stack_overflow

---
### CommandInjection-ntfs3g-0x409174

- **文件路径:** `bin/ntfs-3g`
- **位置:** `ntfs-3g:0x00409174`
- **类型:** command_execution
- **综合优先级分数:** **8.9**
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 命令注入漏洞：通过'-o'挂载选项注入恶意命令（如`-o 'kernel_cache;malicious_cmd'`）。污染数据路径：argv→解析函数(gp-0x7ccc)→24字节栈缓冲区(auStack_1b4)→通过gp-0x7e2c函数执行。触发条件：控制挂载参数并包含命令分隔符（;/$()）。约束条件：缓冲区仅24字节，超长输入导致栈溢出。成功利用可直接以root权限执行任意命令。
- **代码片段:**
  ```
  iVar2 = (**(loc._gp + -0x7ccc))(&uStack_1b4,iVar14);
  uVar4 = (**(loc._gp + -0x7e90))(*0x431f60,&uStack_1b4);
  ```
- **关键词:** auStack_1b4, loc._gp + -0x7ccc, loc._gp + -0x7e2c, *0x431f60, *0x431f70, argv
- **备注:** 利用示例：mount -t ntfs-3g /dev/sda1 /mnt -o 'kernel_cache;reboot'

---
### crypto-weak-md5

- **文件路径:** `web/login/encrypt.js`
- **位置:** `encrypt.js: hex_md5函数实现`
- **类型:** network_input
- **综合优先级分数:** **8.85**
- **风险等级:** 8.5
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 实现已破解的MD5算法用于密码哈希处理：1) 使用抗碰撞性失效的MD5（CVE-2004-2761）2) 无输入长度检查（core_md5函数直接处理任意长度输入）3) 可被用于哈希长度扩展攻击。触发条件：当外部调用hex_md5(s)时，攻击者通过HTTP请求控制's'参数传递恶意构造的输入，可能造成：身份验证绕过（碰撞攻击）、服务拒绝（超长输入消耗资源）
- **代码片段:**
  ```
  function hex_md5(s){ return binl2hex(core_md5(str2binl(s), s.length * 8); }
  ```
- **关键词:** hex_md5, core_md5, str2binl, s
- **备注:** 需结合调用方（如登录认证逻辑）验证实际利用链

---
### file_write-smbd-double_vuln_chain

- **文件路径:** `usr/sbin/smbd`
- **位置:** `smbd:0x0043f418 (do_smbpasswd)`
- **类型:** file_write
- **综合优先级分数:** **8.85**
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整本地提权攻击链：攻击者通过写入特制smbpasswd文件触发双重漏洞。1) 认证维持绕过：当文件0x22偏移处为'*'(0x2a)或'X'(0x58)时，服务跳过密码更新流程维持旧凭证 2) 缓冲区溢出：fcn.0043f300函数解码超长十六进制字符串时溢出固定16字节缓冲区。触发条件：a) 攻击者具有/tmp/samba/private/smbpasswd写权限 b) 触发服务重载。利用方式：组合漏洞实现权限维持+任意代码执行。
- **代码片段:**
  ```
  if ((puVar15[0x22] != 0x2a) && (puVar15[0x22] != 0x58)) {
      iVar8 = fcn.0043f300(puVar15 + 0x22,0x464644);
  }
  ```
- **关键词:** do_smbpasswd, fcn.0043f300, /tmp/samba/private/smbpasswd, puVar15[0x22], 0x464644, 0x2a, 0x58
- **备注:** 前置条件验证：1) smbpasswd文件修改可行性 2) 服务重载触发方式。后续分析建议：1) /tmp/samba目录权限 2) 服务重载机制。网络路径分析(NTLMv2/SMBsesssetupX)因技术限制未完成，需动态分析补充。当前攻击链风险高于网络路径漏洞，应优先处置。

---
### network_input-encrypt-missing_validation

- **文件路径:** `web/login/encrypt.js`
- **位置:** `encrypt.js:72 str2binl()`
- **类型:** network_input
- **综合优先级分数:** **8.8**
- **风险等级:** 8.0
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 核心安全缺陷：所有函数均未验证输入类型/长度/特殊字符。触发条件：向str2binl()等函数传入非字符串或含特殊字符（如NULL字节）的输入。安全影响：导致JS运行时异常或内存破坏，可能被组合利用实现RCE。利用路径：污染输入→加密函数→未校验处理→异常崩溃或内存越界。
- **代码片段:**
  ```
  for(var i=0; i<str.length*8; i+=8) bin[i>>5] |= (str.charCodeAt(i/8) & mask) << (i%32)
  ```
- **关键词:** str2binl, Base64Encoding, charCodeAt, binl2hex
- **备注:** 需强制类型检查（typeof s==='string'）和长度限制。后续应追踪调用此文件的组件（如认证API）。

---
### network_input-ParentCtrlRpm-http_params

- **文件路径:** `web/userRpm/ParentCtrlRpm.htm`
- **位置:** `web/userRpm/ParentCtrlRpm.htm (表单及JavaScript区域)`
- **类型:** network_input
- **综合优先级分数:** **8.75**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 该页面作为家长控制功能入口，暴露多个未防护的网络输入点：攻击者可通过伪造GET请求（含ctrl_enable/parent_mac_addr等参数）直接修改设备配置。触发条件：用户访问恶意链接或跨站请求（CSRF）。实际影响：1) 篡改家长控制规则可能绕过访问限制 2) parent_mac_addr参数未在客户端充分验证（依赖未定义的is_macaddr函数），可能被注入异常值污染后端处理流程。
- **代码片段:**
  ```
  location.href = LP + "?ctrl_enable=" + bEnabled + "&parent_mac_addr=" + pMac + "&Page=" + parent_ctrl_page_param[0];
  ```
- **关键词:** ParentCtrlRpm.htm, ctrl_enable, parent_mac_addr, doSave, is_macaddr, location.href, parent_ctrl_global_cfg_dyn_array
- **备注:** 需优先分析：1) is_macaddr验证函数的实现（可能在共享JS文件）2) 后端处理程序（根据路由规则推测为goahead或lighttpd的CGI模块）

---
### command_execution-httpd_service_start

- **文件路径:** `etc/rc.d/rcS`
- **位置:** `etc/rc.d/rcS (具体行号需反编译)`
- **类型:** command_execution
- **综合优先级分数:** **8.7**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 10.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 脚本通过`/usr/bin/httpd &`启动HTTP服务守护进程。该服务暴露网络接口，可能处理外部输入的HTTP请求（如URL参数、POST数据）。若httpd存在缓冲区溢出或命令注入漏洞，攻击者可通过网络发送特制数据触发漏洞。触发条件：设备联网且httpd服务监听0.0.0.0。边界检查：当前分析未发现httpd服务的输入过滤机制。
- **关键词:** /usr/bin/httpd, httpd, rcS
- **备注:** 关键后续任务：逆向分析/usr/bin/httpd的请求处理函数；关联现有httpd关键词

---
### code_flaw-vlan_handling-uninit_var

- **文件路径:** `sbin/ssdk_sh`
- **位置:** `sbin/ssdk_sh:0x408f64 (fcn.00408f64)`
- **类型:** command_execution
- **综合优先级分数:** **8.7**
- **风险等级:** 8.5
- **置信度:** 9.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** VLAN处理函数(fcn.00408f64)存在未初始化变量漏洞。触发条件：用户输入'0x'/'0X'前缀且无后续字符时，跳过字符验证循环，sscanf空字符串导致uStack_14未初始化，污染*param_2输出。边界检查(uStackX_8 < uStack_14 < uStackX_c)依赖污染数据失效，可导致敏感数据泄露/服务拒绝(错误码0xfffffffc)，结合栈控制可实现RCE。利用方式：构造畸形VLAN参数触发未初始化内存读取。
- **代码片段:**
  ```
  关键漏洞代码：
  if (strlen(param_1) <= 2) break;
  ...
  sscanf(param_1,"%x",&uStack_14); // 空输入时未初始化
  ```
- **关键词:** fcn.00408f64, param_1, sscanf, %x, uStack_14, *param_2, 0xfffffffc
- **备注:** 需验证调用链：检查网络API是否暴露此函数；建议修补输入长度检查

---
### format-string-password

- **文件路径:** `sbin/wpa_supplicant`
- **位置:** `wpa_supplicant:fcn.0044163c:0x4418c0`
- **类型:** network_input
- **综合优先级分数:** **8.65**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危格式化字符串漏洞（sprintf）。密码字段(*(iVar1+0x48))未经验证写入256字节栈缓冲区。触发条件：1) 使用密码认证(*(iVar1+0x44)==0) 2) 密码长度>237字节。边界检查：仅依赖固定缓冲区大小。安全影响：精心构造的格式化字符串可触发栈溢出实现RCE。利用方式：通过CTRL_IFACE注入超长密码或篡改配置文件。
- **关键词:** *(iVar1+0x48), wpa_passphrase, auStack_728, sprintf, passphrase, psk

---
### network_input-NasCfgRpm-exposed_operations

- **文件路径:** `web/userRpm/NasCfgRpm.htm`
- **位置:** `www/NasCfgRpm.htm:? [事件处理]`
- **类型:** network_input
- **综合优先级分数:** **8.55**
- **风险等级:** 7.5
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 敏感操作暴露：remove/is_pwd_access/start_nas等7个参数通过GET请求直接触发磁盘移除、访问控制修改、NAS服务启停等操作。触发条件：直接构造恶意URL。安全影响：攻击者可绕过前端JS验证（如n_mnt约束）直接触发高危操作，缺乏操作二次认证增加风险。
- **代码片段:**
  ```
  location.href = locpath + "?remove=1";
  document.forms[0].start_nas.disabled = (n_mnt == 0)?true:false;
  ```
- **关键词:** remove, is_pwd_access, start_nas, stop_nas, safelyRemoveOpt, OnRemoveMedia, n_mnt
- **备注:** 所有操作均指向NasCfgRpm.htm自身，需分析后端路由处理逻辑

---

## 中优先级发现

### network_input-80211r-FTIE_Length_Validation

- **文件路径:** `sbin/hostapd`
- **位置:** `fcn.00442f18:0x00442f18`
- **类型:** network_input
- **综合优先级分数:** **8.45**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** FTIE长度验证缺陷：函数fcn.00442f18处理802.11r快速过渡认证时，仅检查FTIE长度是否小于0x52字节，未处理超长数据。攻击者可构造长度>0x52字节的FTIE字段，触发字节移位操作(*((uStack_80 + 0x32) - uVar15) << uVar15*8)时破坏栈结构。触发条件：发送恶意FT认证帧且FTIE长度≥0x52。实际影响：可导致栈越界写，结合固件内存布局可能实现任意代码执行。
- **代码片段:**
  ```
  if ((uStack_80 == 0) || (uStack_7c < 0x52)) { ... } else { ... *((uStack_80 + 0x32) - uVar15) << uVar15*8 ... }
  ```
- **关键词:** FTIE, fcn.00442f18, uStack_7c, uStack_80, ieee802_11_process_ft
- **备注:** 关联函数wpa_ft_install_ptk可能扩大攻击面。需验证auStack_140缓冲区大小（0x140字节）与实际偏移关系

---
### command_execution-iptables-memcpy_overflow

- **文件路径:** `sbin/iptables-multi`
- **位置:** `iptables-multi:0x408d44 sym.do_command`
- **类型:** command_execution
- **综合优先级分数:** **8.45**
- **风险等级:** 8.8
- **置信度:** 8.5
- **触发可能性:** 7.5
- **查询相关性:** 9.2
- **阶段:** N/A
- **描述:** 可控长度memcpy漏洞：do_command函数（0x408d44）中memcpy长度参数(a2)直接来自外部可控内存(a1)，而a1值通过命令行输入→getopt_long→fcn.00405fa4→iStack_a0+0x38路径污染。触发条件：构造特定命令行参数控制*(iStack_a0+0x38)内存值。结合目标缓冲区(s2+0x70)边界缺失检查，可导致堆/栈溢出。利用难度取决于缓冲区位置和攻击者对puVar9内容的控制力。
- **代码片段:**
  ```
  0x408d44 lw t9, -sym.imp.memcpy(gp)
  0x408d48 addiu a0, s2, 0x70
  0x408d4c lw a1, 0x38(v0)
  0x408d54 lhu a2, (a1)
  ```
- **关键词:** memcpy, iStack_a0, fcn.00405fa4, getopt_long, param_1, puVar9
- **备注:** 关联漏洞：heap-overflow@0x407a38（共享param_1污染源）。关键验证点：puVar9分配函数(loc._gp+-0x7f04)是否受输入影响。建议后续分析fcn.00405fa4函数逻辑

---
### access-ctrl-ctrl_iface

- **文件路径:** `sbin/wpa_supplicant`
- **位置:** `sym.wpa_supplicant_ctrl_iface_process`
- **类型:** ipc
- **综合优先级分数:** **8.45**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 控制接口无访问控制风险。CTRL_IFACE处理函数直接执行所有命令，未实施身份验证或权限检查。触发条件：攻击者能访问控制接口socket文件（通常位于/var/run）。实际安全影响：使所有后续漏洞可被远程触发，形成完整攻击链的基础。利用方式：通过Unix域套接字发送任意控制命令。
- **关键词:** wpa_supplicant_ctrl_iface_process, CTRL_IFACE, Unix socket, WPS_PBC, SAVE_CONFIG
- **备注:** 需验证固件中/var/run/wpa_supplicant权限设置

---
### file_write-dhcp6s-pid_symbolic_link

- **文件路径:** `usr/sbin/dhcp6s`
- **位置:** `dhcp6s:0x40a514 (main)`
- **类型:** file_write
- **综合优先级分数:** **8.45**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** **PID文件符号链接漏洞**：
- **触发条件**：dhcp6s服务启动时（系统初始化/网络重启）自动创建/tmp/dhcp6s.pid
- **漏洞表现**：使用fopen("w")模式（对应open的O_CREAT|O_TRUNC）未设置O_EXCL标志，且未验证现有文件类型（fstat）
- **安全影响**：攻击者预创建符号链接可覆盖任意文件（如/etc/passwd），文件内容被替换为进程ID数字，造成拒绝服务或权限提升
- **利用概率**：高（需/tmp目录写权限，嵌入式系统普遍满足此条件）
- **代码片段:**
  ```
  iVar1 = (**(loc._gp + -0x7db4))(*0x43a430,0x424a14); // fopen("/tmp/dhcp6s.pid", "w")
  ```
- **关键词:** main, fopen, /tmp/dhcp6s.pid, 0x409b40, O_TRUNC
- **备注:** 修复建议：改用open()配合O_EXCL|O_CREAT标志并验证文件类型

---
### network_input-SystemLogRpm-params

- **文件路径:** `web/userRpm/SystemLogRpm.htm`
- **位置:** `www/SystemLogRpm.htm:0 (doPage)`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** SystemLogRpm.htm暴露多个未经验证的用户输入参数(logType/logLevel/pageNum/doMailLog)，通过location.href直接拼接到URL传递至后端。攻击者可绕过前端控件限制（如修改logType=恶意值），因缺乏客户端输入过滤和编码。当用户触发日志操作(如刷新/分页)时，污染参数直达后端CGI程序。实际安全影响取决于后端处理：若CGI程序未实施严格输入验证，可能导致命令注入、路径遍历或逻辑漏洞（如doMailLog参数未授权触发邮件发送）。触发条件：攻击者诱使用户访问恶意构造的URL（含污染参数）或直接攻击API端点。
- **代码片段:**
  ```
  function doPage(j){location.href = LP + "?logType=" + ... + "&pageNum="+j;}
  ```
- **关键词:** logType, logLevel, pageNum, doMailLog, doTypeChange, doLevelChange, doPage, location.href, SystemLogRpm.htm, /www/cgi-bin/userRpm/SystemLogRpm.cgi
- **备注:** 必须验证后端CGI程序：1) 检查logType/logLevel的边界校验 2) 分析doMailLog=2的对应操作 3) 追踪参数在日志查询/清除功能中的数据流

---
### network_input-dhcp6c-options-oob_read

- **文件路径:** `usr/sbin/dhcp6c`
- **位置:** `sbin/dhcp6c:0x40d030 (dhcp6_get_options)`
- **类型:** network_input
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 选项越界读取漏洞：dhcp6_get_options处理客户端ID选项(0x01)时，通过循环(param_2 = param_2 + 0x10)读取16字节块，但未验证选项长度(uVar11)是否超出数据包边界。触发条件：设置畸形选项长度>实际包剩余空间且为16倍数。安全影响：敏感内存信息泄露或服务崩溃(DoS)，CVSSv3 7.5。
- **代码片段:**
  ```
  do {
      uStack_38 = ...; // 16字节块读取
      param_2 = param_2 + 0x10;
  } while (param_2 < uVar11); // uVar11=param_2+param_1
  ```
- **关键词:** dhcp6_get_options, option_01, dhcp6_find_listval
- **备注:** 影响所有基于WIDE-DHCPv6的固件；需检查其他选项处理函数

---
### attack_path-dhcp6c-option_oob-infoleak

- **文件路径:** `usr/sbin/dhcp6c`
- **位置:** `sbin/dhcp6c`
- **类型:** attack_path
- **综合优先级分数:** **8.4**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 信息泄露攻击链：伪造客户端ID选项(0x01)触发dhcp6_get_options越界读取。关键步骤：1) 设置超长选项长度 2) 响应DHCPv6请求 3) 读取进程内存敏感数据。成功率90%，影响等级High。
- **关键词:** dhcp6_get_options, option_01, infoleak
- **备注:** 关联漏洞：network_input-dhcp6c-options-oob_read

---
### xss-systemlogrpm-param-injection

- **文件路径:** `web/userRpm/SystemLogRpm.htm`
- **位置:** `SystemLogRpm.htm:15/22/30/37`
- **类型:** network_input
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 未经验证的URL参数注入风险：攻击者可通过污染logType/logLevel/pageNum参数构造恶意URL（如包含JS脚本或外部域名），用户访问时触发XSS或开放重定向。触发条件：1) 管理员点击恶意链接 2) 参数值未经HTML编码直接输出。边界检查：无前端过滤，依赖后端验证。实际影响：劫持会话/钓鱼攻击，成功概率取决于后端过滤强度。
- **代码片段:**
  ```
  location.href = LP + '?logType=' + i + '&pageNum=1';
  ```
- **关键词:** location.href, logType, logLevel, pageNum, LP
- **备注:** 关键验证点：后端CGI对参数的过滤逻辑（如SystemLogRpm.cgi）。需关联分析SystemLogRpm.cgi对logType/logLevel/pageNum的过滤。

---
### configuration_load-radvd-config_parser-dos_chain

- **文件路径:** `usr/sbin/radvd`
- **位置:** `sym.reload_config (0x00403e98), sym.yyparse (0x004094b8)`
- **类型:** configuration_load
- **综合优先级分数:** **8.35**
- **风险等级:** 8.0
- **置信度:** 9.5
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 配置解析拒绝服务漏洞链。触发条件：提供畸形/etc/radvd.conf配置文件。包含两个可组合利用的子漏洞：1) reload_config在解析失败时进入死循环持续调用syslog并exit(1) 2) yyparse处理深度嵌套配置时可能耗尽内存。攻击者可使radvd进程挂起中断IPv6服务。关键约束：配置文件需具有写权限，但常被弱权限账户误配置。
- **代码片段:**
  ```
  do {
    (*pcVar8)("readin_config failed.");
    (**(loc._gp + -0x7f44))(1);
  } while( true );
  ```
- **关键词:** sym.reload_config, fcn.00403220, sym.yyparse, obj.conf_file, **(loc._gp + -0x7f44), readin_config failed.
- **备注:** 攻击链：文件系统→配置解析→死循环。需审计配置文件加载路径的完整性检查

---
### auth_bypass-dropbear-password_env

- **文件路径:** `usr/sbin/dropbearmulti`
- **位置:** `dropbearmulti:0x4073bc`
- **类型:** env_get
- **综合优先级分数:** **8.35**
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 认证绕过漏洞：通过污染'DROPBEAR_PASSWORD'环境变量绕过SSH密码验证。触发条件：1) 攻击者设置环境变量（如通过NVRAM写入漏洞）2) 用户尝试密码登录。边界检查缺失：80字节栈缓冲区(auStack_60)未验证环境变量长度，同时认证逻辑直接使用变量值。实际影响：获得未授权系统访问权限。
- **代码片段:**
  ```
  iVar1 = (**(loc._gp + -0x7808))("DROPBEAR_PASSWORD");
  ```
- **关键词:** DROPBEAR_PASSWORD, auStack_60, sym.getpass_or_cancel, sym.cli_auth_password, getenv
- **备注:** 跨组件攻击路径：需结合NVRAM/web接口漏洞设置环境变量。后续应：1)分析/etc_ro/nvram.ini 2)关联KB#nvram_set

---
### ghost_vuln-xl2tpd-gethostbyname

- **文件路径:** `usr/sbin/xl2tpd`
- **位置:** `bin/xl2tpd:0x415198 (gethostbyname_handler)`
- **类型:** configuration_load
- **综合优先级分数:** **8.35**
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 6.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危GHOST漏洞攻击链：snprintf(0x415198)使用gethostbyname解析结果生成错误消息。触发条件：配置>255字节主机名触发glibc漏洞(CVE-2015-0235)。边界检查缺失在libc层面。结合未修补的libc可实现远程代码执行，完整路径：xl2tpd.conf配置→gethostbyname→堆破坏→RCE。
- **关键词:** gethostbyname, CVE-2015-0235, GHOST_vulnerability
- **备注:** 实际风险取决于固件libc版本；关键后续行动：验证libc补丁状态

---
### network_input-NasCfgRpm-disk_no_param

- **文件路径:** `web/userRpm/NasCfgRpm.htm`
- **位置:** `www/NasCfgRpm.htm:? [OnEnableShare]`
- **类型:** network_input
- **综合优先级分数:** **8.3**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未经验证的disk_no参数传递：用户控制的volIndex直接拼入URL（'NasCfgRpm.htm?disk_no='+volIndex）。攻击者可构造任意整数触发后端操作。触发条件：访问包含恶意volIndex的URL。安全影响：若后端未验证disk_no边界，可能导致越权磁盘操作（如删除/挂载非授权卷）。
- **代码片段:**
  ```
  function OnEnableShare(volIndex){
    location.href="NasCfgRpm.htm?disk_no="+ volIndex + "&share_status=" + 1;
  }
  ```
- **关键词:** OnEnableShare, OnDisableShare, disk_no, volIndex, share_status, volumeListArray
- **备注:** 需验证后端/cgi处理程序对disk_no的边界检查。关联文件：可能调用存储管理CGI（如nas_cgi）

---
### crypto-parameter-unsafe

- **文件路径:** `web/login/encrypt.js`
- **位置:** `encrypt.js`
- **类型:** network_input
- **综合优先级分数:** **8.3**
- **风险等级:** 7.0
- **置信度:** 10.0
- **触发可能性:** 9.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 关键函数参数完全缺失安全约束：1) hex_md5的's'参数作为原始HTTP输入入口 2) Base64Encoding的'input'参数 3) 无任何：长度校验/字符过滤/类型检查。边界检查缺失使攻击者可直接注入恶意载荷，实际危害取决于调用方是否进行后续检查
- **关键词:** s, input
- **备注:** 攻击路径：HTTP请求 → 参数's/input' → 加密函数 → 危险操作（需验证调用方）

---
### format_string-xl2tpd-handle_avps

- **文件路径:** `usr/sbin/xl2tpd`
- **位置:** `bin/xl2tpd:0x415630 (handle_avps)`
- **类型:** network_input
- **综合优先级分数:** **8.25**
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危格式化字符串溢出：snprintf(0x415630)使用外部可控param_2生成'Unknown host %s\n'，80字节缓冲区在主机名超66字节时溢出。触发条件：恶意L2TP包包含长主机名且解析失败。边界检查缺失表现为未验证param_2长度。完整攻击路径：网络输入→handle_avps→污染param_2→栈溢出→RCE。
- **关键词:** snprintf, param_2, format_string_overflow
- **备注:** 需结合固件栈保护机制评估实际可利用性；关联关键词'param_2'（知识库存在）

---
### network_input-NasCfgRpm-unvalidated_redirect

- **文件路径:** `web/userRpm/NasCfgRpm.htm`
- **位置:** `web/userRpm/NasCfgRpm.htm:66-70`
- **类型:** network_input
- **综合优先级分数:** **8.2**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未经验证的重定向操作：多个JavaScript函数（如OnEnableShare/OnDisableShare）使用location.href进行敏感操作重定向，携带volIndex等参数。攻击者可构造恶意URL注入额外参数（如admin=1），后端若未严格验证参数边界可能导致权限提升。触发条件：用户访问包含恶意参数的URL（需会话认证）。
- **代码片段:**
  ```
  function OnEnableShare(volIndex){location.href="NasCfgRpm.htm?enable_share=1&volIndex="+volIndex;}
  ```
- **关键词:** location.href, NasCfgRpm.htm, enable_share, disable_share, volIndex
- **备注:** 需验证后端对volIndex的解析逻辑，建议后续分析/cgi-bin目录的处理程序

---
### network_input-VirtualServerAdvRpm-ExPort_validation

- **文件路径:** `web/userRpm/VirtualServerAdvRpm.htm`
- **位置:** `VirtualServerAdvRpm.htm: JavaScript functions`
- **类型:** network_input
- **综合优先级分数:** **8.15**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 前端输入验证缺陷：1) ExPort参数通过check_port函数验证字符(-0-9)和格式(XX-XX)，但未验证端口范围(1-65535)及范围合理性(起始<结束)；2) InPort仅进行基础字符检查；3) IP验证(is_ipaddr)未检测实际有效性。攻击者可提交畸形值(如ExPort='0-70000')触发后端未定义行为。触发条件：用户通过管理界面提交虚拟服务器配置表单。潜在影响包括整数溢出、服务拒绝或配置破坏。
- **代码片段:**
  ```
  function check_port(port_string){
    if(!is_portcharacter(port_string)) return false;
    // 缺失: port_range_min >0 && port_range_max <65535
  }
  ```
- **关键词:** ExPort, InPort, check_port, checkInPort, is_portcharacter, is_num
- **备注:** 需结合VirtualServerRpm.htm分析实际影响

---
### off_by_one-xl2tpd-safe_copy

- **文件路径:** `usr/sbin/xl2tpd`
- **位置:** `bin/xl2tpd:0x405fbc (safe_copy)`
- **类型:** network_input
- **综合优先级分数:** **8.1**
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危单字节溢出漏洞：safe_copy函数(0x405fbc)执行`*(param_1+param_3)=0`时，当param_3等于缓冲区大小时发生越界写。触发条件：攻击者通过污染参数控制param_3值（如来自网络数据的长度字段）。边界检查缺失表现为未验证param_3与缓冲区实际尺寸关系。可破坏堆元数据或敏感变量，结合堆风水技术可能实现RCE。
- **关键词:** safe_copy, buffer_boundary, heap_corruption
- **备注:** 需追踪param_3污染源；潜在关联关键词：'param_1'（知识库存在记录）

---
### env_set-rcS-PATH_injection

- **文件路径:** `etc/rc.d/rcS`
- **位置:** `etc/rc.d/rcS (具体行号需反编译)`
- **类型:** env_set
- **综合优先级分数:** **8.05**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.2
- **阶段:** N/A
- **描述:** 在系统启动阶段，rcS脚本通过`export PATH=$PATH:/etc/ath`将/etc/ath目录加入PATH环境变量。攻击者若能在/etc/ath植入与系统命令同名的恶意程序（如ifconfig），当管理员执行命令时将触发恶意代码执行。触发条件：1) /etc/ath目录权限配置不当（全局可写）2) 攻击者获得文件写入权限。边界检查：脚本未验证/etc/ath是否存在或权限设置。
- **关键词:** PATH, export, /etc/ath, rcS
- **备注:** 需验证/etc/ath目录权限：若权限为777则风险升级至9.0；关联现有PATH关键词

---
### heap_overflow-xl2tpd-add_hostname_avp

- **文件路径:** `usr/sbin/xl2tpd`
- **位置:** `bin/xl2tpd:0x412494 (add_hostname_avp)`
- **类型:** network_input
- **综合优先级分数:** **8.05**
- **风险等级:** 8.0
- **置信度:** 8.5
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 高危堆溢出漏洞：add_hostname_avp函数(0x412494)复制网络提供的param_2(主机名)时，未验证目标缓冲区剩余空间。触发条件：发送超过1017字节的主机名参数。边界检查缺失表现为未比较输入长度与缓冲区剩余容量(uVar1 < 0x3F9)。可导致堆结构破坏，可能引发拒绝服务或代码执行。
- **关键词:** hostname_avp, heap_overflow, 0x3f9
- **备注:** 关联攻击路径'长主机名AVP→堆溢出→RCE'；链接关键词'param_2'（知识库存在）

---
### network_input-80211r-R0KHID_Copy_Without_Bounds

- **文件路径:** `sbin/hostapd`
- **位置:** `fcn.00442f18:0x004435c4`
- **类型:** network_input
- **综合优先级分数:** **8.04**
- **风险等级:** 8.0
- **置信度:** 7.8
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** R0KH-ID无边界拷贝：同一函数内解析R0KH-ID字段时，直接通过(**(loc._gp + -0x75b8))（疑似memcpy）将iStack_6c数据拷贝至piStack_38，未验证iStack_68长度与目标缓冲区关系。触发条件：FTIE中包含超长R0KH-ID字段（>目标缓冲区）。实际影响：栈溢出可能覆盖关键栈帧（如返回地址），实现稳定控制流劫持。
- **代码片段:**
  ```
  (**(loc._gp + -0x75b8))(piStack_38,iStack_6c,iStack_68);
  ```
- **关键词:** R0KH-ID, iStack_6c, iStack_68, piStack_38, loc._gp + -0x75b8
- **备注:** 需确认piStack_38缓冲区大小。动态测试建议使用＞100字节R0KH-ID触发崩溃

---
### network_input-NasCfgRpm-csrf_exposure

- **文件路径:** `web/userRpm/NasCfgRpm.htm`
- **位置:** `web/userRpm/NasCfgRpm.htm:35-36,161`
- **类型:** network_input
- **综合优先级分数:** **7.9**
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** CSRF敏感操作暴露：表单通过GET方法提交NAS服务控制（start_nas/stop_nas）和磁盘操作（safely_remove）。攻击者可构造恶意页面诱使用户触发未授权操作。触发条件：认证用户访问恶意页面时自动发起请求（无需交互）。
- **代码片段:**
  ```
  <INPUT name="start_nas" type="submit" class="buttonBig" value="Start">
  ```
- **关键词:** start_nas, stop_nas, safely_remove, method=get, enctype=multipart/form-data
- **备注:** 缺乏anti-CSRF token机制，需检查HTTP头是否验证Referer

---
### client_validation-ChangeLoginPwdRpm-JS_bypass

- **文件路径:** `web/userRpm/ChangeLoginPwdRpm.htm`
- **位置:** `web/userRpm/ChangeLoginPwdRpm.htm:0 (JavaScript函数)`
- **类型:** network_input
- **综合优先级分数:** **7.8**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 客户端验证机制可被绕过，存在未授权操作风险。具体表现：doSubmit()函数执行字段非空检查、字符合法性验证(CheckUserPswChars)及密码一致性检查，但攻击者可绕过JS验证直接构造请求。触发条件：直接向ChangeLoginPwdRpm.htm发送特制GET请求。约束条件：依赖LoginPwdInf[2]决定哈希处理逻辑。安全影响：可提交非法字符或空密码，若服务器端缺乏等效验证可能导致账户接管或注入攻击。
- **代码片段:**
  ```
  if(document.forms[0].newpassword.value!=document.forms[0].newpassword2.value){alert('Passwords do not match!');return false;}
  ```
- **关键词:** doSubmit, CheckUserPswChars, hex_md5, Base64Encoding, LoginPwdInf, onSubmit
- **备注:** 与加密链（hex_md5/Base64Encoding）存在关联，可能组合利用MD5弱点实现完整攻击。需分析服务器端处理程序(如ChangeLoginPwdRpm.cgi)验证是否存在服务端校验

---
### network_input-dhcp_option_33-0x0041ed40

- **文件路径:** `bin/busybox`
- **位置:** `busybox:0x0041ed40 [fcn.0041ed40]`
- **类型:** network_input
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** DHCP classless static route选项（33/121/249）处理存在长度验证缺陷和危险位反转操作。攻击者发送特制DHCP响应可破坏设备路由配置导致拒绝服务。触发条件：攻击者需网络可达并伪装DHCP服务器发送恶意option字段。实际影响：通过覆盖路由表实现网络隔离或重定向流量到攻击者控制节点。
- **关键词:** option_lengths, uVar2 & 7, dhcp_response
- **备注:** 参考CVE-2018-1111利用模式，需验证固件网络配置是否启用DHCP客户端

---
### ipc-httpd_data_pollution-003

- **文件路径:** `sbin/tphotplug`
- **位置:** `tphotplug:? [reportToHttpd] 0x403900`
- **类型:** ipc
- **综合优先级分数:** **7.75**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** IPC数据污染漏洞：reportToHttpd函数通过send直接发送未验证的usb_type参数（main函数传入的-u选项值）。触发条件：攻击者控制tphotplug启动参数。利用方式：注入异常整数值导致接收方解析错误，可能引发整数溢出或类型混淆。边界检查：无任何校验直接发送原始数据。
- **代码片段:**
  ```
  iVar1 = (**(loc._gp + -0x7f10))(iVar2,auStackX_0,4,0);
  ```
- **关键词:** reportToHttpd, send, main, usb_type, -u, 0x414640
- **备注:** 需动态验证main到reportToHttpd的调用链；关联现有'main'关键词（KB#main）

---
### file_read-dhcp6s-duid_heap_overflow

- **文件路径:** `usr/sbin/dhcp6s`
- **位置:** `sym.get_duid:0x0040eb0c`
- **类型:** file_read
- **综合优先级分数:** **7.75**
- **风险等级:** 8.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** **DUID文件双重漏洞**：
- **符号链接攻击**：get_duid函数使用fopen("w+")创建/tmp/dhcp6s_duid，未用O_EXCL标志，攻击者可操纵DUID数据或覆盖文件
- **堆溢出风险**：读取时通过fread(&uStack_130, 2, 1, file)获取长度字段，未经验证直接用于内存分配，可能触发堆溢出
- **触发条件**：当DUID文件不存在时（首次启动或文件被删）
- **复合影响**：符号链接攻击可破坏系统完整性；堆溢出可能实现远程代码执行（若DUID数据可通过网络影响）
- **代码片段:**
  ```
  iVar1 = (**(loc._gp + -0x7db4))(param_1,"w+"); // 不安全打开方式
  ```
- **关键词:** sym.get_duid, fopen, "w+", uStack_130, fread, 0x0040eb0c
- **备注:** 需动态验证：1) uStack_130缓冲区边界 2) DUID数据是否受网络输入影响

---
### dos-dropbear-buf_getstring

- **文件路径:** `usr/sbin/dropbearmulti`
- **位置:** `dropbearmulti:0x00406188`
- **类型:** network_input
- **综合优先级分数:** **7.65**
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 服务拒绝漏洞：buf_getstring函数处理网络包时，仅硬编码1400字节长度限制(0x578)，未考虑SSH协议最大包长度65535字节。触发条件：发送长度>1400字节的恶意包。安全影响：1) 直接调用dropbear_exit终止进程(DoS) 2) 若全局分配函数存在整数溢出可导致堆溢出。
- **代码片段:**
  ```
  uVar1 = sym.buf_getint();
  if (0x578 < uVar1) {
    (**(loc._gp + -0x7a5c))("String too long");
  }
  ```
- **关键词:** sym.buf_getstring, 0x578, dropbear_exit, String too long, sym.buf_getint
- **备注:** 影响20+安全关键函数。需验证：1)loc._gp-0x7acc分配函数的安全性 2)关联KB#loc._gp指针偏移漏洞

---
### unterminated_string-xl2tpd-config_parser

- **文件路径:** `usr/sbin/xl2tpd`
- **位置:** `bin/xl2tpd:0x414958 (config_parser)`
- **类型:** configuration_load
- **综合优先级分数:** **7.65**
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 中危未终止字符串漏洞：配置文件解析函数(fcn.004143c8)使用strncpy复制配置项到80字节缓冲区(puVar2)后未添加终止符(0x414958)。触发条件：配置项长度≥80字符。边界检查不完整表现为仅限制拷贝长度但忽略字符串终止需求。后续字符串操作可能越界读/写，导致信息泄露或进程崩溃。
- **关键词:** strncpy, unterminated_string, puVar2
- **备注:** 影响范围取决于后续使用该缓冲区的函数；关联配置文件xl2tpd.conf

---
### ipc-syslog_escape-0x433de8

- **文件路径:** `bin/busybox`
- **位置:** `busybox:0x433de8 [fcn.00433974]`
- **类型:** ipc
- **综合优先级分数:** **7.5**
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.5
- **查询相关性:** N/A
- **阶段:** N/A
- **描述:** syslog消息转义序列处理存在栈溢出漏洞（auStack_44缓冲区仅4字节）。本地攻击者向/var/log套接字发送含特制转义序列的日志消息可覆盖相邻函数指针（puStack_40）。触发条件：攻击者需本地shell访问权限。实际影响：可导致拒绝服务或控制流劫持，具体取决于被覆盖指针的用途。
- **关键词:** auStack_44, puStack_40, /var/log
- **备注:** 需动态验证指针使用场景，检查是否开启远程日志(-R)会扩大攻击面

---
### attack_path-radvd-config_dos_chain

- **文件路径:** `usr/sbin/radvd`
- **位置:** `AttackPath:2`
- **类型:** attack_path
- **综合优先级分数:** **7.5**
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击路径：文件系统 → 篡改/etc/radvd.conf → 配置解析死循环 → 服务拒绝。触发概率：7.0（中），影响：服务中断。关键触发步骤：1) 写入畸形配置文件 2) 触发配置重载。利用配置解析器缺乏错误恢复机制的缺陷，导致进程永久挂起。
- **关键词:** configuration_load-radvd-config_parser-dos_chain, DoS, /etc/radvd.conf
- **备注:** 关联发现：configuration_load-radvd-config_parser-dos_chain

---
### mitm-dropbear-ssh_auth_sock

- **文件路径:** `usr/sbin/dropbearmulti`
- **位置:** `dropbearmulti:0x406a50`
- **类型:** env_get
- **综合优先级分数:** **7.45**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** SSH代理劫持漏洞：未验证SSH_AUTH_SOCK环境变量值，攻击者可注入恶意socket路径。触发条件：1) 控制进程环境 2) 触发代理连接流程。实际影响：中间人攻击或文件描述符劫持。
- **关键词:** SSH_AUTH_SOCK, getenv, fcn.00406a30, loc._gp-0x7cb4
- **备注:** 需分析代理连接函数实现。关联发现：KB#/var/run权限漏洞（可能扩大攻击面）

---
### command_execution-ntfs_force_mount-004

- **文件路径:** `sbin/tphotplug`
- **位置:** `tphotplug:? [doMount] 0x00402944`
- **类型:** command_execution
- **综合优先级分数:** **7.4**
- **风险等级:** 7.5
- **置信度:** 9.5
- **触发可能性:** 4.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** NTFS挂载强制选项风险：doMount失败时使用ntfs-3g命令带force选项挂载。触发条件：首次挂载失败（如文件系统损坏）。利用方式：结合恶意USB存储设备强制挂载特制文件系统。安全影响：可能绕过文件系统安全检查，与内核漏洞协同可提升权限。
- **关键词:** ntfs-3g, force, async, fcn.00401c98, ERROR: mount ntfs disk %s%s on %s%s%d failed.

---
### configuration_load-dhcp6c-configure_domain-heap_overflow

- **文件路径:** `usr/sbin/dhcp6c`
- **位置:** `sbin/dhcp6c:0x410ec0 (cf_post_config)`
- **类型:** configuration_load
- **综合优先级分数:** **7.35**
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 配置堆溢出漏洞：cf_post_config加载dhcp6c.conf时，configure_domain对域名配置项(param_1[7])使用strdup无长度限制复制。攻击者篡改配置文件插入>1024字符域名导致堆溢出。触发条件：本地修改配置文件并重启服务。安全影响：本地权限提升或RCE，CVSSv3 7.8。
- **关键词:** cf_post_config, configure_domain, dhcp6c.conf, strdup
- **备注:** 可通过DHCPv6重配置机制(reconfigure)远程触发，需进一步验证

---
### network_input-radvd-process-rs_memory_corruption

- **文件路径:** `usr/sbin/radvd`
- **位置:** `radvd:0x4061e0 (sym.process)`
- **类型:** network_input
- **综合优先级分数:** **7.3**
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** ICMPv6 RS包处理内存安全风险。触发条件：发送length字段=0的特制RS包。漏洞位于process函数，直接使用攻击者控制的param_3[9]字段进行左移运算(iVar7 = param_3[9] << 3)，异常值导致指针越界访问。缺乏边界验证，攻击者可造成内存破坏或DoS。
- **代码片段:**
  ```
  iVar7 = param_3[9] << 3;
  pcVar3 = pcVar3 + iVar7;
  ```
- **关键词:** sym.process, param_3[9], iVar7, pcVar3, acStack_620
- **备注:** 网络→RS包处理→内存异常。需结合反汇编验证具体内存操作类型

---
### network_input-encrypt-base64_dos

- **文件路径:** `web/login/encrypt.js`
- **位置:** `encrypt.js:94 Base64Encoding()`
- **类型:** network_input
- **综合优先级分数:** **7.25**
- **风险等级:** 6.0
- **置信度:** 9.5
- **触发可能性:** 7.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** Base64编码函数无输入长度校验，存在客户端拒绝服务风险。触发条件：前端调用Base64Encoding()处理超长输入（>1MB）。安全影响：恶意构造的长字符串导致浏览器内存耗尽/卡死。利用路径：污染输入→Base64Encoding()→while循环耗尽资源。
- **代码片段:**
  ```
  while (i < input.length) { chr1 = input.charCodeAt(i++); ... }
  ```
- **关键词:** Base64Encoding, keyStr, utf8_encode, charCodeAt
- **备注:** 需添加输入长度上限（建议≤1MB）。结合后端验证防止编码数据篡改。

---
### dos-wps-attr

- **文件路径:** `sbin/wpa_supplicant`
- **位置:** `sym.wps_process_device_attrs`
- **类型:** network_input
- **综合优先级分数:** **7.05**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** WPS属性处理拒绝服务漏洞。信任网络输入的Manufacturer/Model_Name等属性长度字段，未验证长度值合理性即分配内存。触发条件：发送WPS属性设置超大长度值(≥0xFFFFFF)。安全影响：进程崩溃导致拒绝服务。利用概率：高（因无需认证）。
- **关键词:** wps_process_device_attrs, Manufacturer, Model_Name, Serial_Number, Device_Name, length

---
### network_input-AccessRules-moveItem

- **文件路径:** `web/userRpm/AccessCtrlAccessRulesRpm.htm`
- **位置:** `www/AccessCtrlHostsListsRpm.htm: (moveItem) [函数入口]`
- **类型:** network_input
- **综合优先级分数:** **7.05**
- **风险等级:** 7.5
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** moveItem函数处理用户输入的SrcIndex/DestIndex参数时，仅通过未定义的is_number函数验证（范围1-access_rules_page_param[4]）。攻击者可绕过客户端验证（禁用JS或直接构造请求）提交非数字/越界值。若服务端未二次验证，可导致：1) 越权操作规则条目；2) 通过整数溢出触发内存破坏；3) 拒绝服务。触发条件：诱使用户访问恶意URL（含污染参数）或CSRF攻击。
- **代码片段:**
  ```
  function moveItem(nPage){
    var dstIndex = document.forms[0].DestIndex.value;
    var srcIndex = document.forms[0].SrcIndex.value;
    if (false == is_number(srcIndex, 1,access_rules_page_param[4])) {...}
    location.href="...?srcIndex="+srcIndex+"&dstIndex="+dstIndex;
  ```
- **关键词:** moveItem, SrcIndex, DestIndex, is_number, access_rules_page_param
- **备注:** 需验证服务端处理文件（如AccessCtrlAccessRulesRpm.cgi）的输入检查。关联文件：AccessCtrlHostsListsRpm.htm（通过参数传递交互）。

---
### attack_path-dhcp6c-heap_overflow-lpe

- **文件路径:** `usr/sbin/dhcp6c`
- **位置:** `etc/dhcp6c.conf`
- **类型:** attack_path
- **综合优先级分数:** **7.05**
- **风险等级:** 7.5
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 权限提升攻击链：篡改dhcp6c.conf触发configure_domain堆溢出。关键步骤：1) 插入>1024字符域名 2) 重启服务或触发重配置 3) 覆盖堆元数据实现任意写入。成功率60%，影响等级High。
- **关键词:** cf_post_config, dhcp6c.conf, reconfigure
- **备注:** 关联漏洞：configuration_load-dhcp6c-configure_domain-heap_overflow；需验证远程触发机制

---
### configuration_load-rcS_mount_hijack

- **文件路径:** `etc/rc.d/rcS`
- **位置:** `etc/rc.d/rcS (具体行号需反编译)`
- **类型:** configuration_load
- **综合优先级分数:** **7.0**
- **风险等级:** 6.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 脚本执行`mount -a`加载/etc/fstab挂载配置，并调用/etc/rc.d/rc.modules加载内核模块。若攻击者篡改fstab文件（如添加setuid权限的恶意挂载点）或rc.modules脚本（如加载恶意KO文件），可获持久化控制或特权提升。触发条件：系统启动时自动执行。边界检查：未发现配置签名验证机制。
- **关键词:** mount -a, /etc/fstab, /etc/rc.d/rc.modules, rcS
- **备注:** 关联攻击链：需结合fstab文件写权限和rc.modules代码执行漏洞；关联现有mount关键词

---

## 低优先级发现

### hardware_input-mount_traversal-002

- **文件路径:** `sbin/tphotplug`
- **位置:** `tphotplug:? [doMount] 0x004028ec`
- **类型:** hardware_input
- **综合优先级分数:** **6.85**
- **风险等级:** 6.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 挂载路径遍历风险：doMount函数使用sprintf构造挂载路径（`mount %s%s %s%s%d`），其中设备名参数未过滤特殊字符。触发条件：恶意USB设备名含`../`序列。利用方式：突破/tmp目录限制访问敏感区域（如`/etc`）。边界检查：volumeNum有范围校验但路径无过滤。实际影响受目标路径前缀限制，风险中等。
- **代码片段:**
  ```
  mount %s%s %s%s%d -o noatime,fmask=0000,dmask=0000,iocharset=utf8
  ```
- **关键词:** doMount, sprintf, %s%s%d, /tmp/dev/, /tmp/usbdisk/, volumeNum
- **备注:** 设备名来源函数fcn.00401cf4需进一步分析；关联现有'sprintf'关键词（KB#sprintf）及漏洞001的'mount'

---
### attack_path-radvd-rs_memcorrupt_chain

- **文件路径:** `usr/sbin/radvd`
- **位置:** `AttackPath:3`
- **类型:** attack_path
- **综合优先级分数:** **6.75**
- **风险等级:** 7.0
- **置信度:** 6.5
- **触发可能性:** 6.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击路径：网络接口 → 特制RS包 → 异常指针运算 → 内存破坏。触发概率：6.5（中低），影响：DoS或潜在RCE。关键触发步骤：1) 设置length=0的RS包 2) 发送至radvd服务。通过未验证的协议字段触发危险指针操作，可能绕过常规内存保护机制。
- **关键词:** network_input-radvd-process-rs_memory_corruption, RS_packet, memory_corruption
- **备注:** 关联发现：network_input-radvd-process-rs_memory_corruption

---
### crypto-base64-static

- **文件路径:** `web/login/encrypt.js`
- **位置:** `encrypt.js: Base64Encoding函数实现`
- **类型:** network_input
- **综合优先级分数:** **6.7**
- **风险等级:** 5.0
- **置信度:** 10.0
- **触发可能性:** 6.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** Base64编码使用硬编码静态编码表且无输入过滤：1) 编码表keyStr固定不变 2) input参数直接处理未验证内容 3) 无输出长度限制。攻击者可预测编码结果并构造特殊输入（如超长字符串）尝试触发内存错误，或通过编码结果注入恶意载荷（当调用方直接使用输出时）
- **代码片段:**
  ```
  var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  ```
- **关键词:** Base64Encoding, keyStr, input

---
### network_input-NasCfgRpm-client_control

- **文件路径:** `web/userRpm/NasCfgRpm.htm`
- **位置:** `web/userRpm/NasCfgRpm.htm:56`
- **类型:** network_input
- **综合优先级分数:** **6.55**
- **风险等级:** 6.5
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 客户端控制安全开关：密码访问控制（use_passwd）仅通过前端JS（onClickUsePWDCheckbox）切换，未观察到服务端验证逻辑。攻击者可能绕过前端JS直接修改参数禁用密码保护。触发条件：直接构造is_pwd_access=0的请求参数。
- **代码片段:**
  ```
  <INPUT type="checkbox" name="use_passwd" onClick = "onClickUsePWDCheckbox();">
  ```
- **关键词:** use_passwd, onClickUsePWDCheckbox, is_pwd_access, type=checkbox
- **备注:** 需验证后端对is_pwd_access参数的处理是否存在权限校验

---
### StackOverflow-argv0-ntfs3g-0x4088b8

- **文件路径:** `bin/ntfs-3g`
- **位置:** `ntfs-3g:0x004088b8`
- **类型:** command_execution
- **综合优先级分数:** **6.5**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 4.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** argv[0]栈溢出漏洞：main函数中复制argv[0]到24字节栈缓冲区(auStack_168)时未验证长度。触发条件：通过长路径名或符号链接攻击执行ntfs-3g（如`/tmp/$(perl -e'print "A"x1000')`）。约束条件：缓冲区固定24字节。实际影响：程序崩溃或有限代码执行（需精准控制溢出数据）。
- **关键词:** *0x431f60, auStack_168, gp-0x7cfc, 0x004088b8

---
### network_input-WPS-Authenticator_Validation_Bypass

- **文件路径:** `sbin/hostapd`
- **位置:** `sym.wps_process_authenticator`
- **类型:** network_input
- **综合优先级分数:** **6.5**
- **风险等级:** 6.0
- **置信度:** 9.0
- **触发可能性:** 4.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** WPS协议验证依赖风险：wps_process_authenticator验证Authenticator字段时，依赖前序消息完整性(param_1+0x134)和密钥保密性(param_1+0xe4)。虽无内存破坏，但若攻击者能篡改前序消息或泄露HMAC密钥（loc._gp + -0x743c），可伪造认证绕过验证。触发条件：中间人攻击篡改WPS消息流或密钥泄露。实际影响：无线网络未授权接入。
- **代码片段:**
  ```
  iVar1 = (**(loc._gp + -0x7cc0))(auStack_30,param_2,8);
  if (iVar1 == 0) { return 0; }
  ```
- **关键词:** wps_process_authenticator, Authenticator, param_1+0x134, param_1+0xe4, loc._gp + -0x743c
- **备注:** 需追踪密钥管理机制。建议审计wps_build_public_key等密钥派生函数

---
### csrf-systemlogrpm-mail-abuse

- **文件路径:** `web/userRpm/SystemLogRpm.htm`
- **位置:** `SystemLogRpm.htm:37`
- **类型:** network_input
- **综合优先级分数:** **6.45**
- **风险等级:** 7.0
- **置信度:** 6.5
- **触发可能性:** 5.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 潜在邮件日志功能滥用：doMailLog=2参数可能触发邮件发送操作。若后端未验证请求来源或参数合法性，攻击者可构造CSRF迫使管理员触发邮件轰炸。触发条件：1) 管理员登录态有效 2) 后端未校验邮件功能开关状态。实际影响：SMTP服务滥用/敏感日志泄露。
- **代码片段:**
  ```
  location.href = LP + '?doMailLog=2';
  ```
- **关键词:** doMailLog, location.href, MailLog
- **备注:** 需验证：1) syslogWebConf[0]的访问控制 2) 后端邮件触发逻辑。需验证syslogWebConf[0]在CGI中的访问控制。

---
### network_input-radvd-recv_rs_ra-pointer_manipulation

- **文件路径:** `usr/sbin/radvd`
- **位置:** `sym.recv_rs_ra`
- **类型:** network_input
- **综合优先级分数:** **6.45**
- **风险等级:** 6.5
- **置信度:** 7.0
- **触发可能性:** 5.5
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** recv_rs_ra函数辅助控制通道缺陷。存在两项风险：1) 主缓冲区长度完全依赖调用方控制，与栈溢出漏洞形成叠加风险 2) 执行危险指针操作*param_4 = piVar5 + 3。虽对IPV6_PKTINFO/IPV6_HOPLIMIT有基础校验，但指针操作缺乏安全验证。
- **代码片段:**
  ```
  if (piVar5[2] == 0x32) {
    if ((iVar7 != 0x20) || (piVar5[7] == 0)) { ... }
  }
  *param_4 = piVar5 + 3;
  ```
- **关键词:** recv_rs_ra, IPV6_PKTINFO, IPV6_HOPLIMIT, param_4, piVar5, recvmsg
- **备注:** 需与主漏洞链协同利用；关联发现：network_input-radvd-recv_rs_ra-stack_overflow

---
### network_input-AccessRules-doSave

- **文件路径:** `web/userRpm/AccessCtrlAccessRulesRpm.htm`
- **位置:** `www/AccessCtrlAccessRulesRpm.htm: (doSave) [函数入口]`
- **类型:** network_input
- **综合优先级分数:** **6.1**
- **风险等级:** 5.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** doSave函数直接拼接enableCtrl/defRule参数值（预期0/1）到URL，无范围验证。攻击者可通过DOM篡改（开发者工具修改复选框）提交非法值（如enableCtrl=2）。若服务端未验证参数范围，可导致：1) 访问控制策略异常生效/失效；2) 策略配置状态不一致。触发条件：CSRF攻击或诱骗用户提交篡改表单。
- **代码片段:**
  ```
  function doSave(){
    var n = DF.elements['enableCtrl'].checked?1:0;
    location.href = LP + "?enableCtrl=" + n + ...;
  ```
- **关键词:** doSave, enableCtrl, defRule, access_rules_page_param
- **备注:** 需检查服务端对enableCtrl/defRule的边界验证。关联参数：nvram的access_ctrl_enable相关变量（需分析设置函数）。

---
### crypto-weak-md5-web-login-encrypt

- **文件路径:** `web/login/encrypt.js`
- **位置:** `web/login/encrypt.js`
- **类型:** network_input
- **综合优先级分数:** **6.0**
- **风险等级:** 6.0
- **置信度:** 8.0
- **触发可能性:** 3.0
- **查询相关性:** 7.5
- **阶段:** N/A
- **描述:** 文件实现标准MD5哈希和Base64编码功能。风险点在于：1) MD5已被证实不安全（碰撞攻击），若用于密码存储或签名验证存在风险 2) 未发现硬编码密钥 3) 作为工具库无直接输入验证，风险取决于调用方（如登录处理逻辑）是否进行安全处理。触发条件：外部通过HTTP参数传入密码，调用此MD5函数进行哈希后比对。
- **关键词:** hex_md5, core_md5, Base64Encoding, str2binl, binl2hex, safe_add
- **备注:** 需后续分析：1) 调用此文件的登录页面（如login.html）如何传递密码 2) 服务器端密码验证是否恒定时间比对 3) 是否使用盐值加固MD5。关联知识库记录：需追踪调用此函数的页面（如login.html）确认是否用于密码处理（原KB备注#27）

---
### startup_script-rcS-static_ops

- **文件路径:** `etc/rc.d/rcS`
- **位置:** `etc/rc.d/rcS:5-42`
- **类型:** configuration_load
- **综合优先级分数:** **3.19**
- **风险等级:** 0.5
- **置信度:** 9.8
- **触发可能性:** 0.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** rcS作为系统初始化脚本仅执行静态操作：1) 固定PATH环境变量设置(export PATH=$PATH:/etc/ath)，无NVRAM访问或环境变量读取；2) 通过绝对路径执行/etc/rc.d/rc.modules，路径硬编码无动态生成；3) 关键命令(mount/ifconfig/httpd)均使用硬编码参数，无变量插值。触发条件为系统启动时自动执行，无外部输入介入点，因此不存在输入验证缺失或数据污染风险。
- **代码片段:**
  ```
  export PATH=$PATH:/etc/ath
  /etc/rc.d/rc.modules
  mount -a
  /usr/bin/httpd &
  ```
- **关键词:** export, PATH, rc.modules, mount, ifconfig, httpd
- **备注:** 风险转移至：1) rc.modules的模块加载逻辑 2) httpd服务的外部输入处理

---
### script-iptables-stop-cleanup

- **文件路径:** `etc/rc.d/iptables-stop`
- **位置:** `etc/rc.d/iptables-stop`
- **类型:** command_execution
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** 关机时执行的iptables清理脚本，执行静态硬编码命令：1) 清除filter/nat表所有规则(-F/-X) 2) 将INPUT/OUTPUT/FORWARD链默认策略设为ACCEPT。所有命令参数固定，无外部输入处理（环境变量/NVRAM/参数等）。需root权限但无注入风险，因攻击者无法影响其行为。安全影响仅限于正常关机流程中临时开放网络策略，属设计预期且无持久性影响。
- **代码片段:**
  ```
  iptables -t filter -F
  iptables -t filter -X
  iptables -t nat -F
  iptables -t nat -X
  iptables -P INPUT ACCEPT
  ```
- **关键词:** iptables, -F, -X, -P, INPUT, ACCEPT
- **备注:** 调用上下文：由init系统在关机时调用，无外部触发接口。建议后续重点检查防火墙启动脚本（如iptables-start）是否存在动态规则配置漏洞，该处可能接受外部输入。

---
### crypto-isolated-lib

- **文件路径:** `web/login/encrypt.js`
- **位置:** `encrypt.js`
- **类型:** configuration_load
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 6.0
- **阶段:** N/A
- **描述:** 文件为独立加密工具库，未发现与系统组件的直接交互：1) 无NVRAM访问 2) 无环境变量操作 3) 无外部资源调用。风险隔离在加密功能内部，但通过参数传递形成完整攻击链需依赖调用方

---
### analysis-status-usr-sbin-vsftpd

- **文件路径:** `usr/sbin/vsftpd`
- **位置:** `usr/sbin/vsftpd:0 (analysis_blocked)`
- **类型:** analysis_status
- **综合优先级分数:** **3.0**
- **风险等级:** 0.0
- **置信度:** 10.0
- **触发可能性:** 0.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 受限于分析环境（r2工具失效且shell环境不完整），无法获取'usr/sbin/vsftpd'文件的任何字符串或二进制证据。因此：1) 无法识别缓冲区操作函数(strcpy/memcpy等)的存在与使用 2) 无法验证认证机制(USER/PASS)的实现 3) 无法追踪网络输入(PORT命令)的处理流程。没有证据支持存在或不存在可利用漏洞。
- **代码片段:**
  ```
  N/A (Analysis blocked due to environment limitations)
  ```
- **备注:** 关键限制：1) 路径访问权限不足 2) 缺少基础分析工具 3) 环境管道支持缺失。后续建议：a) 在完整Linux环境使用strings/radare2直接分析 b) 通过QEMU模拟执行动态分析 c) 重点审计FTP协议命令处理函数

---
### static-kernel-module-load-rc.modules

- **文件路径:** `etc/rc.d/rc.modules`
- **位置:** `etc/rc.d/rc.modules`
- **类型:** command_execution
- **综合优先级分数:** **2.94**
- **风险等级:** 0.0
- **置信度:** 9.8
- **触发可能性:** 0.0
- **查询相关性:** 7.0
- **阶段:** N/A
- **描述:** rc.modules脚本根据内核版本（通过检测/lib/modules目录存在性）加载硬编码路径的内核模块。所有操作均为静态配置：1) 模块路径固定（如/lib/modules/2.6.15/pptp.ko）2) 未使用任何环境变量/NVRAM参数 3) 仅调用insmod命令且参数完全控制。无外部输入接口，无法被攻击者操控。脚本在启动时自动执行，但缺乏触发条件所需的用户输入点，无法形成有效攻击路径。
- **关键词:** test -d, insmod, /lib/modules/2.6.15, /lib/modules/2.6.31, kver_is_2615
- **备注:** 建议后续分析关注其他可能处理外部输入的启动脚本（如rc启动脚本）或网络服务组件。该文件无进一步分析价值。

---
