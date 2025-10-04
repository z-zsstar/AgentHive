# _US_AC6V1.0BR_V15.03.05.16_multi_TD01.bin.extracted (8 个发现)

---

### Library-Hijacking-ld.so.conf

- **文件/目录路径：** `etc_ro/ld.so.conf`
- **位置：** `文件: ld.so.conf`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 文件 'ld.so.conf' 具有全局可写权限（-rwxrwxrwx），允许任何用户（包括非 root 用户）修改动态链接器的库搜索路径。攻击者可以添加恶意库路径（如用户可控目录），导致库劫持攻击。触发条件：非 root 用户成功登录后，直接修改该文件并添加恶意路径；当系统或用户程序使用动态链接器运行时，会加载恶意库，执行任意代码。利用方式简单：攻击者只需写入恶意路径（例如 '/tmp/malicious_lib'），并确保恶意库存在且可执行，然后触发程序执行（如通过常见系统命令或服务）。缺少边界检查：文件没有权限限制，允许任意修改，且动态链接器默认信任配置路径。
- **代码片段：**
  ```
  /lib
  /usr/lib
  ```
- **关键词：** ld.so.conf
- **备注：** 此发现基于文件权限和内容证据，攻击链完整且可验证。建议进一步分析系统程序是否普遍使用动态链接（例如通过 'ldd' 命令），并检查是否有其他防护机制（如 SELinux）可能缓解此风险。关联文件可能包括动态链接器二进制（如 '/lib/ld-linux.so'）和用户可控目录中的恶意库。

---
### BufferOverflow-define_url_filter_rule_seq_show

- **文件/目录路径：** `lib/modules/url_filter.ko`
- **位置：** `url_filter.ko:0x08000b34 sym.define_url_filter_rule_seq_show`
- **风险评分：** 8.5
- **置信度：** 9.0
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
- **关键词：** NVRAM/环境变量: define_url_array, 全局变量: [sl, 0x3b0], 函数: seq_printf, __kmalloc, kfree, 硬编码地址: 0x08000c24
- **备注：** 漏洞需要攻击者能操纵 URL 过滤规则数据，可能通过 NVRAM set 操作或前端 API。建议进一步分析数据输入点（如 NVRAM 处理函数）以确认完整攻击链。关联文件可能包括用户空间组件或配置接口。

---
### Command-Injection-udev_event

- **文件/目录路径：** `sbin/udevd`
- **位置：** `文件:udevd 地址:0x0000a364 函数名:dbg.udev_event_run（入口） → 地址:0x00009ee8 函数名:dbg.udev_event_process → 地址:0x0000c09c 函数名:dbg.udev_device_event → 地址:0x00011184 函数名:dbg.udev_rules_get_name → 地址:0x0001036c 函数名:dbg.match_rule → 地址:0x00013bb4 函数名:dbg.run_program（危险操作）。`
- **风险评分：** 8.5
- **置信度：** 8.5
- **描述：** 不可信输入通过 udev 事件消息（例如设备插入事件）传播，最终在 `dbg.run_program` 中执行命令，导致命令注入。攻击者可通过伪造事件数据（如设备路径或属性）注入恶意命令。触发条件包括 udev 事件触发（如设备插入），且输入数据未被充分验证。潜在攻击方式包括执行任意系统命令以提升权限或破坏系统。相关代码逻辑涉及函数调用链：`dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.udev_device_event` → `dbg.udev_rules_get_name` → `dbg.match_rule` → `dbg.run_program`。
- **代码片段：**
  ```
  在 \`dbg.udev_event_process\` (0x00009ee8): \`dbg.strlcpy(piVar4 + 0x185, *(param_1 + 0x14), 0x100);\`（污点数据复制）
  在 \`dbg.run_program\` (0x00013bb4): \`sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360);\`（命令执行）
  ```
- **关键词：** udev 事件消息（IPC 或网络接口）, dbg.udev_event_run, dbg.udev_event_process, dbg.udev_device_event, dbg.udev_rules_get_name, dbg.match_rule, dbg.run_program, execv
- **备注：** 输入点（udev 事件消息）可能通过 IPC 或网络接口由攻击者控制；建议验证事件消息的解析逻辑和访问控制。

---
### Shadow-File-Permission-Misconfig

- **文件/目录路径：** `etc_ro/shadow`
- **位置：** `shadow:1`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** shadow 文件具有全局读、写、执行权限（777），这是一个严重的安全配置错误，允许任何用户（包括非 root 用户）读取 root 用户的密码哈希。哈希使用弱 MD5 算法（$1$），易于受到离线暴力破解攻击。攻击者作为已登录非 root 用户，可以执行 'cat /etc/shadow' 或类似命令直接获取哈希值，然后使用工具如 John the Ripper 或 hashcat 进行破解。如果 root 密码强度低（例如，常见密码或短密码），攻击者可以在较短时间内破解并获得 root 权限。触发条件简单：攻击者只需拥有 shell 访问权限并执行读取命令。约束条件包括攻击者需要有效登录凭据，但作为非 root 用户，他们本不应访问 shadow 文件。潜在攻击包括权限提升到 root，从而完全控制设备。利用方式涉及标准密码破解技术，无需复杂交互。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **关键词：** /etc/shadow
- **备注：** 风险评分基于权限配置错误和弱哈希算法，但实际利用成功取决于密码强度；建议立即修复文件权限为 600 并强制使用强密码。后续分析可验证其他用户哈希或检查系统日志以评估破解尝试。关联文件可能包括 /etc/passwd，但本分析仅聚焦于 shadow 文件。

---
### command-injection-cfmd

- **文件/目录路径：** `bin/cfmd`
- **位置：** `cfmd:0x0000adf4 (function fcn.0000adf4)`
- **风险评分：** 8.5
- **置信度：** 8.0
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
- **关键词：** NVRAM variables: lan.ip, wan1.macaddr, wan2.macaddr, lan.mask, iptv.stb.enable, IPC socket: /var/cfm_socket, Shared functions: GetCfmValue, doSystemCmd
- **备注：** The vulnerability relies on doSystemCmd using shell execution (e.g., via system() call), which is plausible given the command templates observed in strings (e.g., 'ifconfig %s down'). Full exploitation requires the attacker to set NVRAM variables through another interface (e.g., web GUI), but this is consistent with the attack scenario. Further analysis should verify the implementation of doSystemCmd in shared libraries like libcommon.so. Additional unsafe functions (strcpy, sprintf) are present but not directly linked to exploitable chains in this analysis.

---
### File-Deletion-udev_event

- **文件/目录路径：** `sbin/udevd`
- **位置：** `文件:udevd 地址:0x0000a364 函数名:dbg.udev_event_run → 地址:0x00009ee8 函数名:dbg.udev_event_process → 地址:0x0000c09c 函数名:dbg.udev_device_event → 地址:0x00011184 函数名:dbg.udev_rules_get_name → 地址:0x00013868 函数名:dbg.unlink_secure → 地址:0x00009620 函数名:sym.imp.unlink（危险操作）。`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 不可信输入通过 udev 事件消息传播，最终在 `sym.imp.unlink` 中删除文件，导致任意文件删除漏洞。攻击者可通过控制事件数据指定删除路径。触发条件包括 udev 事件处理中涉及文件删除操作（如设备移除）。潜在攻击方式包括删除关键系统文件导致拒绝服务或权限提升。相关代码逻辑：`dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.udev_device_event` → `dbg.udev_rules_get_name` → `dbg.unlink_secure` → `sym.imp.unlink`。
- **代码片段：**
  ```
  在 \`dbg.udev_event_process\` (0x00009ee8): \`dbg.strlcpy(piVar4 + 0x185, *(param_1 + 0x14), 0x100);\`（污点数据复制）
  在 \`dbg.unlink_secure\` (0x00013868): \`sym.imp.unlink(puVar16);\`（文件删除）
  ```
- **关键词：** udev 事件消息（IPC 或网络接口）, dbg.udev_event_run, dbg.udev_event_process, dbg.udev_device_event, dbg.udev_rules_get_name, dbg.unlink_secure, sym.imp.unlink
- **备注：** 攻击者需控制文件路径参数；建议检查 `dbg.unlink_secure` 中的路径过滤机制。

---
### Command-Injection-message_queue

- **文件/目录路径：** `sbin/udevd`
- **位置：** `文件:udevd 地址:0x0000a4e0 函数名:dbg.msg_queue_manager（入口） → 地址:0x0000a364 函数名:dbg.udev_event_run → 地址:0x00009ee8 函数名:dbg.udev_event_process → 地址:0x00013bb4 函数名:dbg.run_program（危险操作）。`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 不可信输入通过内部消息队列（IPC）传播，最终在 `dbg.run_program` 中执行命令，导致命令注入。攻击者可通过注入恶意队列元素（例如通过设备事件）来触发命令执行。触发条件是当精心构造的队列元素被处理时，绕过 `dbg.msg_queue_manager` 中的检查。潜在攻击方式包括注入命令数据，这些数据被格式化并执行而缺乏充分验证。相关代码逻辑：`dbg.msg_queue_manager` → `dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.run_program`。
- **代码片段：**
  ```
  在 \`dbg.msg_queue_manager\` (0x0000a4e0): \`dbg.udev_event_run(ppiVar6);\`（队列元素处理）
  在 \`dbg.run_program\` (0x00013bb4): \`sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360);\`（命令执行）
  ```
- **关键词：** 内部消息队列（IPC）, dbg.msg_queue_manager, dbg.udev_event_run, dbg.udev_event_process, dbg.run_program, execv
- **备注：** 需要进一步追踪队列填充函数（如通过设备事件接口）以确认用户可访问性；建议分析 NVRAM、环境变量或 IPC 套接字作为潜在输入源。

---
### Weak-DES-Hash-Passwd-Users

- **文件/目录路径：** `etc_ro/passwd`
- **位置：** `passwd:2-5`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** passwd 文件中多个用户（admin、support、user、nobody）使用弱 DES 密码哈希，且所有用户具有 UID 0（root 权限）。非 root 攻击者可通过读取 /etc/passwd 文件获取哈希值，利用工具（如 john 或 hashcat）破解弱 DES 哈希，从而获得这些用户的密码。攻击者然后可通过 'su' 或 SSH 登录这些用户，由于 UID 0，立即获得 root 权限。触发条件：攻击者具有对 /etc/passwd 的读访问权且密码强度弱；利用方式：离线破解哈希后登录；边界检查：无密码强度强制或哈希升级。
- **代码片段：**
  ```
  admin:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **关键词：** /etc/passwd, admin, support, user, nobody
- **备注：** 假设攻击者具有 /etc/passwd 读访问权（通常为世界可读），且 DES 哈希易破解（使用传统 crypt 算法）。建议验证这些账户是否启用登录，并检查密码策略。关联文件：无其他文件直接涉及；后续可分析认证流程或 setuid 程序。

---
