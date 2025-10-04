# _AC1450-V1.0.0.36_10.0.17.chk.extracted - 验证报告 (3 个发现)

---

## 原始信息

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0x1a1c0 fcn.0001a1c0 和 acos_service:0x19ce8 fcn.00019ce8`
- **描述：** 在函数 fcn.0001a1c0 中发现命令注入漏洞。当参数数量（param_1）大于 1 时，函数从命令行参数（param_2[1]）获取用户输入，并传递给 fcn.00019ce8。在 fcn.00019ce8 中，输入直接用于 sprintf 格式化字符串 'ifconfig %s del %s/%s'，然后通过 system 执行，未经过滤或转义。攻击者可通过注入 shell 元字符（如分号、反引号）执行任意命令。触发条件：攻击者执行 'acos_service' 并传递恶意参数（如通过 web 接口或 CLI），且 NVRAM 配置检查（acosNvramConfig_match）可能影响路径，但作为已登录用户，攻击者可操纵设置或直接触发。利用方式：构造参数如 'eth0; malicious_command'，导致命令执行。
- **代码片段：**
  ```
  // fcn.0001a1c0 片段
  if (param_1 != 1 && param_1 + -1 < 0 == SBORROW4(param_1,1)) {
      // ... NVRAM 检查 ...
      fcn.00019ce8(*0x1a2c4, *(param_2 + 4)); // 传递用户输入
  }
  // fcn.00019ce8 片段
  sym.imp.sprintf(puVar7 + -0x84, *0x19f30, param_2, uVar3); // param_2 是用户输入，格式字符串为 'ifconfig %s del %s/%s'
  sym.imp.system(puVar7 + -0x84); // 执行格式化后的命令
  ```
- **备注：** 漏洞具有高可利用性：攻击链完整（从输入点到命令执行），且作为已登录用户，攻击者可能通过二进制执行触发。建议进一步验证参数来源（如 web 后端调用），但当前证据足够确认风险。其他 system 调用（如 sym.imp.system(*0x1a2c8)）也应检查。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据如下：在 fcn.0001a1c0 中，当参数数量（param_1）大于 1 时，从命令行参数（param_2[1]）获取用户输入并传递给 fcn.00019ce8。在 fcn.00019ce8 中，用户输入直接用于 sprintf 格式化字符串 'ifconfig %s del %s/%s'（地址 0x00019e6c），然后通过 system 执行（地址 0x00019e7c），未经过滤或转义。攻击者模型为已登录用户（通过 web 接口或 CLI 执行二进制），可控制输入并触发路径。完整攻击链：输入可控（命令行参数）、路径可达（参数数量 > 1 且通过 NVRAM 检查）、实际影响（任意命令执行）。PoC：作为已登录用户，执行 './acos_service dummy "eth0; touch /tmp/pwned"'，这将生成命令 'ifconfig eth0; touch /tmp/pwned del ...'，导致注入的命令 'touch /tmp/pwned' 执行。漏洞风险高，因为允许任意命令执行。

## 验证指标

- **验证时长：** 172.26 秒
- **Token 使用量：** 92746

---

## 原始信息

- **文件/目录路径：** `sbin/rc`
- **位置：** `rc:0x0000f4f8-0x0000f610 (main function)`
- **描述：** A command injection vulnerability exists in the hotplug event handling code of the 'rc' binary. The NVRAM variable `lan_ifnames` is retrieved and used to construct a shell command via `_eval` without proper sanitization for shell metacharacters. When MODALIAS is 'platform:coma_dev', the code parses `lan_ifnames` for interface names and executes 'wl -i <interface> down'. An attacker with write access to `lan_ifnames` can inject malicious commands by including semicolons, backticks, or other metacharacters. For example, setting `lan_ifnames` to 'eth0; malicious_command' results in the execution of 'malicious_command' with root privileges. The trigger condition is a hotplug event with MODALIAS='platform:coma_dev', which could be induced by hardware events or potentially simulated by an attacker.
- **代码片段：**
  ```
  0x0000f4f8      ldr r0, str.lan_ifnames     ; 'lan_ifnames'
  0x0000f500      bl sym.imp.nvram_get        ; Get value from NVRAM
  ...
  0x0000f524      mov r2, 0x20                ; 32 bytes
  0x0000f528      mov r1, sl                  ; Source string from NVRAM
  0x0000f52c      mov r0, r4                  ; Destination buffer
  0x0000f530      bl sym.imp.strncpy          ; Copy interface name
  ...
  0x0000f5fc      str r8, [var_2ch]           ; 'wl'
  0x0000f600      str sb, [var_30h]           ; '-i'
  0x0000f604      str r4, [var_34h]           ; Interface name from buffer
  0x0000f608      str fp, [var_38h]           ; 'down'
  0x0000f60c      str ip, [var_3ch]           ; Null terminator
  0x0000f610      bl sym.imp._eval            ; Execute command
  ```
- **备注：** This vulnerability requires the attacker to have write access to the `lan_ifnames` NVRAM variable, which may be possible via web interfaces or CLI tools if access controls are weak. The hotplug event trigger might be exploitable through physical device insertion or other means. Further analysis is needed to confirm the availability of NVRAM write operations to non-root users and the frequency of 'platform:coma_dev' events. The use of `strncpy` with a fixed size limits the injection length to 32 bytes, but this is sufficient for many payloads. Additional vulnerabilities may exist in other command handlers (e.g., 'erase', 'write'), but this chain is the most directly exploitable.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确：在 'sbin/rc' 的 main 函数中，代码在处理 hotplug 事件时（MODALIAS='platform:coma_dev'），通过 nvram_get 获取 'lan_ifnames' 变量，使用 strncpy 复制到缓冲区（限制 32 字节），并直接通过 _eval 执行 'wl -i <interface> down' 命令，未对输入进行消毒。攻击者模型：攻击者需具有写入 NVRAM 变量的能力（如通过弱访问控制的 web 接口或 CLI 工具），并能触发 hotplug 事件（如通过物理设备插入或软件模拟设置 MODALIAS 环境变量）。完整攻击链：攻击者设置 'lan_ifnames' 为恶意值（如 'eth0; touch /tmp/pwned'），当触发事件时，命令 'wl -i eth0; touch /tmp/pwned down' 以 root 权限执行，导致任意命令注入。证据来自反编译代码：nvram_get 调用（0x0000f4f8-0x0000f500）、strncpy（0x0000f524-0x0000f530）、命令构建（0x0000f5fc-0x0000f60c）和 _eval 执行（0x0000f610）。路径可达性通过 MODALIAS 检查（0x0000f4d4-0x0000f4e0）和 hotplug 处理（0x0000f47c-0x0000f484）确认。实际影响为 root 权限命令执行，风险高。

## 验证指标

- **验证时长：** 363.45 秒
- **Token 使用量：** 207446

---

## 原始信息

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0x19f38 fcn.00019f38`
- **描述：** 在函数 fcn.00019f38 中发现命令注入漏洞。当 param_1 不等于 3 且小于 3 时，函数从用户输入结构体（param_2 的偏移 4 和 8）获取数据，使用 sprintf 嵌入命令字符串（地址 *0x1a1b8），然后通过 system 执行。输入未经过滤，允许攻击者注入任意命令。触发条件：依赖 param_1 值和 NVRAM 检查（acosNvramConfig_match），但作为已登录用户，攻击者可能通过参数控制触发路径。利用方式：操纵输入参数包含恶意命令（如 'eth0; rm -rf /'），导致权限提升或设备破坏。
- **代码片段：**
  ```
  // fcn.00019f38 片段
  else if (param_1 != 3 && param_1 + -3 < 0 == SBORROW4(param_1,3)) {
      iVar1 = puVar7 + -0x100;
      uVar5 = *(param_2 + 4);
      uVar2 = *(param_2 + 8);
      *(puVar7 + -0x108) = *(param_2 + 0xc);
      sym.imp.sprintf(iVar1, *0x1a1b8, uVar5, uVar2); // 用户输入嵌入命令
      sym.imp.printf(*0x1a1bc, iVar1);
      sym.imp.system(iVar1); // 执行命令
      return 0;
  }
  ```
- **备注：** 漏洞可利用性高，但需要更详细验证触发条件（如 param_1 和 NVRAM 设置的具体影响）。攻击链从输入到命令执行完整，但置信度略低 due to 依赖条件。建议分析调用上下文以确认攻击者可控性。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 经过对代码的详细分析，验证了命令注入漏洞的存在，但警报描述在触发条件上不准确。实际漏洞触发条件是当 param_1 (argc) > 3 时执行漏洞代码，而非警报描述的 param_1 != 3 且 param_1 < 3。漏洞代码在函数 fcn.00019f38 的 0x1a13c-0x1a16c 处，使用 sprintf 将用户输入的 argv[1]、argv[2] 和 argv[3] 直接嵌入到 'ifconfig %s add %s/%s' 命令字符串中，然后通过 system 执行，输入未经过滤。攻击者模型为已通过身份验证的本地用户或具有 shell 访问权限的攻击者，能够控制 acos_service 的启动参数。利用方式：通过创建程序名包含 'dhcp6c_up' 的符号链接或直接调用，并传递至少三个参数，其中第三个参数包含命令注入载荷（如 '24; rm -rf /'），导致以 root 权限执行任意命令。PoC 步骤：1) ln -s /sbin/acos_service /tmp/dhcp6c_up；2) /tmp/dhcp6c_up eth0 192.168.1.1 '24; malicious_command'。生成的命令 'ifconfig eth0 add 192.168.1.1/24; malicious_command' 将被执行，实现权限提升或设备破坏。

## 验证指标

- **验证时长：** 417.81 秒
- **Token 使用量：** 275246

---

