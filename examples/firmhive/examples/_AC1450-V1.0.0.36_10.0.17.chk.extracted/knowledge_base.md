# _AC1450-V1.0.0.36_10.0.17.chk.extracted (3 个发现)

---

### 命令注入-fcn.0001a1c0

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0x1a1c0 fcn.0001a1c0 和 acos_service:0x19ce8 fcn.00019ce8`
- **风险评分：** 8.5
- **置信度：** 9.0
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
- **关键词：** 命令行参数 via param_2, NVRAM 变量通过 acosNvramConfig_get 和 acosNvramConfig_match（如 *0x19ef4, *0x19f34）, 函数符号: fcn.0001a1c0, fcn.00019ce8, sym.imp.system, sym.imp.sprintf, 硬编码字符串地址: *0x19f30（格式字符串）
- **备注：** 漏洞具有高可利用性：攻击链完整（从输入点到命令执行），且作为已登录用户，攻击者可能通过二进制执行触发。建议进一步验证参数来源（如 web 后端调用），但当前证据足够确认风险。其他 system 调用（如 sym.imp.system(*0x1a2c8)）也应检查。

---
### command-injection-rc-main

- **文件/目录路径：** `sbin/rc`
- **位置：** `rc:0x0000f4f8-0x0000f610 (main function)`
- **风险评分：** 7.5
- **置信度：** 8.0
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
- **关键词：** lan_ifnames, _eval, MODALIAS
- **备注：** This vulnerability requires the attacker to have write access to the `lan_ifnames` NVRAM variable, which may be possible via web interfaces or CLI tools if access controls are weak. The hotplug event trigger might be exploitable through physical device insertion or other means. Further analysis is needed to confirm the availability of NVRAM write operations to non-root users and the frequency of 'platform:coma_dev' events. The use of `strncpy` with a fixed size limits the injection length to 32 bytes, but this is sufficient for many payloads. Additional vulnerabilities may exist in other command handlers (e.g., 'erase', 'write'), but this chain is the most directly exploitable.

---
### 命令注入-fcn.00019f38

- **文件/目录路径：** `sbin/acos_service`
- **位置：** `acos_service:0x19f38 fcn.00019f38`
- **风险评分：** 7.5
- **置信度：** 7.0
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
- **关键词：** 用户输入结构体 via param_2, NVRAM 配置通过 acosNvramConfig_match, 硬编码字符串地址: *0x1a1b8（格式字符串）, 函数符号: fcn.00019f38, sym.imp.system, sym.imp.sprintf
- **备注：** 漏洞可利用性高，但需要更详细验证触发条件（如 param_1 和 NVRAM 设置的具体影响）。攻击链从输入到命令执行完整，但置信度略低 due to 依赖条件。建议分析调用上下文以确认攻击者可控性。

---
