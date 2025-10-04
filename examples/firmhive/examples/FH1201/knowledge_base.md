# FH1201 (15 个发现)

---

### Command-Injection-wps_save

- **文件/目录路径：** `lib/libwifi.so`
- **位置：** `libwifi.so:0x00022950 sym.wps_save`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** The 'wps_save' function in 'libwifi.so' contains a command injection vulnerability due to unsanitized user input being passed directly to 'doSystemCmd'. The function takes three arguments (arg_c8h, arg_cch, arg_d0h), where 'arg_d0h' is used in formatted strings for 'doSystemCmd' calls without validation. An attacker can inject arbitrary commands by controlling 'arg_d0h', such as through semicolons or backticks, leading to command execution in the context of the process using this library. Trigger conditions include calling 'wps_save' with malicious 'arg_d0h', which could be achieved via network interfaces, IPC, or other components that invoke this function. The vulnerability allows full command execution, potentially leading to privilege escalation or system compromise if the process has elevated privileges.
- **代码片段：**
  ```
  0x00022950: lw a1, (arg_d0h)  ; Load user-controlled arg_d0h
  0x00022954: lw t9, -sym.imp.doSystemCmd(gp)  ; Load doSystemCmd function
  0x0002295c: jalr t9  ; Call doSystemCmd with format string 'nvram set %s_wps_mode=enabled' and a1
  Similar calls at 0x000229c8, 0x00022a24, etc., where arg_d0h is used in doSystemCmd without sanitization.
  ```
- **关键词：** wps_save, doSystemCmd, arg_d0h, nvram set
- **备注：** This vulnerability requires that 'wps_save' is callable with user-controlled input, which may be possible through web interfaces, API endpoints, or command-line tools. Further analysis is needed to identify specific call paths and interfaces that expose this function. The library is stripped, but exported functions are accessible. Assumes the attacking user has valid login credentials and can trigger the function call. Recommended to check for input validation in callers and implement sanitization of arguments passed to 'wps_save'.

---
### File-Permission-shadow_private

- **文件/目录路径：** `etc_ro/shadow_private`
- **位置：** `shadow_private:1`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 文件 'shadow_private' 权限设置为 777，允许任何用户读取，其中包含 root 用户的密码哈希（MD5: $1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1）。攻击者（非root用户）可以轻松读取该文件，提取哈希，并使用离线工具（如 John the Ripper）进行密码破解。如果密码强度弱，攻击者可能获得 root 权限，实现权限提升。触发条件简单：攻击者只需执行读取命令（如 'cat shadow_private'）。约束条件包括密码的复杂性和破解工具的有效性，但权限配置错误使得攻击可行。
- **代码片段：**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **关键词：** shadow_private
- **备注：** 此漏洞源于错误的文件权限配置。建议立即修改文件权限为仅 root 可读（如 600），并检查系统是否使用此文件进行认证。后续可验证密码强度以评估实际风险，但当前证据表明攻击链完整。

---
### StackBufferOverflow-CommandInjection-vpnUsrLoginAddRoute

- **文件/目录路径：** `lib/libvpn.so`
- **位置：** `libvpn.so:0x000031e4 sym.vpnUsrLoginAddRoute`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** The function 'sym.vpnUsrLoginAddRoute' in 'libvpn.so' contains a stack buffer overflow and command injection vulnerability due to improper handling of input from login files. The function reads data from files in '/tmp/pptp/logininfo%d' or '/tmp/l2tp/logininfo%d' using sscanf with the format "%[^;];%[^;];%[^;];%[^;];%s", writing string data to fixed-size buffers, including a 4-byte uint variable (&uStack_84), causing stack overflow. The overflowed data is then used in system commands executed via 'doSystemCmd', such as 'ip rule add' and 'ip route add', without sanitization, allowing command injection if input contains shell metacharacters. An attacker with valid login credentials can exploit this by creating a malicious login file in the world-writable /tmp directory and triggering the VPN login process, leading to arbitrary command execution as the process user (likely root or a privileged user).
- **代码片段：**
  ```
  iVar1 = (**(iStack_1a8 + -0x7f5c)) (auStack_140,"%[^;];%[^;];%[^;];%[^;];%s" + *(iStack_1a8 + -0x7fe0),auStack_c0,&uStack_84, acStack_180,auStack_ac,auStack_98);
  ...
  (**(iStack_1a8 + -0x7f4c)) ("ip rule add to %s table wan%d prio %d" + *(iStack_1a8 + -0x7fe0),&uStack_84, uStackX_4, "t mangle %s POSTROUTING -o %s -j TCPMSS -p tcp --syn \t\t\t--set-mss %d");
  ```
- **关键词：** /tmp/pptp/logininfo%d, /tmp/l2tp/logininfo%d, vpn.ser.pptpserver, vpn.ser.l2tpserver, vpn.ser.pptpdWanid, vpn.ser.l2tpdWanid, lan.ip, lan.mask
- **备注：** The vulnerability requires the function to be called with a user-controlled parameter for the login file index. Cross-references show this function is called from other VPN-related processes, likely during user authentication. Further analysis should verify the caller context and test exploitability with specific input. The use of 'doSystemCmd' with unsanitized input is a common pattern in other functions like 'sym.set_vpn_nat', suggesting broader issues.

---
### Permission-Vulnerability-Shadow

- **文件/目录路径：** `var/etc/shadow`
- **位置：** `文件: shadow (完整路径: /etc/shadow)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 '/etc/shadow' 文件中发现 root 用户的 MD5 密码哈希（$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1），且文件权限设置为 777（-rwxrwxrwx），允许任何非 root 用户读取、写入和执行。具体表现：攻击者作为非 root 用户登录后，可直接访问该文件读取密码哈希。触发条件：攻击者拥有有效登录凭据（非 root 用户）并执行文件读取操作。约束条件和边界检查：文件缺少适当的访问控制，无权限验证。潜在攻击和利用方式：攻击者可以读取哈希后进行离线暴力破解（MD5 哈希易受攻击，尤其如果密码弱），成功后可获得 root 权限；或者直接修改文件内容（如清空 root 密码）以提升权限。相关代码逻辑或技术细节：文件为系统密码存储文件，通常应限制为 root 只读，但这里权限配置错误。
- **代码片段：**
  ```
  文件内容: root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **关键词：** /etc/shadow
- **备注：** 此发现基于明确的文件内容和权限证据。攻击链完整：非 root 用户读取哈希 → 离线破解 → 获得 root 权限。MD5 哈希可能容易破解，但实际可利用性取决于密码强度；建议进一步验证密码复杂性或检查是否有其他保护机制（如哈希加盐）。关联文件：无其他直接关联，但可能影响系统认证组件。后续分析方向：检查其他敏感文件（如 passwd）的权限，或分析认证流程以确认漏洞影响范围。

---
### BufferOverflow-connect_pppol2tp

- **文件/目录路径：** `lib/pppol2tp.so`
- **位置：** `pppol2tp.so:0x1a78 connect_pppol2tp`
- **风险评分：** 8.5
- **置信度：** 8.0
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
- **关键词：** PPPoL2TP socket descriptor, global variable at offset 0x2850
- **备注：** 漏洞需要攻击者能访问PPPoL2TP套接字，可能通过网络服务或IPC实现。建议进一步验证套接字初始化逻辑和全局变量来源。关联函数：disconnect_pppol2tp。后续分析方向：检查调用此函数的组件（如pppd守护进程）以确认输入源和利用可行性。

---
### Command-Injection-formexeCommand

- **文件/目录路径：** `bin/httpd`
- **位置：** `httpd:0x0046eefc sym.formexeCommand`
- **风险评分：** 8.0
- **置信度：** 9.0
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
- **关键词：** cmdinput, /tmp/cmdTmp.txt, websGetVar, doSystemCmd, formexeCommand
- **备注：** 漏洞利用链完整：从 HTTP 输入点 ('cmdinput') 到危险操作 (doSystemCmd)。httpd 通常以 root 权限运行，因此命令执行可能获得 root 权限。建议进一步验证 `formexeCommand` 的具体 URL 端点，但代码分析显示明确的漏洞模式。

---
### vulnerability-shadow

- **文件/目录路径：** `etc_ro/shadow`
- **位置：** `shadow:1 (file path)`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 发现 'shadow' 文件对所有用户可读（权限 777），包含 root 用户的 MD5 密码哈希（$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1）。攻击者（非 root 用户）可以直接读取该文件，获取密码哈希，并通过离线破解（如使用工具如 John the Ripper）尝试获得 root 密码。一旦破解成功，攻击者可提升权限至 root，完全控制设备。触发条件简单：攻击者拥有有效登录凭据（非 root 用户）并可以访问文件系统。约束条件：密码强度影响破解难度，但 MD5 哈希相对脆弱，易于破解常见密码。潜在攻击方式包括直接文件读取和密码破解工具的使用。
- **代码片段：**
  ```
  File content: root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  File permissions: -rwxrwxrwx
  ```
- **关键词：** shadow
- **备注：** 此发现基于直接证据：文件可读且包含敏感哈希。建议进一步验证密码强度或检查其他相关文件（如 passwd）以确认完整攻击面。攻击链完整：从非 root 用户读取文件到潜在权限提升。

---
### StackBufferOverflow-upnp_device_attach

- **文件/目录路径：** `usr/lib/libupnp.so`
- **位置：** `libupnp.so:0x7700 sym.upnp_device_attach`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** Stack-based buffer overflow in the sym.upnp_device_attach function due to use of strcpy without bounds checking. The function copies a string from UPnP device data (external input) to a fixed-size stack buffer (at sp+0xa0). When a crafted UPnP message contains a device string longer than 212 bytes, it overflows the buffer and overwrites the saved return address (at sp+0x174), enabling arbitrary code execution. Trigger condition: attacker sends a malicious UPnP device announcement or similar message. Exploitation requires the attacker to control the device string content and length to overwrite the return address with shellcode or ROP chain addresses.
- **代码片段：**
  ```
  0x000076f8      lw t9, -sym.imp.strcpy(gp)
  0x000076fc      addiu a1, s3, 4             ; source: device data string
  0x00007700      jalr t9                     ; call strcpy
  0x00007704      move a0, s5                ; destination: stack buffer at sp+0xa0
  ```
- **关键词：** UPnP device description messages, network interface
- **备注：** The stack buffer has a fixed size, and the distance to the return address is 212 bytes, making overflow straightforward. Assumes no stack protections (e.g., ASLR) are enabled in the firmware environment. Recommended to verify input source in upnp_ifattach and network handling functions. No other exploitable vulnerabilities found in strcpy/strcat usage after full analysis.

---
### XSS-wirelessScan-fillAcc

- **文件/目录路径：** `webroot/js/privatejs/wireless_extra.js`
- **位置：** `wireless_extra.js: wirelessScan函数 和 fillAcc函数`
- **风险评分：** 7.5
- **置信度：** 8.5
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
- **关键词：** /goform/ApclientScan, /goform/WrlExtraGet, wireless_extra.js
- **备注：** 这是一个反射型XSS漏洞，需要用户交互（执行扫描）。由于攻击者已拥有登录凭据，漏洞可被用于提升权限或持久化攻击。建议对所有用户输入进行HTML转义后再使用innerHTML。需要进一步验证后端是否对SSID长度和内容有过滤，但客户端缺乏转义是确定的。关联文件：可能影响其他使用扫描功能的页面。

---
### XSS-subForm

- **文件/目录路径：** `webroot/js/gozila.js`
- **位置：** `gozila.js: ~line 650 (subForm 函数)`
- **风险评分：** 7.5
- **置信度：** 8.0
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
- **关键词：** CA (配置数组), 表单字段名（通过 form2Cfg 处理）, genForm 生成的隐藏输入字段
- **备注：** 此漏洞需要攻击者已获得登录凭据，但作为非 root 用户，可利用此漏洞提升权限或危害设备安全。建议进一步验证后端是否对输入进行额外过滤，并检查其他使用 `innerHTML` 的地方（如 `setpage` 和 `decodeSSID` 函数）。后续分析应关注表单提交的后端处理流程，以确认完整的攻击链。

---
### buffer-overflow-ufilter-url-parsing

- **文件/目录路径：** `usr/sbin/ufilter`
- **位置：** `ufilter:0x004042c0 fcn.004042c0, ufilter:0x00404450 fcn.00404450`
- **风险评分：** 7.5
- **置信度：** 8.0
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
- **关键词：** command-line arguments, sym.set_url, fcn.004042c0, fcn.00404450, /dev/ufilter
- **备注：** The vulnerability is directly exploitable via command-line arguments, and the attack chain is verifiable through code analysis. However, actual exploitation may require specific conditions, such as the binary being executable by non-root users or having sufficient privileges. Further analysis could involve testing for privilege escalation if 'ufilter' runs with elevated permissions. The functions fcn.004042c0 and fcn.00404450 are called from sym.set_url, which handles URL filter settings. Additional input points like other filter modules (e.g., MAC filtering) should be investigated for similar issues.

---
### command-injection-igd_osl_nat_config

- **文件/目录路径：** `usr/sbin/igd`
- **位置：** `igd:0x00402084 igd_osl_nat_config (函数入口), igd:0x0040226c (strcat 调用追加用户输入), igd:0x00402190 (_eval 调用执行命令)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'igd' 二进制文件中发现一个命令注入漏洞，允许攻击者通过 UPnP AddPortMapping 操作执行任意命令。漏洞源于 igd_osl_nat_config 函数在构建 'igdnat' 命令字符串时未对用户输入的 NewInternalClient 参数进行适当过滤。攻击者可以注入恶意命令分隔符（如分号或反引号）到 NewInternalClient 字段，导致 _eval 函数执行额外命令。触发条件包括：攻击者发送恶意的 UPnP 请求到 /control?WANIPConnection 端点，调用 AddPortMapping 操作并设置恶意的 NewInternalClient 值。利用方式例如设置 NewInternalClient 为 '127.0.0.1; malicious_command'，从而在设备上以服务权限（可能为 root）执行任意命令。
- **代码片段：**
  ```
  关键代码片段来自 igd_osl_nat_config 函数：
  - 0x004020f4: sprintf 构建基础命令 'igdnat -i %s -eport %d -iport %d -en %d'
  - 0x0040226c: strcat 追加 ' -client ' 和用户控制的 s1->1c 字段（NewInternalClient）
  - 0x00402190: _eval 执行最终命令字符串，输出重定向到 /dev/console
  完整命令示例：'igdnat -i eth0 -eport 80 -iport 8080 -en 1 -client 127.0.0.1; malicious_command'
  ```
- **关键词：** NewInternalClient, /control?WANIPConnection, igdnat, router_disable, igd_port, /tmp/igd.pid
- **备注：** 此漏洞需要攻击者能访问 UPnP 服务（通常监听局域网）。建议验证 _eval 函数的具体实现以确认命令执行行为。此外，igd_portmap_add 函数中多次使用 strcpy 可能存在缓冲区溢出，但命令注入攻击链更直接且易于利用。后续分析应关注其他 UPnP 操作（如 DeletePortMapping）是否也存在类似问题。

---
### BufferOverflow-return_web_disable_page

- **文件/目录路径：** `lib/modules/u_filter.ko`
- **位置：** `u_filter.ko:0x08004f68 sym.return_web_disable_page`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A buffer overflow vulnerability exists in the 'return_web_disable_page' function when generating HTTP redirect responses. The function uses 'sprintf' to format a response string that includes user-controlled URL data from network packets without proper length validation. Specifically, the format string 'HTTP/1.1 302 Moved Temporarily\r\nLocation: http://%s/disable.asp\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-length: %d\r\n\r\n%s' incorporates the user-provided URL via the '%s' specifier. The buffer 's2' (pointing to skb data) has limited size, and excessive input can overflow it, corrupting kernel heap memory. Attackers with network access can craft long URLs to trigger this overflow, potentially leading to code execution or denial-of-service. The vulnerability is triggered when a URL matches the filter criteria, causing 'url_filter' to call 'return_web_disable_page'.
- **代码片段：**
  ```
  0x08004f5c      0000053c       lui a1, $LC3                ; RELOC 32 $LC3 @ 0x080059b8
  0x08004f60      21306002       move a2, s3
  0x08004f64      21204002       move a0, s2
  0x08004f68      09f82002       jalr s1                      ; sprintf(s2, $LC3, s3, v0, s7)
  ; $LC3: "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://%s/disable.asp\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-length: %d\r\n\r\n%s"
  ```
- **关键词：** URL data from network packets, skb->data buffer, sprintf format string
- **备注：** The vulnerability requires the attacker to send a crafted network packet with a long URL that triggers the URL filter. The skb buffer management might mitigate some risks, but the lack of input sanitization in sprintf makes exploitation plausible. Further analysis is needed to determine exact buffer sizes and exploitation feasibility. Associated functions: sym.url_filter, sym.set_url_filter.

---
### WeakHash-passwd_private

- **文件/目录路径：** `etc_ro/passwd_private`
- **位置：** `文件: passwd_private`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 文件 'passwd_private' 包含 root 用户的密码哈希（MD5格式：$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1），暴露了敏感认证信息。攻击者作为已登录非 root 用户可能能够读取此文件（由于类似 /etc/passwd 的文件通常对所有用户可读），提取哈希后使用离线工具（如 John the Ripper 或 Hashcat）进行破解。如果密码强度弱（例如常见密码），破解可能成功，使攻击者获得 root 密码并提升权限。触发条件是攻击者具有文件读取权限；缺少边界检查包括使用弱哈希算法（MD5 易受碰撞和彩虹表攻击）和可能不严格的文件权限设置。潜在攻击方式包括直接破解哈希后通过 su 或登录机制切换至 root 用户。
- **代码片段：**
  ```
  root:$1$nalENqL8$jnRFwb1x5S.ygN.3nwTbG1:0:0:root:/:/bin/sh
  ```
- **关键词：** passwd_private
- **备注：** 证据基于文件内容分析；需要进一步验证文件权限（例如使用 'ls -l passwd_private' 确认非 root 用户读取权限）和密码实际强度（例如通过破解测试）。建议升级至更强哈希算法（如 bcrypt 或 SHA-512）并限制文件访问权限仅限 root 用户。此发现可能关联其他认证组件，如登录守护进程。

---
### Privilege-Escalation-passwd

- **文件/目录路径：** `etc_ro/passwd`
- **位置：** `passwd`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** The passwd file contains encrypted passwords for multiple default user accounts (admin, support, user, nobody) all with UID 0 (root privileges). This exposes a privilege escalation vulnerability: an attacker with non-root user credentials can read the passwd file (typically world-readable) and perform offline password cracking to obtain root access. The attack chain is: 1) Attacker logs in as a non-root user; 2) Attacker reads /etc/passwd; 3) Attacker extracts password hashes; 4) Attacker uses tools like John the Ripper to crack weak passwords; 5) If successful, attacker gains root privileges. Trigger conditions include weak or default passwords, and no shadow password protection. Potential exploitation involves brute-force or dictionary attacks on the hashes.
- **代码片段：**
  ```
  admin:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **关键词：** passwd
- **备注：** The risk score is based on the complete attack chain and clear security impact (privilege escalation). Confidence is moderated as password strength is unverified; if passwords are default or weak, exploitation is highly likely. Recommend further analysis of password hashes for common defaults, checking for /etc/shadow file existence, and reviewing authentication mechanisms. This finding should be prioritized for password policy enforcement and shadow password implementation.

---
