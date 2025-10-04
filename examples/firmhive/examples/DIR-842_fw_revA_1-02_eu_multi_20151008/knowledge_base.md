# DIR-842_fw_revA_1-02_eu_multi_20151008 (16 个发现)

---

### command-injection-main

- **文件/目录路径：** `bin/iapp`
- **位置：** `iapp:0x004021ec 和 0x00402220 (main 函数)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 'iapp' 程序中发现一个命令注入漏洞，允许攻击者通过恶意接口名称执行任意命令。程序使用 system 调用执行路由命令（如 'route delete' 和 'route add'），其中接口名称直接从命令行参数获取并通过 sprintf 嵌入命令字符串，未进行任何输入过滤或验证。攻击者可以提供包含 shell 元字符（如分号或反引号）的接口名称，从而注入并执行任意命令。由于程序通常以 root 权限运行（如创建 /var/run/iapp.pid），成功利用可能导致完全系统控制。触发条件：攻击者拥有有效登录凭据并能够执行 iapp 命令时，提供恶意接口名称（例如 'wlan0; malicious_command'）。利用方式简单直接，无需复杂的内存操作。
- **代码片段：**
  ```
  0x004021ec: 8f99805c lw t9, -sym.imp.sprintf(gp)
  0x004021f0: 00602821 move a1, v1 ; 命令字符串 'route delete -net 224.0.0.0 netmask 240.0.0.0 dev %s'
  0x004021f4: afa30158 sw v1, (var_158h)
  0x004021f8: 02803021 move a2, s4 ; 接口名称（来自全局变量）
  0x004021fc: 0320f809 jalr t9 ; 调用 sprintf 构建命令
  0x00402200: 02602021 move a0, s3 ; 缓冲区地址
  0x00402208: 8f9980dc lw t9, -sym.imp.system(gp)
  0x0040220c: 0320f809 jalr t9 ; 调用 system 执行命令
  0x00402210: 02602021 move a0, s3 ; 命令字符串缓冲区
  ```
- **关键词：** 命令行参数（接口名称）, 全局变量存储接口名称, system 命令字符串
- **备注：** 该漏洞需要程序以 root 权限运行，这在网络服务中常见。攻击者可通过命令行参数直接控制输入，利用链完整且可验证。建议对接口名称进行严格验证和过滤，或使用 execve 等安全函数替代 system。进一步分析应检查其他输入点（如网络数据包和 FIFO 文件）是否存在类似问题。

---
### command-injection-upgrade_firmware

- **文件/目录路径：** `sbin/bulkagent`
- **位置：** `bulkagent:0x40379c upgrade_firmware`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the 'upgrade_firmware' function, where user-controlled input from network packets is unsafely incorporated into a 'system' call. Attackers can exploit this by sending crafted firmware upgrade commands containing shell metacharacters, leading to arbitrary command execution as the user running 'bulkagent'. The vulnerability is triggered when the command type 0x7eff or 0x7f00 is processed, calling 'upgrade_firmware' with attacker-controlled data. The function uses 'snprintf' to build a command string but does not validate or escape the input, allowing injection into the 'bulkUpgrade' command.
- **代码片段：**
  ```
  In upgrade_firmware (0x40379c):
  - Constructs command using snprintf: 'bulkUpgrade -f "%s%s" -force' with user-controlled strings
  - Calls system() with the constructed command
  Evidence from control_command (0x404118) shows command type 0x7eff/0x7f00 leads to upgrade_firmware call with network data.
  ```
- **关键词：** ipaddr_server, /var/tmp/, bulkUpgrade
- **备注：** The attack requires network access to the bulkagent service. As a non-root user, exploitation can lead to privilege escalation if bulkagent runs with elevated privileges. Recommend immediate input sanitization and avoiding system() with user input.

---
### buffer-overflow-main

- **文件/目录路径：** `sbin/get_set`
- **位置：** `get_set:0x00400d44 main (specifically at the ncc_socket_recv call around 0x00400e00 based on decompilation context)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A stack-based buffer overflow occurs in the main function when ncc_socket_recv is called. The function sets uStack_a48 to 0x100 (256 bytes) but provides auStack_a50, a stack buffer of only 4 bytes. This mismatch allows an attacker to send more than 4 bytes of data, overflowing the buffer and corrupting adjacent stack variables, including the return address. The vulnerability is triggered by sending crafted network data to the service. As the program may run with elevated privileges (e.g., via CGI or network service), successful exploitation could lead to arbitrary code execution. The attack chain is: network input → ncc_socket_recv with oversized data → buffer overflow → control of execution flow.
- **代码片段：**
  ```
  // From main function decompilation
  uStack_a48 = 0x100; // Size set to 256 bytes
  uStack_a44 = 0x310;
  uStack_a40 = 0;
  iStack_a3c = 0;
  pcStack_a38 = NULL;
  iStack_a3c = (**(loc._gp + -0x7fc4))(acStack_434); // strlen call
  pcStack_a38 = acStack_434;
  iVar3 = (**(loc._gp + -0x7f70))(uStack_a4c, &uStack_a48, auStack_a50); // ncc_socket_recv call
  // auStack_a50 is defined as uchar auStack_a50 [4]; (4-byte buffer)
  // But uStack_a48 is 0x100, allowing up to 256 bytes to be written
  ```
- **关键词：** ncc_socket_recv, auStack_a50, uStack_a48
- **备注：** The vulnerability is verified through decompilation evidence. Exploitation depends on the service's accessibility and privileges. Further analysis could involve testing the network protocol and identifying exact offset for overwriting the return address. No other exploitable issues were found in helper functions.

---
### Sensitive-Data-Exposure-key_file.pem

- **文件/目录路径：** `etc/key_file.pem`
- **位置：** `key_file.pem:1 (file content)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 文件 'key_file.pem' 包含未加密的 RSA 私钥和证书，暴露了高度敏感的信息。问题表现为私钥可被非 root 用户读取，触发条件是攻击者具有文件系统访问权限并能够读取该文件。约束条件包括文件位于可访问目录且权限设置不当。潜在攻击方式包括使用私钥进行身份冒充（如 SSH 登录或 TLS 连接解密）、中间人攻击或权限提升。相关技术细节是私钥以明文形式存储，缺少加密或访问控制。
- **代码片段：**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIICXAIBAAKBgQDLLKEQqDuuLDhF7s8TqHGofvXWMJNopCgbHyGRGt9s3bB+2A7a
  rnNjzTlN5MOGwWE/ELXjm0fQDLIiIBgalke5StNqF5i3FHteMN16fdd83BaM2/L6
  U3kyYQ9K6m5GXeoOt6x3mP0xJf1ADovPc59reepPL3wi4eSMXQOpnl0gUwIDAQAB
  AoGAVA97+DNSteZPxgdfH8gCdm9I8TyZ0KKSgV4o+is/I4C5ZFGqG6ovzav8OJEc
  oKVjwb79MlVtqdOG4/2ZW26v72nh/V9OtIpNdHcaulkoJglMwq/w/xIgEwctS6c1
  se/UlM8DEH/WBYtMMJ6/nwJwDB6x8+WD7Hm+vjwVozuUOSkCQQDwBW4AD+FN97RP
  NwSBS64qyhFB7IstT7EPCarbnqPTbEGM39y/PKgPT5wUIS3Zkih09OizsZuroJpS
  XAXhlAXHAkEA2LM8NtdNibGWjzA5PhLCUf225UjTN0ccjSZLKqjW4N/G4hVy6jtL
  9noENq/zir85dTIaIxUpVy9fhjHuq7YhFQJBAJavUffIAHKqaBCzQajKknValqsE
  jfvMZCREtXdbiQ5akGyYvkVxFzFFkX8xtU86axvCBbWKc2i0Uy4Rh7+u5lECQBcl
  TdEtvgJvDX3N0M9ogYjwaJCk7qqA1fPdmzm7PvhV7pBHajbKjpqM/dY5hPHU6vYx
  m8kTgY7maHWU78E3euECQH1AJSESOXzLGcsPPkY0a0M2SWPU+W2SSoxhHnbmG1vG
  KuBYPVK1emsIxwVdGlE13EEaXn9qiK8OcQNKzbEqrww=
  -----END RSA PRIVATE KEY-----
  -----BEGIN CERTIFICATE-----
  MIICoTCCAgqgAwIBAgIJAMu7EW1f923hMA0GCSqGSIb3DQEBBQUAMEAxCzAJBgNV
  BAYTAlRXMQ8wDQYDVQQIEwZUQUlXQU4xDzANBgNVBAcTBlRBSVBFSTEPMA0GA1UE
  ChMGRC1MaW5rMB4XDTEzMTExMTAxMjMwNFoXDTIzMTEwOTAxMjMwNFowQDELMAkG
  A1UEBhMCVFcxDzANBgNVBAgTBlRBSVdBTjEPMA0GA1UEBxMGVEFJUEVJMQ8wDQYD
  VQQKEwZELUxpbmswgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMssoRCoO64s
  OEXuzxOocah+9dYwk2ikKBsfIZEa32zdsH7YDtquc2PNOU3kw4bBYT8QteObR9AM
  siIgGBqWR7lK02oXmLcUe14w3Xp913zcFozb8vpTeTJhD0rqbkZd6g63rHeY/TEl
  /UAOi89zn2t56k8vfCLh5IxdA6meXSBTAgMBAAGjgaIwgZ8wHQYDVR0OBBYEFIvH
  8ES2FWMrzwH0fIj2nJf1nIhGMHAGA1UdIwRpMGeAFIvH8ES2FWMrzwH0fIj2nJf1
  nIhGoUSkQjBAMQswCQYDVQQGEwJUVzEPMA0GA1UECBMGVEFJV0FOMQ8wDQYDVQQH
  EwZUQUlQRUkxDzANBgNVBAoTBkQtTGlua4IJAMu7EW1f923hMAwGA1UdEwQFMAMB
  Af8wDQYJKoZIhvcNAQEFBQADgYEAc3dlDo8BCZHN6iwUjAojGQKuEok8hNFgnTh+
  DI3HZDEGWajn8ytgqFMJvSqMq94mx4KsMUCyqsAfiNlyI22DgrAYGG8aAVOLEZIV
  AT1opv500zQA6gVA4UXecjVv6QjPe8uJRY7BljP1SLg5XRgyKrHsyzedzN5p9nuN
  KajGJc0=
  -----END CERTIFICATE-----
  ```
- **关键词：** key_file.pem
- **备注：** 此发现基于文件内容分析，私钥暴露可直接被利用。建议进一步验证文件权限（如使用 'ls -l key_file.pem'）和系统组件如何使用此私钥，以确认攻击链的完整性。关联文件可能包括使用该私钥的服务配置文件。

---
### Command-Injection-set_timeZone

- **文件/目录路径：** `lib/libapmib.so`
- **位置：** `libapmib.so:0x5990 (system call in set_timeZone)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** The `set_timeZone` function in libapmib.so contains a command injection vulnerability due to improper sanitization of user-controlled input from the NTP_TIMEZONE MIB setting (ID 0x99). The function retrieves the timezone string via `apmib_get`, processes it with `gettoken` to extract the first token (using space as delimiter), and then uses this token in a `sprintf` format string (e.g., 'GMT%s:30%s' or 'GMT%s%s') that is incorporated into a shell command executed via `system`. The command constructed is 'echo %s >/var/TZ', where the first %s is the formatted string containing the user-controlled token. An attacker with valid login credentials can set the NTP_TIMEZONE value to a string containing shell metacharacters (e.g., '; malicious_command #') to break out of the intended command and execute arbitrary commands. The vulnerability is triggered when `set_timeZone` is called, which typically occurs during timezone configuration updates via MIB settings. The function includes multiple `strcmp` checks against hardcoded timezone strings, but if no match is found, it falls back to a default path where the user input is still used unsanitized. The lack of input validation allows command injection regardless of the strcmp outcomes.
- **代码片段：**
  ```
  Relevant code from set_timeZone disassembly:
  0x5990: lw t9, -sym.imp.system(gp)
  0x5994: jalr t9  # Executes the command string
  
  Preceding code constructs the command:
  0x5980: lw t9, -sym.imp.sprintf(gp)
  0x5984: jalr t9  # Formats 'echo %s >%s' with user input
  0x5988: addiu a1, a1, -0x6e38  # 'echo %s >%s' string
  0x598c: move a0, s0  # Command buffer
  0x5990: jalr t9  # Calls system
  
  The user input is derived from:
  0x5848: lw t9, -sym.gettoken(gp)
  0x584c: jalr t9  # Gets first token of timezone string
  0x5850: move a2, zero  # Delimiter space
  0x5854: move a0, s0  # Input buffer from apmib_get(0x99)
  ```
- **关键词：** NTP_TIMEZONE (MIB ID 0x99), DAYLIGHT_SAVE (MIB ID 0x11a), apmib_set, apmib_get, set_timeZone, /var/TZ
- **备注：** The vulnerability requires that set_timeZone is called by a process after the MIB value is set. This is likely triggered through configuration interfaces (e.g., web UI or CLI) accessible to authenticated users. The process executing set_timeZone may run with elevated privileges (e.g., root), leading to full system compromise. Further analysis should identify all callers of set_timeZone in the system to confirm exploitability in context. The use of strcpy and sprintf in this function also indicates potential for buffer overflows, but command injection is the immediately exploitable issue.

---
### PrivEsc-ShadowSample

- **文件/目录路径：** `etc/shadow.sample`
- **位置：** `shadow.sample:1`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** shadow.sample 文件包含 root 用户的密码哈希（MD5 格式：$1$KEKJV2R0$TFJ4jy7waGKrjdNHwPGzV.），且文件权限设置为 777（-rwxrwxrwx），允许任何用户（包括非 root 用户）读取。攻击者（已登录的非 root 用户）可以轻松读取该文件，提取哈希值，并使用离线破解工具（如 John the Ripper 或 hashcat）尝试破解密码。如果密码强度弱，攻击者可能获得 root 密码，从而提升权限到 root。触发条件是攻击者具有文件读取权限，无需额外条件。利用方式包括直接读取文件和使用破解工具进行字典或暴力攻击。
- **代码片段：**
  ```
  root:$1$KEKJV2R0$TFJ4jy7waGKrjdNHwPGzV.:14587:0:99999:7:::
  ```
- **关键词：** shadow.sample
- **备注：** 需要进一步验证密码哈希的强度以评估破解难度。建议检查系统中其他类似文件（如 /etc/shadow）的权限，以防止类似信息泄露。此发现关联到权限管理问题，可能影响整体系统安全。

---
### XSS-category_asp_file_list

- **文件/目录路径：** `wa_www/category.asp`
- **位置：** `category.asp: show_media_list 函数和 show_media_list2 函数（具体行号未知，但从内容看位于输出文件名的代码段）`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 存储型 XSS 漏洞存在于文件列表显示功能中。文件名（从 '/dws/api/ListCategory' API 返回）在 'show_media_list' 和 'show_media_list2' 函数中被直接输出到 HTML 中，未进行 HTML 转义。攻击者可以上传一个文件名包含恶意脚本的文件（例如 `<script>alert('XSS')</script>.mp3`）。当认证用户访问 'category.asp' 页面时，恶意脚本会在其浏览器中执行。由于会话 cookies（'id' 和 'key'）可通过 JavaScript 访问（无 HttpOnly 标志），攻击者可能窃取会话令牌并劫持用户会话。触发条件：攻击者上传恶意文件名文件；用户浏览文件列表。利用方式：通过 XSS 执行任意 JavaScript 代码，可能导致会话窃取、权限提升或进一步攻击。
- **代码片段：**
  ```
  在 show_media_list 函数中：
  str += "<div>" + file_name + "<br>" + get_file_size(obj.size) + ", " + m_time + "</div>"
  在 show_media_list2 函数中：
  bg_str += "<div>" + file_name + "<br>" + get_file_size(obj.size) + ", " + m_time + "</div>"
  文件名 'file_name' 直接连接至 HTML 字符串，未使用转义函数。
  ```
- **关键词：** media_info.files[i].name, session_id, session_tok, /dws/api/ListCategory, /dws/api/GetFile
- **备注：** 漏洞依赖于后端 API 允许恶意文件名上传；建议验证后端是否对文件名进行了过滤。关联文件：上传功能可能在其他脚本中（如 'webfile.js'）。后续分析方向：检查文件上传机制和后端 API 实现，以确认文件名可控性。此漏洞在认证上下文中可利用，攻击链完整。

---
### buffer-overflow-fcn.00401658

- **文件/目录路径：** `bin/iwpriv`
- **位置：** `iwpriv:0x00401658 fcn.00401658`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A buffer overflow vulnerability was identified in the 'iwpriv' binary within the function fcn.00401658 when processing ioctl commands of type 0x6000. The vulnerability arises from the use of a strcpy-like function to copy user-controlled data from command-line arguments into a fixed-size stack buffer (auStack_10b4 of 127 bytes) without length validation. An attacker with valid login credentials (non-root user) can trigger this by providing a specially crafted long string as part of the command-line arguments for a specific ioctl command. This could lead to stack buffer overflow, allowing overwrite of adjacent stack data including return addresses, potentially resulting in arbitrary code execution or denial of service. The vulnerability is triggered when the command-line arguments activate the type 0x6000 handling path in the code.
- **代码片段：**
  ```
  // From decompilation of fcn.00401658
  if (uVar15 == 0x6000) {
      ppuVar16 = apuStack_1034;
      for (iVar2 = 0; iVar2 < uVar3; iVar2 = iVar2 + 1) {
          pcVar21 = loc._gp;
          if (iVar2 != 0) {
              uVar4 = (**(loc._gp + -0x7fb4))(param_5);
              (**(loc._gp + -0x7ef0))("           %.*s", uVar4, "                ");
          }
          iVar17 = ppuVar16 + 2;
          ppuVar16 = ppuVar16 + 4;
          (**(pcVar21 + -0x7f48))(iVar17, auStack_10b4);  // Vulnerable strcpy-like call
          (**(loc._gp + -0x7f1c))(auStack_10b4);
      }
      return 0;
  }
  ```
- **关键词：** argv, ioctl commands, auStack_10b4
- **备注：** The function at offset -0x7f48 from loc._gp is likely strcpy based on the two-argument call and the presence of strcpy in the import table. The buffer auStack_10b4 is only 127 bytes, and user input from command-line arguments can exceed this size. Further analysis is needed to confirm the exact exploitation scenario, including the availability of the binary to non-root users and the stack layout for successful code execution. Additional functions like fcn.00400f1c and fcn.00401154 should be examined for similar vulnerabilities.

---
### BufferOverflow-callback_ccp_hnap

- **文件/目录路径：** `sbin/ncc2`
- **位置：** `ncc2:0x0047b3b0 callback_ccp_hnap`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A potential buffer overflow vulnerability exists in the HNAP request handler (callback_ccp_hnap) where user-controlled input from network requests is copied into fixed-size stack buffers without proper bounds checking. Specifically, the function uses a string copy operation (likely strcpy) to copy data from the input parameter (param_2+0x41) into a 128-byte buffer (auStack_4b0) and a 1024-byte buffer (auStack_430). The lack of length validation before copying allows an attacker to overflow the buffer by sending a crafted HNAP request with excessive data. This could lead to arbitrary code execution if the stack is executable or via return-oriented programming (ROP) in the MIPS architecture. The vulnerability is triggered when processing HNAP requests, which are accessible to authenticated users via network interfaces.
- **代码片段：**
  ```
  // Decompiled code from callback_ccp_hnap
  uchar auStack_4b0 [128]; // 128-byte buffer on stack
  uchar auStack_430 [1024]; // 1024-byte buffer on stack
  // ...
  // Copy user input from param_2+0x41 into auStack_4b0 without bounds check
  (**(iVar10 + -0x7f18))(auStack_4b0, param_2 + 0x41); // Likely strcpy equivalent
  // Similar copies to auStack_430 and other buffers occur later in the function
  ```
- **关键词：** HNAP protocol, SOAP action parameters, network interface
- **备注：** The evidence is based on decompilation analysis showing unchecked copy operations. However, further validation is needed to confirm the exact function used (e.g., strcpy) and to test exploitability in a real environment. The binary is for MIPS architecture, and exploitation may require specific techniques due to platform constraints. Additional input points like CGI handlers should be investigated for similar issues.

---
### XSS-FileFolderDisplay

- **文件/目录路径：** `wa_www/folder_view.asp`
- **位置：** `folder_view.asp: function show_folder_content (约行 300-400) 和 function get_sub_tree (约行 350-400)`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 跨站脚本（XSS）漏洞存在于文件列表和文件夹树显示中。文件名和文件夹名（用户可控输入）在显示时没有进行 HTML 转义，直接插入到 innerHTML 和事件处理程序中。攻击者可以创建或上传包含恶意脚本的文件名或文件夹名（例如：<script>alert('XSS')</script>）。当其他用户查看文件列表或导航文件夹树时，脚本会在其浏览器中执行。这可能导致会话窃取、权限提升或其他恶意操作。触发条件：攻击者上传文件或创建文件夹后，受害者查看相关页面。利用方式：攻击者使用有效登录凭据上传恶意文件，诱骗管理员或其他用户访问文件管理页面。
- **代码片段：**
  ```
  // 在 show_folder_content 函数中
  cell_html = "<input type=\"checkbox\" id=\"" + sum + "\" name=\"" + file_name + "\" value=\"1\" class=\"chk\" onclick=\"shiftkey(event);\" />"
                  + "<a href=\"" + APIGetFileURL(path,volid,file_name) + "\" target=\"_blank\">"
                  + "<div>" + file_name + "<br>" + get_file_size(obj.size) + ", " + m_time + "</div></a>";
  // 在 get_sub_tree 函数中
  my_tree += "<li id=\"" + li_id + "\" class=\"tocollapse\">"
          + "<a href=\"#\" title=\"" + obj.name + "\" " 
          + "onClick=\"click_folder('" + li_id + "', '" + current_volid + "', '" + obj.mode + "')\">"
          + obj.name + "</a></li>"
          + "<li></li>"
          + "<li><span id=\"" + li_id + "-sub\"></span></li>";
  ```
- **关键词：** file_name, folder_name, APIGetFileURL, show_folder_content, get_sub_tree, current_path, current_volid
- **备注：** 这是存储型 XSS，攻击链完整且可验证从前端代码。建议后端增加输入验证和输出编码。关联文件：可能影响所有使用相同显示逻辑的页面。后续应检查后端 API 实现以确保路径遍历和文件上传漏洞已缓解。

---
### FileUpload-API_UploadFile

- **文件/目录路径：** `wa_www/file_access.asp`
- **位置：** `file_access.asp:btn_upload 函数和 dlg_upload_ok 函数（约行 450-500）`
- **风险评分：** 7.0
- **置信度：** 7.0
- **描述：** 文件上传功能通过 '/dws/api/UploadFile' API 处理，但客户端代码没有对文件类型进行验证，仅依赖后端检查。攻击者可能上传恶意文件（如 webshell），如果后端没有严格限制文件类型或路径，可能导致远程代码执行。触发条件：攻击者使用上传功能提交恶意文件，并诱使用户或系统访问该文件。利用方式取决于后端配置，但基于客户端代码，缺少客户端验证增加了风险。
- **代码片段：**
  ```
  function btn_upload()
  {
      $('#wfa_file').val('');
      $('#wfa_tok').val('');
      $('#upload_form').show();
      upload_count = 0;
      clearInterval(polling_id);
      $('#dlg_upload').dialog('open');
  }
  
  function dlg_upload_ok(obj)
  {
      if ($('#wfa_file').val() == '') {
          alert('Select a file');
          return;
      }
      var rand = gen_rand_num(32);//generate 32 bytes random number
      var arg1 = '/dws/api/UploadFile?id='+session_id+rand;
      $('#wfa_id').val(session_id);
      $('#wfa_path').val(cur_path);
      $('#wfa_volid').val(cur_volId);
      $('#wfa_tok').val(rand+hex_hmac_md5(session_tok, arg1));
      document.getElementById('form1').action = '/dws/api/UploadFile';
      document.getElementById('form1').target = 'upload_target';
      $('#form1').submit();
      $(obj).dialog("close");
      setTimeout('delay_refresh_ctx()', 1000);
  }
  ```
- **关键词：** /dws/api/UploadFile, wfa_file, form1
- **备注：** 风险取决于后端实现。如果后端允许执行上传的文件（如 PHP 文件），则可能导致严重漏洞。建议检查后端代码以确认文件类型验证和存储路径安全性。攻击链完整，但需要后端漏洞配合才能完全利用。

---
### XSS-file_access_show_content_update_tree

- **文件/目录路径：** `wa_www/file_access.asp`
- **位置：** `file_access.asp:show_content 函数（约行 350-400）和 update_tree 函数（约行 250-280）`
- **风险评分：** 6.5
- **置信度：** 8.5
- **描述：** 在 'file_access.asp' 文件中，用户控制的文件夹和文件名在输出到 HTML 时没有进行转义，导致反射型跨站脚本（XSS）漏洞。攻击者可以创建恶意文件夹或文件（例如，名称包含 JavaScript 代码），当其他已登录用户浏览文件管理器时，恶意脚本会在其浏览器中执行。这可能导致会话劫持、未经授权的操作或数据窃取。触发条件包括：用户访问文件管理页面并查看包含恶意名称的文件夹或文件。漏洞存在于多个函数中，其中用户输入被直接连接到 HTML 字符串中。
- **代码片段：**
  ```
  // 在 show_content 函数中：
  content_msg += '<tr class=listCtx onclick="ctxClick(\''+rPath+folders[i].name+'\', \''+ulId+'/'+folders[i].name+'\', \'1\')">';
  content_msg += "<td class=listName><img src="+extIcon+">&nbsp;"+files[i].name+"</td>";
  
  // 在 update_tree 函数中：
  branches += '<li><span class=folder>'+dispName+'</span>'+
      '<ul id="'+ulId+'/'+dispName+'"'+
      ' url="req_subfolder(\''+rPath+reqPath+'\', \''+ulId+'/'+dispName+'\', \''+volId+'\')"'+
      ' clr="req_ctx(\''+rPath+reqPath+'\', \''+ulId+'/'+dispName+'\', \''+volId+'\')">'+
      '</ul></li>';
  ```
- **关键词：** folders[i].name, files[i].name, /dws/api/ListDir, /dws/api/ListFile, /dws/api/AddDir
- **备注：** 漏洞可利用性高，因为攻击者只需创建恶意文件夹或文件（通过上传或创建文件夹功能），即可触发 XSS。需要用户交互（浏览文件管理器），但作为已登录用户，风险显著。建议对用户输入进行 HTML 转义。后续可验证后端 API 是否对输入有过滤。

---
### XSS-login_asp_json_ajax

- **文件/目录路径：** `wa_www/login.asp`
- **位置：** `login.asp: ~line 80-120 (check function), pandoraBox.js: ~line 600-650 (json_ajax function)`
- **风险评分：** 6.0
- **置信度：** 8.0
- **描述：** A reflected cross-site scripting (XSS) vulnerability exists in the login authentication mechanism of 'login.asp'. The vulnerability allows an attacker to inject and execute arbitrary JavaScript code via the username field, leading to session cookie theft and account hijacking. The attack triggers when a user submits a malicious username that causes the server to return an HTML error response containing the unsanitized username. The client-side 'json_ajax' function in 'pandoraBox.js' handles such errors by writing the raw response to the document using 'document.write', executing any embedded scripts. This requires the user to attempt login with the malicious username and fail, which can be achieved through social engineering. The stolen cookies ('uid', 'id', 'key') can then be used to impersonate the user and access their account.
- **代码片段：**
  ```
  From login.asp:
  \`\`\`javascript
  function check() {
      // ...
      var username = $("#username").val();
      var password = $("#password").val();
      // First AJAX call to get challenge
      var param = { url: 'dws/api/Login', arg: '' };
      var data = json_ajax(param);
      // Second AJAX call with username and hashed password
      param.arg = 'id=' + username + '&password=' + digs;
      var data = json_ajax(param);
      // ...
  }
  \`\`\`
  From pandoraBox.js:
  \`\`\`javascript
  function json_ajax(param) {
      // ...
      var ajax_param = {
          type: "POST",
          async: false,
          url: param.url,
          data: param.arg,
          dataType: "json",
          success: function(data) {
              if (data['status'] != 'fail') {
                  myData = data;
                  return;
              }
              alert('Error: ' + drws_err[data['errno']]);
              // ...
          },
          error: function(xhr, ajaxOptions, thrownError) {
              if (xhr.status == 200) {
                  try {
                      setTimeout(function() {
                          document.write(xhr.responseText);
                      }, 0);
                  } catch (e) {}
              } else {}
          }
      };
      // ...
  }
  \`\`\`
  ```
- **关键词：** username input field in login.asp, dws/api/Login endpoint, json_ajax function in pandoraBox.js, document.cookie
- **备注：** This vulnerability requires the server to reflect the username in error responses without proper sanitization, which is a common practice. The attack depends on user interaction (entering a malicious username) and a failed login attempt. While the user is a non-root user, session hijacking could lead to unauthorized access to the user's privileges. Further verification should include testing the 'dws/api/Login' endpoint with malicious input to confirm server-side reflection. Additional analysis of other pages may reveal more severe vulnerabilities, but this is the most exploitable issue found in 'login.asp'.

---
### PathTraversal-API_ListDir_GetFile

- **文件/目录路径：** `wa_www/file_access.asp`
- **位置：** `file_access.asp:req_subfolder 函数（约行 150-180）和 fileClick 函数（约行 320-350）`
- **风险评分：** 6.0
- **置信度：** 6.5
- **描述：** 路径参数（如 'path' 和 'volid'）在多个 API 调用（如 '/dws/api/ListDir'、'/dws/api/GetFile'）中被直接使用，没有明显的客户端验证。如果后端没有正确 sanitize 输入，可能导致路径遍历攻击，允许攻击者访问系统敏感文件。触发条件：攻击者操纵 'path' 参数（例如，使用 '../'）来访问受限目录。利用方式：通过修改 AJAX 请求中的 'path' 值，尝试读取或下载系统文件。
- **代码片段：**
  ```
  function req_subfolder(path, ulId, volId) 
  {
      var param = {
          url: '/dws/api/ListDir',
          arg: 'id='+session_id+'&path='+urlencode(path)+'&volid='+volId
      };
      // ...
  }
  
  function fileClick(path, filename, volId)
  {
      var rand = gen_rand_num(32);//generate 32 bytes random number
      var arg1 = '/dws/api/GetFile?id='+session_id+rand;
      $('#get_wfa_id').val(session_id);
      $('#get_wfa_path').val(urlencode(path));
      $('#get_wfa_volid').val(volId);
      $('#get_wfa_file').val(urlencode(filename));
      $('#get_wfa_tok').val(rand+hex_hmac_md5(session_tok, arg1));
      document.getElementById('form2').target = 'upload_target';
      $('#form2').submit();
  }
  ```
- **关键词：** path, volid, /dws/api/ListDir, /dws/api/GetFile, req_subfolder, fileClick
- **备注：** 漏洞可利用性依赖于后端没有对路径进行严格验证。urlencode 函数可能不足以防止路径遍历。建议检查后端 API 实现。攻击链可能不完整，需要后端漏洞验证。

---
### NULL-Pointer-Dereference-pptp_inbound_pkt

- **文件/目录路径：** `lib/modules/2.6.30.9/kernel/net/ipv4/netfilter/nf_nat_pptp.ko`
- **位置：** `nf_nat_pptp.ko:未知行号 sym.pptp_inbound_pkt 函数`
- **风险评分：** 5.0
- **置信度：** 7.0
- **描述：** 在 sym.pptp_inbound_pkt 函数中发现 NULL 指针解引用漏洞。代码中调用 (*NULL)()，当处理特定 PPTP 入站数据包时，如果数据包中某个字段（uVar1，可能对应 PPTP 消息类型或其他标识）的值为 0xb（11）或 0xc 到 0xf（12-15），会导致内核崩溃（denial-of-service）。攻击者作为拥有有效登录凭据的非 root 用户，可以通过网络发送恶意 PPTP 数据包（使用 TCP 端口 1723 或 GRE）触发此漏洞。漏洞触发条件依赖于数据包内容，缺少适当的输入验证和边界检查。潜在利用方式仅为 DoS，未发现权限提升或其他更严重攻击链。
- **代码片段：**
  ```
  uVar1 = *in_a3;
  if (uVar1 != 0xb) {
      if (uVar1 < 0xc) {
          if (uVar1 != 8) {
              return true;
          }
          halt_baddata();
      }
      if (2 < uVar1 - 0xd) {
          halt_baddata();
      }
  }
  iVar2 = (*NULL)();
  return iVar2 != 0;
  ```
- **关键词：** PPTP 数据包字段（uVar1）, TCP 端口 1723, GRE 协议
- **备注：** 此漏洞仅导致 denial-of-service，未发现完整攻击链如权限提升。需要进一步验证 PPTP 数据包格式以确认 uVar1 的具体含义。建议分析其他函数（如 sym.pptp_outbound_pkt）以寻找类似问题。由于是内核模块，漏洞可能影响系统稳定性，但利用条件受限。

---
### Client-JS-Injection-deviceinfo.js

- **文件/目录路径：** `www/config/deviceinfo.js`
- **位置：** `deviceinfo.js:1 DeviceInfo()`
- **风险评分：** 3.0
- **置信度：** 8.0
- **描述：** The 'deviceinfo.js' file is globally writable (permissions: rwxrwxrwx) and is dynamically loaded by 'features.js' using $.getScript in a client-side JavaScript context. An attacker with non-root login credentials can modify this file to inject malicious JavaScript code, which will execute in the browser of any user who accesses the web page that relies on 'features.js'. This could lead to client-side attacks such as session hijacking or configuration tampering within the web interface. However, the vulnerability is limited to client-side execution and does not provide a direct path to system-level privilege escalation or remote code execution on the device. The trigger condition is when the web page loading 'features.js' is accessed, and the exploitation requires the attacker to have write access to the file, which is already available due to the permissions.
- **代码片段：**
  ```
  // From deviceinfo.js
  function DeviceInfo()
  {
  	this.bridgeMode = true;
  	this.featureVPN = true;
  	// ... other properties
  }
  
  // From features.js
  $.getScript("/config/deviceinfo.js", function(){
  	DeviceInfo.prototype = new CommonDeviceInfo();
  	DeviceInfo.prototype.constructor = DeviceInfo;
  	var currentDevice = new DeviceInfo();
  	sessionStorage.setItem('currentDevice', JSON.stringify(currentDevice));
  });
  ```
- **关键词：** /config/deviceinfo.js, /config/features.js
- **备注：** This finding is based on direct evidence of file permissions and code usage. The risk is low because the exploitation is confined to the client-side and does not escalate privileges on the device. Further analysis could involve checking if the web server or other server-side components use these files, but based on the current code, it appears to be client-only. No additional input sources or cross-component interactions were identified in this analysis.

---
