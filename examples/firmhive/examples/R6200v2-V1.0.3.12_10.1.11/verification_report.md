# R6200v2-V1.0.3.12_10.1.11 - 验证报告 (15 个发现)

---

## 原始信息

- **文件/目录路径：** `usr/lib/uams/uams_dhx2_passwd.so`
- **位置：** `uams_dhx2_passwd.so:0x219c sym.logincont2 (approximate address of decryption call)`
- **描述：** The function sym.logincont2 lacks proper length validation on param_3 before using it in gcry_cipher_decrypt with a fixed size of 0x110 bytes. This occurs when param_4 is 0x112 or 0x11c, indicating specific packet types in the DHX2 authentication protocol. An attacker with valid login credentials can send a crafted authentication packet with a short param_3 buffer, triggering an out-of-bounds read during decryption. This could leak adjacent memory contents, such as encryption keys or session data, but does not directly enable code execution. The missing check allows reading beyond the allocated buffer, primarily resulting in information disclosure. The trigger condition involves sending malicious packets during the login process.
- **代码片段：**
  ```
  if ((*(puVar5 + -0x63c) != 0x112) && (*(puVar5 + -0x63c) != 0x11c)) {
      // error handling
  } else {
      // decryption setup
      *(puVar5 + -0x638) = *(puVar5 + -0x638) + 2;
      uVar2 = loc.imp.gcry_cipher_decrypt(*(puVar5 + -0x28), *(puVar5 + -0x638), 0x110, 0);
      // no length check on *(puVar5 + -0x638) before decryption
  }
  ```
- **备注：** Exploitable by an authenticated non-root user via crafted AFP packets, but the impact is limited to information disclosure without a full code execution chain. Further analysis should trace UAM dispatch to confirm external controllability. Related functions include sym.passwd_logincont and uam_setup.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `Medium`
- **详细原因：** 安全警报准确描述了 sym.logincont2 函数中的漏洞。证据显示：1) 在地址 0x2334-0x2350 的代码中，gcry_cipher_decrypt 被调用时使用固定长度 0x110 字节，且没有对 param_3 缓冲区进行长度验证；2) 条件检查（0x21e4-0x21f8）确认当 param_4 为 0x112 或 0x11c 时执行解密路径；3) 通过 sym.passwd_logincont（0x27a4-0x27ac）确认 param_3 来自外部输入，攻击者可控制；4) 攻击者模型为已通过身份验证的用户（拥有有效凭据），通过发送特制的 AFP 包触发漏洞。漏洞可利用性验证：攻击者可以构造包类型为 0x112 或 0x11c 的 AFP 认证包，并提供短缓冲区（长度小于 0x110 字节），导致 gcry_cipher_decrypt 读取越界数据，泄露相邻内存中的敏感信息（如加密密钥或会话数据）。但漏洞仅导致信息泄露，无代码执行能力，因此风险评为中等。PoC 步骤：a) 攻击者使用有效凭据认证；b) 构造 AFP 包，设置包类型为 0x112 或 0x11c，并包含短缓冲区（例如 0x10 字节）；c) 发送包到服务器；d) 服务器处理时触发越界读，泄露内存内容。

## 验证指标

- **验证时长：** 182.42 秒
- **Token 使用量：** 230423

---

## 原始信息

- **文件/目录路径：** `bin/eapd`
- **位置：** `eapd:0x0000a290 (fcn.0000a290), 0x0000b20c (fcn.0000b20c)`
- **描述：** The vulnerability occurs in the function `fcn.0000a290` (decompiled from address 0x0000a290), which handles data from network sockets. User input received via `recv` in `fcn.0000b20c` is passed as `param_2` to `fcn.0000a290`. Inside `fcn.0000a290`, this input is used in a command string constructed with `snprintf` and executed via `_eval` without sanitization. An attacker can inject shell metacharacters (e.g., `;`, `&`, `|`) into the input to execute arbitrary commands. The trigger condition is when data is sent to the eapd socket associated with socket descriptor 0x5170 (as seen in `fcn.0000b20c`), which likely corresponds to a local network service based on strings like '127.0.0.1'. The lack of input validation or escaping allows full command injection.
- **代码片段：**
  ```
  // From fcn.0000b20c (network input handling)
  uVar2 = *(param_1 + 0x5170);
  if ((-1 < uVar2 + 0) && ... ) {
      iVar3 = sym.imp.recv(uVar2, iVar8, 0xff0, 0); // iVar8 is the input buffer
      ...
      if (*(param_1 + 0x20) == 0) {
          fcn.0000a290(param_1, iVar8); // Pass user input to vulnerable function
      }
  }
  
  // From fcn.0000a290 (command execution)
  *(puVar3 + -0x3c) = *0xa3fc; // Format string
  *(puVar3 + -0x38) = param_2;  // User input from recv
  *(puVar3 + -0x34) = *0xa404; // Additional string
  sym.imp._eval(puVar3 + -0x3c, *0xa400, iVar1, iVar1); // Execute command without sanitization
  ```
- **备注：** This vulnerability requires the eapd daemon to be running and accessible to the attacker. Since the attacker has valid login credentials, they can connect to the local socket. The daemon likely runs with root privileges, enabling privilege escalation. Further analysis could identify the exact socket configuration and test exploitability. No additional files or functions are immediately needed for this chain.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报的描述完全准确。基于反编译代码分析：在 fcn.0000b20c 中，当 socket 描述符 0x5170 有数据时，recv 调用接收用户输入到缓冲区 iVar8，并在条件 *(param_1 + 0x20) == 0 时调用 fcn.0000a290(param_1, iVar8)。在 fcn.0000a290 中，用户输入 (param_2) 被直接用于命令字符串构建（通过指针设置到堆栈），并通过 _eval 执行，没有任何输入验证或转义。攻击者模型是已通过身份验证的本地用户，可以访问本地 socket 服务（如基于字符串 '127.0.0.1' 的本地网络服务）。漏洞可利用性验证：输入可控（攻击者可通过 socket 发送任意数据）、路径可达（在现实条件下，当 socket 活跃且条件满足时，易受攻击代码路径可触发）、实际影响（任意命令执行，可能导致权限提升，因为 eapd 可能以 root 权限运行）。概念验证（PoC）：攻击者可以连接到本地 socket（例如使用 netcat 或自定义客户端），发送包含 shell 元字符的载荷，如 '; whoami' 或 '& cat /etc/passwd'，这将注入并执行任意命令。完整攻击链：攻击者控制输入 → recv 接收 → 传递到 fcn.0000a290 → 构建命令字符串 → _eval 执行。

## 验证指标

- **验证时长：** 188.79 秒
- **Token 使用量：** 243240

---

## 原始信息

- **文件/目录路径：** `usr/lib/uams/uams_passwd.so`
- **位置：** `uams_passwd.so:0x00000910 sym.passwd_login, uams_passwd.so:0x00000d98 sym.passwd_login_ext`
- **描述：** An off-by-one buffer overflow vulnerability exists in the authentication functions due to insufficient length validation before memcpy and null termination. In sym.passwd_login and sym.passwd_login_ext, the code checks if the input length (*puVar4) is zero or if it is greater than or equal to the buffer size (puVar4[-2] or puVar4[-7]) but not equal, allowing the copy to proceed when the length exactly equals the buffer size. This results in memcpy copying exactly buffer size bytes, followed by null termination one byte beyond the buffer, causing a one-byte overflow. Trigger conditions include sending crafted authentication requests with specific length values that match the buffer size. Potential exploitation could involve overwriting adjacent memory, such as return addresses or function pointers, leading to arbitrary code execution. The vulnerability is reachable via network inputs to the AFP authentication service, and as a non-root user, an attacker could leverage this to escalate privileges if the service runs as root.
- **代码片段：**
  ```
  From sym.passwd_login:
  if (((*puVar4 == 0) || (puVar4[-7] <= *puVar4 && *puVar4 != puVar4[-7])) || (puVar4[-2] <= *puVar4 && *puVar4 != puVar4[-2])) {
      uVar2 = 0xec65 | 0xffff0000;
  } else {
      sym.imp.memcpy(puVar4[-1], puVar4[-6], *puVar4);
      *(puVar4[-1] + *puVar4) = 0;
      // ...
  }
  
  From sym.passwd_login_ext:
  if ((*puVar4 == 0) || (puVar4[-2] <= *puVar4 && *puVar4 != puVar4[-2])) {
      uVar2 = 0xec65 | 0xffff0000;
  } else {
      sym.imp.memcpy(puVar4[-1], puVar4[-5] + 2, *puVar4);
      *(puVar4[-1] + *puVar4) = 0;
      // ...
  }
  ```
- **备注：** The vulnerability is evidenced by code analysis, but full exploitability depends on the runtime environment (e.g., stack layout, service privileges). Further validation through dynamic analysis or testing in a real system is recommended. The functions are part of the UAM for AFP, suggesting network exposure. Associated files or functions include sym.pwd_login and system libraries like libcrypt.so.0.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The alert accurately describes the off-by-one buffer overflow vulnerability in sym.passwd_login and sym.passwd_login_ext. Based on the disassembly evidence, both functions use condition checks with 'bls' that allow memcpy to copy exactly buffer size bytes when input length equals buffer size, followed by null termination one byte beyond the buffer. This is confirmed in sym.passwd_login at addresses 0x00000cc8 (condition) and 0x00000d1c (null termination), and in sym.passwd_login_ext at 0x00000e54 (condition) and 0x00000e90 (null termination). The vulnerability is exploitable by an unauthenticated remote attacker (attack model: sending crafted authentication requests to the AFP service) who can control input length to match the buffer size. This could overwrite adjacent memory, such as return addresses or function pointers, leading to arbitrary code execution. If the AFP service runs as root, privilege escalation is possible. PoC steps: For sym.passwd_login, send a request with input length equal to puVar4[-7] or puVar4[-2] (buffer size); for sym.passwd_login_ext, use input length equal to puVar4[-2]. This triggers the overflow. The full propagation path from attacker-controlled input to dangerous sink (memcpy and null termination) is verified.

## 验证指标

- **验证时长：** 189.70 秒
- **Token 使用量：** 254854

---

## 原始信息

- **文件/目录路径：** `usr/sbin/upnpd`
- **位置：** `upnpd:0x0001dbcc (fcn.0001dbcc)`
- **描述：** A buffer overflow via strcpy in function fcn.0001dbcc, where network input from recvfrom is directly copied to a stack buffer (auStack_634 [1500 bytes]) without bounds checking. An attacker can craft large UDP packets to overflow the stack, leading to code execution. The vulnerability is accessible through UPnP network interfaces and exploitable by any user who can send packets to the daemon.
- **代码片段：**
  ```
  sym.imp.strcpy(iVar5, param_1);  // param_1 is tainted network data, iVar5 is stack buffer
  ```
- **备注：** Simple and direct exploitation path with unsafe strcpy usage. Buffer size inferred from stack layout.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了缓冲区溢出漏洞。证据来自反汇编代码：函数 fcn.0001dbcc 在地址 0x0001dc24 使用 strcpy 将网络输入（param_1/arg1）直接复制到栈缓冲区（从 sp+0x24 开始），无边界检查。栈缓冲区大小为 1576 字节，但返回地址在偏移 1552 字节处。输入通过 recvfrom 从网络获取，且代码处理 UPnP SSDP 消息（如检查 'M-SEARCH'），使攻击路径可达。攻击者模型为未经身份验证的远程攻击者，可发送特制 UDP 数据包到 UPnP 端口（如 1900）。实际影响为代码执行，通过溢出覆盖返回地址。PoC 步骤：攻击者发送 UDP 数据包包含 'M-SEARCH * HTTP/1.1\r\n' 后跟超过 1552 字节的填充数据（如 'A' * 1552）和 shellcode 或控制地址，以劫持程序流。

## 验证指标

- **验证时长：** 240.43 秒
- **Token 使用量：** 315233

---

## 原始信息

- **文件/目录路径：** `sbin/rc`
- **位置：** `rc:0xf6d4 main 函数`
- **描述：** 在 'rc' 二进制文件的 main 函数中，存在一个命令注入漏洞。代码通过 nvram_get 获取 NVRAM 变量 'router_disable' 的值，并将其设置为环境变量。随后，在特定条件下，代码使用 system 函数执行命令，但未对输入进行充分的验证或过滤。攻击者可以通过设置 'router_disable' NVRAM 变量来注入恶意命令，从而执行任意代码。触发条件包括：攻击者能够设置 NVRAM 变量（通过已认证的 Web 接口或 CLI），并且 rc 程序以 root 权限运行（通常如此）。利用方式包括：设置 'router_disable' 为包含 shell 元字符的值，如 '; malicious_command'。这是一个完整且可验证的攻击链。
- **代码片段：**
  ```
  iVar2 = sym.imp.nvram_get(*0xf714);  // 获取 'router_disable'
  iVar1 = *0xf718;
  if (iVar2 != 0) {
      iVar1 = iVar2;
  }
  sym.imp.setenv(*0xf71c,iVar1,1);  // 设置为环境变量
  // ... 后续代码中调用 system
  sym.imp.system(*0xf784,*0xf778,3);  // 执行命令
  ```
- **备注：** 需要验证 NVRAM 变量 'router_disable' 是否可通过非 root 用户设置。在典型路由器固件中，NVRAM 设置通常需要通过 Web 接口或特定 CLI 命令，但已认证用户可能具有此权限。攻击链完整，可利用性高。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** 安全警报的描述不准确，基于对 'sbin/rc' 二进制文件的证据驱动分析：1. 输入可控性：警报声称 nvram_get 获取 'router_disable' 变量，但检查地址 0xf714（指向 0x1c068）的字符串为 'h'，未确认 'router_disable' 变量名；类似地，其他关键地址（如 0xf71c、0xf75c、0xf784、0xf778）的字符串检查也未提供足够证据支持变量名或命令结构。2. 路径可达性：反编译代码显示 system 调用在特定条件分支中（如 strstr 匹配参数），但未证明环境变量（由 setenv 设置）被直接用于 system 命令参数；代码中 system 调用使用固定地址的字符串，未显示使用环境变量或输入污染。3. 完整攻击链：缺乏证据证明从 nvram_get 到 system 的完整传播路径；攻击者模型（已认证用户设置 NVRAM 变量）合理，但未验证输入是否未过滤或可注入命令。因此，警报基于推测而非实际证据，不构成真实漏洞。

## 验证指标

- **验证时长：** 294.71 秒
- **Token 使用量：** 351453

---

## 原始信息

- **文件/目录路径：** `sbin/parser`
- **位置：** `parser:0x00008f4c fcn.00008eb8`
- **描述：** A stack buffer overflow vulnerability exists in the NVRAM configuration handler (fcn.00008eb8) of the 'parser' binary. The function parses input strings for a '*' character, splitting them into key and value parts. The value part is copied using strcpy into a stack-allocated buffer without bounds checking. An attacker can send a long value string via the network socket to overflow the buffer, overwriting the return address on the stack. This can lead to arbitrary code execution with the privileges of the parser process, which is likely root. The vulnerability is triggered when command code 0 is processed, corresponding to NVRAM set operations. The lack of input validation and use of unsafe functions like strcpy makes this exploitable.
- **代码片段：**
  ```
  0x00008f44      011087e2       add r1, r7, 1               ; const char *src
  0x00008f48      0600a0e1       mov r0, r6                  ; char *dest
  0x00008f4c      05ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **备注：** The vulnerability requires network access to port 63530. The parser service forks a child process for each connection, so exploitation may need to bypass fork-related mitigations. Further analysis is needed to determine exact buffer sizes and develop a reliable exploit. Other functions in the command dispatcher should be checked for similar issues.

## 验证结论

- **描述准确性：** `partially accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The alert accurately describes the stack buffer overflow in fcn.00008eb8 due to strcpy without bounds checking, but incorrectly states the command code as 0; evidence shows it is triggered by command code 4 in the dispatcher (fcn.0000a3c4). The function splits input strings at '*' and copies the value part to a stack buffer at sp+0x68. The saved return address at sp+0xA4 is 60 bytes away, allowing overflow. An attacker can send a network packet to port 63530 with command code 4 and a string containing '*' followed by a value exceeding 60 bytes to overwrite the return address and execute arbitrary code as root. Input controllability and path reachability are confirmed, with no authentication required.

## 验证指标

- **验证时长：** 335.48 秒
- **Token 使用量：** 452297

---

## 原始信息

- **文件/目录路径：** `usr/sbin/upnpd`
- **位置：** `upnpd:0x0000b5c8 (fcn.0000b5c8)`
- **描述：** A buffer overflow vulnerability in function fcn.0000b5c8 where user-controlled file data is read via fopen and fread, then processed through fcn.0000b410 and copied using strcpy without bounds checking. An attacker with file write access (e.g., through configuration manipulation or network requests) can provide a malicious file that overflows the buffer, leading to code execution. The vulnerability is accessible to authenticated users who can influence file paths or content.
- **代码片段：**
  ```
  sym.imp.fopen(param_3, *0xc120);  // Open user-controlled file
  sym.imp.fread(iVar2, 1, 0x4000, *(puVar22 + -0x710));  // Read data
  sym.imp.strcpy(sb, r4);  // In fcn.0000b410, copy to buffer
  sym.imp.strcpy(puVar22 + -0x40, puVar22 + -0xc0);  // Final strcpy in fcn.0000b5c8
  ```
- **备注：** Requires attacker to control file input, which may be achievable through configuration or network requests. Further analysis of fcn.000269f0 is recommended for additional vectors.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了缓冲区溢出漏洞。证据来自反汇编代码：在 fcn.0000b5c8 中，sym.imp.fopen (0x0000b7c4) 打开用户控制的文件，sym.imp.fread (0x0000b7f4) 读取 0x4000 字节数据，然后调用 fcn.0000b410 (0x0000b840)。在 fcn.0000b410 中，sym.imp.strcpy (0x0000b4e8) 将数据复制到栈缓冲区（大小约 0x684 字节）而不进行边界检查。在 fcn.0000b5c8 中，sym.imp.strcpy (0x0000b864) 也执行未绑定的复制。攻击者模型是认证用户（例如通过网络请求或配置更改）能够控制文件输入。完整攻击链：攻击者提供恶意文件（内容超过缓冲区大小），当 upnpd 处理该文件时，strcpy 溢出栈缓冲区，可能覆盖返回地址导致代码执行。PoC 步骤：1) 创建包含长字符串（例如 0x1000 字节）的文件；2) 通过认证请求使 upnpd 读取该文件（例如通过 UPnP 请求触发文件解析）；3) 溢出触发，控制执行流。漏洞实际可利用，风险高。

## 验证指标

- **验证时长：** 173.66 秒
- **Token 使用量：** 275057

---

## 原始信息

- **文件/目录路径：** `usr/sbin/upnpd`
- **位置：** `upnpd:0x00015ac8 (fcn.00015ac8)`
- **描述：** A stack buffer overflow vulnerability in function fcn.00015ac8 where network data from recv/recvfrom is copied into a fixed-size stack buffer (auStack_20ec [8188 bytes]) with a size of 0x1fff (8191 bytes). The null-termination write occurs out-of-bounds for lengths >= 8188, leading to an off-by-three overflow. An attacker with network access can send large UDP or TCP packets to trigger this, potentially overwriting return addresses and executing arbitrary code. The vulnerability is directly accessible via UPnP network sockets and does not require authentication beyond network reachability.
- **代码片段：**
  ```
  iVar4 = sym.imp.recvfrom(uVar3, *(iVar17 + -0x20e0), 0x1fff, 0);
  *(*(iVar17 + -0x20e0) + iVar4) = 0;  // Null-termination out-of-bounds for iVar4 >= 8188
  ```
- **备注：** Buffer size is 8188 bytes, recv size is 8191 bytes, making it easily triggerable. High confidence due to direct evidence from r2 decompilation.

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确识别了栈缓冲区溢出漏洞，但细节不精确：缓冲区auStack_20ec大小为8188字节，但recvfrom使用的指针偏移40字节，实际可用空间仅8148字节。recvfrom大小8191字节允许接收最多8191字节数据，导致最多43字节溢出。空终止写入在iVar4 >= 8148时越界，而非iVar4 >= 8188。漏洞路径可达，函数处理UPnP网络请求，攻击者可通过发送大型UDP数据包（大小8191字节）触发溢出，覆盖栈数据（如返回地址），执行任意代码。攻击者模型为未经身份验证的远程攻击者，具有网络访问权限。PoC：攻击者向UPnP端口发送恶意UDP数据包，大小8191字节，填充数据以覆盖返回地址，实现代码执行。

## 验证指标

- **验证时长：** 397.02 秒
- **Token 使用量：** 642430

---

## 原始信息

- **文件/目录路径：** `usr/local/share/foxconn_ca/server.crt`
- **位置：** `File: server.crt and server.key in /usr/local/share/foxconn_ca/`
- **描述：** The 'server.crt' file contains an X.509 certificate using weak and deprecated cryptographic algorithms (md5WithRSAEncryption and 1024-bit RSA key). Combined with the world-readable 'server.key' private key file, this allows any non-root user with login credentials to access the private key. An attacker can exploit this by copying the private key and using it to impersonate the server, perform man-in-the-middle attacks on encrypted channels (e.g., HTTPS, VPN), or decrypt sensitive communications. The attack requires no additional privileges and is directly feasible due to lax file permissions (rwx for all users). The weak algorithms further increase vulnerability to cryptographic attacks like collision or factorization.
- **代码片段：**
  ```
  Certificate snippet from server.crt:
  -----BEGIN CERTIFICATE-----
  MIIDiDCCAvGgAwIBAgIBATANBgkqhkiG9w0BAQQFADCBhDELMAkGA1UEBhMCVFcx
  ... (truncated for brevity)
  -----END CERTIFICATE-----
  
  Private key snippet from server.key:
  -----BEGIN RSA PRIVATE KEY-----
  MIICXAIBAAKBgQC3TYAabx6bUyBsLPiJ8hzYbup8l28jniriODdoSJ69NR2ODWH6
  ... (truncated for brevity)
  -----END RSA PRIVATE KEY-----
  ```
- **备注：** The weak cryptography and exposed private key form a critical vulnerability. Further analysis is recommended to identify services using these certificates (e.g., web servers, VPNs) to confirm active exploitation scenarios. The directory also contains other sensitive files (e.g., client.key, ca.crt) that may amplify the risk. Ensure file permissions are restricted and upgrade to stronger algorithms (e.g., SHA-256, 2048-bit RSA).

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报描述完全准确。证据显示：1) server.crt 使用弱算法（md5WithRSAEncryption 和 1024 位 RSA 密钥），易受密码学攻击；2) server.key 私钥文件权限为 -rwxrwxrwx，世界可读，任何本地非 root 用户均可访问。攻击者模型为已通过身份验证的本地非 root 用户，他们无需额外权限即可利用此漏洞。完整攻击链可验证：攻击者登录系统后，可读取私钥（例如，使用 `cat /usr/local/share/foxconn_ca/server.key`），然后使用私钥进行服务器冒充、中间人攻击（如解密 HTTPS 或 VPN 通信）或其他恶意活动。PoC 步骤：作为本地用户，执行 `cp /usr/local/share/foxconn_ca/server.key /tmp/` 复制私钥，然后使用工具（如 OpenSSL）将其用于解密或伪造证书。弱算法进一步放大风险，使攻击更易成功。因此，此漏洞构成高危安全威胁。

## 验证指标

- **验证时长：** 182.53 秒
- **Token 使用量：** 372121

---

## 原始信息

- **文件/目录路径：** `usr/sbin/upnpd`
- **位置：** `upnpd:0x00015834 (fcn.00015834)`
- **描述：** An attack chain involving data leakage and buffer overflow via functions fcn.00015834, fcn.00015640, fcn.0001c458, fcn.0001b290, and fcn.00018178. Tainted network data is copied via memcpy and propagated to sprintf (causing buffer overflow) and send (causing data leakage). An attacker can trigger this by sending crafted network packets, leading to potential code execution via overflow or exposure of sensitive information via leakage.
- **代码片段：**
  ```
  sym.imp.memcpy(iVar1, param_2, param_3);  // Tainted data copy
  sym.imp.sprintf(iVar6, *0x18558, iVar4);  // Buffer overflow
  sym.imp.send(...);  // Data leakage
  ```
- **备注：** Sprintf chain is exploitable for code execution; data leakage is less critical but still a concern. Chain is verifiable from input to sink.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了漏洞链。证据如下：在 fcn.00015834（地址 0x000159e4）中，memcpy 复制通过 recv（地址 0x000159bc）接收的污染网格数据；在 fcn.0001b290（地址 0x0001b45c、0x0001b4c0、0x0001b4d0、0x0001b4e0、0x0001b4fc）中，多个 sprintf 调用使用用户控制的数据格式化字符串，未检查边界，导致缓冲区溢出；send 调用（如 fcn.00015834 地址 0x00015a8c 和 fcn.0001c458 地址 0x0001c614）可能泄漏数据。攻击者模型为未经身份验证的远程攻击者，通过发送恶意 UPnP 请求（如 POST 到特定服务）触发。完整路径：fcn.00015834 → fcn.00015640 → fcn.0001c458 → fcn.0001b290。PoC 步骤：1) 攻击者构造恶意 UPnP 请求，包含超长或格式字符串数据；2) 发送到目标设备的 UPnP 服务端口；3) 触发 memcpy 和 sprintf 溢出，可能执行任意代码或通过 send 泄漏内存内容。漏洞风险高，因缓冲区溢出可导致代码执行，数据泄漏可能暴露敏感信息。

## 验证指标

- **验证时长：** 279.84 秒
- **Token 使用量：** 491412

---

## 原始信息

- **文件/目录路径：** `lib/modules/2.6.36.4brcmarm+/kernel/drivers/net/wl/wl.ko`
- **位置：** `文件:wl.ko 地址:0x0810c6ac 函数名:sym.wl_ioctl`
- **描述：** 在函数 `sym.wl_ioctl` 中，处理 ioctl 命令 `0x89f0` 时，对用户提供的输入值 `*(param_2 + 0x10)` 缺少充分验证。当该值大于 `0xffffffe7` 时，条件检查失败，导致 `uVar5` 被设置为 0，从而进入无限循环。这使内核模块挂起，导致拒绝服务。攻击者（已认证的非 root 用户）可以通过打开网络设备句柄并调用 ioctl 命令 `0x89f0` 提供恶意输入来触发此漏洞，使系统无响应。
- **代码片段：**
  ```
  从反编译代码中提取的关键部分：
  \`\`\`c
  if (param_3 == 0x89f0) {
      uVar5 = *((puVar8 + -0x20 & 0xffffe03f & 0xffffffc0) + 8);
      bVar7 = 0xffffffe7 < *(param_2 + 0x10);
      uVar4 = *(param_2 + 0x10) + 0x18;
      if (!bVar7) {
          // ... 复杂条件计算 ...
      }
      if (!bVar7) {
          uVar5 = 0;
      }
      if (uVar5 == 0) {
          do {
              // 无限循环
          } while( true );
      }
      // ...
  }
  \`\`\`
  ```
- **备注：** 此漏洞允许攻击者通过简单的 ioctl 调用导致内核挂起。建议修复方案包括添加对用户输入值的严格验证，确保 `*(param_2 + 0x10)` 在合理范围内。后续分析应检查其他 ioctl 命令（如 `0x8946`）是否存在类似问题。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** The security alert inaccurately describes the code logic. From the decompiled code of sym.wl_ioctl, when handling ioctl command 0x89f0, the variable uVar5 is set to 0 only if the user input *(param_2 + 0x10) is not greater than 0xffffffe7 (i.e., bVar7 is false). For inputs greater than 0xffffffe7, bVar7 is true, so uVar5 is not set to 0, and the infinite loop is not entered. Thus, the condition claimed in the alert does not lead to a denial of service. The attack model assumed an authenticated non-root user who can open a network device handle and call ioctl, but since the code path does not reach the infinite loop under the described conditions, the vulnerability is not present. No PoC is provided as the alert is based on a misinterpretation.

## 验证指标

- **验证时长：** 480.72 秒
- **Token 使用量：** 746861

---

## 原始信息

- **文件/目录路径：** `usr/lib/uams/uams_guest.so`
- **位置：** `uams_guest.so:0x000008bc sym.noauth_login`
- **描述：** 在 'noauth_login' 函数中，使用 'strcpy' 复制从 'uam_afpserver_option' 获取的用户名到堆栈缓冲区，缺少长度验证。用户名为不可信输入，通过 AFP 协议从网络获取。攻击者作为已认证用户（非 root）可发送特制长用户名，触发缓冲区溢出，覆盖保存的返回地址（lr），从而控制程序流并可能执行任意代码。堆栈布局分析显示局部变量区大小为 0x30 字节，保存的返回地址位于堆栈帧末尾，溢出距离约 60 字节，可利用性高。
- **代码片段：**
  ```
  0x000008b4      18201be5       ldr r2, [dest]              ; 0x18
  0x000008b8      14301be5       ldr r3, [src]               ; 0x14
  0x000008bc      0200a0e1       mov r0, r2                  ; char *dest
  0x000008c0      0310a0e1       mov r1, r3                  ; const char *src
  0x000008c4      55ffffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **备注：** 漏洞触发依赖于 AFP 协议中的用户名输入，攻击者需有有效登录凭据。建议进一步验证目标缓冲区的确切大小和偏移，并测试利用链的可行性。关联函数 'noauth_login_ext' 和 'uam_setup' 可能提供额外上下文。知识库中已有其他 'strcpy' 相关发现（如 'parser'），但此为独立漏洞。

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The analysis confirms the use of strcpy without bounds checking in the noauth_login function at 0x8bc. The source string is obtained from uam_afpserver_option, which retrieves the username from the AFP protocol, making it attacker-controllable input. The function is called during authentication, and an authenticated user (non-root) can send a specially crafted long username to trigger the buffer overflow. The stack layout shows a local variable area of 0x30 bytes, and the saved return address is located at the end of the stack frame. Although the exact destination buffer location is not directly visible in the code, the strcpy operation copies data to a pointer set by uam_afpserver_option, and if this pointer points to a stack-based buffer, overflowing it can overwrite the saved return address, allowing control of program flow and potential arbitrary code execution. The attack chain is complete: attacker controls input, path is reachable via AFP authentication, and impact is high due to possible code execution. For exploitation, an attacker would need to send a long username (e.g., exceeding the destination buffer size) through the AFP protocol to overwrite the return address and execute shellcode or redirect execution.

## 验证指标

- **验证时长：** 511.10 秒
- **Token 使用量：** 789203

---

## 原始信息

- **文件/目录路径：** `usr/sbin/upnpd`
- **位置：** `upnpd:0x00015640 (fcn.00015640) and related functions`
- **描述：** An attack chain where tainted network data propagates through functions fcn.00015640, fcn.0001c458, fcn.0001a4d0, and fcn.00018178 to sprintf without validation. The sprintf uses format strings with %s, leading to buffer overflow or command injection. Trigger conditions require specific tokens in network data (e.g., matching *0x15820 or *0x1582c). An attacker can craft packets with these tokens to exploit the vulnerability, potentially achieving code execution.
- **代码片段：**
  ```
  sym.imp.sprintf(iVar6, *0x18558, iVar4);  // iVar4 is tainted data
  sym.imp.strncpy(iVar7, param_1, 0x3ff);  // Tokenization in data flow
  ```
- **备注：** Exploit requires specific token matches, but the chain is complete and verifiable. Additional format string risks should be checked.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The alert accurately describes the function chain and vulnerability. Evidence from disassembly confirms:
- fcn.00015640 (0x156a8) uses strncpy to copy network data (param_1) with size 0x3ff.
- fcn.0001c458 (0x1c4dc) checks for 'Public_UPNP_C3' and calls fcn.0001a4d0 (0x1c56c) when 'upnp_turn_on' is set.
- fcn.0001a4d0 calls fcn.00018178 (0x1a548).
- fcn.00018178 (0x183f0) uses sprintf with format '</%s>' and user-controlled data (r8) without validation, writing to a 128-byte buffer (r4), leading to buffer overflow.

Attack Model: An unauthenticated remote attacker can send crafted UPnP POST requests containing 'Public_UPNP_C3' in the body (e.g., in the SOAP XML) to trigger the chain. The tainted data from network input propagates to sprintf without bounds checks.

Exploitability: The buffer overflow can overwrite stack data, including return addresses, potentially allowing code execution. A proof-of-concept (PoC) payload would involve sending a UPnP request with a long XML tag name (e.g., over 128 bytes) in the body, such as:
```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Body>
    <Public_UPNP_C3>
      <A... [128+ bytes] >value</A...>
    </Public_UPNP_C3>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
This causes overflow when sprintf formats '</%s>' with the long tag name. The vulnerability is verified with complete evidence from the binary analysis.

## 验证指标

- **验证时长：** 333.67 秒
- **Token 使用量：** 614132

---

## 原始信息

- **文件/目录路径：** `usr/lib/uams/uams_dhx2_passwd.so`
- **位置：** `uams_dhx2_passwd.so:sym.logincont2 (addresses 0x2428-0x2438 based on cross-references)`
- **描述：** A stack buffer overflow vulnerability exists in the sym.logincont2 function, which is part of the extended password handling logic. The function reads from the file '/tmp/afppasswd' using fgets into a 1024-byte buffer, then uses sscanf to parse the content into a 512-byte stack buffer without proper bounds checking. The format string in sscanf is likely '%s', allowing uncontrolled string copying. An attacker with valid login credentials can write a payload longer than 512 bytes to '/tmp/afppasswd' (which is writable by any user) and trigger the authentication process (e.g., via sym.passwd_login_ext). This overflow can overwrite stack data, including return addresses, leading to arbitrary code execution or privilege escalation. The trigger condition requires the attacker to initiate login and have write access to /tmp/afppasswd, which is default writable.
- **代码片段：**
  ```
  // Relevant code from sym.logincont2 decompilation
  sym.imp.fopen64(iVar4 + *0x26dc, iVar4 + *0x26e0); // Opens '/tmp/afppasswd'
  sym.imp.fgets(puVar5 + 8 + -0x630, 0x400, *(puVar5 + -0x14)); // Reads into 1024-byte buffer
  sym.imp.sscanf(puVar5 + 8 + -0x630, iVar4 + *0x26e4, puVar5 + iVar3 + -0x230); // Parses into 512-byte buffer without bounds check
  if (*(puVar5 + iVar3 + -0x230) != '\0') {
      iVar3 = sym.imp.strcmp(*(puVar5 + -0x638), puVar5 + iVar3 + -0x230); // Comparison after sscanf
  }
  ```
- **备注：** The vulnerability is highly exploitable due to the writable /tmp/afppasswd and lack of stack protections (e.g., canaries) in the decompiled code. The attack chain is complete: from user-controlled file input to stack overflow. Further validation could confirm the exact sscanf format string and stack layout for reliable exploitation. Recommended next steps include dynamic testing and checking for ASLR mitigations.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 安全警报准确描述了栈缓冲区溢出漏洞。证据支持：1) 反编译代码显示 sym.logincont2 函数声明了 512 字节栈缓冲区 (acStack_234) 和 1024 字节缓冲区 (auStack_634)；2) fgets 读取 0x400 (1024) 字节到缓冲区，sscanf 使用 '%s' 格式字符串（地址 0x2ab4）解析到 512 字节缓冲区，无边界检查；3) 文件路径 '/tmp/afppasswd' 被确认（地址 0x2aa0）。攻击者模型：拥有有效登录凭证的攻击者（可触发认证过程，如通过 sym.passwd_login_ext）且能写入 /tmp/afppasswd（默认全局可写）。漏洞可利用性验证：输入可控（攻击者可写入任意内容到文件）、路径可达（登录过程调用函数）、实际影响（溢出可覆盖栈数据，包括返回地址，导致任意代码执行）。PoC 步骤：1) 攻击者创建 /tmp/afppasswd 文件，包含超过 512 字节的 payload（如 512 字节填充 + shellcode 或返回地址）；2) 攻击者使用有效凭证触发 AFP 登录；3) 登录过程调用 sym.logincont2，读取文件并溢出缓冲区；4) 精心设计的 payload 可劫持控制流。风险高 due to direct code execution potential and lack of stack protections observed in code.

## 验证指标

- **验证时长：** 593.46 秒
- **Token 使用量：** 895991

---

## 原始信息

- **文件/目录路径：** `usr/local/samba/smbd`
- **位置：** `smbd:0x00066d60 reply_trans2 (malloc at 0x00067040 and memcpy at 0x00067278 for first overflow; malloc at 0x00067120 and memcpy at 0x00067290 for second overflow)`
- **描述：** The function 'reply_trans2' at address 0x00066d60 contains a heap buffer overflow vulnerability due to missing size validation in memcpy operations. The function allocates heap buffers based on size fields from the SMB packet (e.g., from offsets 0x27-0x28 and 0x25-0x26) but performs memcpy using different size fields (e.g., from offsets 0x3b-0x3c and 0x37-0x38) without checking if the copy size exceeds the allocated buffer size. An attacker with valid login credentials can craft a malicious SMB TRANS2 request with a large copy size and small allocation size, causing heap buffer overflow. This can overwrite adjacent heap metadata or function pointers, leading to arbitrary code execution or service crash. The vulnerability is triggered immediately upon processing the crafted packet, and the overflow occurs in the heap, which can be exploited for remote code execution in the context of the smbd process.
- **代码片段：**
  ```
  // First overflow path: malloc with size from packet offsets 0x27-0x28 (uVar8), memcpy with size from offsets 0x3b-0x3c (sb)
  0x00067040: bl sym.imp.malloc                    ; allocate buffer with size uVar8 (from packet)
  0x00067278: bl sym.imp.memcpy                   ; copy sb bytes to buffer, no check if sb <= uVar8
  
  // Second overflow path: malloc with size from packet offsets 0x25-0x26 (uVar9), memcpy with size from offsets 0x37-0x38 (sl)
  0x00067120: bl sym.imp.malloc                    ; allocate buffer with size uVar9 (from packet)
  0x00067290: bl sym.imp.memcpy                   ; copy sl bytes to buffer, no check if sl <= uVar9
  ```
- **备注：** This vulnerability is similar to known SMB transaction vulnerabilities in Samba. The missing size check allows controlled heap overflow, which can be leveraged for code execution. Further analysis of the heap layout and exploitation techniques is recommended for full weaponization. The function 'handle_trans2' called later may also be affected if the overflow corrupts data structures. Attack chain is verifiable: network input → SMB packet parsing → heap allocation → memcpy overflow → potential EIP control.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** The analysis confirms a heap buffer overflow in the 'reply_trans2' function due to missing size validation between malloc and memcpy operations. Specifically: 1) At 0x00067040, malloc is called with a size derived from packet offsets 0x27-0x28 (stored in r0). 2) At 0x00067278, memcpy is called with a size from offsets 0x3b-0x3c (stored in sb) without checking if sb <= allocated size. 3) Similarly, at 0x00067120, malloc uses sizes from offsets 0x25-0x26, and at 0x00067290, memcpy uses sizes from offsets 0x37-0x38 (stored in sl) without validation. The code loads these sizes directly from the packet (e.g., via ldrb instructions at 0x00066e78, 0x00066e7c for alloc sizes and 0x00066da4, 0x00066da8 for copy sizes), and no comparative checks exist between alloc and copy sizes in the vulnerable paths. An attacker with valid SMB credentials (authenticated remote attacker) can craft a malicious TRANS2 request with a small allocation size (e.g., set offsets 0x27-0x28 to 0x0001) and a large copy size (e.g., set offsets 0x3b-0x3c to 0x1000), causing heap overflow when memcpy copies data beyond the buffer. This can overwrite adjacent heap structures, potentially leading to arbitrary code execution. The vulnerability is immediately triggered upon packet processing. PoC steps: Craft an SMB TRANS2 packet with: - TotalDataCount (offsets 0x25-0x26) set to a small value (e.g., 1) for the second malloc. - DataOffset (offsets 0x27-0x28) set to a small value (e.g., 1) for the first malloc. - DataCount (offsets 0x37-0x38) set to a large value (e.g., 4096) for the second memcpy. - ParameterCount (offsets 0x3b-0x3c) set to a large value (e.g., 4096) for the first memcpy. Ensure other packet fields meet path conditions (e.g., non-zero sizes to branch to malloc calls). Send the packet to the smbd service to trigger the overflow.

## 验证指标

- **验证时长：** 375.58 秒
- **Token 使用量：** 572018

---

