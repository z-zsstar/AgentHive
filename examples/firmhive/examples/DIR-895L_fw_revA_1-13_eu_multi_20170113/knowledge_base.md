# DIR-895L_fw_revA_1-13_eu_multi_20170113 (40 个发现)

---

### CodeInjection-form_macfilter

- **文件/目录路径：** `htdocs/mydlink/form_macfilter`
- **位置：** `form_macfilter: 多个 fwrite 调用和 dophp 调用（具体行号不可用，但代码段中可见）`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 该脚本存在代码注入漏洞，允许攻击者通过可控的 POST 参数注入并执行任意 PHP 代码。问题源于脚本将用户输入直接嵌入到临时 PHP 文件中，然后使用 dophp('load', $tmp_file) 执行。触发条件包括：settingsChanged=1 且提供恶意的 POST 参数（如 entry_enable_*、mac_* 等）。攻击者可以注入代码如 '; system('id'); //' 来执行系统命令。约束条件：攻击者需具有有效登录凭据（非 root 用户），并能发送 POST 请求到该脚本。潜在攻击方式包括远程代码执行、权限提升或系统控制。
- **代码片段：**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac = $_POST[\"mac_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_hostname = $_POST[\"mac_hostname_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_addr = $_POST[\"mac_addr_".$i."\"];\n");
  fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
  dophp("load",$tmp_file);
  ```
- **关键词：** $_POST['settingsChanged'], $_POST['macFltMode'], $_POST['entry_enable_*'], $_POST['mac_*'], $_POST['mac_hostname_*'], $_POST['mac_addr_*'], $_POST['sched_name_*'], /tmp/form_macfilter.php, dophp, runservice
- **备注：** 漏洞利用链完整：用户输入 → 临时文件写入 → 代码执行。建议进一步验证 dophp 函数的实现和运行环境。关联文件：/htdocs/mydlink/libservice.php（可能包含 dophp 定义）。后续分析方向：检查其他类似脚本是否存在相同问题，并评估 runservice 调用的影响。

---
### Code-Injection-form_wlan_acl

- **文件/目录路径：** `htdocs/mydlink/form_wlan_acl`
- **位置：** `form_wlan_acl:20-25 (估计行号，基于代码结构；具体涉及 fwrite 和 dophp 调用)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 该脚本在处理无线 MAC 地址过滤时，将用户控制的 POST 参数（如 'mac_*' 和 'enable_*'）直接写入临时 PHP 文件（/tmp/form_wlan_acl.php）并执行（通过 dophp 函数），导致任意代码执行。触发条件包括：攻击者发送 POST 请求到处理此脚本的端点，设置 'settingsChanged=1' 和包含 PHP 代码的 'mac_*' 参数（例如，值如 'abc'; system('id'); //'）。利用方式包括执行系统命令，可能以 web 服务器权限运行，允许攻击者提升权限或控制设备。代码中缺少输入验证和转义，使注入成为可能。
- **代码片段：**
  ```
  fwrite("a", $tmp_file, "$MAC = $_POST[\"mac_".$i.\"];\n"); fwrite("a", $tmp_file, "$ENABLE = $_POST[\"enable_".$i.\"];\n"); dophp("load",$tmp_file);
  ```
- **关键词：** $_POST['mac_*'], $_POST['enable_*'], /tmp/form_wlan_acl.php, dophp 函数
- **备注：** 需要进一步验证 dophp 函数的具体实现（可能位于包含文件中），但基于代码逻辑，漏洞明显且攻击链完整。建议检查相关文件（如 /htdocs/phplib/inf.php）以确认函数行为。此漏洞可能与其他组件交互，例如通过 NVRAM 或服务重启（runservice），但当前分析专注于文件本身。

---
### Code-Injection-form_portforwarding

- **文件/目录路径：** `htdocs/mydlink/form_portforwarding`
- **位置：** `form_portforwarding: in the main script body, within the while loop handling POST data (approximately lines 20-40 in the code)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** The 'form_portforwarding' script contains a code injection vulnerability that allows remote code execution (RCE). The vulnerability occurs when the script processes form submissions (triggered by POST parameter 'settingsChanged=1'). It writes user-controlled POST data (e.g., 'enabled_$i', 'name_$i', etc.) directly into a temporary PHP file (/tmp/form_portforwarding.php) using fwrite statements without input validation or escaping. The file is then included and executed via dophp('load', $tmp_file). An attacker can inject malicious PHP code by crafting POST values that break the string context and execute arbitrary commands. For example, setting a POST variable to '1"; system("id"); //' would result in code execution. The attack requires authentication but not root privileges, and it can be triggered via a single HTTP POST request to the script. This leads to full compromise of the web server process, potentially allowing privilege escalation or other attacks.
- **代码片段：**
  ```
  while($i < $max)
  {
      fwrite("w+", $tmp_file, "<?\n");
      fwrite("a", $tmp_file, "$enable = $_POST[\"enabled_".$i."\"];\n");
      fwrite("a", $tmp_file, "$used = $_POST[\"used_".$i."\"];\n");
      fwrite("a", $tmp_file, "$name = $_POST[\"name_".$i."\"];\n");
      fwrite("a", $tmp_file, "$public_port = $_POST[\"public_port_".$i."\"];\n");
      fwrite("a", $tmp_file, "$public_port_to = $_POST[\"public_port_to_".$i."\"];\n");
      fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
      fwrite("a", $tmp_file, "$ip = $_POST[\"ip_".$i."\"];\n");
      fwrite("a", $tmp_file, "$private_port = $_POST[\"private_port_".$i."\"];\n");
      fwrite("a", $tmp_file, "$hidden_private_port_to = $_POST[\"hidden_private_port_to_".$i."\"];\n");
      fwrite("a", $tmp_file, "$protocol = $_POST[\"protocol_".$i."\"];\n");
      fwrite("a", $tmp_file, "?>\n");
      dophp("load",$tmp_file);
      // ... subsequent configuration setting
  }
  ```
- **关键词：** POST parameters: settingsChanged, enabled_$i, used_$i, name_$i, public_port_$i, public_port_to_$i, sched_name_$i, ip_$i, private_port_$i, hidden_private_port_to_$i, protocol_$i, Temporary file: /tmp/form_portforwarding.php, NVRAM paths: /nat/entry/virtualserver, /schedule
- **备注：** This vulnerability is highly exploitable and provides a clear attack chain from input to code execution. The web server likely runs with elevated privileges (possibly root) in embedded devices, amplifying the impact. Further analysis could verify the dophp function's behavior and check for other files in the include chain (e.g., /htdocs/phplib/inf.php) for additional vulnerabilities. Mitigation requires input sanitization (e.g., using escapeshellarg or validation) before writing to files.

---
### Command-Injection-ACCESSCTRL

- **文件/目录路径：** `etc/services/ACCESSCTRL.php`
- **位置：** `ACCESSCTRL.php (大致行号: 在foreach循环中处理machine/entry和portfilter/entry的部分)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 ACCESSCTRL.php 文件中，用户输入的配置参数（如IP地址、MAC地址、URL等）被直接拼接到iptables命令字符串中，没有进行输入验证、过滤或转义。当访问控制功能启用时（'/acl/accessctrl/enable'=='1'），脚本会生成并执行一个shell脚本。攻击者作为已认证的非root用户，可以通过修改ACL配置（例如通过web界面）注入恶意输入。例如，在IP地址字段中输入 '127.0.0.1; malicious_command' 会导致生成的脚本包含任意命令执行。由于iptables规则通常需要root权限来应用，注入的命令可能以root权限执行，从而导致权限提升、系统妥协或拒绝服务。漏洞触发条件包括：访问控制启用、至少一个ACL条目启用，以及脚本被执行。
- **代码片段：**
  ```
  foreach ("machine/entry")
  {
      if(query("type")=="IP")    
      {       
          fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -s ".query("value")." -j FOR_POLICY_FILTER".$i."\n");
          fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -s ".query("value")." -j ACCEPT\n");
      }
      else if(query("type")=="MAC")   
      {
          fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -m mac --mac-source ".query("value")." -j FOR_POLICY_FILTER".$i."\n");
          fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -m mac --mac-source ".query("value")." -j ACCEPT\n");
      }
      else                           fwrite("a",$START, "iptables -t filter -A FOR_POLICY_RULE".$i." -j FOR_POLICY_FILTER".$i."\n");
  }
  ```
- **关键词：** /acl/accessctrl/enable, /acl/accessctrl/entry/machine/entry/value, /acl/accessctrl/entry/machine/entry/type, /acl/accessctrl/webfilter/entry/url, /acl/accessctrl/portfilter/entry/startip, /acl/accessctrl/portfilter/entry/endip, /acl/accessctrl/portfilter/entry/startport, /acl/accessctrl/portfilter/entry/endport, /acl/accessctrl/portfilter/entry/protocol, /acl/accessctrl/action
- **备注：** 漏洞的利用依赖于生成的shell脚本以root权限执行，这在实际固件中常见。建议进一步验证脚本执行机制（如通过init脚本或服务）和输入点的可达性（如通过web界面）。关联文件可能包括 /htdocs/phplib/ 中的库文件，但当前分析仅限 ACCESSCTRL.php。这是一个实际可利用的漏洞，攻击链完整：输入点（配置参数）→ 数据流（直接拼接）→ 危险操作（shell命令执行）。

---
### Path-Traversal-mdb_get_mdb_set

- **文件/目录路径：** `etc/scripts/mydlink/mdb.php`
- **位置：** `mdb.php:行号未知（函数 mdb_get 和 mdb_set）`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'mdb.php' 的 `mdb_get` 和 `mdb_set` 函数中，处理 `attr_*` 命令时，用户可控的 `$cmd_name` 参数被直接拼接到文件路径 `/mydlink/` 中，未进行路径遍历过滤。攻击者可以构造恶意 `$cmd_name`（如 `attr_../../etc/passwd`）来遍历目录结构，实现任意文件读写。触发条件：攻击者已拥有有效登录凭据，并向 `mdb.php` 发送 `ACTION` 为 `GET` 或 `SET`、`CMD` 以 `attr_` 开头但包含路径遍历序列的请求。利用方式：通过 `GET` 动作读取系统敏感文件（如 /etc/shadow）获取密码哈希，或通过 `SET` 动作写入文件（如 /etc/passwd）添加用户以实现权限提升。该漏洞无需额外条件，可直接利用。
- **代码片段：**
  ```
  在 mdb_get 函数中：
  else if(strstr($cmd_name,"attr_") != "") {show_result(query($mydlink_path."/".$cmd_name));}
  
  在 mdb_set 函数中：
  else if(strstr($cmd_name,"attr_") != "") {set($mydlink_path."/".$cmd_name,$cmd_value);}
  ```
- **关键词：** $_GLOBALS["CMD"], $cmd_name, /mydlink/, /runtime/mydlink/mdb
- **备注：** 证据来自代码分析，显示路径遍历漏洞明显且可利用。建议进一步验证 `query` 和 `set` 函数的实现以确认文件操作权限，并检查其他组件是否受此漏洞影响。后续可分析相关 PHP 库文件（如 /htdocs/phplib/xnode.php）以追踪数据流。

---
### PrivKey-Exposure-stunnel.key

- **文件/目录路径：** `etc/stunnel.key`
- **位置：** `stunnel.key:1 (文件路径，无具体行号或函数)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 文件 'stunnel.key' 包含一个 PEM RSA 私钥，且文件权限设置为 777（-rwxrwxrwx），允许所有用户（包括非root用户）完全访问。攻击者作为已登录用户，可以直接读取私钥，从而用于解密 SSL/TLS 通信、进行中间人攻击或冒充服务器。触发条件简单：攻击者只需拥有有效登录凭据并访问文件系统。潜在攻击包括窃取敏感通信数据或破坏服务完整性。约束条件极少，因为权限开放，无需额外权限即可利用。
- **代码片段：**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAo/0bZcpc3Npc89YiNcP+kPxhLCGLmYXR4rHLt2I1BbnkXWHk
  MY1Umfq9FAzBYSvPYEGER4gYq467yvp5wO97CUoTSJHbJDPnp9REj6wLcMkG7R9O
  g8/WuQ3hsoexPu4YkjJXPhtQ6YkV7seEDgP3C2TNqCnHdXzqSs7+vT17chwu8wau
  j/VMVZ2FRHU63JQ9DG6PqcudHTW+T/KVnmWXQnspgr8ZMhXobETtdqtRPtxbA8mE
  ZeF8+cIoA9VcqP09/VMBbRm+o5+Q4hjtvSrv+W2bEd+BDU+V45ZX8ZfPoEWYjQqI
  kv7aMECTIX2ebgKsjCK3PfYUX5PYbVWUV+176wIDAQABAoIBAQCQR/gcBgDQO7t+
  uc9dmLTYYYUpa9ZEW+3/U0kWbuyRvi1DUAaS5nMiCu7ivhpCYWZSnTJCMWbrQmjN
  vLT04H9S+/6dYd76KkTOb79m3Qsvz18tr9bHuEyGgsUp66Mx6BBsSKhjt2roHjnS
  3W29WxW3y5f6NdAM+bu12Ate+sIq8WHsdU0hZD+gACcCbqrt4P2t3Yj3qA9OzzWb
  b9IMSE9HGWoTxEp/TqbKDl37Zo0PhRlT3/BgAMIrwASb1baQpoBSO2ZIcwvof31h
  IfrbUWgTr7O2Im7OiiL5MzzAYBFRzxJsj15mSm3/v3cZwK3isWHpNwgN4MWWInA1
  t39bUFl5AoGBANi5fPuVbi04ccIBh5dmVipy5IkPNhY0OrQp/Ft8VSpkQDXdWYdo
  MKF9BEguIVAIFPQU6ndvoK99lMiWCDkxs2nuBRn5p/eyEwnl2GqrYfhPoTPWKszF
  rzzJSBKoStoOeoRxQx/QFN35/LIxc1oLv/mFmZg4BqkSmLn6HrFq2suVAoGBAMG1
  CqmDs2vU43PeC6G+51XahvRI3JOL0beUW8r882VPUPsgUXp9nH3UL+l9/cBQQgUC
  n12osLOAXhWDJWvJquK9HxkZ7KiirNX5eJuyBeaxtOSfBJEKqz/yGBRRVBdBHxT2
  a1+gO0MlG6Dtza8azl719lr8m6y2O9pyIeUewUl/AoGAfNonCVyls0FwL57n+S2I
  eD3mMJtlwlbmdsI1UpMHETvdzeot2JcKZQ37eIWyxUNSpuahyJqzTEYhf4kHRcO/
  I0hvAe7UeBrLYwlZquH+t6lQKee4km1ULcWbUrxHGuX6aPBDBkG+s75/eDyKwpZA
  S0RPHuUv2RkQiRtxsS3ozB0CgYEAttDCi1G82BxHvmbl23Vsp15i19KcOrRO7U+b
  gmxQ2mCNMTVDMLO0Kh1ESr2Z6xLT/B6Jgb9fZUnVgcAQZTYjjXKoEuygqlc9f4S/
  C1Jst1koPEzH5ouHLAa0KxjGoFvZldMra0iyJaCz/qHw6T4HXyALrbuSwOIMgxIM
  Y00vZskCgYAuUwhDiJWzEt5ltnmYOpCMlY9nx5qJnfcSOld5OHZ0kUsRppKnHvHb
  MMVyCTrp1jiH/o9UiXrM5i79fJBk7NT7zqKdI0qmKTQzNZhmrjPLCM/xEwAXtQMQ
  1ldI69bQEdRwQ1HHQtzVYgKA9XCmvrUGXRq6E5sp2ky+X1QabC7bIg==
  -----END RSA PRIVATE KEY-----
  ```
- **关键词：** stunnel.key
- **备注：** 这是一个高度可利用的漏洞，因为私钥暴露且权限宽松。攻击者无需复杂步骤即可获取敏感信息。建议立即修复文件权限（例如，设置为 600），仅允许必要用户访问。后续分析应检查 stunnel 相关配置和服务，以评估潜在影响范围。

---
### Command-Injection-minidlna-main

- **文件/目录路径：** `usr/bin/minidlna`
- **位置：** `minidlna:0x0000be2c (main function) at the system call invocation`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A command injection vulnerability exists in the minidlna binary when handling the '-R' option (force rescan). The vulnerability allows arbitrary command execution via unsanitized input in the config file path. Specifically, when '-R' is invoked, the program constructs a command string using snprintf with the format 'rm -rf %s/files.db %s/art_cache' and passes it to system(). The %s placeholder is replaced with the config file path (from '-f' argument or default), which is user-controlled. If the path contains shell metacharacters (e.g., ';', '|', '&'), additional commands can be injected. For example, a config path like '/tmp; echo exploited' would execute 'echo exploited' during the rm command. This can be triggered by an authenticated user with access to minidlna command-line or config file, potentially leading to privilege escalation if minidlna runs as root.
- **代码片段：**
  ```
  // Decompiled code snippet from main function (fcn.0000be2c)
  case 0x6: // Corresponds to '-R' option
      ppiVar21 = *0xce7c; // Points to "rm -rf %s/files.db %s/art_cache"
      snprintf(*(puVar26 + -0x11b0), 0x1000, ppiVar21, *(puVar26 + -0x11c0)); // Format string with config path
      iVar14 = system(*(puVar26 + -0x11b0)); // Command injection here
      // ... error handling
  ```
- **关键词：** minidlna command-line options: -R, -f, Config file path: /etc/minidlna.conf (default), Environment variables: None directly, but influenced by user input
- **备注：** The vulnerability requires the '-R' option to be triggered, which is documented for force rescan. The config path is typically controlled via '-f' or default config file. In embedded systems, minidlna often runs as root, so exploitation could lead to full device compromise. Further analysis should verify how minidlna is started (e.g., via init scripts) and whether users can influence arguments. No additional vulnerabilities were identified in this analysis, but the code contains other risky functions (e.g., strcpy) that should be reviewed in depth.

---
### stack-buffer-overflow-main

- **文件/目录路径：** `usr/libexec/ipsec/showhostkey`
- **位置：** `showhostkey:0x0000f4ec (main 函数 case 0x27)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'showhostkey' 二进制文件的主函数中，处理 --file 命令行选项时存在栈缓冲区溢出漏洞。具体来说，当使用 --file 选项并提供长参数时，程序使用 strncat 将参数追加到栈缓冲区，但缓冲区大小（4172 字节）可能已被之前的 snprintf 调用部分填充（最多 4096 字节）。strncat 允许追加最多 4095 字节，导致缓冲区溢出。攻击者可以精心构造长字符串覆盖返回地址，实现代码执行。触发条件：运行 'ipsec showhostkey --file <长字符串>'，其中 <长字符串> 长度超过 76 字节（剩余缓冲区空间）。潜在攻击方式包括覆盖返回地址指向 shellcode 或 ROP 链，从而提升权限或执行任意命令。
- **代码片段：**
  ```
  case 0x27:
      *(piVar7 + (0xefb0 | 0xffff0000) + 4) = 0;
      sym.strncat(piVar7 + 0 + -0x104c, **(iVar2 + *0xf8fc), 0xfff);
      break;
  ```
- **关键词：** --file, /etc/ipsec.secrets
- **备注：** 二进制文件为 ARM 32-bit ELF，动态链接，未剥离，无栈保护证据（未发现 __stack_chk_fail）。攻击链完整：输入点（--file 参数）→ 数据流（strncat 追加到栈缓冲区）→ 危险操作（返回地址覆盖）。建议进一步验证文件权限（如 setuid）和系统 ASLR 状态。关联函数：main、strncat、snprintf。

---
### command-injection-_include

- **文件/目录路径：** `usr/lib/ipsec/_include`
- **位置：** `_include:95 (在 awk 脚本的 system 调用中)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 '_include' 脚本中发现一个命令注入漏洞。该脚本用于处理 IPSec 配置文件中的嵌套包含指令。当脚本解析输入文件时，如果遇到 'include' 指令，它会提取文件名并直接传递给 system() 调用（第95行），而没有进行适当的验证或转义。攻击者可以通过在配置文件中注入恶意文件名（例如，包含 shell 元字符如 ';'、'&' 或 '|'）来执行任意命令。触发条件包括：攻击者能够创建或修改被 ipsec 进程处理的配置文件（例如，通过 IPC 或文件写入权限），并且该文件包含恶意的 'include' 指令。利用方式：攻击者可以注入命令来提升权限、访问敏感数据或执行其他恶意操作。
- **代码片段：**
  ```
  95: system("ipsec _include " newfile)
  ```
- **关键词：** newfile, IPSEC_CONFS, ipsec _include
- **备注：** 此漏洞的利用依赖于攻击者能够控制输入文件的内容。建议进一步分析 ipsec 的其他组件（如主配置文件 ipsec.conf）以确认攻击链的完整性。此外，需要验证 ipsec _include 是否以特权权限运行（例如 root），这可能增加风险。后续分析应关注如何通过 IPC 或 NVRAM 设置来触发文件处理。

---
### 缓冲区溢出-fcn.0000c1b8

- **文件/目录路径：** `usr/sbin/rgbin`
- **位置：** `rgbin:0x0000c4d8 fcn.0000c1b8`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'tcprequest' 命令（函数 fcn.0000c1b8）中，存在栈缓冲区溢出漏洞。函数分配 0x4c4 字节栈空间，但 recv 调用使用偏移 0x40c 的缓冲区，允许写入最多 0x400 字节（1024 字节），而可用栈空间仅约 196 字节（0x4d0 - 0x40c = 0xc4 字节）。攻击者控制 TCP 服务器时，可发送大型响应溢出缓冲区，覆盖保存的寄存器（包括返回地址），导致任意代码执行。触发条件：攻击者拥有有效登录凭据并执行 'tcprequest' 命令连接到恶意服务器。利用方式：恶意服务器发送超过 196 字节的响应，劫持程序流。代码中使用 select 和 recv，缺乏边界检查。
- **代码片段：**
  ```
  0x0000c4bc: sub r3, var_420h
  0x0000c4c0: sub r3, r3, 0xc
  0x0000c4c4: sub r3, r3, 8
  0x0000c4c8: ldr r0, [fildes]
  0x0000c4cc: mov r1, r3
  0x0000c4d0: mov r2, 0x400
  0x0000c4d4: mov r3, 0
  0x0000c4d8: bl sym.imp.recv
  ; recv writes up to 0x400 bytes to stack buffer at [sp + 0x40c]
  ```
- **关键词：** tcprequest, fcn.0000c1b8, recv, select, 栈缓冲区地址 sp+0x40c
- **备注：** 漏洞直接通过网络输入可利用。攻击需要用户运行 tcprequest 对抗恶意服务器。二进制中未发现明显的栈保护或 ASLR，使利用可行。建议确认二进制是否 setuid 或有其他权限，可能导致权限提升。函数 fcn.0000c1b8 从主入口点调用，tcprequest 可能是用户可访问命令。

---
### 命令注入-fcn.0000cc20

- **文件/目录路径：** `usr/sbin/rgbin`
- **位置：** `rgbin:0x0000cc20 fcn.0000cc20`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'login' 命令（函数 fcn.0000cc20）中，存在命令注入漏洞。攻击者通过 -l 命令行选项注入任意命令，在身份验证成功后执行。触发条件：攻击者拥有有效的用户名和密码（非 root 用户），并调用 'login -l <malicious_command> username password'。身份验证逻辑比较用户名和密码，如果匹配，则通过 system() 函数执行 -l 选项指定的字符串。由于缺乏对 -l 参数的过滤或验证，攻击者可以注入任意 shell 命令，导致权限提升或系统 compromise。代码中使用 strncpy 进行输入复制，缓冲区大小（80 字节）和复制大小（0x50=80）匹配，缓冲区溢出风险低。
- **代码片段：**
  ```
  关键代码片段：
  - 选项处理：
    if (iVar1 == 0x6c) { // -l 选项
        *(0xe300 | 0x20000) = *(0xe470 | 0x20000); // 将 -l 参数存储到全局变量
    }
  - 身份验证成功后的执行：
    if (iVar1 == 0) { // 用户名匹配
        iVar1 = sym.imp.strcmp(piVar4 + -0xac, piVar4 + -0x14c); // 密码比较
        if ((iVar1 == 0) || ... ) {
            sym.imp.system(*(0xe300 | 0x20000)); // 执行 -l 参数指定的命令
        }
    }
  ```
- **关键词：** 命令行选项 -l, 全局变量地址 0xe300（存储 -l 参数）, system() 函数调用, 用户名和密码输入
- **备注：** 漏洞可利用性高，因为攻击者只需有效凭据和恶意 -l 参数即可触发。建议验证 -l 参数是否来自用户输入（通过 getopt），并检查是否有其他输入点。需要进一步分析全局变量 0xe300 和 0xe470 的来源，以确认完整攻击链。缓冲区溢出风险低，但建议检查相关函数 fcn.0000c7cc 和 fcn.0000c9e8 的输入处理。

---
### command-injection-ephp

- **文件/目录路径：** `usr/sbin/xmldb`
- **位置：** `fcn.0002ce60:0x2cea4 (system call)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 发现一个通过嵌入 PHP (ephp) 解析导致的命令注入漏洞。攻击者可以通过 xmldbc 客户端工具设置包含恶意 PHP 代码的 XML 节点值，当该值被 ephp 解析时，会调用 system() 函数执行任意命令。具体触发条件包括：使用 xmldbc 的 -s 选项设置节点值，或通过 -P 选项直接执行 ephp 文件。漏洞源于 ephp 解析器中缺乏对用户输入的有效过滤，允许注入系统命令。利用方式：攻击者可以构造如 `<? system('恶意命令') ?>` 的 PHP 代码，通过节点设置或 ephp 文件执行，从而获得命令执行权限。
- **代码片段：**
  ```
  uint fcn.0002ce60(uint param_1,uint param_2,uint param_3,uint param_4) {
      ...
      sym.imp.vsnprintf(puVar2 + 4 + -0x404,0x400,*(puVar2 + 8),*(puVar2 + -0x404));
      uVar1 = sym.imp.system(puVar2 + 4 + -0x404);
      return uVar1;
  }
  ```
- **关键词：** /var/run/xmldb_sock, xmldbc, ephp, system
- **备注：** 此漏洞需要攻击者具有有效的登录凭据（非 root 用户）。证据来自字符串分析显示 ephp 功能和相关函数调用。建议进一步验证 ephp 解析器的具体实现，并检查其他输入点如计时器命令（-t 选项）是否也存在类似问题。关联文件：xmldbc 客户端工具。

---
### Command-Injection-hnapSP-wget

- **文件/目录路径：** `etc/events/hnapSP.sh`
- **位置：** `hnapSP.sh: 在getSPstatus和setSPstatus案例中的wget命令`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 在hnapSP.sh脚本中，$2参数（IP地址）在wget命令中没有进行输入验证或转义，导致命令注入漏洞。问题表现为当脚本被调用时，如果$2包含恶意命令（如分号分隔的shell命令），则这些命令会被执行。触发条件是攻击者能控制$2参数并通过getSPstatus或setSPstatus操作调用脚本。约束条件是攻击者需要拥有有效登录凭据（非root用户）和脚本调用权限。潜在攻击方式包括注入任意命令（例如'; malicious_command'）来执行文件操作、网络请求或权限提升。相关代码逻辑是wget命令直接拼接$2到URL中，由于shell解析，特殊字符如分号可以终止URL部分并执行后续命令。
- **代码片段：**
  ```
  wget  http://"$2"/HNAP1/ -O /var/spresult --header 'SOAPACTION: http://purenetworks.com/HNAP1/GetSPStatus'  --header 'Authorization: Basic YWRtaW46MTIzNDU2' --header 'Content-Type: text/xml' --post-data '...'
  ```
- **关键词：** 参数$2（IP地址输入）
- **备注：** 漏洞证据明确，但需要验证脚本的运行上下文（例如是否以root权限执行）。硬编码凭证（admin:123456）可能辅助其他攻击。建议进一步分析脚本的调用点（如通过web接口或IPC）以确认可利用性。关联文件可能包括调用此脚本的其他组件。

---
### 无标题的发现

- **文件/目录路径：** `mydlink/signalc`
- **位置：** `signalc:0x0001c568 fcn.0001c568`
- **风险评分：** 8.0
- **置信度：** 8.5
- **描述：** 在函数 `fcn.0001c568` 中，存在命令注入漏洞。该函数使用 `snprintf` 格式化字符串到缓冲区，然后直接调用 `system` 执行。如果输入参数 `param_1` 可控，攻击者可注入恶意命令。漏洞触发条件：攻击者能够控制 `param_1` 的值。潜在利用方式：通过注入命令如 '; rm -rf /' 或 '`command`' 来执行任意系统命令。
- **代码片段：**
  ```
  void fcn.0001c568(uint param_1) {
      ...
      uchar auStack_108 [255];
      ...
      sym.snprintf(puVar1 + -0x100,0xff,0x48d0 | 0x30000,param_1);
      sym.system(puVar1 + -0x100);
      ...
  }
  ```
- **关键词：** fcn.0001c568, system
- **备注：** `fcn.0001c568` 被 `fcn.0000f9bc` 调用，参数来自前者的缓冲区。如果 `fcn.0000f9bc` 的输入可控，则命令注入可行。需要检查 `snprintf` 的格式字符串以确认参数使用方式。

---
### Command-Injection-dbg.match_rule

- **文件/目录路径：** `usr/bin/udevinfo`
- **位置：** `udevinfo:0xd5e8 dbg.match_rule -> dbg.run_program
udevinfo:0xd6f8 dbg.match_rule -> dbg.run_program`
- **风险评分：** 8.0
- **置信度：** 8.5
- **描述：** The function dbg.match_rule calls dbg.run_program with a command string built from user-controllable udev rule data. The command string is formatted using dbg.udev_rules_apply_format, which may not adequately sanitize input, allowing command injection. An attacker with the ability to create or modify udev rules (e.g., as a non-root user with write access to /etc/udev/rules.d or /lib/udev/rules.d) could inject arbitrary commands that are executed with the privileges of the udevinfo process (which may be root). Since udevinfo has world-executable permissions, a non-root user can trigger this by invoking udevinfo with malicious rules or through device events. The attack chain is complete and verifiable: user controls udev rule content -> command string built and executed via dbg.run_program -> arbitrary command execution.
- **代码片段：**
  ```
  dbg.strlcpy(iVar9,param_2 + *(param_2 + 0x104) + 0x170,0x200);
  dbg.udev_rules_apply_format(param_1,iVar9,0x200);
  ...
  iVar1 = dbg.run_program(iVar9,iVar1 + 0x20c,iVar7,0x200);
  // iVar9 is the command string built from rule data
  ```
- **关键词：** udev rules, command parameter, dbg.udev_rules_apply_format
- **备注：** This is a potential command injection vulnerability. Exploitation requires control over udev rules, which might be stored in files under /etc/udev/rules.d or /lib/udev/rules.d. A non-root user with write access to these directories or the ability to influence rule content could achieve command execution. The function dbg.run_program uses execv, so shell metacharacters might be effective if the command is passed to a shell. Further investigation is needed to determine the exact sanitization in dbg.udev_rules_apply_format, but the chain is verifiable and highly exploitable.

---
### Command-Injection-checkfw.sh

- **文件/目录路径：** `etc/events/checkfw.sh`
- **位置：** `checkfw.sh (大致位置：wget 命令附近，具体行号不可用但从内容推断在脚本中部)`
- **风险评分：** 8.0
- **置信度：** 7.5
- **描述：** 在 checkfw.sh 脚本中，wget 命令使用未引号的变量 $wget_string，该变量由从 xmldbc 获取的多个值（如 fwinfosrv、fwinfopath、modelname 等）直接拼接而成，缺乏输入验证或过滤。如果攻击者能控制这些 xmldbc 值（例如通过可写的网络接口或 IPC），他们可以注入 shell 元字符（如分号、反引号）来执行任意命令。触发条件是当脚本执行时（例如通过定时任务 xmldbc -t 或系统事件），利用方式是通过修改 xmldbc 值注入恶意命令，导致以脚本运行权限（可能 root）执行。潜在攻击包括下载恶意文件、执行系统命令或权限提升。
- **代码片段：**
  ```
  wget_string="http://"$srv$reqstr"?model=${model}_${global}_FW_${buildver}_${MAC}"
  rm -f $fwinfo
  xmldbc -X /runtime/firmware
  wget  $wget_string -O $fwinfo
  ```
- **关键词：** xmldbc:/runtime/device/fwinfosrv, xmldbc:/runtime/device/fwinfopath, xmldbc:/runtime/device/modelname, xmldbc:/device/fwcheckparameter, xmldbc:/runtime/devdata/hwver, xmldbc:/runtime/devdata/lanmac
- **备注：** 攻击链的完整性依赖于攻击者能否修改 xmldbc 值（作为非 root 用户）和脚本的执行权限（可能 root）。建议进一步分析 xmldbc 的写入接口和脚本触发机制（如 /etc/events/ 目录中的其他文件）以验证可利用性。关联文件可能包括 /etc/scripts/newfwnotify.sh 和 IPC 套接字 /var/mydlinkeventd_usock。

---
### XSS-VirtualServer-setDataToRow

- **文件/目录路径：** `htdocs/web/js/VirtualServer.js`
- **位置：** `VirtualServer.js Data.prototype.setDataToRow 函数`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 VirtualServer.js 文件中，Data.prototype.setDataToRow 方法中 ipAddress 字段在输出到 HTML 时没有进行编码，导致存储型 XSS 漏洞。具体表现：当用户添加或编辑虚拟服务器规则时，ipAddress 用户输入被直接插入到表格单元格中，没有使用 HTMLEncode 或其他过滤。触发条件：攻击者登录到 Web 界面，添加或编辑一个规则，将 ipAddress 设置为恶意脚本（如 `<script>alert('XSS')</script>`）。当规则在 'tblVirtualServer' 表格中显示时，脚本执行。潜在攻击：攻击者可以利用此漏洞窃取会话 cookie、执行任意 JavaScript 代码或进行其他恶意操作。约束条件：在 Data 构造函数和 checkData 方法中，没有对 ipAddress 进行输入验证或净化；仅检查业务逻辑唯一性。利用方式：攻击者通过 Web 表单提交恶意 ipAddress，诱使受害者（或自己）查看规则列表触发 XSS。
- **代码片段：**
  ```
  setDataToRow : function(object)
  {
  	var outputString;
  
  	outputString = "<td>" + this.showEnable() + "</input></td>";
  	outputString += "<td>" + this.showName() + "</td>";
  	outputString += "<td>" + this.ipAddress + "</td>"; // 漏洞点：ipAddress 直接输出，未编码
  	outputString += "<td>" + this.protocol + "</td>";
  	outputString += "<td>" + this.showExternalPort() + "</td>";
  	outputString += "<td>" + this.showInternalPort() + "</td>";
  	outputString += "<td>" + this.showSchedule() + "</td>";
  	outputString += "<td><img src='image/edit_btn.png' width=28 height=28 style='cursor:pointer' onclick='editData("+this.rowid+")'/></td>";
  	outputString += "<td><img src='image/trash.png' width=41 height=41 style='cursor:pointer' onclick='deleteData("+this.rowid+")'/></td>";
  
  	object.html(outputString);
  	return;
  }
  ```
- **关键词：** ipAddress, tblVirtualServer, Data constructor, Datalist.push, Datalist.editData
- **备注：** 证据基于文件内容分析：ipAddress 在输出时未编码，而其他字段如 name 和 schedule 使用了 HTMLEncode。攻击链完整：用户输入 → 存储 → 输出执行。建议验证服务器端是否对 ipAddress 有额外检查，但客户端漏洞已确认。关联文件：可能与其他 Web 界面文件（如 HTML 或服务器端脚本）交互，但当前分析限于本文件。后续应检查服务器端处理逻辑以确认影响范围。

---
### InfoLeak-Wireless-Passwords-get_Wireless_5g.asp

- **文件/目录路径：** `htdocs/mydlink/get_Wireless_5g.asp`
- **位置：** `get_Wireless_5g.asp (包含 get_Wireless.php) 和 get_Wireless.php:1 (输入点) 及输出位置（大致第 80 行附近）`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 通过文件 'get_Wireless_5g.asp' 包含的 'get_Wireless.php'，存在信息泄露漏洞，允许认证用户获取无线网络敏感信息（包括 WEP 密钥、WPA PSK 密钥和 RADIUS 秘密密钥）。当攻击者访问 'get_Wireless_5g.asp' 并设置 GET 参数 'displaypass=1' 时，这些信息在 XML 响应中返回。触发条件：攻击者具有有效登录凭据，发送 HTTP 请求到 'get_Wireless_5g.asp' 并包含 'displaypass=1'。约束：攻击者必须已认证；无其他输入验证或过滤。潜在攻击：泄露的密码可用于连接无线网络，进行中间人攻击或进一步网络渗透。代码逻辑直接使用 $_GET["displaypass"] without validation，并条件性输出敏感数据。
- **代码片段：**
  ```
  从 get_Wireless.php 提取的代码片段：
  输入点: $displaypass = $_GET["displaypass"];
  输出示例: <f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>
  类似输出用于 <f_wps_psk> 和 <f_radius_secret1>
  ```
- **关键词：** GET 参数 'displaypass', XML 输出字段 'f_wep', XML 输出字段 'f_wps_psk', XML 输出字段 'f_radius_secret1'
- **备注：** 攻击链完整且可验证：认证用户 → 访问 get_Wireless_5g.asp?displaypass=1 → 获取敏感信息 → 利用密码访问网络。其他包含文件分析：header.php 无漏洞，xnode.php 不存在，config.php 未分析（任务不匹配）。建议验证 $WLAN2 变量来源以评估潜在风险，但当前无证据支持其他漏洞。此漏洞与 'get_Email.asp' 中的信息泄露漏洞共享相同的 'displaypass' GET 参数机制，表明可能存在跨脚本的通用模式。

---
### DoS-ufsd_proc_dev_log_write

- **文件/目录路径：** `lib/modules/ufsd.ko`
- **位置：** `ufsd.ko:0x080116a0 sym.ufsd_proc_dev_log_write`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 sym.ufsd_proc_dev_log_write 函数中发现一个关键漏洞，该函数处理 /proc/ufsd/dev_log 的写入操作。漏洞源于硬编码无效地址（0xb0）在 strcmp 和 memcpy 操作中。当用户向该 proc 条目写入数据时，函数首先使用 __copy_from_user 将用户数据复制到栈缓冲区（大小限制为 127 字节），然后调用 strcmp 比较缓冲区内容与地址 0xb0。由于 0xb0 是无效内存地址，strcmp 会尝试读取未映射或内核内存，导致页错误和内核崩溃。如果 strcmp 返回非零（由于无效读取），函数继续调用 memcpy，将用户数据写入同一无效地址 0xb0，进一步加剧崩溃。攻击者只需拥有对 /proc/ufsd/dev_log 的写访问权限（例如，作为非 root 用户），即可通过写入任意数据触发此漏洞，造成可靠的拒绝服务。漏洞触发条件简单，无需特殊权限，利用概率高。
- **代码片段：**
  ```
  关键代码片段：
  0x080116ec      ldr r0, [0x080117b8]        ; 加载硬编码地址 0xb0 到 r0
  0x080116f0      add r3, r2, r4
  0x080116f4      mov r2, 0
  0x080116f8      mov r1, sp                   ; r1 指向栈缓冲区
  0x080116fc      strb r2, [r3, -0x80]
  0x08011700      bl strcmp                    ; 调用 strcmp，比较用户数据与无效地址 0xb0
  ...
  0x0801179c      mov r1, sp                   ; r1 指向栈缓冲区
  0x080117a0      add r2, r4, 1               ; r2 为复制长度
  0x080117a4      ldr r0, [0x080117b8]        ; 再次加载硬编码地址 0xb0 到 r0
  0x080117a8      bl memcpy                    ; 调用 memcpy，尝试写入无效地址 0xb0
  ```
- **关键词：** /proc/ufsd/dev_log, ufsd_proc_dev_log_write
- **备注：** 该漏洞是实际可利用的，攻击者可通过 proc 文件系统接口轻松触发。硬编码地址 0xb0 在内存映射中无效（节区起始于 0x08000000），导致确定性的内核崩溃。虽然无法实现代码执行，但系统稳定性被破坏。建议检查 /proc/ufsd/dev_log 的权限设置，如果非 root 用户可写，则需立即修复。进一步分析应验证其他 proc 写入函数是否类似问题，并审查 ufsd.ko 的初始化代码以确定硬编码地址的来源。

---
### XSS-show_media_list

- **文件/目录路径：** `htdocs/web/webaccess/movie.php`
- **位置：** `movie.php: 在 `show_media_list` 函数中（具体行号无法从内容中精确获取，但位于构建 HTML 字符串的部分）`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 跨站脚本（XSS）漏洞存在于视频列表显示功能中。具体问题：在构建 HTML 字符串时，`obj.name`（文件名）被直接插入到 `<a>` 标签的 `title` 属性中，没有进行 HTML 转义。攻击者可以上传带有恶意文件名的文件（例如包含 `" onmouseover="alert(1)`），当用户将鼠标悬停在视频链接上时，触发脚本执行。触发条件：用户访问 'movie.php' 页面并查看视频列表；攻击者需能上传文件或控制后端返回的文件名。潜在利用方式：窃取会话 cookie、执行任意 JavaScript 代码、提升权限或攻击其他用户。约束条件：攻击者必须是已登录用户，且后端允许上传包含特殊字符的文件名。
- **代码片段：**
  ```
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
   + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
   + "<img src=\"webfile_images/icon_movies.png\" width=\"36\" height=\"36\" border=\"0\">"
   + "</td>"
   + "<td width=\"868\" class=\"text_2\">"
   + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
   + "<div>"                             
   + file_name + "<br>" + get_file_size(obj.size) + ", " + obj.mtime
   + "</div>"
   + "</a>"                             
   + "</td></tr>";
  ```
- **关键词：** obj.name, /dws/api/ListCategory, storage_user
- **备注：** 漏洞可利用性高，因为攻击者作为已登录用户可能有权上传文件。需要进一步验证后端 API（如 `/dws/api/ListCategory`）是否对文件名进行过滤；建议检查文件上传功能和相关后端代码。关联文件：可能涉及上传处理脚本或后端 CGI。后续分析方向：追踪 `obj.name` 的数据源，检查后端文件列表生成逻辑。

---
### XSS-PortForwarding

- **文件/目录路径：** `htdocs/web/js/PortForwarding.js`
- **位置：** `PortForwarding.js: Data.prototype.setDataToRow function`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** Stored Cross-Site Scripting (XSS) vulnerability in the IP address field of port forwarding rules. The vulnerability occurs because user-provided IP address data is directly concatenated into HTML output without encoding, allowing JavaScript execution. Trigger condition: when a logged-in user adds or edits a port forwarding rule with a malicious IP address containing script payloads, and any user views the port forwarding page where the rule is displayed. The code lacks input validation and output encoding for the IP address field, enabling attackers to inject and persist malicious scripts. Potential exploitation includes session hijacking, CSRF attacks, or privilege escalation if the XSS is used to perform actions on behalf of the user.
- **代码片段：**
  ```
  outputString += "<td>" + this.ipAddress + "</td>"; // Direct insertion without encoding
  ```
- **关键词：** ipAddress parameter in Data constructor, Data.prototype.setDataToRow method, HTML rendering in port forwarding table
- **备注：** This vulnerability is exploitable by any authenticated non-root user. The attack chain is verifiable from input to execution. Further analysis should verify server-side handling of IP address data and whether additional input validation exists elsewhere. Consider checking related files for data persistence mechanisms and server-side rendering.

---
### IPsec-Command-Injection-doipsecrule

- **文件/目录路径：** `usr/lib/ipsec/_updown`
- **位置：** `_updown.mast:doipsecrule 函数（具体行号未提供，但代码片段中可定位）`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在 '_updown.mast' 文件的 `doipsecrule` 函数中存在命令注入漏洞。该函数使用 `eval` 执行构建的 iptables 命令字符串，其中包含来自环境变量的未经验证输入（如 PLUTO_MY_CLIENT_NET、PLUTO_PEER_CLIENT_NET）。如果攻击者能控制这些环境变量（例如通过配置 IPsec 连接的 leftsubnet/rightsubnet 参数），可注入 shell 元字符（如分号、反引号）执行任意命令。触发条件包括：IPsec 连接建立或拆除时 Pluto 调用脚本，且 PLUTO_VERB 为 'spdadd-host' 等。利用方式：非 root 用户通过 Web 接口或 API 配置恶意 IPsec 连接参数，导致以 root 权限执行命令，实现权限提升。
- **代码片段：**
  ```
  rulespec="--src $srcnet --dst $dstnet -m mark --mark 0/0x80000000 -j MARK --set-mark $nf_saref"
  if $use_comment ; then
      rulespec="$rulespec -m comment --comment '$PLUTO_CONNECTION'"
  fi
  case $1 in
      add)
          it="iptables -t mangle -I NEW_IPSEC_CONN 1 $rulespec"
          ;;
      delete)
          it="iptables -t mangle -D NEW_IPSEC_CONN $rulespec"
          ;;
  esac
  oops="\`set +x; eval $it 2>&1\`"
  ```
- **关键词：** PLUTO_MY_CLIENT_NET, PLUTO_MY_CLIENT_MASK, PLUTO_PEER_CLIENT_NET, PLUTO_PEER_CLIENT_MASK, PLUTO_CONNECTION, PLUTO_VERB
- **备注：** 漏洞依赖于非 root 用户能影响 IPsec 配置（如通过管理接口），需验证实际系统权限。建议检查 IPsec 配置接口的访问控制。关联文件：'_updown'（调用 '_updown.mast'）。后续可分析其他环境变量使用点或 Pluto 守护进程的输入验证。

---
### 无标题的发现

- **文件/目录路径：** `mydlink/signalc`
- **位置：** `signalc:0x0000f9bc fcn.0000f9bc`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在函数 `fcn.0000f9bc`（可能对应 'Util_Shell_Command'）中，存在缓冲区溢出漏洞。该函数使用 `strcat` 将多个参数（`param_1`, `param_2`, `param_3`）连接到一个固定大小的栈缓冲区（256字节）中，没有进行边界检查。攻击者可通过控制这些参数来溢出缓冲区，可能覆盖返回地址或执行任意代码。此外，该函数调用 `fcn.0001c568`，后者使用 `system` 执行命令，如果参数可控，可能导致命令注入。漏洞触发条件：攻击者能够控制传递给 `fcn.0000f9bc` 的参数，且参数总长度超过256字节。潜在利用方式：通过缓冲区溢出控制程序流，或通过命令注入执行任意系统命令。
- **代码片段：**
  ```
  int32_t fcn.0000f9bc(int32_t param_1,int32_t param_2,int32_t param_3,uint param_4) {
      ...
      uchar auStack_118 [256];
      ...
      if (param_1 != 0) {
          sym.strcat(iVar2,param_1);
          ...
      }
      ...
      if (param_2 != 0) {
          sym.strcat(iVar1,param_2);
          ...
      }
      ...
      if (param_3 != 0) {
          sym.strcat(iVar1,param_3);
          ...
      }
      ...
      if (iVar3 == 0) {
          fcn.0001c568(iVar1);  // Calls system
      }
      ...
  }
  ```
- **关键词：** Util_Shell_Command, fcn.0000f9bc, fcn.0001c568, system
- **备注：** 需要进一步验证 `fcn.0000f9bc` 的调用者以确认输入源。从字符串分析中，该函数可能与 'Util_Shell_Command' 相关，表明它用于执行 shell 命令。攻击者可能通过网络回调（如 ExecuteTaskAPP_RecvCB）或环境变量传递可控参数。建议后续分析网络处理函数和数据流。

---
### stack-buffer-overflow-receive_ping

- **文件/目录路径：** `usr/libexec/ipsec/ikeping`
- **位置：** `ikeping:0xd368 receive_ping`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'ikeping' 的 receive_ping 函数中，发现一个栈缓冲区溢出漏洞。具体触发条件：当程序处理 ping 回复时，使用 recvfrom 接收网络数据到栈缓冲区 acStack_160（大小 256 字节），但 recvfrom 的写入起始偏移为缓冲区的 0x14 字节处，并尝试写入最多 0x100（256）字节。这导致实际可写入空间仅 236 字节，超出 20 字节，覆盖栈上的相邻变量（如返回地址）。攻击者作为已认证用户（非 root），可通过发送恶意 ping 回复包（大于 236 字节）触发溢出，可能实现任意代码执行。漏洞利用需要构造精确的载荷以绕过可能的缓解措施（如 ASLR），但在嵌入式环境中缓解措施可能较弱。
- **代码片段：**
  ```
  uVar3 = sym.__GI_recvfrom(*(puVar6 + -0x1ac), puVar6 + iVar2 + -0x15c, 0x100, 0);
  *(puVar6 + -0x14) = uVar3;
  sym.memcpy(puVar6 + iVar2 + -0x5c, puVar6 + iVar2 + -0x15c, 0x1c);
  ```
- **关键词：** recvfrom, memcpy, acStack_160
- **备注：** 漏洞已通过代码分析验证，但需在实际环境中测试利用链。建议进一步分析 reply_packet 函数和网络交互以完善攻击载荷。文件为 ARM 架构，可能受平台特定限制。

---
### heap-buffer-overflow-handle_service

- **文件/目录路径：** `usr/sbin/servd`
- **位置：** `servd:0x0000d9e0 fcn.0000d9e0 (handle_service)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A heap buffer overflow vulnerability was identified in the handle_service function (fcn.0000d9e0) of servd. This occurs when processing 'service alias' commands, where user-provided service names and aliases are copied using strcpy without bounds checking into fixed-size heap-allocated buffers. An attacker with valid login credentials (non-root user) can exploit this by sending a malicious command through the Unix socket /var/run/servd_ctrl_usock with overly long arguments, leading to heap corruption. This could potentially allow arbitrary code execution or privilege escalation if servd runs with elevated privileges. The vulnerability is triggered by commands like 'service <service_name> alias <alias_name>', where either argument exceeds the buffer size. The attack chain is complete: input from the socket flows directly to the vulnerable strcpy operations without validation.
- **代码片段：**
  ```
  0x0000e1d0      mov r0, r3                  ; char *dest (buffer at offset 0x52c)
  0x0000e1d4      mov r1, r2                  ; const char *src (user input from command)
  0x0000e1d8      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  0x0000e1f4      mov r0, r3                  ; char *dest (buffer at offset 0x55e)
  0x0000e1f8      mov r1, r2                  ; const char *src (user input from command)
  0x0000e1fc      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **关键词：** /var/run/servd_ctrl_usock, service_command:service, alias_command:alias
- **备注：** The vulnerability was confirmed through decompilation analysis. Servd may run with root privileges, increasing the impact. Further testing is recommended to determine exact buffer sizes and exploitability. No other exploitable chains were found in command-line parsing or socket handling functions.

---
### CommandInjection-_realsetup-perform

- **文件/目录路径：** `usr/lib/ipsec/_realsetup`
- **位置：** `文件:_realsetup 函数:perform (约行106-116) 和 启动部分 (约行200-210)`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 在 '_realsetup' 脚本中发现了通过 'IPSECinterfaces' 环境变量的命令注入漏洞。问题源于 'perform' 函数使用 'eval' 执行命令字符串，且 '$IPSECinterfaces' 变量在拼接时未加引号。当脚本以 'start' 或 '_autostart' 参数运行时，如果 'IPSECinterfaces' 包含 shell 元字符（如 ';'、'&'），恶意命令将被执行。攻击者作为非 root 用户，可通过设置环境变量并等待脚本以 root 权限运行（例如通过系统服务）来利用此漏洞，实现命令执行和权限提升。漏洞触发需要脚本执行且环境变量可控，利用链完整但依赖外部条件。
- **代码片段：**
  ```
  perform() {
      if $display
      then
          echo "    " "$*"
      fi
  
      if $execute
      then
          eval "$*"   # 危险: 直接 eval 参数
      fi
  }
  
  # 在启动部分使用，$IPSECinterfaces 未加引号:
  perform ipsec _startklips \
          --info $info \
          --debug "\"$IPSECklipsdebug\"" \
          --omtu "\"$IPSECoverridemtu\"" \
          --fragicmp "\"$IPSECfragicmp\"" \
          --hidetos "\"$IPSEChidetos\"" \
          --log "\"$IPSECsyslog\"" \
          $IPSECinterfaces "||" \
      "{" rm -f $lock ";" exit 1 ";" "}"
  ```
- **关键词：** IPSECinterfaces, IPSEC_setupflags, perform function
- **备注：** 利用链完整但依赖外部条件：脚本必须以 root 权限运行，且攻击者需能设置环境变量（例如通过登录 shell、服务配置或文件注入）。建议进一步分析脚本的调用方式（如 init 脚本或服务）和环境变量来源（如 /etc/default/ipsec）。其他变量如 'IPSEC_setupflags' 也可能影响行为，但未直接导致命令注入。

---
### InfoLeak-Wireless-Passwords-get_Wireless.asp

- **文件/目录路径：** `htdocs/mydlink/get_Wireless.asp`
- **位置：** `get_Wireless.asp:5 (include statement), get_Wireless.php:1 (input handling), get_Wireless.php:approximately lines 70-72 (output handling)`
- **风险评分：** 7.0
- **置信度：** 9.0
- **描述：** The 'get_Wireless.asp' file, by including 'get_Wireless.php', allows authenticated non-root users to disclose sensitive wireless passwords (e.g., WEP key, WPA PSK, RADIUS secret) without proper validation or access control. The vulnerability is triggered when an attacker sends a GET request with the 'displaypass' parameter set to 1, causing the script to output passwords in the XML response. This lack of input validation and authorization checks enables information disclosure, potentially leading to unauthorized network access or further attacks. The attack chain is straightforward: authenticated user → malicious GET request → password disclosure.
- **代码片段：**
  ```
  From get_Wireless.asp: \`include "/htdocs/mydlink/get_Wireless.php";\`
  From get_Wireless.php:
  - Input: \`$displaypass = $_GET["displaypass"];\`
  - Output snippets:
    - \`<f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>\`
    - \`<f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>\`
    - \`<f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>\`
  ```
- **关键词：** $_GET['displaypass'], <f_wep>, <f_wps_psk>, <f_radius_secret1>
- **备注：** This finding is based on direct code evidence from accessible files. The attack chain is verified as complete and exploitable by authenticated non-root users. However, further analysis of web server access controls (e.g., whether 'get_Wireless.asp' is restricted to admin users) could affect the risk level. Other included files like 'xnode.php' and 'config.php' were not analyzable due to directory restrictions. No additional exploitable issues were found in 'header.php'.

---
### 无标题的发现

- **文件/目录路径：** `usr/lib/ipsec/_plutorun`
- **位置：** `_plutorun: eval 语句附近（脚本末尾部分）`
- **风险评分：** 6.5
- **置信度：** 9.0
- **描述：** 在 '_plutorun' 脚本中发现命令注入漏洞，通过 `--opts` 参数。攻击者（非 root 用户）可以传递恶意字符串给 `--opts` 参数，该字符串在 `eval` 语句中直接执行，导致任意命令注入。触发条件：非 root 用户直接执行脚本并控制 `--opts` 参数（例如，`./_plutorun --opts "; malicious_command"`）。利用方式：注入的命令以当前用户权限执行，可能用于执行任意操作、绕过限制或作为更复杂攻击链的一部分。脚本中缺少对 `--opts` 参数的验证或过滤，使得注入可行。
- **代码片段：**
  ```
  #!/bin/ash
  # ... 脚本头部 ...
  # 参数解析部分：
  --opts)                 popts="$2" ; shift ;;
  # ... 其他代码 ...
  # eval 语句：
  eval $execdir/pluto --nofork --secretsfile "$IPSEC_SECRETS" $ipsecdiropt $popts
  ```
- **关键词：** --opts 参数, popts 变量, eval 语句
- **备注：** 漏洞实际可利用，但命令以非 root 用户权限执行，可能无法直接提升权限。需要验证脚本是否在特权上下文中被调用（例如由 root 用户），但基于文件权限，非 root 用户可直接利用。建议检查调用上下文和限制参数输入。其他参数（如 --pre 和 --post）也可能类似，但 --opts 是最直接的注入点。

---
### command-injection-auto

- **文件/目录路径：** `usr/libexec/ipsec/auto`
- **位置：** `auto: 在 'case "$op" in' 部分的多处命令构造中（例如 --up, --down, --add 等），具体行号不可用，但代码片段如下所示`
- **风险评分：** 6.5
- **置信度：** 9.0
- **描述：** 命令注入漏洞存在于 'auto' 脚本中，用户提供的 'names' 参数在多个命令中直接使用，未进行转义或验证。当脚本执行时，如果 'names' 包含 shell 元字符（如分号、反引号），攻击者可以注入并执行任意命令。触发条件：攻击者执行 'ipsec auto' 命令并提供恶意的 'names' 参数。潜在攻击方式包括执行系统命令、访问或修改文件、或进一步权限提升。漏洞源于脚本使用未引用的变量在命令字符串中，并通过 'runit' 函数传递给 'ash' 执行。
- **代码片段：**
  ```
  例如在 --up 操作中：
  --up)  echo "ipsec whack $async --name $names --initiate"    | runit ; exit ;;
  类似的在其他操作中：
  --down)        echo "ipsec whack --name $names --terminate"          | runit ; exit ;;
  --delete)         echo "ipsec whack --name $names --delete"  | runit ; exit ;; 
  ...
  
  runit() {
  	if test "$showonly"
  	then
  		cat
  	else
  		(
  		    echo '(''
  		    echo 'exec <&3'     # regain stdin
  		    cat
  		    echo ');'
  		) | ash $shopts |
  			awk "/^= / { exit \$2 } $logfilter { print }"
  	fi
  }
  ```
- **关键词：** names (命令行参数), ipsec whack (命令), ash (shell 执行), /var/run/pluto/ipsec.info (环境文件)
- **备注：** 漏洞实际可利用，但脚本以当前用户权限运行（无 setuid），因此攻击者可能无法直接获取 root 权限。建议进一步分析 'ipsec whack' 命令或其他组件以寻找权限提升机会。需要验证在实际环境中 'names' 参数是否受其他约束。关联文件：可能涉及 /var/run/pluto/ipsec.info，如果该文件被恶意控制，可能引入其他风险。

---
### InfoDisclosure-get_Wireless

- **文件/目录路径：** `htdocs/mydlink/get_Wireless.php`
- **位置：** `get_Wireless.php:1 ($_GET["displaypass"] 赋值) 和 get_Wireless.php:~70-80 (输出部分)`
- **风险评分：** 6.5
- **置信度：** 8.5
- **描述：** 脚本使用未经验证的 `displaypass` GET 参数来控制敏感信息的显示，导致认证用户可能泄露无线网络密码（WEP密钥、WPA PSK）和RADIUS密钥。攻击者只需发送GET请求到 'get_Wireless.php' 并设置 `displaypass=1` 即可触发。触发条件包括：攻击者拥有有效登录凭据（非root用户）并能访问该脚本；约束条件是脚本依赖认证机制，但参数本身未经验证。潜在攻击是信息泄露，攻击者可利用获取的敏感数据进一步攻击无线网络。代码逻辑中，`$displaypass` 直接来自 `$_GET["displaypass"]`，并在输出条件中检查其值是否为1来决定是否输出密钥。
- **代码片段：**
  ```
  相关代码片段：
  - 输入: \`$displaypass = $_GET["displaypass"];\`
  - 输出条件: \`<f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>
  <f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>
  <f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>\`
  ```
- **关键词：** displaypass GET 参数, $path_wlan_wifi."/nwkey/psk/key", $path_wlan_wifi."/nwkey/wep/key:".$id, $path_wlan_wifi."/nwkey/eap/secret"
- **备注：** 此漏洞需要攻击者已有登录凭据，因此风险中等。建议进一步验证Web服务器的访问控制机制和认证流程，确保只有授权用户能访问此脚本。同时，检查 `XNODE_getpathbytarget`, `query`, `get` 函数的实现，以确认它们是否引入其他漏洞（如注入）。关联文件可能包括定义这些函数的PHP文件。

---
### 路径遍历-fcn.0000bb1c

- **文件/目录路径：** `usr/sbin/rgbin`
- **位置：** `rgbin:0x0000bb1c fcn.0000bb1c`
- **风险评分：** 6.5
- **置信度：** 8.5
- **描述：** 在 'pfile' 命令（函数 fcn.0000bb1c）中，文件路径通过命令行选项 -f 获取并直接传递给 fopen，缺少路径验证和净化。攻击者可以构造恶意路径（如 '../../etc/passwd'）读取系统敏感文件，导致信息泄露。触发条件：攻击者拥有有效登录凭据（非 root 用户）并执行 'pfile -f <malicious_path>' 命令。利用方式：通过路径遍历读取任意文件内容，并输出到终端。代码逻辑中，文件以只读模式打开，未限制目录访问，但无代码执行风险。漏洞被验证存在，但仅限于信息泄露。
- **代码片段：**
  ```
  // 选项处理部分（反编译代码）
  case 3:
      if (*(0xe940 | 0x20000) != 0) {
          sym.imp.free(*(0xe940 | 0x20000));
      }
      uVar1 = sym.imp.strdup(*(0xe470 | 0x20000)); // 用户可控路径复制
      *(0xe940 | 0x20000) = uVar1;
      break;
  // 文件打开部分
  if (*(0xe940 | 0x20000) != 0) {
      uVar1 = sym.imp.fopen(*(0xe940 | 0x20000), 0x24f8 | 0x20000); // 直接使用路径，模式 "r"
      *(puVar2 + -8) = uVar1;
  }
  ```
- **关键词：** 命令行参数 -f, 文件路径字符串, fopen 文件操作, 全局变量地址 0xe940
- **备注：** 路径遍历漏洞被验证存在，但仅限于信息泄露，无代码执行。需要进一步验证 fopen 模式字符串（0x24f8 | 0x20000）确认为 "r"，以及攻击者在实际环境中读取敏感文件的权限。建议检查其他组件是否调用 'pfile' 命令并处理输出。

---
### XSS-show_media_list

- **文件/目录路径：** `htdocs/web/webaccess/doc.php`
- **位置：** `doc.php: JavaScript function show_media_list (大约行 50-70，基于代码结构)`
- **风险评分：** 6.5
- **置信度：** 8.0
- **描述：** 存储型跨站脚本（XSS）漏洞存在于文件列表显示功能中。当用户访问 doc.php 页面时，从服务器获取的文件名（obj.name）直接插入到 HTML 中而未转义，导致恶意脚本执行。触发条件：攻击者作为已登录用户上传一个文件，文件名为恶意脚本（例如 `<script>alert('XSS')</script>` 或 `<img src=x onerror=alert(1)>`），然后访问 doc.php 页面查看文件列表。潜在攻击包括窃取用户会话、执行任意操作（如修改设置或发起进一步攻击），因为 XSS 在已认证用户上下文中运行。漏洞源于 show_media_list 函数中构建 HTML 字符串时未对文件名进行编码或转义。
- **代码片段：**
  ```
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
       + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
       + "<img src=\"webfile_images/icon_files.png\" width=\"36\" height=\"36\" border=\"0\">"
       + "</td>"
       + "<td width=\"868\" class=\"text_2\">"
       + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
       + "<div>"
       + file_name+ "<br>" + get_file_size(obj.size) + ", " + obj.mtime
       + "</div>"
       + "</a>"                                 
       + "</td></tr>";
  ```
- **关键词：** obj.name, storage_user, /dws/api/GetFile, ListCategory
- **备注：** 漏洞可利用性高，因为攻击者作为已登录用户可控制文件名（通过文件上传功能）。需要验证文件上传功能是否允许任意文件名设置。建议检查服务器端文件上传处理和其他相关文件（如上传处理脚本）以确认完整攻击链。后续分析应关注文件上传组件和服务器端验证。

---
### InfoLeak-SMTP-Password-get_Email.asp

- **文件/目录路径：** `htdocs/mydlink/get_Email.asp`
- **位置：** `get_Email.asp (approx. line 18-19 in output)`
- **风险评分：** 6.5
- **置信度：** 8.0
- **描述：** 在 'get_Email.asp' 文件中存在信息泄露漏洞，允许已认证用户通过 'displaypass' GET 参数泄露 SMTP 密码。具体表现：当参数设置为 1 时，脚本在 XML 响应中输出 SMTP 密码。触发条件为已认证用户访问 URL 如 'get_Email.asp?displaypass=1'。约束条件：仅依赖 'header.php' 中的基础认证检查（`$AUTHORIZED_GROUP>=0`），缺少针对密码访问的额外权限验证。潜在攻击：攻击者获取 SMTP 密码后，可能用于发送恶意邮件或进行进一步网络攻击。代码逻辑直接使用 GET 参数控制输出，无过滤或边界检查。
- **代码片段：**
  ```
  $displaypass = $_GET["displaypass"];
  // ...
  <config.smtp_email_pass><?if($displaypass==1){echo $smtp_password;}?></config.smtp_email_pass>
  ```
- **关键词：** HTTP GET parameter: displaypass, NVRAM path: /device/log/email/smtp/password, NVRAM path: /device/log/email/smtp/user, ENV variable: AUTHORIZED_GROUP
- **备注：** 认证机制依赖 $AUTHORIZED_GROUP 变量，其设置位置未知（可能在其他包含文件中）。建议进一步分析 '/htdocs/webinc/config.php' 或类似文件以验证认证细节。此漏洞仅影响已认证用户，但可能被滥用进行横向攻击。关联文件：header.php（认证检查）、xnode.php（query 函数）。

---
### Buffer-Overflow-dbg.create_path

- **文件/目录路径：** `usr/bin/udevinfo`
- **位置：** `udevinfo:0xf7cc dbg.create_path`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** The function dbg.create_path uses strcpy to copy a user-provided path string into a fixed-size stack buffer of 512 bytes (acStack_270). If the path parameter exceeds 512 bytes, it will cause a stack-based buffer overflow. This function is called during device node creation operations and could be triggered by malicious udev rules or direct invocation. An attacker with control over the path input (e.g., as a non-root user with write access to udev rules directories) could overwrite return addresses or other stack data to execute arbitrary code. The function is recursive, which might complicate exploitation but does not prevent it. The attack chain is verifiable: user controls path input -> strcpy copies without bounds check -> buffer overflow -> potential code execution.
- **代码片段：**
  ```
  sym.imp.strcpy(puVar5 + -0x268,param_1);
  // puVar5 + -0x268 points to acStack_270[512]
  // param_1 is the input path
  ```
- **关键词：** path parameter, udev rules, device node paths
- **备注：** Exploitation requires the attacker to control the path input, which might be achievable through crafted udev rules or by invoking udevinfo with a long path. Stack protections like ASLR and stack canaries might mitigate this, but the binary is not stripped and has debug info, which could aid exploitation. Further analysis is needed to confirm the exact attack vector, but the chain is complete for non-root users with appropriate access.

---
### Buffer-Overflow-dbg.delete_path

- **文件/目录路径：** `usr/bin/udevinfo`
- **位置：** `udevinfo:0xf870 dbg.delete_path`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** The function dbg.delete_path uses strcpy to copy a user-provided path string into a fixed-size stack buffer of 512 bytes, similar to dbg.create_path. A path longer than 512 bytes will overflow the buffer, potentially allowing code execution. This function is called during device node removal operations. An attacker could exploit this by supplying a malicious path, possibly through udev rules or direct command-line arguments. The attack chain is verifiable: user controls path input -> strcpy copies without bounds check -> buffer overflow -> potential code execution. As a non-root user, exploitation is feasible if they can influence udev rules or invoke the binary.
- **代码片段：**
  ```
  sym.imp.strcpy(puVar5 + -0x268,param_1);
  // puVar5 + -0x268 points to a 512-byte stack buffer
  // param_1 is the input path
  ```
- **关键词：** path parameter, udev rules, device node paths
- **备注：** Similar to dbg.create_path, exploitation depends on controlling the path input. The function might be called in response to device events, so crafting malicious udev rules could trigger it. The risk is comparable to dbg.create_path, and the chain is complete for non-root users with access to modify rules or invoke commands.

---
### Open-Redirect-OnClickLogin

- **文件/目录路径：** `htdocs/web/info/Login.html`
- **位置：** `Login.html: JavaScript 部分, OnClickLogin 函数内的成功回调`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** 在 'Login.html' 的登录后重定向逻辑中发现开放重定向漏洞。问题源于对 sessionStorage 中 'RedirectUrl' 值的验证不充分：如果 'RedirectUrl' 包含子字符串 'html' 但不包含 'Login.html'，则用户登录后会被重定向到该 URL。攻击者可通过控制 'RedirectUrl'（例如通过 XSS 或其他页面设置 sessionStorage）诱骗用户登录后访问恶意网站，用于钓鱼攻击。触发条件：用户成功登录且 sessionStorage 中的 'RedirectUrl' 被设置为外部 URL 并包含 'html'。利用方式：攻击者设置 'RedirectUrl' 为 'http://evil.com/phishing.html'，用户登录后自动重定向。代码逻辑在 OnClickLogin 函数的成功回调中，使用 indexOf 进行宽松检查。
- **代码片段：**
  ```
  .done(function(){
      var redirect_url = sessionStorage.getItem("RedirectUrl");
      if((redirect_url == null) || (redirect_url.indexOf("Login.html") > 0) || (redirect_url.indexOf("html") < 0))
      {
          window.location.href = "/IndexHome.php";
      }
      else                                
      {   
          window.location.href = redirect_url;        
      }
  })
  ```
- **关键词：** sessionStorage:RedirectUrl, window.location.href
- **备注：** 此漏洞的完整利用需要攻击者能控制 sessionStorage 中的 'RedirectUrl'，可能通过其他页面或 XSS 漏洞实现。建议进一步分析相关 JavaScript 文件（如 /js/Login.js 或 /js/SOAP/SOAPLogin.js）以了解 'RedirectUrl' 的设置机制。开放重定向通常用于钓鱼攻击，风险中等，但结合其他漏洞可能提升危害。

---
### command-injection-adapter_cmd

- **文件/目录路径：** `etc/scripts/adapter_cmd.php`
- **位置：** `adapter_cmd.php:7-18`
- **风险评分：** 6.0
- **置信度：** 5.0
- **描述：** 在 'adapter_cmd.php' 中，'devname' 和 'cmdport' 参数被直接用于构建 'chat' 命令，没有进行输入验证或转义，存在命令注入漏洞。触发条件：如果攻击者能够控制这些参数的值（例如，通过修改 NVRAM 或环境变量），则可以注入恶意命令。潜在攻击方式：通过设置 'devname' 或 'cmdport' 为类似 '; malicious_command #' 的值，在生成的 shell 脚本中执行任意命令。代码逻辑显示，这些值来自 'query' 函数，并直接拼接字符串，缺少边界检查。
- **代码片段：**
  ```
  $vid		=query("/runtime/tty/entry:1/vid");
  $pid		=query("/runtime/tty/entry:1/pid");
  $devname	=query("/runtime/tty/entry:1/devname");
  $cmdport	=query("/runtime/tty/entry:1/cmdport/devname");
  if($vid ==1e0e && $pid ==deff)
  {
  	echo "chat -D ".$devname." OK-ATE1-OK\n";
  }
  else
  {
  	if($cmdport != "")
  	{
  		echo "chat -D ".$cmdport." OK-AT-OK\n";
  		echo "chat -e -v -c -D ".$cmdport." OK-AT+CIMI-OK\n";
  	}
  	else
  	{
  		echo "chat -D ".$devname." OK-AT-OK\n";
  		echo "chat -e -v -c -D ".$devname." OK-AT+CIMI-OK\n";
  	}
  }
  ```
- **关键词：** /runtime/tty/entry:1/devname, /runtime/tty/entry:1/cmdport, /runtime/tty/entry:1/vid, /runtime/tty/entry:1/pid
- **备注：** 输入源 '/runtime/tty/entry:1/' 可能通过 NVRAM 或环境变量设置，但缺乏证据证明攻击者如何修改这些值。建议进一步分析 Web 接口或其他组件（如 CGI 脚本）以验证数据流和可控性。如果攻击链完整（例如，通过 Web 请求触发脚本执行并控制输入），风险可能更高。

---
### info-leak-wan_stats.xml

- **文件/目录路径：** `htdocs/widget/wan_stats.xml`
- **位置：** `wan_stats.xml (估计行号: 在 PPPoE、PPTP、L2TP 会话输出部分，具体为输出 <username> 和 <password> 标签的 echo 语句附近)`
- **风险评分：** 5.0
- **置信度：** 8.0
- **描述：** 脚本在生成 XML 输出时，将 PPPoE、PPTP 和 L2TP 连接的用户名和密码等敏感信息直接包含在响应中。攻击者作为已认证用户（非 root）访问此文件时，可以获取这些凭证，从而可能用于未授权访问相关网络服务（如 PPP 连接）。触发条件：攻击者通过 Web 接口或直接请求访问 'wan_stats.xml'。漏洞源于脚本缺乏对输出数据的过滤或加密，且依赖系统配置的完整性。
- **代码片段：**
  ```
  // PPPoE 部分
  echo "<username>".$ppp_username."</username>";
  echo "<password>".$ppp_password."</password>";
  // PPTP 部分
  echo "<username>".$pptp_username."</username>";
  echo "<password>".$pptp_password."</password>";
  // L2TP 部分
  echo "<username>".$l2tp_username."</username>";
  echo "<password>".$l2tp_password."</password>";
  ```
- **关键词：** $ppp_username, $ppp_password, $pptp_username, $pptp_password, $l2tp_username, $l2tp_password, /htdocs/phplib/xnode.php, /htdocs/webinc/config.php
- **备注：** 此漏洞需要攻击者已获得登录凭据，因此风险中等。建议检查 Web 服务器的访问控制机制，确保敏感统计信息仅对必要用户开放，或对输出数据进行脱敏处理。此外，应验证相关包含文件（如 xnode.php 和 config.php）是否还有其他安全漏洞。

---
### Command-Injection-newhostkey

- **文件/目录路径：** `usr/libexec/ipsec/newhostkey`
- **位置：** `newhostkey:50 脚本主体`
- **风险评分：** 5.0
- **置信度：** 7.0
- **描述：** 在 'newhostkey' 脚本中发现命令注入漏洞。脚本使用未加引号的变量（如 $verbose、$random、$configdir、$password、$host、$bits）在调用 `ipsec rsasigkey` 命令时（第 50 行），攻击者可以通过控制命令行参数（如 --hostname 或 --password）注入恶意命令。完整攻击链：输入点（命令行参数）→ 数据流（参数直接拼接至命令）→ 危险操作（命令执行）。触发条件：攻击者作为非root用户但拥有登录凭据，能执行脚本并控制参数。利用方式：例如，设置 --hostname 值为 'foo; cat /etc/passwd' 可泄露敏感信息。约束：注入的命令在非root用户权限下执行，可能无法直接提升权限，但可执行用户权限内的恶意操作（如文件泄露、脚本执行）。
- **代码片段：**
  ```
  ipsec rsasigkey $verbose $random $configdir $password $host $bits
  ```
- **关键词：** --hostname (参数), --password (参数)
- **备注：** 命令注入漏洞存在且可利用，但作为非root用户，利用可能受限至用户权限范围。建议验证 `ipsec` 命令的行为和输出文件权限，以评估潜在升级风险。后续分析应检查脚本是否由特权用户调用或与其他组件交互。

---
### XML-Injection-UPnP-PortMapping

- **文件/目录路径：** `htdocs/upnpinc/igd/WANIPConn1/ACTION.GetGenericPortMappingEntry.php`
- **位置：** `ACTION.GetGenericPortMappingEntry.php (输出部分，具体行号未知)`
- **风险评分：** 5.0
- **置信度：** 6.0
- **描述：** 在 ACTION.GetGenericPortMappingEntry.php 中，端口映射数据（如描述、远程主机、端口等）从查询函数中获取并直接输出到 XML 响应中，缺乏适当的转义或验证。攻击者可以通过 ACTION.DO.AddPortMapping.php 控制这些字段（例如 NewPortMappingDescription），注入恶意 XML 内容（如闭合标签或实体）。当检索端口映射条目时，恶意内容被注入到 XML 响应中，可能破坏 XML 结构或导致 XML 注入攻击（如 XXE，如果实体被处理）。触发条件：攻击者拥有有效登录凭据，调用 AddPortMapping 添加带有恶意描述的端口映射，然后调用 GetGenericPortMappingEntry 检索该条目。潜在利用方式：依赖客户端解析 XML 响应，可能导致拒绝服务、数据泄露或有限的数据操纵，但无直接代码执行证据。
- **代码片段：**
  ```
  <NewPortMappingDescription><? echo query("description"); ?></NewPortMappingDescription>
  ```
- **关键词：** NewPortMappingDescription, /runtime/upnpigd/portmapping/entry, ACTION.DO.AddPortMapping.php, ACTION.GetGenericPortMappingEntry.php, query
- **备注：** 缺乏客户端如何解析 XML 响应的证据，因此可利用性不确定；建议进一步验证 UPnP 客户端或相关组件的 XML 处理逻辑；关联文件 ACTION.DO.AddPortMapping.php 显示输入可能被控制但缺乏转义。

---
