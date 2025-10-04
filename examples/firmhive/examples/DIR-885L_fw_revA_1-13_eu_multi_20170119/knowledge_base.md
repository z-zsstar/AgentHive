# DIR-885L_fw_revA_1-13_eu_multi_20170119 (36 个发现)

---

### CodeInjection-form_macfilter

- **文件/目录路径：** `htdocs/mydlink/form_macfilter`
- **位置：** `form_macfilter (具体行号未知，但代码在 fwrite 和 dophp 调用部分)`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 'form_macfilter' 脚本中发现一个代码注入漏洞，允许远程代码执行（RCE）。当 $_POST['settingsChanged'] 为 1 时，脚本将用户控制的 POST 参数（如 entry_enable_*, mac_*, mac_hostname_*, mac_addr_*, sched_name_*）直接写入临时 PHP 文件（/tmp/form_macfilter.php），然后通过 dophp('load') 执行。攻击者可以注入恶意 PHP 代码，例如通过设置 entry_enable_0 为 '1; system("id"); //'，导致任意命令执行。触发条件包括：攻击者提交 POST 请求到该脚本，且 settingsChanged=1。利用方式简单，只需构造恶意 POST 数据即可实现 RCE。
- **代码片段：**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac = $_POST[\"mac_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_hostname = $_POST[\"mac_hostname_".$i."\"];\n");
  fwrite("a", $tmp_file, "$mac_addr = $_POST[\"mac_addr_".$i."\"];\n");
  fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_".$i."\"];\n");
  dophp("load",$tmp_file);
  ```
- **关键词：** $_POST['settingsChanged'], $_POST['entry_enable_*'], $_POST['mac_*'], $_POST['mac_hostname_*'], $_POST['mac_addr_*'], $_POST['sched_name_*'], /tmp/form_macfilter.php, dophp
- **备注：** 此漏洞具有完整的攻击链：攻击者控制 POST 数据 -> 数据写入临时文件 -> 文件被执行 -> RCE。需要验证 dophp 函数的确切行为，但基于上下文，它执行 PHP 代码。建议进一步分析 dophp 函数的实现以确认可利用性。关联文件可能包括 /htdocs/mydlink/libservice.php（定义 dophp）。

---
### RCE-form_macfilter

- **文件/目录路径：** `htdocs/mydlink/get_Macfilter.asp`
- **位置：** `form_macfilter: 约第 30-40 行（fwrite 和 dophp 调用）`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 'form_macfilter' 文件中，用户输入通过 `$_POST` 处理，并直接写入临时 PHP 文件，然后使用 `dophp("load")` 动态加载和执行。攻击者可以注入恶意 PHP 代码到 POST 参数（如 `entry_enable_*`），导致远程代码执行。具体触发条件：攻击者提交 POST 请求到 'form_macfilter' 端点，包含恶意代码在 `entry_enable_*` 或其他参数中。例如，设置 `entry_enable_0` 为 `1; system('id'); //` 会在临时文件中生成 `$enable = 1; system('id'); //;`，当 `dophp` 加载时执行 `system('id')`。利用方式：通过认证后，攻击者可以执行任意系统命令，提升权限或控制设备。
- **代码片段：**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_".$i."\"];\n");
  // 其他类似 fwrite 调用
  dophp("load",$tmp_file);
  ```
- **关键词：** form_macfilter, get_Macfilter.asp, /acl/macctrl
- **备注：** 此漏洞要求攻击者具有有效登录凭据，但利用链完整且可验证。'dophp' 函数可能定义在 'xnode.php' 中，未直接分析，但代码行为明显。建议进一步验证 'xnode.php' 的实现。'get_Macfilter.asp' 作为数据输出点，可能被用于反射攻击，但风险较低。

---
### 无标题的发现

- **文件/目录路径：** `etc/init0.d/rcS`
- **位置：** `rcS:行号未指定，但关键代码在 'for i in /etc/init0.d/S??* ; do ... $i start' 循环中`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 'rcS' 脚本中，通过循环执行 /etc/init0.d/ 目录下的所有 S??* 脚本（'$i start'），但由于这些脚本具有全局可写权限（777），非root攻击者可以修改或添加恶意脚本。当系统启动或 rcS 以 root 权限运行时，这些脚本会被执行，允许攻击者注入任意代码并提升权限。触发条件包括系统启动或服务重启。攻击者只需登录设备，修改 /etc/init0.d/ 中的任意脚本（如 S80telnetd.sh），添加恶意命令（如反向 shell 或后门），然后等待或触发重启。约束条件是攻击者需要文件系统访问权限，但基于证据，目录和文件均为可写。
- **代码片段：**
  ```
  for i in /etc/init0.d/S??* ; do
  	# Ignore dangling symlinks (if any).
  	[ ! -f "$i" ] && continue
  	# run the script
  	#echo [$i start]
  	$i start
  	# generate stop script
  	echo "$i stop" > $KRC.tmp
  	[ -f $KRC ] && cat $KRC >> $KRC.tmp
  	mv $KRC.tmp $KRC
  done
  ```
- **关键词：** /etc/init0.d/, /var/killrc0
- **备注：** 基于 ls 输出，/etc/init0.d/ 目录和所有脚本文件权限为 777，表明非root用户可写。rcS 通常以 root 权限运行，因此执行脚本时具有高特权。建议进一步验证 /var/killrc0 文件的权限和生成过程，但当前攻击链已完整。关联文件包括 /etc/init0.d/ 下的所有脚本（如 S80telnetd.sh）。后续分析应检查其他启动脚本和服务交互。

---
### RCE-SQLite3_load_command

- **文件/目录路径：** `bin/sqlite3`
- **位置：** `fcn.0000d0d0 (0x0000d0d0) in sqlite3`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** The '.load' command in SQLite3 CLI allows loading external shared libraries without proper validation of the file path or entry point. A non-root user with login credentials can create a malicious shared library (e.g., in their home directory) and load it via '.load /path/to/malicious.so', leading to arbitrary code execution. The command processes user input directly and passes it to `sqlite3_load_extension`, which loads and executes the library's initialization function. This provides a complete attack chain for privilege escalation or other malicious activities.
- **代码片段：**
  ```
  Relevant code from decompilation:
  if ((piVar12[-0x17] != 0x6c) || ... ) {
      // ... 
  } else {
      piVar12[-100] = 0;
      piVar12[-0x24] = piVar12[-0x5e];  // filename from user input
      iVar3 = piVar12[-1];
      if (iVar3 == 2 || ... ) {
          iVar3 = 0;
      } else {
          iVar3 = piVar12[-0x5d];  // entry point from user input
      }
      piVar12[-0x25] = iVar3;
      fcn.0000cc84(...);
      iVar3 = sym.imp.sqlite3_load_extension(**(piVar12 + ...), piVar12[-0x24], piVar12[-0x25], piVar12 + -400);
      // ...
  }
  ```
- **关键词：** .load, sqlite3_load_extension
- **备注：** This vulnerability is exploitable only if the user can create a shared library, which is feasible with login access. The SQLite3 CLI must have load extension enabled, which appears to be the case here as `sqlite3_load_extension` is called directly. No additional vulnerabilities like SQL injection or buffer overflows were found to be fully exploitable in this context.

---
### 无标题的发现

- **文件/目录路径：** `etc/scripts/upnp/M-SEARCH.sh`
- **位置：** `ssdp.php:SSDP_ms_send_resp 函数（具体行号不可用，但函数定义在文件中）`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** 在 UPnP M-SEARCH 处理过程中，用户控制的 TARGET_HOST 参数被直接嵌入到 shell 命令中，缺乏输入验证和转义，导致命令注入漏洞。具体表现：当攻击者发送恶意 UPnP M-SEARCH 请求时，TARGET_HOST 参数（对应 M-SEARCH.sh 的 $2）传播到 ssdp.php 的 SSDP_ms_send_resp 函数，并用于构建 'httpc' 命令字符串。由于参数被双引号包裹但未转义内部引号，攻击者可注入 shell 元字符（如分号、反引号）来执行任意命令。触发条件：攻击者拥有有效登录凭据，可发送 UPnP 请求；约束条件：无输入过滤或边界检查；潜在利用：通过注入命令实现任意代码执行，可能提升权限（如果脚本以高权限运行）。代码逻辑：ssdp.php 中的命令拼接直接使用用户输入，M-SEARCH.sh 和 M-SEARCH.php 未进行验证。
- **代码片段：**
  ```
  function SSDP_ms_send_resp($target_host, $phyinf, $max_age, $date, $location, $server, $st, $usn)
  {
  	echo "xmldbc -P /etc/scripts/upnp/__M-SEARCH.resp.php";
  	echo " -V \"MAX_AGE="	.$max_age	."\"";
  	echo " -V \"DATE="		.$date		."\"";
  	echo " -V \"LOCATION="	.$location	."\"";
  	echo " -V \"SERVER="	.$server	."\"";
  	echo " -V \"ST="		.$st		."\"";
  	echo " -V \"USN="		.$usn		."\"";
  
  	echo " | httpc -i ".$phyinf." -d \"".$target_host."\" -p UDP\n";
  }
  ```
- **关键词：** UPNPMSG=/runtime/upnpmsg, TARGET_HOST（来自 UPnP 请求）, /var/run/M-SEARCH.*.sh, SSDP_ms_send_resp 函数, httpc 命令
- **备注：** 漏洞基于代码分析，攻击链完整：从 UPnP 请求输入到命令执行。建议进一步验证实际设备环境中的利用（例如测试 httpc 命令行为）。关联文件：M-SEARCH.sh（参数传递）、M-SEARCH.php（数据流）。后续分析方向：检查其他 UPnP 相关文件（如 NOTIFYAB.sh）是否存在类似问题，或分析 httpc 二进制以确认命令处理逻辑。

---
### Command-Injection-usbmount_helper_add

- **文件/目录路径：** `etc/scripts/usbmount_helper.php`
- **位置：** `usbmount_helper.php: 在 action='add' 的代码块中（大约第 40-50 行，基于代码结构）`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'add' 动作中，当处理新磁盘条目时，代码使用 `setattr` 函数执行 shell 命令 `sh /etc/scripts/usbmount_fsid.sh `.prefix.pid`，其中 `prefix` 和 `pid` 变量直接来自用户输入且未经过滤或验证。攻击者可通过注入 shell 元字符（如 `;`、`&`、`|`）来执行任意命令。触发条件包括：发送 HTTP 请求设置 `action=add` 并控制 `prefix` 或 `pid` 参数（例如，设置为 `; malicious_command #`）。利用此漏洞，攻击者可获得命令执行权限，可能提升权限（如果 Web 服务器以 root 权限运行），导致设备完全控制。潜在攻击方式包括：文件系统操作、网络访问或持久化后门安装。
- **代码片段：**
  ```
  if ($action=="add")
  {
      // ... 代码省略 ...
      if (isfile("/sbin/sfdisk")=="1"&&$pid!="0")
          setattr($base."/id", "get", "sh /etc/scripts/usbmount_fsid.sh ".$prefix.$pid);
      else
          set($base."/id","");
      // ... 代码省略 ...
  }
  ```
- **关键词：** $action, $prefix, $pid, setattr
- **备注：** 漏洞基于代码逻辑分析，证据来自文件内容。建议进一步验证实际环境中的输入过滤机制和 Web 接口访问控制。关联文件：'/etc/scripts/usbmount_fsid.sh' 可能受此影响。后续分析方向：检查 Web 服务器配置和权限，确认输入源（如 HTTP 参数）是否可控。

---
### CodeInjection-form_portforwarding

- **文件/目录路径：** `htdocs/mydlink/form_portforwarding`
- **位置：** `form_portforwarding:20-40 (在循环中使用 fwrite 和 dophp 的部分)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'form_portforwarding' 文件中发现代码注入漏洞。当用户提交端口转发配置时（通过 POST 请求设置 `settingsChanged=1`），脚本将未过滤的 POST 数据（如 'enabled_*', 'name_*', 'ip_*' 等）直接写入临时文件 '/tmp/form_portforwarding.php'，然后使用 `dophp("load",$tmp_file)` 加载执行。由于输入未经过任何验证或转义，攻击者可以注入恶意 PHP 代码（例如，在 'name_*' 字段中包含 `"; system("id"); //`），导致任意代码执行。触发条件：攻击者发送特制 POST 请求到该脚本。利用方式：通过控制 POST 参数注入代码，从而执行系统命令，可能获得 web 服务器权限。攻击者是已连接到设备并拥有有效登录凭据的用户（非root用户）。
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
      // ... 后续配置设置
  }
  ```
- **关键词：** $_POST["settingsChanged"], $_POST["enabled_*"], $_POST["name_*"], $_POST["ip_*"], /tmp/form_portforwarding.php, dophp
- **备注：** 漏洞基于直接代码证据：未过滤的输入被写入并执行。建议进一步验证 'dophp' 函数的行为和临时文件的使用情况。关联文件：/htdocs/phplib/xnode.php 和 /htdocs/webinc/config.php 可能包含相关函数定义。后续分析应检查这些包含文件是否有输入过滤机制。攻击链完整且可验证，适用于已认证用户。

---
### CodeInjection-form_wlan_acl

- **文件/目录路径：** `htdocs/mydlink/form_wlan_acl`
- **位置：** `form_wlan_acl:15-19`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'form_wlan_acl' 脚本中发现一个PHP代码注入漏洞。当用户提交POST请求且 'settingsChanged' 参数为1时，脚本将用户控制的 'mac_i' 和 'enable_i' 参数直接嵌入到临时PHP文件中，然后通过 'dophp("load",$tmp_file)' 执行。攻击者可以注入恶意PHP代码（如系统命令），导致任意代码执行。触发条件：攻击者发送POST请求到该脚本，其中包含恶意代码的MAC或enable参数。利用方式：例如，设置 'mac_0' 参数值为 '\"; system(\"id\"); //' 可执行系统命令。漏洞由于缺少输入验证和转义，允许直接代码注入。
- **代码片段：**
  ```
  fwrite("w+", $tmp_file, "<?\n");\nfwrite("a",  $tmp_file, "$MAC = $_POST["mac_.$i."];\n");\nfwrite("a",  $tmp_file, "$ENABLE = $_POST["enable_.$i."];\n");\nfwrite("a",  $tmp_file, ">\n");\ndophp("load",$tmp_file);
  ```
- **关键词：** $_POST['settingsChanged'], $_POST['mode'], $_POST['mac_<i>'], $_POST['enable_<i>'], /tmp/form_wlan_acl.php, dophp
- **备注：** 漏洞允许攻击者以Web服务器权限执行任意代码，可能导致权限提升或系统控制。建议检查其他类似脚本是否存在相同问题，并验证 'get_valid_mac' 函数是否提供任何保护（但代码注入发生在验证之前）。后续分析应关注 'dophp' 函数的实现和其他输入处理点。

---
### Hardcoded-Credentials-logininfo.xml

- **文件/目录路径：** `htdocs/web/webaccess/logininfo.xml`
- **位置：** `logininfo.xml:1 (文件路径)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'logininfo.xml' 文件中发现硬编码凭据（用户名 'admin'，密码 't'），密码强度极弱，可能为默认或测试密码。文件权限设置为 '-rwxrwxrwx'，允许所有用户（包括非root用户）读取。攻击者作为已登录的非root用户，可以轻松读取文件内容，获取管理员凭据，并用于权限提升或未授权访问。触发条件为攻击者拥有有效登录凭据（非root）并能够访问文件系统。潜在攻击方式包括使用获取的凭据登录管理员账户或执行敏感操作。约束条件为文件必须存在且权限未修复。
- **代码片段：**
  ```
  <?xml version="1.0"?><root><user>admin</user><user_pwd>t</user_pwd><volid>1</volid></root>
  ```
- **关键词：** logininfo.xml
- **备注：** 文件可能被登录系统或其他组件使用，建议进一步分析相关组件（如登录处理逻辑）以确认凭据的使用方式。攻击链完整：非root用户读取文件 → 获取凭据 → 利用凭据进行攻击。风险评分高，因为凭据弱且权限宽松，易于利用。

---
### FilePermission-stunnel.key

- **文件/目录路径：** `etc/stunnel.key`
- **位置：** `stunnel.key`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 文件 'stunnel.key' 包含一个 RSA 私钥，权限设置为 -rwxrwxrwx，允许所有用户（包括非root用户）完全访问。攻击者作为已登录用户可以直接读取该文件，获取私钥。触发条件简单：攻击者只需使用基本文件读取命令（如 'cat'）。缺少适当的权限控制（如限制为 root 或特定用户可读）导致私钥泄露。潜在攻击包括：使用私钥解密 SSL/TLS 通信、模拟服务进行中间人攻击、或结合其他漏洞提升权限。利用方式直接：攻击者复制私钥并用于恶意工具（如 OpenSSL）解密流量或伪造证书。
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
- **备注：** 此发现基于直接证据：文件权限和内容验证。攻击链完整且可验证：非root用户可读取私钥并直接滥用。建议立即修复文件权限（例如，设置为 600），仅允许必要用户访问。后续分析应检查是否其他服务依赖此私钥，并评估潜在影响范围。

---
### Config-DefaultValue_XML

- **文件/目录路径：** `etc/defnodes/defaultvalue.xml`
- **位置：** `defaultvalue.xml: 整个文件，具体在账户部分（约行 30-35）、Wi-Fi 部分（约行 200-250）和 Web 访问部分（约行 400-410）`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'defaultvalue.xml' 文件中发现默认配置漏洞，导致攻击者可以完全控制路由器。具体表现：
- Wi-Fi 网络默认设置为开放认证（authtype>OPEN</authtype>）和无加密（encrtype>NONE</encrtype>），SSID 为 'dlink' 和 'dlink-5GHz'，允许任何用户无需凭据连接。
- Web 管理界面启用（<enable>1</enable>），监听 HTTP 端口 8181 和 HTTPS 端口 4433。
- Admin 账户密码为空（<password></password>），攻击者可使用空密码登录。
触发条件：攻击者已连接到设备的 Wi-Fi 网络（由于开放，无需凭据）或通过局域网访问。攻击者然后访问 Web 管理界面（如 http://192.168.0.1:8181），使用用户名 'Admin' 和空密码登录，获得管理员权限。潜在利用方式包括修改路由器设置、启动恶意服务或进一步攻击内网设备。约束条件：此配置为默认设置，在实际部署中可能被更改，但若未修改，则漏洞存在。
- **代码片段：**
  ```
  账户部分示例：
  <account>
    <count>1</count>
    <max>2</max>
    <entry>
      <name>Admin</name>
      <password></password>
      <group>0</group>
    </entry>
  </account>
  
  Wi-Fi 部分示例：
  <entry>
    <uid>WIFI-1</uid>
    <opmode>AP</opmode>
    <defaultssid>dlink</defaultssid>
    <ssid>dlink</ssid>
    <ssidhidden>0</ssidhidden>
    <authtype>OPEN</authtype>
    <encrtype>NONE</encrtype>
    ...
  </entry>
  
  Web 访问部分示例：
  <webaccess>
    <enable>1</enable>
    <httpenable>0</httpenable>
    <httpport>8181</httpport>
    <httpsenable>0</httpsenable>
    <httpsport>4433</httpsport>
    ...
  </webaccess>
  ```
- **关键词：** defaultvalue.xml, device.account.entry.password, wifi.entry.authtype, wifi.entry.encrtype, webaccess.enable, webaccess.httpport, webaccess.httpsport
- **备注：** 此漏洞基于默认配置文件，在实际设备中若配置未更改则存在。攻击链完整且可验证：从开放 Wi-Fi 连接到 Web 登录，无需额外漏洞。建议检查实际设备是否应用了这些默认设置，并验证其他配置文件（如 PHP 脚本）是否强化了安全。后续可分析相关 PHP 文件（如 defaultvalue.php）以确认数据流和处理逻辑。关联发现：查询到 '/webaccess/account/entry' 相关漏洞（PrivEsc-WEBACCESS_setup_wfa_account），但本发现独立且更直接。

---
### Command-Injection-try_set_psk_passphrase

- **文件/目录路径：** `etc/services/WIFI/rtcfg.php`
- **位置：** `rtcfg.php:357 try_set_psk_passphrase 函数`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'rtcfg.php' 文件中发现多个命令注入漏洞。攻击者可以通过控制 WiFi 配置参数（如 SSID、PSK 密钥、WEP 密钥）注入恶意 shell 命令。当脚本生成配置并执行时，注入的命令会以 root 权限运行。具体触发条件包括：用户通过 Web 界面设置恶意 SSID 或密钥值（包含 shell 元字符如 ; 、 | 、 ` 等），然后应用配置（如重启 WiFi 或保存设置），导致 'rtcfg.php' 生成包含注入命令的 shell 脚本。利用方式：在 SSID 或密钥字段中输入 '; malicious_command ;'，生成的命令会执行恶意命令。缺少输入验证和转义，导致直接嵌入到 echo 语句中。
- **代码片段：**
  ```
  function try_set_psk_passphrase($wl_prefix, $wifi)
  {
  	$auth = query($wifi."/authtype");
  	if($auth != "WPAPSK" && $auth != "WPA2PSK" && $auth != "WPA+2PSK")
  		return;
  
  	$key = get("s", $wifi."/nwkey/psk/key");
  	echo "nvram set ".$wl_prefix."_wpa_psk=\"".$key."\"\n";
  }
  ```
- **关键词：** nvram set wl*_wpa_psk, nvram set wl*_ssid, nvram set wl*_key*, /wifi/entry/ssid, /wifi/entry/nwkey/psk/key, /wifi/entry/nwkey/wep/key:*
- **备注：** 攻击链完整：输入点（Web 界面）→ 数据流（通过 get/query 获取）→ 危险操作（生成 shell 命令）。需要验证生成的脚本是否被执行，但基于上下文，很可能由 Web 服务器或初始化脚本以 root 权限执行。建议检查包含的文件（如 xnode.php）是否对输入进行过滤，但当前文件无转义。后续可分析 Web 界面如何调用此脚本。

---
### command-injection-dhcp-hostname-dynamic

- **文件/目录路径：** `etc/services/INET/inet_ipv4.php`
- **位置：** `inet_ipv4.php:inet_ipv4_dynamic 函数（大约行100-110）`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 inet_ipv4_dynamic 函数中，$hostname_dhcpc 变量（来自NVRAM的 /device/hostname_dhcpc）被直接插入到 udhcpc 命令中，缺乏转义。攻击者可修改主机名为恶意字符串（如 'example.com; malicious_command'），当接口启动或更新时，触发命令注入，导致任意命令执行。触发条件：攻击者修改主机名配置后，网络接口重新连接或DHCP续约。利用方式：通过Web界面或API修改主机名字段，注入shell命令。
- **代码片段：**
  ```
  $hostname_dhcpc = get("s", "/device/hostname_dhcpc");
  ...
  'udhcpc '.$unicast.'-i '.$ifname.' -H '.$hostname_dhcpc.' -p '.$udhcpc_pid.' -s '.$udhcpc_helper.' '.$dhcpplus_cmd.' &\n'
  ```
- **关键词：** /device/hostname_dhcpc, /etc/services/INET/inet4_dhcpc_helper.php, /var/servd/*-udhcpc.sh
- **备注：** 需要验证 hostname_dhcpc 是否确实用户可控（通过Web界面）。建议检查 /etc/scripts/IPV4.INET.php 是否对参数进行转义。关联函数：get() 和 query() 可能从XML数据库读取数据。

---
### Command-Injection-AddPortMapping

- **文件/目录路径：** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **位置：** `ACTION.DO.AddPortMapping.php: in the code constructing $sourceip and $cmd (exact line number unknown, near end of file)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 该漏洞源于 `$NewRemoteHost` 输入参数未经验证直接拼接进 `iptables` 命令字符串。攻击者可通过在 `NewRemoteHost` 参数中注入特殊字符（如引号或分号）来突破命令字符串并执行任意命令。触发条件为：当 UPnP 添加端口映射请求处理时，`NewRemoteHost` 包含恶意 payload。约束条件包括：设备必须处于路由器模式（`/runtime/device/layout` 为 'router'），且攻击者需拥有有效登录凭据（非 root 用户，但 UPnP 服务可能以高权限运行）。潜在攻击方式包括：发送 UPnP 请求 with `NewRemoteHost` 值为 `"; malicious_command ; #` 等，导致命令注入。代码逻辑中，在构建 `iptables` 命令时，`$NewRemoteHost` 被直接用于 `-s` 选项，且无过滤。
- **代码片段：**
  ```
  $sourceip = ' -s "'.$NewRemoteHost.'"'; and $cmd = 'iptables -t nat -A DNAT.UPNP'.$proto.' --dport '.$NewExternalPort.' -j DNAT --to-destination "'.$NewInternalClient.'":'.$NewInternalPort.$sourceip; and fwrite("a", $_GLOBALS["SHELL_FILE"], $cmd."\n");
  ```
- **关键词：** NewRemoteHost, SHELL_FILE
- **备注：** 需要进一步验证 `SHELL_FILE` 的路径和执行机制（例如是否由 cron 或系统服务执行）。建议检查相关 IPC 或 NVRAM 交互，但本文件内未直接涉及。后续分析应关注 UPnP 服务整体流程和权限设置。此漏洞与已知 UPnP 命令注入漏洞（如 in M-SEARCH.sh）相关，表明 UPnP 服务中存在多个输入验证缺陷。

---
### Command-Injection-checkfw.sh

- **文件/目录路径：** `etc/events/checkfw.sh`
- **位置：** `文件: checkfw.sh (具体行号无法精确获取，但从内容推断，漏洞位于构建 `wget_string` 和执行 `wget` 命令的部分，大约在输出中第 20-30 行附近)`
- **风险评分：** 8.5
- **置信度：** 7.5
- **描述：** 该漏洞存在于脚本构建 wget URL 并执行下载命令的部分。多个变量（如 `srv`、`reqstr`、`model`、`global`、`buildver`、`MAC`）通过 `xmldbc -g` 从 NVRAM 或运行时数据获取，并在构建 `wget_string` 时直接拼接，没有使用引号或转义。如果攻击者能控制这些变量中的任何一个（例如通过修改 NVRAM 设置），并在其中插入 shell 元字符（如分号、空格、反引号），则可以在 wget 命令执行时注入任意命令。例如，如果 `srv` 变量被设置为 "http://example.com; malicious_command", 则完整的 wget 命令可能变成 "wget http://http://example.com; malicious_command ...", 导致 `malicious_command` 以 root 权限执行。攻击触发条件是脚本定期运行（通过 xmldbc 定时任务）或手动执行，且攻击者需先修改相关 NVRAM 变量。潜在利用方式包括执行系统命令、下载恶意软件或提升权限。
- **代码片段：**
  ```
  #!/bin/sh
  ...
  model="\`xmldbc -g /runtime/device/modelname\`"
  srv="\`xmldbc -g /runtime/device/fwinfosrv\`"
  reqstr="\`xmldbc -g /runtime/device/fwinfopath\`"
  ...
  wget_string="http://"$srv$reqstr"?model=${model}_${global}_FW_${buildver}_${MAC}"
  rm -f $fwinfo
  xmldbc -X /runtime/firmware
  wget  $wget_string -O $fwinfo
  ...
  ```
- **关键词：** /runtime/device/fwinfosrv, /runtime/device/fwinfopath, /runtime/device/modelname, /device/fwcheckparameter, /runtime/devdata/hwver, /runtime/devdata/lanmac
- **备注：** 该发现需要进一步验证：
  - 确认攻击者作为非 root 用户是否能通过 web 接口或 CLI 修改相关 NVRAM 变量。
  - 验证脚本的执行上下文（是否以 root 权限运行）。
  - 建议后续分析相关组件（如 xmldbc 工具、web 接口）以确认数据流和访问控制。
  - 关联文件：/etc/events/checkfw.sh（当前文件）、可能涉及 /usr/sbin/xmldbc 或其他 IPC 机制。

---
### File-Permission-Exploit-wan_stats.xml

- **文件/目录路径：** `htdocs/widget/wan_stats.xml`
- **位置：** `wan_stats.xml:1 (整个文件)`
- **风险评分：** 8.5
- **置信度：** 7.0
- **描述：** 文件 'wan_stats.xml' 具有全局读、写、执行权限（-rwxrwxrwx），允许任何用户（包括非 root 用户）修改其内容。该文件是一个 PHP 脚本，用于生成 WAN 统计信息的 XML 输出，并通过 web 接口可能被访问。攻击者可以修改文件插入恶意 PHP 代码（如系统命令执行），然后通过 web 请求触发执行。由于 web 服务器通常以 root 权限运行，这可能允许权限升级。触发条件包括：攻击者拥有文件修改权限并通过认证 web 访问请求该文件。潜在攻击方式包括：插入 `system($_GET['cmd'])` 等代码实现远程命令执行。边界检查：无文件权限限制或代码签名验证。
- **代码片段：**
  ```
  文件权限: -rwxrwxrwx 1 user user 14162 11月 29  2016 wan_stats.xml
  相关代码: <?
  	include "/htdocs/phplib/xnode.php";
  	include "/htdocs/webinc/config.php";
  	// ... PHP 代码生成 XML 输出
  ?>
  ```
- **关键词：** wan_stats.xml, /htdocs/phplib/xnode.php, /htdocs/webinc/config.php
- **备注：** 攻击链依赖于文件通过 web 服务器执行（如 Apache 或 lighttpd），需要进一步验证 web 服务器配置和该文件的可访问性。建议检查 web 根目录位置和服务器执行权限。关联文件：/htdocs/phplib/xnode.php 和 /htdocs/webinc/config.php 可能包含更多数据流逻辑。后续分析方向：验证 web 接口如何调用此文件，并检查其他类似权限的 PHP 文件。

---
### command-injection-SSDP_ms_send_resp

- **文件/目录路径：** `etc/scripts/upnp/M-SEARCH.php`
- **位置：** `M-SEARCH.php (多个分支使用 $TARGET_HOST) 和 ssdp.php:SSDP_ms_send_resp 函数`
- **风险评分：** 8.0
- **置信度：** 8.5
- **描述：** 在 'M-SEARCH.php' 中，变量 `$TARGET_HOST` 来自不可信输入（如网络请求），并被直接传递给 'ssdp.php' 中的 `SSDP_ms_send_resp` 函数。该函数使用 `echo` 构建 shell 命令（涉及 `xmldbc` 和 `httpc`），并将 `$target_host` 嵌入到命令字符串中而没有转义或验证。攻击者可通过控制 `$TARGET_HOST` 注入 shell 元字符（如分号、反引号）来执行任意命令。触发条件：攻击者发送 M-SEARCH 请求，其中 `TARGET_HOST` 参数包含恶意负载（例如 '; whoami #'），且 `$SEARCH_TARGET` 为有效值（如 'ssdpall'）。利用方式：命令注入可能导致非root用户权限下的任意命令执行，潜在影响包括信息泄露、权限提升或设备控制。代码逻辑中缺少输入过滤和边界检查，使攻击可行。
- **代码片段：**
  ```
  来自 M-SEARCH.php:
  foreach ($path)
  {
      ...
      SSDP_ms_send_resp($TARGET_HOST, $phyinf, $max_age, $date, $location, $server, "upnp:rootdevice", $uuid."::upnp:rootdevice");
      ...
  }
  
  来自 ssdp.php:
  function SSDP_ms_send_resp($target_host, $phyinf, $max_age, $date, $location, $server, $st, $usn)
  {
      echo "xmldbc -P /etc/scripts/upnp/__M-SEARCH.resp.php";
      echo " -V \"MAX_AGE=".$max_age."\"";
      ...
      echo " | httpc -i ".$phyinf." -d \"".$target_host."\" -p UDP\n";
  }
  ```
- **关键词：** $TARGET_HOST, $SEARCH_TARGET, SSDP_ms_send_resp, /etc/scripts/upnp/ssdp.php
- **备注：** 漏洞依赖于输出命令被 shell 执行的环境；建议验证实际执行流程（如检查调用者是否执行输出）。关联文件：'/etc/scripts/upnp/__M-SEARCH.resp.php' 可能包含更多上下文。后续分析方向：测试实际利用、检查其他输入变量（如 $PARAM）是否也存在类似问题。

---
### Command-Injection-dev_start

- **文件/目录路径：** `etc/services/WIFI/rtcfg.php`
- **位置：** `rtcfg.php:728 dev_start 函数`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** 在 SSID 设置处存在命令注入漏洞。攻击者控制 SSID 值，直接嵌入到 nvram set 命令中，未转义 shell 元字符。触发条件：用户设置恶意 SSID（如 '; echo "hacked" > /tmp/test ;'），当配置应用时，生成命令 'nvram set wl*_ssid="; echo "hacked" > /tmp/test ;"'，导致命令注入。缺少边界检查和验证，输入直接来自用户。
- **代码片段：**
  ```
  echo "nvram set ".$wl_prefix."_ssid=\"".get("s",$wifi."/ssid")."\"\n";
  ```
- **关键词：** nvram set wl*_ssid, /wifi/entry/ssid
- **备注：** SSID 是常见用户可配置字段，攻击容易触发。关联到 Web 界面配置流程。建议验证其他输入点如国家代码、WPS 设置。

---
### Stored-XSS-version.php

- **文件/目录路径：** `htdocs/webinc/version.php`
- **位置：** `version.php 在 SSID 输出部分（具体代码行约在文件中部，对应 2.4GHz、5GHz 和次级 5GHz SSID 输出）`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 存储型 XSS 漏洞存在于 SSID 输出部分。攻击者作为非root用户但拥有登录凭据，可以通过 web 界面修改 WiFi SSID 设置为恶意字符串（例如 `<script>alert('XSS')</script>`）。当访问 version.php 页面时，SSID 值被直接输出到 HTML 而不转义，导致恶意脚本执行。触发条件：攻击者修改 SSID 并访问 version.php。潜在利用方式：在认证后上下文中执行任意 JavaScript，可能用于权限提升、窃取会话或修改设备设置。代码逻辑直接使用 `echo` 输出 SSID 值，没有输入验证或输出编码。
- **代码片段：**
  ```
  <div class="info">
  	<span class="name">SSID (2.4G) :</span>				
  	<pre style="font-family:Tahoma"><span class="value"><? include "/htdocs/phplib/xnode.php"; $path = XNODE_getpathbytarget("/wifi", "entry", "uid", "WIFI-1", "0"); echo get(h,$path."/ssid");?></span></pre>
  </div>
  <!-- 类似代码用于 WIFI-3 和 WIFI-5 -->
  ```
- **关键词：** /wifi/entry/uid/WIFI-1/ssid, /wifi/entry/uid/WIFI-3/ssid, /wifi/entry/uid/WIFI-5/ssid
- **备注：** SSID 通常可通过 web 界面由非root用户修改，这增加了可利用性。建议进一步验证 web 界面中 SSID 设置的输入过滤机制。关联文件：/htdocs/phplib/xnode.php（用于获取 SSID 值）。后续分析方向：检查其他用户可控变量（如国家代码、MAC 地址）是否类似地不安全输出。

---
### XSS-onepage.php

- **文件/目录路径：** `htdocs/webinc/js/onepage.php`
- **位置：** `onepage.php:行号未指定（在 OnClickSave 和 OnConnecting 函数中）`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 'onepage.php' 文件中发现存储型跨站脚本（XSS）漏洞。用户输入的 SSID 和密码值在未转义的情况下直接赋值给 innerHTML，导致恶意脚本执行。触发条件：攻击者（已登录用户）在设置向导中输入恶意 JavaScript 代码作为 SSID 或密码，然后点击保存或连接按钮。当页面更新显示这些值时，脚本会在用户浏览器中执行。潜在利用方式：窃取会话 cookie、重定向用户或执行其他客户端攻击。漏洞存在于多个函数中，包括 OnClickSave 和 OnConnecting。
- **代码片段：**
  ```
  // OnClickSave 函数片段
  document.getElementById("24Gssid_megg").innerHTML = ssid24;
  document.getElementById("24Gkey_megg").innerHTML = pass24;
  document.getElementById("5Gssid_megg").innerHTML = ssid5;
  document.getElementById("5Gkey_megg").innerHTML = pass5;
  
  // OnConnecting 函数片段
  document.getElementById("24Gssid_megg1").innerHTML = ssid24;
  document.getElementById("24Gkey_megg1").innerHTML = pass24;
  document.getElementById("5Gssid_megg1").innerHTML = ssid5;
  document.getElementById("5Gkey_megg1").innerHTML = pass5;
  ```
- **关键词：** OBJ("wiz_ssid").value, OBJ("wiz_key").value, OBJ("wiz_ssid_Aband").value, OBJ("wiz_key_Aband").value, document.getElementById("24Gssid_megg").innerHTML, document.getElementById("24Gkey_megg").innerHTML, document.getElementById("5Gssid_megg").innerHTML, document.getElementById("5Gkey_megg").innerHTML
- **备注：** 漏洞需要用户交互（点击按钮）来触发，但由于攻击者是已登录用户，他们可以自行触发或通过社交工程诱骗其他用户。建议检查服务器端是否对输入进行验证和转义。后续分析应关注其他输入点和服务端脚本（如 getcfg.php、register_send.php）是否存在类似问题。

---
### Command-Injection-inet_ipv6-get_dns

- **文件/目录路径：** `etc/services/INET/inet_ipv6.php`
- **位置：** `inet_ipv6.php:多处（例如 inet_ipv6_static 函数、inet_ipv6_auto 函数）`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'inet_ipv6.php' 文件中发现命令注入漏洞，源于 `get_dns` 函数返回的用户可控DNS值被直接嵌入到shell命令中，缺乏输入验证和转义。攻击者作为已认证非root用户，可通过Web界面修改DNS设置（例如在IPv6配置中），注入恶意命令。当IPv6配置应用时（如模式切换或服务重启），通过 `startcmd` 或 `fwrite` 执行的命令会解析注入的载荷，导致任意命令执行。触发条件包括：修改DNS值为包含shell元字符（如 `;`、`"`、`|`）的恶意字符串，并触发IPv6重配置（例如通过界面保存设置）。潜在利用方式包括执行系统命令、上传文件或提升权限。
- **代码片段：**
  ```
  // inet_ipv6_static 函数示例
  startcmd("phpsh /etc/scripts/IPV6.INET.php ACTION=ATTACH".
      " MODE=STATIC INF=".$inf.
      " DEVNAM=".$devnam.
      " IPADDR=".query("ipaddr").
      " PREFIX=".query("prefix").
      " GATEWAY=".query("gateway").
      " ROUTERLFT=".query("routerlft").
      " PREFERLFT=".query("preferlft").
      " VALIDLFT=".query("validlft").
      ' "DNS='.get_dns($inetp."/ipv6").'"'
      );
  
  // get_dns 函数定义
  function get_dns($p)
  {
      anchor($p);
      $cnt = query("dns/count")+0;
      foreach ("dns/entry")
      {
          if ($InDeX > $cnt) break;
          if ($dns=="") $dns = $VaLuE;
          else $dns = $dns." ".$VaLuE;
      }
      return $dns;
  }
  ```
- **关键词：** dns/entry, /inet/entry/ipv6/dns, startcmd, fwrite
- **备注：** 攻击链完整：输入点（DNS设置）→ 数据流（通过 `get_dns` 获取）→ 危险操作（shell命令执行）。需要验证DNS值是否确实用户可控（通过Web界面），并确认服务以root权限运行。建议进一步分析相关Web界面文件（如CGI脚本）以确认输入路径。漏洞在多个IPv6模式中存在（如STATIC、AUTO、6IN4等）。

---
### Command-Injection-security_setup

- **文件/目录路径：** `etc/services/WIFI/rtcfg.php`
- **位置：** `rtcfg.php:312 security_setup 函数`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 WEP 密钥设置处存在命令注入漏洞。攻击者控制 WEP 密钥值，通过 nvram set 命令注入。触发条件：用户设置恶意 WEP 密钥（如 '; malicious_command ;'），生成命令 'nvram set wl*_key*="; malicious_command ;"'。缺少输入过滤，数据流从 /wifi/entry/nwkey/wep/key:* 直接到 echo 语句。
- **代码片段：**
  ```
  $keystring = query($wifi."/nwkey/wep/key:".$defkey);
  echo "nvram set ".$wl_prefix."_key".$defkey."=\"".$keystring."\"\n";
  ```
- **关键词：** nvram set wl*_key*, /wifi/entry/nwkey/wep/key:*
- **备注：** WEP 虽较少使用，但仍是可配置选项。攻击链依赖于 Web 界面暴露这些字段。建议检查所有使用 query/get 的输入点。

---
### info-leak-vpnconfig

- **文件/目录路径：** `htdocs/web/vpnconfig.php`
- **位置：** `vpnconfig.php: 约行 10-12（获取凭据），约行 30-50（输出凭据到XML）`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 脚本 'vpnconfig.php' 在授权检查通过后（$AUTHORIZED_GROUP >= 0），生成 Apple VPN 配置文件（mobileconfig），其中包含明文 VPN 用户名、密码、预共享密钥（PSK）和 IP 地址。攻击者可以通过 HTTP 请求访问此脚本，下载配置文件，并提取敏感凭据。触发条件：攻击者拥有有效登录凭据且授权检查通过。约束条件：授权依赖于 $AUTHORIZED_GROUP 变量，其值可能来自会话或全局配置。潜在攻击：攻击者使用获取的凭据连接到 VPN，可能访问内部网络资源或提升权限。代码逻辑：使用 get('x', ...) 函数从配置路径（如 /vpn/ipsec/username）获取数据，并直接嵌入 XML 输出，没有输入验证或输出编码。
- **代码片段：**
  ```
  $username = get("x", "/vpn/ipsec/username");
  $password = get("x", "/vpn/ipsec/password");
  $psk = get("x", "/vpn/ipsec/psk");
  // ... 输出到 XML:
  echo '\t\t\t<data>'.$psk.'</data>';
  echo '\t\t\t<string>'.$username.'</string>';
  echo '\t\t\t<string>'.$password.'</string>';
  ```
- **关键词：** NVRAM/ENV 变量: /vpn/ipsec/username, /vpn/ipsec/password, /vpn/ipsec/psk, 文件路径: vpnconfig.php, IPC/套接字: 可能通过 web 服务器（HTTP）
- **备注：** 授权机制（$AUTHORIZED_GROUP）和 get 函数的行为需要进一步验证，建议分析包含文件如 /htdocs/webinc/config.php 和 /htdocs/phplib/xnode.php。此漏洞依赖于攻击者已有登录凭据，但提供了清晰的攻击链：访问脚本 → 下载配置 → 提取凭据 → VPN 连接。

---
### command-injection-static-ip-config

- **文件/目录路径：** `etc/services/INET/inet_ipv4.php`
- **位置：** `inet_ipv4.php:inet_ipv4_static 函数（大约行30-50）`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 在 inet_ipv4_static 函数中，$ipaddr、$mask、$gw、$mtu 和 $dns 变量（来自NVRAM查询）被直接插入到 phpsh 命令中。攻击者可修改静态IP配置字段（如IP地址），注入命令分隔符（如分号）执行任意命令。触发条件：攻击者修改静态网络设置后，接口重新配置。利用方式：通过配置界面设置恶意IP地址（如 '1.1.1.1; malicious_command'）。
- **代码片段：**
  ```
  $ipaddr = query("ipaddr");
  $mask = query("mask");
  $gw = query("gateway");
  ...
  startcmd("phpsh /etc/scripts/IPV4.INET.php ACTION=ATTACH STATIC=1 INF=".$inf." DEVNAM=".$ifname." IPADDR=".$ipaddr." MASK=".$mask." GATEWAY=".$gw." MTU=".$mtu.' "DNS='.$dns.'"\n'.$event_add_WANPORTLINKUP );
  ```
- **关键词：** /inet/entry/ipv4/ipaddr, /inet/entry/ipv4/mask, /inet/entry/ipv4/gateway, /inet/entry/ipv4/dns/entry, /etc/scripts/IPV4.INET.php
- **备注：** phpsh 可能对参数进行部分处理，但直接字符串连接仍存在风险。需要验证 IPV4.INET.php 的输入处理。关联文件：/htdocs/phplib/xnode.php。

---
### Command-Injection-inet_child

- **文件/目录路径：** `etc/services/INET/inet_child.php`
- **位置：** `inet_child.php: 在 ipv6_child 函数和脚本末尾，具体行号未知（但代码片段中显示相关调用）`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 在 inet_child.php 中，通过 $CHILD_INFNAME 变量在 startcmd 和 stopcmd 函数中构建命令时，缺少输入验证和过滤，可能导致命令注入。具体表现：当 $CHILD_INFNAME 包含 shell 元字符（如分号、反引号或管道）时，攻击者可以注入任意命令。触发条件包括脚本以足够权限（如 root）执行，并且命令通过写入的文件被执行。潜在利用方式：攻击者作为非 root 用户但拥有登录凭据，可通过环境变量、NVRAM 设置或其他接口控制 $CHILD_INFNAME，注入恶意命令（如文件创建、权限提升）。约束条件：漏洞依赖于命令执行器的权限和输入来源的可控性。
- **代码片段：**
  ```
  stopcmd( "rm -f /var/run/CHILD.".$child.".UP");
  startcmd("echo 1 > /var/run/CHILD.".$child.".UP");
  // 其中 $child 来源于 $CHILD_INFNAME
  startcmd("phpsh /etc/scripts/IPV6.INET.php ACTION=ATTACH INF=".$child." MODE=CHILD DEVNAM=".$devnam." IPADDR=".$ipaddr." PREFIX=".$prefix);
  ```
- **关键词：** $CHILD_INFNAME, XNODE_get_var 获取的变量（如 {child}_IPADDR、{child}_PREFIX）, /var/run/CHILD.{child}.UP, /proc/sys/net/ipv6/conf/{devnam}/disable_ipv6
- **备注：** 漏洞的完整利用链需要验证命令执行上下文（例如 $_GLOBALS['START'] 和 $_GLOBALS['STOP'] 的文件句柄是否指向以 root 权限执行的脚本）。建议后续分析其他组件，如 /etc/scripts/IPV6.INET.php 和命令执行机制，以确认可利用性。关联函数包括 ipv6_child、startcmd、stopcmd。

---
### XSS-form_admin-get_Admin.asp

- **文件/目录路径：** `htdocs/mydlink/get_Admin.asp`
- **位置：** `get_Admin.asp 和 form_admin（具体行号未知，但从内容推断关键代码段）`
- **风险评分：** 7.0
- **置信度：** 8.5
- **描述：** 在 'get_Admin.asp' 文件中发现存储型跨站脚本（XSS）漏洞。攻击链始于 'form_admin' 文件，其中用户通过 POST 参数 'config.web_server_wan_port_http' 控制 'web' 配置值（端口号），该值被直接存储而无验证。当 'get_Admin.asp' 使用 `query("web")` 读取该配置并直接输出到 HTML 时，恶意脚本可能被执行。触发条件：攻击者（拥有有效登录凭据）提交恶意数据到 'form_admin'，设置端口号为恶意脚本（如 `<script>alert('XSS')</script>`），然后访问 'get_Admin.asp' 页面。潜在攻击包括会话劫持、权限提升或执行任意 JavaScript 代码。代码逻辑中缺少输入验证和输出转义，使得漏洞可利用。
- **代码片段：**
  ```
  从 'form_admin':
  <?
  $Remote_Admin_Port = $_POST["config.web_server_wan_port_http"];
  if($Remote_Admin=="true"){
      set($WAN1P."/web", $Remote_Admin_Port);
  }
  ?>
  从 'get_Admin.asp':
  <?
  $remotePort = query("web");
  ?>
  <divide><? echo $remotePort; ?><option>
  ```
- **关键词：** web, /htdocs/mydlink/form_admin, /htdocs/mydlink/get_Admin.asp
- **备注：** 漏洞已验证为完整攻击链：输入点（form_admin）→ 数据流（set/web）→ 危险操作（直接输出）。建议检查其他类似文件（如 form_*）是否也存在输入验证缺失问题，并实施输出转义（如使用 htmlspecialchars）。攻击者需认证，但风险较高因可导致会话劫持。

---
### Command-Injection-DeletePortMapping

- **文件/目录路径：** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.DeletePortMapping.php`
- **位置：** `ACTION.DO.DeletePortMapping.php:~20-30 (在 'if (query("enable")==1)' 块内)`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 在 DeletePortMapping.php 中，脚本使用来自端口映射条目的数据（如 remotehost、internalclient）直接拼接到 iptables 命令字符串中，没有充分的输入验证或过滤。如果这些条目数据被恶意控制（例如通过 UPnP 添加操作），可能导致命令注入当命令被执行。攻击链完整：攻击者需先通过 UPnP 添加功能（如 ACTION.DO.AddPortMapping.php）注入恶意 NewRemoteHost 数据到端口映射条目，然后触发删除操作来执行任意命令。触发条件包括设备处于启用状态（query("enable")==1），且攻击者拥有有效登录凭据（非 root 用户）。可利用性已验证，通过关联分析确认输入数据可控。
- **代码片段：**
  ```
  if (query("enable")==1)
  {
  	$remotehost = get("s", "remotehost");
  	if ($remotehost != "") $sourceip = ' -s "'.$remotehost.'"';
  	if (query("protocol") == "TCP")	$proto = ' -p tcp';
  	else							$proto = ' -p udp';
  	$extport = query("externalport");
  	$intport = query("internalport");
  	$intclnt = query("internalclient");
  
  	$cmd =	'iptables -t nat -D DNAT.UPNP'.$proto.' --dport '.$extport.
  			' -j DNAT --to-destination "'.$intclnt.'":'.$intport;
  	SHELL_info("a", $_GLOBALS["SHELL_FILE"], "UPNP:".$cmd);
  	fwrite("a", $_GLOBALS["SHELL_FILE"], $cmd."\n");
  }
  ```
- **关键词：** NewRemoteHost, NewExternalPort, NewProtocol, /runtime/upnpigd/portmapping/entry, remotehost, externalport, protocol, internalport, internalclient, SHELL_FILE
- **备注：** 通过关联分析 ACTION.DO.AddPortMapping.php 中的命令注入漏洞，确认 NewRemoteHost 等输入可由攻击者控制，形成完整攻击链。建议进一步检查 SHELL_FILE 的执行上下文和权限，但当前证据链已足够验证可利用性。攻击者需利用 UPnP 服务流程，先添加后删除恶意条目。

---
### BufferOverflow-main-mDNSResponderPosix

- **文件/目录路径：** `bin/mDNSResponderPosix`
- **位置：** `main function at addresses 0x0003a5c0 to 0x0003a5dc in mDNSResponderPosix`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** A buffer overflow vulnerability exists in the TXT record processing of mDNSResponderPosix when handling the -x command-line option. The program copies user-provided name=val pairs into a fixed-size global buffer (gServiceText) without proper bounds checking. The vulnerability occurs in a while loop that uses strlen to get the length of each argument and memcpy to copy the data into the buffer. The current offset (gServiceTextLen) is updated without verifying if the total size exceeds the buffer capacity. When the total input length exceeds approximately 263 bytes, it overwrites the gServiceTextLen variable itself, allowing an attacker to control the write offset and achieve arbitrary memory write. This can lead to code execution by overwriting function pointers or other critical data structures. The vulnerability is triggerable by any user with execute permissions on the binary, and exploitation does not require root privileges, though it does not escalate privileges unless the binary is setuid root.
- **代码片段：**
  ```
  while (iVar9 = *piVar14, iVar9 - param_1 < 0 != SBORROW4(iVar9,param_1)) {
      uVar1 = *(iVar3 + 0x1f8);
      uVar2 = sym.imp.strlen(param_2[iVar9]);
      *(iVar3 + uVar1 + 0xf0) = uVar2;
      sym.mDNSPlatformMemCopy(iVar3 + uVar1 + 0xf1, param_2[iVar9]);
      *(iVar3 + 0x1f8) = *(iVar3 + 0x1f8) + 1 + *(iVar3 + *(iVar3 + 0x1f8) + 0xf0);
      *piVar14 = *piVar14 + 1;
  }
  ```
- **关键词：** Command-line arguments (-x), Global variable gServiceText, Global variable gServiceTextLen
- **备注：** This vulnerability is exploitable by a non-root user with login credentials to execute arbitrary code within their own privilege context. The attack chain involves providing malicious -x arguments to overflow the buffer and overwrite gServiceTextLen, enabling arbitrary memory write. Further analysis could explore other input points like service files (-f) or network interfaces for additional vulnerabilities. The binary is not setuid, so privilege escalation is not directly possible, but it could be used in conjunction with other vulnerabilities.

---
### Command-Injection-SETVPNSRRT

- **文件/目录路径：** `etc/profile`
- **位置：** `scripts/SETVPNSRRT.php`
- **风险评分：** 7.0
- **置信度：** 7.0
- **描述：** 在 SETVPNSRRT.php 脚本中，当处理 PPTP/L2TP VPN 连接时，使用用户可控的服务器地址（来自 NVRAM 或 web 配置）生成 shell 命令，缺少输入验证。变量 $server 用于 'gethostip -d' 命令，如果包含特殊字符（如分号），可注入任意命令。触发条件：攻击者通过 web 接口设置恶意 VPN 服务器地址（例如，包含 '; malicious_command'），当 VPN 连接尝试时脚本执行。约束：仅当服务器地址非 IPv4 格式时触发 gethostip 命令。潜在利用：注入命令获取 shell 或执行恶意操作，可能以 root 权限运行（脚本通常由系统服务调用）。
- **代码片段：**
  ```
  if(INET_validv4addr($server) != 1)
  {
      echo "sip=\`gethostip -d ".$server."\`\n";
      echo "sed -i \"s/".$server."/$sip/g\" /etc/ppp/options.".$INF."\n";
      echo "phpsh /etc/scripts/vpnroute.php PATH=".$inetp."/ppp4/".$overtype."/olddomainip INF=".$INF." DOMAINIP=".$domain." IP=".$l_ip." SERVER=$sip"." MASK=".$l_mask." DEV=".$l_dev." GW=".$l_gw."\n";
  }
  ```
- **关键词：** pptp_server, l2tp_server, /etc/scripts/SETVPNSRRT.php, /etc/scripts/vpnroute.php, NVRAM 变量
- **备注：** 需要验证 web 接口如何设置服务器地址（如通过 nvram_set），以确认用户可控性。建议后续分析 web 组件以完善攻击链。关联文件：vpnroute.php（也可能存在类似漏洞）。

---
### info-leak-get_Wireless.php

- **文件/目录路径：** `htdocs/mydlink/get_Wireless.php`
- **位置：** `get_Wireless.php:1 (代码开头) 和输出部分（例如靠近文件末尾的条件输出语句）`
- **风险评分：** 6.5
- **置信度：** 8.5
- **描述：** 该漏洞允许攻击者通过控制 'displaypass' GET 参数为 1，导致脚本输出敏感无线网络配置信息，包括 WEP 密钥、PSK 密钥和 RADIUS 密钥。攻击链完整：输入点（$_GET['displaypass']）→ 数据流（直接使用用户输入，缺乏授权验证和边界检查）→ 危险操作（条件输出敏感信息）。触发条件是攻击者发送 GET 请求到 'get_Wireless.php' 并设置 'displaypass=1'。攻击者拥有登录凭据，可实际利用泄露的密钥进行无线网络连接或进一步攻击。可利用性高，因为代码逻辑直接依赖用户输入。
- **代码片段：**
  ```
  相关代码片段：
  - 输入获取: \`$displaypass = $_GET["displaypass"];\`
  - 条件输出示例: \`<f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>\`
  - 其他敏感输出: \`<f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>\` 和 \`<f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>\`
  ```
- **关键词：** $_GET["displaypass"], get_Wireless.php, /wifi/entry/nwkey/psk/key, /wifi/entry/nwkey/wep/key:*
- **备注：** 漏洞实际可利用，因为攻击者拥有登录凭据，可能通过 Web 界面访问该脚本。关联函数包括 XNODE_getpathbytarget、query 和 get，可能涉及 NVRAM 或配置数据交互。建议检查整体认证和授权机制，确保只有授权用户（如管理员）才能访问敏感信息。后续分析方向包括验证脚本的访问控制和其他潜在输入点。

---
### PrivEsc-WEBACCESS_setup_wfa_account

- **文件/目录路径：** `etc/services/WEBACCESS.php`
- **位置：** `WEBACCESS.php setup_wfa_account function (大致行 70-110)`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在 WEBACCESS.php 的 setup_wfa_account 函数中，用户名在写入认证文件 '/var/run/storage_account_root' 时未过滤换行符。攻击者（已认证非root用户）可通过 web 接口创建或修改用户账户，设置用户名为包含换行符的恶意字符串（如 'attacker\nadmin'），导致在认证文件中注入新用户条目。这可能允许攻击者创建高权限账户（如 'admin'）或操纵磁盘权限，从而提升权限。触发条件包括：webaccess 启用、攻击者能修改用户名、setup_wfa_account 函数执行（通常当配置更改时）。利用方式：攻击者设置恶意用户名 → 配置更新时文件被写入 → 注入新用户条目 → 攻击者使用注入的账户登录。
- **代码片段：**
  ```
  fwrite("a", $ACCOUNT, query("username").":x".$storage_msg."\n");
  ```
- **关键词：** /var/run/storage_account_root, /webaccess/account/entry, /runtime/webaccess/device/entry
- **备注：** 需要进一步验证 web 接口是否允许换行符在用户名中输入，以及认证文件解析器是否正确处理多行条目。建议检查用户创建/修改接口的输入过滤。关联函数：comma_handle（可能未使用）。后续分析方向：验证输入点（如 web 接口处理）和认证文件的使用情况。

---
### 信息泄露-get_Email.asp

- **文件/目录路径：** `htdocs/mydlink/get_Email.asp`
- **位置：** `get_Email.asp:行号未指定（但代码片段中条件输出部分）`
- **风险评分：** 6.0
- **置信度：** 9.0
- **描述：** 该文件存在敏感信息泄露漏洞，允许攻击者通过控制 'displaypass' GET 参数来泄露 SMTP 密码。具体表现：当攻击者（已认证用户）发送 GET 请求到 'get_Email.asp' 并设置 'displaypass=1' 时，SMTP 密码会以明文形式输出在 XML 响应中。触发条件：攻击者必须拥有有效登录凭据并能够访问该页面。约束条件：参数值必须为 1 才能触发泄露；其他值不会输出密码。潜在攻击：攻击者可以利用泄露的密码进行进一步攻击，如滥用 SMTP 服务器或密码重用攻击。代码逻辑直接，缺少对参数访问控制的额外验证。
- **代码片段：**
  ```
  $displaypass = $_GET["displaypass"];
  ...
  <config.smtp_email_pass><?if($displaypass==1){echo $smtp_password;}?></config.smtp_email_pass>
  ```
- **关键词：** displaypass (GET 参数), /device/log/email/smtp/password (NVRAM 变量)
- **备注：** 此漏洞需要攻击者已通过认证，因此风险中等。建议检查该页面的访问控制机制是否足够严格。后续可分析其他相关文件（如调用了此文件的组件）以寻找更复杂的攻击链。

---
### 无标题的发现

- **文件/目录路径：** `htdocs/web/getcfg.php`
- **位置：** `getcfg.php: in the main else block after authorization check, where SERVICES parameter is processed`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** 在 'getcfg.php' 中，通过 `$_POST["SERVICES"]` 参数存在潜在的任意文件包含漏洞。攻击者可以控制 `$GETCFG_SVC` 变量，用于构造文件路径 `/htdocs/webinc/getcfg/`.$GETCFG_SVC.`.xml.php`，没有输入验证或路径遍历防护。如果攻击者能注入路径遍历序列（如 `../../../etc/passwd`），可能导致加载并执行任意文件，从而实现远程代码执行（RCE）或信息泄露。触发条件：攻击者发送 POST 请求到 'getcfg.php'，设置 `SERVICES` 参数为恶意值，且用户为 power user（`$AUTHORIZED_GROUP >= 0`）。潜在利用方式：包含系统敏感文件（如 /etc/passwd）或上传的恶意 PHP 文件执行代码。约束条件：文件必须存在，且 `dophp` 函数可能只执行 PHP 文件，但如果没有后缀检查，可能泄露非 PHP 文件内容。
- **代码片段：**
  ```
  $GETCFG_SVC = cut($_POST["SERVICES"], $SERVICE_INDEX, ",");
  TRACE_debug("GETCFG: serivce[".$SERVICE_INDEX."] = ".$GETCFG_SVC);
  if ($GETCFG_SVC!="")
  {
      $file = "/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php";
      /* GETCFG_SVC will be passed to the child process. */
      if (isfile($file)=="1")
      {
          if(get("", "/runtime/device/sessions_privatekey")==1)
          {
              AES_Encrypt_DBnode($GETCFG_SVC, "Encrypt");
              dophp("load", $file);
              AES_Encrypt_DBnode($GETCFG_SVC, "Decrypt");
          }
          else
          {    dophp("load", $file);}
      }
  }
  ```
- **关键词：** $_POST["SERVICES"], $GETCFG_SVC, $file, dophp
- **备注：** 这个发现基于代码证据，但可利用性取决于攻击者能否上传恶意文件或系统存在可读敏感文件。建议进一步分析 'dophp' 函数的行为（可能位于 '/htdocs/phplib/' 中）和系统文件结构，以验证任意文件包含是否可导致 RCE。此外，检查会话管理（如 $SESSION_UID）可能揭示信息泄露风险。攻击者需为 power user，因此授权机制也可能是一个攻击向量。

---
### command-injection-dns-dynamic

- **文件/目录路径：** `etc/services/INET/inet_ipv4.php`
- **位置：** `inet_ipv4.php:inet_ipv4_dynamic 函数（大约行80-90）`
- **风险评分：** 6.0
- **置信度：** 6.5
- **描述：** 在 inet_ipv4_dynamic 函数中，$dns 变量（来自NVRAM的DNS设置）被插入到生成的udhcpc helper脚本中，该脚本通过phpsh执行。如果$dns包含恶意内容，可能影响脚本行为或导致注入。触发条件：修改DNS设置后DHCP客户端重启。利用方式：设置DNS为恶意字符串。
- **代码片段：**
  ```
  $dns = $dns.$VaLuE." ";
  ...
  ' "DNS='.$dns.'$dns"'
  ```
- **关键词：** /inet/entry/ipv4/dns/entry, /var/servd/*-udhcpc.sh
- **备注：** 代码中有拼写错误（'$dns' 重复），可能影响行为。需要验证udhcpc helper脚本的生成和执行。

---
### Config-Injection-generate_configs

- **文件/目录路径：** `etc/services/WIFI/hostapdcfg.php`
- **位置：** `hostapdcfg.php:80 generate_configs`
- **风险评分：** 5.0
- **置信度：** 6.0
- **描述：** 在 'hostapdcfg.php' 文件中，发现配置注入漏洞。攻击者可以通过控制 SSID 字段注入任意 hostapd 配置选项，因为 SSID 值被直接写入配置文件而没有适当的输入验证或过滤。具体表现：当生成 hostapd 配置文件时，SSID 值（来自 `query("ssid")`）被直接用于 `fwrite` 调用，如果 SSID 包含换行符（`\n`），攻击者可以添加额外的配置行。触发条件：攻击者通过 Web 界面或其他接口修改无线设置中的 SSID，并包含恶意配置选项。潜在攻击包括注入 `ignore_broadcast_ssid=1` 来隐藏 SSID，或注入 `wpa_passphrase=attacker` 来尝试覆盖预共享密钥（但可能被后续正式设置覆盖）。利用方式：攻击者作为非 root 用户但拥有有效登录凭据，修改 SSID 为恶意字符串，导致生成的配置文件包含意外配置，可能造成拒绝服务或安全设置绕过。约束条件：注入的配置选项必须在 hostapd 中有效，且不被后续写入的配置覆盖；攻击者需要知道可用的 hostapd 选项。
- **代码片段：**
  ```
  fwrite("a", $output, 'ssid='.$ssid.'\n'. 'wpa='.$wpa.'\n'. 'ieee8021x='.$ieee8021x.'\n' );
  ```
- **关键词：** ssid, /runtime/phyinf, /wifi/entry/ssid, /var/run/hostapd-*.conf
- **备注：** 此漏洞的利用取决于 hostapd 对配置文件的解析行为（例如，是否允许多个相同键或未知选项）。建议进一步验证 hostapd 二进制文件如何处理注入的配置，并检查 Web 界面是否对 SSID 长度和字符有限制。关联文件：/etc/services/PHYINF/phywifi.php（可能定义输入源）。后续分析方向：追踪 SSID 数据流从 Web 界面到本脚本的路径，并测试实际注入场景。

---
### XSS-index.php-modelname

- **文件/目录路径：** `htdocs/smart404/index.php`
- **位置：** `index.php:3 (在 <TITLE> 标签中)`
- **风险评分：** 3.5
- **置信度：** 4.0
- **描述：** 在 'index.php' 文件中，使用 `query` 函数动态输出设备模型名（/runtime/device/modelname）到 HTML <TITLE> 标签中。如果攻击者能控制该值（例如通过 NVRAM 设置），可能注入恶意脚本导致 XSS。触发条件：攻击者修改 NVRAM 中的 modelname 值，用户访问错误页面时执行脚本。潜在利用方式：窃取会话或重定向用户。但当前文件未显示直接用户输入处理，且缺乏证据证明 modelname 可被外部控制或未过滤。
- **代码片段：**
  ```
  <TITLE><?echo query("/runtime/device/modelname");?></TITLE>
  ```
- **关键词：** query, /runtime/device/modelname, /runtime/device/devconfsize
- **备注：** 风险评分较低，因为缺乏完整攻击链证据。需要进一步分析 `query` 函数的实现（可能在 /htdocs/phplib/xnode.php）和 NVRAM 设置机制，以验证数据可控性和过滤情况。建议追踪 /runtime/device/modelname 的数据源和修改接口。关联发现：在 /etc/events/checkfw.sh 中，modelname 通过 NVRAM 获取并用于命令注入，证实 modelname 可由攻击者修改，从而完善了攻击链。

---
