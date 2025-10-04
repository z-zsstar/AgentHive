# _DIR890LA1_FW111b02_20170519_beta01.bin.extracted (30 个发现)

---

### permission-stunnel.key

- **文件/目录路径：** `etc/stunnel.key`
- **位置：** `stunnel.key`
- **风险评分：** 9.0
- **置信度：** 9.5
- **描述：** stunnel.key 文件包含一个 RSA 私钥，且文件权限设置为 777（-rwxrwxrwx），允许任何用户（包括非root用户）读取、写入和执行。攻击者作为非root用户可以直接读取私钥，无需提升权限。触发条件：攻击者拥有有效登录凭据（非root用户）并执行文件读取操作（如 'cat stunnel.key'）。约束条件：无边界检查或访问控制，权限全局开放。潜在攻击包括解密 stunnel 保护的通信、进行中间人攻击或冒充服务身份。利用方式简单：直接读取文件内容并滥用私钥。
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
- **备注：** 此漏洞是实际可利用的，攻击链简单直接：非root用户读取私钥文件。建议立即修复文件权限（例如设置为 600），并检查 stunnel 配置以确保私钥不被滥用。关联文件可能包括 stunnel 配置文件（如 stunnel.conf），但当前分析仅限于 stunnel.key。后续分析应验证 stunnel 服务是否使用此私钥以及网络暴露情况。

---
### PrivKey-Permission-stunnel

- **文件/目录路径：** `etc/stunnel.conf`
- **位置：** `stunnel.conf (implicit via configuration) and file permissions at /etc/stunnel.key`
- **风险评分：** 9.0
- **置信度：** 9.5
- **描述：** stunnel.key 私钥文件权限设置为 777（rwxrwxrwx），允许任何用户（包括非 root 用户）读取该文件。攻击者作为已登录的非 root 用户，可直接执行读取操作（例如使用 'cat /etc/stunnel.key'）获取私钥。私钥泄露后，攻击者可用于解密 SSL/TLS 通信、进行中间人攻击或模仿服务身份。触发条件简单：攻击者只需拥有有效登录凭据和文件读取权限。无需其他漏洞或复杂步骤，即可完成利用。约束条件：无边界检查或访问控制，文件全局可读。潜在攻击方式包括被动窃听或主动劫持加密会话。
- **代码片段：**
  ```
  key = /etc/stunnel.key
  # File permissions: -rwxrwxrwx 1 user user 1679 5月  19  2017 stunnel.key
  ```
- **关键词：** /etc/stunnel.key, /etc/stunnel_cert.pem
- **备注：** 此发现基于直接证据：文件权限为 777 且文件存在。建议立即修复文件权限（例如设置为 600），并审查其他相关文件（如 stunnel_cert.pem）。虽然 stunnel 以 root 权限运行（setuid=0）和调试模式开启（debug=7）可能增加风险，但当前缺乏完整攻击链证据。后续分析应检查 stunnel 二进制是否存在漏洞，以及日志文件（/var/log/stunnel.log）权限是否不当。

---
### Code-Injection-form_portforwarding

- **文件/目录路径：** `htdocs/mydlink/form_portforwarding`
- **位置：** `文件: ./form_portforwarding, 函数: 在 if($settingsChanged == 1) 块中，具体在 fwrite 和 dophp 调用处`
- **风险评分：** 9.0
- **置信度：** 9.0
- **描述：** 在 'form_portforwarding' 文件中发现代码注入漏洞。脚本处理端口转发配置时，直接从 POST 请求中读取用户输入（如 'enabled_*', 'name_*', 'ip_*' 等字段），没有进行输入验证、过滤或转义。这些输入被写入临时文件 `/tmp/form_portforwarding.php`，然后通过 `dophp("load",$tmp_file)` 加载执行。攻击者可以通过构造恶意 POST 数据注入 PHP 代码，例如设置 `enabled_0` 为 '1; system("恶意命令"); //'，当文件加载时执行任意命令。触发条件是发送 POST 请求到处理此脚本的端点，并设置 `settingsChanged=1`。利用方式简单，攻击者作为已登录用户可远程执行代码，可能导致设备完全控制。
- **代码片段：**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"enabled_".$i."\"];\n");
  // 类似的多行 fwrite 用于其他 POST 字段
  dophp("load",$tmp_file);
  ```
- **关键词：** POST 字段: settingsChanged, enabled_*, used_*, name_*, public_port_*, public_port_to_*, sched_name_*, ip_*, private_port_*, hidden_private_port_to_*, protocol_*, 临时文件路径: /tmp/form_portforwarding.php, 函数: dophp, fwrite, ipv4hostid, 配置路径: /nat/entry/virtualserver
- **备注：** 漏洞利用需要攻击者拥有有效登录凭据。建议进一步验证 `dophp` 函数的定义和行为（可能位于包含文件中，如 `/htdocs/phplib/xnode.php`），以确认代码执行机制。同时，检查其他类似脚本是否存在相同问题。攻击链完整，从输入到代码执行可验证。

---
### code-injection-form_macfilter

- **文件/目录路径：** `htdocs/mydlink/form_macfilter`
- **位置：** `form_macfilter: (estimated lines 20-50) within if($settingsChanged == 1) block`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** 在 'form_macfilter' 文件中发现代码注入漏洞，允许通过未过滤的 POST 参数执行任意 PHP 代码。具体表现：当 'settingsChanged' POST 参数设置为 1 时，脚本动态生成临时文件 '/tmp/form_macfilter.php'，并将用户控制的 POST 参数（如 'entry_enable_X', 'mac_X', 'mac_hostname_X', 'mac_addr_X', 'sched_name_X'）直接写入该文件，然后通过 'dophp("load",$tmp_file)' 加载执行。缺少输入验证和过滤，攻击者可以注入恶意 PHP 代码。触发条件：攻击者发送 POST 请求 with 'settingsChanged=1' 和恶意参数值。潜在攻击方式：注入代码如 'system("id")' 可实现 RCE，影响设备安全。约束条件：攻击者需有有效登录凭据（非 root 用户）并访问相关 web 接口。
- **代码片段：**
  ```
  fwrite("a", $tmp_file, "$enable = $_POST[\"entry_enable_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$mac = $_POST[\"mac_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$mac_hostname = $_POST[\"mac_hostname_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$mac_addr = $_POST[\"mac_addr_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$sched_name = $_POST[\"sched_name_\".$i.\"];\n");
  dophp("load",$tmp_file);
  ```
- **关键词：** $_POST["settingsChanged"], $_POST["macFltMode"], $_POST["entry_enable_*"], $_POST["mac_*"], $_POST["mac_hostname_*"], $_POST["mac_addr_*"], $_POST["sched_name_*"], /tmp/form_macfilter.php, dophp, runservice
- **备注：** 漏洞基于代码分析确认，但未实际测试执行。建议进一步验证 'dophp' 函数的行为（可能定义于引入的库文件如 '/htdocs/phplib/xnode.php'）和临时文件执行上下文。关联文件：'/htdocs/mydlink/header.php', '/htdocs/phplib/xnode.php', '/htdocs/mydlink/libservice.php'。后续分析方向：检查 web 接口端点是否暴露此脚本，并测试实际注入 payload。

---
### CodeInjection-RCE-form_wlan_acl

- **文件/目录路径：** `htdocs/mydlink/form_wlan_acl`
- **位置：** `form_wlan_acl: approximately lines 20-25 (in the while loop with fwrite and dophp calls)`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** 该漏洞源于脚本动态生成并执行临时 PHP 文件时，未对用户输入进行过滤或转义。攻击者可通过控制 POST 参数如 'mac_i' 或 'enable_i'（其中 i 是索引）注入恶意 PHP 代码。触发条件为：发送 POST 请求且 'settingsChanged'=1。注入的代码在 dophp('load',$tmp_file) 时执行，可导致任意命令执行。例如，设置 'mac_0' 为 '"; system("id"); //' 会破坏代码语法并执行 system("id")。约束条件：攻击者需拥有有效登录凭据（非 root 用户），且需通过 Web 接口发送请求。利用方式简单，仅需构造恶意 POST 请求即可实现 RCE。
- **代码片段：**
  ```
  fwrite("a", $tmp_file, "$MAC = $_POST[\"mac_\".$i.\"];\n");
  fwrite("a", $tmp_file, "$ENABLE = $_POST[\"enable_\".$i.\"];\n");
  dophp("load", $tmp_file);
  ```
- **关键词：** $_POST['settingsChanged'], $_POST['mode'], $_POST['mac_i'], $_POST['enable_i'], /tmp/form_wlan_acl.php, dophp
- **备注：** 证据基于代码分析，但建议进一步验证 dophp 函数的具体实现（可能位于包含文件中，如 '/htdocs/mydlink/libservice.php'）以确认执行行为。关联文件可能包括其他 PHP 包含文件。后续分析方向：检查 get_valid_mac 函数是否可能绕过，以及 runservice 调用的服务是否引入其他风险。

---
### CommandInjection-hedwig.cgi

- **文件/目录路径：** `htdocs/cgibin`
- **位置：** `cgibin:0x175f4 fcn.000175f4 (hedwig.cgi handler)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 hedwig.cgi 的 service 参数处理中存在命令注入漏洞。service 参数从 QUERY_STRING 环境变量中提取，未经过滤就用于 sprintf 构造命令字符串，然后通过 system() 执行。触发条件：POST 请求，Content-Type 为 text/xml，且 QUERY_STRING 包含 service 参数。约束条件：请求方法必须为 POST，Content-Type 必须正确设置。潜在攻击：认证用户可以在 service 参数中注入 shell 元字符（如 ;, &, |）来执行任意命令，可能导致远程代码执行，CGI 进程可能以提升的权限运行。代码逻辑：函数 fcn.000175f4 检查环境变量，提取 service 参数，并使用它在 sprintf 中构造如 'sh /var/run/%s_%d.sh > /dev/console &' 的命令，最终调用 system()。
- **代码片段：**
  ```
  // Key vulnerable code sections:
  - Extraction of service parameter: uVar1 = sym.imp.strchr(*(puVar6 + -0x14),0x3f); // Finds '?' in QUERY_STRING
    *(puVar6 + -0x1c) = uVar1;
    if (...) {
      *(puVar6 + -0x1c) = *(puVar6 + -0x1c) + 9; // Points to value after '?service='
    }
  - Command construction: sym.imp.sprintf(0x7544 | 0x30000,0xbf50 | 0x20000,0xbf1c | 0x20000,*(puVar6 + -0x1c)); // Format: 'sh %s/%s_%d.sh > /dev/console &' with /var/run and service value
  - Command execution: sym.imp.system(0x7544 | 0x30000); // Executes the constructed command
  ```
- **关键词：** QUERY_STRING, CONTENT_TYPE, REQUEST_METHOD, service, /var/run/, fcn.000175f4
- **备注：** 漏洞高度可利用，因为用户输入直接传递给 system()。CGI 可能以 root 权限运行，增加影响。攻击链完整，从环境变量输入到命令执行。

---
### Private-Key-Exposure-stunnel

- **文件/目录路径：** `etc/stunnel_cert.pem`
- **位置：** `文件: stunnel.key (权限: 777), stunnel.conf:1-2 (配置路径)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在分析 'stunnel_cert.pem' 文件时，发现其关联的私钥文件 'stunnel.key' 权限设置为 777（所有用户可读），导致私钥暴露给非 root 用户。攻击者（拥有有效登录凭据的非 root 用户）可以直接读取私钥，并利用它进行 TLS 相关攻击，如解密捕获的流量或进行中间人攻击。stunnel 服务配置（'stunnel.conf'）显示服务以 root 权限运行，使用这些证书和私钥文件，进一步放大了风险。攻击链完整：攻击者登录系统 → 读取 '/etc/stunnel.key' → 使用私钥解密或冒充服务。证书使用弱签名算法 SHA-1，但单独不构成直接漏洞；主要风险来自私钥暴露。
- **代码片段：**
  ```
  从 stunnel.key 文件内容：
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAo/0bZcpc3Npc89YiNcP+kPxhLCGLmYXR4rHLt2I1BbnkXWHk
  ... (完整私钥内容)
  -----END RSA PRIVATE KEY-----
  
  从 stunnel.conf 文件内容：
  cert = /etc/stunnel_cert.pem
  key = /etc/stunnel.key
  setuid = 0
  setgid = 0
  ```
- **关键词：** stunnel.key, stunnel_cert.pem, stunnel.conf, /etc/stunnel.key, /etc/stunnel_cert.pem
- **备注：** 私钥暴露是一个严重问题，攻击链完整且可验证。建议立即修复文件权限（例如，设置为 600），并考虑轮换证书和私钥。进一步分析应检查 stunnel 服务是否暴露在网络上，以及是否有其他敏感文件存在类似权限问题。

---
### command-injection-DS_IPT

- **文件/目录路径：** `etc/scripts/wfa_igd_handle.php`
- **位置：** `wfa_igd_handle.php:DS_IPT 模式处理块（约行 150-190）`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'DS_IPT' 模式下，变量 $C_IP、$E_PORT、$SSL 来自外部输入（如 HTTP 请求），被直接拼接进 iptables 命令字符串，并通过 exe_ouside_cmd 函数执行。由于缺乏输入验证和过滤，攻击者可通过注入恶意字符（如分号、反引号）执行任意系统命令。触发条件：攻击者发送 MODE=DS_IPT 的请求并控制 $C_IP 等参数。利用方式：例如，设置 $C_IP 为 '192.168.1.1; malicious_command'，导致命令注入。代码逻辑直接拼接输入到命令中，未使用转义或白名单验证。攻击链完整：输入点→命令拼接→执行。
- **代码片段：**
  ```
  else if($MODE=="DS_IPT")  //add directserver iptable rules
  {
      $ipt_cmd="";
      
      if($C_IP=="0.0.0.0")
          {$ipt_cmd="PRE.WFA -p tcp";}
      else
          {$ipt_cmd="PRE.WFA -p tcp -s ".$C_IP;}
          
      if($SSL == '0')
          {$ipt_cmd=$ipt_cmd." --dport ".$E_PORT." -j REDIRECT --to-ports ".query("/webaccess/httpport");}
      else
          {$ipt_cmd=$ipt_cmd." --dport ".$E_PORT." -j REDIRECT --to-ports ".query("/webaccess/httpsport");}
      
      if($ipt_cmd!="")
      {
          $del_ipt="iptables -t nat -D ".$ipt_cmd;
          exe_ouside_cmd($del_ipt);
          $add_ipt="iptables -t nat -A ".$ipt_cmd;
          exe_ouside_cmd($add_ipt);
      }
      // ... 其他代码
  }
  ```
- **关键词：** MODE, C_IP, E_PORT, SSL, /runtime/webaccess/ext_node
- **备注：** 攻击链完整：输入点（$C_IP 等）→ 命令拼接 → exe_ouside_cmd 执行。exe_ouside_cmd 函数使用 setattr 和 get，可能在其他文件中实现命令执行，需进一步验证。建议检查包含的文件（如 /htdocs/phplib/xnode.php）以确认执行机制。其他模式（如 SEND_IGD）也可能存在类似问题，但 DS_IPT 模式证据最直接。攻击者是已连接用户，拥有登录凭据，非root用户。

---
### command-injection-inet6_dhcpc_helper

- **文件/目录路径：** `etc/services/INET/inet6_dhcpc_helper.php`
- **位置：** `inet6_dhcpc_helper.php:handle_stateful 函数（约行 100-150）和 handle_stateless 函数（约行 250-300）`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 命令注入漏洞存在于多个 cmd() 调用中，由于输入变量（如 NEW_PD_PREFIX、NEW_PD_PLEN、DNS）仅使用 strip() 函数处理（可能只去除首尾空格），未过滤 shell 元字符（如 ;、&、|）。攻击者可通过控制这些变量注入恶意命令。触发条件包括：当 MODE 为 STATEFUL、STATELESS 或 PPPDHCP 时，处理 DHCPv6 客户端回调；攻击者需能影响 DHCP 配置或响应（例如通过恶意 DHCP 服务器或本地配置修改）。潜在利用方式：注入命令如 '; malicious_command #' 到变量中，导致以脚本运行权限（可能 root）执行任意命令。约束条件：输入来自 $_GLOBALS，可能受网络或配置控制；strip() 函数可能不足以防注入。
- **代码片段：**
  ```
  // 示例来自 handle_stateful 函数
  cmd(\"ip -6 route add blackhole \".$NEW_PD_PREFIX.\"/\".$NEW_PD_PLEN.\" dev lo\");
  // 示例来自 phpsh 调用
  cmd(\"phpsh /etc/scripts/IPV6.INET.php ACTION=ATTACH INF=\".$_GLOBALS[\"INF\"].\" MODE=\".$_GLOBALS[\"MODE\"].\" DEVNAM=\".$devnam.\" IPADDR=\".$ipaddr.\" PREFIX=\".$pfxlen.\" GATEWAY=\".$router.' \"DNS=\'.$dns.'\"\');
  // 输入处理
  $NEW_PD_PREFIX = strip($_GLOBALS[\"NEW_PD_PREFIX\"]);
  $dns = dns_handler($DNS, $NAMESERVERS); // 其中 $DNS = strip($_GLOBALS[\"DNS\"]);
  ```
- **关键词：** $_GLOBALS[\"NEW_PD_PREFIX\"], $_GLOBALS[\"NEW_PD_PLEN\"], $_GLOBALS[\"DNS\"], $_GLOBALS[\"NAMESERVERS\"], $_GLOBALS[\"NEW_ADDR\"], cmd() 函数, /var/run/ 文件路径, phpsh /etc/scripts/IPV6.INET.php
- **备注：** 证据基于代码分析：strip() 函数可能未定义在本文件中，但假设它仅处理空格，不防止命令注入。攻击链完整：输入点（$_GLOBALS）→ 数据流（strip() 处理）→ 危险操作（cmd() 执行）。建议验证 strip() 的具体实现（在包含文件中），并检查其他组件（如 DHCP 客户端）如何设置 $_GLOBALS。非 root 用户可能通过 Web 界面或 CLI 修改 DHCP 配置来触发。关联文件：/htdocs/phplib/ 中的包含文件可能定义相关函数。通过知识库查询，发现与 'MODE' 标识符相关的现有命令注入漏洞，但本发现独立且完整。

---
### command-injection-inet_ipv6

- **文件/目录路径：** `etc/services/INET/inet_ipv6.php`
- **位置：** `inet_ipv6.php: inet_ipv6_static 函数 (约第 250 行附近), inet_ipv6_auto 函数 (约第 400 行附近), 及其他使用 `get_dns` 的函数`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'inet_ipv6.php' 文件中发现命令注入漏洞。攻击者可通过配置恶意 DNS 服务器地址（包含 shell 元字符如双引号或分号），当脚本执行 IPv6 配置时，DNS 数据通过 `get_dns` 函数获取并直接插入到 shell 命令字符串中，未进行转义处理。例如，在 `inet_ipv6_static` 函数中，DNS 数据被用于构建 `phpsh` 命令，如果 DNS 值包含 `"; malicious_command "`，可突破双引号限制执行任意命令。触发条件为攻击者修改 IPv6 配置（如静态模式 DNS 设置）并触发脚本执行（例如接口启动）。利用方式：攻击者作为已登录用户通过 web 界面或 API 设置恶意 DNS 配置，等待或触发网络重新配置，导致以 root 权限执行任意命令。
- **代码片段：**
  ```
  在 inet_ipv6_static 函数中:
  startcmd("phpsh /etc/scripts/IPV6.INET.php ACTION=ATTACH".
      " MODE=STATIC INF=".$inf.
      " DEVNAM=".        $devnam.
      " IPADDR=".        query("ipaddr").
      " PREFIX=".        query("prefix").
      " GATEWAY=".    query("gateway").
      ' "DNS='.get_dns($inetp."/ipv6").'"'
      );
  
  在 inet_ipv6_auto 函数中:
  fwrite(w, $rawait,
      "#!/bin/sh\n".
      "phpsh /etc/scripts/RA-WAIT.php".
          " INF=".$inf.
          " PHYINF=".$phyinf.
          " DEVNAM=".$ifname.
          " DHCPOPT=".query($inetp."/ipv6/dhcpopt").
          ' "DNS='.get_dns($inetp."/ipv6").'"'.
          " ME=".$rawait.
          "\n");
  
  get_dns 函数:
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
- **关键词：** NVRAM: /inet/entry/ipv6/dns/entry, ENV: INET_INFNAME, 文件路径: /etc/scripts/IPV6.INET.php, IPC: 通过 xmldbc 命令通信
- **备注：** 该漏洞的利用依赖于用户能够控制 DNS 配置数据并通过网络接口提交。需要进一步验证 web 界面或其他输入点是否对 DNS 数据进行了过滤，以及脚本执行的具体权限上下文。建议检查相关配置文件和输入验证机制。其他函数（如 inet_ipv6_6in4）也可能存在类似问题，但当前证据集中于 DNS 数据流。

---
### 无标题的发现

- **文件/目录路径：** `etc/services/INET/inet_ppp4.php`
- **位置：** `inet_ppp4.php:~200 (在 over=='tty' 分支的 fwrite 调用处)`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 'inet_ppp4.php' 文件中，当 PPP 连接使用 USB 调制解调器（over=='tty'）时，APN 和拨号号码参数从用户可控的 NVRAM 或环境变量获取，并直接拼接至 shell 命令中生成脚本文件。由于未对输入进行转义或验证，攻击者可通过设置恶意 APN 或拨号号码（如包含 shell 元字符的命令字符串）注入任意命令。触发条件：当 PPP 连接启动时（例如用户应用网络设置或连接建立），生成的脚本以 root 权限执行，导致命令注入。利用方式：攻击者作为已认证非 root 用户，通过 Web 界面或 API 设置恶意参数，触发脚本执行并获得 root 权限。
- **代码片段：**
  ```
  fwrite(a, $START,
      'xmldbc -s '.$ttyp.'/apn "'.$apn.'"\n'.
      'xmldbc -s '.$ttyp.'/dialno "'.$dialno.'"\n'.
      'usb3gkit -o /etc/ppp/chat.'.$inf.' -v 0x'.$vid.' -p 0x'.$pid.' -d '.$devnum.'\n'.
      '# chatfile=[/etc/ppp/char'.$inf.']\n'
      );
  ```
- **关键词：** /runtime/auto_config/apn, /runtime/auto_config/dialno, /inet/entry/ppp4/tty/apn, /inet/entry/ppp4/tty/dialno
- **备注：** 此漏洞需要 over=='tty' 条件成立（即使用 USB 调制解调器）。攻击链完整且可验证：用户输入→脚本生成→命令执行。建议检查相关组件（如 usb3gkit）是否也存在类似问题，并验证输入过滤机制。后续可分析其他输入点（如 PPPoE 参数）以识别类似漏洞。

---
### 无标题的发现

- **文件/目录路径：** `etc/services/INET/inet_ipv4.php`
- **位置：** `inet_ipv4.php:inet_ipv4_static, inet_ipv4.php:inet_ipv4_dynamic, inet_ipv4.php:inet_ipv4_dslite`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** 在 inet_ipv4.php 文件中，多个函数（inet_ipv4_static、inet_ipv4_dynamic、inet_ipv4_dslite）从 NVRAM 或配置中获取用户输入，并直接嵌入到系统命令或 shell 脚本中，缺乏输入验证和转义。具体问题包括：
- 在 inet_ipv4_static 函数中，IP 地址、掩码、网关、MTU 和 DNS 值被拼接进 phpsh 命令，如果输入包含特殊字符（如分号、反引号），可能注入任意命令。
- 在 inet_ipv4_dynamic 函数中，主机名、DNS 和 DHCP+ 凭据被用于构建 udhcpc 命令和生成 shell 脚本，脚本中输入被直接嵌入，允许命令注入。
- 在 inet_ipv4_dslite 函数中，IP 地址和远程地址被用于 ip 命令，类似风险存在。
触发条件：攻击者通过 Web 界面或 API 配置网络设置时，提供恶意输入（如主机名包含 '; id;'）。当网络配置应用时（例如接口启动），命令被执行。
潜在攻击：攻击者可执行任意命令，提升权限或破坏系统。利用方式简单，只需控制输入值。
- **代码片段：**
  ```
  // inet_ipv4_static 函数中的命令拼接
  startcmd("phpsh /etc/scripts/IPV4.INET.php ACTION=ATTACH".
      " STATIC=1".
      " INF=".$inf.
      " DEVNAM=".$ifname.
      " IPADDR=".$ipaddr.
      " MASK=".$mask.
      " GATEWAY=".$gw.
      " MTU=".$mtu.
      ' "DNS='.$dns.'"\\n'.
      $event_add_WANPORTLINKUP
      );
  
  // inet_ipv4_dynamic 函数中的脚本生成和命令拼接
  fwrite(w,$udhcpc_helper,
      '#!/bin/sh\\n'.
      'echo [$0]: $1 $interface $ip $subnet $router $lease $domain $scope $winstype $wins $sixrd_prefix $sixrd_prefixlen $sixrd_msklen $sixrd_bripaddr ... > /dev/console\\n'.
      'phpsh '.$hlper.' ACTION=$1'.
          ' INF='.$inf.
          ' INET='.$inet.
          ' MTU='.$mtu.
          ' INTERFACE=$interface'.
          ' IP=$ip'.
          ' SUBNET=$subnet'.
          ' BROADCAST=$broadcast'.
          ' LEASE=$lease'.
          ' "DOMAIN=$domain"'.
          ' "ROUTER=$router"'.
          ' "DNS='.$dns.'$dns"'.\\t\\t\\t
          ' "CLSSTROUT=$clsstrout"'.
          ' "MSCLSSTROUT=$msclsstrout"'.
          ' "SSTROUT=$sstrout"'.
          ' "SCOPE=$scope"'.
          ' "WINSTYPE=$winstype"'.
          ' "WINS=$wins"'.
          ' "SIXRDPFX=$sixrd_prefix"'.
          ' "SIXRDPLEN=$sixrd_prefixlen"'.
          ' "SIXRDMSKLEN=$sixrd_msklen"'.
          ' "SIXRDBRIP=$sixrd_bripaddr"'.\\t\\t\\t
          ' "SDEST=$sdest"'.
          ' "SSUBNET=$ssubnet"'.
          ' "SROUTER=$srouter"\\n'.
      'exit 0\\n'
      );
  
  'udhcpc '.$unicast.'-i '.$ifname.' -H '.$hostname_dhcpc.' -p '.$udhcpc_pid.' -s '.$udhcpc_helper.' '.$dhcpplus_cmd.' &\\n'
  ```
- **关键词：** /device/hostname_dhcpc, $inetp/ipv4/ipaddr, $inetp/ipv4/mask, $inetp/ipv4/gateway, $inetp/ipv4/mtu, $inetp/ipv4/dns/entry, $inetp/ipv4/dhcpplus/username, $inetp/ipv4/dhcpplus/password, $inetp/ipv4/ipv4in6/remote
- **备注：** 输入点可能通过 Web 界面或 API 用户配置可控。攻击链完整：用户输入 → 数据流（直接拼接） → 命令执行。建议进一步验证输入来源和过滤机制在其他文件（如 Web 后端脚本）中的实现。关联文件：/etc/scripts/IPV4.INET.php、/etc/services/INET/inet4_dhcpc_helper.php。

---
### buffer_overflow-fcn.000183f8_filename

- **文件/目录路径：** `sbin/mt-daapd`
- **位置：** `mt-daapd:0x18994 fcn.000183f8`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 在函数 fcn.000183f8 中，strcpy 被调用于地址 0x18994，将目录条目中的文件名复制到目标缓冲区。文件名通过 readdir_r 从文件系统获取，攻击者可能控制文件系统内容（例如，上传或创建文件）。没有边界检查，目标缓冲区大小未知（来自函数参数 arg_1000h），导致缓冲区溢出漏洞。触发条件：当函数处理目录时，攻击者提供长文件名（超过目标缓冲区大小）。利用方式：通过创建长文件名文件，溢出缓冲区可能覆盖返回地址或执行任意代码。
- **代码片段：**
  ```
  0x18454: ldr r3, [r6, 4] ; cmp r3, 0 ; bne 0x18870 --> 循环开始调用 readdir_r 获取目录条目
  0x18520: add r4, r8, 0xb ; mov r0, r4 ; bl sym.imp.strlen --> r4 设置为文件名字符串地址
  0x18994: bl sym.imp.strcpy --> 污点数据 r4 复制到目标缓冲区 r8，无边界检查
  ```
- **关键词：** 目录条目, arg_1000h
- **备注：** 需要进一步验证目标缓冲区具体大小和溢出后果，但基于数据流从不可信输入到危险操作，漏洞实际可利用。建议检查函数参数传递和缓冲区分配。

---
### buffer_overflow-fcn.000183f8_filecontent

- **文件/目录路径：** `sbin/mt-daapd`
- **位置：** `mt-daapd:0x18b50 fcn.000183f8`
- **风险评分：** 8.0
- **置信度：** 9.0
- **描述：** 在函数 fcn.000183f8 中，strcpy 被调用于地址 0x18b50，将文件内容复制到目标缓冲区。文件内容通过文件读取（fread-like 操作）获取，攻击者可能控制文件内容。没有边界检查，目标缓冲区大小未知（来自函数参数 arg_1000h），导致缓冲区溢出漏洞。触发条件：当函数读取文件时，攻击者提供长内容文件（超过目标缓冲区大小）。利用方式：通过上传长内容文件，溢出缓冲区可能覆盖返回地址或执行任意代码。
- **代码片段：**
  ```
  0x18a4c: ldr r0, [fildes] ; mov r1, r5 ; mov r2, 0x1000 ; bl fcn.00010fd8 --> 从文件读取数据到缓冲区 r5，大小 0x1000
  0x18b50: bl sym.imp.strcpy --> 污点数据 r5 复制到目标缓冲区 r8，无边界检查
  ```
- **关键词：** 文件内容, arg_1000h
- **备注：** 类似第一个调用，但源是文件内容。需要确认文件读取操作的具体上下文，但基于证据，漏洞实际可利用。建议限制文件输入大小或使用安全函数。

---
### XSS-folder_view_php

- **文件/目录路径：** `htdocs/web/webaccess/folder_view.php`
- **位置：** `folder_view.php: JavaScript functions show_folder_content and get_sub_tree`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 'folder_view.php' 的文件列表显示功能中存在存储型跨站脚本（XSS）漏洞。攻击者可以通过上传带有恶意JavaScript代码的文件名（例如：'<img src=x onerror=alert(1)>.txt'），当其他用户或攻击者自己查看文件列表时，文件名会被直接插入HTML而不转义，导致恶意脚本执行。触发条件包括：1) 攻击者已登录并拥有文件上传权限；2) 上传文件时使用恶意文件名；3) 用户访问文件列表页面。潜在利用方式包括：窃取用户会话令牌、执行管理操作、重定向用户到恶意网站等。该漏洞由于缺少对文件名的HTML转义验证，使得攻击者可以注入任意脚本。
- **代码片段：**
  ```
  在 show_folder_content 函数中：
  cell_html = "<input type=\"checkbox\" id=\"" + i + "\" name=\"" + file_name + "\" value=\"1\"/>"
  + "<a  href=\""+req+"\" title=\"" + obj.name + "\">"
  + "<div style=\"width:665px;overflow:hidden\">"
  + file_name + "<br>" + get_file_size(obj.size) + ", " + time
  + "</div></a>";
  
  在 get_sub_tree 函数中：
  my_tree += "<li id=\"" + obj_path + "\" class=\"tocollapse\">"
  +  "<a href=\"#\" onClick=\"click_folder('" + obj_path + "', '" + current_volid + "', '" +obj.mode+ "')\">"
  + '<div class ="current_node" title="'+ show_name +'">'+obj.name + "</a></li>"
  + "<li></li>"
  + "<li><span id=\"" + obj_path + "-sub\"></span></li>";
  ```
- **关键词：** file_name, obj.name, show_name, upload_file, show_folder_content, get_sub_tree
- **备注：** 该漏洞是实际可利用的，因为攻击链完整：输入点（文件上传）-> 数据流（文件名存储并返回）-> 漏洞点（HTML渲染时不转义）。建议对所有用户输入进行HTML转义处理。后续分析应检查后端CGI接口是否对文件名进行了额外验证，以及是否有其他类似XSS点。

---
### XSS-get_Logopt.asp-form_mydlink_log_opt

- **文件/目录路径：** `htdocs/mydlink/get_Logopt.asp`
- **位置：** `get_Logopt.asp:1 (整体文件), form_mydlink_log_opt:1 (整体文件)`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 'get_Logopt.asp' 文件中发现存储型跨站脚本（XSS）漏洞。该文件通过 `query` 函数从路径如 '/device/log/mydlink/eventmgnt/pushevent' 读取配置数据并输出 XML，但输出未对数据进行转义。相关文件 'form_mydlink_log_opt' 处理 POST 请求设置这些数据，但输入参数（如 'config.log_enable'）直接从 `$_POST` 获取且缺乏验证。攻击者（已登录用户）可提交恶意 POST 请求注入 JavaScript 代码，当用户访问 'get_Logopt.asp' 时，恶意脚本在浏览器中执行。触发条件：攻击者向 'form_mydlink_log_opt' 发送恶意参数（例如，设置 'config.log_enable' 为 `<script>alert('XSS')</script>`），然后用户访问 'get_Logopt.asp'。利用方式：存储型 XSS 可窃取会话 cookie、执行未授权操作或劫持用户会话。代码逻辑中缺少输入过滤和输出转义是根本原因。
- **代码片段：**
  ```
  从 'get_Logopt.asp': 
  <?
  include "/htdocs/mydlink/header.php";
  include "/htdocs/phplib/xnode.php";
  include "/htdocs/webinc/config.php";
  $LOGP		="/device/log/mydlink/eventmgnt/pushevent";
  $PUSH		=query($LOGP."/enable");
  $USERLOGIN	=query($LOGP."/types/userlogin");
  $FWUPGRADE	=query($LOGP."/types/firmwareupgrade");
  $WLINTRU	=query($LOGP."/types/wirelessintrusion");
  ?>
  <mydlink_logopt>
  <config.log_enable><?=$PUSH?></config.log_enable>
  <config.log_userloginfo><?=$USERLOGIN?></config.log_userloginfo>
  <config.log_fwupgrade><?=$FWUPGRADE?></config.log_fwupgrade>
  <config.wirelesswarn><?=$WLINTRU?></config.wirelesswarn>
  </mydlink_logopt>
  
  从 'form_mydlink_log_opt':
  <?
  include "/htdocs/mydlink/header.php";
  $settingsChanged	=$_POST["settingsChanged"];
  $PUSH			=$_POST["config.log_enable"];
  $USERLOGIN		=$_POST["config.log_userloginfo"];
  $FWUPGRADE		=$_POST["config.log_fwupgrade"];
  $WLINTRU_V1		=$_POST["config.log_wirelesswarn"];
  $WLINTRU_V2		=$_POST["config.wirelesswarn"];
  $LOGP		="/device/log/mydlink/eventmgnt/pushevent";
  $PUSHP		=$LOGP."/enable";
  $USERLOGINP	=$LOGP."/types/userlogin";
  $FWUPGRADEP	=$LOGP."/types/firmwareupgrade";
  $WLINTRUP	=$LOGP."/types/wirelessintrusion";
  $WLINTRU = 0;
  if($WLINTRU_V1 == 1 || $WLINTRU_V2 == 1)
  	$WLINTRU = 1;
  if($USERLOGIN	== 1 || $FWUPGRADE == 1 || $WLINTRU == 1)
  	$PUSH = 1;
  $ret="fail";
  if($settingsChanged==1){
  	set($PUSHP, $PUSH);
  	set($USERLOGINP, $USERLOGIN);
  	set($FWUPGRADEP, $FWUPGRADE);
  	set($WLINTRUP, $WLINTRU);
  }
  $ret="ok";
  ?>
  <?=$ret?>
  ```
- **关键词：** POST参数: config.log_enable, config.log_userloginfo, config.log_fwupgrade, config.wirelesswarn, 文件路径: form_mydlink_log_opt, get_Logopt.asp, NVRAM路径: /device/log/mydlink/eventmgnt/pushevent/enable, /device/log/mydlink/eventmgnt/pushevent/types/userlogin, /device/log/mydlink/eventmgnt/pushevent/types/firmwareupgrade, /device/log/mydlink/eventmgnt/pushevent/types/wirelessintrusion
- **备注：** 漏洞已验证通过代码分析：输入未过滤且输出未转义。攻击链完整，从输入点到危险操作（XSS执行）。需要进一步验证其他组件是否使用这些输出值，但当前证据足够。建议检查 `set` 和 `query` 函数的实现（可能在未找到的 'xnode.php' 中）以确认数据存储机制，但不影响此漏洞的利用。后续分析应关注其他表单文件是否存在类似问题。

---
### info-leak-get_Wireless-displaypass-updated

- **文件/目录路径：** `htdocs/mydlink/get_Wireless.asp`
- **位置：** `get_Wireless.php:1 (变量赋值) 和 get_Wireless.php:~70-80 (输出部分)，函数: 无特定函数，全局代码`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 'get_Wireless.php' 文件中发现信息泄露漏洞，该文件通过 'get_Wireless.asp' 被引用。漏洞允许认证用户通过 HTTP GET 参数 'displaypass' 泄露无线网络的敏感配置信息，包括 WEP 密钥、WPA PSK 密钥和 RADIUS 密钥。具体表现：当参数 'displaypass' 设置为 1 时，脚本在 XML 输出中返回这些敏感数据；否则返回空字符串。触发条件简单：攻击者只需在 HTTP 请求中添加 '?displaypass=1'。代码中缺少输入验证、边界检查或过滤，直接使用 `$_GET["displaypass"]` 与 1 进行比较。潜在攻击：攻击者获取敏感密码后，可能用于未经授权的无线网络访问、离线密码破解或进一步网络渗透。利用方式：认证用户发送请求到相关端点（如 'get_Wireless.php?displaypass=1' 或通过 'get_Wireless.asp' 间接访问）即可触发。
- **代码片段：**
  ```
  关键代码片段：
  - 输入处理: \`$displaypass = $_GET["displaypass"];\`
  - 条件输出: 
    \`<f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>\`
    \`<f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>\`
    \`<f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>\`
  ```
- **关键词：** HTTP GET 参数: displaypass, 输出字段: f_wep, f_wps_psk, f_radius_secret1, 内部数据源: NVRAM 或配置文件通过 query/get 函数获取, 关联文件: get_Wireless.asp (通过包含引用)
- **备注：** 此漏洞假设脚本在认证后可通过 web 访问，且攻击者拥有有效登录凭据（非root用户）。关联文件：'get_Wireless.asp' 通过包含引入 'get_Wireless.php'，但漏洞核心在后者。建议进一步验证：1) 'get_Wireless.php' 是否在 web 根目录下且可被认证用户直接或间接访问；2) 是否有角色权限限制参数使用。后续分析方向：检查调用链中的认证机制和 web 接口路径。

---
### 无标题的发现

- **文件/目录路径：** `htdocs/web/webaccess/photo.php`
- **位置：** `photo.php: show_media_list 函数 (大约在代码中第 50-70 行)`
- **风险评分：** 7.5
- **置信度：** 8.5
- **描述：** 在 'photo.php' 的 show_media_list 函数中，文件名 (obj.name) 在插入 HTML 时没有进行转义，导致存储型 XSS 漏洞。触发条件：当用户访问 photo.php 页面时，如果文件列表中的文件名包含恶意脚本（例如 `<script>alert('XSS')</script>`），该脚本将在受害者浏览器中执行。攻击者作为已登录用户，可以通过文件上传或修改文件名的方式注入恶意负载，然后诱使其他用户查看照片列表，从而窃取会话 Cookie 或执行任意操作。约束条件：攻击者需要具备文件上传或修改权限，且受害者必须访问 photo.php 页面。利用方式简单直接，无需特殊权限。
- **代码片段：**
  ```
  str += "<tr onMouseOver=\"this.style.background='#D8D8D8'\" onMouseOut=\"this.style.background=''\">"
       + "<td width=\"36\" height=\"36\" class=\"tdbg\">"
       + "<img src=\"webfile_images/icon_photos.png\" width=\"36\" height=\"36\" border=\"0\">"
       + "</td>"
       + "<td width=\"868\" class=\"text_2\">"
       + "<a rel=\"image1\" href=\""+req+"\" title=\"" + obj.name + "\">"
       + "<div>"
       + file_name +"<br>" + get_file_size(obj.size) + ", " + obj.mtime
       + "</div>"
       + "</a>"
       + "</td></tr>";
  ```
- **关键词：** obj.name, media_info.files[i].name, /dws/api/GetFile
- **备注：** 证据基于代码分析：文件名在 HTML 中直接拼接，没有使用转义函数（如 encodeHTML）。攻击链完整：攻击者控制文件名 → 服务器返回文件列表 → 受害者查看页面 → XSS 触发。建议验证文件上传功能是否允许设置任意文件名，并检查后端 API 是否对文件名进行过滤。关联文件可能包括上传处理脚本或文件管理组件。

---
### Command-Injection-ppp6_ipup-route

- **文件/目录路径：** `etc/services/INET/ppp6_ipup.php`
- **位置：** `ppp6_ipup.php:50 (近似行号，基于代码结构) 在 echo 'ip -6 route add default via '.$REMOTE.' dev '.$IFNAME.'
'; 处。`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在代码中，$REMOTE 和 $IFNAME 变量被直接拼接进 'ip -6 route' 命令中，缺乏输入验证和转义。攻击者如果控制 $REMOTE 或 $IFNAME（例如通过恶意 PPP 配置或中间人攻击），可以注入任意 shell 命令。例如，设置 $REMOTE 为 '192.168.1.1; malicious_command' 可能导致命令执行。触发条件是在 PPP 连接建立时脚本执行，攻击者需能影响 PPP 协商或配置。潜在利用方式包括执行系统命令、提升权限或破坏网络配置。
- **代码片段：**
  ```
  echo 'ip -6 route add default via '.$REMOTE.' dev '.$IFNAME.'
  ';
  ```
- **关键词：** 环境变量 $REMOTE, $IFNAME, 文件路径 /htdocs/phplib/xnode.php, /htdocs/phplib/phyinf.php, IPC 事件如 $PARAM.UP, 自定义函数 XNODE_getpathbytarget, PHYINF_setup
- **备注：** 需要进一步验证 $REMOTE 和 $IFNAME 的实际来源和可控性；建议检查 PPP 守护进程的输入处理；关联文件包括 ppp4_ipup.php 和其他 PPP 相关脚本。

---
### Command-Injection-bound

- **文件/目录路径：** `etc/services/INET/inet4_dhcpc_helper.php`
- **位置：** `inet4_dhcpc_helper.php: 在 'bound' 动作的代码块中（具体行号未提供，但从内容看位于脚本中部）`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 在 'bound' 动作中，多个用户可控变量（如 $INF、$INTERFACE、$IP、$SUBNET、$BROADCAST、$ROUTER、$DOMAIN、$DNS、$CLSSTROUT、$SSTROUT）被直接拼接进 shell 命令字符串，缺乏输入验证或过滤。攻击者可通过操纵这些变量注入恶意命令（例如使用分号、反引号或管道符号），导致任意命令执行。触发条件包括当 $ACTION 为 'bound' 时，脚本执行命令构建逻辑。潜在利用方式包括通过恶意 DHCP 响应或 web 接口调用控制变量值，执行系统命令。
- **代码片段：**
  ```
  echo "phpsh /etc/scripts/IPV4.INET.php ACTION=ATTACH".\n        " STATIC=0".\n        " INF=".$INF.\n        " DEVNAM=".$INTERFACE.\n        " MTU=".$MTU.\n        " IPADDR=".$IP.\n        " SUBNET=".$SUBNET.\n        " BROADCAST=".$BROADCAST.\n        " GATEWAY=".$ROUTER.\n        ' "DOMAIN='.$DOMAIN.'"'.\n        ' "DNS='.$DNS.'"'.\n        ' "CLSSTROUT='.$CLSSTROUT.'"'.\n        ' "SSTROUT='.$SSTROUT.'"'.\n        '\n';
  ```
- **关键词：** $ACTION, $INF, $INTERFACE, $IP, $SUBNET, $BROADCAST, $ROUTER, $DOMAIN, $DNS, $CLSSTROUT, $SSTROUT
- **备注：** 需要进一步验证输入变量是否来自不可信源（如 DHCP 响应或 web 接口）以及是否有其他过滤机制。建议分析调用此脚本的上下文（如 web 前端或 DHCP 客户端）以确认可利用性。关联文件可能包括 '/etc/scripts/IPV4.INET.php' 和 web 接口脚本。

---
### PPP-Option-Injection-create_pppoptions

- **文件/目录路径：** `etc/services/INET/options_ppp4.php`
- **位置：** `options_ppp4.php:~25-30 (函数 create_pppoptions, 具体在 fwrite 调用处)`
- **风险评分：** 7.5
- **置信度：** 7.0
- **描述：** 函数 `create_pppoptions` 将用户控制的输入（如用户名、密码、PPPoE 参数）直接拼接并写入 PPP 选项文件，而没有转义或验证。攻击者可通过在输入中注入引号 (`"`) 或换行符 (`\n`) 来转义字符串边界并添加任意 PPP 选项（例如 `connect` 选项以执行任意命令）。触发条件包括：通过 Web 界面设置 PPP 用户名或密码；当 PPP 配置被应用时，该函数被调用写入 `/etc/ppp/options.*` 文件；PPP 守护进程（可能以 root 权限运行）读取该文件并执行注入的选项。潜在利用方式包括权限提升、网络配置篡改或命令执行。约束条件：攻击者需具有设置 PPP 配置的权限（通过 Web 界面）；输入长度可能受限于字段大小，但未在代码中显式检查。
- **代码片段：**
  ```
  $user = get("s","username");
  $pass = get("s","password");
  // ...
  if ($user!="") fwrite(a,$OPTF, 'user "'.$user.'"\n');
  if ($pass!="") fwrite(a,$OPTF, 'password "'.$pass.'"\n');
  // 类似地其他输入如 $acn 和 $svc：
  $acn = get(s, "pppoe/acname");
  $svc = get(s, "pppoe/servicename");
  if ($acn!="") fwrite(a,$OPTF, 'pppoe_ac_name "'. $acn.'"\n');
  if ($svc!="") fwrite(a,$OPTF, 'pppoe_srv_name "'.$svc.'"\n');
  ```
- **关键词：** username, password, pppoe/acname, pppoe/servicename, /etc/ppp/options.*
- **备注：** 此发现基于代码中的直接证据，但可利用性取决于：1) 调用此函数的上下文（例如，是否通过 Web 界面暴露给用户）；2) PPP 守护进程是否支持危险选项（如 `connect`）；3) 文件写入权限（可能需要 root 权限）。建议进一步分析调用此函数的其他文件（如 Web 脚本）和 PPP 配置以验证完整攻击链。关联函数：`get` 和 `query` 可能从 NVRAM 或 XML 配置读取数据。

---
### PathTraversal-fwupload.cgi

- **文件/目录路径：** `htdocs/cgibin`
- **位置：** `cgibin: fcn.0001b9d0 (fwupload.cgi handler), fcn.0000d090 (file open function)`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 在 fwupload.cgi 处理程序中存在路径遍历漏洞。当 CGI 脚本被调用时，如果参数以 '/htdocs/web/info/' 开头，该参数会被直接用于 open() 系统调用，未进行路径遍历序列过滤。攻击者可以通过在参数中包含 '../' 序列来读取任意文件。触发条件：请求必须包含一个以 '/htdocs/web/info/' 开头的参数。约束条件：用户必须已认证，但无需 root 权限。潜在攻击：攻击者可以构造如 '/htdocs/web/info/../../../etc/passwd' 的路径来访问敏感文件，导致信息泄露。代码逻辑：函数 fcn.0001b9d0 检查参数前缀，然后调用 fcn.0000d090 使用 open() 打开文件。
- **代码片段：**
  ```
  // From fcn.0001b9d0:
  uVar1 = sym.imp.strstr(*(puVar4[-0xb] + 4), "/htdocs/web/info/");
  puVar4[-3] = uVar1;
  ...
  if (puVar4[-3] != 0) {
      if (*(puVar4[-0xb] + 4) != puVar4[-3]) {
          fcn.0001b988();
          goto code_r0x0001bba8;
      }
      puVar4[-1] = *(puVar4[-0xb] + 4);
  }
  ...
  if ((puVar4[-1] != 0) && (iVar2 = fcn.0000d090(puVar4[-1], *(0x36430)), iVar2 == 0)) {
      *puVar4 = 0;
  }
  
  // From fcn.0000d090:
  uVar1 = sym.imp.open(puVar3[-4], 0); // Direct use of user input in open()
  ```
- **关键词：** argv[1], open_file_path, HTTP request path parameter, /htdocs/web/info/
- **备注：** 漏洞利用需要用户认证，但非 root 权限即可。输出流（地址 0x36430）可能是 HTTP 响应，导致文件内容泄露。未发现其他缓解措施，攻击链完整可验证。

---
### XSS-get_Macfilter.asp

- **文件/目录路径：** `htdocs/mydlink/get_Macfilter.asp`
- **位置：** `get_Macfilter.asp: output in foreach loop for MAC addresses without escaping`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 在 'get_Macfilter.asp' 中，MAC 地址从 NVRAM 读取并直接输出到 XML 响应中，未进行转义或过滤。攻击者可通过 'form_macfilter' 提交恶意 MAC 地址（包含 JavaScript 代码），当受害者（如管理员）访问 MAC 过滤器页面（触发 'get_Macfilter.asp'）时，恶意脚本执行，可能导致会话窃取或权限提升。触发条件：攻击者修改 MAC 过滤器设置并注入脚本，受害者查看相关页面。利用方式：注入如 '<script>alert(1)</script>' 的 MAC 地址。
- **代码片段：**
  ```
  来自 'get_Macfilter.asp': \`echo "<addr>".query("mac")."</addr>
  ";\` 和来自 'form_macfilter': \`$mac = $_POST["mac_".$i];\` ... \`$entry_mac = get_valid_mac($mac);\` ... \`set($entry_p."/mac",toupper($entry_mac));\`
  ```
- **关键词：** /acl/macctrl/entry/mac, $_POST["mac_*"]
- **备注：** 需要受害者访问 'get_Macfilter.asp' 或相关页面；建议检查其他输出点是否类似未转义；后续可分析 'get_valid_mac' 函数的限制。

---
### info-leak-get_Wireless-displaypass

- **文件/目录路径：** `htdocs/mydlink/get_Wireless.php`
- **位置：** `get_Wireless.php:1 (输入点), get_Wireless.php:~75-77 (输出点), get_Wireless.php:~78-80 (输出点), get_Wireless.php:~81-83 (输出点)`
- **风险评分：** 6.5
- **置信度：** 9.0
- **描述：** 该漏洞允许攻击者通过设置 'displaypass=1' GET参数来强制输出无线网络的敏感信息，包括WEP密钥、WPA PSK和RADIUS秘密。触发条件简单：攻击者发送HTTP请求到该脚本（例如 'http://device/htdocs/mydlink/get_Wireless.php?displaypass=1'）。作为已登录用户（非root），攻击者可能有权访问此脚本（取决于Web服务器配置）。利用方式直接：通过查看响应内容获取密码信息，从而可能用于连接到无线网络或发起进一步攻击。代码中缺少对 'displaypass' 参数的验证或访问控制，导致无条件输出敏感数据。
- **代码片段：**
  ```
  输入点:
  <? 
  $displaypass = $_GET["displaypass"];
  
  ...
  
  输出点:
  <f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>
  <f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>
  <f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>
  ```
- **关键词：** $_GET["displaypass"], $key, $pskkey, $eapkey
- **备注：** 风险评分未达到7.0以上，因为虽然攻击链完整，但漏洞主要是信息泄露，而非直接代码执行或权限提升。置信度高，因为代码证据明确显示输入到输出的直接数据流。建议进一步验证该脚本的访问控制机制（例如是否受认证保护）和上下文（如是否在Web根目录下可访问）。关联文件可能包括其他使用类似模式的PHP脚本。后续分析应检查 'query' 和 'get' 函数的实现，以识别其他潜在漏洞。

---
### info-leak-wireless-displaypass

- **文件/目录路径：** `htdocs/mydlink/get_Wireless_5g.asp`
- **位置：** `get_Wireless.php:1 (assignment of $displaypass) and get_Wireless.php:~70-80 (output conditions)`
- **风险评分：** 6.5
- **置信度：** 9.0
- **描述：** 在 'get_Wireless.php' 中，'displaypass' GET 参数被直接用于控制敏感无线密码信息的输出，包括 WEP 密钥、PSK 密钥和 RADIUS 密钥。攻击者作为已登录用户（非 root）可以通过发送 GET 请求到 'get_Wireless_5g.asp?displaypass=1' 来触发信息泄露。触发条件包括：用户拥有有效登录凭据、授权通过（由 'header.php' 检查 $AUTHORIZED_GROUP>=0），且参数未经验证。潜在攻击方式包括获取无线网络密码，可能用于进一步网络渗透或权限提升。代码逻辑直接使用 $_GET['displaypass'] without 任何过滤或边界检查，导致可控输出。
- **代码片段：**
  ```
  $displaypass = $_GET["displaypass"];
  // ...
  <f_wep><? if ($displaypass==1){echo $key;}else{echo "";} ?></f_wep>
  <f_wps_psk><? if ($displaypass==1){echo $pskkey;} ?></f_wps_psk>
  <f_radius_secret1><? if ($displaypass==1){echo $eapkey;} ?></f_radius_secret1>
  ```
- **关键词：** displaypass, $_GET, get_Wireless_5g.asp, get_Wireless.php
- **备注：** 此漏洞依赖于用户授权，但 'header.php' 的授权机制可能不足 if $AUTHORIZED_GROUP 被误设。建议验证 $AUTHORIZED_GROUP 的来源和设置。后续可分析其他 'form_' 文件（如 'form_wireless.php'）以寻找更多输入点或交互漏洞。无法访问 '/htdocs/phplib/xnode.php' 和 '/htdocs/webinc/config.php' 限制了对完整数据流的分析。

---
### InfoLeak-SMTP-Password

- **文件/目录路径：** `htdocs/mydlink/get_Email.asp`
- **位置：** `get_Email.asp (具体行号未知，位于输出 SMTP 密码的条件语句处)`
- **风险评分：** 6.5
- **置信度：** 7.5
- **描述：** 在 'get_Email.asp' 文件中发现信息泄露漏洞，允许认证用户通过 'displaypass' GET 参数获取 SMTP 密码。具体表现：当参数设置为 1 时，脚本输出 SMTP 密码；否则不输出。触发条件：授权用户（$AUTHORIZED_GROUP >= 0）访问 URL 如 'get_Email.asp?displaypass=1'。约束条件：依赖 'header.php' 中的授权检查，但未验证 $AUTHORIZED_GROUP 的设置机制，可能存在绕过风险。潜在攻击：攻击者获取 SMTP 密码后，可能用于未授权访问 SMTP 服务器或进行钓鱼攻击，从而提升权限或泄露更多数据。代码逻辑：直接使用 $_GET['displaypass'] 控制输出，缺少额外验证。
- **代码片段：**
  ```
  <config.smtp_email_pass><?if($displaypass==1){echo $smtp_password;}?></config.smtp_email_pass>
  ```
- **关键词：** displaypass, config.smtp_email_pass
- **备注：** 授权机制依赖 $AUTHORIZED_GROUP 变量，但未在分析文件中定义，建议进一步验证其来源和设置方式（例如在 'phplib/xnode.php' 或 'webinc/config.php' 中）。SMTP 密码泄露可能影响外部服务安全。攻击链完整对于认证用户：输入点（displaypass 参数）→ 数据处理（条件输出）→ 危险操作（密码泄露）。但由于工具限制，未验证其他文件，可能存在未知依赖。

---
### Command-Injection-classlessstaticroute

- **文件/目录路径：** `etc/services/INET/inet4_dhcpc_helper.php`
- **位置：** `inet4_dhcpc_helper.php: 在 'classlessstaticroute' 和 'staticroute' 动作的代码块中`
- **风险评分：** 6.5
- **置信度：** 6.5
- **描述：** 在 'classlessstaticroute' 和 'staticroute' 动作中，变量 $SDEST、$SSUBNET、$SROUTER 被直接拼接进 ip route 命令，缺乏输入验证。攻击者可通过控制这些变量注入命令，修改路由表或执行任意操作。触发条件当 $ACTION 为 'classlessstaticroute' 或 'staticroute' 时。利用方式类似，通过恶意输入导致命令注入。
- **代码片段：**
  ```
  echo "ip route add ".$netid."/".$SSUBNET." via ".$SROUTER." table CLSSTATICROUTE\n";
  ```
- **关键词：** $ACTION, $SDEST, $SSUBNET, $SROUTER
- **备注：** 变量可能来自 DHCP 选项，但攻击者可能伪造。需要确认输入源和权限。建议检查网络配置接口。

---
### Event-Injection-ppp6_ipup-param

- **文件/目录路径：** `etc/services/INET/ppp6_ipup.php`
- **位置：** `ppp6_ipup.php:多处，例如 echo "event ".$PARAM.".UP
"; 和 echo "echo 1 > /var/run/".$PARAM.".UP
";`
- **风险评分：** 6.0
- **置信度：** 7.0
- **描述：** $PARAM 变量被直接用于构建事件名（如 event $PARAM.UP）和文件路径（如 /var/run/$PARAM.UP），缺乏验证。攻击者控制 $PARAM 可能导致事件系统混乱或路径遍历（如果 $PARAM 包含 '../'）。触发条件类似发现 1。潜在利用包括干扰其他进程或文件操作。
- **代码片段：**
  ```
  echo "event ".$PARAM.".UP
  "; echo "echo 1 > /var/run/".$PARAM.".UP
  ";
  ```
- **关键词：** 环境变量 $PARAM, IPC 事件 $PARAM.UP, 文件路径 /var/run/$PARAM.UP, 自定义函数 XNODE_set_var
- **备注：** 需要验证事件系统的处理；建议检查 xmldbc 命令的输入处理。

---
### 命令注入-ppp4_ipdown.php

- **文件/目录路径：** `etc/services/INET/ppp4_ipdown.php`
- **位置：** `ppp4_ipdown.php:36, ppp4_ipdown.php:38, ppp4_ipdown.php:39, ppp4_ipdown.php:40`
- **风险评分：** 6.0
- **置信度：** 6.5
- **描述：** 命令注入漏洞由于未验证用户输入直接拼接到 shell 命令中。问题具体表现：当 PPP 连接关闭时，脚本使用变量 $REMOTE、$IFNAME、$IP 和 $PARAM 构建 shell 命令（如 ip route、event、rm），如果这些变量包含 shell 元字符（如 ;、`、$()），攻击者可以注入并执行任意命令。触发条件：脚本在 PPP 连接关闭时被调用，且变量值来自外部输入。约束条件：代码中缺少输入验证、过滤或转义机制。潜在攻击：攻击者通过控制这些变量注入命令，可能导致权限提升、文件删除或系统控制。相关代码逻辑：使用 echo 输出命令，可能通过 shell 执行。
- **代码片段：**
  ```
  36: echo 'ip route del '.$REMOTE.' dev '.$IFNAME.' src '.$IP.' table LOCAL\n';
  38: echo "ip route flush table ".$PARAM."\n";
  39: echo "event ".$PARAM.".DOWN\n";
  40: echo "rm -f /var/run/".$PARAM.".UP\n";
  ```
- **关键词：** $REMOTE, $IFNAME, $IP, $PARAM, ppp4_ipdown.php
- **备注：** 输入来源未验证（可能通过环境变量或 PPP 事件传递），建议进一步分析脚本调用上下文和变量设置机制（如检查 pppd 或其他守护进程的配置）。关联文件可能包括 PPP 相关脚本或配置文件。后续分析方向：追踪变量来源和调用链，以验证完整攻击链的可利用性。攻击者是非root用户但拥有有效登录凭据，需确认变量是否可通过用户控制输入影响。

---
### Command-Injection-dhcpplus

- **文件/目录路径：** `etc/services/INET/inet4_dhcpc_helper.php`
- **位置：** `inet4_dhcpc_helper.php: 在 'dhcpplus' 动作的代码块中`
- **风险评分：** 6.0
- **置信度：** 6.0
- **描述：** 在 'dhcpplus' 动作中，变量 $IP、$SUBNET、$BROADCAST、$INTERFACE、$ROUTER 被用于构建 ip addr 和 ip route 命令，缺乏过滤。攻击者可注入命令导致网络配置篡改或命令执行。触发条件当 $ACTION 为 'dhcpplus' 时。
- **代码片段：**
  ```
  echo "ip addr add ".$IP."/".$mask." broadcast ".$brd." dev ".$INTERFACE."\n";\necho "ip route add default via ".$ROUTER." metric ".$defrt." table default\n";
  ```
- **关键词：** $ACTION, $IP, $SUBNET, $BROADCAST, $INTERFACE, $ROUTER
- **备注：** 输入可能受限于 DHCP，但如果用户可控制 ACTION，风险增加。建议验证脚本调用机制。

---
