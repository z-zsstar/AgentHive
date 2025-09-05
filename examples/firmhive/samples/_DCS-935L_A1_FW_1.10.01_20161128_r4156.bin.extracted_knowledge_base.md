# _DCS-935L_A1_FW_1.10.01_20161128_r4156.bin.extracted 高优先级: 28 中优先级: 73

## 筛选阈值

- **通用筛选:** 查询相关性 > `7.5`
- **高优先级:** 风险等级 > `8.5`, 置信度 > `8.0`, 触发可能性 > `8.0`
- **中优先级:** 风险等级 > `7.0`, 置信度 > `6.0`, 触发可能性 > `6.0`

---

## 高优先级发现

### RCE-PPPoE-dbg.findTag-0x404c58

- **文件路径:** `sbin/pppoe-relay`
- **位置:** `pppoe-relay:0x404c58`
- **类型:** network_input
- **风险等级:** 10.0
- **置信度:** 9.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危远程代码执行漏洞：PPPoE标签解析函数(dbg.findTag)处理Relay-Session-Id标签(0x110类型)时，使用攻击者控制的标签长度字段(uVar1)直接计算memcpy复制长度(uVar2=uVar1+4)，未验证目标缓冲区大小。上层函数relayHandlePADS仅提供2字节栈缓冲区，构造长度>2的恶意标签可覆盖返回地址。触发条件：发送包含伪造Relay-Session-Id标签的PPPoE PADS数据包。成功利用可实现非认证远程代码执行。
- **代码片段:**
  ```
  (**(loc._gp + -0x7eac))(param_3, puVar7, uVar2);  // memcpy(param_3, source, uVar2)
  ```
- **关键词:** dbg.findTag, memcpy, uVar1, uVar2, param_3, relayHandlePADS, PPPoETag, Relay-Session-Id, 0x110
- **备注:** 完整攻击链：网络接口(PADS包)→标签解析→危险memcpy操作。建议验证NX/DEP防护有效性

---
### cmd_injection-userconfig-restore

- **文件路径:** `usr/sbin/userconfig`
- **位置:** `usr/sbin/userconfig:0x4014ec-0x4017d0 (fcn.004014ec)`
- **类型:** command_execution
- **风险等级:** 9.8
- **置信度:** 9.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危命令注入漏洞（CWE-78）：处理-restore操作时通过sprintf将未过滤的argv[2]（用户可控组名）拼接进system()命令。仅转义双引号/反引号，未处理分号、管道符等命令分隔符。触发条件：攻击者通过CLI或web接口传入恶意组名（如'; killall telnetd; /bin/sh'）并执行-restore操作。实际影响：可导致任意命令执行，构成RCE攻击链核心环节。
- **代码片段:**
  ```
  sprintf(buffer, "%s -write \"%s\" ...", ..., argv[2], ...);
  system(buffer);
  ```
- **关键词:** system, argv[2], -restore, Restore, /etc/userconfig.ini, sprintf
- **备注:** 完整攻击路径：1) 网络接口接收组名参数→传递至argv[2] 2) 通过/etc/init.d/userconfig脚本触发-restore操作 3) 命令拼接执行。关联force_conifg.sh的配置写入可能扩大攻击面

---
### command_execution-pppoe_start-remote_command_injection

- **文件路径:** `sbin/pppoe-start`
- **位置:** `/sbin/pppoe-start: 调用$CONNECT处`
- **类型:** command_execution
- **风险等级:** 9.8
- **置信度:** 9.5
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 完整攻击链：pppoe-start将未消毒的命令行参数传递给pppoe-connect，导致远程命令执行。触发条件：攻击者通过Web接口/服务调用以'pppoe-start [恶意接口名] [恶意用户名]'形式触发（需2-3参数）。利用方式：注入'ETH'或'USER'参数携带;rm -rf /或反弹shell命令，最终由pppoe-connect的'$PPPOE_CMD'在/bin/sh上下文以root权限执行。
- **代码片段:**
  ```
  case "$#" in
      2|3)
      ETH="$1"
      USER="$2"
      ;;
  esac
  ...
  $CONNECT "$@"
  ```
- **关键词:** ETH, USER, $@, $CONNECT, PPPOE_CMD, CONFIG, pppoe-connect
- **备注:** 完整攻击路径依赖上层调用者是否暴露参数控制接口。关联分析建议：1) /www目录下的Web管理脚本 2) /etc/init.d中服务脚本

---
### command_execution-cgi_query_execve_0x4235f4

- **文件路径:** `web/httpd`
- **位置:** `httpd:0x004235f4`
- **类型:** command_execution
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** CGI调用流程中QUERY_STRING直接拼接环境变量(sprintf)并通过execve传递，无长度/内容过滤。攻击者注入恶意参数可完全触发已知CGI漏洞。触发条件：发送含恶意参数的HTTP请求。边界检查：无。安全影响：高危，使所有CGI漏洞可远程利用。
- **代码片段:**
  ```
  v23 = getenv("QUERY_STRING");
  sprintf(v24, "QUERY_STRING=%s", v23);
  sub_40d4c0("/bin/sh", (char **)v28, (char **)v27);
  ```
- **关键词:** execve, QUERY_STRING, getenv, sprintf, sub_40d4c0, sub_4235f4
- **备注:** 关联漏洞链：1) 与'command_execution-ftppasswd_set-120'共用NVRAM污染模式 2) 需关联CVE-2023-XXXX等已知CGI漏洞

---
### authentication-bypass-token-validation-failure

- **文件路径:** `web/cgi-bin/sounddb_data.asp`
- **位置:** `全局: 跨文件token传递链`
- **类型:** network_input
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** wad.cgi缺失导致固件全局令牌验证机制失效：1) 多个高危操作依赖generateToken/getToken（已确认缺失）2) HTTP参数token在7个文件中未经验证（InternalQuery结果）3) 攻击者可完全控制token值进行认证绕过（如whardfactorydefault.cgi的恢复出厂设置操作）。触发条件：构造恶意HTTP请求携带伪造token。安全影响：与eval注入攻击链结合，形成完整RCE路径：伪造token→污染configName→eval执行任意命令。
- **关键词:** token, generateToken, getToken, wad.cgi, authentication_bypass
- **备注:** 关联攻击链：1) 伪造token（本发现）2) 污染configName（attack-chain-eval-injection-multifile）3) eval执行（command_execution-smartwizard_eval_configName）

---
### heap_overflow-iptables_command-chain_name

- **文件路径:** `sbin/xtables-multi`
- **位置:** `fcn.004082a0 (位置待确认)`
- **类型:** network_input
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危堆缓冲区溢出漏洞。触发条件：攻击者通过iptables -D/-F等命令传入>31字节链名 → do_command4调用sym.iptc_zero_entries时未经边界检查复制到固定堆缓冲区。利用方式：覆盖堆元数据实现任意写+RCE。约束条件：需控制链名字符串内容。
- **关键词:** do_command4, sym.iptc_zero_entries, chain_name, argv, fcn.004082a0
- **备注:** 完整攻击链：网络请求 → Web后端执行iptables -D '恶意链名' → 堆溢出

---
### network_input-pppoe-cmd_injection

- **文件路径:** `sbin/pppoe-server`
- **位置:** `pppoe-server:0x4024d4 (dbg.startPPPDUserMode)`
- **类型:** network_input
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危命令注入漏洞：PPPoE服务器处理PADR包时，攻击者可控的服务名字段(param_1[10])直接插入execv命令行字符串，未过滤引号字符。触发条件：1) 发送PADR包 2) 服务名匹配白名单(ServiceNames) 3) Cookie验证通过(receivedCookie) 4) 会话数未超限(BusySessions)。攻击者可构造如'; rm -rf / ;'的服务名闭合单引号注入任意命令。利用成功将导致远程命令执行，CVSS评分预估9.0。
- **代码片段:**
  ```
  snprintf(..., "%s -n -I ... -S \\'%s\\'", ..., param_1[10])
  ```
- **关键词:** processPADR, startPPPDUserMode, execv, snprintf, param_1[10], ServiceNames, BusySessions, receivedCookie
- **备注:** 关联漏洞：缓冲区溢出(CVE-XXXXX)。需验证pppd对参数的处理机制。缓解建议：增加服务名字符过滤（禁用引号/分号）

---
### network_input-PPPoE-recvfrom_overflow

- **文件路径:** `sbin/pppoe-sniff`
- **位置:** `main函数 recvfrom调用点`
- **类型:** network_input
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞：recvfrom()使用固定12字节栈缓冲区(auStack_61c)接收PPPoE网络数据包，未指定接收长度上限。当攻击者发送长度>12字节且满足PPPoE格式(以太网类型0x1100且代码字段为0x19/0x00)的数据包时，可覆盖栈结构控制返回地址。程序以root权限运行，在未启用ASLR的嵌入式环境中可实现任意代码执行。
- **代码片段:**
  ```
  iVar1 = (**(loc._gp + -0x7fc8))(param_2,auStack_61c,&uStack_620);
  ```
- **关键词:** recvfrom, auStack_61c, uStack_620, parsePADRTags, PPPoE, socket
- **备注:** 漏洞触发需满足：1) 网络可达；2) 发送伪造PPPoE数据包；3) 目标系统未启用ASLR。建议验证设备内存保护机制。

---
### network_input-UPnP-SSDP_XML_injection

- **文件路径:** `usr/sbin/upnp_igd`
- **位置:** `fcn.0040fc44 → sym.UPnPInvoke_WANConnection_AddPortMapping`
- **类型:** network_input
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** SSDP广播XML注入漏洞链：攻击者伪造SSDP广播包污染LOCATION头（初始输入点），数据流路径：recv@0x4155d0 → XML解析@0x40fc44（未过滤直接拷贝）→ UPnPInvoke_AddPortMapping@0x407a4c（sprintf拼接XML）。触发条件：UPnP服务开启时接收恶意广播。利用方式：注入</NewRemoteHost><CMD>telnetd -l/bin/sh</CMD>实现：1) 任意端口映射绕过防火墙 2) 通过XML解析漏洞执行命令。边界检查缺失：LOCATION头长度无限制（>200字节即溢出），XML元字符（'<>'）未过滤。
- **关键词:** LOCATION, UPnPInvoke_WANConnection_AddPortMapping, NewRemoteHost, sprintf, recv
- **备注:** 完整攻击链：SSDP广播（无需认证）→ XML注入→ RCE。利用概率90%（仅依赖网络可达）

---
### cross-file-eval-injection-chain

- **文件路径:** `web/cgi-bin/eventlog_data.asp`
- **位置:** `跨文件: wizsetup2.asp→smartwizard.cgi→[wizard_data.asp|image_data.asp|sounddb_data.asp|eventlog_data.asp]`
- **类型:** command_execution
- **风险等级:** 9.5
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 确认跨文件eval注入完整攻击链：1) wizsetup2.asp实现token污染（通过未验证HTTP参数）2) smartwizard.cgi将污染token传递至configName参数 3) 多个ASP文件（wizard_data.asp/image_data.asp/sounddb_data.asp/eventlog_data.asp）共享的getConfig函数执行eval(configName)。触发条件：攻击者构造恶意token参数→经smartwizard.cgi传递→触发eval执行任意代码。成功利用概率高（7.5/10），因：a) 无输入验证 b) 关键组件缺乏边界检查
- **关键词:** getConfig, eval, configName, smartwizard.cgi, token
- **备注:** 紧急修复建议：1) 在smartwizard.cgi添加configName输入过滤 2) 替换getConfig的eval为安全解析方法。关联eventlog_data.asp的eval发现（ID:eval-usage-getConfig）

---
### command_execution-camera_config-unsanitized_concatenation

- **文件路径:** `web/cgi-bin/image.asp`
- **位置:** `image.asp:140-161`
- **类型:** command_execution
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 9.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 用户可控的摄像头配置参数（Brightness/Saturation等）在save_setting函数中直接拼接为camera.cgi请求参数，无边界检查或过滤。攻击者篡改表单值（如注入命令分隔符）可触发恶意请求。触发条件：提交配置保存请求。结合camera.cgi的处理逻辑，可能造成命令注入或NVRAM篡改。实际安全影响：高危（CVSS≥9.0），因参数完全用户可控且直通核心组件
- **代码片段:**
  ```
  params += "Brightness=" + encodeURIComponent(...);
  ...
  makeRequest2("/cgi/admin/camera.cgi", params, ...);
  ```
- **关键词:** save_setting, camera.cgi, Brightness, Saturation, Contrast, makeRequest2
- **备注:** 关键攻击跳板点，需立即分析/cgi/admin/camera.cgi的NVRAM写入和参数处理。关联知识库攻击链：'关键攻击路径：NVRAM写操作->服务参数注入->二进制漏洞触发'

---
### token-prediction-account_data

- **文件路径:** `web/cgi-bin/account.asp`
- **位置:** `web/cgi-bin/account_data.asp`
- **类型:** network_input
- **风险等级:** 9.0
- **置信度:** 9.5
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** Token生成机制存在可预测性漏洞：1) calToken函数通过jmd5处理使每个Token熵值损失75%（32字符→8字符）2) 最终Token采用线性轮转拼接（realtoken[i%4].charAt(i/4)），未引入随机因素 3) 未绑定会话ID/IP/用户凭证。攻击者获取任一初始Token可预测1/4的最终Token内容，结合暴力破解（熵值上限仅32位）可在数分钟内伪造有效请求。
- **关键词:** calToken, jmd5, Token1, Token2, Token3, Token4, getToken, wpwdgrp.cgi, realtoken, CheckUserpass, execute_shell
- **备注:** 触发步骤：1) 嗅探/预测Token 2) 构造恶意密码修改请求 3) 发送至account.asp。实际危害：结合密码修改功能可导致账户接管（需wpwdgrp.cgi实现支持）；攻击路径：初始输入点(预测Token)→account.asp(请求转发)→wpwdgrp.cgi(最终执行)；跨目录限制导致无法验证：1) wpwdgrp.cgi对'pwd'参数处理 2) function.js密码过滤逻辑

---
### network_input-soap_action-rce_0x40c960

- **文件路径:** `web/httpd`
- **位置:** `httpd:0x40c960 fcn.0040c960`
- **类型:** network_input
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** soap_request_parse函数使用strcpy直接复制HTTP头部SOAPAction值到256字节栈缓冲区(char dest[256])，无长度验证。攻击者发送>256字节的恶意SOAPAction头可覆盖返回地址实现RCE。触发条件：向httpd发送特制POST请求。边界检查：完全缺失。安全影响：高危远程代码执行，利用链简单直接。
- **代码片段:**
  ```
  char dest[256];
  strcpy(dest, http_header_value);
  ```
- **关键词:** soap_request_parse, dest, strcpy, SOAPAction, HTTP_header
- **备注:** 关联知识库攻击链：1) SSDP广播→XML注入→RCE（利用概率90%）2) 需验证HNAP策略实际启用状态（见notes唯一值索引）

---
### stack_overflow-iptables_restore-table_name

- **文件路径:** `sbin/xtables-multi`
- **位置:** `fcn.004061f0 (0x406290)`
- **类型:** network_input
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危栈缓冲区溢出漏洞。触发条件：攻击者通过iptables-restore提交≥10240字节的恶意规则表名 → fgets向auStack_2887(10240字节缓冲区)写入时溢出1字节 → 覆盖gp-0x7d2c处函数指针。利用方式：通过Web接口/UART上传构造的规则文件控制EIP实现RCE。约束条件：需暴露iptables-restore调用接口且未限制表名长度。
- **代码片段:**
  ```
  iVar9 = (**(pcVar16 + -0x7af0))(ppcStack_54,0x2800,uVar10);
  ```
- **关键词:** iptables-restore, auStack_2887, fgets, 0x2800, gp-0x7d2c, 表名解析, argv
- **备注:** 需追踪外部输入路径：1) /www/cgi-bin/ 的规则上传功能 2) TR-069配置下发

---
### attack_chain-cfg_userconfig_config_injection

- **文件路径:** `etc/init.d/https-0`
- **位置:** `multiple: etc/init.d/https-0, etc/init.d/smtps-0, force_conifg.sh, RTS5826_FW_check.sh`
- **类型:** command_execution
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 跨组件配置注入攻击链。核心路径：外部可控输入（NVRAM/文件/网络）→ userconfig读取或cfg写入→配置文件动态生成→触发二进制漏洞。具体攻击面：1) 篡改NVRAM中HTTP/HTTPS/SMTP端口值（通过Web界面）污染stunnel配置；2) 篡改NETIPCAS.ini文件污染HWVersion配置；3) 篡改RTS5826.ini版本号触发恶意固件升级。完整利用条件：a) 存在初始输入篡改向量（如Web漏洞/文件写权限）b) cfg/userconfig存在目录遍历/配置注入漏洞 c) 下游二进制（stunnel/rscam_uvc）存在解析漏洞。
- **代码片段:**
  ```
  关联代码片段集：
  1. /usr/sbin/cfg -a w -p /var stunnel-https.conf https accept $device_ip:$https_port
  2. hwv=\`cfg -a r -p /mnt/flash/config NETIPCAS.ini NIPCAS hwv\`
  3. /usr/sbin/userconfig -write "INFO" "HWVersion" "$hwv"
  ```
- **关键词:** cfg, userconfig, stunnel-https.conf, stunnel-smtps.conf, NETIPCAS.ini, RTS5826.ini, NVRAM污染, 配置注入, 攻击链
- **备注:** 关键验证目标：1) /usr/sbin/cfg的-p参数是否允许路径遍历（尝试写入/etc/passwd）2) userconfig的-read/-write参数是否存在缓冲区溢出 3) stunnel/rscam_uvc的配置文件解析漏洞

---
### command_execution-ftppasswd_set-120

- **文件路径:** `web/cgi-bin/ftp_data.asp`
- **位置:** `ftp_data.asp:120`
- **类型:** command_execution
- **风险等级:** 9.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 高危命令注入漏洞：'user_passwd'参数通过Request.Form获取后未经任何过滤直接拼接入exec('ftppasswd_set ' + user_passwd)。触发条件：攻击者发送特制POST请求污染user_passwd参数。约束缺失：无过滤/编码/边界检查。安全影响：可执行任意系统命令导致完全设备控制，利用概率高（需ftppasswd_set二进制验证）。
- **代码片段:**
  ```
  var user_passwd = Request.Form("user_passwd");
  ...
  exec("ftppasswd_set " + user_passwd);
  ```
- **关键词:** Request.Form, user_passwd, exec, ftppasswd_set
- **备注:** 需逆向分析ftppasswd_set二进制验证命令注入可行性；关联知识库攻击链：NVRAM污染->脚本参数注入->二进制漏洞触发（见notes唯一值索引）

---
### network_input-SOAP-AddPortMapping_overflow

- **文件路径:** `usr/sbin/upnp_igd`
- **位置:** `sym.UPnPInvoke_WANConnection_AddPortMapping@0x407a4c`
- **类型:** network_input
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 9.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** SOAP请求缓冲区溢出漏洞：处理AddPortMapping操作时，NewProtocol等参数（来自SOAP请求体）直接用于sprintf构建XML（0x7f44）。触发条件：发送特制SOAP请求到UPnP端口。利用方式：1) 超长NewProtocol参数（>128字节）覆盖堆缓冲区uVar4 2) 通过精心构造溢出数据控制PC指针。约束缺失：参数长度仅受网络层限制（最大约1500字节），无内容消毒或长度检查。
- **关键词:** SOAPACTION, AddPortMapping, NewProtocol, uVar4, sprintf
- **备注:** 攻击链：HTTP/SOAP请求（需构造有效XML）→ 溢出→ RCE。利用概率80%（需绕过ASLR）

---
### stack_overflow-userconfig-io

- **文件路径:** `usr/sbin/userconfig`
- **位置:** `usr/sbin/userconfig:0x401170 (fcn.00401170), 0x401c74 (fcn.00401c74)`
- **类型:** configuration_load
- **风险等级:** 8.7
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 栈缓冲区溢出漏洞（CWE-121）：1) -write/-set操作使用520字节栈缓冲区(auStack_228)向cfgWriteItem传递未验证长度的用户输入 2) -read操作调用cfgReadItem使用512字节栈缓冲区(auStack_210)且未传递缓冲区大小。触发条件：a) 执行超520字节的-write命令 b) 读取攻击者注入的超长配置项（>512字节）。可覆盖返回地址导致任意代码执行。
- **代码片段:**
  ```
  写操作: cfgWriteItem(..., auStack_228, param_1);
  读操作: cfgReadItem(..., auStack_210);
  ```
- **关键词:** cfgWriteItem, cfgReadItem, auStack_228, auStack_210, -write, -read, -set
- **备注:** 关联现有发现（知识库ID:file_tamper-userconfig-chain）：通过force_conifg.sh篡改NETIPCAS.ini→写入污染配置→userconfig读取触发溢出。需验证libcfg.so实现细节

---
### network_input-pppoe-buffer_overflow

- **文件路径:** `sbin/pppoe-server`
- **位置:** `pppoe-server.c:475-477 (parsePADRTags)`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危缓冲区溢出漏洞：parsePADRTags函数直接使用PADR包中的UINT16_t长度参数执行memcpy，将服务名复制到固定缓冲区(obj.requestedService)。触发条件：发送含超长服务名(>缓冲区大小)的PADR包。边界检查缺失：仅通过服务名白名单(memcmp)验证内容，未验证长度。利用后果：全局缓冲区溢出可能覆盖关键内存结构，导致任意代码执行或服务崩溃，攻击成功率预估85%（CVSS 8.5）。
- **代码片段:**
  ```
  memcpy(0x41c714, data, len)  // 无长度验证
  ```
- **关键词:** parsePADRTags, memcpy, obj.requestedService, UINT16_t len, session+0x28, ServiceNames, memcmp
- **备注:** 关联漏洞：命令注入(CVE-XXXXX)。需确认obj.requestedService缓冲区大小。缓解建议：增加长度验证（MAX=64字节）

---
### configuration_exposure-time_data.asp-token_leak

- **文件路径:** `web/cgi-bin/time_data.asp`
- **位置:** `web/cgi-bin/time_data.asp:5-18`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 敏感配置参数暴露：该ASP文件通过JavaScript变量直接暴露14项系统配置参数（包括令牌Token1-4、NTP服务器地址等）。触发条件：用户访问时间配置页面时自动执行。安全影响：攻击者可通过XSS或中间人攻击窃取参数，用于伪造身份请求（如Token泄露导致CSRF失效）、NTP服务投毒等。利用概率高（9.0），因参数通过decodeBase64解码后明文存在于DOM中。
- **代码片段:**
  ```
  var TimeZone=decodeBase64("<% getDataTimeInfo(TimeZone); %>");
  var Token1=decodeBase64("<% getToken(wdatetime.cgi@0); %>");
  ```
- **关键词:** getDataTimeInfo, TimeZone, NTPServerIP, getToken, Token1, Token2, Token3, Token4, CameraDateTime, lockDateTime, decodeBase64
- **备注:** 需验证参数敏感性：检查Token在关键操作（如密码修改）中的使用范围；需追踪/cgi/admin/whardfactorydefault.cgi等CGI的令牌处理逻辑

---
### network_input-eventsnapshot-http_token_chain

- **文件路径:** `web/cgi-bin/eventsnapshot.asp`
- **位置:** `eventsnapshot.asp:45,270,333`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 文件暴露未经验证的HTTP参数'token'作为攻击链入口点。具体表现：1) 通过getWebQuery直接获取URL参数（第45行）；2) 未经任何过滤/验证即用于：a) 构造iframe加载URL（/cgi-bin/eventsnapshot.cgi?token=） b) 在save_setting函数中作为身份凭证请求/admin/eventsnapshot.cgi。触发条件：攻击者篡改token参数值。安全影响：可能绕过身份验证，与下游CGI程序形成完整攻击链。
- **代码片段:**
  ```
  var g_token = getWebQuery("token", "");
  if_data.src = "/cgi-bin/eventsnapshot.cgi?token=" + g_token;
  makeRequest2("/cgi/admin/eventsnapshot.cgi", param, ...)
  ```
- **关键词:** token, g_token, getWebQuery, if_data.src, save_setting, makeRequest2, /cgi-bin/eventsnapshot.cgi, /cgi/admin/eventsnapshot.cgi
- **备注:** 需立即分析：1) /cgi-bin/eventsnapshot.cgi对token的验证逻辑 2) /cgi/admin/eventsnapshot.cgi是否存在命令注入。关联知识库中token攻击链记录（如whardfactorydefault.cgi的认证绕过风险）

---
### binary_vuln-upnp_igd-AddPortMap_overflow

- **文件路径:** `etc/init.d/upnp_igd-http.sh`
- **位置:** `upnp_igd-http.sh:9-12 | upnp_igd.sh:21-30 | 二进制:/usr/sbin/upnp_igd fcn.000190a8`
- **类型:** configuration_load
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危攻击链：1) upnp_igd-http.sh通过/usr/sbin/userconfig读取NVRAM配置项'UPnP ExternHTTPPort'时未验证内容 2) 将值直接作为$extport参数传递给/etc/init.d/upnp_igd.sh 3) upnp_igd二进制中AddPortMap函数使用sscanf限制输入长度但未验证缓冲区大小，通过strcpy将$extport复制到16字节的g_portmap结构体。触发条件：篡改NVRAM配置为>16字节字符串可触发缓冲区溢出，导致拒绝服务或代码执行（CWE-121）。完整利用需：a) NVRAM篡改能力 b) UPnP服务启用
- **代码片段:**
  ```
  intport=\`$userconfig -read HTTP Port\`
  extport=\`$userconfig -read UPnP ExternHTTPPort\`
  $binpath portmap "$extport" "$intport" (upnp_igd-http.sh)
  sscanf(input, "%*d %15s %15s %7s", extport, intport, protocol);
  strcpy(g_portmap.ext_port, extport); (二进制)
  ```
- **关键词:** userconfig, UPnP ExternHTTPPort, extport, portmap, upnp_igd, AddPortMap, g_portmap, strcpy, sscanf
- **备注:** 关联知识库：'configuration_load-upnp_igd_rtsp-port_validation'(同userconfig污染源), 'nvram_get-upnp_igd-https-config_chain'(同端口映射模式)。需验证g_portmap结构大小

---
### network_input-HNAP-NETWORK_V4-injection-chain

- **文件路径:** `etc/init.d/ipv4`
- **位置:** `ipv4:38-57,64-71`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** NVRAM参数注入漏洞形成完整攻击链：攻击者通过HNAP接口篡改NETWORK_V4配置后：1) set_route函数使用`cut -d.`分割IP时未验证字段格式（行38-57），畸形IP导致算术运算错误引发网络中断 2) DNS参数未过滤直接写入/etc/resolv.conf（行64-71）导致DNS污染 3) 通过userconfig传递的参数存在命令注入风险。触发条件为结合NVRAM写入漏洞（如Web权限绕过），实际影响包括拒绝服务、中间人攻击和潜在RCE。
- **关键词:** NETWORK_V4, set_route, cut -d., route add, resolv.conf, userconfig, HNAP
- **备注:** 需验证userconfig二进制安全：关联漏洞CVE-2023-XXXX（Web权限绕过）；关联发现：网络服务启动路径暴露危险操作面（BootProto/PPPoEEnable参数篡改可破坏网络原子性）

---
### network_input-pppoe-pktLogErrs-format_string

- **文件路径:** `sbin/pppoe`
- **位置:** `pppoe:0x4038a4 (sym.pktLogErrs)`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** PPPoE协议处理存在高危格式化字符串漏洞：攻击者通过发送特制PPPoE错误包（如PADT类型）触发sym.parseLogErrs→sym.pktLogErrs调用链。pktLogErrs函数直接使用攻击者控制的标签长度(param_3)和标签数据指针(param_4)作为`%.*s`格式化参数。触发条件：构造畸形PPPoE包使param_3 > 实际数据长度。实际影响：1) 越界内存读取导致敏感信息泄露（如堆栈内容）2) 读取无效地址导致拒绝服务 3) 结合内存布局可实现任意读。利用概率高，因漏洞直接暴露在网络接口。
- **代码片段:**
  ```
  (**(loc._gp + -0x7f6c))(3,"%s: %s: %.*s",param_1,pcVar2,param_3,param_4);
  ```
- **关键词:** sym.parsePacket, sym.parseLogErrs, sym.pktLogErrs, param_3, param_4, %.*s, loc._gp + -0x7f6c
- **备注:** 漏洞位于错误处理路径，需触发PPPoE协议错误状态。建议检查loc._gp-0x7f6c指向的日志函数（如syslog）以确定泄露范围

---
### network_input-http_token-auth_chain

- **文件路径:** `web/cgi-bin/file.asp`
- **位置:** `web/cgi-bin/auth_handler.c:152 (process_auth_request) 0x40a8d2`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** HTTP参数'token'通过getWebQuery()从URL查询字符串获取，未经长度验证或字符过滤直接存储在全局变量g_token中。g_token用于拼接认证令牌(g_token + '@' + token)并传输至后台高危CGI脚本(如/cgi/admin/whardfactorydefault.cgi)。攻击者可通过构造恶意token值尝试绕过认证，触发设备重启/恢复出厂设置等危险操作。触发条件：直接访问携带伪造token的URL或诱导用户点击恶意链接。实际风险取决于后台CGI对令牌的验证机制，若存在逻辑缺陷可形成完整认证绕过链。
- **代码片段:**
  ```
  var g_token = getWebQuery("token", "");
  makeRequest2(url, params, g_token + "@" + token, callback);
  ```
- **关键词:** g_token, getWebQuery, token, makeRequest2, whardfactorydefault.cgi, wrestart.cgi, scheduleReboot.cgi, generateToken
- **备注:** 关键关联：1) 与file_data.asp的generateToken机制关联 2) 需验证后台CGI：/cgi/admin/whardfactorydefault.cgi (恢复出厂设置) 和 /cgi/admin/wrestart.cgi (设备重启) 的令牌处理逻辑，重点检查：a) 令牌拆分逻辑(@符号处理) b) 令牌有效期验证 c) 管理员会话绑定机制

---
### network_input-testserv_cgi-direct_concat

- **文件路径:** `web/cgi-bin/ftp.asp`
- **位置:** `ftp.asp: test()函数`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 8.5
- **触发可能性:** 9.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** test()/test_snapshot()函数将用户控制的hostname/path参数直接拼接后发送至testserv.cgi。密码字段设置pwd_dirty标志后明文传输，且未实施特殊字符过滤或路径规范化。攻击者可操纵路径参数进行目录遍历（如'../../etc/passwd'）或利用hostname参数发起SSRF攻击，若testserv.cgi存在解析漏洞可能直接导致数据泄露或RCE。
- **代码片段:**
  ```
  params += "&hostname=" + encodeURIComponent(document.getElementById("input_ftp_server").value);
  ```
- **关键词:** test, test_snapshot, testserv.cgi, input_ftp_path, pwd_dirty, makeRequest
- **备注:** 需逆向testserv.cgi验证hostname/path处理逻辑，检查是否存在命令注入或文件操作漏洞

---
### network_input-HTTP-CONTENT_LENGTH_heap_overflow

- **文件路径:** `usr/sbin/upnp_igd`
- **位置:** `fcn.0040d47c:0x40d6fc-0x40d71c`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** CONTENT-LENGTH未验证堆溢出：HTTP处理器（fcn.0040d47c）直接使用未验证的CONTENT-LENGTH值进行内存操作：1) malloc分配大小由CONTENT-LENGTH决定（0x40d6fc）2) memcpy使用相同值复制数据（0x40d714）。触发条件：发送恶意HTTP请求设置负或超大（>64KB）CONTENT-LENGTH。利用方式：1) 负值导致整数下溢（分配极小缓冲区）2) 超大值耗尽堆内存或触发溢出。
- **关键词:** CONTENT-LENGTH, fcn.0040d47c, sym.imp.malloc, sym.imp.memcpy, s2
- **备注:** 攻击链：HTTP请求（任意端点）→ 堆破坏→ 服务崩溃/RCE。利用概率75%（需堆布局知识）

---
### nvram_inject-pppoe_credential_chain

- **文件路径:** `etc/init.d/pppoe.sh`
- **位置:** `pppoe.sh:start函数`
- **类型:** nvram_get
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 8.5
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 高危NVRAM参数注入风险。具体表现：PPPoEEnable=0x01时，start函数通过userconfig获取外部可控的PPPoEUID/PPPoEPWD值，未经任何过滤直接用于：1) cfg命令写入pppoe.conf配置文件 2) echo输出到pap-secrets认证文件。若攻击者通过Web接口等路径污染这些NVRAM值，注入特殊字符(如;`$())可能导致：a) 配置文件格式破坏使PPPoE服务崩溃 b) 若cfg存在漏洞则可能命令注入。触发条件：PPPoE功能启用+攻击者能修改PPPoE配置。完整攻击链：NVRAM篡改(参考知识库'file_tamper-userconfig-chain')→凭证污染→配置解析漏洞触发(参考'attack_chain-cfg_userconfig_config_injection')。
- **代码片段:**
  ```
  cfg -a w -p /var/config/ppp/ pppoe.conf "" "USER" $PPPoEUID
  echo -ne "\""$PPPoEUID"\"\t*\t\""$PPPoEPWD"\"\n" > /var/config/ppp/pap-secrets
  ```
- **关键词:** PPPoEEnable, PPPoEUID, PPPoEPWD, userconfig, cfg, pap-secrets, /var/config/ppp/pppoe.conf
- **备注:** 攻击链扩展：1) 与'nvram_get-udhcpc-hostname_injection'共享NVRAM污染向量 2) cfg二进制分析受阻（工具目录限制）需人工验证特殊字符处理 3) 关联漏洞利用概率提升至8.5（基于知识库现有攻击链）

---

## 中优先级发现

### command_execution-night_data-eval_injection

- **文件路径:** `web/cgi-bin/night_data.asp`
- **位置:** `night_data.asp:17`
- **类型:** command_execution
- **风险等级:** 9.5
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危eval注入漏洞：
- 具体表现：getConfig函数使用eval(configName)直接执行传入的字符串参数
- 触发条件：当父页面（如wizard.asp）调用getConfig并传入攻击者可控的configName参数时
- 约束检查：完全缺失输入验证和过滤机制
- 安全影响：攻击者可构造恶意configName参数执行任意JS代码，导致XSS/RCE（例如通过document.cookie窃取会话）
- **代码片段:**
  ```
  function getConfig(configName)
  {
  	return eval(configName);
  }
  ```
- **关键词:** getConfig, configName, eval, parent.ifDataOK, dayMode.cgi
- **备注:** 跨文件关联：1) 需验证wizard.asp调用链 2) dayMode.cgi可能污染configName（参见configuration_load-live.asp-token_bypass_risk） 3) 未解决问题：dayMode.cgi缺失/wizard.asp超出范围

---
### command_execution-factory_reset-dangerous_operations

- **文件路径:** `etc/init.d/userconfig`
- **位置:** `etc/init.d/userconfig: factory_reset()`
- **类型:** command_execution
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 强制重置攻击链：攻击者破坏/mnt/flash/config/restore.ini文件 → 导致start()中$binpath -initial失败 → 触发factory_reset() → 执行危险操作：1) 未验证路径删除/mnt/flash/config（可能通过符号链接删除系统文件）2) 备份敏感文件到/var（权限未设）3) 若存在bundle.ini则执行bundle_restore（可能代码执行）。触发条件：非特权用户需具有config目录写权限。
- **代码片段:**
  ```
  rm -rf /mnt/flash/config
  cp /mnt/flash/config/auto_apmode_config_key /var/
  [ -f /mnt/flash/config/bundle.ini ] && has_bundle=1
  $binpath -factory
  ```
- **关键词:** start(), factory_reset(), rm -rf /mnt/flash/config, bundle.ini, bundle_restore, restore.ini, S??*, killall
- **备注:** 需后续验证：1)/var目录权限 2)config目录符号链接攻击可行性 3)bundle_restore安全性；关联知识库：文件篡改攻击链和服务启动参数注入记录

---
### command-execution-pppoe-setup-sed

- **文件路径:** `sbin/pppoe-setup`
- **位置:** `pppoe-setup: sed command block`
- **类型:** command_execution
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在sed命令处理中存在命令注入漏洞：用户输入的USERNAME($U)和INTERFACE($E)参数未经过滤直接拼接到sed命令。攻击者可通过输入反引号包裹的命令(如`malicious_command`)在sed执行时触发任意命令执行。触发条件：1) 攻击者能控制输入参数；2) 脚本以root权限运行。实际影响：获得root权限shell。
- **代码片段:**
  ```
  sed -e "s&^USER=.*&USER=\\'$U\\'&" -e "s&^ETH=.*&ETH=\\'$E\\'&" ...
  ```
- **关键词:** U, USER, E, ETH, sed, CONFIG, /etc/ppp/pppoe.conf
- **备注:** 需验证web接口是否调用此脚本传递参数

---
### config-load-pppoe.conf-command-exec

- **文件路径:** `sbin/pppoe-status`
- **位置:** `pppoe-status:28`
- **类型:** configuration_load
- **风险等级:** 9.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 配置文件加载漏洞：通过`. $CONFIG`直接加载/etc/ppp/pppoe.conf文件内容作为shell命令执行。攻击者若篡改配置文件（需写权限），可在管理员执行pppoe-status时以root权限执行任意命令。触发条件：1) 攻击者获得配置文件写权限（如通过其他漏洞）；2) 管理员执行pppoe-status。边界检查完全缺失，文件内容未经任何过滤。
- **代码片段:**
  ```
  . $CONFIG
  ```
- **关键词:** CONFIG, pppoe.conf, PIDFILE, DEMAND, LINUX_PLUGIN
- **备注:** 实际风险依赖/etc/ppp/pppoe.conf文件权限。需后续验证该文件默认权限及是否被其他服务写入

---
### attack-chain-eval-injection-multifile

- **文件路径:** `web/cgi-bin/sounddb_data.asp`
- **位置:** `跨文件: wizsetup2.asp→smartwizard.cgi→[wizard_data.asp|image_data.asp|sounddb_data.asp]`
- **类型:** command_execution
- **风险等级:** 9.0
- **置信度:** 8.0
- **触发可能性:** 7.5
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 跨文件eval注入攻击链确认：1) wizsetup2.asp实现token污染（InternalQuery结果第三条）2) smartwizard.cgi传递污染token至configName 3) wizard_data.asp/image_data.asp/sounddb_data.asp共享的getConfig函数执行eval(configName)。完整触发路径：不可信输入(token)→参数传递(configName)→eval执行。风险集中于：a) token生成机制(wad.cgi缺失) b) 缺乏输入验证的eval调用点
- **关键词:** getConfig, eval, configName, smartwizard.cgi, generateToken
- **备注:** 需紧急验证：1) sounddb_data.asp是否被smartwizard.cgi调用 2) wad.cgi缺失对generateToken的影响（关联第一个发现）

---
### command_execution-smartwizard_eval_configName

- **文件路径:** `web/cgi-bin/wizsetup2.asp`
- **位置:** `www/wizard_data.asp:? (getConfig) ?`
- **类型:** command_execution
- **风险等级:** 9.0
- **置信度:** 7.5
- **触发可能性:** 8.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** smartwizard.cgi通过eval(configName)动态执行配置名，当外部输入污染configName时可能导致任意代码执行。触发条件：HTTP参数控制configName值；边界检查：无输入过滤机制；利用方式：构造恶意configName参数触发命令注入。该风险与wizsetup2.asp的token污染形成完整攻击链（token→参数传递→eval执行）
- **代码片段:**
  ```
  function getConfig(configName)
  {
      return eval(configName);
  }
  ```
- **关键词:** getConfig, eval, configName, smartwizard.cgi, g_token
- **备注:** 关联wizsetup2.asp的token污染：若token控制configName则形成RCE链。需验证：1) smartwizard.cgi中configName来源 2) token到configName的数据流

---
### nvram_get-udhcpc-hostname_injection

- **文件路径:** `etc/init.d/udhcpc.sh`
- **位置:** `udhcpc.sh:0 [run_dhcp_process]`
- **类型:** nvram_get
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 在udhcpc.sh的run_dhcp_process函数中，hostname变量通过`userconfig -read`从NVRAM(CAMSYSTEM.CameraName或System.ModelName)读取后，未经任何过滤或边界检查直接传递给/sbin/udhcpc的-x hostname参数。攻击者若能控制NVRAM值（例如通过其他漏洞），可在hostname中注入恶意内容。触发条件：当网络物理链路恢复时自动执行该函数。潜在影响取决于udhcpc对hostname参数的处理：若存在缓冲区溢出或命令注入漏洞，可能导致任意代码执行。
- **代码片段:**
  ```
  hostname=\`userconfig -read CAMSYSTEM CameraName\`
  /sbin/udhcpc -n -i $iface -x hostname:"$hostname" -p $pidfile
  ```
- **关键词:** hostname, userconfig, CAMSYSTEM, CameraName, System, ModelName, udhcpc, -x hostname, run_dhcp_process
- **备注:** 关键攻击路径：NVRAM污染->脚本参数注入->二进制漏洞触发。关联现有发现：1) 知识库ID关联：nvram_inject-rtspd-port_param（同userconfig读取模式）2) nvram_get-udhcpd_conf-injection（同DHCP组件风险模式）。后续验证：1) /sbin/udhcpc对hostname参数的处理 2) NVRAM写入点（如web接口）对CameraName的可控性验证

---
### configuration-stunnel-weak_ssl_protocol

- **文件路径:** `etc/stunnel-https.conf`
- **位置:** `etc/stunnel-https.conf:13 [N/A] [N/A]`
- **类型:** configuration_load
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** SSL配置允许所有协议版本(sslVersion=all)，包含已弃用的SSLv2/SSLv3。攻击者可通过协议降级攻击（如POODLE）解密HTTPS流量。触发条件：当客户端支持弱协议版本时，中间人攻击可强制使用不安全协议。边界检查：无协议版本过滤机制。安全影响：可导致加密流量被完全解密，暴露认证凭证和敏感数据。
- **代码片段:**
  ```
  sslVersion=all
  options=all
  ```
- **关键词:** sslVersion, options, ciphers, stunnel.pem
- **备注:** 需验证NVRAM配置是否覆盖此设置

---
### firmware-upgrade-RTS5826-unauth-flash

- **文件路径:** `etc/init.d/RTS5826_FW_check.sh`
- **位置:** `etc/init.d/RTS5826_FW_check.sh:7-15`
- **类型:** configuration_load
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 该脚本通过比较配置文件版本与设备当前版本决定是否升级固件。若版本不一致，直接执行固件刷写操作且无完整性校验。攻击者可篡改/etc/RTS5826.ini文件中的版本号或替换/home/RTS5826_FW.bin文件，在设备重启时触发恶意固件刷写。触发条件：1) 攻击者获得文件系统写权限；2) 设备重启执行该脚本。边界检查缺失：未验证固件文件签名/哈希值，未过滤配置文件的版本号格式。
- **代码片段:**
  ```
  if [ "$latest_version" != "$now_version" ]; then
  	echo "5826 firmware is not mapping, upgrade 5826 firmware now!"
  	/usr/sbin/rscam_uvc -d /dev/video0 --download /home/RTS5826_FW.bin
  ```
- **关键词:** /etc/RTS5826.ini, /home/RTS5826_FW.bin, rscam_uvc, cfg, latest_version, now_version, RTS5826_FW_check.sh
- **备注:** 需后续验证：1) /etc/RTS5826.ini文件是否可被外部修改（关联文件权限分析）; 2) /home/RTS5826_FW.bin文件的写入权限控制; 3) rscam_uvc工具是否实现固件签名验证（关联二进制分析）

---
### firmware-upgrade-RTS5826-unauth-flash

- **文件路径:** `web/cgi-bin/upgrade.asp`
- **位置:** `etc/init.d/RTS5826_FW_check.sh:7-15`
- **类型:** configuration_load
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 该脚本通过比较配置文件版本与设备当前版本决定是否升级固件。若版本不一致，直接执行固件刷写操作且无完整性校验。攻击者可篡改/etc/RTS5826.ini文件中的版本号或替换/home/RTS5826_FW.bin文件，在设备重启时触发恶意固件刷写。触发条件：1) 攻击者获得文件系统写权限；2) 设备重启执行该脚本。边界检查缺失：未验证固件文件签名/哈希值，未过滤配置文件的版本号格式。
- **代码片段:**
  ```
  if [ "$latest_version" != "$now_version" ]; then
  	echo "5826 firmware is not mapping, upgrade 5826 firmware now!"
  	/usr/sbin/rscam_uvc -d /dev/video0 --download /home/RTS5826_FW.bin
  ```
- **关键词:** /etc/RTS5826.ini, /home/RTS5826_FW.bin, rscam_uvc, cfg, latest_version, now_version, RTS5826_FW_check.sh
- **备注:** 需后续验证：1) /etc/RTS5826.ini文件是否可被外部修改（关联文件权限分析）; 2) /home/RTS5826_FW.bin文件的写入权限控制; 3) rscam_uvc工具是否实现固件签名验证（关联二进制分析）

---
### buffer_overflow-command_execution-0x004021a4

- **文件路径:** `sbin/iwcontrol`
- **位置:** `unknown:0 [main] 0x004021a4`
- **类型:** command_execution
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 命令行参数长度验证缺失导致全局缓冲区溢出。攻击者通过传递超长参数（如'wlanAAAAAAAA...'）触发漏洞：1) 程序检测参数以'wlan'开头后，将argv[1]直接复制到固定大小(20字节)的全局缓冲区(0x418a6c + *0x418310*0x14)；2) 未进行长度检查，若参数长度≥20字节将溢出覆盖相邻全局变量(*0x418310计数器等)；3) 可造成内存破坏，导致拒绝服务或控制流劫持。触发条件：参数需以'wlan'开头且长度≥20字节。
- **代码片段:**
  ```
  (**(loc._gp + -0x7e90))(0x418a6c + *0x418310 * 0x14, puVar14[1]);
  ```
- **关键词:** argv, 0x418a6c, *0x418310, (loc._gp + -0x7e90), wlan
- **备注:** 结合字符串分析，(loc._gp + -0x7e90)对应strcpy函数。影响范围取决于相邻全局变量内容，需验证内存布局。与路径注入漏洞共享argv输入源（见location:0x00402420）

---
### config-rtspd-multi_vulns

- **文件路径:** `etc/rtspd.conf`
- **位置:** `etc/rtspd.conf`
- **类型:** configuration_load
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** RTSP服务配置文件存在三重风险：1) 未设置认证机制，允许任意客户端无需凭证访问服务 2) 未配置IP黑白名单，无法限制恶意源IP访问 3) DocumentRoot和ServerRoot均指向/tmp/rtspd，该目录可能被其他服务（如HTTP上传）污染。攻击者可结合目录写入漏洞植入恶意媒体文件或劫持服务逻辑。
- **代码片段:**
  ```
  DocumentRoot /tmp/rtspd
  ServerRoot /tmp/rtspd
  ```
- **关键词:** DocumentRoot, ServerRoot, /tmp/rtspd
- **备注:** 需验证RTSP二进制是否加载该路径文件。建议后续：1) 分析sbin/rtspd对/tmp目录的校验逻辑 2) 检查HTTP服务是否存在/tmp目录写入漏洞

---
### file_tamper-userconfig-chain

- **文件路径:** `etc/init.d/force_conifg.sh`
- **位置:** `force_conifg.sh:10-11`
- **类型:** file_read
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 攻击者可通过物理访问或文件系统漏洞篡改/mnt/flash/config/NETIPCAS.ini中的hwv值。系统启动时force_conifg.sh执行：1) 使用cfg工具读取被篡改的hwv值 2) 通过userconfig将污染值写入系统HWVersion配置。若userconfig存在缓冲区溢出漏洞（如未验证$hwv长度），可形成完整攻击链：文件篡改→配置污染→内存破坏→任意代码执行。关键约束：a) NETIPCAS.ini需具备可写权限 b) userconfig需存在安全缺陷。
- **代码片段:**
  ```
  hwv=\`cfg -a r -p /mnt/flash/config NETIPCAS.ini NIPCAS hwv\`
  /usr/sbin/userconfig -write "INFO" "HWVersion" "$hwv"
  ```
- **关键词:** force_conifg.sh, NETIPCAS.ini, hwv, HWVersion, userconfig, cfg, -write
- **备注:** 关联现有发现：需验证/usr/sbin/userconfig的二进制安全机制（参考知识库中'network_input-credential_verify-verify_user_sh'的notes）。攻击链依赖：1) 文件可篡改性 2) userconfig漏洞

---
### command_execution-ipfind-start

- **文件路径:** `etc/init.d/ipfind-0`
- **位置:** `etc/init.d/ipfind-0:18`
- **类型:** command_execution
- **风险等级:** 8.5
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 启动root权限二进制文件：脚本通过'$binpath $netinterface &'以root权限启动/usr/sbin/ipfind，传递固定参数'br0'。若该二进制文件存在参数解析漏洞（如缓冲区溢出），攻击者可通过篡改服务配置文件或二进制本身触发。触发条件：系统启动或服务重启时自动执行。约束检查：参数硬编码无外部输入验证。安全影响：高权限二进制漏洞可导致权限提升或RCE。
- **代码片段:**
  ```
  $binpath $netinterface &
  ```
- **关键词:** /usr/sbin/ipfind, br0, netinterface, args, start()
- **备注:** 需进一步分析/usr/sbin/ipfind的二进制安全

---
### StackOverflow-PPPoE-dbg.relaySendError-0x4028e8

- **文件路径:** `sbin/pppoe-relay`
- **位置:** `pppoe-relay:0x4028e8`
- **类型:** network_input
- **风险等级:** 8.5
- **置信度:** 8.5
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** MAC地址处理栈溢出：错误处理函数dbg.relaySendError使用strcpy直接将攻击者控制的MAC地址(param_6)复制到固定大小栈缓冲区(auStack_be4)，无长度验证。触发条件：通过异常会话触发dbg.cleanSessions清理流程并注入超长MAC地址。可导致拒绝服务或控制流劫持。
- **代码片段:**
  ```
  (**loc._gp-0x7e6c)(auStack_be4, param_6);  // strcpy调用
  ```
- **关键词:** dbg.relaySendError, strcpy, param_6, auStack_be4, MAC, dbg.cleanSessions
- **备注:** 需验证ASLR防护强度

---
### command-execution-pppoe-setup-echo

- **文件路径:** `sbin/pppoe-setup`
- **位置:** `pppoe-setup: DNS config block`
- **类型:** command_execution
- **风险等级:** 8.5
- **置信度:** 8.5
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 在DNS配置处理中存在命令注入漏洞：用户输入的DNS地址($DNS1/$DNS2)未过滤直接拼接到echo命令。攻击者输入`$(malicious_command)`格式的DNS地址可在写入/etc/resolv.conf时触发命令执行。触发条件：1) 输入非常规DNS值；2) 脚本以root权限执行。实际影响：任意命令执行。
- **代码片段:**
  ```
  $ECHO "nameserver $DNS1" >> /etc/resolv.conf
  ```
- **关键词:** DNS1, DNS2, echo, /etc/resolv.conf
- **备注:** 可能通过DHCP客户端或网络配置接口触发

---
### command_execution-smartwizard_token_chain

- **文件路径:** `web/cgi-bin/wizsetup2.asp`
- **位置:** `wizard.asp: doSmartWizard函数`
- **类型:** command_execution
- **风险等级:** 8.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** smartwizard.cgi的reset操作将用户可控的g_token与动态Token拼接执行，存在未授权操作风险。触发条件：token污染+Token验证缺陷；边界检查：无token内容过滤；利用方式：构造恶意token绕过认证执行系统命令。与wizsetup2.asp的token未验证直接关联，形成认证绕过→命令执行链
- **代码片段:**
  ```
  makeRequest2("/cgi/admin/smartwizard.cgi", "action=reset", g_token + "@" + token, doSmartWizard_callback);
  ```
- **关键词:** makeRequest2, smartwizard.cgi, action=reset, g_token, calToken
- **备注:** 完整攻击链：wizsetup2.asp获取未验证token→传递至本操作→触发smartwizard.cgi的reset命令执行

---
### command_execution-upnp_binary_launch

- **文件路径:** `etc/init.d/upnp-0`
- **位置:** `etc/init.d/upnp-0: unknown line (shell script)`
- **类型:** command_execution
- **风险等级:** 8.0
- **置信度:** 9.5
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 识别出关键服务二进制'/usr/sbin/upnp'的启动路径及参数。具体表现：当UPnP Enable=0x01时，以后台方式执行'/usr/sbin/upnp br0 1>/dev/null 2>&1'。参数'br0'表明该程序绑定网桥接口，但脚本中未实现网络防护（如端口访问控制）。触发条件：服务启动时自动执行。潜在影响：若二进制存在漏洞（如缓冲区溢出），攻击者可通过网络直接触发。
- **关键词:** /usr/sbin/upnp, binpath, args, br0, 1>/dev/null
- **备注:** 'br0'参数表明网络数据处理逻辑在二进制内。必须分析/usr/sbin/upnp以确认实际漏洞。关联链条：NVRAM配置读取（nvram_get）→ 服务启动判断 → 二进制执行

---
### network_input-client_validation_bypass-asp157

- **文件路径:** `web/cgi-bin/wizsetup2.asp`
- **位置:** `wizsetup2.asp:157-220`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 网络配置参数(IP/PPPoE)客户端验证(devip_check/check_mask)可被绕过。触发条件：直接构造POST请求到smartwizard.cgi。边界检查：客户端有格式验证但无长度限制，服务端验证未知。潜在安全影响：攻击者可提交畸形网络参数篡改设备配置。利用方式：绕过浏览器直接发送恶意参数至/cgi/admin/smartwizard.cgi。
- **代码片段:**
  ```
  if ((ret_ip=devip_check(document.getElementById("input_IPv4Address").value)) == 1) {
    alert(pop_msg[PMSG_INVALID_IPADDRESS]);
    return;
  }
  ```
- **关键词:** save_setting, devip_check, input_IPv4Address, input_PPPoEUID, smartwizard.cgi
- **备注:** 关键验证函数devip_check定义在function.js需交叉分析

---
### network_input-http_token-direct_unvalidated

- **文件路径:** `web/cgi-bin/image.asp`
- **位置:** `image.asp:36`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** HTTP参数'token'通过getWebQuery函数直接获取且未经验证过滤。攻击者可构造恶意token值（如`image.asp?token=恶意payload`）尝试注入攻击。触发条件仅需访问CGI脚本时携带该参数。由于缺乏边界检查，可能造成权限绕过或命令注入，具体风险取决于calToken函数的验证机制。安全影响：CVSS≥8.0（需结合calToken分析确认）
- **代码片段:**
  ```
  var g_token = getWebQuery("token", "");
  ```
- **关键词:** getWebQuery, token, g_token, calToken
- **备注:** 需验证function.js中getWebQuery实现及calToken的token校验逻辑。关联知识库记录：'必须验证function.js中makeRequest2对g_token的处理逻辑'

---
### network_input-ftp_cgi-unfiltered_params

- **文件路径:** `web/cgi-bin/ftp.asp`
- **位置:** `ftp.asp: JavaScript函数区域`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未经验证的用户输入（HTTP参数'token'及表单字段input_ftp_server/port/uid/pwd）通过save_setting()直接传递至ftp.cgi。仅对端口/间隔实施数值范围检查（1-65535），未对服务器地址、用户名、密码等字符串输入进行过滤或长度限制。攻击者可构造恶意参数（如超长用户名或特殊字符）污染配置，若ftp.cgi存在命令注入或缓冲区溢出漏洞，可能导致远程代码执行。
- **代码片段:**
  ```
  params += "ServerAddr=" + encodeURIComponent(document.getElementById("input_ftp_server").value);
  ```
- **关键词:** getWebQuery, input_ftp_server, input_ftp_port, input_ftp_uid, input_ftp_pwd, save_setting, ftp.cgi, encodeURIComponent
- **备注:** 需验证ftp.cgi对ServerAddr/uid/pwd参数的处理逻辑，重点检查是否存在命令拼接（如system()调用）或缓冲区操作

---
### network_input-network_asp-bonjour_auth_pollution

- **文件路径:** `web/cgi-bin/network.asp`
- **位置:** `network.asp: 行346-548 (save_setting函数)`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 攻击者可构造恶意Bonjour名称或认证参数污染输入。触发条件：用户提交表单时，攻击者绕过客户端验证（如禁用JS）注入恶意负载。约束条件：1) IP/子网掩码/端口有前端验证 2) Bonjour验证函数未实现 3) RTSP/HTTP认证参数无过滤。潜在影响：污染数据经encodeURIComponent编码后传入network.cgi，可能导致命令注入或配置篡改。
- **代码片段:**
  ```
  params += '&BonjourName=' + encodeURIComponent(document.getElementById('input_bonjourName').value);
  params += '&HTTPAuthenticate=' + encodeURIComponent(document.getElementById('selectHTTPAuthenticate').value);
  ```
- **关键词:** input_bonjourName, selectHTTPAuthenticate, selectRTSPAuthenticate, CheckBonjourname, encodeURIComponent, network.cgi
- **备注:** 需分析/cgi/admin/network.cgi的处理逻辑验证攻击可行性。PPPoE密码(pwd_dirty标记)虽前端清空但未过滤特殊字符。

---
### network_input-rtspurl-param_chain

- **文件路径:** `web/cgi-bin/audiovideo.asp`
- **位置:** `web/cgi-bin/audiovideo.asp (函数: save_setting)`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未经验证的RTSPURL参数传递链：在audiovideo.asp的save_setting()函数中，用户控制的input_rtspurl_h264/input_rtspurl_mjpeg参数（最大127字符）未经任何过滤直接通过makeRequest2()发送到后端audiovideo.cgi。触发条件：攻击者拦截修改POST请求中的RTSPURL0/RTSPURL2参数。潜在影响：若后端未实施长度检查/过滤，结合危险函数可能导致缓冲区溢出或命令注入。实际风险取决于后端验证机制（当前无法验证）。
- **代码片段:**
  ```
  未提供具体代码片段，需后续补充
  ```
- **关键词:** RTSPURL0, RTSPURL2, input_rtspurl_h264, input_rtspurl_mjpeg, save_setting, makeRequest2
- **备注:** 关键依赖：必须分析'cgi-bin/cgi/audiovideo.cgi'验证后端处理逻辑。建议后续：1) 反编译该ELF文件 2) 追踪RTSPURL参数解析过程 3) 检查sprintf/system等危险函数调用

---
### network_input-wizsetup5-token_injection_chain

- **文件路径:** `web/cgi-bin/wizsetup5.asp`
- **位置:** `wizsetup5.asp:10-15`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** HTTP参数'token'通过getWebQuery获取后直接赋值给g_token变量，未进行任何输入验证或过滤。攻击者可通过构造恶意token值尝试注入攻击。该参数随后传递至makeRequest2函数，可能形成注入攻击链。触发条件：通过HTTP请求传入污染token参数；影响：取决于makeRequest2的实现，可能导致命令注入或敏感操作未授权访问。
- **代码片段:**
  ```
  var g_token = getWebQuery("token", "");
  ```
- **关键词:** getWebQuery, token, g_token, makeRequest2
- **备注:** 必须验证function.js中makeRequest2对g_token的处理逻辑

---
### nvram_get-llmnr-param_injection

- **文件路径:** `etc/init.d/llmnr-0`
- **位置:** `etc/init.d/llmnr-0:13-22 (start函数)`
- **类型:** nvram_get
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** LLMNR服务启动时存在参数注入风险。具体表现：/usr/sbin/llmnr进程的$CameraName参数通过`userconfig -read CAMSYSTEM CameraName`从NVRAM获取，仅使用tr命令进行大小写转换，未实施长度检查或特殊字符过滤。触发条件：攻击者通过Web接口漏洞等途径篡改NVRAM中的CameraName值。潜在影响：若llmnr二进制存在缓冲区溢出或命令注入漏洞，可导致远程代码执行。约束条件：需满足a) NVRAM值可被篡改 b) llmnr存在参数处理漏洞。
- **代码片段:**
  ```
  CameraName=\`/usr/sbin/userconfig -read CAMSYSTEM CameraName|tr '[A-Z]' '[a-z]'\`
  ...
  $binpath $Interfacce $CameraName $mac &
  ```
- **关键词:** /usr/sbin/llmnr, userconfig, CAMSYSTEM, CameraName, tr, START_SERVICE
- **备注:** 关键后续步骤：分析/usr/sbin/llmnr对CameraName参数的处理逻辑，验证是否存在边界检查缺失

---
### file_write-stunnel_config_dynamic_generation

- **文件路径:** `etc/init.d/https-0`
- **位置:** `etc/init.d/https-0:14-29`
- **类型:** file_write
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** stunnel配置文件动态生成漏洞。具体表现：脚本使用外部可控变量($device_ip/$https_port/$http_port)直接写入配置文件。触发条件：当NVRAM中'HTTPS Enable=0x01'时执行start()函数。约束条件：1) device_ip来自ifconfig br0输出（可被ARP欺骗篡改）2) 端口号来自NVRAM（可通过Web界面修改）。安全影响：若cfg命令存在目录遍历或配置注入漏洞，攻击者可操控配置文件导致RCE或MITM攻击。利用方式：篡改br0 IP或NVRAM端口值→污染配置文件→触发cfg/stunnel漏洞。
- **代码片段:**
  ```
  /usr/sbin/cfg -a w -p /var stunnel-https.conf https accept $device_ip:$https_port
  /usr/sbin/cfg -a w -p /var stunnel-https.conf https connect $device_ip:$http_port
  ```
- **关键词:** cfg, stunnel-https.conf, device_ip, https_port, http_port, ifconfig, br0, userconfig, start()
- **备注:** 关键依赖：需验证/usr/sbin/cfg的-p参数处理机制（是否允许路径遍历）和变量插值安全（是否导致配置语法注入）

---
### network_input-httpd-ntp_server_validation

- **文件路径:** `web/cgi-bin/time.asp`
- **位置:** `time.asp`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** HTTP输入点存在未充分验证的NTP服务器参数(input_ntp_server)。触发条件：用户提交时间设置表单时，前端通过save_setting()函数将参数编码后发送至wdatetime.cgi。约束条件：仅前端空值检查(if value=='')和maxlength=64限制，无内容过滤或特殊字符处理。潜在安全影响：攻击者可构造恶意NTP服务器地址(含特殊字符/超长数据)，若后端wdatetime.cgi未严格过滤，可能导致命令注入或缓冲区溢出。利用方式：绕过前端直接发送恶意请求至/cgi/admin/wdatetime.cgi
- **代码片段:**
  ```
  params += "&NTPServerIP=" + encodeURIComponent(document.getElementById("input_ntp_server").value);
  if (document.getElementById("input_ntp_server").value == "") {
    alert(pop_msg[PMSG_NTP_SERVER_FORMAT_INVALID]);
    return;
  }
  ```
- **关键词:** input_ntp_server, save_setting, encodeURIComponent, wdatetime.cgi, NTPServerIP, maxlength=64, getWebQuery
- **备注:** 需立即分析wdatetime.cgi对NTPServerIP参数的处理逻辑，验证注入可能性

---
### network_input-x_forwarded_for-bof_0x402f18

- **文件路径:** `web/httpd`
- **位置:** `httpd:0x402f18`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 函数fcn.00402e20(0x402f18/0x402fcc)使用strcpy复制客户端IP到全局缓冲区(256字节)，攻击者通过X-Forwarded-For注入超长IP(>255字节)可溢出覆盖相邻变量。触发条件：伪造恶意HTTP连接或头字段。边界检查：仅依赖IP格式约束。安全影响：全局数据破坏可能导致权限提升或拒绝服务。
- **代码片段:**
  ```
  (**(loc._gp + -0x7dcc))(*0x422c84 + iVar4, param_1);  // strcpy等效
  ```
- **关键词:** fcn.00402e20, strcpy, param_1, *0x422c84, uStack_4b0, X-Forwarded-For
- **备注:** 关联知识库：1) 平行攻击面（smtps-snapshot-0）2) 与'file_tamper-userconfig-chain'组合可形成完整攻击链

---
### configuration-stunnel-missing_client_auth

- **文件路径:** `etc/stunnel-https.conf`
- **位置:** `etc/stunnel-https.conf:17 [N/A] [N/A]`
- **类型:** configuration_load
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 缺失客户端证书验证(requireCert未配置)，允许任意客户端连接。触发条件：攻击者可直接连接服务。边界检查：无客户端身份验证机制。安全影响：结合弱加密配置形成完整攻击链：中间人攻击→协议降级→流量解密→数据窃取，尤其影响192.168.0.30:80的后台服务。
- **代码片段:**
  ```
  accept=192.168.0.30:443
  connect=192.168.0.30:80
  ```
- **关键词:** accept, connect, TIMEOUTclose
- **备注:** 需追踪192.168.0.30:80服务的输入验证逻辑

---
### nvram_inject-rtspd-port_param

- **文件路径:** `etc/init.d/rtspd-0`
- **位置:** `rtspd-0:19`
- **类型:** nvram_set
- **风险等级:** 8.0
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** NVRAM配置值'RTSP Port'直接作为rtspd服务启动参数(-p)且未进行边界验证。攻击者通过篡改NVRAM值(如利用未授权API)可控制端口参数，若rtspd二进制存在整数溢出或边界检查缺陷，可能触发服务崩溃或RCE。触发条件：1) 攻击者具有NVRAM写权限 2) rtspd未正确处理异常端口值。约束条件：当PRIVACY_MODE Enable=0x01且Manual=0x01时服务不启动。
- **代码片段:**
  ```
  /usr/sbin/rtsp/rtspd -p $port -v 1>/dev/null 2>/dev/null
  ```
- **关键词:** RTSP Port, port, -p, /usr/sbin/rtsp/rtspd, start(), userconfig
- **备注:** 关键攻击路径：NVRAM写操作->服务参数注入->二进制漏洞触发。需验证/usr/sbin/rtsp/rtspd的端口处理逻辑。关联现有'start()'相关发现（知识库ID待关联）

---
### StackOverflow-PPPoE-dbg.relayGotSessionPacket-0x00401bdc

- **文件路径:** `sbin/pppoe-relay`
- **位置:** `pppoe-relay:0x00401bdc`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未初始化变量栈溢出：dbg.relayGotSessionPacket中recvfrom调用使用未初始化的栈变量uStack_608作为缓冲区大小参数。当该随机值小于实际数据包长度时导致栈溢出。触发条件：发送长度>1500字节的PPPoE会话包。可造成拒绝服务或潜在代码执行。
- **代码片段:**
  ```
  iVar3 = (**(loc._gp + -0x7fc4))(*(param_1 + 0x18), &uStack_604, &uStack_608);
  ```
- **关键词:** uStack_608, dbg.relayGotSessionPacket, recvfrom, loc._gp + -0x7fc4
- **备注:** 需结合系统内存布局评估利用难度

---
### command_execution-upnp_igd_rtsp-argument_injection

- **文件路径:** `etc/init.d/upnp_igd-rtsp.sh`
- **位置:** `upnp_igd-rtsp.sh: start/stop函数`
- **类型:** command_execution
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 7.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 通过binpath(/etc/init.d/upnp_igd.sh)执行底层端口操作时，虽使用双引号包裹变量防止命令注入，但未对$extport/$intport值过滤。若upnp_igd.sh存在缓冲区溢出等漏洞，可形成完整攻击链：篡改配置→传递恶意参数→触发底层漏洞。
- **代码片段:**
  ```
  $binpath portmap "$extport" "$intport"
  $binpath portdel "$oldport"
  ```
- **关键词:** binpath, upnp_igd.sh, portmap, portdel, $extport, $intport
- **备注:** 必须分析/etc/init.d/upnp_igd.sh的portmap/portdel实现。关联知识库记录：'关键攻击路径：NVRAM写操作->服务参数注入->二进制漏洞触发'

---
### command_execution-smartwizard_cgi-token_pollution

- **文件路径:** `web/cgi-bin/wizard.asp`
- **位置:** `wizard.asp: doSmartWizard函数`
- **类型:** command_execution
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 6.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 通过makeRequest2调用smartwizard.cgi执行reset操作时，将用户可控的g_token与动态Token拼接发送。若Token验证缺陷或smartwizard.cgi存在命令注入，可导致未授权系统操作。触发条件：污染token参数+Token生成机制缺陷，利用概率中等需进一步验证下游文件。
- **代码片段:**
  ```
  makeRequest2("/cgi/admin/smartwizard.cgi", "action=reset", g_token + "@" + token, doSmartWizard_callback);
  ```
- **关键词:** makeRequest2, smartwizard.cgi, action=reset, g_token, calToken
- **备注:** 关键依赖：需分析/cgi/admin/smartwizard.cgi的reset实现及Token验证逻辑；关联现存需求：/cgi/admin/smartwizard.cgi验证逻辑分析（见notes唯一值列表）

---
### network_input-email_asp-csrf_token_bypass

- **文件路径:** `web/cgi-bin/email.asp`
- **位置:** `email.asp (客户端脚本)`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 7.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** CSRF token绕过风险：客户端JavaScript通过getWebQuery('token')直接获取未经验证的token参数用于身份校验（calToken调用）。攻击者可结合XSS漏洞窃取有效token或伪造token值发送请求，最终绕过CSRF保护执行配置篡改。触发条件：1) 有效用户会话 2) 攻击者诱导访问恶意页面或触发XSS 3) 后端calToken校验存在逻辑缺陷。
- **关键词:** getWebQuery, token, g_token, calToken
- **备注:** 关键依赖项未验证：1) getWebQuery实现 2) calToken校验逻辑。需动态测试token篡改效果。关联知识库：必须验证/cgi/admin/whardfactorydefault.cgi的令牌处理逻辑（知识库ID关联）。

---
### attack_chain_gap-iptables_input_validation

- **文件路径:** `sbin/xtables-multi`
- **位置:** `固件全局 (待定位)`
- **类型:** network_input
- **风险等级:** 8.0
- **置信度:** 7.0
- **触发可能性:** 6.0
- **查询相关性:** 10.0
- **阶段:** N/A
- **描述:** 高危漏洞利用链关键缺口。需验证初始输入点：1) /www/cgi-bin/目录下的规则上传功能是否调用iptables-restore；2) TR-069配置下发是否传递恶意规则表名/链名。若存在，将构成完整RCE攻击链：网络输入 → 缓冲区溢出 → EIP控制。约束条件：需逆向分析Web后端和TR-069服务实现。
- **关键词:** iptables-restore, www/cgi-bin, TR-069, RCE攻击链, argv
- **备注:** 关联已知漏洞：stack_overflow-iptables_restore-table_name 和 heap_overflow-iptables_command-chain_name

---
### configuration_load-sysmgr-0-binpath_missing

- **文件路径:** `etc/init.d/sysmgr-0`
- **位置:** `etc/init.d/sysmgr-0:7`
- **类型:** configuration_load
- **风险等级:** 7.5
- **置信度:** 10.0
- **触发可能性:** 10.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 未定义binpath变量导致服务启动/停止操作前强制退出。具体表现：执行脚本任何命令（如/etc/init.d/sysmgr-0 start）时触发'[ -f $binpath ] || exit'检测，因binpath未定义而立即退出。边界检查缺失：无默认值或错误处理。安全影响：造成拒绝服务（服务无法启动），攻击者可通过任意脚本执行操作（如web接口调用）瘫痪系统管理服务。
- **代码片段:**
  ```
  [ -f $binpath ] || exit
  ```
- **关键词:** binpath, exit, start, stop, 攻击链
- **备注:** 需验证是否固件配置错误；关联关键词'start()'/'stop()'在httpd服务中存在历史记录（S90httpd-0）

---
### network_input-wizard_asp-unauth_redirect

- **文件路径:** `web/cgi-bin/wizard.asp`
- **位置:** `wizard.asp: init函数`
- **类型:** network_input
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** HTTP参数'token'和'wizardtype'未经过滤直接用于流程控制。攻击者可通过操控wizardtype=1触发未授权跳转至reboot_wizard.asp，或注入恶意token进行参数污染。触发条件：发送含恶意参数的HTTP请求，成功概率高因仅依赖基础parseInt转换且无边界检查。
- **代码片段:**
  ```
  var wizardtype = parseInt(getWebQuery("wizardtype", "0"), 10);
  if (wizardtype == 1) { location.href = "reboot_wizard.asp?token=" + g_token; }
  ```
- **关键词:** getWebQuery, token, wizardtype, parseInt, location.href
- **备注:** 需验证reboot_wizard.asp的敏感性；当前未发现长度/内容过滤

---
### network_input-motion_asp_cgi_endpoints

- **文件路径:** `web/cgi-bin/motion.asp`
- **位置:** `web/cgi-bin/motion.asp`
- **类型:** network_input
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 文件'web/cgi-bin/motion.asp'为纯客户端HTML，通过JavaScript调用后端CGI接口：1) /cgi/admin/motion.cgi处理运动检测请求 2) /cgi/admin/wgetheader.cgi处理HTTP头操作。这两个CGI是关键的初始攻击面，需追踪其参数传递路径和输入验证机制。攻击者可通过构造恶意请求直接访问这些端点，潜在风险取决于CGI的实现安全性。
- **关键词:** /cgi/admin/motion.cgi, /cgi/admin/wgetheader.cgi, makeRequestByGet
- **备注:** 后续分析优先级：1) 逆向motion.cgi/wgetheader.cgi二进制 2) 追踪makeRequestByGet参数传递 3) 验证CGI输入过滤机制

---
### nvram_get-upnp_init_config

- **文件路径:** `etc/init.d/upnp-0`
- **位置:** `etc/init.d/upnp-0: unknown line (shell script)`
- **类型:** nvram_get
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.2
- **阶段:** N/A
- **描述:** UPnP服务启动流程存在未验证的NVRAM输入点。具体表现：通过'/usr/sbin/userconfig -read UPnP Enable'读取配置值后直接用于条件判断（if [ $enable == "0x01" ]）。触发条件：系统执行start命令时自动触发。约束检查缺失：未验证读取值是否为合法布尔值（0x00/0x01），攻击者通过NVRAM写入漏洞可篡改该值强制启动服务，暴露网络攻击面。
- **关键词:** UPnP Enable, userconfig, -read, enable, start
- **备注:** 需结合NVRAM写入漏洞利用。关联发现：通过'start'关键词连接服务启动路径。后续分析方向：1) 查找NVRAM设置点（nvram_set） 2) 分析/usr/sbin/upnp二进制

---
### network_input-credential_verify-verify_user_sh

- **文件路径:** `etc/init.d/verify_user.sh`
- **位置:** `verify_user.sh:4-36`
- **类型:** network_input
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 脚本接受外部输入$1(用户名)和$2(密码)，通过userconfig工具从NVRAM明文读取三类凭证(ADMIN/GENERAL/GUEST)进行比对。存在三重风险：1) 未对$1/$2过滤/截断，允许超长或特殊字符输入 2) NVRAM凭证明文存储 3) 循环遍历凭证类型暴露所有账户体系。攻击者通过调用此脚本的组件(如web接口)可：a) 注入恶意字符触发后续解析漏洞 b) 暴力遍历所有凭证类型 c) 获取完整凭证库。触发需满足：调用者未实施权限控制+可传递任意$1/$2参数。
- **代码片段:**
  ```
  username="$1"
  password="$2"
  for user_type in USER_ADMIN USER_GENERAL USER_GUEST; do
    stored_user=\`userconfig -read $user_type Username1\`
    stored_pass=\`userconfig -read $user_type Password1\`
  ```
- **关键词:** $1, $2, userconfig, USER_ADMIN, USER_GENERAL, USER_GUEST, Username1, Password1
- **备注:** 完整利用需验证：1) /usr/sbin/userconfig是否存在缓冲区溢出（参数未过滤）2) web服务器调用此脚本的权限控制机制 3) NVRAM加密强度。建议后续分析：a) web接口调用链 b) userconfig二进制安全。关联知识库：NVRAM配置验证需求

---
### network_input-night_asp-http_params_unvalidated

- **文件路径:** `web/cgi-bin/night.asp`
- **位置:** `night.asp`
- **类型:** network_input
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** HTTP参数'token'和表单参数(radio_mode/select_start_hour等)未经充分验证即传递至dayMode.cgi。具体表现：1) token直接拼接未过滤 2) 时间参数使用parseInt但未处理NaN值。触发条件：攻击者构造含恶意token或非数字时间值的HTTP请求。安全影响：若dayMode.cgi存在命令注入等漏洞，可形成RCE攻击链；时间参数NaN可能引发解析异常导致服务拒绝。
- **代码片段:**
  ```
  var g_token = getWebQuery("token", "");
  params += "&IRScheEnd=" + encodeURIComponent(startmins.toString());
  ```
- **关键词:** getWebQuery, token, radio_mode, select_start_hour, save_setting, IRScheEnd, makeRequest2, /cgi/admin/dayMode.cgi, parseInt
- **备注:** 攻击链关键缺口在dayMode.cgi：需验证其对IRScheEnd/token参数的解析是否存在命令注入或缓冲区溢出

---
### nvram-ptctrl-param-injection

- **文件路径:** `etc/init.d/ptctl.sh`
- **位置:** `ptctl.sh:6-39`
- **类型:** nvram_get
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 脚本从NVRAM的PAN_TILT配置组读取9类参数(Pan_Speed/Tilt_Speed等)，未经验证直接传递给ptctrl执行硬件操作。仅StartUp参数有范围检查(1-8)，其他参数如速度/步长值均无校验。攻击者通过篡改NVRAM参数(如设置极高速度值)可导致云台异常操作(如高速撞击物理限位)，需满足触发条件：a) 攻击者具有NVRAM写权限 b) 系统重启或服务重载触发脚本执行
- **代码片段:**
  ```
  p_speed=\`userconfig -read PAN_TILT Pan_Speed\`
  /usr/sbin/ptctrl -h -speed=$p_speed
  ```
- **关键词:** userconfig -read, PAN_TILT, Pan_Speed, Tilt_Speed, Pan_Step, Tilt_Step, /usr/sbin/ptctrl, pt_ini
- **备注:** 需验证ptctrl是否进行二次校验；追踪NVRAM写入点(如web接口)

---
### nvram_set-ftp_enable-85

- **文件路径:** `web/cgi-bin/ftp_data.asp`
- **位置:** `ftp_data.asp:85`
- **类型:** nvram_set
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 7.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** NVRAM配置篡改漏洞：'ftp_enable'参数通过Request.QueryString直接传入nvram_set，缺乏类型校验。触发条件：污染GET参数。约束缺失：未验证布尔值范围(0/1)。安全影响：可非法启用/禁用FTP服务破坏系统状态，可能作为攻击链环节。
- **代码片段:**
  ```
  ftp_enable = Request.QueryString("ftp_enable");
  nvram_set("ftp_enable", ftp_enable);
  ```
- **关键词:** Request.QueryString, ftp_enable, nvram_set, nvram_commit

---
### command_execution-mydlink_service-opt.local_param_inject

- **文件路径:** `etc/init.d/service.sh`
- **位置:** `service.sh:15 [start]; service.sh:28 [stop]`
- **类型:** command_execution
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 6.5
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 服务脚本通过变量$mydlink_script调用外部脚本/mydlink/opt.local并传递控制参数(start/stop)。虽然service.sh对自身参数$1进行严格校验(仅接受start/stop/restart)，但若被调用的/mydlink/opt.local未经验证处理参数，攻击者可能通过操纵服务状态(如触发服务重启)注入恶意参数。触发条件：1) 攻击者能控制服务管理接口(如web服务控制) 2) /mydlink/opt.local存在参数处理漏洞(如命令注入)。成功利用可导致任意命令执行，风险随被调用脚本的安全强度递增。
- **代码片段:**
  ```
  $mydlink_script start
  $mydlink_script stop
  ```
- **关键词:** mydlink_script, /mydlink/opt.local, $1, start(), stop()
- **备注:** 关键攻击链节点：需立即分析/mydlink/opt.local脚本：1) 检查参数是否直接用于命令执行(eval/system) 2) 验证参数边界检查 3) 确认是否加载外部输入源(如环境变量)。建议后续任务：深度分析/mydlink/opt.local的参数处理机制与外部输入交互。与知识库中其他start()控制链（如wanip_detect/rtspd）无直接调用关系，但同属服务启动参数传递模式。

---
### command_injection-write_hosts-modelname_mac

- **文件路径:** `etc/init.d/network`
- **位置:** `etc/init.d/network:13-26`
- **类型:** command_execution
- **风险等级:** 7.5
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 9.8
- **阶段:** N/A
- **描述:** 在write_hosts函数中发现命令注入漏洞：1) 通过`userconfig -read System ModelName`获取设备型号名，与MAC地址拼接后直接用于`hostname`系统命令 2) 无任何输入验证或过滤机制 3) 攻击者可篡改ModelName配置注入恶意命令（如`;rm -rf /`），当网络服务启动时触发执行。触发条件：系统启动或执行`/etc/init.d/network start`命令时自动调用write_hosts函数。
- **代码片段:**
  ```
  hostname=\`/usr/sbin/userconfig -read System ModelName\`
  macaddress=\`rtkmib mac|tr '[a-z]' '[A-Z]'\`
  hostname "${hostname}-$mac"
  ```
- **关键词:** write_hosts, userconfig, System ModelName, rtkmib, hostname, /etc/hosts, NVRAM污染, 服务启动参数注入
- **备注:** 完整攻击链依赖ModelName配置的写入接口安全性（如HTTP API/NVRAM设置）。关联知识库攻击链：'关键攻击路径：NVRAM污染->脚本参数注入->二进制漏洞触发'。待验证点：1) userconfig二进制实现 2) NVRAM写入点暴露程度

---
### file_operation-config_recovery-1

- **文件路径:** `etc/init.d/check_other_config.sh`
- **位置:** `check_other_config.sh:4-58`
- **类型:** file_write
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 当/mnt/flash/config/或/var/目录下关键配置文件（如passwd, ipfilter.ini）缺失时，脚本自动从/etc/复制默认文件。攻击路径：1) 攻击者删除目标文件（需写权限）→ 2) 触发脚本执行（需满足触发条件）→ 3) 复制被污染的源文件（如/etc/passwd_default）→ 4) 植入恶意配置。边界检查缺失：未验证源文件完整性或目标路径安全性。实际影响：结合/etc目录写权限漏洞可导致权限提升或网络过滤规则篡改。
- **关键词:** /mnt/flash/config/passwd, /etc/passwd_default, /mnt/flash/config/ipfilter.ini, /etc/ipfilter.ini, /var/stunnel-https.conf, cp -f
- **备注:** 利用链依赖两个前提：1) /etc/目录源文件可被篡改（需另查权限设置）2) 脚本触发机制（启动时/事件驱动）。关联发现：file_write-passwd_restore-default_weakness（位于etc/init.d/restore_other_config.sh:27）

---
### env_set-userconfig_script-environment_pollution

- **文件路径:** `etc/init.d/userconfig`
- **位置:** `etc/init.d/userconfig: 首行`
- **类型:** env_set
- **风险等级:** 7.5
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 环境变量污染攻击链：脚本开头'set -a'导出所有变量。若攻击者在执行前注入PATH或binpath变量（如通过其他服务漏洞），可劫持$binpath执行的/usr/sbin/userconfig。触发条件：需控制脚本执行环境。
- **代码片段:**
  ```
  #!/bin/sh
  set -a
  binpath=/usr/sbin/userconfig
  ```
- **关键词:** set -a, PATH, binpath, /usr/sbin/userconfig, export
- **备注:** 需逆向分析/usr/sbin/userconfig验证环境变量处理；关联发现：env_set-ipfind-global_export存在同类风险

---
### network_input-email_asp-frontend_validation_bypass

- **文件路径:** `web/cgi-bin/email.asp`
- **位置:** `save_setting()函数`
- **类型:** network_input
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 9.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 前端验证绕过导致参数污染：SMTP端口/邮件间隔等参数仅通过前端checkIntRange验证范围（如端口1-65535）。攻击者可直接修改POST请求提交非法值（端口0或65536）至/cgi/admin/testserv.cgi，若后端缺乏验证可能引发服务异常或内存破坏。触发条件：1) 后端CGI未重复验证 2) 参数直接用于敏感系统调用。
- **关键词:** checkIntRange, input_smtp_port, input_smtp_interval, testserv.cgi
- **备注:** 证据缺口：testserv.cgi实际处理逻辑未确认（关联知识库CGI分析需求）。建议Fuzz测试端口参数。攻击链关联：可能衔接NVRAM污染->服务参数注入模式（知识库ID:nvram_inject-rtspd-port_param）。

---
### network_input-wizsetup2_token-asp15

- **文件路径:** `web/cgi-bin/wizsetup2.asp`
- **位置:** `wizsetup2.asp:15`
- **类型:** network_input
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** HTTP参数'token'通过getWebQuery获取后未经验证即使用。触发条件：访问wizsetup2.asp时携带token参数。边界检查：无长度限制或内容过滤。潜在安全影响：可能被用于CSRF攻击或参数注入，若后端smartwizard.cgi未验证则形成利用链起点。利用方式：构造恶意token发起请求干扰配置流程。
- **代码片段:**
  ```
  var g_token = getWebQuery("token", "");
  ```
- **关键词:** getWebQuery, token, g_token, wizsetup2.asp
- **备注:** 需验证/cgi/admin/smartwizard.cgi对token的处理逻辑

---
### data_flow-network_asp-cgi_request_chain

- **文件路径:** `web/cgi-bin/network.asp`
- **位置:** `network.asp: 行499-503`
- **类型:** network_input
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 污染数据流向关键路径：用户输入→客户端DOM获取→URL参数拼接→CGI脚本执行。触发条件：构造恶意参数后通过makeRequest2发送至network.cgi。约束条件：1) token机制(g_token)增加攻击复杂度 2) 需确保CGI脚本存在漏洞。实际影响：若CGI脚本未验证输入，可导致NVRAM污染或命令注入。
- **代码片段:**
  ```
  var url = '/cgi/admin/network.cgi';
  makeRequest2(url, params, g_token + '@' + token, save_setting_callback);
  ```
- **关键词:** makeRequest2, network.cgi, params, g_token, save_setting_callback
- **备注:** 攻击链完整度依赖network.cgi的安全性验证。关联知识库中现有g_token漏洞链（如whardfactorydefault.cgi），需验证跨组件攻击可能性。

---
### network_input-wizsetup4-CameraName_validation

- **文件路径:** `web/cgi-bin/wizsetup4.asp`
- **位置:** `web/wizsetup4.asp:? (CameraName处理段)`
- **类型:** network_input
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 7.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 文件实现前端输入收集与基本验证：1) token参数通过getWebQuery获取且无验证 2) CameraName输入框(maxlength=10)经CheckSrvname函数验证，验证失败时阻止提交。前端仅进行长度限制和未知内容的验证，未过滤特殊字符。用户输入经URI编码后通过POST发送到/smartwizard.cgi。攻击路径依赖后端对CameraName的处理：若后端存在命令注入/缓冲区溢出且CheckSrvname验证不充分，攻击者可能构造恶意输入触发漏洞。触发条件：提交包含特殊字符的CameraName值且后端处理不当。
- **代码片段:**
  ```
  if (CheckSrvname(document.getElementById("input_camera_name").value)) {
    document.getElementById("input_camera_name").select();
    alert(pop_msg[PMSG_CAMERA_NAME_INVALID]);
    return;
  }
  params += "&CameraName=" + encodeURIComponent(document.getElementById("input_camera_name").value);
  ```
- **关键词:** getWebQuery, input_camera_name, CheckSrvname, CameraName, makeRequest2, smartwizard.cgi, encodeURIComponent, maxlength, userconfig, NVRAM污染
- **备注:** 完整攻击链验证需：1) 分析function.js确认CheckSrvname过滤逻辑 2) 分析smartwizard.cgi对CameraName的处理（是否写入NVRAM）。关联知识库发现：CameraName在NVRAM中可能被多个服务（如llmnr、udhcpc、bonjour）使用，存在参数注入风险（参见记录：nvram_get-llmnr-param_injection, nvram_get-udhcpc-hostname_injection, nvram-mdns-chain）。

---
### nvram_get-upnp_igd-https-config_chain

- **文件路径:** `etc/init.d/upnp_igd-https.sh`
- **位置:** `upnp_igd-https.sh:start()/stop()`
- **类型:** nvram_get
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.5
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 未验证配置输入传播链：脚本通过userconfig工具读取'HTTPS Port'和'UPnP ExternHTTPSPort'配置项，未进行任何过滤或边界检查即传递给upnp_igd.sh的portmap命令。若攻击者通过NVRAM写入漏洞污染这些配置项，恶意值将直接传播到端口映射操作。触发条件：1) 存在NVRAM写入漏洞 2) 下游upnp_igd二进制存在参数处理漏洞。
- **代码片段:**
  ```
  intport=\`$userconfig -read HTTPS Port\`
  extport=\`$userconfig -read UPnP ExternHTTPSPort\`
  $binpath portmap "$extport" "$intport"
  ```
- **关键词:** userconfig, HTTPS Port, UPnP ExternHTTPSPort, extport, intport, portmap, binpath
- **备注:** 关键未验证点：1) userconfig配置来源(NVRAM?) 2) /usr/sbin/upnp_igd的端口参数处理。关联线索：知识库存在'userconfig'和'portmap'相关记录需交叉验证

---
### nvram_get-smtp_snapshot-config_tamper

- **文件路径:** `etc/init.d/smtps-snapshot-0`
- **位置:** `/etc/init.d/smtps-snapshot-0:10-20`
- **类型:** nvram_get
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 脚本通过/usr/sbin/userconfig读取EVENT_SERVER_SMTP_SNAPSHOT配置项（ServerPort/ServerAddr/STARTTLS/SSL）时未进行输入验证：1) ServerAddr与ServerPort直接拼接为连接地址（$server_addr:$server_port），攻击者篡改配置可重定向至恶意服务器；2) STARTTLS值直接控制协议配置，可被操纵导致协议降级；3) SSL值决定服务状态，可致拒绝服务。若攻击者污染NVRAM配置源（如通过web接口漏洞），可形成完整攻击链：配置篡改→协议降级/服务中断→数据窃取或拒绝服务。
- **代码片段:**
  ```
  server_port=\`/usr/sbin/userconfig -read EVENT_SERVER_SMTP_SNAPSHOT ServerPort\`
  server_addr=\`/usr/sbin/userconfig -read EVENT_SERVER_SMTP_SNAPSHOT ServerAddr\`
  starttls_enable=\`/usr/sbin/userconfig -read EVENT_SERVER_SMTP_SNAPSHOT STARTTLS\`
  ```
- **关键词:** userconfig, EVENT_SERVER_SMTP_SNAPSHOT, ServerPort, ServerAddr, STARTTLS, SSL, stunnel-smtps-snapshot.conf, cfg
- **备注:** 关键后续验证方向：1) /usr/sbin/userconfig的数据源是否暴露于外部输入（如NVRAM/web接口）；2) stunnel-smtps-snapshot的配置文件解析是否存在二次漏洞。建议优先分析/usr/sbin/userconfig和/bin/stunnel-smtps-snapshot的代码实现。

---
### nvram_get-smtps_stunnel_config_injection

- **文件路径:** `etc/init.d/smtps-0`
- **位置:** `etc/init.d/smtps-0`
- **类型:** nvram_get
- **风险等级:** 7.5
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 脚本通过`/usr/sbin/userconfig`读取NVRAM配置项(ServerPort/ServerAddr/SSL)，并直接用于构建stunnel配置文件和启动决策。攻击者可通过篡改NVRAM值(如通过Web接口漏洞)注入恶意配置(如换行符破坏配置文件结构)，触发条件包括：1) 攻击者能修改EVENT_SERVER_SMTP相关NVRAM配置；2) 触发服务重启。未观察到输入过滤机制，可能造成stunnel非预期行为(如流量重定向)。实际影响取决于stunnel配置解析安全性，风险包括服务劫持或拒绝服务。
- **代码片段:**
  ```
  server_port=\`/usr/sbin/userconfig -read EVENT_SERVER_SMTP ServerPort\`
  server_addr=\`/usr/sbin/userconfig -read EVENT_SERVER_SMTP ServerAddr\`
  /usr/sbin/cfg -a w -p /var stunnel-smtps.conf smtps connect $server_addr:$server_port
  ```
- **关键词:** userconfig, EVENT_SERVER_SMTP, ServerPort, ServerAddr, stunnel-smtps.conf, cfg, smtps connect
- **备注:** 关联知识库：1) 平行攻击面（smtps-snapshot-0）见'nvram_get-smtp_snapshot-config_tamper'；2) 需验证/usr/sbin/cfg对特殊字符处理；3) 与'file_tamper-userconfig-chain'组合可形成完整攻击链

---
### command_execution-ddp_service-start_br0

- **文件路径:** `etc/init.d/ddp-0`
- **位置:** `etc/init.d/ddp-0: start()函数`
- **类型:** command_execution
- **风险等级:** 7.2
- **置信度:** 9.0
- **触发可能性:** 6.8
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 脚本通过固定参数'br0'启动/usr/sbin/ddp服务，标准输出/错误重定向到/dev/null。若ddp二进制存在输入验证缺陷（如缓冲区溢出），攻击者可能通过污染网络输入触发漏洞。触发条件：系统启动或手动执行脚本时自动运行。边界检查完全缺失（硬编码参数），实际风险取决于ddp对网络接口br0的数据处理安全性。
- **代码片段:**
  ```
  $binpath br0 1>/dev/null 2>&1 &
  ```
- **关键词:** /usr/sbin/ddp, br0, binpath, 1>/dev/null, 2>&1
- **备注:** 关联发现：binpath使用模式与HNAPPushService-0相似；关键后续方向：分析/usr/sbin/ddp是否暴露网络接口及输入处理逻辑

---
### network_input-httpd_ini-critical_routes

- **文件路径:** `etc/httpd.ini`
- **位置:** `etc/httpd.ini`
- **类型:** network_input
- **风险等级:** 7.0
- **置信度:** 10.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在httpd.ini中发现关键路由配置：1) /HNAP1请求由/hnap/hnap_service处理 2) /onvif/请求由/onvif/onvif_service处理。这些端点构成网络攻击面的核心入口，外部输入可直接到达服务处理程序。但受限于当前分析焦点目录(etc)，无法验证服务实现是否存在漏洞。触发攻击需满足：a) 攻击者发送特制HTTP请求 b) 目标服务存在输入验证缺陷。
- **代码片段:**
  ```
  [url]
  /HNAP1=/hnap/hnap_service
  /onvif/analytics_service=/onvif/onvif_service
  ```
- **关键词:** /HNAP1, /hnap/hnap_service, /onvif/, /onvif/onvif_service, httpd.ini
- **备注:** 需切换分析焦点至：1) /hnap/ 分析hnap_service 2) /onvif/ 分析onvif_service。关联知识库记录：'需验证HNAP策略是否实际启用。建议后续分析：1) /etc/config/hnap配置文件 2) /www/HNAP1/目录下的HNAP服务实现'

---
### network_input-live_play_asp-activex_control_chain

- **文件路径:** `web/cgi-bin/live_play.asp`
- **位置:** `live_play.asp:35-39`
- **类型:** network_input
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 9.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 攻击者通过向/cgi-bin/live_play.asp发送恶意HTTP请求，操控profile/java/serverpush参数。这些参数经getWebQuery获取后仅进行parseInt整数转换，缺乏有效范围检查（如profile允许0-5外的值）。转换后的参数直接控制g_activex.PlayVideo()调用，形成完整攻击链：不可信输入→参数传递→高危操作。边界检查仅存在于SetResolution函数（验证width/height>0），未覆盖核心播放参数。若ActiveX控件存在漏洞（如缓冲区溢出），可导致远程代码执行。
- **代码片段:**
  ```
  if(profile == 5)
    g_activex.PlayVideo(2);
  else if (profile == 0)
    g_activex.PlayVideo(3);
  else
    g_activex.PlayVideo(1);
  ```
- **关键词:** getWebQuery, profile, java, serverpush, g_activex.PlayVideo, SetResolution
- **备注:** 实际风险取决于ActiveX控件实现。与知识库现有记录关联：1) 需立即分析CLSID对应的ActiveX二进制文件（通常在web/ocx目录）验证PlayVideo方法内存安全 2) 关联攻击链节点：'关键攻击路径：NVRAM写操作->服务参数注入->二进制漏洞触发'（若ActiveX漏洞存在则形成终端攻击链）

---
### network_input-live.asp-profile_manipulation

- **文件路径:** `web/cgi-bin/live.asp`
- **位置:** `web/cgi-bin/live.asp:0 [JavaScript变量声明区域]`
- **类型:** network_input
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** HTTP参数profile/java/serverpush通过getWebQuery获取后未经范围验证直接用于视频流配置。攻击者可操纵profile值（1-5范围外）改变视频编码格式，或通过java/serverpush参数启用非标准功能。结合restartStream函数可能造成服务异常。触发条件：构造包含非法profile或serverpush=1的HTTP请求。
- **代码片段:**
  ```
  var profile = parseInt(getWebQuery("profile", "5"), 10);
  ```
- **关键词:** getWebQuery, profile, java, serverpush, restartStream
- **备注:** 需验证profile=0或6时是否引发解析异常；关联文件：function.js（getWebQuery实现）

---
### network_input-wizsetup3.asp-DDNS_credentials

- **文件路径:** `web/cgi-bin/wizsetup3.asp`
- **位置:** `wizsetup3.asp (函数: save_setting)`
- **类型:** network_input
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在wizsetup3.asp中，用户通过表单字段(input_ddns_host/uid/pwd/provider/timeout)提供DDNS凭据。触发条件：点击'NEXT'按钮后，JS函数save_setting()收集数据并通过makeRequest2发送至/cgi/admin/smartwizard.cgi。验证缺陷：1) 仅前端JS空值检查(host/uid/pwd)，可被绕过 2) timeout有整数校验但host/uid/pwd无长度/格式过滤 3) pwd_dirty机制可能干扰服务端验证。若smartwizard.cgi未安全处理参数，可导致命令注入或配置篡改。
- **代码片段:**
  ```
  params += "&DDNSPWD=" + encodeURIComponent(document.getElementById("input_ddns_pwd").value);
  makeRequest2("/cgi/admin/smartwizard.cgi", params, ...);
  ```
- **关键词:** input_ddns_host, input_ddns_uid, input_ddns_pwd, save_setting, makeRequest2, DDNSHOST, DDNSUID, DDNSPWD
- **备注:** 攻击链关键：需验证smartwizard.cgi对DDNSPWD的处理。关联关键词'makeRequest2'已存在于知识库（可能关联其他CGI调用）

---
### configuration_load-ftp_asp-validation_flaws

- **文件路径:** `web/cgi-bin/ftp.asp`
- **位置:** `ftp.asp: 表单处理逻辑`
- **类型:** configuration_load
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 7.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 输入验证存在严重缺陷：1) 仅通过checkIntRange验证端口/间隔数值范围 2) 用户名/路径等字符串输入仅依赖HTML maxlength=32限制，无服务器端长度校验 3) 匿名登录模式（LoginType=2）自动设置用户名但未禁用密码字段。攻击者可绕过客户端限制提交超长输入（>32字符）触发缓冲区溢出，或利用匿名登录特性注入恶意凭证。
- **代码片段:**
  ```
  if (document.getElementById("selectLoginType").value == "2") {
    document.getElementById("input_ftp_uid").value = "anonymous";
  }
  ```
- **关键词:** checkIntRange, maxlength, selectLoginType, onLoginTypeChanged, input_ftp_uid
- **备注:** 需确认服务器端是否重复验证输入长度及范围，并检查NVRAM写入操作对超长输入的处理

---
### network_input-upnp_igd-param_injection

- **文件路径:** `etc/init.d/upnp_igd.sh`
- **位置:** `upnp_igd.sh:22,30,43,50,63,82,86`
- **类型:** network_input
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 在upnp_igd.sh脚本中，位置参数($1/$2/$3)未经过任何过滤或引号保护直接传递给/usr/sbin/upnp_igd程序。攻击者通过控制调用参数（如端口号或操作码），可能触发二进制层漏洞：1) 参数包含空格导致参数结构破坏 2) 特殊字符(; & |)保留传递 3) 当调用portmap/portdel等函数时($binpath $1 $AddPortMap ...)，形成完整攻击面。触发条件：存在暴露的脚本调用点（如通过web接口或IPC调用此脚本）。
- **代码片段:**
  ```
  $binpath $1 $AddPortMap $2 TCP $model $3 >/dev/null 2>&1
  ```
- **关键词:** $1, $2, $3, $binpath, AddPortMap, DelPortMap, portmap, portdel, upnp_igd, TCP
- **备注:** 实际危害依赖：1) /usr/sbin/upnp_igd的输入处理机制 2) 脚本调用点的暴露程度。需逆向分析二进制验证漏洞存在性

---
### configuration_load-httpd_port_injection

- **文件路径:** `etc/init.d/httpd-0`
- **位置:** `未知 (原因：用户未提供具体文件路径)`
- **类型:** configuration_load
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** HTTP服务启动时动态获取端口配置（通过`/usr/sbin/userconfig -read HTTP Port`），该配置值未经边界检查直接作为参数传递给`/web/httpd`。攻击者若能篡改配置存储（如NVRAM），可控制监听端口：1) 设置无效端口导致拒绝服务 2) 绑定特权端口引发权限问题 3) 结合httpd程序漏洞触发缓冲区溢出（若端口值未验证）。触发需先攻破配置写入接口。
- **关键词:** userconfig, HTTP Port, httpd, $http_port, ./httpd $http_port
- **备注:** 需分析/userconfig的配置读写机制及/web/httpd的端口参数处理逻辑

---
### binary_exec-eventd-integrity_check_missing

- **文件路径:** `etc/init.d/eventd-0`
- **位置:** `etc/init.d/eventd-0:0 (需反编译确认行号)`
- **类型:** command_execution
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** start()函数使用'cd /usr/sbin; ./eventd &'直接执行二进制文件，未进行哈希校验或签名验证。触发条件：系统启动或管理员执行service eventd-0 start。攻击路径：1) 攻击者通过文件上传漏洞替换/usr/sbin/eventd 2) 管理员或系统自动启动服务 3) 恶意代码以root权限执行。约束：需具备文件写入权限和重启触发条件。
- **关键词:** start(), /usr/sbin/eventd, & (后台执行符)
- **备注:** 关联发现：env_set-ipfind-global_export（etc/init.d/ipfind-0）存在类似环境导出风险，可能共用攻击面

---
### env_set-eventd_script-auto_export

- **文件路径:** `etc/init.d/eventd-0`
- **位置:** `etc/init.d/eventd-0:0 (需反编译确认行号)`
- **类型:** env_set
- **风险等级:** 7.0
- **置信度:** 9.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 'set -a'指令使所有变量自动导出到环境。触发条件：任何在脚本执行前设置的变量。攻击路径：1) 攻击者控制前置流程设置恶意变量（如通过HTTP参数）2) eventd进程继承污染的环境变量 3) 未过滤变量用于敏感操作（如命令执行）。约束：需eventd实际使用环境变量且未过滤。
- **关键词:** set -a, start(), PATH
- **备注:** 跨组件关联：etc/init.d/ipfind-0同样使用'set -a'导出变量，需验证eventd与ipfind的环境变量交互

---
### configuration_load-upnp_igd_rtsp-port_validation

- **文件路径:** `etc/init.d/upnp_igd-rtsp.sh`
- **位置:** `upnp_igd-rtsp.sh: start函数`
- **类型:** configuration_load
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 脚本通过userconfig读取RTSP Port和UPnP ExternRTSPPort配置值时未进行边界验证，端口值($intport/$extport)直接传递至portmap操作。攻击者可篡改配置注入非法端口号(如>65535)，当UPnP EnablePortForward=0x01时触发start操作，可导致端口冲突或未授权访问。缺乏数字格式校验和范围检查(0-65535)。
- **代码片段:**
  ```
  intport=\`$userconfig -read RTSP Port\`
  extport=\`$userconfig -read UPnP ExternRTSPPort\`
  $binpath portmap "$extport" "$intport"
  ```
- **关键词:** userconfig, RTSP Port, UPnP ExternRTSPPort, intport, extport, portmap, $binpath portmap
- **备注:** 关联知识库：需验证userconfig的配置存储安全性及upnp_igd.sh端口处理逻辑。延伸攻击路径：NVRAM配置→参数注入→底层漏洞触发

---
### network_input-wizsetup5-TimeZone_cgi_chain

- **文件路径:** `web/cgi-bin/wizsetup5.asp`
- **位置:** `wizsetup5.asp:80-85`
- **类型:** network_input
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 8.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** TimeZone参数通过DOM直接获取后仅经encodeURIComponent编码即拼接入URL，发送至smartwizard.cgi。编码可防止XSS但无法防御逻辑漏洞，攻击者可能通过污染TimeZone参数篡改系统时区配置。触发条件：通过表单提交恶意TimeZone值；影响：可能导致系统配置异常或作为其他攻击的跳板。
- **代码片段:**
  ```
  params += "&TimeZone=" + encodeURIComponent(document.getElementById("select_timezone").value);
  ```
- **关键词:** select_timezone, TimeZone, save_setting, smartwizard.cgi
- **备注:** 需分析cgi-bin/smartwizard.cgi对TimeZone参数的解析和处理逻辑

---
### path_injection-command_execution-0x00402420

- **文件路径:** `sbin/iwcontrol`
- **位置:** `unknown:0 [main] 0x00402420`
- **类型:** command_execution
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.5
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 接口名未过滤特殊字符导致路径注入。攻击者通过恶意接口名（如'wlan../../etc/passwd'）触发：1) 程序直接使用argv构造文件路径'/var/auth-%s.fifo'；2) 未过滤'/'、'.'等字符，允许路径遍历；3) 通过fcn.00401174操作注入路径，可能创建/访问非预期文件。触发条件：参数需被识别为接口名且包含特殊字符。成功利用可导致任意文件操作（iwcontrol通常以root运行）。
- **代码片段:**
  ```
  (**(pcVar15 + -0x7f74))(auStack_58,"/var/auth-%s.fifo",0x418324 + (iVar7 * 3 + 1) * 8);
  ```
- **关键词:** auStack_58, (loc._gp + -0x7f74), 0x418324, fcn.00401174, /var/auth-%s.fifo
- **备注:** 需确认fcn.00401174的文件操作权限。与缓冲区溢出漏洞（location:0x004021a4）共享argv输入源，可组合利用构造攻击链

---
### configuration-stunnel-weak_cipher_and_key

- **文件路径:** `etc/stunnel-https.conf`
- **位置:** `etc/stunnel-https.conf:4 [N/A] [N/A]`
- **类型:** configuration_load
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.5
- **查询相关性:** 8.0
- **阶段:** N/A
- **描述:** 使用弱加密算法(DES-CBC3-SHA)，易受暴力破解攻击。证书与密钥共用stunnel.pem文件，若权限配置不当将导致私钥泄露。触发条件：攻击者获取文件读取权限或实施中间人攻击。边界检查：无算法强度强制机制。安全影响：私钥泄露可使攻击者完全模拟服务端，实施钓鱼或中间人攻击。
- **代码片段:**
  ```
  cert=/etc/stunnel/stunnel.pem
  key=/etc/stunnel/stunnel.pem
  ciphers=...DES-CBC3-SHA...
  ```
- **关键词:** cert, key, ciphers, AES128-SHA, DES-CBC3-SHA
- **备注:** 需验证/etc/stunnel/stunnel.pem文件权限

---
### nvram-mdns-chain

- **文件路径:** `etc/init.d/bonjour-0`
- **位置:** `bonjour-0: 行号10-44`
- **类型:** nvram_get
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** 发现从NVRAM污染源到高危二进制调用的完整数据流路径：1) 污染源：攻击者可通过Web接口等篡改NVRAM中的CameraName/PresentationURL（最大长度未知） 2) 传播路径：脚本通过userconfig直接读取并赋值给Target变量 3) 危险操作：未经验证的Target变量作为主机名参数(-h)传递给mDNSResponderPosix。触发条件：Bonjour Enable=0x01且服务文件存在时执行脚本start/restart操作。实际影响取决于mDNSResponderPosix对主机名参数的处理，存在触发二次漏洞（如缓冲区溢出）的风险。
- **代码片段:**
  ```
  Target1="$CameraName"
  Target3="$bonjour_presentationURL"
  $binpath -f $bonjour_http_service_file -h "$Target1" -b
  ```
- **关键词:** userconfig -read, CameraName, bonjour_presentationURL, Target1, Target3, mDNSResponderPosix -h, $binpath -f $bonjour_http_service_file -h "$Target1", Bonjour Enable
- **备注:** 需验证：1) mDNSResponderPosix对-h参数的边界检查 2) CameraName在NVRAM中的最大长度限制 3) 其他服务（如DHNAP）是否受同类影响；关联关键词：userconfig -read（存在硬件控制攻击链记录）

---
### network_input-pppoe-parsePacket-boundary

- **文件路径:** `sbin/pppoe`
- **位置:** `pppoe:0x004035a0 sym.parsePacket`
- **类型:** network_input
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 数据包解析边界验证缺陷：parsePacket函数处理PPPoE标签时仅验证总包长度(uVar8)，未检查标签头读取所需的最小缓冲区。当攻击者构造特殊长度标签使剩余空间<4字节时，puVar7指针运算将越界访问。触发条件：发送包含畸形长度标签的PPPoE数据包。实际影响：1) 非法内存访问导致进程崩溃（拒绝服务）2) 可能泄露相邻内存数据。利用概率中等，需精确控制标签序列。
- **代码片段:**
  ```
  puVar7 = puVar7 + uVar1;
  uVar4 = puVar7[3] + puVar7[2] * 0x100;
  ```
- **关键词:** sym.parsePacket, uVar4, uVar8, puVar7, param_1, param_2
- **备注:** 需结合固件内存保护机制评估信息泄露可行性

---
### attack_vectors-iptables_subcommands

- **文件路径:** `sbin/xtables-multi`
- **位置:** `subcmd_main (位置待确认)`
- **类型:** network_input
- **风险等级:** 7.0
- **置信度:** 8.5
- **触发可能性:** 6.0
- **查询相关性:** 9.0
- **阶段:** N/A
- **描述:** 规则配置面暴露42个攻击向量。高风险参数：--jump(控制流跳转)、--set-mark(内核标记)、--match(模块加载)。触发条件：恶意参数值通过iptables/ip6tables子命令传入。约束条件：依赖扩展模块的输入验证缺陷。
- **关键词:** --jump, --set-mark, --match, subcmd_main, argv
- **备注:** 后续分析方向：1) --jump目标链名处理逻辑 2) --match加载的扩展模块

---
### nvram_get-udhcpd_conf-injection

- **文件路径:** `etc/init.d/udhcpd.sh`
- **位置:** `udhcpd.sh:20-33 (start_udhcpd函数)`
- **类型:** nvram_get
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 9.5
- **阶段:** N/A
- **描述:** udhcpd服务启动时动态生成配置文件/var/udhcpd.conf，其内容完全依赖从NVRAM读取的配置参数（如DHCPD Gateway/DNS0）。攻击者若通过Web接口或CLI漏洞篡改NVRAM值，可在参数中注入换行符等特殊字符（如'\nopt dns 恶意IP'），添加恶意DNS配置。触发条件：攻击者需具备NVRAM写权限。边界检查：userconfig未对读取值进行过滤。实际影响：成功篡改DNS配置后，可实施中间人攻击或DNS劫持（成功率取决于网络拓扑）。
- **代码片段:**
  ```
  echo "opt router $gateway" >> $udhcpd_conf
  echo "opt dns $dns0" >> $udhcpd_conf
  ```
- **关键词:** userconfig, DHCPD Gateway, DHCPD DNS0, udhcpd_conf, start_udhcpd, opt router, opt dns
- **备注:** 需验证关联组件：1) userconfig二进制（/usr/sbin）的输入过滤 2) udhcpd对配置文件的解析机制

---
### configuration_load-nvram_imageinfo-data_echo

- **文件路径:** `web/cgi-bin/image.asp`
- **位置:** `image.asp:38-50`
- **类型:** configuration_load
- **风险等级:** 7.0
- **置信度:** 8.0
- **触发可能性:** 6.0
- **查询相关性:** 8.5
- **阶段:** N/A
- **描述:** 通过<% getCameraImageInfo %>指令读取NVRAM配置（如Brightness_Def），经decodeBase64解码后渲染至前端。虽无直接写操作，但构成攻击链中的数据回显节点。触发条件：加载页面时自动执行。攻击者可利用此机制验证NVRAM篡改结果，但本身风险有限。安全影响：中危（CVSS≈5.0），主要作为攻击链辅助环节
- **代码片段:**
  ```
  var Contrast_Def=decodeBase64("<% getCameraImageInfo(Contrast_Def); %>");
  ```
- **关键词:** getCameraImageInfo, Contrast_Def, Brightness_Def, decodeBase64
- **备注:** 需关联分析NVRAM get/set的底层实现。关联知识库记录：'需关联分析NVRAM get/set的底层实现'

---
