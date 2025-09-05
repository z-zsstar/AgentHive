# DIR-895L_fw_revA_1-13_eu_multi_20170113 - 综合验证报告

总共验证了 10 条发现。

---

## 高优先级发现 (3 条)

### 待验证的发现: command_execution-init_scripts-rcS_Swildcard

#### 原始信息
- **文件/目录路径:** `etc/init.d/rcS`
- **位置:** `etc/init.d/rcS:5`
- **描述:** rcS 作为系统初始化主控脚本，无条件执行 /etc/init.d/ 目录下所有 S 开头的服务脚本。这些脚本可能包含网络服务、特权操作等攻击入口点。触发条件为系统启动时自动执行，无输入验证机制。潜在风险在于：攻击者可通过植入恶意服务脚本或篡改现有脚本实现持久化攻击。
- **代码片段:**\n  ```\n  for i in /etc/init.d/S??* ;do\n  	[ ! -f "$i" ] && continue\n  	$i\n  done\n  ```
- **备注:** 需后续分析被启动的 /etc/init.d/S* 脚本（如 S80httpd）和非常规路径 /etc/init0.d/rcS 以追踪攻击链\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 1) 代码验证：在 etc/init.d/rcS 中确认存在无条件执行 /etc/init.d/S??* 脚本的循环逻辑，与发现描述完全一致；2) 风险验证：执行过程无输入验证/沙箱机制，攻击者可通过植入恶意脚本实现持久化攻击；3) 触发机制：漏洞依赖系统启动时自动触发，但需攻击者先获得文件写入权限（如通过其他漏洞），故非直接触发。

#### 验证指标
- **验证耗时:** 227.25 秒
- **Token用量:** 170735

---

### 待验证的发现: command_injection-usbmount-event_command

#### 原始信息
- **文件/目录路径:** `etc/scripts/usbmount_helper.sh`
- **位置:** `usbmount_helper.sh:10,14,16,24`
- **描述:** 命令注入漏洞 - 外部输入的$dev和$suffix参数直接拼接到event命令执行环境（如'event MOUNT.$suffix add "usbmount mount $dev"'）。攻击者通过恶意USB设备名（如'dev=sda;rm -rf /'）可注入任意命令。触发条件：USB设备挂载/卸载时内核传递污染参数。边界检查：完全缺失特殊字符过滤。安全影响：获得root权限shell（脚本以root运行），可执行任意系统命令。
- **代码片段:**\n  ```\n  event MOUNT.$suffix add "usbmount mount $dev"\n  event FORMAT.$suffix add "phpsh /etc/events/FORMAT.php dev=$dev action=try_unmount counter=30"\n  ```
- **备注:** 需验证event命令执行环境是否通过shell解释命令字符串。关联文件：/etc/events/FORMAT.php。关联知识库记录：command_execution-IPV4.INET-dev_attach-xmldbc_service（文件：etc/scripts/IPV4.INET.php）\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 验证发现：
1. 准确部分：代码片段确实存在（usbmount_helper.sh:16），$dev参数未过滤直接拼接，脚本以root运行
2. 存疑部分：
   - 未找到event可执行文件，无法确认命令是否通过shell解释（关键证据缺失）
   - 未定位到调用脚本的源头，无法完全确认$2/$3参数是否来自外部USB设备名
   - FORMAT.php存在二次注入但非直接触发点
3. 漏洞评估：
   - 危险代码存在构成潜在漏洞
   - 但触发需要满足：a)参数来源外部可控 b)event通过shell执行命令
   - 当前证据不足以证明完整攻击链可实现，故评为非直接触发

#### 验证指标
- **验证耗时:** 451.76 秒
- **Token用量:** 399235

---

### 待验证的发现: env_get-telnetd-unauthenticated_access

#### 原始信息
- **文件/目录路径:** `etc/init0.d/S80telnetd.sh`
- **位置:** `S80telnetd.sh:7`
- **描述:** 当环境变量entn=1时启动无认证telnetd服务（telnetd -i br0）。攻击者可通过控制环境变量（如通过nvram设置）触发，开启无认证root shell访问。关键触发条件：1) 外部输入能设置entn=1 2) 服务启动参数未校验来源。潜在影响：远程获取root权限。
- **代码片段:**\n  ```\n  if [ "$1" = "start" ] && [ "$entn" = "1" ]; then\n  	telnetd -i br0 -t 99999999999999999999999999999 &\n  ```
- **备注:** 需验证entn环境变量控制机制（如通过web接口/nvram）。关联发现：xmldbc在S45gpiod.sh中处理NVRAM配置（/device/router/wanindex）\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 验证确认漏洞代码存在（当entn=1时启动无认证telnetd），但缺乏关键证据证明触发机制可被外部控制：1) entn变量来自ALWAYS_TN，但未发现ALWAYS_TN的设置点；2) 关联文件S45gpiod.sh不存在；3) 全系统搜索未找到web接口/NVRAM与ALWAYS_TN的关联代码；4) devdata工具的实现逻辑未知。漏洞利用需满足两个独立条件（设置entn=1+服务启动），且未发现完整攻击链。

#### 验证指标
- **验证耗时:** 1493.57 秒
- **Token用量:** 1059808

---

## 中优先级发现 (4 条)

### 待验证的发现: NVRAM_Pollution-FirmwareResetChain-S22mydlink

#### 原始信息
- **文件/目录路径:** `etc/init.d/S22mydlink.sh`
- **位置:** `etc/init.d/S22mydlink.sh:10-22`
- **描述:** NVRAM污染触发固件重置链。当dev_uid未设置时，脚本通过devdata获取lanmac值生成新uid。若攻击者篡改lanmac（如通过未授权API），mydlinkuid处理污染数据后：1) 执行erase_nvram.sh（疑似全配置擦除）2) 强制系统重启。边界检查仅验证空值，未校验MAC格式/长度。触发条件：首次启动或dev_uid被清除时执行本脚本。实际影响：拒绝服务+配置清零。
- **代码片段:**\n  ```\n  mac=\`devdata get -e lanmac\`\n  uid=\`mydlinkuid $mac\`\n  devdata set -e dev_uid=$uid\n  /etc/scripts/erase_nvram.sh\n  reboot\n  ```
- **备注:** 关键依赖验证：1) lanmac需外部可控（未验证）2) erase_nvram.sh功能未确认。关联分析建议：逆向/sbin/devdata和/etc/scripts/erase_nvram.sh\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 验证结果：1) 准确性部分成立 - 脚本逻辑存在但关键工具缺失导致无法验证lanmac污染路径和边界检查（原描述中'未校验MAC格式/长度'无法证实）2) 漏洞存在 - 基于S22mydlink.sh逻辑，若lanmac可被污染则必然触发擦除和重启 3) 非直接触发 - 依赖首次启动/dev_uid清除状态且需lanmac污染能力（未验证）。遗留问题：devdata获取机制和mydlinkuid边界检查因文件缺失无法分析。

#### 验证指标
- **验证耗时:** 534.25 秒
- **Token用量:** 503696

---

### 待验证的发现: network_input-httpcfg-port_boundary

#### 原始信息
- **文件/目录路径:** `etc/services/HTTP.php`
- **位置:** `HTTP/httpcfg.php (端口输出位置)`
- **描述:** HTTP端口设置缺乏边界检查：httpcfg.php中`$port`变量（来源：/runtime/services/http/server节点）未经范围验证直接输出到配置。触发条件：当该节点值被污染为非法端口（如0或65536）。边界检查：完全缺失。实际影响：httpd服务启动失败（拒绝服务）。利用方式：通过NVRAM写入漏洞或配置接口注入非法端口值。
- **备注:** 需验证httpd对非法端口的容错能力；关联限制：未分析httpd服务组件\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 1) 边界检查缺失被确认：HTTP.php中端口值直接输出且无范围验证（CWE-1287）；2) 服务崩溃影响成立：非法端口导致httpd启动失败（拒绝服务）；3) 直接触发特性成立：一旦非法端口写入配置，服务重启即崩溃；4) 不完整验证：污染路径（NVRAM/配置接口）受分析范围限制未验证，完整利用链依赖外部漏洞存在。

#### 验证指标
- **验证耗时:** 655.58 秒
- **Token用量:** 594893

---

### 待验证的发现: parameter_processing-usbmount-argv

#### 原始信息
- **文件/目录路径:** `etc/scripts/usbmount_helper.sh`
- **位置:** `usbmount_helper.sh:3-8`
- **描述:** 参数处理边界缺失 - 所有命令行参数($1-$5)未进行长度校验和内容过滤（如'suffix="`echo $2|tr "[a-z]" "[A-Z]"`$3"'）。攻击者传递超长参数（>128KB）可导致环境变量溢出，或构造复合攻击链。触发条件：脚本调用时传入恶意参数。边界检查：无长度限制和内容过滤机制。安全影响：破坏脚本执行环境或作为其他漏洞的触发媒介。
- **代码片段:**\n  ```\n  suffix="\`echo $2|tr "[a-z]" "[A-Z]"\`$3"\n  if [ "$3" = "0" ]; then dev=$2; else dev=$2$3; fi\n  ```
- **备注:** 需审查调用此脚本的父进程（如udev/hotplug）的参数传递机制。建议后续分析：/etc/hotplug.d/block目录下的触发脚本\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 1) 代码片段验证：usbmount_helper.sh第3-8行确实存在未过滤的参数使用，与发现描述一致；2) 参数源分析：参数来自内核生成的设备名（如/dev/sda1），攻击者无法控制超长输入（内核限制设备名长度）；3) 影响评估：虽存在边界缺失，但因参数源受限，无法构造>128KB输入，环境变量溢出不可行；4) 攻击链断裂：未发现其他可注入参数的调用路径，复合攻击链不成立

#### 验证指标
- **验证耗时:** 1015.55 秒
- **Token用量:** 858761

---

### 待验证的发现: path_traversal-svchlper-script_injection

#### 原始信息
- **文件/目录路径:** `etc/services/svchlper`
- **位置:** `sbin/svchlper:4,8,9,10,16`
- **描述:** 服务名参数$2未过滤导致路径遍历漏洞：1) L4的文件存在检查`[ ! -f /etc/services/$2.php ]`可通过`$2="../malicious"`绕过；2) L9的xmldbc调用生成`/var/servd/$2_{start,stop}.sh`时未验证路径合法性；3) L8/L10/L16直接执行生成的脚本文件。触发条件：攻击者能控制svchlper的$2参数值。约束条件：a)/etc/services目录外需存在可控.php文件；b)/var/servd目录需有写权限。潜在影响：通过路径遍历实现任意脚本写入与执行，可能导致设备完全控制。利用方式：构造恶意$2参数注入路径遍历序列（如`../../tmp/exploit`）。
- **代码片段:**\n  ```\n  [ ! -f /etc/services/$2.php ] && exit 108\n  xmldbc -P /etc/services/$2.php -V START=/var/servd/$2_start.sh\n  sh /var/servd/$2_start.sh > /dev/console\n  ```
- **备注:** 需验证：1) svchlper调用者及$2参数来源（关联知识库记录：nvram_get-gpiod-param-injection中的wanindex设置）；2)/etc/services目录边界；3)/var/servd目录权限。关键溯源方向：检查gpiod是否通过IPC传递参数影响$2。\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 1) 代码逻辑验证：确认svchlper脚本中$2参数未过滤，存在路径遍历和脚本注入风险（证据：文件分析结果）；2) 触发条件未验证：知识库查询显示gpiod未向svchlper传递$2参数，无法证明攻击者能控制该参数（关键触发条件缺失）；3) 约束条件未验证：受工具限制无法检查/var/servd目录权限（写权限约束未证实）；4) 综合评估：漏洞理论存在但实际可利用性不成立，因核心触发路径和约束条件均未满足证据要求。

#### 验证指标
- **验证耗时:** 1142.60 秒
- **Token用量:** 912825

---

## 低优先级发现 (3 条)

### 待验证的发现: start_param_handling-S41event-2

#### 原始信息
- **文件/目录路径:** `etc/init0.d/S41event.sh`
- **位置:** `S41event.sh:3`
- **描述:** 脚本通过位置参数$1接收输入（如'start'），仅用于条件分支判断。触发条件：系统启动时传入参数。安全影响：低，因参数未传递到危险操作且比较值硬编码。
- **代码片段:**\n  ```\n  if [ "$1" = "start" ]; then\n  ```

#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 1) 参数$1仅用于if条件比较和echo输出，比较值'start'为硬编码字符串；2) $1未传递到任何event命令或子脚本中，所有命令参数均为固定字符串；3) 无危险操作（如命令注入或敏感文件操作）依赖$1；4) 即使触发条件满足（系统启动传入'start'），也只能执行预设的安全命令，无法被利用。

#### 验证指标
- **验证耗时:** 78.48 秒
- **Token用量:** 33901

---

### 待验证的发现: access_control-WEBACCESS-static_config

#### 原始信息
- **文件/目录路径:** `etc/services/WEBACCESS.php`
- **位置:** `WEBACCESS.php:? (setup_wfa_account & webaccesssetup) ?`
- **描述:** 访问控制通过静态配置实现：1) 账户权限基于/webaccess/account/entry的permission字段(rw/ro) 2) 服务启用状态检查/webaccess/enable。未发现动态权限校验缺陷，但配置错误可能导致未授权访问。触发条件：权限配置错误或NVRAM篡改。
- **代码片段:**\n  ```\n  foreach("entry")\n  {\n    $rw = query("permission");\n  }\n  if ($webaccess != 1) { http_error("8"); }\n  ```

#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 1) 权限验证逻辑确认：在setup_wfa_account函数中，明确遍历'/webaccess/account/entry'并读取permission字段（rw/ro）分配权限
2) 服务启用检查确认：webaccesssetup函数中通过query("/webaccess/enable")获取配置值，并在$webaccess!=1时调用http_error("8")
3) 构成真实漏洞：静态配置机制在权限配置错误时可导致未授权访问（如普通账户获得rw权限）
4) 非直接触发：需要满足配置错误或底层存储（如NVRAM）篡改的前提条件，无远程直接利用路径
5) 证据支撑：实际代码片段验证发现描述的所有关键点（权限字段读取、服务状态检查、错误处理）

#### 验证指标
- **验证耗时:** 448.62 秒
- **Token用量:** 390847

---

### 待验证的发现: command_execution-IPV4.INET-dev_attach-xmldbc_service

#### 原始信息
- **文件/目录路径:** `etc/scripts/IPV4.INET.php`
- **位置:** `IPV4.INET.php:dev_attach()/dev_detach()`
- **描述:** 危险固件交互：通过xmldbc直接操作数据库（'xmldbc -t kick_alias'）并重启服务（service DHCPS4）。若参数被污染，可导致固件拒绝服务或权限提升。
- **代码片段:**\n  ```\n  echo "xmldbc -t kick_alias:30:\"sh ".$kick_alias_fn."\" \\n";\n  echo "service DHCPS4.".$_GLOBALS["INF"]." restart\\n";\n  ```
- **备注:** 需结合参数污染才能触发，建议审计xmldbc的安全机制\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 1. 准确性验证：代码片段位置与描述完全匹配（dev_attach行175的kick_alias调用，dev_detach行75的服务重启）；2. 漏洞存在：$_GLOBALS['INF']参数无过滤且可被外部污染（仅空值检查），通过构造';malicious_command;'类payload可实现命令注入；3. 非直接触发：需先污染全局变量（需其他攻击面），且依赖xmldbc与服务重启机制。风险等级7.0合理：攻击向量为网络远程污染，影响可达权限提升。

#### 验证指标
- **验证耗时:** 1599.53 秒
- **Token用量:** 1087963

---

