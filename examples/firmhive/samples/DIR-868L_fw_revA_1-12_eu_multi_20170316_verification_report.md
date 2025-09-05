# DIR-868L_fw_revA_1-12_eu_multi_20170316 - 综合验证报告

总共验证了 8 条发现。

---

## 高优先级发现 (4 条)

### 待验证的发现: stack_overflow-httpd-REQUEST_URI_fcn.0000ac10

#### 原始信息
- **文件/目录路径:** `htdocs/fileaccess.cgi`
- **位置:** `fcn.0000ac10:0xac10`
- **描述:** 高危栈溢出漏洞：在fcn.0000ac10函数中，strcat操作未验证总长度是否超出auStack_1038缓冲区（4035字节）。触发条件：1) 攻击者通过HTTP请求控制环境变量（如REQUEST_URI）；2) 污染数据经fcn.0000a480处理；3) 拼接后长度超过4035字节。利用方式：构造超长请求（≈4034字节）覆盖返回地址，实现任意代码执行。程序以root权限运行，成功利用可完全控制设备。
- **代码片段:**\n  ```\n  sym.imp.strcat(*piVar3, piVar3[-1]);\n  ```
- **备注:** 完整攻击链：HTTP请求 → REQUEST_URI污染 → fcn.0000a480处理 → strcat栈溢出 → EIP劫持\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 1) 缓冲区尺寸偏差：实际栈缓冲区auStack_1038为4152字节（0x1038），非报告中的4035字节，但该差异不影响漏洞本质；2) 漏洞链完整：a) REQUEST_URI通过getenv获取（地址0x35bd0） b) 污染数据经fcn.0000a480函数处理 c) strcat操作在0xac24-0xac5c无边界检查；3) 可利用性确认：通过构造4034字节请求（受0xfc2长度检查限制）再追加数据，可覆盖返回地址（位于缓冲区+4156处）；4) 运行权限：程序以root权限执行，成功利用可完全控制设备。

#### 验证指标
- **验证耗时:** 2900.63 秒
- **Token用量:** 1900365

---

### 待验证的发现: path_traversal-http_request_uri_construct

#### 原始信息
- **文件/目录路径:** `htdocs/fileaccess.cgi`
- **位置:** `fcn.0000adbc:0xb188`
- **描述:** 路径遍历漏洞。具体表现：REQUEST_URI直接用于sprintf构造文件路径，未过滤'../'序列。触发条件：在URI中包含路径遍历序列(如'GET /../../etc/passwd')。安全影响：可访问任意文件（读取敏感文件/删除关键文件）。边界检查：完全缺失路径规范化或过滤机制。
- **代码片段:**\n  ```\n  sprintf(file_path, "id=%s", user_input);\n  ```
- **备注:** 形成关键攻击链节点：控制file_path变量后可触发不安全文件操作（见unsafe_file_operation-fileaccess_cgi发现），同类漏洞在其它CGI中已证实可稳定利用\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 基于代码证据链：1) REQUEST_URI环境变量被直接获取并用于路径构造（用户输入完全可控）2) sprintf函数使用'id=%s'格式直接拼接未过滤的用户输入 3) 构造的路径传递至底层文件操作函数 4) 全程缺乏路径规范化或'../'序列过滤机制。攻击者可构造如/../../etc/passwd的URI直接触发任意文件访问。地址差异（0x5cb4 vs 0xb188）不影响漏洞本质，属反编译工具差异。

#### 验证指标
- **验证耗时:** 5768.26 秒
- **Token用量:** 2641527

---

### 待验证的发现: stack_overflow-httpd-REQUEST_URI_fcn.0000ac10

#### 原始信息
- **文件/目录路径:** `htdocs/fileaccess.cgi`
- **位置:** `fcn.0000ac10:0xac10`
- **描述:** 高危栈溢出漏洞：在fcn.0000ac10函数中，strcat操作未验证总长度是否超出auStack_1038缓冲区（4035字节）。触发条件：1) 攻击者通过HTTP请求控制环境变量（如REQUEST_URI）；2) 污染数据经fcn.0000a480处理；3) 拼接后长度超过4035字节。利用方式：构造超长请求（≈4034字节）覆盖返回地址，实现任意代码执行。程序以root权限运行，成功利用可完全控制设备。
- **代码片段:**\n  ```\n  sym.imp.strcat(*piVar3, piVar3[-1]);\n  ```
- **备注:** 完整攻击链：HTTP请求 → REQUEST_URI污染 → fcn.0000a480处理 → strcat栈溢出 → EIP劫持\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 代码分析确认：1) 地址0xac10存在strcat操作(0xac5c)且无长度验证；2) REQUEST_URI通过getenv(0x5bd0)直接获取；3) 数据经fcn.0000a480处理；4) 仅检查REQUEST_URI长度(4034字节)但忽略拼接后长度；5) 4096字节缓冲区可被4034字节请求+≥63字节拼接内容溢出；6) 返回地址覆盖距离4156字节在可控范围；7) root权限运行。实际缓冲区(4096字节)与描述(4035字节)有细微差异，但不影响漏洞本质和可利用性。

#### 验证指标
- **验证耗时:** 1509.74 秒
- **Token用量:** 496760

---

### 待验证的发现: unsafe_file_operation-fileaccess_cgi

#### 原始信息
- **文件/目录路径:** `htdocs/fileaccess.cgi`
- **位置:** `Cross-referenced: fcn.000266d8`
- **描述:** 用户控制路径的不安全文件操作。具体表现：fopen64/unlink等函数直接使用REQUEST_URI派生的路径。触发条件：通过HTTP请求控制文件路径参数。安全影响：实现任意文件读/写/删除。约束条件：依赖路径遍历漏洞突破目录限制，两者结合形成完整攻击链。
- **备注:** 与路径遍历漏洞（path_traversal-http_request_uri_construct）形成叠加风险：路径遍历提供任意路径构造能力，本漏洞执行最终危险操作\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `False`
- **详细原因:** 证据显示：1) REQUEST_URI确实被用于路径构造（如字符串证据）2) fopen64/unlink函数存在 3) 但未观察到REQUEST_URI派生路径直接作为文件操作函数参数的代码证据。知识库验证指出攻击链不完整：路径遍历漏洞（path_traversal）提供目录突破能力，但本文件中的危险文件操作未被证实直接使用该路径。漏洞描述部分准确但未构成完整可验证的漏洞，需反编译fcn.000266d8函数才能最终确认。

#### 验证指标
- **验证耗时:** 10327.69 秒
- **Token用量:** 7758312

---

## 中优先级发现 (4 条)

### 待验证的发现: network_input-explorer-client_validation_flaws

#### 原始信息
- **文件/目录路径:** `htdocs/web/portal/explorer.php`
- **位置:** `explorer.php: JavaScript函数CreateDir()`
- **描述:** 客户端验证存在三处缺陷：1) 正则表达式/[\\/:*?"<>|]/无法过滤Unicode或URL编码字符；2) 首字符空格检查可通过%20绕过；3) 无路径规范化或../检测。触发条件：直接发送恶意Ajax请求。安全影响：可能实现目录遍历攻击（如where=../../../etc）
- **代码片段:**\n  ```\n  var re=/[\\/:*?"<>|]/;\n  if(re.exec(newDirectoryName)) { alert(...); }\n  ```
- **备注:** 验证缺陷可被利用进行路径遍历；需结合后端文件htdocs/web/portal/__ajax_explorer.sgi分析完整攻击链\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `unknown`
- **是否可直接触发:** `unknown`
- **详细原因:** 验证结果：1) 确认前端存在正则表达式过滤缺陷（/[\\/:*?"<>|]/）和首字符空格检查缺陷（indexOf(" ")==0），与发现描述一致 2) 未发现路径规范化或../检测代码，支持缺陷3描述 3) 关键后端文件htdocs/web/portal/__ajax_explorer.sgi为空，导致无法验证攻击链完整性。因此前端缺陷存在但无法确认是否构成真实漏洞，需要后端处理逻辑作为必要证据。

#### 验证指标
- **验证耗时:** 274.50 秒
- **Token用量:** 93398

---

### 待验证的发现: potential_command_injection-upnp-AddPortMapping_NewInternalClient

#### 原始信息
- **文件/目录路径:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **位置:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.AddPortMapping.php`
- **描述:** 潜在命令注入风险：NewInternalClient参数经INET_validv4addr验证后直接拼接到iptables命令（--to-destination参数）。若INET_validv4addr验证不严格（如未过滤特殊字符），攻击者可能注入恶意命令。触发条件：提交包含命令分隔符的伪造IP地址且验证函数存在缺陷。
- **备注:** 关键依赖项INET_validv4addr需单独分析（文件路径：/htdocs/phplib/inet.php）。知识库中已存在关联分析：该函数缺陷可能导致command_injection-upnp-DeletePortMapping漏洞（见notes字段）\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `False`
- **详细原因:** 验证证据：1) 主文件确认NewInternalClient外部输入直接拼接命令（无过滤/转义）2) INET_validv4addr仅验证IP数值范围(1-223)，不检测命令分隔符（允许'127.0.0.1;rm -rf /'通过验证）3) 知识库关联漏洞证明相同缺陷可被利用。漏洞成立但非直接触发：需设备处于router模式激活SHELL_FILE执行路径（需特定系统状态）

#### 验证指标
- **验证耗时:** 1981.65 秒
- **Token用量:** 1370312

---

### 待验证的发现: access_control-upnp-DeletePortMapping-permission_bypass

#### 原始信息
- **文件/目录路径:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.DeletePortMapping.php`
- **位置:** `htdocs/upnpinc/igd/WANIPConn1/ACTION.DO.DeletePortMapping.php:0 (行号未知)`
- **描述:** 权限控制缺失：脚本仅通过`query('/runtime/device/layout')!='router'`检查设备角色，未验证调用者身份。攻击者可在局域网内发送伪造UPnP请求删除任意端口映射，导致：1)拒绝服务(删除合法映射) 2)清除攻击痕迹 3)破坏防火墙规则。触发条件：设备处于router模式且UPnP服务开启。
- **备注:** 漏洞独立存在，但可与命令注入链（knowledge_base_id:command_injection-upnp-DeletePortMapping）组合使用：攻击者先删除日志映射掩盖痕迹，再触发命令注入攻击。\n
#### 验证结论
- **描述准确性:** `accurate`
- **是否为真实漏洞:** `True`
- **是否可直接触发:** `True`
- **详细原因:** 代码证据显示：1) 仅通过设备布局检查(query('/runtime/device/layout'))决定是否处理请求，无调用者身份验证机制；2) 删除操作直接执行iptables命令删除DNAT规则(XNODE_del_entry和fwrite调用)；3) 攻击者只需构造符合协议格式的请求(提供NewRemoteHost/NewExternalPort/NewProtocol参数)即可触发，满足UPnP开启和router模式的条件即可直接利用。漏洞可导致任意端口映射删除，符合拒绝服务、清除痕迹等影响描述。

#### 验证指标
- **验证耗时:** 60.69 秒
- **Token用量:** 12370

---

### 待验证的发现: network_input-IP_Validation-INET_validv4host_buffer

#### 原始信息
- **文件/目录路径:** `htdocs/phplib/inet.php`
- **位置:** `inet.php:34`
- **描述:** 攻击路径2：INET_validv4host函数接收$ipaddr参数时未进行长度检查（最大长度约束缺失）→ 直接传递给ipv4hostid函数 → 超长IP地址字符串可能触发缓冲区溢出。触发条件：上游调用者（如WiFi配置接口）未过滤用户输入长度。潜在影响：远程代码执行或服务拒绝，成功概率取决于ipv4hostid的缓冲区操作实现。
- **代码片段:**\n  ```\n  function INET_validv4host($ipaddr, $mask)\n  {\n      $hostid = ipv4hostid($ipaddr, $mask);\n      ...\n  ```
- **备注:** 关键限制：无法访问fatlady目录验证调用点\n
#### 验证结论
- **描述准确性:** `partially`
- **是否为真实漏洞:** `False`
- **是否可直接触发:** `True`
- **详细原因:** 验证确认：1) INET_validv4host函数确实未对$ipaddr参数进行长度检查（代码片段证实）；2) 上游调用点（如bwc.php）直接使用用户配置输入且未进行长度过滤（调用点代码证实）。但关键限制：无法访问ipv4hostid函数实现，不能确认是否存在缓冲区操作风险。因此描述部分准确（存在未过滤输入路径），但因缺乏核心函数实现证据，无法证实构成真实漏洞。

#### 验证指标
- **验证耗时:** 289.31 秒
- **Token用量:** 93988

---

