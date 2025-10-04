# Archer_C20_V1_151120 (10 个发现)

---

### BufferOverflow-cwmp_processConnReq

- **文件/目录路径：** `usr/bin/cwmp`
- **位置：** `cwmp:0x0040b34c sym.cwmp_processConnReq`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** Buffer overflow in HTTP Authorization header parsing in 'cwmp_processConnReq'. The function reads HTTP requests from a socket, parses the Authorization header, and uses strcpy to copy header values into fixed-size stack buffers without bounds checking. Attackers with valid login credentials can send crafted HTTP GET requests with long Authorization header values, overflowing the buffer and potentially overwriting return addresses or critical stack data. This can lead to arbitrary code execution or denial of service. The vulnerability triggers during connection request processing before full authentication, making it accessible to authenticated users. Code logic involves reading input via read() and cwmp_getLine(), then unsafe copying with strcpy.
- **代码片段：**
  ```
  Key code locations from disassembly and decompilation:
  - 0x0040ad78: read(socket_fd, stack_buffer, 0x400)  // Read untrusted HTTP request
  - 0x0040ade8: cwmp_getLine(buffer, 0x200, stack_buffer)  // Parse HTTP lines
  - 0x0040b150: strncpy(temp_buffer, field_value, length)  // Copy field value with limited check
  - 0x0040b34c: strcpy(dest_buffer, temp_buffer)  // Unsafe copy to fixed buffer causing overflow
  ```
- **关键词：** socket_fd, HTTP_Authorization_header, cwmp_processConnReq, cwmp_getLine, auStack_e18, auStack_e7c
- **备注：** Vulnerability verified through static analysis with evidence of unsafe strcpy use. The stack buffers (e.g., auStack_e18 and auStack_e7c) are fixed-size (100 bytes), and overflow is achievable with headers exceeding this size. Further dynamic testing could confirm exploitability, but the attack chain is complete from input to dangerous operation. Associated functions include cwmp_digestCalcHA1 and cwmp_digestCalcResponse for authentication handling.

---
### BufferOverflow-fcn.0040553c

- **文件/目录路径：** `usr/bin/cwmp`
- **位置：** `cwmp:0x0040553c fcn.0040553c`
- **风险评分：** 8.5
- **置信度：** 8.5
- **描述：** Buffer overflow in SOAP SetParameterValues string parameter handling in subfunction fcn.0040553c. When processing SOAP requests to set parameter values, the function uses memcpy to copy string-type parameter values into a fixed-size stack buffer (auStack_c38, 3072 bytes) without checking the length. Attackers can send crafted SOAP SetParameterValues requests with string parameter values exceeding 3071 bytes, causing a stack buffer overflow that may overwrite return addresses and lead to arbitrary code execution. The vulnerability triggers during SOAP message parsing for parameter updates, and exploitation requires authenticated access. Code logic involves parsing ParameterValueStruct elements and directly copying values via memcpy.
- **代码片段：**
  ```
  Key code from decompilation:
  if (parameter_type == 'string') {
      memcpy(auStack_c38, parameter_value, value_length); // value_length not bounded to 3072
      auStack_c38[value_length] = 0; // Null-terminate, but if value_length >= 3072, overflow occurs
  }
  ```
- **关键词：** ParameterList, ParameterValueStruct, Name, Value, string, fcn.0040553c, cwmp_processSetParameterValues
- **备注：** Vulnerability identified in a subfunction called by cwmp_processSetParameterValues. The stack buffer auStack_c38 is 3072 bytes, and memcpy allows unbounded copying. Exploitability is high on MIPS architecture due to predictable stack layouts. Recommend verification through dynamic analysis to confirm EIP control. Associated functions include fcn.00405f2c for parameter validation.

---
### RCE-$.exe

- **文件/目录路径：** `web/js/lib.js`
- **位置：** `lib.js: `$.exe` 函数中的 resolve 函数`
- **风险评分：** 8.0
- **置信度：** 7.5
- **描述：** 函数 `$.exe` 处理 CGI 响应并执行其中的 JavaScript 代码，这可能导致远程代码执行。如果攻击者能控制 CGI 响应内容（例如通过后端注入或恶意配置），他们可以注入任意代码。在 `$.exe` 的解析过程中，如果响应包含 'cgi' 栈，则脚本内容会被收集并通过 `$.script` 执行。触发条件：攻击者能够操纵 CGI 脚本的输出，例如通过修改 NVRAM 变量或利用后端漏洞。利用方式：攻击者通过认证会话发送恶意请求，使后端返回恶意 JavaScript，从而在前端执行。
- **代码片段：**
  ```
  var resolve = function(ret, ds) {
      // ...
      if (stack == "cgi") {
          scripts += lines[i] + '\n';
      }
      // ...
      if (scripts != "") {
          $.script(scripts);
          if ($.ret) {
              ret = $.ret;
              $.err("cgi", ret, unerr);
              break;
          }
          scripts = "";
      }
      // ...
  };
  ```
- **关键词：** $.exe, $.script, CGI 响应, /cgi?
- **备注：** 此漏洞依赖于后端 CGI 脚本的行为。建议分析后端 CGI 脚本以确保输入验证和输出编码。关联文件可能包括其他 CGI 脚本或配置文件。

---
### stack-buffer-overflow-login

- **文件/目录路径：** `usr/sbin/bpalogin`
- **位置：** `bpalogin:sym.login (地址范围基于反编译，具体在循环处理部分)`
- **风险评分：** 8.0
- **置信度：** 7.5
- **描述：** 在 sym.login 函数中，处理网络提取的字符串时，使用 strcspn 和 strncpy 将数据复制到固定大小的栈缓冲区 auStack_d8[200]。如果输入字符串长于 200 字节且不包含 ' ' 或 ',' 字符，strncpy 会溢出缓冲区。随后，代码执行写入操作 `(&stack0xfffff8e8)[iVar5 + 0x640] = 0`，其中 iVar5 基于输入长度，这可能覆盖栈上的返回地址或其他关键数据。触发条件是通过网络认证过程发送恶意数据中的特定字段（字段 0x16），使字符串长度超过 200 字节且无分隔符。潜在利用方式包括覆盖返回地址以控制程序流，执行任意代码。
- **代码片段：**
  ```
  while (iVar5 = strcspn(iStack_6f0, " ,"), iVar5 != 0) {
      strncpy(auStack_d8, iStack_6f0, iVar5);
      (&stack0xfffff8e8)[iVar5 + 0x640] = 0;
      iStack_6f0 = iStack_6f0 + iVar5 + 1;
      ...
  }
  ```
- **关键词：** auStack_d8, iStack_6f0, strcspn, strncpy, sym.extract_valuestring
- **备注：** 需要进一步验证 bpalogin 的运行权限（是否以 root 运行）和实际网络交互。建议测试恶意数据注入以确认可利用性。关联函数包括 sym.receive_transaction 和 sym.extract_valuestring，用于追踪数据流。

---
### XSS-doAddUrl-initUrlTbl

- **文件/目录路径：** `web/main/parentCtrl.htm`
- **位置：** `parentCtrl.htm: doAddUrl() 函数和 initUrlTbl() 函数（具体行号不可用，但代码片段中标识了相关部分）`
- **风险评分：** 7.5
- **置信度：** 9.0
- **描述：** 在 URL 添加功能中存在存储型 XSS 漏洞。攻击者可以在 'urlInfo' 输入字段中输入恶意 JavaScript 代码（例如：<script>alert('XSS')</script>），当用户通过 doAddUrl() 函数添加 URL 时，代码被直接插入到表格的 innerHTML 中（未转义）。在 initUrlTbl() 函数中，所有 URL 再次被插入到 DOM 中，导致脚本在页面加载或查看时执行。触发条件：攻击者登录后访问家长控制页面，输入恶意 URL 并添加；当任何用户（包括管理员）查看该页面时，脚本自动执行。利用方式：窃取会话 cookie、重定向页面或执行未授权操作。漏洞由于缺少输入转义和输出编码。
- **代码片段：**
  ```
  // doAddUrl() 函数中的漏洞代码
  cell.innerHTML = $.id("urlInfo").value; // 直接插入用户输入到 HTML
  // initUrlTbl() 函数中的漏洞代码
  cell.innerHTML = allUrl[i]; // 再次插入未转义的数据
  ```
- **关键词：** urlInfo, doAddUrl, initUrlTbl, urltbl, allUrl
- **备注：** 证据基于文件内容中的代码片段。漏洞可被已验证用户利用，形成完整攻击链（输入→存储→执行）。建议进一步分析后端 CGI 处理（如 /cgi/lanMac）以确认数据持久化影响。关联文件：可能涉及其他 HTML 或 CGI 文件，但当前任务仅限于本文件。

---
### XSS-$.dhtml

- **文件/目录路径：** `web/js/lib.js`
- **位置：** `lib.js: `$.dhtml` 函数定义处`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'lib.js' 中，函数 `$.dhtml` 使用 `innerHTML` 解析字符串并提取执行脚本元素，这可能导致 XSS 漏洞。如果用户控制的输入（如通过 URL 参数或表单数据）被传递给 `$.dhtml` 或相关函数（如 `$.append`、`$.load`）而没有适当消毒，攻击者可以注入恶意脚本。这些脚本将在用户会话上下文中执行，可能导致会话劫持、数据窃取或未授权操作。触发条件包括：用户输入被直接用于动态更新页面内容，且输入包含恶意 HTML 或 JavaScript 代码。利用方式：攻击者构造恶意输入，诱使受害者访问特定页面或执行操作，从而触发脚本执行。
- **代码片段：**
  ```
  dhtml: function(str, hook, midhook) {
      $.div.innerHTML = "div" + str;
      var scripts = [];
      $.chgChd($.div.childNodes, function() {
          if (this.nodeName && this.nodeName.toLowerCase() === "script")
              scripts.push(this);
          else
              hook.call(this);
      });
      if (midhook) midhook();
      $.each(scripts, function() {$.script(this.text || this.textContent || this.innerHTML || "")});
      $.empty($.div);
  }
  ```
- **关键词：** $.dhtml, $.append, $.load, innerHTML
- **备注：** 此漏洞需要用户输入被传递给 `$.dhtml` 或相关函数。建议检查调用这些函数的地方，确保输入消毒。后续分析应追踪用户输入源，如 HTTP 请求参数或 CGI 响应。

---
### PathTraversal-reply_ntcreate_and_X

- **文件/目录路径：** `usr/bin/smbd`
- **位置：** `smbd:0x004354ec sym.reply_ntcreate_and_X`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** A path traversal vulnerability exists in the 'reply_ntcreate_and_X' function (handling SMB NT_CREATE_ANDX requests). The function uses 'srvstr_get_path' to extract file paths from SMB packets but does not adequately sanitize paths containing '..' sequences. This allows an authenticated user to access files outside the intended share directory. The vulnerability is triggered when a malicious SMB request includes a path with traversal sequences, leading to arbitrary file read/write operations. The function 'check_path_syntax' is called but may not block all traversal attempts depending on configuration.
- **代码片段：**
  ```
  // From sym.reply_ntcreate_and_X decompilation
  sym.srvstr_get_path(param_2, acStack_911 + 1, param_2 + *(param_2 + 0x24) * 2 + 0x27, 0x400, 0, 1, &iStack_460, 0);
  // Then uses the path in file operations without sufficient traversal checks
  ```
- **关键词：** SMB command: NT_CREATE_ANDX, Function: sym.reply_ntcreate_and_X, Function: sym.srvstr_get_path, Function: sym.check_path_syntax
- **备注：** This vulnerability requires the attacker to have valid login credentials (non-root user). Exploitation depends on share configuration and permissions. Further validation is needed to confirm if 'check_path_syntax' always blocks traversals in practice. Associated functions: sym.open_file_shared, sym.file_set_dosmode.

---
### BufferOverflow-sym.cli_input_parse

- **文件/目录路径：** `usr/bin/cli`
- **位置：** `0x00404664 sym.cli_input_parse`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** 在 sym.cli_input_parse 函数中，处理 CLI 输入时，正常字符输入有边界检查（限制为 512 字节），但历史记录机制（通过箭头键召回）使用 strcpy-like 函数复制历史字符串到输入缓冲区 param_1，未验证历史字符串长度。如果历史字符串超过 512 字节，将导致缓冲区溢出。触发条件：攻击者作为已登录用户，首先输入一个超长命令（例如，通过 CLI 交互）以填充历史缓冲区，然后使用上/下箭头键召回该命令。潜在攻击：溢出可覆盖栈内存，导致任意代码执行或服务崩溃。利用方式：攻击者精心构造长命令包含 shellcode 或利用返回地址，通过历史召回触发溢出。
- **代码片段：**
  ```
  puVar9 = *(iVar11 * 4 + 0x4269f8);
  if (puVar9 != NULL) {
      puStack_2c = puVar9;
      (**(loc._gp + -0x7dcc))(param_1, puVar9);  // strcpy-like copy without bounds check
      puStack_30 = *0x426a24;
      pcVar13 = *(loc._gp + -0x7ec4);
      *0x426a24 = 0;
      *0x426a20 = 0;
      *0x426a28 = 0;
      uVar4 = (*pcVar13)(puStack_2c);
      puVar7 = puStack_30;
      *0x426a2c = uVar4;
      iVar11 = 0;
      goto code_r0x00404f60;
  }
  ```
- **关键词：** param_1, *0x4269f8, function_ptr_gp_minus_0x7dcc, sym.cli_input_parse, g_cliMsgBuff
- **备注：** 该漏洞需要用户具有 CLI 访问权限和历史记录功能启用。历史缓冲区 *0x4269f8 可能跨会话持久化，增加攻击面。建议进一步分析 sym.cli_parseTab 函数（处理标签完成），可能类似漏洞。关联文件或函数：sym.start_cli（初始化 CLI）、msg_recv（IPC 通信）。后续分析方向：检查历史存储机制和溢出后的控制流劫持可能性。

---
### XSS-virtualServer-init

- **文件/目录路径：** `web/main/virtualServer.htm`
- **位置：** `virtualServer.htm:init 函数中的表格单元格渲染部分（多行，例如在 IP 和 PPP 连接循环中）`
- **风险评分：** 6.5
- **置信度：** 8.5
- **描述：** 存储型跨站脚本（XSS）漏洞存在于 'virtualServer.htm' 文件的表格显示逻辑中。当渲染端口映射规则的 'internalClient' 字段（IP 地址）时，代码直接使用 `innerHTML` 属性而未转义用户输入，允许攻击者注入任意 JavaScript 代码。触发条件：攻击者作为已登录用户添加或编辑端口映射规则时，设置 'internalClient' 为恶意 payload（例如 `<script>alert('xss')</script>`）。当其他用户（包括潜在的管理员）查看该页面时，payload 自动执行。利用方式：攻击者可窃取会话 Cookie、执行未授权操作（如修改配置）或尝试权限提升。漏洞的根源是缺乏输入验证和输出编码，使得用户可控数据被直接插入 DOM。
- **代码片段：**
  ```
  // 示例代码片段来自 IP 连接处理部分
  cell = row.insertCell(-1);
  cell.width = "18%";
  cell.innerHTML = this.internalClient; // 直接使用 innerHTML 而未转义
  
  // 类似代码在 PPP、L2TP、PPTP 连接处理中重复出现
  ```
- **关键词：** WAN_IP_CONN_PORTMAPPING, WAN_PPP_CONN_PORTMAPPING, WAN_L2TP_CONN_PORTMAPPING, WAN_PPTP_CONN_PORTMAPPING, internalClient
- **备注：** 该漏洞需要攻击者具有配置端口映射的权限，但作为已登录用户，这可能默认允许。攻击链完整：输入点（internalClient 设置）→ 数据流（存储到 NVRAM 并检索）→ 触发点（页面渲染）。建议后续验证后端是否对 internalClient 输入有过滤，并检查其他类似字段（如名称字段）是否也存在 XSS。关联文件：vtlServEdit.htm（用于编辑规则）可能包含相关输入处理逻辑。

---
### XSS-$.cgi

- **文件/目录路径：** `web/js/lib.js`
- **位置：** `lib.js: `$.cgi` 函数定义处`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 函数 `$.cgi` 构造 URL 和查询参数时使用 `$.toStr` without encoding，可能反射用户输入到响应中。如果后端 CGI 脚本反射这些参数而没有消毒，可能导致 XSS 或代码执行。在 `$.cgi` 中，`path` 和 `arg` 被用于构建请求，响应可能通过 `$.io` 以脚本形式执行。触发条件：用户输入被作为 `arg` 传递给 `$.cgi`，且后端反射该输入。利用方式：攻击者注入恶意脚本到参数中，当响应被处理时执行。
- **代码片段：**
  ```
  cgi: function(path, arg, hook, noquit, unerr) {
      if ($.local || $.sim) path = $.params;
      else path = (path ? path : $.curPage.replace(/\.htm$/, ".cgi")) + (arg ? "?" + $.toStr(arg, "=", "&") : "");
      // ...
      var ret =  $.io(path, true, func, null, noquit, unerr);
      // ...
  }
  ```
- **关键词：** $.cgi, $.toStr, $.io, CGI 参数
- **备注：** 需要后端 CGI 脚本实际反射用户输入。建议验证具体 CGI 脚本的实现。后续分析应关注 CGI 脚本文件。

---
