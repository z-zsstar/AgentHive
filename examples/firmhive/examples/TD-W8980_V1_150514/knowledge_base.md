# TD-W8980_V1_150514 (4 个发现)

---

### permission-etc-group

- **文件/目录路径：** `etc/group`
- **位置：** `etc/group`
- **风险评分：** 8.5
- **置信度：** 8.0
- **描述：** The /etc/group file has world-writable permissions (rwxrwxrwx), allowing any non-root user with login credentials to modify group memberships. This vulnerability can be triggered by simply editing the file using standard text editors or commands. Attackers can add themselves to privileged groups (e.g., root, wheel) to gain elevated privileges. For example, adding to the 'wheel' group might allow sudo access if configured, or adding to the 'root' group could grant access to root-owned files. The exploitation requires the attacker to write to the file and may necessitate a re-login for group changes to take effect, but it is feasible and directly actionable.
- **代码片段：**
  ```
  File permissions: -rwxrwxrwx 1 user user 877 5月  11  2015 group
  Relevant group entries (e.g., root group): root:x:0:root
  wheel group: wheel:x:10:root
  ```
- **关键词：** /etc/group
- **备注：** The risk is high due to the direct write capability, but full privilege escalation may depend on ancillary system configurations (e.g., /etc/sudoers). No additional files in the current directory were analyzed, as the task was focused solely on 'group'. Recommend verifying sudo configurations and monitoring for unauthorized group modifications.

---
### 无标题的发现

- **文件/目录路径：** `usr/bin/cwmp`
- **位置：** `bin/cwmp:0x00404974 在函数 parseSetParameterValues（fcn.00404974）中`
- **风险评分：** 8.0
- **置信度：** 8.0
- **描述：** 在解析 SOAP SetParameterValues 请求时，函数使用 strncpy 将参数值复制到栈上的小缓冲区中，但未充分验证输入长度，导致栈缓冲区溢出。具体问题出现在处理字符串类型的参数值时：代码使用 strncpy(&uStack_c28, uStack_f30, iVar7)，其中 &uStack_c28 可能指向一个较小的栈缓冲区（可能仅1字节），而 iVar7 是来自输入的可控长度。如果 iVar7 足够大，会覆盖栈上的返回地址或其他关键数据，允许攻击者执行任意代码。触发条件为发送包含长参数值的 SetParameterValues SOAP 请求。潜在利用方式包括覆盖返回地址以控制程序流，在 MIPS 架构上可能通过精心构造的负载实现代码执行。攻击者作为已登录的非 root 用户，可通过网络或本地接口发送恶意请求利用此漏洞。
- **代码片段：**
  ```
  // 相关代码片段从反编译中提取：
  sym.imp.strncpy(&uStack_c28, uStack_f30, iVar7);
  *(*0x74 + iVar7 + -0xc28) = 0;
  sym.imp.xml_unescapeString(&uStack_c28, iVar7 + 1, iVar2);
  // 其中 iVar7 是参数值的长度，来自输入且可控；&uStack_c28 是栈缓冲区地址。
  ```
- **关键词：** SOAP SetParameterValues 请求, ParameterValue 参数, cwmp 服务网络接口
- **备注：** 此漏洞需要进一步验证以确认可利用性，例如通过动态测试或构建完整攻击负载。建议分析其他相关函数（如 HTTP 请求处理）以确定输入点如何到达此代码路径。此外，检查二进制保护机制（如 ASLR、栈保护）以评估实际利用难度。关联文件可能包括配置文件或网络服务组件。攻击者场景为已登录非 root 用户，可能通过本地网络访问 cwmp 服务。

---
### info-leak-passwd.bak

- **文件/目录路径：** `etc/passwd.bak`
- **位置：** `passwd.bak:1 (文件内容第一行)`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 文件 'passwd.bak' 包含 admin 用户的密码哈希（MD5: $1$$iC.dUsGpxNNJGeOm1dFio/），且文件权限设置为全可读（-rwxrwxrwx），允许任何用户访问。攻击者（非 root 用户）可以读取此文件，提取哈希，并使用离线工具（如 John the Ripper 或 Hashcat）进行字典或暴力破解。一旦哈希被破解，攻击者可以获得 admin 密码，从而提升权限到 root（因为 admin 用户具有 UID 0）。触发条件包括：攻击者拥有文件读取权限、哈希可破解（MD5 较弱），且系统可能使用此哈希进行认证。利用方式涉及简单的文件读取和后续离线攻击，无需额外系统交互。
- **代码片段：**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **关键词：** passwd.bak
- **备注：** 证据基于文件内容和权限检查。建议进一步验证系统是否实际使用此 'passwd.bak' 文件进行用户认证，或检查相关进程（如登录服务）是否引用此文件。关联文件可能包括 /etc/passwd 或认证模块。后续分析方向：检查系统认证机制和哈希使用情况，以确认可利用性。

---
### 无标题的发现

- **文件/目录路径：** `usr/bin/smbd`
- **位置：** `smbd:0x0044b0bc sym.reply_sesssetup_and_X`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在函数 'reply_sesssetup_and_X' 中处理 SMB 会话设置请求时，存在栈缓冲区溢出漏洞。具体表现：当请求数据的第一个字节不是 'N'、'`' 或 0xa1 时，会进入十六进制编码路径，使用固定大小的栈缓冲区（256 字节）。输入数据长度（iStack_788）来自用户控制的 SMB 请求字段（如 param_2 偏移 0x33、0x34），且没有充分验证其大小。如果输入数据长度大于 128 字节，十六进制编码循环会写入超过缓冲区边界（例如，长度为 129 时，写入索引 0 到 257，而缓冲区大小仅为 256 字节），导致栈溢出，可能覆盖返回地址或其他关键数据。触发条件：攻击者发送 SMB 会话设置请求，其中数据部分长度大于 128 字节且第一个字节不符合特定值。约束和边界检查：代码缺乏对输入数据长度的严格验证，仅通过循环条件检查，但缓冲区大小固定。潜在攻击和利用方式：攻击者可通过精心构造的溢出数据覆盖返回地址，控制程序执行流，实现任意代码执行。利用概率高，因为攻击者只需有效登录凭据即可发送恶意请求。
- **代码片段：**
  ```
              sym.imp.memset(&uStack_45c,0,0x100);
              iVar15 = 0x80;
              if ((0xff < iStack_788 << 1) || (iVar15 = iStack_788, 0 < iStack_788)) {
                  pcVar11 = &uStack_45c + 1;
                  iVar6 = 0;
                  do {
                      if (pcStack_78c[iVar6] >> 4 < 10) {
                          cVar4 = '0';
                      }
                      else {
                          cVar4 = 'W';
                      }
                      pcVar11[-1] = cVar4 + (pcStack_78c[iVar6] >> 4);
                      cVar4 = 'W';
                      if ((pcStack_78c[iVar6] & 0xfU) < 10) {
                          cVar4 = '0';
                      }
                      *pcVar11 = cVar4 + (pcStack_78c[iVar6] & 0xf);
                      iVar6 = iVar6 + 1;
                      pcVar11 = pcVar11 + 2;
                  } while (iVar6 < iVar15);
              }
              uStack_35d = 0;
  ```
- **关键词：** SMB 请求数据字段（如 param_2 偏移 0x33、0x34 的长度字段）, pcStack_78c（输入数据指针）, iStack_788（输入数据长度）
- **备注：** 漏洞存在于 SMB 会话设置处理的核心路径中，攻击链完整：从网络输入（SMB 请求）到栈溢出。攻击者需要有效登录凭据，但非 root 用户即可利用。建议进一步验证栈布局和缓解措施（如 ASLR、栈保护）的影响，但在嵌入式设备中可能缺乏保护，增加了可利用性。其他分析（如 'file_new'、'execl' 引用和环境变量）未发现完整攻击链，因此未包括。

---
