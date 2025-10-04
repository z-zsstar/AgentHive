# TD-W8980_V1_150514 - 验证报告 (4 个发现)

---

## 原始信息

- **文件/目录路径：** `etc/group`
- **位置：** `etc/group`
- **描述：** The /etc/group file has world-writable permissions (rwxrwxrwx), allowing any non-root user with login credentials to modify group memberships. This vulnerability can be triggered by simply editing the file using standard text editors or commands. Attackers can add themselves to privileged groups (e.g., root, wheel) to gain elevated privileges. For example, adding to the 'wheel' group might allow sudo access if configured, or adding to the 'root' group could grant access to root-owned files. The exploitation requires the attacker to write to the file and may necessitate a re-login for group changes to take effect, but it is feasible and directly actionable.
- **代码片段：**
  ```
  File permissions: -rwxrwxrwx 1 user user 877 5月  11  2015 group
  Relevant group entries (e.g., root group): root:x:0:root
  wheel group: wheel:x:10:root
  ```
- **备注：** The risk is high due to the direct write capability, but full privilege escalation may depend on ancillary system configurations (e.g., /etc/sudoers). No additional files in the current directory were analyzed, as the task was focused solely on 'group'. Recommend verifying sudo configurations and monitoring for unauthorized group modifications.

## 验证结论

- **描述准确性：** `accurate`
- **是否为真实漏洞：** `True`
- **风险级别：** `High`
- **详细原因：** 警报准确描述了/etc/group文件的世界可写权限（-rwxrwxrwx）和包含特权组（如root和wheel）的内容。攻击者模型是已通过身份验证的本地用户（有登录凭证），因为他们需要写入文件。漏洞可利用性验证：输入可控（攻击者可以使用标准命令或编辑器直接修改文件），路径可达（文件权限允许任何用户写入），实际影响（修改组成员身份可能导致权限提升，例如添加到wheel组可能允许sudo访问）。完整攻击链：1. 攻击者登录系统；2. 使用命令如`echo 'wheel:x:10:root,attacker' >> /etc/group`添加自己到特权组（假设用户名为attacker）；3. 重新登录或使用`newgrp wheel`使组更改生效；4. 如果系统配置（如/etc/sudoers）允许，攻击者可获得提升权限。证据支持所有声明，漏洞真实存在且风险高。

## 验证指标

- **验证时长：** 128.84 秒
- **Token 使用量：** 40040

---

## 原始信息

- **文件/目录路径：** `usr/bin/cwmp`
- **位置：** `bin/cwmp:0x00404974 在函数 parseSetParameterValues（fcn.00404974）中`
- **描述：** 在解析 SOAP SetParameterValues 请求时，函数使用 strncpy 将参数值复制到栈上的小缓冲区中，但未充分验证输入长度，导致栈缓冲区溢出。具体问题出现在处理字符串类型的参数值时：代码使用 strncpy(&uStack_c28, uStack_f30, iVar7)，其中 &uStack_c28 可能指向一个较小的栈缓冲区（可能仅1字节），而 iVar7 是来自输入的可控长度。如果 iVar7 足够大，会覆盖栈上的返回地址或其他关键数据，允许攻击者执行任意代码。触发条件为发送包含长参数值的 SetParameterValues SOAP 请求。潜在利用方式包括覆盖返回地址以控制程序流，在 MIPS 架构上可能通过精心构造的负载实现代码执行。攻击者作为已登录的非 root 用户，可通过网络或本地接口发送恶意请求利用此漏洞。
- **代码片段：**
  ```
  // 相关代码片段从反编译中提取：
  sym.imp.strncpy(&uStack_c28, uStack_f30, iVar7);
  *(*0x74 + iVar7 + -0xc28) = 0;
  sym.imp.xml_unescapeString(&uStack_c28, iVar7 + 1, iVar2);
  // 其中 iVar7 是参数值的长度，来自输入且可控；&uStack_c28 是栈缓冲区地址。
  ```
- **备注：** 此漏洞需要进一步验证以确认可利用性，例如通过动态测试或构建完整攻击负载。建议分析其他相关函数（如 HTTP 请求处理）以确定输入点如何到达此代码路径。此外，检查二进制保护机制（如 ASLR、栈保护）以评估实际利用难度。关联文件可能包括配置文件或网络服务组件。攻击者场景为已登录非 root 用户，可能通过本地网络访问 cwmp 服务。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `Low`
- **详细原因：** 安全警报描述在 strncpy 调用中存在栈缓冲区溢出，但反汇编证据显示：1) 对于字符串类型参数值，目标缓冲区为 sp+0x330，大小 3072 字节（通过 memset 设置）；2) strncpy 使用的长度 s1 来自输入且可控，但 strncpy 最多复制 3072 字节，不会溢出缓冲区；3) 其他 strncpy 调用（如到 sp+0x2c）有长度检查（s2 < 257）或使用足够缓冲区（如 sp+0x130 大小 512 字节）。xml_unescapeString 调用可能因长度 s1+1 过大导致读取溢出，但这不是警报所述的写入溢出，且未证实可利用性。攻击者模型为已登录非 root 用户通过 SOAP 请求发送长参数值，但无证据显示可覆盖返回地址或执行任意代码。因此，漏洞不存在，警报不准确。

## 验证指标

- **验证时长：** 382.95 秒
- **Token 使用量：** 104225

---

## 原始信息

- **文件/目录路径：** `usr/bin/smbd`
- **位置：** `smbd:0x0044b0bc sym.reply_sesssetup_and_X`
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
- **备注：** 漏洞存在于 SMB 会话设置处理的核心路径中，攻击链完整：从网络输入（SMB 请求）到栈溢出。攻击者需要有效登录凭据，但非 root 用户即可利用。建议进一步验证栈布局和缓解措施（如 ASLR、栈保护）的影响，但在嵌入式设备中可能缺乏保护，增加了可利用性。其他分析（如 'file_new'、'execl' 引用和环境变量）未发现完整攻击链，因此未包括。

## 验证结论

- **描述准确性：** `inaccurate`
- **是否为真实漏洞：** `False`
- **风险级别：** `Low`
- **详细原因：** 验证基于汇编代码分析：在地址 0x0044b910-0x0044b93c，代码检查 2 * 输入长度是否小于 256 字节。如果为真且输入长度 > 0，则循环使用输入长度；否则，循环上限被固定为 128。因此，无论输入长度多大，循环最多写入 256 字节，而缓冲区大小为 256 字节，无溢出发生。输入长度来自用户控制的 SMB 请求（偏移 0x33、0x34），但代码逻辑确保不会写入超出缓冲区。攻击者模型为经过身份验证的远程用户，但无法利用此路径实现溢出。PoC 不可行，因为输入长度被硬性限制。

## 验证指标

- **验证时长：** 484.48 秒
- **Token 使用量：** 181272

---

## 原始信息

- **文件/目录路径：** `etc/passwd.bak`
- **位置：** `passwd.bak:1 (文件内容第一行)`
- **描述：** 文件 'passwd.bak' 包含 admin 用户的密码哈希（MD5: $1$$iC.dUsGpxNNJGeOm1dFio/），且文件权限设置为全可读（-rwxrwxrwx），允许任何用户访问。攻击者（非 root 用户）可以读取此文件，提取哈希，并使用离线工具（如 John the Ripper 或 Hashcat）进行字典或暴力破解。一旦哈希被破解，攻击者可以获得 admin 密码，从而提升权限到 root（因为 admin 用户具有 UID 0）。触发条件包括：攻击者拥有文件读取权限、哈希可破解（MD5 较弱），且系统可能使用此哈希进行认证。利用方式涉及简单的文件读取和后续离线攻击，无需额外系统交互。
- **代码片段：**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **备注：** 证据基于文件内容和权限检查。建议进一步验证系统是否实际使用此 'passwd.bak' 文件进行用户认证，或检查相关进程（如登录服务）是否引用此文件。关联文件可能包括 /etc/passwd 或认证模块。后续分析方向：检查系统认证机制和哈希使用情况，以确认可利用性。

## 验证结论

- **描述准确性：** `partially`
- **是否为真实漏洞：** `False`
- **风险级别：** `N/A`
- **详细原因：** 警报准确描述了文件 'etc/passwd.bak' 的存在、全可读权限和敏感内容（admin 用户的 MD5 密码哈希）。攻击者模型为未经身份验证的本地用户（非 root），具有文件系统访问权限，可以读取文件并尝试破解哈希。然而，验证系统是否实际使用此文件进行认证是攻击链的关键部分。证据显示 'etc/passwd' 是符号链接到 '/var/passwd'，但 '/var/passwd' 不存在于当前目录，且未找到其他文件引用 'passwd.bak'，因此无法确认系统使用此哈希进行认证。缺少系统使用证据意味着攻击者无法通过破解哈希提升权限，因此漏洞不实际可利用。攻击载荷（例如：读取文件 'etc/passwd.bak'，提取哈希，使用 John the Ripper 破解）仅在校验系统使用此文件时才有效，但当前证据不支持这一点。

## 验证指标

- **验证时长：** 636.29 秒
- **Token 使用量：** 188974

---

