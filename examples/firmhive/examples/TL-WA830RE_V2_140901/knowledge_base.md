# TL-WA830RE_V2_140901 (2 个发现)

---

### CommandInjection-wpa_cli_event_handler

- **文件/目录路径：** `sbin/wpa_cli`
- **位置：** `wpa_cli:0x405188 in function fcn.00405224`
- **风险评分：** 7.0
- **置信度：** 8.0
- **描述：** A command injection vulnerability exists in wpa_cli's event handler function. When processing events from wpa_supplicant, if the event string contains 'CONNECTED', the function extracts the substring after 'CONNECTED' and passes it directly to the 'system' function without validation. This allows an attacker to execute arbitrary commands by crafting a malicious SSID or other network parameter that includes 'CONNECTED' followed by a command. For example, setting the SSID to 'CONNECTED; malicious_command' via the 'set_network' command and triggering a connection would cause wpa_supplicant to send an event string containing 'CONNECTED; malicious_command', leading to command execution when processed by wpa_cli. The vulnerability is triggered under normal usage conditions where users configure networks and establish connections.
- **代码片段：**
  ```
  iVar4 = strstr(pcVar11, "CONNECTED");
  if (iVar4 != 0) {
      pcVar5 = strdup(iVar4 + 4);
      // ... 
      system(pcVar5);
  }
  ```
- **关键词：** wpa_supplicant event strings, SSID variable set via set_network command, NVRAM/ENV variables for network configuration
- **备注：** The attack requires the attacker to have valid login credentials and the ability to configure network settings using wpa_cli commands. The vulnerability was identified through static code analysis; dynamic testing could further validate exploitability. Additional review of wpa_supplicant event handling may reveal related issues. The 'echo' string found in the binary ('echo "====status from supplicant===: %s\n" > /dev/ttyS0') was not directly linked to this vulnerability but should be investigated for other potential command injection points.

---
### BufferOverflow-iwlist-scanning

- **文件/目录路径：** `sbin/iwlist`
- **位置：** `iwlist:0x00403b78 fcn.00403b78 (scanning command handler)`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** A buffer overflow vulnerability exists in the 'iwlist' binary's scanning command handler when processing the 'essid' option. User-provided input for the essid is copied into a fixed-size stack buffer (296 bytes) using strncpy with the length set to the string length (strlen). This can result in buffer overflow if the input exceeds 296 bytes, as strncpy does not null-terminate the destination when the source length is greater than or equal to the specified count. The lack of null termination may cause subsequent string operations to read beyond the buffer, leading to information disclosure or further memory corruption. Under specific conditions, an attacker could overwrite stack variables, including the return address, to achieve arbitrary code execution. The vulnerability is triggered by running 'iwlist scanning essid <long_string>' where <long_string> is longer than 296 bytes. Potential attacks include local code execution by a non-root user, which could be leveraged for further exploitation if combined with other vulnerabilities.
- **代码片段：**
  ```
  // From decompilation at ~0x00403c00 in fcn.00403b78
  uStack_3cf = (**(loc._gp + -0x7f2c))(pcVar10); // strlen(pcVar10) where pcVar10 is user input
  (**(loc._gp + -0x7ef0))(auStack_3bc, pcVar10, uStack_3cf); // strncpy(auStack_3bc, pcVar10, uStack_3cf)
  // auStack_3bc is a stack buffer of 296 bytes
  ```
- **关键词：** command-line argument 'essid', scanning command
- **备注：** The binary has permissions -rwxrwxrwx, allowing execution by any user. While the vulnerability is present and exploitable for arbitrary code execution, it does not directly lead to privilege escalation as the binary is not setuid. Further analysis of the stack layout and potential exploitation techniques (e.g., ROP chains) is recommended. The function fcn.00403b78 is complex, and other command handlers should be investigated for similar issues.

---
