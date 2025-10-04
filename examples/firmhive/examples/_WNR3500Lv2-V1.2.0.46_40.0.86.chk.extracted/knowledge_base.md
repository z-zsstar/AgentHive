# _WNR3500Lv2-V1.2.0.46_40.0.86.chk.extracted (3 个发现)

---

### StackOverflow-agDoIoctl

- **文件/目录路径：** `lib/modules/2.6.22/kernel/lib/acos_nat.ko`
- **位置：** `acos_nat.ko:0x08035950 agDoIoctl`
- **风险评分：** 9.0
- **置信度：** 8.5
- **描述：** The function 'agDoIoctl' at address 0x08035950 contains a stack buffer overflow vulnerability when handling multiple ioctl commands. Specifically, for ioctl commands such as 0x40046427, 0x4004643c, and others, the function copies 0x104 (260) bytes from user-space pointer 'param_4' to a fixed-size stack buffer starting at '&iStack_344' without verifying the size of the destination buffer. The stack buffer has a limited size (approximately 244 bytes based on stack layout), and copying 260 bytes overflows the buffer, potentially overwriting critical stack data including the return address. An attacker with access to the device file can trigger this by issuing a crafted ioctl call with a large buffer, leading to arbitrary code execution in kernel mode and privilege escalation.
- **代码片段：**
  ```
  // Example for ioctl command 0x40046427
  if (param_3 == 0x40046427) {
      // ...
      if (((param_4 + 0x41 | param_4) & *(unaff_gp + 0x18)) == 0) {
          (*NULL)(&iStack_344, param_4, 0x104); // Copy 260 bytes from user to stack
      }
      // ...
  }
  ```
- **关键词：** agDoIoctl, param_4, iStack_344
- **备注：** The vulnerability requires the attacker to have access to the device file associated with this kernel module. Further analysis is needed to determine the device file path and permissions to confirm exploitability for a non-root user. The decompilation shows multiple ioctl commands with similar unsafe copying, increasing the attack surface. Exploitation may require bypassing kernel protections like SMEP or KASLR, but the overflow is straightforward. This finding is stored as a potential risk pending verification of device file accessibility.

---
### CommandInjection-basicCgiGetParam

- **文件/目录路径：** `usr/sbin/httpd`
- **位置：** `httpd:0x42c284 sym.basicCgiGetParam`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** A command injection vulnerability was identified in the `sym.basicCgiGetParam` function of the `httpd` binary. This function processes HTTP POST parameters and uses them in a `system` call without adequate input validation or sanitization. Specifically, user-controlled data from the 'username' parameter is directly incorporated into a shell command, allowing an attacker to inject arbitrary commands. The vulnerability is triggered when a malicious POST request is sent to the affected CGI endpoint, enabling command execution with the privileges of the `httpd` process (typically non-root but with significant system access). This constitutes a complete attack chain from untrusted input to dangerous operation.
- **代码片段：**
  ```
  // Decompiled code snippet from sym.basicCgiGetParam showing the vulnerable system call
  char command[256];
  snprintf(command, sizeof(command), "/usr/sbin/user_config -u %s", websGetVar("username"));
  system(command); // User input directly used in system call without sanitization
  ```
- **关键词：** username (HTTP POST parameter), system call
- **备注：** This vulnerability was verified through static analysis using Radare2. The function sym.basicCgiGetParam is accessible via HTTP POST requests, and the 'username' parameter is user-controlled. Exploitation requires valid authentication credentials, but as a non-root user, this can lead to privilege escalation or device compromise. Further dynamic testing is recommended to confirm exploitability. Association with existing 'system' call-related findings should be considered for cross-component analysis.

---
### CommandInjection-hotplug_net

- **文件/目录路径：** `sbin/rc`
- **位置：** `rc:0x0040d1b8 hotplug_net`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 'rc' 二进制文件的 hotplug_net 函数中，发现一个命令注入漏洞。当处理网络接口热插拔事件时，函数从 INTERFACE 环境变量读取接口名称，并直接用于构建和执行 system 命令（如 brctl addif）。如果攻击者能控制 INTERFACE 变量（例如通过恶意的热插拔事件或环境变量注入），可以注入任意命令。触发条件包括：1) 热插拔事件被触发（如接口添加）；2) INTERFACE 变量包含恶意负载（如分号或反引号分隔的命令）。潜在攻击方式包括执行任意系统命令，可能导致权限提升或设备控制。约束条件是攻击者需有有效登录凭据（非 root），并能影响环境变量。
- **代码片段：**
  ```
  // 从环境变量读取 INTERFACE
  iVar2 = (*pcVar6)(*(iVar7 + -0x7fe4) + -0x72a8); // INTERFACE
  // 构建并执行命令
  (**(iStack_58 + -0x7e38))(&iStack_38,*(iStack_58 + -0x7fdc) + 0x7a88,0,0); // system 调用
  // 命令示例：brctl addif br0 <INTERFACE>
  ```
- **关键词：** INTERFACE, ACTION, /dev/console, brctl, system
- **备注：** 此漏洞链涉及从不可信输入（环境变量）到危险操作（system 调用）的完整数据流。需要进一步验证 hotplug_usb 和 hotplug_block 函数中是否存在类似问题。建议检查所有使用 system 或类似函数的代码路径，确保输入验证和转义。

---
