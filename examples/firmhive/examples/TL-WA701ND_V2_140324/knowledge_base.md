# TL-WA701ND_V2_140324 (5 个发现)

---

### 栈缓冲区溢出-wlanconfig_p2pgo_noa

- **文件/目录路径：** `sbin/wlanconfig`
- **位置：** `wlanconfig:0x004024b0 main+0xc00 (大致地址基于反编译代码中的 'p2pgo_noa' 处理逻辑)`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'wlanconfig' 的 'p2pgo_noa' 子命令处理中存在栈缓冲区溢出漏洞。当攻击者提供多个参数集时，程序在解析参数时未正确检查写入边界，导致栈缓冲区溢出。具体来说，在循环处理参数时，写入指针 'pcVar14' 初始指向栈变量 'cStack_174'（单个字符），但每次循环递增 5 字节，当循环次数达到最大值（iVar4=2）时，写入位置超出 'cStack_174' 的边界，覆盖相邻栈变量如 'auStack_173' 和 'iStack_168'。攻击者可通过控制命令行参数（如迭代次数、偏移值）来操纵写入值，从而覆盖返回地址或关键栈数据。触发条件：使用 'wlanconfig <interface> p2pgo_noa' 命令并提供至少三组参数（每组包含迭代次数、偏移和持续时间），例如 'wlanconfig wlan0 p2pgo_noa 1 1000 2000 2 2000 3000 3 3000 4000'。利用方式：精心构造参数值，覆盖返回地址指向 shellcode 或 gadget，实现任意代码执行。约束条件：参数数量受程序逻辑限制（最多三组），但每组参数值完全可控，足以完成攻击。
- **代码片段：**
  ```
  // 从反编译代码中提取的相关片段
  pcVar18 = &cStack_174;
  piVar16 = param_2 + 0xc;
  iVar4 = 0;
  iVar3 = *piVar16;
  pcVar14 = pcVar18;
  while( true ) {
      if (iVar3 == 0) break;
      iVar3 = (**(pcVar20 + -0x7fcc))(iVar3); // atoi 转换
      *pcVar14 = iVar3; // 写入栈，可能溢出
      // ... 其他操作写入 auStack_173
      pcVar14 = pcVar14 + 5; // 指针递增，可能超出边界
      iVar4 = iVar4 + 1;
      if ((iVar3 == 0) || (iVar4 == 2)) break;
  }
  ```
- **关键词：** 命令行参数, ioctl 套接字路径, 函数符号：main, fcn.00401950
- **备注：** 漏洞在 'p2pgo_noa' 子命令处理中验证，溢出发生在 ioctl 调用之前，因此即使 ioctl 失败（如权限不足），溢出仍可触发。攻击链完整：从不可信输入（命令行）到危险操作（栈溢出覆盖返回地址）。建议进一步验证利用可行性，例如通过动态测试或检查栈布局。关联文件：无其他文件直接交互，但通过 ioctl 与内核无线驱动通信。后续分析方向：检查其他子命令（如 'nawds'）是否类似漏洞，并评估固件中 ASLR 和栈保护机制的存在。

---
### CommandInjection-WPS_set_ap_ssid_configuration

- **文件/目录路径：** `sbin/hostapd`
- **位置：** `hostapd:0x43737c sym.wps_set_ap_ssid_configuration`
- **风险评分：** 8.5
- **置信度：** 9.0
- **描述：** 在 'hostapd' 二进制文件中发现一个 command injection 漏洞，允许攻击者通过恶意 WPS 消息执行任意命令。漏洞触发条件：WPS 功能启用且网络接口可访问。攻击者无需特定登录凭据即可通过网络发送 WPS 消息，但用户指定攻击者已连接到设备（可能包括网络层访问）。输入数据从 WPS 消息流经多个函数（如 `sym.eap_wps_config_set_ssid_configuration` 和 `sym.wps_set_ssid_configuration`），最终在 `sym.wps_set_ap_ssid_configuration` 中未经 sanitization 即通过 `sprintf` 格式化并传递给 `system` 函数。利用方式：攻击者伪造 WPS 消息包含恶意命令（如 shell 元字符），导致命令在设备上执行。边界检查缺失，输入直接嵌入命令字符串。
- **代码片段：**
  ```
  // 在 sym.wps_set_ap_ssid_configuration 函数中
  (**(loc._gp + -0x7ddc))(auStack_498, "cfg wpssave %s", uStackX_4); // uStackX_4 是用户控制的参数 param_2
  (**(loc._gp + -0x7948))(auStack_498); // 调用 system 执行命令
  ```
- **关键词：** param_2 in sym.wps_set_ap_ssid_configuration, WPS message data, eap_wps_cmp.conf file, system, sprintf
- **备注：** 漏洞依赖于 WPS 接口的可用性；在默认配置中可能启用。攻击者可能不需要登录凭据，但用户指定了 '已连接到设备'，因此网络访问可能足够。然而，用户核心要求攻击者拥有有效登录凭据（非root用户），此处条件可能不完全一致，建议进一步验证 WPS 配置和网络隔离。其他函数（如 main 或控制接口处理）未显示完整攻击链。

---
### BufferOverflow-LoginFunction

- **文件/目录路径：** `usr/sbin/bpalogin`
- **位置：** `bpalogin:0x004021e4 sym.login`
- **风险评分：** 7.5
- **置信度：** 8.0
- **描述：** 在 login 函数中，处理认证响应时使用 strcpy 和 strcat 复制字符串到固定大小的全局缓冲区，缺少边界检查。攻击者可通过恶意认证服务器提供长字符串，导致缓冲区溢出。溢出可能覆盖全局结构体中的函数指针（如偏移 0x308），当调用该指针时（例如在错误处理中），可控制执行流。触发条件：攻击者运行 bpalogin 并指定 'authserver' 参数指向恶意服务器，服务器在认证响应中返回超长字符串。利用方式：精心构造响应字符串，覆盖函数指针指向 shellcode 或 ROP 链，实现代码执行。
- **代码片段：**
  ```
  0x004021c4      8f998024       lw t9, -sym.imp.strcpy(gp)  ; [0x405310:4]=0x8f998010
  0x004021e4      0320f809       jalr t9
  ; strcpy 调用，目标地址为 s1 + a0（全局缓冲区），源为 s7（堆栈缓冲区）
  0x00402200      8f9980f8       lw t9, -sym.imp.strcat(gp)  ; [0x405100:4]=0x8f998010
  0x00402210      0320f809       jalr t9
  ; strcat 调用，追加字符串到同一全局缓冲区
  ```
- **关键词：** authserver, user, password, T_MSG_LOGIN_RESP, extract_valuestring
- **备注：** 漏洞在全局缓冲区中，可能绕过 ASLR；攻击链需要攻击者控制认证服务器，但作为本地用户可通过命令行参数设置。建议进一步分析全局结构体布局和函数指针使用点。

---
### null-ptr-deref-athr_gmac_do_ioctl

- **文件/目录路径：** `lib/modules/2.6.31/net/ag7240_mod.ko`
- **位置：** `ag7240_mod.ko:sym.athr_gmac_do_ioctl (地址 0x08005b54)`
- **风险评分：** 7.0
- **置信度：** 9.0
- **描述：** 在 athr_gmac_do_ioctl 函数中，处理 ioctl 命令时存在 NULL 指针解引用漏洞。当 param_3（ioctl 命令）为 0x89f3 或 0x89f7 时，函数直接调用 (*NULL)()，导致内核崩溃。攻击者作为非 root 用户，可通过访问相关设备文件并发送这些 ioctl 命令触发漏洞，造成拒绝服务。触发条件包括：设备文件权限允许非 root 用户访问、攻击者拥有有效登录凭据。利用方式简单直接，无需复杂输入。
- **代码片段：**
  ```
  uint sym.athr_gmac_do_ioctl(uint param_1,uint param_2,int32_t param_3)
  {
      uint uVar1;
      
      if (param_3 == 0x89f3) {
          uVar1 = (*NULL)();
          return uVar1;
      }
      if (0x89f3 < param_3) {
          if (param_3 == 0x89f6) {
              halt_baddata();
          }
          if (param_3 == 0x89f7) {
              uVar1 = (*NULL)();
              return uVar1;
          }
      }
      else if (param_3 == 0x89f2) {
          halt_baddata();
      }
      return 0xffffffff;
  }
  ```
- **关键词：** ioctl command 0x89f3, ioctl command 0x89f7
- **备注：** 漏洞证据明确，但需要进一步验证设备文件权限（如 /dev/ 下的相关文件）是否允许非 root 用户访问。此漏洞主要导致拒绝服务，可能无法直接用于特权提升。建议检查系统配置以确认可利用性。未发现其他缓冲区溢出或内存损坏漏洞在此文件中。

---
### DOM-XSS-WzdEndRpm

- **文件/目录路径：** `web/userRpm/WzdEndRpm.htm`
- **位置：** `WzdEndRpm.htm: JavaScript 函数 loadWlanCfg, loadWlanMbss, loadNetworkCfg 等`
- **风险评分：** 6.5
- **置信度：** 7.0
- **描述：** 在 'WzdEndRpm.htm' 文件中发现多个潜在的 DOM-based XSS 漏洞。攻击者可以通过修改 NVRAM 配置变量（如无线 SSID、安全密钥等）注入恶意 JavaScript 代码，当用户访问此配置总结页面时，代码通过 `innerHTML` 赋值执行。具体触发条件包括：攻击者首先通过其他配置接口（如无线设置页面）修改可控的配置值，使其包含恶意脚本；然后访问 'WzdEndRpm.htm' 页面，脚本自动执行。潜在利用方式包括窃取会话 cookies、重定向用户或执行未授权操作。由于攻击者拥有有效登录凭据，此攻击链可行，但风险受限于用户会话权限。代码中缺少对配置数据的输入验证和输出转义，导致漏洞存在。
- **代码片段：**
  ```
  示例代码片段来自 loadWlanCfg 函数：
  document.getElementById("localSsid").innerHTML = getWlanCfg("ssid1");
  document.getElementById("localSecText").innerHTML = getWlanCfg("secText");
  document.getElementById("brlSsid").innerHTML = getWlanCfg("brl_ssid");
  // 类似代码在多处使用 innerHTML 显示配置数据，缺乏转义
  ```
- **关键词：** getWlanCfg, getWanCfg, getLanCfg, ssid1, secText, brl_ssid, wanip, usrName, password
- **备注：** 此漏洞的利用依赖于攻击者能通过其他接口修改配置数据，但基于攻击者拥有登录凭据，这是可行的。需要进一步验证 `getWlanCfg` 等函数是否从 NVRAM 读取数据以及后端是否对输入进行过滤。建议检查相关配置页面（如无线设置）以确认数据流。漏洞可能影响会话安全，但非 root 用户权限可能限制损害范围。

---
