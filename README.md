# AgentHive

**AgentHive 是一个用于构建多智体为共同目标有组织的协作的框架。**

它不仅仅是单个 Agent 的简单集合，而是旨在将多个独立的智能体编排、组织成一个具有高度协同性、能够自我进化和修正的“智能蜂巢”。其核心目标是解决那些远超单个 Agent 能力范围的、需要多步骤、大范围探索的复杂问题。

## 核心特性

AgentHive 的设计哲学是“**组织优于自治**”。我们认为，对于复杂的开放式探索任务，一个结构清晰、分工明确的协作型智能体系统，远比一个完全依赖单个 LLM 自主探索的“超级智能体”更可靠、更高效。

框架的核心特性根植于此哲学：

1.  **动态与层级的智能体结构 (Tree of Agents)**
    *   AgentHive 能够根据任务的复杂性，动态地、递归地生成树状的智能体团队结构，而非依赖于硬编码的固定团队。这赋予了框架极高的灵活性和可扩展性。
    *   在 AgentHive 中，上层 Agent 扮演“总指挥”的角色，负责将探索和总体分析任务，并将其精准地委派给下层的“中层执行者”或更专业的子团队，形成一个清晰的指挥链。
    *   上下文和权限随着任务指派层层传递，每个 Agent 仅获得其完成任务所需的最小信息和工具权限。这种设计确保了子任务的专注性，并极大地提升了系统的稳定性和安全性。
    *   *实现参考: `firmhive.blueprint.py` 中的 `create_analysis_blueprint` 和 `research/blueprint.py` 中的 `_build_agent_config` 方法都展示了这种动态组合能力。*

    *   **核心思想：定义于运行 (Define-by-Run) 的智能体之树**

        AgentHive 的核心是动态构建一个“智能体之树”（Tree of Agents, ToA）。与静态定义的流程不同，整个协作结构是在任务执行过程中，由上层智能体根据当前情境和任务需求，即时地、动态地创建和组织下层智能体而形成的。

        这赋予了 AgentHive 两个核心特点：

        *   **组织性 (Organized)**: 整个树的构建是有向的、分层的（总指挥 -> 中层执行者 -> 低层执行者），每个节点（Agent）职责明确，上下文和数据沿着清晰的路径传递。
        *   **动态性 (Dynamic)**: 树的形态不是预设的。它每层的节点数量，以及节点之间的连接关系，都可以根据任务的需求，在运行时动态调整。其具体结构完全取决于任务的内在逻辑和智能体在运行时的“决策”。
        *   **可扩展性 (Scalable)**: 框架支持在运行时添加新的一个或多个智能体节点，或者智能体不断递归生成子智能体。这使得系统能够根据任务的变化，灵活地调整其协作结构。

        **抽象符号示例**

        下面是一个三层结构（L0 -> L1 -> L2）的动态构建过程：

        ```mermaid
        graph TD
            subgraph L0 [L0 - 最高层]
                Master(MasterAgent)
            end

            subgraph L1 [L1 - 总指挥]
                P1(Planner)
            end

            subgraph L2 [L2 - 执行层]
                Exec_A(Executor_A)
                Exec_B(Executor_B)
            end

            Master -- 1. 委派规划任务 --> P1
            P1 -- 2. 委派执行任务 A --> Exec_A
            P1 -- 2. 委派执行任务 B --> Exec_B

            Exec_A -- 3. 返回结果 A --> P1
            Exec_B -- 3. 返回结果 B --> P1
            P1 -- 4. 汇总结果 --> Master

            style Master fill:#cde4ff,stroke:#99c7ff
            style P1 fill:#d2ffd2,stroke:#a6fca6
            style Exec_A fill:#fff0c1,stroke:#ffe38a
            style Exec_B fill:#fff0c1,stroke:#ffe38a
        ```

        **伪代码示例：递归构建可定制的智能体“蓝图”**

        下面的伪代码展示了 AgentHive 如何通过递归，构建一个类似您在 `firmhive/blueprint.py` 中实现的多层、可定制的智能体“蓝图”(Blueprint)。

        ```python
        # 伪代码：展示如何通过递归构建一个可定制层级的智能体“蓝图”

        def create_agent_blueprint(max_levels: int, user_roles: dict, user_tools: dict) -> AgentConfig:
            """
            通过递归创建一个多层、可定制的智能体配置蓝图。

            Args:
                max_levels: 定义了智能体之树的最大深度 (例如, 2 表示 L2->L1->L0 三层)。
                user_roles: 一个字典，允许用户为每一层级(0, 1, ...)自定义角色(system_prompt)。
                user_tools: 一个字典，允许用户为每一层级自定义工具列表。
            """

            def _create_level(level: int) -> AgentConfig:
                """递归地为单个层级创建配置。"""

                # 1. 递归基例：最深层 (L0)，通常是纯粹的执行者。
                if level == 0:
                    return AgentConfig(
                        agent_class="ExecutorAgent",
                        system_prompt=user_roles.get(0, "L0 执行者：我负责执行具体任务。"),
                        tool_configs=user_tools.get(0, [ShellTool, FileTool])
                    )

                # 2. 递归步骤：获取更深一层的配置，它将成为当前层的一个“子工具”。
                deeper_level_config = _create_level(level - 1)

                # 3. 为当前层级配置工具。
                #    核心：将下一层的智能体配置(deeper_level_config)包装成一个当前层可以调用的“助理工具”。
                current_level_tools = user_tools.get(level, [GetContextInfoTool])
                current_level_tools.append(
                    AssistantToolConfig(
                        name=f"Recursive_Delegator_L{level-1}",
                        description=f"将任务委派给 L{level-1} 层级的子智能体进行分析和处理，任务过于复杂时，我会委派给下一层。",
                        sub_agent_config=deeper_level_config
                    )
                )

                # 4. 返回当前层级的配置。
                return AgentConfig(
                    agent_class="TopAgent",
                    system_prompt=user_roles.get(level, f"L{level} 顶层智能体：我负责接收任务，适当探索和分析，复杂任务我会委派给下一层。")
                )

            # 从最顶层开始构建
            return _create_level(max_levels)

        # --- 如何使用这个蓝图 ---

        # 1. 用户自定义每一层的角色和工具
        my_roles = {
            2: "L2 总指挥：负责最高层策略制定。",
            1: "L1 区域经理：负责将策略分解为具体计划。",
            0: "L0 现场工人：负责执行具体操作。"
        }
        my_tools = {
            2: [HighLevelStrategyTool],
            1: [ProjectPlanningTool],
            0: [WebSearchTool, CalculatorTool]
        }

        # 2. 从用户配置创建一个三层(L2->L1->L0)的智能体蓝图
        three_level_blueprint = create_agent_blueprint(max_levels=2, user_roles=my_roles, user_tools=my_tools)

        # 3. 从蓝图实例化顶层智能体
        master_agent = Agent.from_config(three_level_blueprint)

        # 4. 运行
        master_agent.run("分析市场趋势并制定下季度产品路线图。")
        ```
        这个例子清晰地展示了：
        *   **配置即蓝图**: `create_agent_blueprint` 函数返回的是一个静态的配置结构，定义了整个智能体团队的潜力。
        *   **递归嵌套**: `AssistantToolConfig` 是实现层级结构的关键，它将一个智能体的配置变成了另一个智能体的工具。
        *   **运行时动态实例化**: 只有当 `master_agent.run()` 被调用时，这棵“智能体之树”才会被根据蓝图真正地、动态地创建出来。

## 应用展示

AgentHive 的灵活性使其能够胜任多种复杂任务。目前，我们已经成功实践了以下三个典型应用：

### 1. 固件与二进制安全分析 (`firmhive`)

这不仅仅是一个分析工具，更是一个模拟人类安全团队工作的多智能体系统。

*   **工作模式**: 系统模拟一个由“高级研究员”、“二进制分析专家”、“代码审计员”和“知识库管理员”组成的团队。
*   **能力**:
    *   自适应的对文件系统进行深层、并行的探索性分析。
    *   调用 `radare2` 等专业工具对二进制文件进行深度反汇编和污点分析。
    *   自动发现、记录和关联潜在的漏洞（如硬编码密钥、危险函数、命令注入等）。
    *   持久化存储关键记忆，形成对整个固件安全状况的完整画像。

### 2. 深度研究与报告生成 (`deepresearch`)

这是一个能够针对任何复杂主题进行深度研究，并自动撰写结构化报告的智能系统。

*   **工作模式**: 系统扮演“首席研究员”的角色，它将一个宽泛的研究主题（如 "Explainable AI"）分解为大纲，然后为每个章节指派一个“助理研究员”。
*   **能力**:
    *   **结构化规划**: 自动生成研究大纲，并将其分解为具体的研究点。
    *   **并行研究**: 并行地对每个研究点进行深度信息检索和分析。
    *   **递归深入**: 如果某个子主题依然复杂，系统会进一步递归地创建下一级研究团队进行探索。
    *   **综合成文**: 将所有研究结果汇总、提炼，最终生成一篇逻辑清晰、内容详实的深度研究报告。

### 3. 交互式网页信息获取 (`websearch`)

这是一个能够像人类一样“浏览”和“理解”网页的智能代理。

*   **工作模式**: `WebSearchAgent` 能够自主地与网页进行交互，以完成复杂的信息提取任务。
*   **能力**:
    *   **多模态理解**: 结合网页截图（视觉信息）和 DOM 文本，精准定位和理解页面元素。
    *   **交互操作**: 能够执行点击、滚动、输入文本等操作，可以处理登录、表单填写、动态加载等复杂场景。
    *   **并行浏览**: 能够同时打开多个页面，并行执行多个浏览任务，并综合来自不同页面的信息。
    *   **内容提取**: 支持从网页、甚至在线 PDF 文件中提取和总结内容。

## 快速开始


1.  **克隆仓库**
    ```bash
    git clone https://github.com/z-zsstar/AgentHive.git
    cd AgentHive
    ```

2.  **安装依赖**
    ```bash
    pip install -r requirements.txt
    ```

3.  **配置**
    *   复制 `config.ini.template` 到 `config.ini`。
    *   在 `config.ini` 中填入您的 API 密钥等信息。

4.  **运行一个示例 (例如：深度研究)**
    ```bash
    python -m research.main --task "深入分析大语言模型中的幻觉问题" 
    ```

## 贡献

我们欢迎任何形式的贡献！无论是 Bug 修复、新功能开发，还是文档改进，都对我们至关重要。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源。