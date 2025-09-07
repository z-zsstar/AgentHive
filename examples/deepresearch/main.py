import argparse
import sys
from blueprint import DeepResearchManager

DEFAULT_TASK = """
请撰写一篇关于“大型语言模型（LLM）多智能体协作”的深度学术论文。

**核心要求：**
1.  **自拟主题与创新点**：你需要查询当前LLM多智能体领域的研究现状，**自行构思一个独特且具有创新性的研究主题**。在此主题下，提出至少一个具体的创新点，并详细阐述其理论基础、实现方法和潜在优势。
2.  **深度分析与论证**：文章应具有学术论文的严谨性，对所提出主题和创新点进行深入分析和充分论证。避免泛泛而谈，注重细节和逻辑清晰。
3.  **行文风格**：请确保综述结构合理、逻辑清晰、论证有力。内容应紧凑且富有洞察力，主要以流畅的段落形式呈现，避免过度使用列表或分点。优先使用中文撰写。

**请务必体现出你作为“自主研究专家”的深度思考和原创性贡献。**
"""

def main():
    """
    Main function to run the Deep Research agent.
    Handles command-line arguments for a single run and enters an interactive loop for multiple runs.
    """
    parser = argparse.ArgumentParser(
        description="AgentHive - Deep Research Manager\n"
                    "Run with a specific task or in interactive mode."
    )
    parser.add_argument(
        "task",
        nargs='?',  # Makes the task optional
        default=None,
        help="The research task to be executed. If not provided, enters interactive mode."
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum delegation depth for agents (e.g., Master -> L1 -> L2). Default: 2"
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        help="Maximum iterations for the research process. Default: 50"
    )

    args = parser.parse_args()

    # Instantiate the manager with the specified depth and max_iterations
    try:
        manager = DeepResearchManager(max_iterations=args.max_iterations, depth=args.depth)
    except Exception as e:
        print(f"Error creating DeepResearchManager: {e}")
        sys.exit(1)

    # If a task is provided as a command-line argument, execute it and exit.
    if args.task:
        print(f"Executing task: \"{args.task}\"")
        manager.run(user_input=args.task)
        print("Task finished.")
        return

    # If no task is provided, enter interactive mode.
    print("--- AgentHive Deep Research (Interactive Mode) ---")
    print("Type your research task and press Enter.")
    print("Type 'exit' or 'quit' to end the session.")
    
    while True:
        try:
            user_input = input("\n[User Task]> ")
            if user_input.lower() in ['exit', 'quit']:
                print("Exiting interactive mode.")
                break
            if not user_input.strip():
                print(f"No input provided, using default task.\nExecuting task: \"{DEFAULT_TASK}\"")
                user_input = DEFAULT_TASK
            
            manager.run(user_input=user_input)
            print("Task finished. You can enter a new task.")

        except KeyboardInterrupt:
            print("\nSession terminated by user.")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            # Depending on the severity, you might want to break or continue
            # For now, we'll continue the loop
            pass

if __name__ == "__main__":
    main()
