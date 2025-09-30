import argparse
import sys
import asyncio
import shlex
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown

from blueprint import DeepResearchManager
from models import ReportNode, ContentBlock

DEFAULT_TASK = """
请撰写一篇关于“大型语言模型（LLM）多智能体协作”的深度学术论文。

**核心要求：**
1.  **自拟主题与创新点**：你需要查询当前LLM多智能体领域的研究现状，**自行构思一个独特且具有创新性的研究主题**。在此主题下，提出至少一个具体的创新点，并详细阐述其理论基础、实现方法和潜在优势。
2.  **深度分析与论证**：文章应具有学术论文的严谨性，对所提出主题和创新点进行深入分析和充分论证。避免泛泛而谈，注重细节和逻辑清晰。
3.  **行文风格**：请确保综述结构合理、逻辑清晰、论证有力。内容应紧凑且富有洞察力，主要以流畅的段落形式呈现，避免过度使用列表或分点。优先使用中文撰写。

**请务必体现出你作为“自主研究专家”的深度思考和原创性贡献。**
"""

def _print_help():
    print("\n--- hivemind Deep Research (Interactive Mode) ---")
    print("Available commands:")
    print("  run [task description] - Start a new research task. If no description, use default.")
    print("  view [path|'all']      - View content of a chapter or the whole report. E.g., 'view 1-2'.")
    print("  tree                   - Display the report's structure.")
    print("  edit                   - Enter editing mode to modify the report.")
    print("  reset                  - Clear the current report and start fresh.")
    print("  help                   - Show this help message.")
    print("  exit/quit              - Exit the interactive session.")

def _print_edit_help():
    print("\n--- Editing Mode ---")
    print("Available commands:")
    print("  update <block_id> \"<new_text>\" - Update the text of a content block.")
    print("  add <parent_path> <item_type> \"<text>\" - Add a new item (e.g., 'add 1-2 paragraph \"New content...\"').")
    print("  delete <item_id>               - Delete a chapter or content block.")
    print("  view [path|'all']              - View content to find IDs.")
    print("  back                           - Exit editing mode.")
    print("  help                           - Show this help message.")

def _find_parent_node(root_node: "ReportNode", item_id: str) -> Optional["ReportNode"]:
    """Helper function to find the direct parent of an item by its ID."""
    for node in root_node.get_subtree_items():
        if isinstance(node, ReportNode):
            for item in node.content_items:
                if item.id == item_id:
                    return node
    return None

async def amain():
    """
    Main function to run the Deep Research agent.
    Handles command-line arguments for a single run and enters an interactive loop for multiple runs.
    """
    parser = argparse.ArgumentParser(
        description="hivemind - Deep Research Manager\n"
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
        manager = DeepResearchManager(max_iterations=args.max_iterations)
    except Exception as e:
        print(f"Error creating DeepResearchManager: {e}")
        sys.exit(1)

    # If a task is provided as a command-line argument, execute it and exit.
    if args.task:
        print(f"Executing task: \"{args.task}\"")
        await manager.arun(user_input=args.task)
        print("Task finished.")
        return

    # If no task is provided, enter interactive mode.
    console = Console()
    _print_help()
    
    while True:
        try:
            user_input = input("\n[User]> ")
            if not user_input.strip():
                continue

            parts = shlex.split(user_input)
            command = parts[0].lower()
            args_cmd = parts[1:]

            if command in ['exit', 'quit']:
                print("Exiting interactive mode.")
                break
            
            elif command == 'help':
                _print_help()

            elif command == 'run':
                task = " ".join(args_cmd) if args_cmd else DEFAULT_TASK
                if task == DEFAULT_TASK:
                    print("No task provided, using default task.")
                print("Executing task...")
                await manager.arun(user_input=task)
                print("Task finished. You can enter a new command (type 'help' for options).")

            elif command == 'view':
                if not args_cmd:
                    print("Error: 'view' command requires a path (e.g., '1-2') or 'all'.")
                    continue
                
                report_tree = manager.context.get("report_tree")
                if not report_tree:
                    print("No report has been generated yet. Use the 'run' command first.")
                    continue
                
                path = args_cmd[0]
                node_to_view = report_tree
                if path != 'all':
                    node_to_view = report_tree.get_node_by_path(path)
                
                if not node_to_view:
                    print(f"Error: Could not find chapter at path '{path}'.")
                    continue

                markdown_content = node_to_view.to_markdown()
                if not markdown_content.strip():
                    print(f"Chapter '{path}' is empty.")
                else:
                    console.print(Markdown(markdown_content))

            elif command == 'tree':
                report_tree = manager.context.get("report_tree")
                if not report_tree or not report_tree.content_items:
                    print("The report is empty. Use the 'run' command to generate content.")
                    continue
                print(report_tree.to_tree_str())

            elif command == 'edit':
                _print_edit_help()
                while True:
                    edit_input = input("\n[User|Edit]> ")
                    if not edit_input.strip():
                        continue
                    
                    edit_parts = shlex.split(edit_input)
                    edit_cmd = edit_parts[0].lower()
                    edit_args = edit_parts[1:]

                    if edit_cmd == 'back':
                        print("Exiting editing mode.")
                        break
                    elif edit_cmd == 'help':
                        _print_edit_help()
                    elif edit_cmd == 'view':
                        if not edit_args:
                            print("Error: 'view' command requires a path or 'all'.")
                            continue
                        # This duplicates the main view logic, but keeps the edit loop self-contained.
                        # A refactor could move this to a shared function.
                        report_tree = manager.context.get("report_tree")
                        path = edit_args[0]
                        node_to_view = report_tree
                        if path != 'all':
                           node_to_view = report_tree.get_node_by_path(path)
                        if not node_to_view:
                            print(f"Error: Could not find chapter at path '{path}'.")
                            continue
                        # In edit mode, we want to see IDs, so we use the JSON format.
                        print(node_to_view.to_json_str())
                        
                    elif edit_cmd == 'update':
                        if len(edit_args) < 2:
                            print("Error: 'update' requires a block_id and new_text.")
                            continue
                        block_id, new_text = edit_args[0], edit_args[1]
                        report_tree = manager.context.get("report_tree")
                        if report_tree.update_block_text(block_id, new_text):
                            print(f"Success: Block '{block_id}' updated.")
                        else:
                            print(f"Error: Could not update block '{block_id}'. Make sure the ID is correct and it's a content block.")

                    elif edit_cmd == 'delete':
                        if len(edit_args) < 1:
                            print("Error: 'delete' requires an item_id.")
                            continue
                        item_id = edit_args[0]
                        report_tree = manager.context.get("report_tree")
                        parent_node = _find_parent_node(report_tree, item_id)
                        if parent_node and parent_node.delete_item(item_id):
                            print(f"Success: Item '{item_id}' deleted.")
                        else:
                            print(f"Error: Could not delete item '{item_id}'. Make sure the ID is correct.")
                    
                    elif edit_cmd == 'add':
                        if len(edit_args) < 3:
                            print("Error: 'add' requires parent_path, item_type, and text.")
                            print("Example: add 1-1 paragraph \"This is a new paragraph.\"")
                            continue
                        parent_path, item_type, text = edit_args[0], edit_args[1], edit_args[2]
                        report_tree = manager.context.get("report_tree")
                        parent_node = report_tree.get_node_by_path(parent_path)
                        if not parent_node:
                            print(f"Error: Could not find parent chapter at path '{parent_path}'.")
                            continue
                        
                        new_item = None
                        if item_type.lower() == 'chapter':
                            new_item = ReportNode(parent=parent_node)
                        elif item_type.lower() in ['paragraph', 'list', 'code', 'table', 'heading']:
                            new_item = ContentBlock(block_type=item_type.lower(), text=text)
                        else:
                            print(f"Error: Invalid item_type '{item_type}'. Supported types are 'chapter', 'paragraph', etc.")
                            continue
                        
                        if parent_node.add_item(new_item):
                            print(f"Success: New {item_type} with ID '{new_item.id}' added to chapter '{parent_path}'.")
                        else:
                            print("Error: Failed to add the new item.")

                    else:
                        print(f"Unknown command in edit mode: '{edit_cmd}'. Type 'help' for options.")

            elif command == 'reset':
                manager.context.set("report_tree", None)
                manager.context.set("reference_manager", None)
                print("Report has been reset.")

            else:
                print(f"Unknown command: '{command}'. Type 'help' for a list of commands.")

        except KeyboardInterrupt:
            print("\nSession terminated by user.")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            pass

if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("\nSession terminated by user.")
