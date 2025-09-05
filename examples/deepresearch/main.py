import argparse
import sys
from blueprint import DeepResearchManager

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
                continue
            
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