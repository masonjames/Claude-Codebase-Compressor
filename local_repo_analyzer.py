import os
import json
import zlib
import base64
import argparse

def get_subdirectories(path):
    return [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]

def select_directories(directories):
    print("Available directories:")
    for i, directory in enumerate(directories):
        print(f"{i + 1}. [ ] {directory}")
    
    print("\nEnter the numbers of the directories you want to analyze, separated by commas.")
    print("Enter 'all' to select all directories, or 'done' when finished.")
    
    selected = set()
    while True:
        choice = input("> ").strip().lower()
        if choice == 'done':
            break
        elif choice == 'all':
            selected = set(range(len(directories)))
            break
        else:
            try:
                for num in choice.split(','):
                    num = int(num.strip()) - 1
                    if 0 <= num < len(directories):
                        selected.add(num)
                    else:
                        print(f"Invalid number: {num + 1}")
            except ValueError:
                print("Invalid input. Please enter numbers, 'all', or 'done'.")
        
        # Display updated selection
        print("\nCurrent selection:")
        for i, directory in enumerate(directories):
            mark = 'X' if i in selected else ' '
            print(f"{i + 1}. [{mark}] {directory}")
    
    return [directories[i] for i in selected]

def summarize_code(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.split('\n')
        function_count = sum(1 for line in lines if line.strip().startswith(('fn', 'def', 'function')))
        comment_count = sum(1 for line in lines if line.strip().startswith(('#', '//', '/*')))
        
        return {
            "total_lines": len(lines),
            "function_count": function_count,
            "comment_count": comment_count,
            "brief": content[:200] + "..." if len(content) > 200 else content
        }
    except Exception as e:
        print(f"Error summarizing file {file_path}: {str(e)}")
        return None

def analyze_repository(repo_path):
    repo_structure = {}
    file_extensions = {}
    total_lines = 0
    total_files = 0
    code_files = []

    for root, dirs, files in os.walk(repo_path):
        rel_path = os.path.relpath(root, repo_path)
        current_dir = repo_structure
        
        if rel_path != '.':
            for part in rel_path.split(os.sep):
                if part not in current_dir:
                    current_dir[part] = {"files": [], "subdirs": {}}
                current_dir = current_dir[part]["subdirs"]

        for file in files:
            total_files += 1
            file_path = os.path.join(root, file)
            _, ext = os.path.splitext(file)
            file_extensions[ext] = file_extensions.get(ext, 0) + 1

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    total_lines += len(lines)

                file_info = {
                    "name": file,
                    "lines": len(lines),
                    "size": os.path.getsize(file_path)
                }

                # Update the list of file extensions to include more types
                if ext in ['.py', '.js', '.java', '.c', '.cpp', '.h', '.ua', '.toml', '.yml', '.svg', '.css', '.html']:
                    summary = summarize_code(file_path)
                    if summary:
                        file_info["summary"] = summary
                        code_files.append(file_path)

                if rel_path == '.':
                    if "files" not in repo_structure:
                        repo_structure["files"] = []
                    repo_structure["files"].append(file_info)
                else:
                    current_dir["files"].append(file_info)
            except Exception as e:
                print(f"Error processing file {file_path}: {str(e)}")
    
    return {
        "structure": repo_structure,
        "file_extensions": file_extensions,
        "total_lines": total_lines,
        "total_files": total_files,
        "code_files": code_files
    }

def compress_analysis(analysis):
    json_data = json.dumps(analysis)
    compressed = zlib.compress(json_data.encode('utf-8'))
    return base64.b64encode(compressed).decode('utf-8')

def decompress_analysis(compressed_data):
    decoded = base64.b64decode(compressed_data)
    decompressed = zlib.decompress(decoded)
    return json.loads(decompressed.decode('utf-8'))

def main():
    parser = argparse.ArgumentParser(description="Analyze selected subdirectories in a given path.")
    parser.add_argument("path", help="Path to the parent directory")
    parser.add_argument("--output_dir", default="analysis_results", help="Directory to store analysis results")
    args = parser.parse_args()

    parent_path = os.path.abspath(args.path)
    
    if not os.path.isdir(parent_path):
        print(f"Error: {parent_path} is not a valid directory.")
        return

    subdirectories = get_subdirectories(parent_path)
    if not subdirectories:
        print(f"No subdirectories found in {parent_path}")
        return

    selected_dirs = select_directories(subdirectories)
    if not selected_dirs:
        print("No directories selected. Exiting.")
        return

    os.makedirs(args.output_dir, exist_ok=True)

    for directory in selected_dirs:
        repo_path = os.path.join(parent_path, directory)
        print(f"\nAnalyzing directory: {repo_path}")
        
        try:
            analysis = analyze_repository(repo_path)
            compressed_analysis = compress_analysis(analysis)
            
            output_file = os.path.join(args.output_dir, f"{directory}_analysis.json")
            with open(output_file, 'w') as f:
                json.dump({"compressed_analysis": compressed_analysis}, f)
            
            print(f"Analysis complete. Results saved to {output_file}")
            
            # Print summary
            print("\nSummary:")
            print(f"Total files: {analysis['total_files']}")
            print(f"Total lines of code: {analysis['total_lines']}")
            print("File extensions:")
            for ext, count in analysis['file_extensions'].items():
                print(f"  {ext}: {count}")
            
            print("\nCode files found:")
            for file in analysis['code_files'][:5]:  # Limit to first 5 for brevity
                print(f"  {os.path.relpath(file, repo_path)}")
            
            if len(analysis['code_files']) > 5:
                print(f"  ... and {len(analysis['code_files']) - 5} more")
        except Exception as e:
            print(f"Error analyzing directory {repo_path}: {str(e)}")

    print(f"\nAll analyses completed. Results are stored in the '{args.output_dir}' directory.")

if __name__ == "__main__":
    main()