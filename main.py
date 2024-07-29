import os
from dotenv import load_dotenv
import json
from tavily import TavilyClient
import zlib
import base64
import argparse
import ast
import git
import re
from anthropic import Anthropic, APIStatusError, APIError
import difflib
import time
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown
import venv
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

try:
    import astroid
    ASTROID_AVAILABLE = True
except ImportError:
    ASTROID_AVAILABLE = False
    print("Warning: astroid module not found. Advanced code analysis will be limited.")

@dataclass
class CodeSummary:
    total_lines: int
    function_count: int
    class_count: int
    comment_count: int
    cyclomatic_complexity: int
    brief: str
    docstring: Optional[str]

@dataclass
class FileInfo:
    name: str
    path: str
    lines: int
    size: int
    summary: Optional[CodeSummary]

@dataclass
class DependencyInfo:
    name: str
    version: Optional[str]
    type: str  # 'internal' or 'external'

@dataclass
class RepositoryAnalysis:
    structure: Dict[str, Any]
    file_extensions: Dict[str, int]
    total_lines: int
    total_files: int
    code_files: List[str]
    dependencies: List[DependencyInfo]
    commit_history: List[Dict[str, Any]]
    contributors: List[Dict[str, Any]]

# Load environment variables from .env file
load_dotenv()

# Initialize the Anthropic client
anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
if not anthropic_api_key:
    raise ValueError("ANTHROPIC_API_KEY not found in environment variables")
client = Anthropic(api_key=anthropic_api_key)

# Initialize the Tavily client
tavily_api_key = os.getenv("TAVILY_API_KEY")
if not tavily_api_key:
    raise ValueError("TAVILY_API_KEY not found in environment variables")
tavily = TavilyClient(api_key=tavily_api_key)

console = Console()


# Token tracking variables
main_model_tokens = {'input': 0, 'output': 0}
tool_checker_tokens = {'input': 0, 'output': 0}
code_editor_tokens = {'input': 0, 'output': 0}
code_execution_tokens = {'input': 0, 'output': 0}

# Set up the conversation memory (maintains context for MAINMODEL)
conversation_history = []

# Store file contents (part of the context for MAINMODEL)
file_contents = {}

# Code editor memory (maintains some context for CODEEDITORMODEL between calls)
code_editor_memory = []

# automode flag
automode = False

# Store file contents
file_contents = {}

# Global dictionary to store running processes
running_processes = {}

# Constants
CONTINUATION_EXIT_PHRASE = "AUTOMODE_COMPLETE"
MAX_CONTINUATION_ITERATIONS = 25
MAX_CONTEXT_TOKENS = 200000  # Reduced to 200k tokens for context window

# Models
# Models that maintain context memory across interactions
MAINMODEL = "claude-3-5-sonnet-20240620"  # Maintains conversation history and file contents

# Models that don't maintain context (memory is reset after each call)
TOOLCHECKERMODEL = "claude-3-5-sonnet-20240620"
CODEEDITORMODEL = "claude-3-5-sonnet-20240620"
CODEEXECUTIONMODEL = "claude-3-haiku-20240307"

# System prompts
BASE_SYSTEM_PROMPT = """
You are Claude, an AI assistant powered by Anthropic's Claude-3.5-Sonnet model, specialized in software development with access to a variety of tools and the ability to instruct and direct a coding agent and a code execution one.
"""

def get_subdirectories(path: str) -> List[str]:
    return [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]

def select_directories(directories: List[str]) -> List[str]:
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
                selected.update(int(num.strip()) - 1 for num in choice.split(','))
            except ValueError:
                print("Invalid input. Please enter numbers, 'all', or 'done'.")
        
        # Display updated selection
        print("\nCurrent selection:")
        for i, directory in enumerate(directories):
            mark = 'X' if i in selected else ' '
            print(f"{i + 1}. [{mark}] {directory}")
    
    return [directories[i] for i in selected]

def calculate_cyclomatic_complexity(node):
    complexity = 1
    for child in node.get_children():
        if isinstance(child, (astroid.If, astroid.While, astroid.For, astroid.Assert,
                              astroid.ExceptHandler, astroid.Raise,
                              astroid.TryExcept, astroid.TryFinally)):
            complexity += 1
        elif isinstance(child, astroid.BoolOp) and child.op == 'or':
            complexity += len(child.values) - 1
    return complexity

def summarize_code(file_path: str) -> Optional[CodeSummary]:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        tree = astroid.parse(content)
        
        function_count = len(list(tree.nodes_of_class(astroid.FunctionDef)))
        class_count = len(list(tree.nodes_of_class(astroid.ClassDef)))
        
        comment_count = len(tree.doc.split('\n')) if tree.doc else 0
        for node in tree.body:
            if isinstance(node, astroid.Expr) and isinstance(node.value, astroid.Const):
                comment_count += len(node.value.value.split('\n'))
        
        complexity = sum(calculate_cyclomatic_complexity(node) for node in tree.nodes_of_class(astroid.FunctionDef))
        
        docstring = ast.get_docstring(ast.parse(content))
        
        return CodeSummary(
            total_lines=len(content.split('\n')),
            function_count=function_count,
            class_count=class_count,
            comment_count=comment_count,
            cyclomatic_complexity=complexity,
            brief=content[:200] + "..." if len(content) > 200 else content,
            docstring=docstring
        )
    except Exception as e:
        print(f"Error summarizing file {file_path}: {str(e)}")
        return None

def get_default_branch(repo_path: str) -> str:
    try:
        repo = git.Repo(repo_path)
        branches = [ref.name for ref in repo.references]
        if 'refs/heads/main' in branches:
            return 'main'
        elif 'refs/heads/master' in branches:
            return 'master'
        else:
            raise ValueError("Neither 'main' nor 'master' branch found.")
    except Exception as e:
        print(f"Error determining default branch for {repo_path}: {str(e)}")
        return 'master'

def analyze_dependencies(repo_path: str) -> List[DependencyInfo]:
    dependencies = []
    
    # Analyze Python dependencies
    requirements_file = os.path.join(repo_path, 'requirements.txt')
    if os.path.exists(requirements_file):
        with open(requirements_file, 'r') as f:
            for line in f:
                parts = line.strip().split('==')
                dependencies.append(DependencyInfo(name=parts[0], version=parts[1] if len(parts) == 2 else None, type='external'))
    
    # Analyze JavaScript dependencies
    package_json = os.path.join(repo_path, 'package.json')
    if os.path.exists(package_json):
        with open(package_json, 'r') as f:
            data = json.load(f)
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        dependencies.append(DependencyInfo(name=name, version=version, type='external'))
    
    # Analyze internal dependencies
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    imports = re.findall(r'^\s*(?:from|import)\s+(\S+)', content, re.MULTILINE)
                    for imp in imports:
                        if not imp.startswith(('os', 'sys', 'json', 'typing')):  # Exclude standard library
                            dependencies.append(DependencyInfo(name=imp, version=None, type='internal'))
    
    return dependencies

def analyze_git_history(repo_path: str) -> Dict[str, Any]:
    try:
        repo = git.Repo(repo_path)
        commits = list(repo.iter_commits('main'))
        
        commit_history = [
            {
                'hash': commit.hexsha,
                'author': commit.author.name,
                'date': commit.committed_datetime.isoformat(),
                'message': commit.message.strip()
            }
            for commit in commits[:100]  # Limit to last 100 commits
        ]
        
        contributors = {}
        for commit in commits:
            author = commit.author
            if author.email not in contributors:
                contributors[author.email] = {
                    'name': author.name,
                    'email': author.email,
                    'commits': 0
                }
            contributors[author.email]['commits'] += 1
        
        return {
            'commit_history': commit_history,
            'contributors': list(contributors.values())
        }
    except git.exc.InvalidGitRepositoryError:
        print(f"Warning: {repo_path} is not a valid Git repository.")
        return {'commit_history': [], 'contributors': []}

def analyze_repository(repo_path: str) -> RepositoryAnalysis:
    repo_structure = {}
    file_extensions = defaultdict(int)
    total_lines = 0
    total_files = 0
    code_files = []

    for root, dirs, files in os.walk(repo_path):
        rel_path = os.path.relpath(root, repo_path)
        current_dir = repo_structure
        
        if rel_path != '.':
            for part in rel_path.split(os.sep):
                current_dir = current_dir.setdefault(part, {"files": [], "subdirs": {}})["subdirs"]

        for file in files:
            total_files += 1
            file_path = os.path.join(root, file)
            _, ext = os.path.splitext(file)
            file_extensions[ext] += 1

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    total_lines += len(lines)

                file_info = FileInfo(
                    name=file,
                    path=os.path.relpath(file_path, repo_path),
                    lines=len(lines),
                    size=os.path.getsize(file_path),
                    summary=None
                )

                if ext in ['.py', '.js', '.java', '.c', '.cpp', '.h', '.rs', '.go', '.rb', '.php', '.ua', '.toml', '.yml', '.svg', '.css', '.html']:
                    summary = summarize_code(file_path)
                    if summary:
                        file_info.summary = summary
                        code_files.append(file_path)

                if rel_path == '.':
                    repo_structure.setdefault("files", []).append(asdict(file_info))
                else:
                    current_dir["files"].append(asdict(file_info))
            except Exception as e:
                print(f"Error processing file {file_path}: {str(e)}")
    
    dependencies = analyze_dependencies(repo_path)
    git_info = analyze_git_history(repo_path)
    
    return RepositoryAnalysis(
        structure=repo_structure,
        file_extensions=dict(file_extensions),
        total_lines=total_lines,
        total_files=total_files,
        code_files=code_files,
        dependencies=dependencies,
        commit_history=git_info['commit_history'],
        contributors=git_info['contributors']
    )

def compress_analysis(analysis: RepositoryAnalysis) -> str:
    json_data = json.dumps(asdict(analysis))
    compressed = zlib.compress(json_data.encode('utf-8'))
    return base64.b64encode(compressed).decode('utf-8')

def decompress_analysis(compressed_data: str) -> RepositoryAnalysis:
    decoded = base64.b64decode(compressed_data)
    decompressed = zlib.decompress(decoded)
    data = json.loads(decompressed.decode('utf-8'))
    return RepositoryAnalysis(**data)

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
            print(f"Total files: {analysis.total_files}")
            print(f"Total lines of code: {analysis.total_lines}")
            print("File extensions:")
            for ext, count in analysis.file_extensions.items():
                print(f"  {ext}: {count}")
            
            print("\nCode files found:")
            for file in analysis.code_files[:5]:  # Limit to first 5 for brevity
                print(f"  {os.path.relpath(file, repo_path)}")
            
            if len(analysis.code_files) > 5:
                print(f"  ... and {len(analysis.code_files) - 5} more")
            
            print("\nDependencies:")
            for dep in analysis.dependencies[:10]:  # Limit to first 10 for brevity
                print(f"  {dep.name} ({dep.type})")
            
            if len(analysis.dependencies) > 10:
                print(f"  ... and {len(analysis.dependencies) - 10} more")
            
            print("\nGit Information:")
            print(f"  Total commits: {len(analysis.commit_history)}")
            print(f"  Contributors: {len(analysis.contributors)}")
            
        except Exception as e:
            print(f"Error analyzing directory {repo_path}: {str(e)}")

    print(f"\nAll analyses completed. Results are stored in the '{args.output_dir}' directory.")

if __name__ == "__main__":
    main()