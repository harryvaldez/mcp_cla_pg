import ast

SERVER_FILE = "server.py"

with open(SERVER_FILE, "r", encoding="utf-8") as f:
    src = f.read()

tree = ast.parse(src, filename=SERVER_FILE)

# Look specifically for task_progress_demo
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name == "task_progress_demo":
        print(f"Found task_progress_demo at line {node.lineno}")
        print(f"Decorators: {node.decorator_list}")
        for dec in node.decorator_list:
            print(f"  Decorator type: {type(dec)}")
            if isinstance(dec, ast.Call):
                print(f"    Call func: {dec.func}")
                print(f"    Keywords: {dec.keywords}")
        break
else:
    print("task_progress_demo not found in top-level functions")

# Check if it's nested
for node in tree.body:
    if isinstance(node, ast.AsyncFunctionDef) and node.name == "task_progress_demo":
        print(f"Found task_progress_demo (async) at line {node.lineno}")
        print(f"Decorators: {node.decorator_list}")
        break

# Try scanning with AsyncFunctionDef
print("\n\nScanning for all functions (FunctionDef + AsyncFunctionDef):")
discovered = []
for node in tree.body:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        continue
    has_tool_decorator = False
    tool_name = None
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        is_mcp_tool = (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "mcp"
            and target.attr == "tool"
        )
        is_tool = isinstance(target, ast.Name) and target.id == "tool"
        
        if is_mcp_tool or is_tool:
            has_tool_decorator = True
            # Extract tool name from decorator if provided
            if isinstance(dec, ast.Call):
                for keyword in dec.keywords:
                    if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                        tool_name = keyword.value.value
                        break
            break
    if has_tool_decorator:
        # Use the tool name from decorator, or fall back to function name
        name_to_add = tool_name if tool_name else node.name
        if "demo" in node.name or "dependency" in node.name or "elicitation" in node.name or "logging" in node.name or "context" in node.name or "runtime" in node.name:
            print(f"Found: func_name={node.name}, tool_name={tool_name}, final={name_to_add}")
        discovered.append(name_to_add)

print("\n\nAll demo/Phase 4 tools found:")
for d in sorted(set(discovered)):
    if any(x in d for x in ["demo", "dependency", "elicitation", "logging", "context", "runtime"]):
        print(f"  {d}")

expected = [
    "task_progress_demo",
    "dependency_injection_snapshot",
    "elicitation_collect_maintenance_window",
    "elicitation_create_maintenance_ticket",
    "logging_demo",
    "server_runtime_config_snapshot",
    "context_state_demo",
]

print(f"\n\nExpected: {expected}")
missing = [t for t in expected if t not in discovered]
print(f"Missing: {missing}")

