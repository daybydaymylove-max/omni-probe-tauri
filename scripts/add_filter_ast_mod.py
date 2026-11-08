# -*- coding: utf-8 -*-

lib_path = "src-tauri/src/lib.rs"

with open(lib_path, "r", encoding="utf-8") as f:
    code = f.read()

target = "pub mod instance_guard;"
replacement = "pub mod instance_guard;\n// 工业级 Display Filter 抽象语法树 (AST) 编译引擎\npub mod filter_ast;"

if target in code and "pub mod filter_ast;" not in code:
    code = code.replace(target, replacement, 1)
    with open(lib_path, "w", encoding="utf-8") as f:
        f.write(code)
    print("pub mod filter_ast added to lib.rs")
else:
    print("Already added or target not found.")
