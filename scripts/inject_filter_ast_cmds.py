with open('src-tauri/src/lib.rs', 'r', encoding='utf-8') as f:
    text = f.read()

cmd_code = """
#[tauri::command]
fn validate_display_filter_cmd(expression: String) -> Result<bool, String> {
    filter_ast::compile_filter(&expression)
        .map(|_| true)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn filter_packets_by_ast_cmd(
    expression: String,
    records: Vec<sniffer::PacketRecord>,
) -> Result<Vec<sniffer::PacketRecord>, String> {
    let compiled = filter_ast::compile_filter(&expression)
        .map_err(|e| e.to_string())?;

    let filtered = records
        .into_iter()
        .filter(|r| compiled.matches(r))
        .collect();

    Ok(filtered)
}
"""

target_cmd = "#[tauri::command]\nfn fetch_paged_packets_cmd"
if target_cmd in text and "validate_display_filter_cmd" not in text:
    text = text.replace(target_cmd, cmd_code + "\n" + target_cmd, 1)

target_reg = "fetch_paged_packets_cmd,"
reg_code = "validate_display_filter_cmd,\n            filter_packets_by_ast_cmd,\n            fetch_paged_packets_cmd,"
if target_reg in text and "validate_display_filter_cmd," not in text:
    text = text.replace(target_reg, reg_code, 1)

with open('src-tauri/src/lib.rs', 'w', encoding='utf-8') as f:
    f.write(text)

print("FILTER_AST_CMDS_INJECTED")
