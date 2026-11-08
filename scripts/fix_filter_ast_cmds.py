with open('src-tauri/src/lib.rs', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''#[tauri::command]
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
}'''

replacement = '''#[tauri::command]
fn validate_display_filter_cmd(expression: String) -> Result<bool, String> {
    filter_ast::CompiledFilter::compile(&expression)
        .map(|_| true)
        .map_err(|e| e)
}

#[tauri::command]
fn filter_packets_by_ast_cmd(
    expression: String,
    records: Vec<sniffer::PacketRecord>,
) -> Result<Vec<sniffer::PacketRecord>, String> {
    let compiled = filter_ast::CompiledFilter::compile(&expression)
        .map_err(|e| e)?;

    let filtered = records
        .into_iter()
        .filter(|r| {
            let p_text = r.raw_text.as_deref().unwrap_or("");
            compiled.matches(
                &r.src_ip,
                &r.dst_ip,
                r.src_port,
                r.dst_port,
                &r.protocol,
                r.length,
                r.entropy,
                p_text,
            )
        })
        .collect();

    Ok(filtered)
}'''

if target in text:
    text = text.replace(target, replacement, 1)
    with open('src-tauri/src/lib.rs', 'w', encoding='utf-8') as f:
        f.write(text)
    print("FIX_SUCCESS")
else:
    print("TARGET_NOT_FOUND")
