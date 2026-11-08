with open('src-tauri/src/lib.rs', 'r', encoding='utf-8') as f:
    text = f.read()

cmd_code = """
#[tauri::command]
fn fetch_paged_packets_cmd(offset: usize, limit: usize) -> Result<stream_paging::PagedPacketsResponse, String> {
    if let Ok(buf) = stream_paging::GLOBAL_STREAM_BUFFER.lock() {
        Ok(buf.fetch_page(offset, limit))
    } else {
        Err("获取分页缓冲区锁失败".into())
    }
}

#[tauri::command]
fn get_stream_buffer_stats_cmd() -> Result<stream_paging::StreamBufferStats, String> {
    if let Ok(buf) = stream_paging::GLOBAL_STREAM_BUFFER.lock() {
        Ok(buf.get_stats())
    } else {
        Err("获取流式缓冲统计失败".into())
    }
}
"""

target_cmd = "#[tauri::command]\nfn get_baseline_status_cmd()"
if target_cmd in text and "fetch_paged_packets_cmd" not in text:
    text = text.replace(target_cmd, cmd_code + "\n" + target_cmd, 1)

target_reg = "get_baseline_status_cmd,"
reg_code = "fetch_paged_packets_cmd,\n            get_stream_buffer_stats_cmd,\n            get_baseline_status_cmd,"
if target_reg in text and "fetch_paged_packets_cmd," not in text:
    text = text.replace(target_reg, reg_code, 1)

with open('src-tauri/src/lib.rs', 'w', encoding='utf-8') as f:
    f.write(text)

print("SUCCESS_INJECT")
