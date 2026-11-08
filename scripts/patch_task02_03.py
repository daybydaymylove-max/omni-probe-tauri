with open('src-tauri/src/sniffer.rs', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. 替换 baseline_learning 调用
target_baseline = '''    crate::baseline_learning::process_packet_for_baseline(
        app,
        &record.src_ip,
        &record.dst_ip,
        &record.protocol,
        record.dst_port,
        is_modbus_write,
        is_cross_zone,
    );'''

replacement_baseline = '''    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    crate::baseline_learning::process_packet_for_baseline_temporal(
        app,
        &record.src_ip,
        &record.dst_ip,
        &record.protocol,
        record.dst_port,
        is_modbus_write,
        is_cross_zone,
        record.length,
        now_ms,
    );'''

if target_baseline in text:
    text = text.replace(target_baseline, replacement_baseline, 1)

# 2. 插入 stream_paging 调用
target_paging = '''    // 推送前端渲染
    let _ = app.emit("packet-received", &record);'''

replacement_paging = '''    // (8) 异步流式分页缓冲与自动分卷 PCAPng 滚动落盘 (解耦 IPC，保障百万级流量有界内存)
    crate::stream_paging::buffer_packet_and_auto_flush(record.clone());

    // 推送前端渲染
    let _ = app.emit("packet-received", &record);'''

if target_paging in text:
    text = text.replace(target_paging, replacement_paging, 1)

with open('src-tauri/src/sniffer.rs', 'w', encoding='utf-8') as f:
    f.write(text)

print("TASK02_TASK03_PATCHED")
