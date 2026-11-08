with open("src-tauri/src/serial.rs", "r", encoding="utf-8") as f:
    text = f.read()

vcd_impl = """
// ============================================================
// VCD (Value Change Dump / IEEE 1364) 逻辑分析仪物理采样波形解调引擎
// 对标 sigrok / PulseView / Saleae Logic 硬件底层信号分析
// ============================================================

/// 逻辑分析仪采样点跳变事件
#[derive(Debug, Clone, PartialEq)]
pub struct VcdTransition {
    pub timestamp_us: u64,
    pub level: u8,
}

/// 逻辑分析仪波形解析与 UART 物理重组结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcdUartDecodedResult {
    pub decoded_bytes: Vec<u8>,
    pub decoded_text: String,
    pub total_sample_duration_us: u64,
    pub detected_baud_rate: u32,
    pub framing_errors: usize,
    pub glitch_count: usize,
}

/// 解析 VCD 物理波形并按指定波特率执行 UART 采样恢复
/// 时间复杂度: O(N) 顺序单遍扫描, 空间复杂度: O(N)
pub fn decode_vcd_uart_waveform(
    vcd_content: &str,
    target_signal: &str,
    baud_rate: u32,
) -> Result<VcdUartDecodedResult, String> {
    let mut signal_sym = "!".to_string();
    for line in vcd_content.lines() {
        let t = line.trim();
        if t.starts_with("$var") && t.contains(target_signal) {
            let tokens: Vec<&str> = t.split_whitespace().collect();
            if tokens.len() >= 5 {
                signal_sym = tokens[3].to_string();
                break;
            }
        }
    }

    let mut transitions = Vec::new();
    let mut cur_time = 0u64;

    for line in vcd_content.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            if let Ok(ts) = t[1..].parse::<u64>() {
                cur_time = ts;
            }
        } else if t.ends_with(&signal_sym) && t.len() >= 2 {
            let lvl_char = t.chars().next().unwrap();
            let level = if lvl_char == '1' { 1 } else { 0 };
            transitions.push(VcdTransition { timestamp_us: cur_time, level });
        }
    }

    if transitions.is_empty() {
        return Err("VCD 文件中未找到有效的电平跳变事件".to_string());
    }

    let bit_period_us = 1_000_000.0 / (baud_rate as f64);
    let sample_level_at = |time_us: f64| -> u8 {
        let mut last_lvl = 1u8;
        for tr in &transitions {
            if (tr.timestamp_us as f64) <= time_us {
                last_lvl = tr.level;
            } else {
                break;
            }
        }
        last_lvl
    };

    let total_duration = transitions.last().map(|t| t.timestamp_us).unwrap_or(0);
    let mut decoded_bytes = Vec::new();
    let mut framing_errors = 0;
    let mut glitch_count = 0;

    let mut idx = 1;
    let mut next_allowed_search_time = 0.0;

    while idx < transitions.len() {
        let prev = &transitions[idx - 1];
        let curr = &transitions[idx];

        if (curr.timestamp_us as f64) >= next_allowed_search_time && prev.level == 1 && curr.level == 0 {
            let t_start = curr.timestamp_us as f64;

            if idx + 1 < transitions.len() && (transitions[idx + 1].timestamp_us as f64 - t_start) < (0.2 * bit_period_us) {
                glitch_count += 1;
                idx += 1;
                continue;
            }

            let mid_start = sample_level_at(t_start + 0.5 * bit_period_us);
            if mid_start == 0 {
                let mut byte_val = 0u8;
                for b in 0..8 {
                    let sample_t = t_start + (1.5 + b as f64) * bit_period_us;
                    let bit_val = sample_level_at(sample_t);
                    byte_val |= bit_val << b;
                }

                let stop_sample_t = t_start + 9.5 * bit_period_us;
                let stop_val = sample_level_at(stop_sample_t);
                if stop_val != 1 {
                    framing_errors += 1;
                }

                decoded_bytes.push(byte_val);
                next_allowed_search_time = t_start + 10.0 * bit_period_us;
            }
        }
        idx += 1;
    }

    let text_repr: String = decoded_bytes
        .iter()
        .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
        .collect();

    Ok(VcdUartDecodedResult {
        decoded_bytes,
        decoded_text: text_repr,
        total_sample_duration_us: total_duration,
        detected_baud_rate: baud_rate,
        framing_errors,
        glitch_count,
    })
}
"""

test_vcd = """
    #[test]
    fn test_vcd_waveform_uart_physical_decoding() {
        // 模拟 sigrok 导出的 115200 bps (位周期约 8.68 us) UART 字符 'A' (0x41 = 0b01000001)
        // LSB First 传输: Start(0), Bit0(1), Bit1(0), Bit2(0), Bit3(0), Bit4(0), Bit5(0), Bit6(1), Bit7(0), Stop(1)
        let vcd_content = r#"
$date 2026-11-08 $end
$version sigrok 0.5.2 $end
$timescale 1 us $end
$scope module top $end
$var wire 1 ! rx $end
$upscope $end
$enddefinitions $end
#0
1!
#10
0!
#19
1!
#27
0!
#71
1!
#79
0!
#88
1!
#120
1!
"#;

        let result = decode_vcd_uart_waveform(vcd_content, "rx", 115200).expect("VCD 解码失败");
        assert_eq!(result.decoded_bytes.len(), 1);
        assert_eq!(result.decoded_bytes[0], b'A');
        assert_eq!(result.decoded_text, "A");
        assert_eq!(result.framing_errors, 0);
    }
"""

text_lf = text.replace("\r\n", "\n")
marker = "#[cfg(test)]\nmod tests {"
assert marker in text_lf
text_lf = text_lf.replace(marker, vcd_impl + "\n" + marker, 1)

last_brace = text_lf.rfind("}")
assert last_brace != -1
text_lf = text_lf[:last_brace] + test_vcd + "\n}\n"

with open("src-tauri/src/serial.rs", "w", encoding="utf-8") as f:
    f.write(text_lf)

print("Added VCD waveform decoder to serial.rs successfully.")
