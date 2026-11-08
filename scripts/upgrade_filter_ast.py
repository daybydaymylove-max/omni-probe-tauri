with open("src-tauri/src/filter_ast.rs", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Add CompiledRegex and update AstNode and Token
old_ast_node = """/// 抽象语法树节点
#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    Comparison {
        field: String,
        op: CompOp,
        value: FilterValue,
    },
    BinaryLogic {
        op: LogicOp,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    UnaryNot(Box<AstNode>),
    SliceComparison {
        field: String,
        offset: usize,
        length: usize,
        op: CompOp,
        value: FilterValue,
    },
    CidrMatch {
        field: String,
        cidr: String,
    },
    AlwaysTrue,
}

/// 词法记号
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    Number(f64),
    StringLiteral(String),
    Comp(CompOp),
    Logic(LogicOp),
    Not,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    In,
    Eof,
}"""

new_ast_node = """/// 正则表达式安全包装器 (具备模式串等价性)
#[derive(Debug, Clone)]
pub struct CompiledRegex {
    pub pattern: String,
    pub inner: regex::Regex,
}

impl PartialEq for CompiledRegex {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

/// 抽象语法树节点
#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    Comparison {
        field: String,
        op: CompOp,
        value: FilterValue,
    },
    BinaryLogic {
        op: LogicOp,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    UnaryNot(Box<AstNode>),
    SliceComparison {
        field: String,
        offset: usize,
        length: usize,
        op: CompOp,
        value: FilterValue,
    },
    CidrMatch {
        field: String,
        cidr: String,
    },
    /// Wireshark 级 PCRE 正则匹配: field matches "pattern"
    RegexMatch {
        field: String,
        pattern: String,
        regex: CompiledRegex,
    },
    /// 离散值集合成员包含测试: field in [v1, v2, v3]
    InSet {
        field: String,
        values: Vec<FilterValue>,
    },
    AlwaysTrue,
}

/// 词法记号
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    Number(f64),
    StringLiteral(String),
    Comp(CompOp),
    Logic(LogicOp),
    Not,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    In,
    Matches,
    Eof,
}"""

text_lf = text.replace("\r\n", "\n")
old_ast_node_lf = old_ast_node.replace("\r\n", "\n")
new_ast_node_lf = new_ast_node.replace("\r\n", "\n")
assert old_ast_node_lf in text_lf
text_lf = text_lf.replace(old_ast_node_lf, new_ast_node_lf, 1)

# 2. Update Lexer to recognize comma and matches
old_lexer_punct = """        // 括号与符号
        match ch {
            '(' => { self.advance(); return Ok(Token::LParen); }
            ')' => { self.advance(); return Ok(Token::RParen); }
            '[' => { self.advance(); return Ok(Token::LBracket); }
            ']' => { self.advance(); return Ok(Token::RBracket); }
            ':' => { self.advance(); return Ok(Token::Colon); }
            _ => {}
        }"""

new_lexer_punct = """        // 括号与符号
        match ch {
            '(' => { self.advance(); return Ok(Token::LParen); }
            ')' => { self.advance(); return Ok(Token::RParen); }
            '[' => { self.advance(); return Ok(Token::LBracket); }
            ']' => { self.advance(); return Ok(Token::RBracket); }
            ':' => { self.advance(); return Ok(Token::Colon); }
            ',' => { self.advance(); return Ok(Token::Comma); }
            _ => {}
        }"""

old_lexer_punct_lf = old_lexer_punct.replace("\r\n", "\n")
new_lexer_punct_lf = new_lexer_punct.replace("\r\n", "\n")
assert old_lexer_punct_lf in text_lf
text_lf = text_lf.replace(old_lexer_punct_lf, new_lexer_punct_lf, 1)

old_keywords = """                "not" => return Ok(Token::Not),
                "in" => return Ok(Token::In),
                "contains" => return Ok(Token::Comp(CompOp::Contains)),"""

new_keywords = """                "not" => return Ok(Token::Not),
                "in" => return Ok(Token::In),
                "matches" => return Ok(Token::Matches),
                "contains" => return Ok(Token::Comp(CompOp::Contains)),"""

old_keywords_lf = old_keywords.replace("\r\n", "\n")
new_keywords_lf = new_keywords.replace("\r\n", "\n")
assert old_keywords_lf in text_lf
text_lf = text_lf.replace(old_keywords_lf, new_keywords_lf, 1)

# 3. Update Parser::parse_primary to support matches and in [set]
old_parser_cidr = """                // B. CIDR 子网判定支持: ip.src in "192.168.1.0/24"
                if self.current_token == Token::In {
                    self.advance()?; // 跳过 in
                    let cidr_str = match &self.current_token {
                        Token::StringLiteral(s) => s.clone(),
                        Token::Ident(raw) => raw.clone(),
                        _ => return Err(format!("字段 '{}' in 操作符后必须跟随合法的 CIDR 子网掩码", field)),
                    };
                    self.advance()?;
                    return Ok(AstNode::CidrMatch { field, cidr: cidr_str });
                }"""

new_parser_ext = """                // B. 正则表达式匹配: payload matches "(?i)admin"
                if self.current_token == Token::Matches {
                    self.advance()?;
                    let pat_str = match &self.current_token {
                        Token::StringLiteral(s) => s.clone(),
                        Token::Ident(raw) => raw.clone(),
                        _ => return Err(format!("字段 '{}' matches 之后必须跟随正则表达式字符串", field)),
                    };
                    self.advance()?;
                    let compiled = regex::Regex::new(&pat_str)
                        .map_err(|e| format!("正则表达式 '{}' 语法错误: {}", pat_str, e))?;
                    return Ok(AstNode::RegexMatch {
                        field,
                        pattern: pat_str.clone(),
                        regex: CompiledRegex { pattern: pat_str, inner: compiled },
                    });
                }

                // C. 离散集合或 CIDR 判定: field in [v1, v2] 或 ip.src in "192.168.1.0/24"
                if self.current_token == Token::In {
                    self.advance()?; // 跳过 in
                    if self.current_token == Token::LBracket {
                        self.advance()?; // 跳过 '['
                        let mut values = Vec::new();
                        while self.current_token != Token::RBracket && self.current_token != Token::Eof {
                            let val = match &self.current_token {
                                Token::Number(n) => FilterValue::Number(*n),
                                Token::StringLiteral(s) => FilterValue::String(s.clone()),
                                Token::Ident(raw) => {
                                    if let Ok(ip) = IpAddr::from_str(raw) {
                                        FilterValue::Ip(ip)
                                    } else {
                                        FilterValue::String(raw.clone())
                                    }
                                }
                                _ => return Err(format!("集合表达式包含非法元素: {:?}", self.current_token)),
                            };
                            values.push(val);
                            self.advance()?;
                            if self.current_token == Token::Comma {
                                self.advance()?; // 跳过逗号
                            }
                        }
                        if self.current_token != Token::RBracket {
                            return Err("离散集合表达式缺少闭合中括号 ']'".to_string());
                        }
                        self.advance()?; // 跳过 ']'
                        return Ok(AstNode::InSet { field, values });
                    }

                    let cidr_str = match &self.current_token {
                        Token::StringLiteral(s) => s.clone(),
                        Token::Ident(raw) => raw.clone(),
                        _ => return Err(format!("字段 '{}' in 操作符后必须跟随集合 [v1, v2] 或 CIDR 掩码", field)),
                    };
                    self.advance()?;
                    return Ok(AstNode::CidrMatch { field, cidr: cidr_str });
                }"""

old_parser_cidr_lf = old_parser_cidr.replace("\r\n", "\n")
new_parser_ext_lf = new_parser_ext.replace("\r\n", "\n")
assert old_parser_cidr_lf in text_lf
text_lf = text_lf.replace(old_parser_cidr_lf, new_parser_ext_lf, 1)

# 4. Update eval_node to evaluate RegexMatch and InSet
old_eval_cidr = """            AstNode::CidrMatch { field, cidr } => {
                let ip_to_test = match field.to_lowercase().as_str() {
                    "ip.src" | "src" | "src_ip" => src_ip,
                    "ip.dst" | "dst" | "dst_ip" => dst_ip,
                    "ip.addr" | "ip" => {
                        return check_cidr_match(src_ip, cidr) || check_cidr_match(dst_ip, cidr);
                    }
                    _ => return false,
                };
                check_cidr_match(ip_to_test, cidr)
            }
        }
    }"""

new_eval_ext = """            AstNode::CidrMatch { field, cidr } => {
                let ip_to_test = match field.to_lowercase().as_str() {
                    "ip.src" | "src" | "src_ip" => src_ip,
                    "ip.dst" | "dst" | "dst_ip" => dst_ip,
                    "ip.addr" | "ip" => {
                        return check_cidr_match(src_ip, cidr) || check_cidr_match(dst_ip, cidr);
                    }
                    _ => return false,
                };
                check_cidr_match(ip_to_test, cidr)
            }
            AstNode::RegexMatch { field, regex, .. } => {
                let field_lower = field.to_lowercase();
                let text_val = match field_lower.as_str() {
                    "payload" | "payload_text" | "data" | "frame" => payload_text.to_string(),
                    "ip.src" | "src" | "src_ip" => src_ip.to_string(),
                    "ip.dst" | "dst" | "dst_ip" => dst_ip.to_string(),
                    "protocol" | "proto" | "ip.proto" => protocol.to_string(),
                    _ => {
                        if let Some(dyn_val) = eval_dynamic_field(field, fields) {
                            match dyn_val {
                                serde_json::Value::String(s) => s,
                                serde_json::Value::Number(n) => n.to_string(),
                                serde_json::Value::Bool(b) => b.to_string(),
                                _ => dyn_val.to_string(),
                            }
                        } else {
                            String::new()
                        }
                    }
                };
                regex.inner.is_match(&text_val)
            }
            AstNode::InSet { field, values } => {
                for val in values {
                    if self.eval_comparison(field, CompOp::Eq, val, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields) {
                        return true;
                    }
                }
                false
            }
        }
    }"""

old_eval_cidr_lf = old_eval_cidr.replace("\r\n", "\n")
new_eval_ext_lf = new_eval_ext.replace("\r\n", "\n")
assert old_eval_cidr_lf in text_lf
text_lf = text_lf.replace(old_eval_cidr_lf, new_eval_ext_lf, 1)

# 5. Add unit tests for matches and in [set]
test_ext = """
    #[test]
    fn test_ast_regex_matches_and_set_membership() {
        // 1. 正则 matches 语法测试
        let filter_regex = CompiledFilter::compile("payload matches \\"(?i)unauthorized_access\\"").unwrap();
        let payload1 = "ERROR: Unauthorized_Access to PLC registers!";
        assert!(filter_regex.matches("192.168.1.10", "192.168.1.20", 1234, 502, "MODBUS", 100, 3.5, payload1));

        let payload2 = "Normal Modbus Read Request";
        assert!(!filter_regex.matches("192.168.1.10", "192.168.1.20", 1234, 502, "MODBUS", 100, 3.5, payload2));

        // 2. 离散整数集合 in [80, 443, 8080] 测试
        let filter_set = CompiledFilter::compile("tcp.dstport in [80, 443, 8080]").unwrap();
        assert!(filter_set.matches("1.1.1.1", "2.2.2.2", 50000, 443, "TCP", 64, 2.0, ""));
        assert!(filter_set.matches("1.1.1.1", "2.2.2.2", 50000, 8080, "TCP", 64, 2.0, ""));
        assert!(!filter_set.matches("1.1.1.1", "2.2.2.2", 50000, 502, "TCP", 64, 2.0, ""));

        // 3. 动态字段在集合中判定: modbus.func_code in [1, 2, 3, 4]
        let mut fields = HashMap::new();
        fields.insert("modbus.func_code".to_string(), serde_json::json!(3));
        let filter_func = CompiledFilter::compile("modbus.func_code in [1, 2, 3, 4]").unwrap();
        assert!(filter_func.matches_with_fields("10.0.0.1", "10.0.0.2", 1000, 502, "MODBUS", 64, 1.0, "", Some(&fields)));

        fields.insert("modbus.func_code".to_string(), serde_json::json!(16)); // 强写多寄存器
        assert!(!filter_func.matches_with_fields("10.0.0.1", "10.0.0.2", 1000, 502, "MODBUS", 64, 1.0, "", Some(&fields)));
    }
"""

last_brace = text_lf.rfind("}")
assert last_brace != -1
text_lf = text_lf[:last_brace] + test_ext + "\n}\n"

with open("src-tauri/src/filter_ast.rs", "w", encoding="utf-8") as f:
    f.write(text_lf)

print("Upgraded filter_ast with regex matches and in [set] successfully.")
