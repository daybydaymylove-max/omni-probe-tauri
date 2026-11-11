// ============================================================
// 工业全能网络探针 - 工业级 Display Filter 抽象语法树 (AST) 编译器
// 模块名称: filter_ast.rs
//
// 核心职责:
// 1. 词法分析器 (Lexer): 零依赖手写高性能 Tokenizer, 时间复杂度 O(N);
// 2. 语法分析器 (Parser): 递归下降结合优先级爬升生成不可变 AST 树, 时间复杂度 O(N);
// 3. 语义求值器 (Evaluator): 微秒级对原始报文执行类型安全关系判定与短路求值, 时间复杂度 O(Depth);
// 4. 防御性语法容错: 健全的语法报错定位与类型自动提升转换;
// 5. 协议字段注册表 (ProtocolFieldRegistry): 对标 Wireshark hf_register_info 与 proto_tree 动态字段下推.
// ============================================================

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use serde::{Deserialize, Serialize};

/// 比较运算符
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompOp {
    Eq,        // ==
    Neq,       // !=
    Gt,        // >
    Lt,        // <
    Gte,       // >=
    Lte,       // <=
    Contains,  // contains
}

/// 逻辑运算符
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicOp {
    And, // &&, and
    Or,  // ||, or
}

/// 过滤器字面量值
#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    Number(f64),
    String(String),
    Ip(IpAddr),
}

/// 正则表达式安全包装器 (具备模式串等价性)
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
    /// Wireshark 级相对算术运算与跨层字段联动比较: frame.len - ip.len > 14
    ArithmeticComparison {
        left: ArithExpr,
        op: CompOp,
        right: ArithExpr,
    },
    AlwaysTrue,
    AlwaysFalse,
}

/// 算术运算符 (对标 Wireshark dfilter 相对算术表达式)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add, // +
    Sub, // -
    Mul, // *
    Div, // /
    Mod, // %
}

/// 算术表达式节点
#[derive(Debug, Clone, PartialEq)]
pub enum ArithExpr {
    Number(f64),
    Field(String),
    Binary {
        op: ArithOp,
        left: Box<ArithExpr>,
        right: Box<ArithExpr>,
    },
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
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    In,
    Matches,
    Eof,
}

/// 协议字段类型定义 (对标 Wireshark ftenum)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    Integer,
    Float,
    String,
    Boolean,
    Bytes,
    IpAddress,
}

/// 注册的协议字段描述条目 (对标 Wireshark hf_register_info)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefinition {
    pub name: String,
    pub protocol: String,
    pub field_type: FieldType,
    pub description: String,
}

/// 词法扫描器
pub struct Lexer<'a> {
    _input: &'a str,
    chars: Vec<(usize, char)>,
    cursor: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            _input: input,
            chars: input.char_indices().collect(),
            cursor: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        if self.cursor < self.chars.len() {
            Some(self.chars[self.cursor].1)
        } else {
            None
        }
    }

    fn advance(&mut self) -> Option<char> {
        if self.cursor < self.chars.len() {
            let ch = self.chars[self.cursor].1;
            self.cursor += 1;
            Some(ch)
        } else {
            None
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    /// 提取下一个 Token
    pub fn next_token(&mut self) -> Result<Token, String> {
        self.skip_whitespace();

        let ch = match self.peek() {
            Some(c) => c,
            None => return Ok(Token::Eof),
        };

        // 括号与符号
        match ch {
            '(' => { self.advance(); return Ok(Token::LParen); }
            ')' => { self.advance(); return Ok(Token::RParen); }
            '[' => { self.advance(); return Ok(Token::LBracket); }
            ']' => { self.advance(); return Ok(Token::RBracket); }
            ':' => { self.advance(); return Ok(Token::Colon); }
            ',' => { self.advance(); return Ok(Token::Comma); }
            '+' => { self.advance(); return Ok(Token::Plus); }
            '-' => { self.advance(); return Ok(Token::Minus); }
            '*' => { self.advance(); return Ok(Token::Star); }
            '%' => { self.advance(); return Ok(Token::Percent); }
            '/' => {
                self.advance();
                if self.peek() == Some('/') {
                    while let Some(c) = self.advance() {
                        if c == '\n' { break; }
                    }
                    return self.next_token();
                }
                return Ok(Token::Slash);
            }
            _ => {}
        }

        // 逻辑与比较运算符 (双字符/单字符)
        if ch == '&' {
            self.advance();
            if self.peek() == Some('&') {
                self.advance();
                return Ok(Token::Logic(LogicOp::And));
            }
            return Err("词法错误: 预期 '&&' 但遇到了单个 '&'".to_string());
        }

        if ch == '|' {
            self.advance();
            if self.peek() == Some('|') {
                self.advance();
                return Ok(Token::Logic(LogicOp::Or));
            }
            return Err("词法错误: 预期 '||' 但遇到了单个 '|'".to_string());
        }

        if ch == '!' {
            self.advance();
            if self.peek() == Some('=') {
                self.advance();
                return Ok(Token::Comp(CompOp::Neq));
            }
            return Ok(Token::Not);
        }

        if ch == '=' {
            self.advance();
            if self.peek() == Some('=') {
                self.advance();
                return Ok(Token::Comp(CompOp::Eq));
            }
            // 允许单个 '=' 宽容映射为 '=='
            return Ok(Token::Comp(CompOp::Eq));
        }

        if ch == '>' {
            self.advance();
            if self.peek() == Some('=') {
                self.advance();
                return Ok(Token::Comp(CompOp::Gte));
            }
            return Ok(Token::Comp(CompOp::Gt));
        }

        if ch == '<' {
            self.advance();
            if self.peek() == Some('=') {
                self.advance();
                return Ok(Token::Comp(CompOp::Lte));
            }
            return Ok(Token::Comp(CompOp::Lt));
        }

        // 字符串字面量: "..." 或 '...'
        if ch == '"' || ch == '\'' {
            let quote = ch;
            self.advance(); // consume opening quote
            let mut s = String::new();
            let mut closed = false;

            while let Some(c) = self.advance() {
                if c == quote {
                    closed = true;
                    break;
                }
                if c == '\\' {
                    if let Some(escaped) = self.advance() {
                        s.push(escaped);
                    }
                } else {
                    s.push(c);
                }
            }

            if !closed {
                return Err("词法错误: 字符串字面量未闭合".to_string());
            }

            return Ok(Token::StringLiteral(s));
        }

        // 数字字面量 (支持十进制、浮点数以及 0x 十六进制)
        if ch.is_ascii_digit() {
            let start = self.cursor;
            self.advance();

            // 检查 0x 十六进制
            if ch == '0' && (self.peek() == Some('x') || self.peek() == Some('X')) {
                self.advance(); // consume 'x'
                let hex_start = self.cursor;
                while let Some(c) = self.peek() {
                    if c.is_ascii_hexdigit() {
                        self.advance();
                    } else {
                        break;
                    }
                }
                let hex_str: String = self.chars[hex_start..self.cursor].iter().map(|&(_, c)| c).collect();
                if hex_str.is_empty() {
                    return Err("词法错误: 0x 后缺失十六进制数字".to_string());
                }
                let num = u64::from_str_radix(&hex_str, 16)
                    .map_err(|e| format!("十六进制解析错误: {}", e))? as f64;
                return Ok(Token::Number(num));
            }

            // 常规十进制与浮点数
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() || c == '.' {
                    self.advance();
                } else {
                    break;
                }
            }

            let num_str: String = self.chars[start..self.cursor].iter().map(|&(_, c)| c).collect();
            // 如果点号有多个，则可能是 IPv4 地址或者字段，先检查 parse::<f64>
            if let Ok(num) = num_str.parse::<f64>() {
                return Ok(Token::Number(num));
            }
            // 若不是合规浮点数，回退视为标识符
            return Ok(Token::Ident(num_str));
        }

        // 标识符 (保留字, 字段名, IP 地址字面量等)
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '/' {
            let start = self.cursor;
            while let Some(c) = self.peek() {
                if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '/' || c == '-' {
                    self.advance();
                } else {
                    break;
                }
            }

            let ident_str: String = self.chars[start..self.cursor].iter().map(|&(_, c)| c).collect();
            let lower = ident_str.to_lowercase();

            // 关键词判定
            match lower.as_str() {
                "and" => return Ok(Token::Logic(LogicOp::And)),
                "or" => return Ok(Token::Logic(LogicOp::Or)),
                "not" => return Ok(Token::Not),
                "in" => return Ok(Token::In),
                "matches" => return Ok(Token::Matches),
                "contains" => return Ok(Token::Comp(CompOp::Contains)),
                "eq" => return Ok(Token::Comp(CompOp::Eq)),
                "ne" => return Ok(Token::Comp(CompOp::Neq)),
                "gt" => return Ok(Token::Comp(CompOp::Gt)),
                "ge" => return Ok(Token::Comp(CompOp::Gte)),
                "lt" => return Ok(Token::Comp(CompOp::Lt)),
                "le" => return Ok(Token::Comp(CompOp::Lte)),
                _ => return Ok(Token::Ident(ident_str)),
            }
        }

        Err(format!("词法错误: 无法识别字符 '{}'", ch))
    }
}

/// 递归下降语法分析器
pub struct Parser<'a> {
    lexer: Lexer<'a>,
    current_token: Token,
}

impl<'a> Parser<'a> {
    pub fn new(mut lexer: Lexer<'a>) -> Result<Self, String> {
        let first = lexer.next_token()?;
        Ok(Self {
            lexer,
            current_token: first,
        })
    }

    fn advance(&mut self) -> Result<(), String> {
        self.current_token = self.lexer.next_token()?;
        Ok(())
    }

    /// 解析完整表达式入口
    pub fn parse_expression(&mut self) -> Result<AstNode, String> {
        let node = self.parse_or()?;
        if self.current_token != Token::Eof {
            return Err(format!("语法错误: 表达式解析结束后遇到冗余记号 {:?}", self.current_token));
        }
        Ok(node)
    }

    /// 语法规则: OrExpr -> AndExpr ( '||' AndExpr )*
    fn parse_or(&mut self) -> Result<AstNode, String> {
        let mut left = self.parse_and()?;

        while self.current_token == Token::Logic(LogicOp::Or) {
            self.advance()?;
            let right = self.parse_and()?;
            left = AstNode::BinaryLogic {
                op: LogicOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// 语法规则: AndExpr -> UnaryExpr ( '&&' UnaryExpr )*
    fn parse_and(&mut self) -> Result<AstNode, String> {
        let mut left = self.parse_unary()?;

        while self.current_token == Token::Logic(LogicOp::And) {
            self.advance()?;
            let right = self.parse_unary()?;
            left = AstNode::BinaryLogic {
                op: LogicOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// 语法规则: UnaryExpr -> '!' UnaryExpr | PrimaryExpr
    fn parse_unary(&mut self) -> Result<AstNode, String> {
        if self.current_token == Token::Not {
            self.advance()?;
            let sub = self.parse_unary()?;
            return Ok(AstNode::UnaryNot(Box::new(sub)));
        }
        self.parse_primary()
    }

    /// 语法规则: PrimaryExpr -> '(' Expr ')' | Comparison
    fn parse_primary(&mut self) -> Result<AstNode, String> {
        match &self.current_token {
            Token::LParen => {
                self.advance()?;
                let expr = self.parse_or()?;
                if self.current_token != Token::RParen {
                    return Err("语法错误: 缺失闭合括号 ')'".to_string());
                }
                self.advance()?;
                Ok(expr)
            }
            Token::Ident(field_name) => {
                let field = field_name.clone();
                self.advance()?;

                // A. 切片语法支持: payload[0:4] == "GET "
                if self.current_token == Token::LBracket {
                    self.advance()?; // 跳过 '['
                    let offset = match self.current_token {
                        Token::Number(n) => n as usize,
                        _ => return Err("切片语法起始偏移必须为整数, 如 [0:4]".to_string()),
                    };
                    self.advance()?; // 跳过 offset
                    if self.current_token != Token::Colon {
                        return Err("切片语法缺少冒号分隔符, 格式应为 [offset:length]".to_string());
                    }
                    self.advance()?; // 跳过 ':'
                    let length = match self.current_token {
                        Token::Number(n) => n as usize,
                        _ => return Err("切片语法长度必须为整数, 如 [0:4]".to_string()),
                    };
                    self.advance()?; // 跳过 length
                    if self.current_token != Token::RBracket {
                        return Err("切片语法缺少闭合中括号 ']'".to_string());
                    }
                    self.advance()?; // 跳过 ']'

                    let op = match &self.current_token {
                        Token::Comp(op) => *op,
                        _ => return Err(format!("切片表达式 '{}[{}:{}]' 后必须跟随比较操作符", field, offset, length)),
                    };
                    self.advance()?;

                    let value = match &self.current_token {
                        Token::Number(n) => FilterValue::Number(*n),
                        Token::StringLiteral(s) => FilterValue::String(s.clone()),
                        Token::Ident(raw) => FilterValue::String(raw.clone()),
                        _ => return Err("切片比较操作符后缺失有效值".to_string()),
                    };
                    self.advance()?;
                    return Ok(AstNode::SliceComparison { field, offset, length, op, value });
                }

                // B. 正则表达式匹配: payload matches "(?i)admin"
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
                }

                // D. 算术运算符支持: field - other_field > 14
                if matches!(
                    self.current_token,
                    Token::Plus | Token::Minus | Token::Star | Token::Slash | Token::Percent
                ) {
                    let left_expr = self.continue_parse_arith_additive(ArithExpr::Field(field))?;
                    let op = match &self.current_token {
                        Token::Comp(op) => *op,
                        other => return Err(format!("算术表达式后期望比较操作符，实际为 {:?}", other)),
                    };
                    self.advance()?;
                    let right_expr = self.parse_arith_expr()?;
                    return Ok(AstNode::ArithmeticComparison { left: left_expr, op, right: right_expr });
                }

                // 期望比较运算符
                let op = match &self.current_token {
                    Token::Comp(op) => *op,
                    _ => {
                        // 简写支持: 单独字段如 "modbus", 等价于 protocol contains "modbus"
                        return Ok(AstNode::Comparison {
                            field: "protocol".to_string(),
                            op: CompOp::Contains,
                            value: FilterValue::String(field),
                        });
                    }
                };

                self.advance()?;

                // 期望右侧操作数
                let value = match &self.current_token {
                    Token::Number(n) => {
                        let num = *n;
                        self.advance()?;
                        if matches!(
                            self.current_token,
                            Token::Plus | Token::Minus | Token::Star | Token::Slash | Token::Percent
                        ) {
                            let right_expr = self.continue_parse_arith_additive(ArithExpr::Number(num))?;
                            return Ok(AstNode::ArithmeticComparison {
                                left: ArithExpr::Field(field),
                                op,
                                right: right_expr,
                            });
                        }
                        FilterValue::Number(num)
                    }
                    Token::StringLiteral(s) => {
                        let s_clone = s.clone();
                        self.advance()?;
                        FilterValue::String(s_clone)
                    }
                    Token::Ident(raw) => {
                        let raw_clone = raw.clone();
                        self.advance()?;
                        if matches!(
                            self.current_token,
                            Token::Plus | Token::Minus | Token::Star | Token::Slash | Token::Percent
                        ) {
                            let right_expr = self.continue_parse_arith_additive(ArithExpr::Field(raw_clone))?;
                            return Ok(AstNode::ArithmeticComparison {
                                left: ArithExpr::Field(field),
                                op,
                                right: right_expr,
                            });
                        }
                        if let Ok(ip) = IpAddr::from_str(&raw_clone) {
                            FilterValue::Ip(ip)
                        } else {
                            FilterValue::String(raw_clone)
                        }
                    }
                    _ => return Err(format!("字段 '{}' 的操作符后缺失有效比较值", field)),
                };

                Ok(AstNode::Comparison { field, op, value })
            }
            Token::Number(n) => {
                let num = *n;
                self.advance()?;
                let left_expr = self.continue_parse_arith_additive(ArithExpr::Number(num))?;
                let op = match &self.current_token {
                    Token::Comp(op) => *op,
                    other => return Err(format!("数值或算术表达式后期望比较操作符，实际为 {:?}", other)),
                };
                self.advance()?;
                let right_expr = self.parse_arith_expr()?;
                Ok(AstNode::ArithmeticComparison {
                    left: left_expr,
                    op,
                    right: right_expr,
                })
            }
            Token::Eof => Ok(AstNode::AlwaysTrue),
            other => Err(format!("非预期的记号: {:?}", other)),
        }
    }

    fn parse_arith_expr(&mut self) -> Result<ArithExpr, String> {
        self.parse_arith_additive()
    }

    fn parse_arith_additive(&mut self) -> Result<ArithExpr, String> {
        let mut left = self.parse_arith_multiplicative()?;
        while matches!(self.current_token, Token::Plus | Token::Minus) {
            let op = match self.current_token {
                Token::Plus => ArithOp::Add,
                Token::Minus => ArithOp::Sub,
                _ => unreachable!(),
            };
            self.advance()?;
            let right = self.parse_arith_multiplicative()?;
            left = ArithExpr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn continue_parse_arith_additive(&mut self, mut left: ArithExpr) -> Result<ArithExpr, String> {
        while matches!(self.current_token, Token::Plus | Token::Minus | Token::Star | Token::Slash | Token::Percent) {
            let op = match self.current_token {
                Token::Plus => ArithOp::Add,
                Token::Minus => ArithOp::Sub,
                Token::Star => ArithOp::Mul,
                Token::Slash => ArithOp::Div,
                Token::Percent => ArithOp::Mod,
                _ => unreachable!(),
            };
            self.advance()?;
            let right = self.parse_arith_multiplicative()?;
            left = ArithExpr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_arith_multiplicative(&mut self) -> Result<ArithExpr, String> {
        let mut left = self.parse_arith_primary()?;
        while matches!(self.current_token, Token::Star | Token::Slash | Token::Percent) {
            let op = match self.current_token {
                Token::Star => ArithOp::Mul,
                Token::Slash => ArithOp::Div,
                Token::Percent => ArithOp::Mod,
                _ => unreachable!(),
            };
            self.advance()?;
            let right = self.parse_arith_primary()?;
            left = ArithExpr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_arith_primary(&mut self) -> Result<ArithExpr, String> {
        match &self.current_token {
            Token::Number(n) => {
                let val = *n;
                self.advance()?;
                Ok(ArithExpr::Number(val))
            }
            Token::Ident(name) => {
                let field = name.clone();
                self.advance()?;
                Ok(ArithExpr::Field(field))
            }
            Token::LParen => {
                self.advance()?;
                let expr = self.parse_arith_expr()?;
                if self.current_token != Token::RParen {
                    return Err("算术表达式括号未闭合".to_string());
                }
                self.advance()?;
                Ok(expr)
            }
            other => Err(format!("期望数值或字段名作为算术操作数，实际为 {:?}", other)),
        }
    }
}

// ============================================================
// 工业级 Display Filter 抽象语法树重写、常量折叠与求值优化器 (AstOptimizer)
// 对标 Wireshark 30 年沉淀的 GNode 虚拟机与 AST 编译优化器 (dfilter/dfvm)
//
// 核心能力:
// 1. 常量算术折叠 (Arithmetic Constant Folding): 纯常数子树预计算 (如 10+20*2 => 50);
// 2. 代数恒等律与消元 (Algebraic Identities): x+0=>x, x*1=>x, x*0=>0, x-x=>0, x/x=>1;
// 3. 算术比较单调移项归一化与降维 (Term Normalization & Relocation):
//    frame.len - 14 > 100 自动移项归一化为 frame.len > 114, 并直接降维重写为原生单字段 Comparison,
//    跳过运行时动态算术虚拟机求值开销;
// 4. 布尔代数优化与短路求值 (Boolean Algebra Simplification):
//    - 德·摩根定律下推: !(A && B) => !A || !B, !(A || B) => !A && !B;
//    - 双重否定消除: !(!A) => A;
//    - 比较操作符下推取反: !(field == val) => field != val, !(x > y) => x <= y;
//    - 零元与幺元消去: A && True => A, A && False => False, A || True => True, A || False => A;
//    - 幂等律与互斥矛盾消除: A && A => A, A && !A => False, A || !A => True;
// 5. 离散集合 (InSet) 优化: 空集 => False, 单元素集合自动退化为等值比较 (in [80] => == 80), 自动去重;
// 6. 不动点多轮级联收敛循环 (Fixed-Point Optimization Loop): 保证多重嵌套规则完全收敛.
// ============================================================

/// 翻转比较运算符 (当左右操作数交换时使用: left op right <=> right flip(op) left)
pub fn flip_comp_op(op: CompOp) -> CompOp {
    match op {
        CompOp::Eq => CompOp::Eq,
        CompOp::Neq => CompOp::Neq,
        CompOp::Gt => CompOp::Lt,
        CompOp::Lt => CompOp::Gt,
        CompOp::Gte => CompOp::Lte,
        CompOp::Lte => CompOp::Gte,
        CompOp::Contains => CompOp::Contains,
    }
}

/// 否定取反比较运算符 (当外部存在否定逻辑时下推: !(left op right) <=> left invert(op) right)
pub fn invert_comp_op(op: CompOp) -> Option<CompOp> {
    match op {
        CompOp::Eq => Some(CompOp::Neq),
        CompOp::Neq => Some(CompOp::Eq),
        CompOp::Gt => Some(CompOp::Lte),
        CompOp::Lt => Some(CompOp::Gte),
        CompOp::Gte => Some(CompOp::Lt),
        CompOp::Lte => Some(CompOp::Gt),
        CompOp::Contains => None, // contains 取反通常保持 UnaryNot 语义
    }
}

/// 判断指定协议字段在单个报文中是否为唯一单值字段
fn is_single_valued_field(field: &str) -> bool {
    let fl = field.to_lowercase();
    matches!(
        fl.as_str(),
        "tcp.srcport" | "tcp.dstport" | "udp.srcport" | "udp.dstport" | "ip.src" | "ip.dst" | "length" | "len" | "frame.len" | "entropy" | "protocol"
    )
}

/// 递归执行算术表达式常量折叠与代数恒等律消元
/// 时间复杂度: O(N), 空间复杂度: O(Depth)
pub fn fold_arith_constants(expr: ArithExpr) -> ArithExpr {
    match expr {
        ArithExpr::Number(n) => ArithExpr::Number(n),
        ArithExpr::Field(f) => ArithExpr::Field(f),
        ArithExpr::Binary { op, left, right } => {
            let left_folded = fold_arith_constants(*left);
            let right_folded = fold_arith_constants(*right);

            // 1. 纯常数折叠 (Pure Constant Folding)
            if let (ArithExpr::Number(l), ArithExpr::Number(r)) = (&left_folded, &right_folded) {
                let res = match op {
                    ArithOp::Add => Some(l + r),
                    ArithOp::Sub => Some(l - r),
                    ArithOp::Mul => Some(l * r),
                    ArithOp::Div => if *r != 0.0 { Some(l / r) } else { None },
                    ArithOp::Mod => if *r != 0.0 { Some(l % r) } else { None },
                };
                if let Some(val) = res {
                    return ArithExpr::Number(val);
                }
            }

            // 2. 代数恒等律与消元优化 (Algebraic Identities & Annihilators)
            match op {
                ArithOp::Add => {
                    // x + 0 => x
                    if let ArithExpr::Number(n) = left_folded {
                        if n == 0.0 { return right_folded; }
                    }
                    if let ArithExpr::Number(n) = right_folded {
                        if n == 0.0 { return left_folded; }
                    }
                }
                ArithOp::Sub => {
                    // x - 0 => x
                    if let ArithExpr::Number(n) = right_folded {
                        if n == 0.0 { return left_folded; }
                    }
                    // x - x => 0
                    if left_folded == right_folded {
                        return ArithExpr::Number(0.0);
                    }
                }
                ArithOp::Mul => {
                    // x * 1 => x, 1 * x => x
                    if let ArithExpr::Number(n) = left_folded {
                        if n == 1.0 { return right_folded; }
                        if n == 0.0 { return ArithExpr::Number(0.0); }
                    }
                    if let ArithExpr::Number(n) = right_folded {
                        if n == 1.0 { return left_folded; }
                        if n == 0.0 { return ArithExpr::Number(0.0); }
                    }
                }
                ArithOp::Div => {
                    // x / 1 => x
                    if let ArithExpr::Number(n) = right_folded {
                        if n == 1.0 { return left_folded; }
                    }
                    // x / x => 1 (非零)
                    if left_folded == right_folded {
                        return ArithExpr::Number(1.0);
                    }
                }
                ArithOp::Mod => {}
            }

            ArithExpr::Binary {
                op,
                left: Box::new(left_folded),
                right: Box::new(right_folded),
            }
        }
    }
}

/// 工业级 AST 语法树重写与短路优化执行引擎
pub struct AstOptimizer;

impl AstOptimizer {
    /// 统计语法树节点总数 (用于衡量优化压缩比与树深度)
    pub fn node_count(node: &AstNode) -> usize {
        match node {
            AstNode::AlwaysTrue | AstNode::AlwaysFalse => 1,
            AstNode::Comparison { .. } => 1,
            AstNode::SliceComparison { .. } => 1,
            AstNode::CidrMatch { .. } => 1,
            AstNode::RegexMatch { .. } => 1,
            AstNode::InSet { .. } => 1,
            AstNode::ArithmeticComparison { .. } => 1,
            AstNode::UnaryNot(sub) => 1 + Self::node_count(sub),
            AstNode::BinaryLogic { left, right, .. } => 1 + Self::node_count(left) + Self::node_count(right),
        }
    }

    /// 执行多轮不动点迭代优化, 直至语法树收敛或达到最大轮次 (上限 8 轮防止死循环)
    /// 时间复杂度: O(K * N), K <= 8, 空间复杂度: O(N)
    pub fn optimize(mut node: AstNode) -> AstNode {
        for _ in 0..8 {
            let next = Self::optimize_step(node.clone());
            if next == node {
                break;
            }
            node = next;
        }
        node
    }

    /// 单轮自底向上语法树重写与常量折叠
    fn optimize_step(node: AstNode) -> AstNode {
        match node {
            AstNode::AlwaysTrue => AstNode::AlwaysTrue,
            AstNode::AlwaysFalse => AstNode::AlwaysFalse,

            // 1. 一元否定运算的深度重写与否定下推
            AstNode::UnaryNot(sub) => {
                let opt_sub = Self::optimize_step(*sub);
                match opt_sub {
                    AstNode::AlwaysTrue => AstNode::AlwaysFalse,
                    AstNode::AlwaysFalse => AstNode::AlwaysTrue,

                    // 1a. 双重否定消除: !(!A) => A
                    AstNode::UnaryNot(inner) => *inner,

                    // 1b. 德·摩根定律下推: !(A && B) => !A || !B
                    AstNode::BinaryLogic { op: LogicOp::And, left, right } => {
                        AstNode::BinaryLogic {
                            op: LogicOp::Or,
                            left: Box::new(Self::optimize_step(AstNode::UnaryNot(left))),
                            right: Box::new(Self::optimize_step(AstNode::UnaryNot(right))),
                        }
                    }

                    // 1c. 德·摩根定律下推: !(A || B) => !A && !B
                    AstNode::BinaryLogic { op: LogicOp::Or, left, right } => {
                        AstNode::BinaryLogic {
                            op: LogicOp::And,
                            left: Box::new(Self::optimize_step(AstNode::UnaryNot(left))),
                            right: Box::new(Self::optimize_step(AstNode::UnaryNot(right))),
                        }
                    }

                    // 1d. 关系操作符取反下推: !(field == val) => field != val, !(field > val) => field <= val
                    AstNode::Comparison { field, op, value } => {
                        if let Some(inv_op) = invert_comp_op(op) {
                            AstNode::Comparison { field, op: inv_op, value }
                        } else {
                            AstNode::UnaryNot(Box::new(AstNode::Comparison { field, op, value }))
                        }
                    }

                    // 1e. 算术关系操作符取反下推: !(left > right) => left <= right
                    AstNode::ArithmeticComparison { left, op, right } => {
                        if let Some(inv_op) = invert_comp_op(op) {
                            AstNode::ArithmeticComparison { left, op: inv_op, right }
                        } else {
                            AstNode::UnaryNot(Box::new(AstNode::ArithmeticComparison { left, op, right }))
                        }
                    }

                    other => AstNode::UnaryNot(Box::new(other)),
                }
            }

            // 2. 二元逻辑布尔代数优化 (短路零元、幺元、幂等、互斥矛盾与单值等值消元)
            AstNode::BinaryLogic { op, left, right } => {
                let opt_l = Self::optimize_step(*left);
                let opt_r = Self::optimize_step(*right);

                match op {
                    LogicOp::And => {
                        // 短路零元与幺元消去: False && X => False, True && X => X
                        if opt_l == AstNode::AlwaysFalse || opt_r == AstNode::AlwaysFalse {
                            return AstNode::AlwaysFalse;
                        }
                        if opt_l == AstNode::AlwaysTrue {
                            return opt_r;
                        }
                        if opt_r == AstNode::AlwaysTrue {
                            return opt_l;
                        }

                        // 幂等律: A && A => A
                        if opt_l == opt_r {
                            return opt_l;
                        }

                        // 矛盾律: A && !A => AlwaysFalse
                        if let AstNode::UnaryNot(ref inner) = opt_r {
                            if **inner == opt_l {
                                return AstNode::AlwaysFalse;
                            }
                        }
                        if let AstNode::UnaryNot(ref inner) = opt_l {
                            if **inner == opt_r {
                                return AstNode::AlwaysFalse;
                            }
                        }

                        // 关系比较互补矛盾律消去: (f == v) && (f != v) => AlwaysFalse
                        if let (
                            AstNode::Comparison { field: f1, op: op1, value: v1 },
                            AstNode::Comparison { field: f2, op: op2, value: v2 },
                        ) = (&opt_l, &opt_r) {
                            if f1 == f2 && v1 == v2 {
                                if (*op1 == CompOp::Eq && *op2 == CompOp::Neq) || (*op1 == CompOp::Neq && *op2 == CompOp::Eq) {
                                    return AstNode::AlwaysFalse;
                                }
                                if (*op1 == CompOp::Gt && *op2 == CompOp::Lte) || (*op1 == CompOp::Lte && *op2 == CompOp::Gt) {
                                    return AstNode::AlwaysFalse;
                                }
                                if (*op1 == CompOp::Lt && *op2 == CompOp::Gte) || (*op1 == CompOp::Gte && *op2 == CompOp::Lt) {
                                    return AstNode::AlwaysFalse;
                                }
                            }
                            // 单值字段等值冲突矛盾消去:
                            // 例如: tcp.srcport == 80 && tcp.srcport == 443 => AlwaysFalse
                            if f1 == f2 && v1 != v2 && *op1 == CompOp::Eq && *op2 == CompOp::Eq && is_single_valued_field(f1) {
                                return AstNode::AlwaysFalse;
                            }
                        }

                        AstNode::BinaryLogic {
                            op: LogicOp::And,
                            left: Box::new(opt_l),
                            right: Box::new(opt_r),
                        }
                    }
                    LogicOp::Or => {
                        // 短路零元与幺元消去: True || X => True, False || X => X
                        if opt_l == AstNode::AlwaysTrue || opt_r == AstNode::AlwaysTrue {
                            return AstNode::AlwaysTrue;
                        }
                        if opt_l == AstNode::AlwaysFalse {
                            return opt_r;
                        }
                        if opt_r == AstNode::AlwaysFalse {
                            return opt_l;
                        }

                        // 幂等律: A || A => A
                        if opt_l == opt_r {
                            return opt_l;
                        }

                        // 排中律: A || !A => AlwaysTrue
                        if let AstNode::UnaryNot(ref inner) = opt_r {
                            if **inner == opt_l {
                                return AstNode::AlwaysTrue;
                            }
                        }
                        if let AstNode::UnaryNot(ref inner) = opt_l {
                            if **inner == opt_r {
                                return AstNode::AlwaysTrue;
                            }
                        }

                        // 关系比较互补排中律消去: (f == v) || (f != v) => AlwaysTrue
                        if let (
                            AstNode::Comparison { field: f1, op: op1, value: v1 },
                            AstNode::Comparison { field: f2, op: op2, value: v2 },
                        ) = (&opt_l, &opt_r) {
                            if f1 == f2 && v1 == v2 {
                                if (*op1 == CompOp::Eq && *op2 == CompOp::Neq) || (*op1 == CompOp::Neq && *op2 == CompOp::Eq) {
                                    return AstNode::AlwaysTrue;
                                }
                                if (*op1 == CompOp::Gt && *op2 == CompOp::Lte) || (*op1 == CompOp::Lte && *op2 == CompOp::Gt) {
                                    return AstNode::AlwaysTrue;
                                }
                                if (*op1 == CompOp::Lt && *op2 == CompOp::Gte) || (*op1 == CompOp::Gte && *op2 == CompOp::Lt) {
                                    return AstNode::AlwaysTrue;
                                }
                            }
                        }

                        AstNode::BinaryLogic {
                            op: LogicOp::Or,
                            left: Box::new(opt_l),
                            right: Box::new(opt_r),
                        }
                    }
                }
            }

            // 3. 算术比较节点的常量折叠、单调移项归一化与单字段比较降维
            AstNode::ArithmeticComparison { left, op, right } => {
                let mut f_left = fold_arith_constants(left);
                let mut f_right = fold_arith_constants(right);
                let mut effective_op = op;

                // 3a. 标准范式归一化: 若左侧为纯数字而右侧包含字段，翻转为变量在左，数字在右
                // 例如: 100 < frame.len => frame.len > 100
                if matches!(f_left, ArithExpr::Number(_)) && !matches!(f_right, ArithExpr::Number(_)) {
                    std::mem::swap(&mut f_left, &mut f_right);
                    effective_op = flip_comp_op(op);
                }

                // 3b. 纯常数比较预求值 (例如: 100 + 20 > 50 => AlwaysTrue)
                if let (ArithExpr::Number(l), ArithExpr::Number(r)) = (&f_left, &f_right) {
                    let b = apply_comp_scalar(*l, *r, effective_op);
                    return if b { AstNode::AlwaysTrue } else { AstNode::AlwaysFalse };
                }

                // 3c. 同构字段自比较 (例如: x == x => AlwaysTrue, x < x => AlwaysFalse)
                if let (ArithExpr::Field(f1), ArithExpr::Field(f2)) = (&f_left, &f_right) {
                    if f1 == f2 {
                        let b = match effective_op {
                            CompOp::Eq | CompOp::Gte | CompOp::Lte => true,
                            CompOp::Neq | CompOp::Gt | CompOp::Lt => false,
                            CompOp::Contains => true,
                        };
                        return if b { AstNode::AlwaysTrue } else { AstNode::AlwaysFalse };
                    }
                }

                // 3d. 单调加减法移项归一化与单字段比较降维重写 (Algebraic Term Relocation):
                // 形式 1: Field(f) + Number(c) op Number(k) => Comparison(f op k - c)
                if let (
                    ArithExpr::Binary { op: ArithOp::Add, left: b_left, right: b_right },
                    ArithExpr::Number(k),
                ) = (&f_left, &f_right) {
                    if let (ArithExpr::Field(f), ArithExpr::Number(c)) = (&**b_left, &**b_right) {
                        return AstNode::Comparison {
                            field: f.clone(),
                            op: effective_op,
                            value: FilterValue::Number(k - c),
                        };
                    }
                    if let (ArithExpr::Number(c), ArithExpr::Field(f)) = (&**b_left, &**b_right) {
                        return AstNode::Comparison {
                            field: f.clone(),
                            op: effective_op,
                            value: FilterValue::Number(k - c),
                        };
                    }
                }

                // 形式 2: Field(f) - Number(c) op Number(k) => Comparison(f op k + c)
                // 例如: frame.len - 14 > 100 => frame.len > 114
                if let (
                    ArithExpr::Binary { op: ArithOp::Sub, left: b_left, right: b_right },
                    ArithExpr::Number(k),
                ) = (&f_left, &f_right) {
                    if let (ArithExpr::Field(f), ArithExpr::Number(c)) = (&**b_left, &**b_right) {
                        return AstNode::Comparison {
                            field: f.clone(),
                            op: effective_op,
                            value: FilterValue::Number(k + c),
                        };
                    }
                }

                // 形式 3: Field(f) op Number(k) => 直接降维重写为原生高效单字段 Comparison
                if let (ArithExpr::Field(f), ArithExpr::Number(k)) = (&f_left, &f_right) {
                    return AstNode::Comparison {
                        field: f.clone(),
                        op: effective_op,
                        value: FilterValue::Number(*k),
                    };
                }

                AstNode::ArithmeticComparison {
                    left: f_left,
                    op: effective_op,
                    right: f_right,
                }
            }

            // 4. 离散集合 (InSet) 优化与退化
            AstNode::InSet { field, mut values } => {
                if values.is_empty() {
                    return AstNode::AlwaysFalse;
                }
                if values.len() == 1 {
                    return AstNode::Comparison {
                        field,
                        op: CompOp::Eq,
                        value: values.pop().unwrap(),
                    };
                }

                // 集合自动去重 (保持原本有序性)
                let mut deduped = Vec::new();
                for v in values {
                    if !deduped.contains(&v) {
                        deduped.push(v);
                    }
                }
                if deduped.len() == 1 {
                    return AstNode::Comparison {
                        field,
                        op: CompOp::Eq,
                        value: deduped.pop().unwrap(),
                    };
                }

                AstNode::InSet { field, values: deduped }
            }

            other => other,
        }
    }
}

/// 编译后的工业级过滤器结构体
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    root: AstNode,
}

impl CompiledFilter {
    /// 从源码编译 AST 语法树并自动运行工业级 AstOptimizer 常量折叠与重写优化器
    pub fn compile(filter_expr: &str) -> Result<Self, String> {
        let trimmed = filter_expr.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                root: AstNode::AlwaysTrue,
            });
        }

        let lexer = Lexer::new(trimmed);
        let mut parser = Parser::new(lexer)?;
        let raw_root = parser.parse_expression()?;
        let optimized_root = AstOptimizer::optimize(raw_root);

        Ok(Self { root: optimized_root })
    }

    /// 编译未经过优化的原始语法树 (主要用于优化对比测试与基准度量)
    pub fn compile_unoptimized(filter_expr: &str) -> Result<Self, String> {
        let trimmed = filter_expr.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                root: AstNode::AlwaysTrue,
            });
        }

        let lexer = Lexer::new(trimmed);
        let mut parser = Parser::new(lexer)?;
        let root = parser.parse_expression()?;

        Ok(Self { root })
    }

    /// 获取编译优化后的语法树根节点引用
    pub fn root(&self) -> &AstNode {
        &self.root
    }

    /// 统计当前语法树的节点总数
    pub fn node_count(&self) -> usize {
        AstOptimizer::node_count(&self.root)
    }

    /// 评估数据包是否满足过滤器表达式 (默认基础字段)
    /// 
    /// 复杂度: O(Depth), 单次微秒级求值, 严格只读, 零拷贝
    pub fn matches(
        &self,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        length: usize,
        entropy: f64,
        payload_text: &str,
    ) -> bool {
        self.matches_with_fields(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length,
            entropy,
            payload_text,
            None,
        )
    }

    /// 评估数据包是否满足过滤器表达式 (支持协议树动态字段下推，对标 Wireshark proto_tree)
    /// 
    /// 复杂度: O(Depth), 单次微秒级求值
    pub fn matches_with_fields(
        &self,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        length: usize,
        entropy: f64,
        payload_text: &str,
        fields: Option<&HashMap<String, serde_json::Value>>,
    ) -> bool {
        self.eval_node(
            &self.root,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length,
            entropy,
            payload_text,
            fields,
        )
    }

    fn eval_node(
        &self,
        node: &AstNode,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        length: usize,
        entropy: f64,
        payload_text: &str,
        fields: Option<&HashMap<String, serde_json::Value>>,
    ) -> bool {
        match node {
            AstNode::AlwaysTrue => true,
            AstNode::AlwaysFalse => false,
            AstNode::UnaryNot(sub) => {
                !self.eval_node(sub, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields)
            }
            AstNode::BinaryLogic { op, left, right } => match op {
                LogicOp::And => {
                    self.eval_node(left, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields)
                        && self.eval_node(right, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields)
                }
                LogicOp::Or => {
                    self.eval_node(left, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields)
                        || self.eval_node(right, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields)
                }
            },
            AstNode::Comparison { field, op, value } => {
                self.eval_comparison(field, *op, value, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields)
            }
            AstNode::SliceComparison { field, offset, length: slen, op, value } => {
                let target_text = match field.to_lowercase().as_str() {
                    "payload" | "payload_text" | "data" | "frame" => payload_text,
                    _ => "",
                };
                if target_text.is_empty() {
                    return false;
                }
                let bytes = target_text.as_bytes();
                if *offset >= bytes.len() {
                    return false;
                }
                let end = (*offset + *slen).min(bytes.len());
                let slice = &bytes[*offset..end];
                match value {
                    FilterValue::String(s) => apply_comp_slice(slice, s.as_bytes(), *op),
                    FilterValue::Number(n) => {
                        if slice.is_empty() || slice.len() > 8 {
                            return false;
                        }
                        let target_val = *n as u64;
                        let mut slice_val: u64 = 0;
                        for &b in slice {
                            slice_val = (slice_val << 8) | (b as u64);
                        }
                        apply_comp_scalar(slice_val, target_val, *op)
                    }
                    _ => false,
                }
            }
            AstNode::CidrMatch { field, cidr } => {
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
                        if let Some(f_map) = fields {
                            if let Some(dyn_val) = Self::get_field_raw_value(field, f_map) {
                                match dyn_val {
                                    serde_json::Value::String(s) => s.clone(),
                                    serde_json::Value::Number(n) => n.to_string(),
                                    serde_json::Value::Bool(b) => b.to_string(),
                                    _ => dyn_val.to_string(),
                                }
                            } else {
                                String::new()
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
            AstNode::ArithmeticComparison { left, op, right } => {
                let l_val = match Self::eval_arith_expr(left, src_port, dst_port, length, entropy, fields) {
                    Some(v) => v,
                    None => return false,
                };
                let r_val = match Self::eval_arith_expr(right, src_port, dst_port, length, entropy, fields) {
                    Some(v) => v,
                    None => return false,
                };
                apply_comp_scalar(l_val, r_val, *op)
            }
        }
    }

    fn eval_arith_expr(
        expr: &ArithExpr,
        src_port: u16,
        dst_port: u16,
        length: usize,
        entropy: f64,
        fields: Option<&HashMap<String, serde_json::Value>>,
    ) -> Option<f64> {
        match expr {
            ArithExpr::Number(n) => Some(*n),
            ArithExpr::Field(field) => {
                let fl = field.to_lowercase();
                match fl.as_str() {
                    "length" | "len" | "frame.len" | "frame_len" => Some(length as f64),
                    "tcp.srcport" | "udp.srcport" | "src_port" | "sport" => Some(src_port as f64),
                    "tcp.dstport" | "udp.dstport" | "dst_port" | "dport" => Some(dst_port as f64),
                    "entropy" => Some(entropy),
                    _ => {
                        if let Some(f_map) = fields {
                            if let Some(val) = Self::get_field_raw_value(field, f_map) {
                                match val {
                                    serde_json::Value::Number(n) => n.as_f64(),
                                    serde_json::Value::String(s) => {
                                        if s.starts_with("0x") || s.starts_with("0X") {
                                            u64::from_str_radix(&s[2..], 16).ok().map(|v| v as f64)
                                        } else {
                                            s.parse::<f64>().ok()
                                        }
                                    }
                                    serde_json::Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
                                    _ => None,
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                }
            }
            ArithExpr::Binary { op, left, right } => {
                let l = Self::eval_arith_expr(left, src_port, dst_port, length, entropy, fields)?;
                let r = Self::eval_arith_expr(right, src_port, dst_port, length, entropy, fields)?;
                match op {
                    ArithOp::Add => Some(l + r),
                    ArithOp::Sub => Some(l - r),
                    ArithOp::Mul => Some(l * r),
                    ArithOp::Div => {
                        if r == 0.0 {
                            None
                        } else {
                            Some(l / r)
                        }
                    }
                    ArithOp::Mod => {
                        if r == 0.0 {
                            None
                        } else {
                            Some(l % r)
                        }
                    }
                }
            }
        }
    }

    fn eval_comparison(
        &self,
        field: &str,
        op: CompOp,
        val: &FilterValue,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        length: usize,
        entropy: f64,
        payload_text: &str,
        fields: Option<&HashMap<String, serde_json::Value>>,
    ) -> bool {
        let field_lower = field.to_lowercase();

        match field_lower.as_str() {
            "ip.src" | "src" | "src_ip" => match val {
                FilterValue::Ip(target_ip) => {
                    if let Ok(pkt_ip) = IpAddr::from_str(src_ip) {
                        apply_comp_scalar(pkt_ip, *target_ip, op)
                    } else {
                        false
                    }
                }
                FilterValue::String(s) => apply_comp_str(src_ip, s, op),
                _ => false,
            },
            "ip.dst" | "dst" | "dst_ip" => match val {
                FilterValue::Ip(target_ip) => {
                    if let Ok(pkt_ip) = IpAddr::from_str(dst_ip) {
                        apply_comp_scalar(pkt_ip, *target_ip, op)
                    } else {
                        false
                    }
                }
                FilterValue::String(s) => apply_comp_str(dst_ip, s, op),
                _ => false,
            },
            "ip.addr" | "ip" => {
                self.eval_comparison("ip.src", op, val, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields)
                    || self.eval_comparison("ip.dst", op, val, src_ip, dst_ip, src_port, dst_port, protocol, length, entropy, payload_text, fields)
            }
            "tcp.port" | "udp.port" | "port" => match val {
                FilterValue::Number(n) => {
                    let target = *n as u16;
                    apply_comp_scalar(src_port, target, op) || apply_comp_scalar(dst_port, target, op)
                }
                _ => false,
            },
            "tcp.srcport" | "udp.srcport" | "src_port" | "sport" => match val {
                FilterValue::Number(n) => apply_comp_scalar(src_port, *n as u16, op),
                _ => false,
            },
            "tcp.dstport" | "udp.dstport" | "dst_port" | "dport" => match val {
                FilterValue::Number(n) => apply_comp_scalar(dst_port, *n as u16, op),
                _ => false,
            },
            "protocol" | "proto" => match val {
                FilterValue::String(s) => apply_comp_str(protocol, s, op),
                _ => false,
            },
            "length" | "len" | "frame.len" | "frame_len" => match val {
                FilterValue::Number(n) => apply_comp_scalar(length as f64, *n, op),
                _ => false,
            },
            "entropy" => match val {
                FilterValue::Number(n) => apply_comp_scalar(entropy, *n, op),
                _ => false,
            },
            "payload" | "data" | "text" => match val {
                FilterValue::String(s) => apply_comp_str(payload_text, s, op),
                _ => false,
            },
            _ => {
                // Wireshark 级协议树字段动态下推求值
                if let Some(fmap) = fields {
                    self.eval_dynamic_field(field_lower.as_str(), op, val, fmap)
                } else {
                    false
                }
            }
        }
    }

    /// 动态解析评估协议树/业务上下文字段
    /// 优先级: 精确字段 -> 下划线别名 -> 嵌套二级键 -> 后缀键
    /// 动态提取协议树/上下文字段原始 JSON 键值
    /// 优先级: 精确字段 -> 下划线别名 -> 嵌套二级键 -> 后缀键
    pub fn get_field_raw_value<'b>(
        field: &str,
        fields: &'b HashMap<String, serde_json::Value>,
    ) -> Option<&'b serde_json::Value> {
        fields.get(field)
            .or_else(|| {
                let alt_key = field.replace('.', "_");
                fields.get(&alt_key)
            })
            .or_else(|| {
                if let Some((proto, subkey)) = field.split_once('.') {
                    fields.get(proto).and_then(|v| v.get(subkey))
                } else {
                    None
                }
            })
            .or_else(|| {
                if let Some(last) = field.split('.').last() {
                    fields.get(last)
                } else {
                    None
                }
            })
    }

    fn eval_dynamic_field(
        &self,
        field: &str,
        op: CompOp,
        target_val: &FilterValue,
        fields: &HashMap<String, serde_json::Value>,
    ) -> bool {
        let resolved_value = Self::get_field_raw_value(field, fields);

        let Some(json_val) = resolved_value else {
            return false;
        };

        match json_val {
            serde_json::Value::Number(num) => {
                if let Some(actual_f64) = num.as_f64() {
                    match target_val {
                        FilterValue::Number(target_num) => apply_comp_scalar(actual_f64, *target_num, op),
                        FilterValue::String(target_str) => {
                            if let Ok(target_num) = target_str.parse::<f64>() {
                                apply_comp_scalar(actual_f64, target_num, op)
                            } else {
                                false
                            }
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            serde_json::Value::String(s) => {
                match target_val {
                    FilterValue::String(target_str) => apply_comp_str(s, target_str, op),
                    FilterValue::Number(target_num) => {
                        let parsed = if s.starts_with("0x") || s.starts_with("0X") {
                            u64::from_str_radix(&s[2..], 16).map(|v| v as f64).ok()
                        } else {
                            s.parse::<f64>().ok()
                        };
                        if let Some(actual_num) = parsed {
                            apply_comp_scalar(actual_num, *target_num, op)
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            }
            serde_json::Value::Bool(b) => {
                let actual_bool = *b;
                match target_val {
                    FilterValue::Number(n) => {
                        let target_bool = *n != 0.0;
                        apply_comp_scalar(actual_bool, target_bool, op)
                    }
                    FilterValue::String(s) => {
                        let s_lower = s.to_lowercase();
                        let target_bool = s_lower == "true" || s_lower == "1";
                        apply_comp_scalar(actual_bool, target_bool, op)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

fn apply_comp_scalar<T: PartialOrd + PartialEq>(left: T, right: T, op: CompOp) -> bool {
    match op {
        CompOp::Eq => left == right,
        CompOp::Neq => left != right,
        CompOp::Gt => left > right,
        CompOp::Lt => left < right,
        CompOp::Gte => left >= right,
        CompOp::Lte => left <= right,
        CompOp::Contains => false,
    }
}

fn apply_comp_slice(slice: &[u8], target: &[u8], op: CompOp) -> bool {
    match op {
        CompOp::Eq => slice == target,
        CompOp::Neq => slice != target,
        CompOp::Contains => {
            if target.is_empty() {
                true
            } else {
                slice.windows(target.len()).any(|w| w == target)
            }
        }
        _ => false,
    }
}

fn apply_comp_str(left: &str, right: &str, op: CompOp) -> bool {
    match op {
        CompOp::Eq => left.eq_ignore_ascii_case(right),
        CompOp::Neq => !left.eq_ignore_ascii_case(right),
        CompOp::Contains => left.to_lowercase().contains(&right.to_lowercase()),
        _ => false,
    }
}

/// 快速判定 IP 地址是否属于 CIDR 掩码子网
/// 算法: 基于 32 位无符号整数按位与运算判定, 时间复杂度 O(1), 空间复杂度 O(1)
fn check_cidr_match(ip_str: &str, cidr_str: &str) -> bool {
    let parts: Vec<&str> = cidr_str.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let Ok(target_ip) = IpAddr::from_str(parts[0]) else { return false; };
    let Ok(prefix_len) = parts[1].parse::<u8>() else { return false; };
    let Ok(pkt_ip) = IpAddr::from_str(ip_str) else { return false; };

    match (pkt_ip, target_ip) {
        (IpAddr::V4(pkt_v4), IpAddr::V4(target_v4)) => {
            if prefix_len > 32 { return false; }
            let mask = if prefix_len == 0 { 0u32 } else { !0u32 << (32 - prefix_len) };
            let pkt_u32 = u32::from(pkt_v4);
            let target_u32 = u32::from(target_v4);
            (pkt_u32 & mask) == (target_u32 & mask)
        }
        (IpAddr::V6(pkt_v6), IpAddr::V6(target_v6)) => {
            if prefix_len > 128 { return false; }
            let mask = if prefix_len == 0 { 0u128 } else { !0u128 << (128 - prefix_len) };
            let pkt_u128 = u128::from(pkt_v6);
            let target_u128 = u128::from(target_v6);
            (pkt_u128 & mask) == (target_u128 & mask)
        }
        _ => false,
    }
}

/// 获取 Wireshark 级已注册的协议字段字典清单 (供前端自动补全与语义高亮)
pub fn get_standard_field_registry() -> Vec<FieldDefinition> {
    vec![
        FieldDefinition { name: "ip.src".into(), protocol: "IP".into(), field_type: FieldType::IpAddress, description: "源 IPv4/IPv6 地址".into() },
        FieldDefinition { name: "ip.dst".into(), protocol: "IP".into(), field_type: FieldType::IpAddress, description: "目的 IPv4/IPv6 地址".into() },
        FieldDefinition { name: "tcp.srcport".into(), protocol: "TCP".into(), field_type: FieldType::Integer, description: "TCP 源端口号".into() },
        FieldDefinition { name: "tcp.dstport".into(), protocol: "TCP".into(), field_type: FieldType::Integer, description: "TCP 目的端口号".into() },
        FieldDefinition { name: "tcp.flags.syn".into(), protocol: "TCP".into(), field_type: FieldType::Boolean, description: "TCP SYN 同步握手标志".into() },
        FieldDefinition { name: "tcp.flags.ack".into(), protocol: "TCP".into(), field_type: FieldType::Boolean, description: "TCP ACK 确认标志".into() },
        FieldDefinition { name: "tcp.flags.reset".into(), protocol: "TCP".into(), field_type: FieldType::Boolean, description: "TCP RST 强行复位标志".into() },
        FieldDefinition { name: "modbus.func_code".into(), protocol: "Modbus".into(), field_type: FieldType::Integer, description: "Modbus 功能码 (如 3:读保持, 16:写多个)".into() },
        FieldDefinition { name: "modbus.unit_id".into(), protocol: "Modbus".into(), field_type: FieldType::Integer, description: "Modbus 从站单元地址 (1-247)".into() },
        FieldDefinition { name: "s7comm.param.func".into(), protocol: "S7comm".into(), field_type: FieldType::Integer, description: "西门子 S7 控制原语功能码 (如 0x29:停止, 0x28:启动)".into() },
        FieldDefinition { name: "iec104.type_id".into(), protocol: "IEC104".into(), field_type: FieldType::Integer, description: "电力远动 IEC 104 ASDU 类型标识 (如 1:单点信息, 45:单点命令)".into() },
        FieldDefinition { name: "dns.qry.name".into(), protocol: "DNS".into(), field_type: FieldType::String, description: "DNS 域名解析查询目标主机名".into() },
        FieldDefinition { name: "http.request.method".into(), protocol: "HTTP".into(), field_type: FieldType::String, description: "HTTP 请求动词方法 (GET/POST/PUT/DELETE)".into() },
        FieldDefinition { name: "http.response.code".into(), protocol: "HTTP".into(), field_type: FieldType::Integer, description: "HTTP 响应状态码 (200/404/500)".into() },
        FieldDefinition { name: "dnp3.func_code".into(), protocol: "DNP3".into(), field_type: FieldType::Integer, description: "DNP3 应用层功能码 (1:读, 2:写, 5:直接操作)".into() },
        FieldDefinition { name: "dnp3.src".into(), protocol: "DNP3".into(), field_type: FieldType::Integer, description: "DNP3 数据链路层源地址".into() },
        FieldDefinition { name: "dnp3.dst".into(), protocol: "DNP3".into(), field_type: FieldType::Integer, description: "DNP3 数据链路层目的地址".into() },
        FieldDefinition { name: "bacnet.bvll_function".into(), protocol: "BACnet".into(), field_type: FieldType::Integer, description: "BACnet/IP 虚拟链路层功能码 (0x0A:单播)".into() },
        FieldDefinition { name: "bacnet.service_choice".into(), protocol: "BACnet".into(), field_type: FieldType::Integer, description: "BACnet APDU 服务选择码 (0x0C:读属性)".into() },
    ]
}

// ============================================================
// 严苛单元测试与极限语法覆盖
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ast_simple_equality() {
        let filter = CompiledFilter::compile("ip.src == 192.168.1.10").unwrap();
        assert!(filter.matches("192.168.1.10", "10.0.0.1", 1234, 80, "TCP", 100, 2.5, ""));
        assert!(!filter.matches("192.168.1.11", "10.0.0.1", 1234, 80, "TCP", 100, 2.5, ""));
    }

    #[test]
    fn test_ast_complex_boolean_logic() {
        let expr = r#"(ip.src == 10.0.0.1 || ip.dst == 10.0.0.2) && (port == 502 || protocol == "MODBUS")"#;
        let filter = CompiledFilter::compile(expr).unwrap();

        assert!(filter.matches("10.0.0.1", "172.16.0.1", 5020, 502, "TCP", 128, 3.1, ""));
        assert!(filter.matches("172.16.0.1", "10.0.0.2", 12345, 80, "MODBUS", 128, 3.1, ""));
        assert!(!filter.matches("192.168.1.1", "192.168.1.2", 1234, 80, "HTTP", 200, 1.2, ""));
    }

    #[test]
    fn test_ast_unary_not_and_contains() {
        let expr = "! (protocol contains 'UDP')";
        let filter = CompiledFilter::compile(expr).unwrap();

        assert!(filter.matches("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 64, 1.0, ""));
        assert!(!filter.matches("1.1.1.1", "2.2.2.2", 53, 53, "UDP", 64, 1.0, ""));
    }

    #[test]
    fn test_ast_hex_and_float_numbers() {
        let expr = "port == 0x01F6 && entropy > 7.2"; // 0x01F6 = 502
        let filter = CompiledFilter::compile(expr).unwrap();

        assert!(filter.matches("10.0.0.1", "10.0.0.2", 40000, 502, "TCP", 128, 7.85, ""));
        assert!(!filter.matches("10.0.0.1", "10.0.0.2", 40000, 502, "TCP", 128, 6.9, ""));
    }

    #[test]
    fn test_ast_malformed_syntax_fail_fast() {
        let err1 = CompiledFilter::compile("ip.src == ");
        assert!(err1.is_err());

        let err2 = CompiledFilter::compile("(protocol == 'TCP'");
        assert!(err2.is_err());
    }

    #[test]
    fn test_ast_slice_syntax() {
        let filter = CompiledFilter::compile(r#"payload[0:4] == "GET ""#).unwrap();
        assert!(filter.matches("192.168.1.1", "10.0.0.1", 1234, 80, "HTTP", 200, 3.5, "GET /index.html HTTP/1.1"));
        assert!(!filter.matches("192.168.1.1", "10.0.0.1", 1234, 80, "HTTP", 200, 3.5, "POST /api/data HTTP/1.1"));
    }

    #[test]
    fn test_ast_cidr_subnet_match() {
        let filter = CompiledFilter::compile(r#"ip.src in "192.168.1.0/24""#).unwrap();
        assert!(filter.matches("192.168.1.42", "8.8.8.8", 1234, 53, "DNS", 64, 1.2, ""));
        assert!(!filter.matches("192.168.2.42", "8.8.8.8", 1234, 53, "DNS", 64, 1.2, ""));
        assert!(!filter.matches("10.0.0.1", "8.8.8.8", 1234, 53, "DNS", 64, 1.2, ""));
    }

    #[test]
    fn test_dynamic_protocol_fields_downpush() {
        let mut fields = HashMap::new();
        fields.insert("modbus_func_code".to_string(), serde_json::json!(3));
        fields.insert("unit_id".to_string(), serde_json::json!(1));
        fields.insert("s7comm.param.func".to_string(), serde_json::json!("0x29"));
        fields.insert("tcp.flags.syn".to_string(), serde_json::json!(true));

        // 1. 测试 modbus.func_code == 3
        let filter1 = CompiledFilter::compile("modbus.func_code == 3").unwrap();
        assert!(filter1.matches_with_fields("10.0.0.1", "10.0.0.2", 1234, 502, "MODBUS", 64, 1.0, "", Some(&fields)));

        // 2. 测试 s7comm.param.func == 41 (0x29)
        let filter2 = CompiledFilter::compile("s7comm.param.func == 41").unwrap();
        assert!(filter2.matches_with_fields("10.0.0.1", "10.0.0.2", 1234, 102, "S7", 64, 1.0, "", Some(&fields)));

        // 3. 测试布尔标志下推 tcp.flags.syn == 1
        let filter3 = CompiledFilter::compile("tcp.flags.syn == 1").unwrap();
        assert!(filter3.matches_with_fields("10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 64, 1.0, "", Some(&fields)));
    }

    #[test]
    fn test_ast_regex_matches_and_set_membership() {
        // 1. 正则 matches 语法测试
        let filter_regex = CompiledFilter::compile("payload matches \"(?i)unauthorized_access\"").unwrap();
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

    #[test]
    fn test_relative_arithmetic_comparison_and_cross_layer_fields() {
        // 1. 测试 frame.len - 14 > 100
        let filter1 = CompiledFilter::compile("frame.len - 14 > 100").expect("编译算术过滤表达式必须成功");
        assert!(filter1.matches("192.168.1.1", "192.168.1.2", 1000, 502, "TCP", 120, 1.0, ""));
        assert!(!filter1.matches("192.168.1.1", "192.168.1.2", 1000, 502, "TCP", 114, 1.0, ""));

        // 2. 测试两端口跨层加法: tcp.srcport + tcp.dstport == 1080
        let filter2 = CompiledFilter::compile("tcp.srcport + tcp.dstport == 1080").expect("编译双字段算术必须成功");
        assert!(filter2.matches("10.0.0.1", "10.0.0.2", 1000, 80, "TCP", 64, 1.0, ""));
        assert!(!filter2.matches("10.0.0.1", "10.0.0.2", 1000, 443, "TCP", 64, 1.0, ""));

        // 3. 测试协议树动态下推字段算术与常数混合: modbus_len * 2 <= 64
        let mut fields = HashMap::new();
        fields.insert("modbus_len".to_string(), serde_json::json!(30));
        let filter3 = CompiledFilter::compile("modbus_len * 2 <= 64").expect("编译动态字段算术必须成功");
        assert!(filter3.matches_with_fields("10.0.0.1", "10.0.0.2", 1000, 502, "MODBUS", 64, 1.0, "", Some(&fields)));

        fields.insert("modbus_len".to_string(), serde_json::json!(35)); // 35 * 2 = 70 > 64
        assert!(!filter3.matches_with_fields("10.0.0.1", "10.0.0.2", 1000, 502, "MODBUS", 64, 1.0, "", Some(&fields)));
    }

    #[test]
    fn test_optimizer_pure_constant_folding() {
        // 1. 纯常数算术折叠与预先求值: 100 + 20 * 2 > 130 => True
        let filter1 = CompiledFilter::compile("100 + 20 * 2 > 130").unwrap();
        assert_eq!(*filter1.root(), AstNode::AlwaysTrue);
        assert!(filter1.matches("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 64, 1.0, ""));

        // 2. 纯常数算术折叠为假: 50 * 2 < 80 => False
        let filter2 = CompiledFilter::compile("50 * 2 < 80").unwrap();
        assert_eq!(*filter2.root(), AstNode::AlwaysFalse);
        assert!(!filter2.matches("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 64, 1.0, ""));
    }

    #[test]
    fn test_optimizer_algebraic_identities_and_self_elimination() {
        // 1. 同构减法消元: tcp.srcport - tcp.srcport == 0 => AlwaysTrue
        let filter1 = CompiledFilter::compile("tcp.srcport - tcp.srcport == 0").unwrap();
        assert_eq!(*filter1.root(), AstNode::AlwaysTrue);

        // 2. 乘以零元消元: frame.len * 0 == 0 => AlwaysTrue
        let filter2 = CompiledFilter::compile("frame.len * 0 == 0").unwrap();
        assert_eq!(*filter2.root(), AstNode::AlwaysTrue);

        // 3. 加零与乘幺元消元: frame.len + 0 > 100 => 归一化降维为 frame.len > 100
        let filter3 = CompiledFilter::compile("frame.len + 0 > 100").unwrap();
        assert_eq!(*filter3.root(), AstNode::Comparison {
            field: "frame.len".to_string(),
            op: CompOp::Gt,
            value: FilterValue::Number(100.0),
        });
    }

    #[test]
    fn test_optimizer_term_relocation_and_comparison_demotion() {
        // 1. 算术移项归一化与降维: frame.len - 14 > 100 => frame.len > 114
        let filter1 = CompiledFilter::compile("frame.len - 14 > 100").unwrap();
        assert_eq!(*filter1.root(), AstNode::Comparison {
            field: "frame.len".to_string(),
            op: CompOp::Gt,
            value: FilterValue::Number(114.0),
        });

        // 2. 加法移项归一化: frame.len + 10 == 60 => frame.len == 50
        let filter2 = CompiledFilter::compile("frame.len + 10 == 60").unwrap();
        assert_eq!(*filter2.root(), AstNode::Comparison {
            field: "frame.len".to_string(),
            op: CompOp::Eq,
            value: FilterValue::Number(50.0),
        });

        // 3. 左常数右变量反向比较移项: 100 < frame.len - 14 <=> frame.len - 14 > 100 => frame.len > 114
        let filter3 = CompiledFilter::compile("100 < frame.len - 14").unwrap();
        assert_eq!(*filter3.root(), AstNode::Comparison {
            field: "frame.len".to_string(),
            op: CompOp::Gt,
            value: FilterValue::Number(114.0),
        });
    }

    #[test]
    fn test_optimizer_de_morgans_laws_pushdown() {
        // 1. 德·摩根下推: !(A && B) => !A || !B => field1 != val1 || field2 != val2
        let filter1 = CompiledFilter::compile("! (ip.src == 10.0.0.1 && ip.dst == 10.0.0.2)").unwrap();
        assert_eq!(*filter1.root(), AstNode::BinaryLogic {
            op: LogicOp::Or,
            left: Box::new(AstNode::Comparison {
                field: "ip.src".to_string(),
                op: CompOp::Neq,
                value: FilterValue::Ip(IpAddr::from_str("10.0.0.1").unwrap()),
            }),
            right: Box::new(AstNode::Comparison {
                field: "ip.dst".to_string(),
                op: CompOp::Neq,
                value: FilterValue::Ip(IpAddr::from_str("10.0.0.2").unwrap()),
            }),
        });

        // 2. 德·摩根下推: !(A || B) => !A && !B
        let filter2 = CompiledFilter::compile("! (tcp.srcport == 80 || tcp.dstport == 443)").unwrap();
        assert_eq!(*filter2.root(), AstNode::BinaryLogic {
            op: LogicOp::And,
            left: Box::new(AstNode::Comparison {
                field: "tcp.srcport".to_string(),
                op: CompOp::Neq,
                value: FilterValue::Number(80.0),
            }),
            right: Box::new(AstNode::Comparison {
                field: "tcp.dstport".to_string(),
                op: CompOp::Neq,
                value: FilterValue::Number(443.0),
            }),
        });
    }

    #[test]
    fn test_optimizer_double_negation_and_operator_inversion() {
        // 1. 双重否定消除: !(! (protocol == "TCP")) => protocol == "TCP"
        let filter1 = CompiledFilter::compile("! (! (protocol == 'TCP'))").unwrap();
        assert_eq!(*filter1.root(), AstNode::Comparison {
            field: "protocol".to_string(),
            op: CompOp::Eq,
            value: FilterValue::String("TCP".to_string()),
        });

        // 2. 比较操作符取反下推: !(frame.len > 100) => frame.len <= 100
        let filter2 = CompiledFilter::compile("! (frame.len > 100)").unwrap();
        assert_eq!(*filter2.root(), AstNode::Comparison {
            field: "frame.len".to_string(),
            op: CompOp::Lte,
            value: FilterValue::Number(100.0),
        });
    }

    #[test]
    fn test_optimizer_boolean_identity_and_annihilation() {
        // 1. 幺元消去: A && True => A
        let filter1 = CompiledFilter::compile("ip.src == 1.1.1.1 && (10 > 5)").unwrap();
        assert_eq!(*filter1.root(), AstNode::Comparison {
            field: "ip.src".to_string(),
            op: CompOp::Eq,
            value: FilterValue::Ip(IpAddr::from_str("1.1.1.1").unwrap()),
        });

        // 2. 零元消去: A && False => False
        let filter2 = CompiledFilter::compile("ip.src == 1.1.1.1 && (5 > 10)").unwrap();
        assert_eq!(*filter2.root(), AstNode::AlwaysFalse);

        // 3. 或运算零元消去: A || True => True
        let filter3 = CompiledFilter::compile("ip.src == 1.1.1.1 || (10 > 5)").unwrap();
        assert_eq!(*filter3.root(), AstNode::AlwaysTrue);

        // 4. 或运算幺元消去: A || False => A
        let filter4 = CompiledFilter::compile("ip.src == 1.1.1.1 || (5 > 10)").unwrap();
        assert_eq!(*filter4.root(), AstNode::Comparison {
            field: "ip.src".to_string(),
            op: CompOp::Eq,
            value: FilterValue::Ip(IpAddr::from_str("1.1.1.1").unwrap()),
        });
    }

    #[test]
    fn test_optimizer_idempotence_and_complementarity() {
        // 1. 幂等律消去: A && A => A
        let filter1 = CompiledFilter::compile("protocol == 'TCP' && protocol == 'TCP'").unwrap();
        assert_eq!(*filter1.root(), AstNode::Comparison {
            field: "protocol".to_string(),
            op: CompOp::Eq,
            value: FilterValue::String("TCP".to_string()),
        });

        // 2. 矛盾律消去: A && !A => AlwaysFalse
        let filter2 = CompiledFilter::compile("protocol == 'TCP' && ! (protocol == 'TCP')").unwrap();
        assert_eq!(*filter2.root(), AstNode::AlwaysFalse);

        // 3. 排中律消去: A || !A => AlwaysTrue
        let filter3 = CompiledFilter::compile("protocol == 'TCP' || ! (protocol == 'TCP')").unwrap();
        assert_eq!(*filter3.root(), AstNode::AlwaysTrue);
    }

    #[test]
    fn test_optimizer_single_valued_disjoint_contradiction() {
        // 单值端口矛盾: tcp.srcport == 80 && tcp.srcport == 443 => AlwaysFalse
        let filter1 = CompiledFilter::compile("tcp.srcport == 80 && tcp.srcport == 443").unwrap();
        assert_eq!(*filter1.root(), AstNode::AlwaysFalse);
        assert!(!filter1.matches("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 64, 1.0, ""));

        // 单值源 IP 矛盾: ip.src == 1.1.1.1 && ip.src == 2.2.2.2 => AlwaysFalse
        let filter2 = CompiledFilter::compile("ip.src == 1.1.1.1 && ip.src == 2.2.2.2").unwrap();
        assert_eq!(*filter2.root(), AstNode::AlwaysFalse);
    }

    #[test]
    fn test_optimizer_inset_dedup_and_demotion() {
        // 1. 单元素集合降维退化: in [80] => == 80
        let filter1 = CompiledFilter::compile("tcp.dstport in [80]").unwrap();
        assert_eq!(*filter1.root(), AstNode::Comparison {
            field: "tcp.dstport".to_string(),
            op: CompOp::Eq,
            value: FilterValue::Number(80.0),
        });

        // 2. 重复元素集合去重: in [80, 80, 443, 80] => in [80, 443]
        let filter2 = CompiledFilter::compile("tcp.dstport in [80, 80, 443, 80]").unwrap();
        assert_eq!(*filter2.root(), AstNode::InSet {
            field: "tcp.dstport".to_string(),
            values: vec![FilterValue::Number(80.0), FilterValue::Number(443.0)],
        });
    }

    #[test]
    fn test_optimizer_fixed_point_cascading_and_evaluation_consistency() {
        // 级联嵌套复合表达式:
        // ! (frame.len - 14 > 100 && (10 * 2 == 20)) || (tcp.srcport == 80 && tcp.srcport == 8080)
        // 级联收敛过程:
        // 10 * 2 == 20 折叠为 True;
        // frame.len - 14 > 100 && True 折叠为 frame.len - 14 > 100;
        // frame.len - 14 > 100 移项降维为 frame.len > 114;
        // ! (frame.len > 114) 下推取反为 frame.len <= 114;
        // 右侧 tcp.srcport == 80 && tcp.srcport == 8080 折叠为 False;
        // (frame.len <= 114) || False 幺元消去为 frame.len <= 114!
        let expr = "! (frame.len - 14 > 100 && (10 * 2 == 20)) || (tcp.srcport == 80 && tcp.srcport == 8080)";
        let unopt = CompiledFilter::compile_unoptimized(expr).unwrap();
        let opt = CompiledFilter::compile(expr).unwrap();

        // 验证节点压缩比
        assert!(opt.node_count() < unopt.node_count(), "优化后的节点总数必须显著减少");
        assert_eq!(*opt.root(), AstNode::Comparison {
            field: "frame.len".to_string(),
            op: CompOp::Lte,
            value: FilterValue::Number(114.0),
        });

        // 验证全真数据包求值一致性
        let cases = [
            ("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 110, 1.0, ""),  // len=110 <= 114 -> true
            ("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 114, 1.0, ""),  // len=114 <= 114 -> true
            ("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 115, 1.0, ""),  // len=115 > 114  -> false
            ("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 200, 1.0, ""),  // len=200 > 114  -> false
        ];

        for (src_ip, dst_ip, sport, dport, proto, len, entropy, payload) in cases {
            let res_unopt = unopt.matches(src_ip, dst_ip, sport, dport, proto, len, entropy, payload);
            let res_opt = opt.matches(src_ip, dst_ip, sport, dport, proto, len, entropy, payload);
            assert_eq!(res_opt, res_unopt, "优化前后求值逻辑必须 100% 绝对一致");
        }
    }

    #[test]
    fn test_slice_arbitrary_length_and_empty_needle_safety() {
        // 极限用例 1: 非 1/2/4 字节长度 (3 字节 = 0x414243) 大端无符号数值比对
        let f_3b = CompiledFilter::compile("payload[0:3] == 0x414243").unwrap();
        assert!(f_3b.matches("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 64, 1.0, "ABCdef"));
        assert!(!f_3b.matches("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 64, 1.0, "ABXdef"));

        // 极限用例 2: 超过 8 字节切片数值比较稳健拦截返回 false 而非截断误判
        let f_over8 = CompiledFilter::compile("payload[0:10] == 0").unwrap();
        assert!(!f_over8.matches("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 64, 1.0, "0123456789AB"));

        // 极限用例 3: 空针串 slice contains 防 windows(0) Panic 崩溃验证
        let f_empty_needle = CompiledFilter::compile(r#"payload[0:4] contains """#).unwrap();
        assert!(f_empty_needle.matches("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 64, 1.0, "TEST"));
    }
}
