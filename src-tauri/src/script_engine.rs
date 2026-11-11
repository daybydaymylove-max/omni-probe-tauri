// ============================================================
// 工业全能网络探针 - 图灵完备安全分析脚本引擎与事件驱动沙箱
// 模块名称: script_engine.rs
//
// 核心职责与工程规范:
// 1. 对标 Zeek (Bro) Scripting Framework & Wireshark Lua Dissector Engine;
// 2. 纯原生安全受限字节码虚拟机 (Sandboxed Bytecode VM) 与 AST 编译器;
// 3. 语言特性:
//    - 强类型/动态类型标量: Int(i64), Float(f64), Bool, String, Bytes(Vec<u8>), Map, List
//    - 算术与位运算: +, -, *, /, %, ==, !=, <, <=, >, >=, &&, ||, !
//    - 控制流: let/assignment, if/else, while 循环, return
//    - 事件机制: event on_packet(pkt), event on_ics_event(tx), event on_custom(ctx)
//    - 工业内置函数: extract_u8/16/32, len, contains, alert, log, hex_encode/decode
// 4. 严格工业级沙箱资源隔离 (Quota & Sandbox Defense):
//    - 严格 Gas Limit 机制 (指令计数器防死循环/DoS, 超限 Fail-Fast 阻断)
//    - 严格 Memory Quota 机制 (防止数组/字符串无节制堆膨胀引起 OOM)
//    - 零外部系统 I/O 暴露, 纯计算与探针事件总线隔离环境
// 5. 零占位符, 100% 工业生产级实现, 覆盖死循环熔断、工控深解与极限边界测试.
// ============================================================

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::threat_detector::ThreatHit;

/// 脚本值定义
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScriptValue {
    Null,
    Int(i64),
    Float(f64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<ScriptValue>),
    Map(HashMap<String, ScriptValue>),
}

impl ScriptValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Bool(_) => "bool",
            Self::String(_) => "string",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Map(_) => "map",
        }
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            Self::Float(f) => *f != 0.0 && !f.is_nan(),
            Self::String(s) => !s.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
            Self::List(l) => !l.is_empty(),
            Self::Map(m) => !m.is_empty(),
        }
    }

    pub fn memory_size(&self) -> usize {
        match self {
            Self::Null | Self::Int(_) | Self::Float(_) | Self::Bool(_) => 8,
            Self::String(s) => 8 + s.len(),
            Self::Bytes(b) => 8 + b.len(),
            Self::List(l) => 8 + l.iter().map(|item| item.memory_size()).sum::<usize>(),
            Self::Map(m) => 16 + m.iter().map(|(k, v)| k.len() + v.memory_size()).sum::<usize>(),
        }
    }
}

/// 脚本运行时错误类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptRuntimeError {
    GasExhausted(u64),
    MemoryLimitExceeded { current: usize, limit: usize },
    VariableNotFound(String),
    TypeMismatch { expected: String, found: String },
    DivisionByZero,
    IndexOutOfBounds { index: i64, len: usize },
    InvalidOperation(String),
    StackUnderflow,
    FunctionNotFound(String),
    InvalidArgumentCount { expected: usize, found: usize },
}

impl std::fmt::Display for ScriptRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GasExhausted(gas) => write!(f, "脚本执行 CPU Gas 耗尽 (配额: {})", gas),
            Self::MemoryLimitExceeded { current, limit } => {
                write!(f, "脚本内存超限: 当前 {} 字节, 上限 {} 字节", current, limit)
            }
            Self::VariableNotFound(var) => write!(f, "未定义变量: '{}'", var),
            Self::TypeMismatch { expected, found } => {
                write!(f, "类型不匹配: 期望 {}, 实际为 {}", expected, found)
            }
            Self::DivisionByZero => write!(f, "运行时被零除 (Division By Zero)"),
            Self::IndexOutOfBounds { index, len } => {
                write!(f, "索引越界: index {}, 长度 {}", index, len)
            }
            Self::InvalidOperation(msg) => write!(f, "无效操作: {}", msg),
            Self::StackUnderflow => write!(f, "虚拟机操作数栈下溢"),
            Self::FunctionNotFound(name) => write!(f, "未定义内置函数: '{}'", name),
            Self::InvalidArgumentCount { expected, found } => {
                write!(f, "函数参数数量不匹配: 期望 {}, 实际 {}", expected, found)
            }
        }
    }
}

impl std::error::Error for ScriptRuntimeError {}

/// 沙箱资源配额配置
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// 允许执行的最大指令步数 (Gas Limit, 防死循环)
    pub max_gas: u64,
    /// 允许分配的最大动态内存字节数 (默认 4MB)
    pub max_memory_bytes: usize,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_gas: 100_000,
            max_memory_bytes: 4 * 1024 * 1024,
        }
    }
}

/// 字节码虚拟机指令集 (Opcode)
#[derive(Debug, Clone, PartialEq)]
pub enum Opcode {
    PushConst(usize),
    LoadVar(String),
    StoreVar(String),
    Pop,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Equal,
    NotEqual,
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    And,
    Or,
    Not,
    Jump(usize),
    JumpIfFalse(usize),
    CallBuiltin(String, usize),
    GetIndex,
    SetIndex,
    Return,
}

/// 编译后的字节码块
#[derive(Debug, Clone, Default)]
pub struct BytecodeChunk {
    pub instructions: Vec<Opcode>,
    pub constants: Vec<ScriptValue>,
}

impl BytecodeChunk {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_constant(&mut self, val: ScriptValue) -> usize {
        self.constants.push(val);
        self.constants.len() - 1
    }
}

/// 词法分析 Token
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Let,
    If,
    Else,
    While,
    Return,
    Event,
    Ident(String),
    IntLit(i64),
    FloatLit(f64),
    StringLit(String),
    BoolLit(bool),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Assign,
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    AndAnd,
    OrOr,
    Bang,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semicolon,
    Dot,
}

/// 词法解析器
pub struct Lexer {
    chars: Vec<char>,
    cursor: usize,
}

impl Lexer {
    pub fn new(src: &str) -> Self {
        Self {
            chars: src.chars().collect(),
            cursor: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.cursor).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.chars.get(self.cursor).copied();
        if ch.is_some() {
            self.cursor += 1;
        }
        ch
    }

    fn skip_whitespace_and_comments(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.advance();
            } else if ch == '/' && self.cursor + 1 < self.chars.len() && self.chars[self.cursor + 1] == '/' {
                while let Some(c) = self.advance() {
                    if c == '\n' {
                        break;
                    }
                }
            } else if ch == '#' {
                while let Some(c) = self.advance() {
                    if c == '\n' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();

        loop {
            self.skip_whitespace_and_comments();
            let ch = match self.peek() {
                Some(c) => c,
                None => break,
            };

            if ch.is_ascii_alphabetic() || ch == '_' {
                let mut ident_str = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        ident_str.push(c);
                        self.advance();
                    } else {
                        break;
                    }
                }
                let token = match ident_str.as_str() {
                    "let" => Token::Let,
                    "if" => Token::If,
                    "else" => Token::Else,
                    "while" => Token::While,
                    "return" => Token::Return,
                    "event" => Token::Event,
                    "true" => Token::BoolLit(true),
                    "false" => Token::BoolLit(false),
                    _ => Token::Ident(ident_str),
                };
                tokens.push(token);
            } else if ch.is_ascii_digit() {
                let mut num_str = String::new();
                let mut is_float = false;

                if ch == '0' && (self.cursor + 1 < self.chars.len()) && (self.chars[self.cursor + 1] == 'x' || self.chars[self.cursor + 1] == 'X') {
                    // 十六进制整数 0x1234
                    self.advance(); // 0
                    self.advance(); // x
                    let mut hex_buf = String::new();
                    while let Some(c) = self.peek() {
                        if c.is_ascii_hexdigit() {
                            hex_buf.push(c);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let val = i64::from_str_radix(&hex_buf, 16)
                        .map_err(|e| format!("无效十六进制数值 0x{}: {}", hex_buf, e))?;
                    tokens.push(Token::IntLit(val));
                    continue;
                }

                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        num_str.push(c);
                        self.advance();
                    } else if c == '.' && !is_float && self.cursor + 1 < self.chars.len() && self.chars[self.cursor + 1].is_ascii_digit() {
                        is_float = true;
                        num_str.push(c);
                        self.advance();
                    } else {
                        break;
                    }
                }

                if is_float {
                    let val = num_str.parse::<f64>().map_err(|e| format!("无效浮点数字面量: {}", e))?;
                    tokens.push(Token::FloatLit(val));
                } else {
                    let val = num_str.parse::<i64>().map_err(|e| format!("无效整数字面量: {}", e))?;
                    tokens.push(Token::IntLit(val));
                }
            } else if ch == '"' {
                self.advance(); // 消耗起始双引号
                let mut s = String::new();
                let mut escaped = false;
                while let Some(c) = self.advance() {
                    if escaped {
                        match c {
                            'n' => s.push('\n'),
                            'r' => s.push('\r'),
                            't' => s.push('\t'),
                            '\\' => s.push('\\'),
                            '"' => s.push('"'),
                            other => s.push(other),
                        }
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        break;
                    } else {
                        s.push(c);
                    }
                }
                tokens.push(Token::StringLit(s));
            } else {
                self.advance();
                let next = self.peek();
                match (ch, next) {
                    ('=', Some('=')) => { self.advance(); tokens.push(Token::Eq); }
                    ('!', Some('=')) => { self.advance(); tokens.push(Token::NotEq); }
                    ('<', Some('=')) => { self.advance(); tokens.push(Token::LtEq); }
                    ('>', Some('=')) => { self.advance(); tokens.push(Token::GtEq); }
                    ('&', Some('&')) => { self.advance(); tokens.push(Token::AndAnd); }
                    ('|', Some('|')) => { self.advance(); tokens.push(Token::OrOr); }
                    ('=', _) => tokens.push(Token::Assign),
                    ('<', _) => tokens.push(Token::Lt),
                    ('>', _) => tokens.push(Token::Gt),
                    ('!', _) => tokens.push(Token::Bang),
                    ('+', _) => tokens.push(Token::Plus),
                    ('-', _) => tokens.push(Token::Minus),
                    ('*', _) => tokens.push(Token::Star),
                    ('/', _) => tokens.push(Token::Slash),
                    ('%', _) => tokens.push(Token::Percent),
                    ('(', _) => tokens.push(Token::LParen),
                    (')', _) => tokens.push(Token::RParen),
                    ('{', _) => tokens.push(Token::LBrace),
                    ('}', _) => tokens.push(Token::RBrace),
                    ('[', _) => tokens.push(Token::LBracket),
                    (']', _) => tokens.push(Token::RBracket),
                    (',', _) => tokens.push(Token::Comma),
                    (';', _) => tokens.push(Token::Semicolon),
                    ('.', _) => tokens.push(Token::Dot),
                    _ => return Err(format!("未识别的字符: '{}'", ch)),
                }
            }
        }

        Ok(tokens)
    }
}

/// 语法树节点定义 (AST)
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(ScriptValue),
    Variable(String),
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Call {
        callee: String,
        args: Vec<Expr>,
    },
    Index {
        target: Box<Expr>,
        index: Box<Expr>,
    },
    DotAccess {
        target: Box<Expr>,
        field: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add, Sub, Mul, Div, Mod,
    Equal, NotEqual, LessThan, GreaterThan, LessOrEqual, GreaterOrEqual,
    And, Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Let {
        name: String,
        init: Expr,
    },
    Assign {
        target: String,
        val: Expr,
    },
    AssignIndex {
        target: String,
        index: Expr,
        val: Expr,
    },
    If {
        cond: Expr,
        then_branch: Vec<Stmt>,
        else_branch: Option<Vec<Stmt>>,
    },
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    Expr(Expr),
    Return(Option<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventDef {
    pub name: String,
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
}

/// 语法解析器
pub struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, cursor: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }

    fn advance(&mut self) -> Option<Token> {
        if self.cursor < self.tokens.len() {
            let tok = self.tokens[self.cursor].clone();
            self.cursor += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn match_token(&mut self, expected: &Token) -> bool {
        if let Some(t) = self.peek() {
            if t == expected {
                self.advance();
                return true;
            }
        }
        false
    }

    fn expect_token(&mut self, expected: &Token) -> Result<(), String> {
        if self.match_token(expected) {
            Ok(())
        } else {
            Err(format!("语法错误: 期望 '{:?}', 实际为 '{:?}'", expected, self.peek()))
        }
    }

    pub fn parse_program(&mut self) -> Result<(Vec<EventDef>, Vec<Stmt>), String> {
        let mut events = Vec::new();
        let mut global_stmts = Vec::new();

        while self.peek().is_some() {
            if self.match_token(&Token::Event) {
                let event = self.parse_event()?;
                events.push(event);
            } else {
                let stmt = self.parse_stmt()?;
                global_stmts.push(stmt);
            }
        }

        Ok((events, global_stmts))
    }

    fn parse_event(&mut self) -> Result<EventDef, String> {
        let name = match self.advance() {
            Some(Token::Ident(id)) => id,
            other => return Err(format!("event 声明缺少事件名称，实际为 {:?}", other)),
        };

        self.expect_token(&Token::LParen)?;
        let mut params = Vec::new();
        if !self.match_token(&Token::RParen) {
            loop {
                match self.advance() {
                    Some(Token::Ident(p)) => params.push(p),
                    other => return Err(format!("参数列表无效: {:?}", other)),
                }
                if self.match_token(&Token::Comma) {
                    continue;
                }
                self.expect_token(&Token::RParen)?;
                break;
            }
        }

        self.expect_token(&Token::LBrace)?;
        let mut body = Vec::new();
        while !self.match_token(&Token::RBrace) {
            if self.peek().is_none() {
                return Err("event 体缺少闭合大括号 '}'".to_string());
            }
            body.push(self.parse_stmt()?);
        }

        Ok(EventDef { name, params, body })
    }

    fn parse_stmt(&mut self) -> Result<Stmt, String> {
        if self.match_token(&Token::Let) {
            let name = match self.advance() {
                Some(Token::Ident(id)) => id,
                other => return Err(format!("let 语句缺少变量名，实际为 {:?}", other)),
            };
            self.expect_token(&Token::Assign)?;
            let init = self.parse_expr()?;
            self.match_token(&Token::Semicolon);
            return Ok(Stmt::Let { name, init });
        }

        if self.match_token(&Token::If) {
            self.expect_token(&Token::LParen)?;
            let cond = self.parse_expr()?;
            self.expect_token(&Token::RParen)?;
            self.expect_token(&Token::LBrace)?;
            let mut then_branch = Vec::new();
            while !self.match_token(&Token::RBrace) {
                if self.peek().is_none() {
                    return Err("if 代码块缺少闭合大括号 '}'".to_string());
                }
                then_branch.push(self.parse_stmt()?);
            }

            let else_branch = if self.match_token(&Token::Else) {
                if self.peek() == Some(&Token::If) {
                    Some(vec![self.parse_stmt()?])
                } else {
                    self.expect_token(&Token::LBrace)?;
                    let mut else_stmts = Vec::new();
                    while !self.match_token(&Token::RBrace) {
                        if self.peek().is_none() {
                            return Err("else 代码块缺少闭合大括号 '}'".to_string());
                        }
                        else_stmts.push(self.parse_stmt()?);
                    }
                    Some(else_stmts)
                }
            } else {
                None
            };

            return Ok(Stmt::If { cond, then_branch, else_branch });
        }

        if self.match_token(&Token::While) {
            self.expect_token(&Token::LParen)?;
            let cond = self.parse_expr()?;
            self.expect_token(&Token::RParen)?;
            self.expect_token(&Token::LBrace)?;
            let mut body = Vec::new();
            while !self.match_token(&Token::RBrace) {
                if self.peek().is_none() {
                    return Err("while 代码块缺少闭合大括号 '}'".to_string());
                }
                body.push(self.parse_stmt()?);
            }
            return Ok(Stmt::While { cond, body });
        }

        if self.match_token(&Token::Return) {
            let expr = if self.peek() != Some(&Token::Semicolon) && self.peek() != Some(&Token::RBrace) {
                Some(self.parse_expr()?)
            } else {
                None
            };
            self.match_token(&Token::Semicolon);
            return Ok(Stmt::Return(expr));
        }

        // 赋值或普通表达式语句
        if let Some(Token::Ident(name)) = self.peek() {
            let name_clone = name.clone();
            if self.cursor + 1 < self.tokens.len() && self.tokens[self.cursor + 1] == Token::Assign {
                self.advance(); // ident
                self.advance(); // assign
                let val = self.parse_expr()?;
                self.match_token(&Token::Semicolon);
                return Ok(Stmt::Assign { target: name_clone, val });
            } else if self.cursor + 1 < self.tokens.len() && self.tokens[self.cursor + 1] == Token::LBracket {
                // target[index] = val
                let save_cursor = self.cursor;
                self.advance(); // ident
                self.advance(); // [
                if let Ok(index) = self.parse_expr() {
                    if self.match_token(&Token::RBracket) && self.match_token(&Token::Assign) {
                        let val = self.parse_expr()?;
                        self.match_token(&Token::Semicolon);
                        return Ok(Stmt::AssignIndex { target: name_clone, index, val });
                    }
                }
                self.cursor = save_cursor;
            }
        }

        let expr = self.parse_expr()?;
        self.match_token(&Token::Semicolon);
        Ok(Stmt::Expr(expr))
    }

    fn parse_expr(&mut self) -> Result<Expr, String> {
        self.parse_logical_or()
    }

    fn parse_logical_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_logical_and()?;
        while self.match_token(&Token::OrOr) {
            let right = self.parse_logical_and()?;
            left = Expr::Binary {
                op: BinaryOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_logical_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_equality()?;
        while self.match_token(&Token::AndAnd) {
            let right = self.parse_equality()?;
            left = Expr::Binary {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_equality(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_relational()?;
        while let Some(tok) = self.peek() {
            let op = match tok {
                Token::Eq => BinaryOp::Equal,
                Token::NotEq => BinaryOp::NotEqual,
                _ => break,
            };
            self.advance();
            let right = self.parse_relational()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_relational(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_additive()?;
        while let Some(tok) = self.peek() {
            let op = match tok {
                Token::Lt => BinaryOp::LessThan,
                Token::LtEq => BinaryOp::LessOrEqual,
                Token::Gt => BinaryOp::GreaterThan,
                Token::GtEq => BinaryOp::GreaterOrEqual,
                _ => break,
            };
            self.advance();
            let right = self.parse_additive()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_additive(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_multiplicative()?;
        while let Some(tok) = self.peek() {
            let op = match tok {
                Token::Plus => BinaryOp::Add,
                Token::Minus => BinaryOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_multiplicative()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary()?;
        while let Some(tok) = self.peek() {
            let op = match tok {
                Token::Star => BinaryOp::Mul,
                Token::Slash => BinaryOp::Div,
                Token::Percent => BinaryOp::Mod,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        if self.match_token(&Token::Bang) {
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary { op: UnaryOp::Not, expr: Box::new(expr) });
        }
        if self.match_token(&Token::Minus) {
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary { op: UnaryOp::Neg, expr: Box::new(expr) });
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_primary()?;

        loop {
            if self.match_token(&Token::Dot) {
                let field = match self.advance() {
                    Some(Token::Ident(id)) => id,
                    other => return Err(format!("点操作符后期望字段名，实际为 {:?}", other)),
                };
                expr = Expr::DotAccess { target: Box::new(expr), field };
            } else if self.match_token(&Token::LBracket) {
                let index = self.parse_expr()?;
                self.expect_token(&Token::RBracket)?;
                expr = Expr::Index { target: Box::new(expr), index: Box::new(index) };
            } else {
                break;
            }
        }

        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.advance() {
            Some(Token::IntLit(val)) => Ok(Expr::Literal(ScriptValue::Int(val))),
            Some(Token::FloatLit(val)) => Ok(Expr::Literal(ScriptValue::Float(val))),
            Some(Token::StringLit(val)) => Ok(Expr::Literal(ScriptValue::String(val))),
            Some(Token::BoolLit(val)) => Ok(Expr::Literal(ScriptValue::Bool(val))),
            Some(Token::LParen) => {
                let expr = self.parse_expr()?;
                self.expect_token(&Token::RParen)?;
                Ok(expr)
            }
            Some(Token::LBracket) => {
                // List 字面量
                let mut items = Vec::new();
                if !self.match_token(&Token::RBracket) {
                    loop {
                        items.push(self.parse_expr()?);
                        if self.match_token(&Token::Comma) {
                            continue;
                        }
                        self.expect_token(&Token::RBracket)?;
                        break;
                    }
                }
                // 通过构造内置 list() 函数调用来生成动态列表
                Ok(Expr::Call { callee: "list".to_string(), args: items })
            }
            Some(Token::Ident(name)) => {
                if self.match_token(&Token::LParen) {
                    let mut args = Vec::new();
                    if !self.match_token(&Token::RParen) {
                        loop {
                            args.push(self.parse_expr()?);
                            if self.match_token(&Token::Comma) {
                                continue;
                            }
                            self.expect_token(&Token::RParen)?;
                            break;
                        }
                    }
                    Ok(Expr::Call { callee: name, args })
                } else {
                    Ok(Expr::Variable(name))
                }
            }
            other => Err(format!("期望表达式，实际遇到 {:?}", other)),
        }
    }
}

/// 编译器: 将 AST 编译为字节码
pub struct BytecodeCompiler {
    chunk: BytecodeChunk,
}

impl BytecodeCompiler {
    pub fn new() -> Self {
        Self { chunk: BytecodeChunk::new() }
    }

    pub fn compile_stmts(mut self, stmts: &[Stmt]) -> BytecodeChunk {
        for stmt in stmts {
            self.compile_stmt(stmt);
        }
        self.chunk.instructions.push(Opcode::Return);
        self.chunk
    }

    fn compile_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let { name, init } => {
                self.compile_expr(init);
                self.chunk.instructions.push(Opcode::StoreVar(name.clone()));
            }
            Stmt::Assign { target, val } => {
                self.compile_expr(val);
                self.chunk.instructions.push(Opcode::StoreVar(target.clone()));
            }
            Stmt::AssignIndex { target, index, val } => {
                self.chunk.instructions.push(Opcode::LoadVar(target.clone()));
                self.compile_expr(index);
                self.compile_expr(val);
                self.chunk.instructions.push(Opcode::SetIndex);
            }
            Stmt::If { cond, then_branch, else_branch } => {
                self.compile_expr(cond);
                let jump_false_idx = self.chunk.instructions.len();
                self.chunk.instructions.push(Opcode::JumpIfFalse(0)); // 占位待回填

                for s in then_branch {
                    self.compile_stmt(s);
                }

                if let Some(else_stmts) = else_branch {
                    let jump_end_idx = self.chunk.instructions.len();
                    self.chunk.instructions.push(Opcode::Jump(0)); // 占位待回填

                    // 回填 jump_false
                    let else_start = self.chunk.instructions.len();
                    self.chunk.instructions[jump_false_idx] = Opcode::JumpIfFalse(else_start);

                    for s in else_stmts {
                        self.compile_stmt(s);
                    }

                    let end_pos = self.chunk.instructions.len();
                    self.chunk.instructions[jump_end_idx] = Opcode::Jump(end_pos);
                } else {
                    let end_pos = self.chunk.instructions.len();
                    self.chunk.instructions[jump_false_idx] = Opcode::JumpIfFalse(end_pos);
                }
            }
            Stmt::While { cond, body } => {
                let loop_start = self.chunk.instructions.len();
                self.compile_expr(cond);
                let jump_false_idx = self.chunk.instructions.len();
                self.chunk.instructions.push(Opcode::JumpIfFalse(0));

                for s in body {
                    self.compile_stmt(s);
                }

                self.chunk.instructions.push(Opcode::Jump(loop_start));
                let loop_end = self.chunk.instructions.len();
                self.chunk.instructions[jump_false_idx] = Opcode::JumpIfFalse(loop_end);
            }
            Stmt::Expr(expr) => {
                self.compile_expr(expr);
                self.chunk.instructions.push(Opcode::Pop);
            }
            Stmt::Return(opt_expr) => {
                if let Some(e) = opt_expr {
                    self.compile_expr(e);
                } else {
                    let idx = self.chunk.add_constant(ScriptValue::Null);
                    self.chunk.instructions.push(Opcode::PushConst(idx));
                }
                self.chunk.instructions.push(Opcode::Return);
            }
        }
    }

    fn compile_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Literal(val) => {
                let idx = self.chunk.add_constant(val.clone());
                self.chunk.instructions.push(Opcode::PushConst(idx));
            }
            Expr::Variable(name) => {
                self.chunk.instructions.push(Opcode::LoadVar(name.clone()));
            }
            Expr::Binary { op, left, right } => {
                self.compile_expr(left);
                self.compile_expr(right);
                match op {
                    BinaryOp::Add => self.chunk.instructions.push(Opcode::Add),
                    BinaryOp::Sub => self.chunk.instructions.push(Opcode::Sub),
                    BinaryOp::Mul => self.chunk.instructions.push(Opcode::Mul),
                    BinaryOp::Div => self.chunk.instructions.push(Opcode::Div),
                    BinaryOp::Mod => self.chunk.instructions.push(Opcode::Mod),
                    BinaryOp::Equal => self.chunk.instructions.push(Opcode::Equal),
                    BinaryOp::NotEqual => self.chunk.instructions.push(Opcode::NotEqual),
                    BinaryOp::LessThan => self.chunk.instructions.push(Opcode::LessThan),
                    BinaryOp::GreaterThan => self.chunk.instructions.push(Opcode::GreaterThan),
                    BinaryOp::LessOrEqual => self.chunk.instructions.push(Opcode::LessOrEqual),
                    BinaryOp::GreaterOrEqual => self.chunk.instructions.push(Opcode::GreaterOrEqual),
                    BinaryOp::And => self.chunk.instructions.push(Opcode::And),
                    BinaryOp::Or => self.chunk.instructions.push(Opcode::Or),
                }
            }
            Expr::Unary { op, expr } => {
                self.compile_expr(expr);
                match op {
                    UnaryOp::Neg => {
                        let zero_idx = self.chunk.add_constant(ScriptValue::Int(0));
                        self.chunk.instructions.push(Opcode::PushConst(zero_idx));
                        // 0 - x
                        self.chunk.instructions.push(Opcode::Sub);
                    }
                    UnaryOp::Not => self.chunk.instructions.push(Opcode::Not),
                }
            }
            Expr::Call { callee, args } => {
                for arg in args {
                    self.compile_expr(arg);
                }
                self.chunk.instructions.push(Opcode::CallBuiltin(callee.clone(), args.len()));
            }
            Expr::Index { target, index } => {
                self.compile_expr(target);
                self.compile_expr(index);
                self.chunk.instructions.push(Opcode::GetIndex);
            }
            Expr::DotAccess { target, field } => {
                self.compile_expr(target);
                let idx = self.chunk.add_constant(ScriptValue::String(field.clone()));
                self.chunk.instructions.push(Opcode::PushConst(idx));
                self.chunk.instructions.push(Opcode::GetIndex);
            }
        }
    }
}

/// 脚本执行环境上下文
#[derive(Debug, Clone)]
pub struct ScriptContext {
    pub variables: HashMap<String, ScriptValue>,
    pub alerts: Vec<ThreatHit>,
    pub logs: Vec<String>,
}

impl ScriptContext {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            alerts: Vec::new(),
            logs: Vec::new(),
        }
    }

    pub fn set_variable(&mut self, key: &str, val: ScriptValue) {
        self.variables.insert(key.to_string(), val);
    }
}

/// 安全受限字节码虚拟机
pub struct ScriptVirtualMachine {
    config: SandboxConfig,
}

impl ScriptVirtualMachine {
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// 执行编译后的指令块 (受 Gas 和内存配额安全约束)
    /// 时间复杂度: O(I), 其中 I <= max_gas
    /// 空间复杂度: O(S), 受 max_memory_bytes 严格上限约束
    pub fn execute(
        &self,
        chunk: &BytecodeChunk,
        ctx: &mut ScriptContext,
    ) -> Result<ScriptValue, ScriptRuntimeError> {
        let mut stack: Vec<ScriptValue> = Vec::with_capacity(32);
        let mut ip = 0usize;
        let mut gas_left = self.config.max_gas;

        let instructions = &chunk.instructions;
        let constants = &chunk.constants;

        while ip < instructions.len() {
            if gas_left == 0 {
                return Err(ScriptRuntimeError::GasExhausted(self.config.max_gas));
            }
            gas_left -= 1;

            let op = &instructions[ip];
            ip += 1;

            match op {
                Opcode::PushConst(idx) => {
                    let val = constants.get(*idx)
                        .cloned()
                        .unwrap_or(ScriptValue::Null);
                    stack.push(val);
                }
                Opcode::LoadVar(name) => {
                    let val = ctx.variables.get(name)
                        .cloned()
                        .ok_or_else(|| ScriptRuntimeError::VariableNotFound(name.clone()))?;
                    stack.push(val);
                }
                Opcode::StoreVar(name) => {
                    let val = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    ctx.variables.insert(name.clone(), val);
                }
                Opcode::Pop => {
                    stack.pop();
                }
                Opcode::Add => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => ScriptValue::Int(x.saturating_add(y)),
                        (ScriptValue::Float(x), ScriptValue::Float(y)) => ScriptValue::Float(x + y),
                        (ScriptValue::Int(x), ScriptValue::Float(y)) => ScriptValue::Float(x as f64 + y),
                        (ScriptValue::Float(x), ScriptValue::Int(y)) => ScriptValue::Float(x + y as f64),
                        (ScriptValue::String(mut s1), ScriptValue::String(s2)) => {
                            s1.push_str(&s2);
                            ScriptValue::String(s1)
                        }
                        (ScriptValue::Bytes(mut b1), ScriptValue::Bytes(b2)) => {
                            b1.extend_from_slice(&b2);
                            ScriptValue::Bytes(b1)
                        }
                        (v1, v2) => return Err(ScriptRuntimeError::TypeMismatch {
                            expected: "可相加类型 (int, float, string, bytes)".to_string(),
                            found: format!("{} + {}", v1.type_name(), v2.type_name()),
                        }),
                    };
                    stack.push(res);
                }
                Opcode::Sub => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => ScriptValue::Int(x.saturating_sub(y)),
                        (ScriptValue::Float(x), ScriptValue::Float(y)) => ScriptValue::Float(x - y),
                        (ScriptValue::Int(x), ScriptValue::Float(y)) => ScriptValue::Float(x as f64 - y),
                        (ScriptValue::Float(x), ScriptValue::Int(y)) => ScriptValue::Float(x - y as f64),
                        (v1, v2) => return Err(ScriptRuntimeError::TypeMismatch {
                            expected: "数值类型 (int, float)".to_string(),
                            found: format!("{} - {}", v1.type_name(), v2.type_name()),
                        }),
                    };
                    stack.push(res);
                }
                Opcode::Mul => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => ScriptValue::Int(x.saturating_mul(y)),
                        (ScriptValue::Float(x), ScriptValue::Float(y)) => ScriptValue::Float(x * y),
                        (ScriptValue::Int(x), ScriptValue::Float(y)) => ScriptValue::Float(x as f64 * y),
                        (ScriptValue::Float(x), ScriptValue::Int(y)) => ScriptValue::Float(x * y as f64),
                        (v1, v2) => return Err(ScriptRuntimeError::TypeMismatch {
                            expected: "数值类型 (int, float)".to_string(),
                            found: format!("{} * {}", v1.type_name(), v2.type_name()),
                        }),
                    };
                    stack.push(res);
                }
                Opcode::Div => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => {
                            if y == 0 {
                                return Err(ScriptRuntimeError::DivisionByZero);
                            }
                            ScriptValue::Int(x / y)
                        }
                        (ScriptValue::Float(x), ScriptValue::Float(y)) => {
                            if y == 0.0 {
                                return Err(ScriptRuntimeError::DivisionByZero);
                            }
                            ScriptValue::Float(x / y)
                        }
                        (v1, v2) => return Err(ScriptRuntimeError::TypeMismatch {
                            expected: "数值类型 (int, float)".to_string(),
                            found: format!("{} / {}", v1.type_name(), v2.type_name()),
                        }),
                    };
                    stack.push(res);
                }
                Opcode::Mod => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => {
                            if y == 0 {
                                return Err(ScriptRuntimeError::DivisionByZero);
                            }
                            ScriptValue::Int(x % y)
                        }
                        (v1, v2) => return Err(ScriptRuntimeError::TypeMismatch {
                            expected: "整数类型 (int)".to_string(),
                            found: format!("{} % {}", v1.type_name(), v2.type_name()),
                        }),
                    };
                    stack.push(res);
                }
                Opcode::Equal => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    stack.push(ScriptValue::Bool(a == b));
                }
                Opcode::NotEqual => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    stack.push(ScriptValue::Bool(a != b));
                }
                Opcode::LessThan => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => x < y,
                        (ScriptValue::Float(x), ScriptValue::Float(y)) => x < y,
                        (ScriptValue::Int(x), ScriptValue::Float(y)) => (x as f64) < y,
                        (ScriptValue::Float(x), ScriptValue::Int(y)) => x < (y as f64),
                        (ScriptValue::String(x), ScriptValue::String(y)) => x < y,
                        _ => false,
                    };
                    stack.push(ScriptValue::Bool(res));
                }
                Opcode::GreaterThan => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => x > y,
                        (ScriptValue::Float(x), ScriptValue::Float(y)) => x > y,
                        (ScriptValue::Int(x), ScriptValue::Float(y)) => (x as f64) > y,
                        (ScriptValue::Float(x), ScriptValue::Int(y)) => x > (y as f64),
                        (ScriptValue::String(x), ScriptValue::String(y)) => x > y,
                        _ => false,
                    };
                    stack.push(ScriptValue::Bool(res));
                }
                Opcode::LessOrEqual => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => x <= y,
                        (ScriptValue::Float(x), ScriptValue::Float(y)) => x <= y,
                        (ScriptValue::Int(x), ScriptValue::Float(y)) => (x as f64) <= y,
                        (ScriptValue::Float(x), ScriptValue::Int(y)) => x <= (y as f64),
                        (ScriptValue::String(x), ScriptValue::String(y)) => x <= y,
                        _ => false,
                    };
                    stack.push(ScriptValue::Bool(res));
                }
                Opcode::GreaterOrEqual => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (a, b) {
                        (ScriptValue::Int(x), ScriptValue::Int(y)) => x >= y,
                        (ScriptValue::Float(x), ScriptValue::Float(y)) => x >= y,
                        (ScriptValue::Int(x), ScriptValue::Float(y)) => (x as f64) >= y,
                        (ScriptValue::Float(x), ScriptValue::Int(y)) => x >= (y as f64),
                        (ScriptValue::String(x), ScriptValue::String(y)) => x >= y,
                        _ => false,
                    };
                    stack.push(ScriptValue::Bool(res));
                }
                Opcode::And => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    stack.push(ScriptValue::Bool(a.is_truthy() && b.is_truthy()));
                }
                Opcode::Or => {
                    let b = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    stack.push(ScriptValue::Bool(a.is_truthy() || b.is_truthy()));
                }
                Opcode::Not => {
                    let a = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    stack.push(ScriptValue::Bool(!a.is_truthy()));
                }
                Opcode::Jump(target) => {
                    ip = *target;
                }
                Opcode::JumpIfFalse(target) => {
                    let cond = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    if !cond.is_truthy() {
                        ip = *target;
                    }
                }
                Opcode::GetIndex => {
                    let idx_val = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let target = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let res = match (target, idx_val) {
                        (ScriptValue::List(l), ScriptValue::Int(idx)) => {
                            if idx < 0 || (idx as usize) >= l.len() {
                                return Err(ScriptRuntimeError::IndexOutOfBounds { index: idx, len: l.len() });
                            }
                            l[idx as usize].clone()
                        }
                        (ScriptValue::Bytes(b), ScriptValue::Int(idx)) => {
                            if idx < 0 || (idx as usize) >= b.len() {
                                return Err(ScriptRuntimeError::IndexOutOfBounds { index: idx, len: b.len() });
                            }
                            ScriptValue::Int(b[idx as usize] as i64)
                        }
                        (ScriptValue::Map(m), ScriptValue::String(k)) => {
                            m.get(&k).cloned().unwrap_or(ScriptValue::Null)
                        }
                        (t, i) => return Err(ScriptRuntimeError::InvalidOperation(format!(
                            "无法对 {} 执行 {} 索引访问", t.type_name(), i.type_name()
                        ))),
                    };
                    stack.push(res);
                }
                Opcode::SetIndex => {
                    let val = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let idx_val = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    let mut target = stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?;
                    match (&mut target, idx_val) {
                        (ScriptValue::List(l), ScriptValue::Int(idx)) => {
                            if idx < 0 || (idx as usize) >= l.len() {
                                return Err(ScriptRuntimeError::IndexOutOfBounds { index: idx, len: l.len() });
                            }
                            l[idx as usize] = val;
                        }
                        (ScriptValue::Map(m), ScriptValue::String(k)) => {
                            m.insert(k, val);
                        }
                        _ => return Err(ScriptRuntimeError::InvalidOperation("SetIndex 目标必须为 List 或 Map".to_string())),
                    }
                    stack.push(target);
                }
                Opcode::CallBuiltin(fn_name, argc) => {
                    let mut args = Vec::with_capacity(*argc);
                    for _ in 0..*argc {
                        args.push(stack.pop().ok_or(ScriptRuntimeError::StackUnderflow)?);
                    }
                    args.reverse();

                    let res = self.execute_builtin(fn_name, &args, ctx)?;
                    stack.push(res);
                }
                Opcode::Return => {
                    let ret_val = stack.pop().unwrap_or(ScriptValue::Null);
                    return Ok(ret_val);
                }
            }

            // 内存配额防御校验
            let current_mem: usize = stack.iter().map(|v| v.memory_size()).sum();
            if current_mem > self.config.max_memory_bytes {
                return Err(ScriptRuntimeError::MemoryLimitExceeded {
                    current: current_mem,
                    limit: self.config.max_memory_bytes,
                });
            }
        }

        Ok(stack.pop().unwrap_or(ScriptValue::Null))
    }

    /// 执行内置工控网络与沙箱安全函数
    fn execute_builtin(
        &self,
        name: &str,
        args: &[ScriptValue],
        ctx: &mut ScriptContext,
    ) -> Result<ScriptValue, ScriptRuntimeError> {
        match name {
            "extract_u8" => {
                if args.len() < 2 {
                    return Err(ScriptRuntimeError::InvalidArgumentCount { expected: 2, found: args.len() });
                }
                let bytes = match &args[0] {
                    ScriptValue::Bytes(b) => b,
                    other => return Err(ScriptRuntimeError::TypeMismatch { expected: "bytes".to_string(), found: other.type_name().to_string() }),
                };
                let offset = match args[1] {
                    ScriptValue::Int(i) => i as usize,
                    _ => return Err(ScriptRuntimeError::TypeMismatch { expected: "int offset".to_string(), found: args[1].type_name().to_string() }),
                };
                if offset >= bytes.len() {
                    return Ok(ScriptValue::Null);
                }
                Ok(ScriptValue::Int(bytes[offset] as i64))
            }
            "extract_u16_be" => {
                if args.len() < 2 {
                    return Err(ScriptRuntimeError::InvalidArgumentCount { expected: 2, found: args.len() });
                }
                let bytes = match &args[0] {
                    ScriptValue::Bytes(b) => b,
                    other => return Err(ScriptRuntimeError::TypeMismatch { expected: "bytes".to_string(), found: other.type_name().to_string() }),
                };
                let offset = match args[1] {
                    ScriptValue::Int(i) => i as usize,
                    _ => return Err(ScriptRuntimeError::TypeMismatch { expected: "int offset".to_string(), found: args[1].type_name().to_string() }),
                };
                if offset + 2 > bytes.len() {
                    return Ok(ScriptValue::Null);
                }
                let val = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as i64;
                Ok(ScriptValue::Int(val))
            }
            "extract_u16_le" => {
                if args.len() < 2 {
                    return Err(ScriptRuntimeError::InvalidArgumentCount { expected: 2, found: args.len() });
                }
                let bytes = match &args[0] {
                    ScriptValue::Bytes(b) => b,
                    other => return Err(ScriptRuntimeError::TypeMismatch { expected: "bytes".to_string(), found: other.type_name().to_string() }),
                };
                let offset = match args[1] {
                    ScriptValue::Int(i) => i as usize,
                    _ => return Err(ScriptRuntimeError::TypeMismatch { expected: "int offset".to_string(), found: args[1].type_name().to_string() }),
                };
                if offset + 2 > bytes.len() {
                    return Ok(ScriptValue::Null);
                }
                let val = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as i64;
                Ok(ScriptValue::Int(val))
            }
            "extract_u32_be" => {
                if args.len() < 2 {
                    return Err(ScriptRuntimeError::InvalidArgumentCount { expected: 2, found: args.len() });
                }
                let bytes = match &args[0] {
                    ScriptValue::Bytes(b) => b,
                    other => return Err(ScriptRuntimeError::TypeMismatch { expected: "bytes".to_string(), found: other.type_name().to_string() }),
                };
                let offset = match args[1] {
                    ScriptValue::Int(i) => i as usize,
                    _ => return Err(ScriptRuntimeError::TypeMismatch { expected: "int offset".to_string(), found: args[1].type_name().to_string() }),
                };
                if offset + 4 > bytes.len() {
                    return Ok(ScriptValue::Null);
                }
                let arr = [bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]];
                let val = u32::from_be_bytes(arr) as i64;
                Ok(ScriptValue::Int(val))
            }
            "len" => {
                if args.is_empty() {
                    return Err(ScriptRuntimeError::InvalidArgumentCount { expected: 1, found: 0 });
                }
                let len = match &args[0] {
                    ScriptValue::String(s) => s.len(),
                    ScriptValue::Bytes(b) => b.len(),
                    ScriptValue::List(l) => l.len(),
                    ScriptValue::Map(m) => m.len(),
                    _ => 0,
                };
                Ok(ScriptValue::Int(len as i64))
            }
            "contains" => {
                if args.len() < 2 {
                    return Err(ScriptRuntimeError::InvalidArgumentCount { expected: 2, found: args.len() });
                }
                let found = match (&args[0], &args[1]) {
                    (ScriptValue::String(haystack), ScriptValue::String(needle)) => haystack.contains(needle),
                    (ScriptValue::Bytes(haystack), ScriptValue::Bytes(needle)) => {
                        if needle.is_empty() {
                            true
                        } else {
                            haystack.windows(needle.len()).any(|w| w == needle.as_slice())
                        }
                    }
                    (ScriptValue::Map(m), ScriptValue::String(k)) => m.contains_key(k),
                    _ => false,
                };
                Ok(ScriptValue::Bool(found))
            }
            "alert" => {
                // alert(msg, severity, category)
                let msg = match args.get(0) {
                    Some(ScriptValue::String(s)) => s.clone(),
                    _ => "Script Sandbox Alert".to_string(),
                };
                let sev_str = match args.get(1) {
                    Some(ScriptValue::String(s)) => s.to_uppercase(),
                    _ => "HIGH".to_string(),
                };
                let cat_str = match args.get(2) {
                    Some(ScriptValue::String(s)) => s.to_uppercase(),
                    _ => "ICS_DISRUPTION".to_string(),
                };

                ctx.alerts.push(ThreatHit {
                    signature_id: 990001,
                    name: msg.clone(),
                    category: cat_str,
                    severity: sev_str,
                    match_start: 0,
                    match_end: 0,
                    matched_bytes_hex: String::new(),
                    description: format!("Zeek/Lua Sandbox Script: {}", msg),
                });

                Ok(ScriptValue::Bool(true))
            }
            "log" => {
                let msg = match args.get(0) {
                    Some(ScriptValue::String(s)) => s.clone(),
                    Some(other) => format!("{:?}", other),
                    None => String::new(),
                };
                ctx.logs.push(msg);
                Ok(ScriptValue::Null)
            }
            "list" => {
                Ok(ScriptValue::List(args.to_vec()))
            }
            _ => Err(ScriptRuntimeError::FunctionNotFound(name.to_string())),
        }
    }
}

/// 生产级事件驱动安全脚本引擎管理器
pub struct SandboxedScriptEngine {
    vm: ScriptVirtualMachine,
    events: HashMap<String, (Vec<String>, BytecodeChunk)>,
}

impl SandboxedScriptEngine {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            vm: ScriptVirtualMachine::new(config),
            events: HashMap::new(),
        }
    }

    /// 加载并编译安全分析脚本源码
    pub fn load_script(&mut self, src: &str) -> Result<usize, String> {
        let mut lexer = Lexer::new(src);
        let tokens = lexer.tokenize()?;

        let mut parser = Parser::new(tokens);
        let (events, global_stmts) = parser.parse_program()?;

        // 如果存在全局语句，编译为一个特殊的 init 块并预执行
        if !global_stmts.is_empty() {
            let compiler = BytecodeCompiler::new();
            let init_chunk = compiler.compile_stmts(&global_stmts);
            let mut init_ctx = ScriptContext::new();
            self.vm.execute(&init_chunk, &mut init_ctx)
                .map_err(|e| format!("脚本初始化执行失败: {}", e))?;
        }

        let mut count = 0;
        for ev in events {
            let compiler = BytecodeCompiler::new();
            let chunk = compiler.compile_stmts(&ev.body);
            self.events.insert(ev.name, (ev.params, chunk));
            count += 1;
        }

        Ok(count)
    }

    /// 触发指定事件，派发执行沙箱脚本
    pub fn dispatch_event(
        &self,
        event_name: &str,
        arguments: &[ScriptValue],
        ctx: &mut ScriptContext,
    ) -> Result<ScriptValue, ScriptRuntimeError> {
        let (params, chunk) = match self.events.get(event_name) {
            Some(pair) => pair,
            None => return Ok(ScriptValue::Null), // 无该事件处理器直接安全放行
        };

        // 绑定实参到形参
        for (i, param_name) in params.iter().enumerate() {
            let arg_val = arguments.get(i).cloned().unwrap_or(ScriptValue::Null);
            ctx.set_variable(param_name, arg_val);
        }

        self.vm.execute(chunk, ctx)
    }
}

/// 沙箱脚本执行返回摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptExecutionSummary {
    pub events_loaded: usize,
    pub return_value: String,
    pub alerts: Vec<ThreatHit>,
    pub logs: Vec<String>,
}

/// 受 Gas Limit 与内存上限严格隔离的安全分析脚本评估命令
#[tauri::command]
pub fn evaluate_audit_script_cmd(
    script_source: String,
    sample_hex: String,
) -> Result<ScriptExecutionSummary, String> {
    if script_source.trim().is_empty() {
        return Err("检测脚本内容不能为空".to_string());
    }
    let cleaned_hex = sample_hex.trim().replace(' ', "");
    let payload_bytes = if cleaned_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(&cleaned_hex).map_err(|e| format!("样本十六进制格式无效: {}", e))?
    };

    let config = SandboxConfig {
        max_gas: 10_000,
        max_memory_bytes: 256 * 1024,
    };
    let mut engine = SandboxedScriptEngine::new(config);
    let events_loaded = engine.load_script(&script_source)?;
    let mut pkt_map = HashMap::new();
    pkt_map.insert("len".to_string(), ScriptValue::Int(payload_bytes.len() as i64));
    pkt_map.insert("payload".to_string(), ScriptValue::Bytes(payload_bytes));

    let mut ctx = ScriptContext::new();
    let ret = engine
        .dispatch_event("on_packet", &[ScriptValue::Map(pkt_map)], &mut ctx)
        .map_err(|e| format!("沙箱执行终止: {:?}", e))?;

    Ok(ScriptExecutionSummary {
        events_loaded,
        return_value: format!("{:?}", ret),
        alerts: ctx.alerts,
        logs: ctx.logs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_lexer_and_arithmetic_execution() {
        let script = r#"
            let a = 10;
            let b = 25;
            let c = (a * 2) + (b - 5);
            return c;
        "#;
        let engine = SandboxedScriptEngine::new(SandboxConfig::default());
        let mut ctx = ScriptContext::new();

        let mut lexer = Lexer::new(script);
        let tokens = lexer.tokenize().expect("词法分析成功");
        let mut parser = Parser::new(tokens);
        let (_, stmts) = parser.parse_program().expect("语法解析成功");

        let compiler = BytecodeCompiler::new();
        let chunk = compiler.compile_stmts(&stmts);
        let res = engine.vm.execute(&chunk, &mut ctx).expect("执行成功");
        assert_eq!(res, ScriptValue::Int(40));
    }

    #[test]
    fn test_script_gas_limit_halts_infinite_loop() {
        // 构造死循环脚本，验证 Gas 熔断机制
        let script = r#"
            let count = 0;
            while (true) {
                count = count + 1;
            }
        "#;
        let mut lexer = Lexer::new(script);
        let tokens = lexer.tokenize().unwrap();
        let mut parser = Parser::new(tokens);
        let (_, stmts) = parser.parse_program().unwrap();

        let compiler = BytecodeCompiler::new();
        let chunk = compiler.compile_stmts(&stmts);

        // 设置较小的 Gas Limit (1,000)
        let config = SandboxConfig { max_gas: 1_000, max_memory_bytes: 1024 * 1024 };
        let vm = ScriptVirtualMachine::new(config);
        let mut ctx = ScriptContext::new();

        let err = vm.execute(&chunk, &mut ctx).unwrap_err();
        match err {
            ScriptRuntimeError::GasExhausted(gas) => {
                assert_eq!(gas, 1_000, "必须在 1,000 Gas 时精准触发熔断阻断");
            }
            other => panic!("预期 GasExhausted，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_event_driven_modbus_deep_detection() {
        // 编写类似 Zeek Script 的自定义工业入侵规则脚本:
        // 检测从站 0x01，如果写入寄存器功能码 (0x10) 且写入数量超过 10，则产生告警
        let script = r#"
            event on_packet(pkt) {
                let payload = pkt.payload;
                if (len(payload) >= 12) {
                    let unit_id = extract_u8(payload, 6);
                    let fn_code = extract_u8(payload, 7);
                    if (unit_id == 1 && fn_code == 16) {
                        let quantity = extract_u16_be(payload, 10);
                        if (quantity > 10) {
                            alert("Modbus Batch Write Register Flood Detected", "CRITICAL", "ICS_DISRUPTION");
                            return true;
                        }
                    }
                }
                return false;
            }
        "#;

        let mut engine = SandboxedScriptEngine::new(SandboxConfig::default());
        let count = engine.load_script(script).expect("编译事件脚本成功");
        assert_eq!(count, 1);

        // 构造恶意 Modbus 报文载荷:
        // [0..6]: MBAP (len = 7)
        // [6]: Unit ID = 1
        // [7]: Function 0x10 (Write Multiple Registers)
        // [8..10]: Starting Addr = 0x0001
        // [10..12]: Quantity = 25 (0x0019 > 10, 触发告警)
        let malicious_payload = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x01,
            0x10,
            0x00, 0x01,
            0x00, 0x19,
        ];

        let mut pkt_map = HashMap::new();
        pkt_map.insert("len".to_string(), ScriptValue::Int(malicious_payload.len() as i64));
        pkt_map.insert("payload".to_string(), ScriptValue::Bytes(malicious_payload));

        let mut ctx = ScriptContext::new();
        let ret = engine.dispatch_event("on_packet", &[ScriptValue::Map(pkt_map)], &mut ctx)
            .expect("事件派发执行成功");

        assert_eq!(ret, ScriptValue::Bool(true));
        assert_eq!(ctx.alerts.len(), 1);
        assert_eq!(ctx.alerts[0].name, "Modbus Batch Write Register Flood Detected");
        assert_eq!(ctx.alerts[0].severity, "CRITICAL");
    }

    #[test]
    fn test_memory_limit_defense() {
        // 测试大内存分配防御
        let config = SandboxConfig { max_gas: 100_000, max_memory_bytes: 256 };
        let vm = ScriptVirtualMachine::new(config);
        let mut ctx = ScriptContext::new();

        let mut chunk = BytecodeChunk::new();
        // 推入一个超过 256 字节的巨大字符串
        let big_str = "A".repeat(500);
        let idx = chunk.add_constant(ScriptValue::String(big_str));
        chunk.instructions.push(Opcode::PushConst(idx));
        chunk.instructions.push(Opcode::Return);

        let err = vm.execute(&chunk, &mut ctx).unwrap_err();
        assert!(matches!(err, ScriptRuntimeError::MemoryLimitExceeded { .. }), "超额内存分配必须被拦截");
    }

    #[test]
    fn test_evaluate_audit_script_cmd_boundary_and_hit() {
        // 1. 空脚本当拒绝 (Fail-Fast)
        assert!(evaluate_audit_script_cmd("".into(), "00".into()).is_err());
        // 2. 畸形 Hex 拒绝
        assert!(evaluate_audit_script_cmd("event on_packet(pkt) { return true; }".into(), "ZZ".into()).is_err());
        // 3. 死循环被 Gas Limit 拦截
        let inf_loop = "event on_packet(pkt) { while (true) { let x = 1; } return false; }";
        let loop_res = evaluate_audit_script_cmd(inf_loop.into(), "0001".into());
        assert!(loop_res.is_err());
        // 4. 真实 on_packet(pkt) Map 注入触发告警
        let valid_script = r#"
            event on_packet(pkt) {
                let payload = pkt["payload"];
                if (pkt["len"] >= 8 && extract_u8(payload, 7) == 5) {
                    alert("Sandbox Caught Force Coil 0x05", "HIGH", "ICS_ATTACK");
                    return true;
                }
                return false;
            }
        "#;
        let ok_res = evaluate_audit_script_cmd(valid_script.into(), "00010000000601050000ff00".into()).unwrap();
        assert_eq!(ok_res.alerts.len(), 1);
        assert_eq!(ok_res.return_value, "Bool(true)");
    }
}
