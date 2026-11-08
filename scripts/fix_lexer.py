# -*- coding: utf-8 -*-

filter_ast_path = "src-tauri/src/filter_ast.rs"

with open(filter_ast_path, "r", encoding="utf-8") as f:
    code = f.read()

# Replace the number and ident scanning in Lexer::next_token
old_scan = """        // 数字 (包括浮点数与十六进制)
        if ch.is_ascii_digit() {
            let start = self.chars[self.cursor].0;
            let mut has_dot = false;
            let mut is_hex = false;

            if ch == '0' && (self.peek_next() == Some('x') || self.peek_next() == Some('X')) {
                is_hex = true;
                self.advance();
                self.advance();
            }

            while let Some(c) = self.peek() {
                if is_hex && c.is_ascii_hexdigit() {
                    self.advance();
                } else if !is_hex && (c.is_ascii_digit() || (c == '.' && !has_dot)) {
                    if c == '.' {
                        // 预读防范: 如果后续是 IP 地址格式 (如 192.168.1.1)，不应被当作浮点数截断
                        let remaining = &self.input[self.chars[self.cursor].0..];
                        if remaining.split('.').count() >= 3 {
                            break;
                        }
                        has_dot = true;
                    }
                    self.advance();
                } else {
                    break;
                }
            }

            let end = if self.cursor < self.chars.len() {
                self.chars[self.cursor].0
            } else {
                self.input.len()
            };
            let raw_str = &self.input[start..end];

            if is_hex {
                let hex_digits = &raw_str[2..];
                if let Ok(val) = u64::from_str_radix(hex_digits, 16) {
                    return Ok(Token::Number(val as f64));
                }
            } else if let Ok(val) = raw_str.parse::<f64>() {
                return Ok(Token::Number(val));
            }
            // 若无法解析为常规浮点，回退为普通标识符 (如 IP 地址片段)
            return Ok(Token::Ident(raw_str.to_string()));
        }

        // 标识符或保留关键字 (如 ip.src, contains, and, or)
        if ch.is_ascii_alphabetic() || ch == '_' || ch == '.' || ch == ':' {
            let start = self.chars[self.cursor].0;
            while let Some(c) = self.peek() {
                if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '-' {
                    self.advance();
                } else {
                    break;
                }
            }
            let end = if self.cursor < self.chars.len() {
                self.chars[self.cursor].0
            } else {
                self.input.len()
            };
            let word = &self.input[start..end];

            match word.to_lowercase().as_str() {
                "and" => Ok(Token::Logic(LogicOp::And)),
                "or" => Ok(Token::Logic(LogicOp::Or)),
                "not" => Ok(Token::Not),
                "contains" => Ok(Token::Comp(CompOp::Contains)),
                _ => Ok(Token::Ident(word.to_string())),
            }
        } else {
            Err(format!("无法识别的非法字符: '{}'", ch))
        }"""

new_scan = """        // 连续字符单元扫描: 数字、IP地址、十六进制常量、字段标识符或保留关键字
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == ':' || ch == '-' {
            let start = self.chars[self.cursor].0;
            while let Some(c) = self.peek() {
                if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '-' {
                    self.advance();
                } else {
                    break;
                }
            }
            let end = if self.cursor < self.chars.len() {
                self.chars[self.cursor].0
            } else {
                self.input.len()
            };
            let word = &self.input[start..end];

            // 1. 保留字匹配
            match word.to_lowercase().as_str() {
                "and" => return Ok(Token::Logic(LogicOp::And)),
                "or" => return Ok(Token::Logic(LogicOp::Or)),
                "not" => return Ok(Token::Not),
                "contains" => return Ok(Token::Comp(CompOp::Contains)),
                _ => {}
            }

            // 2. 十六进制数字 (0x1F6)
            if (word.starts_with("0x") || word.starts_with("0X")) && word.len() > 2 {
                if let Ok(val) = u64::from_str_radix(&word[2..], 16) {
                    return Ok(Token::Number(val as f64));
                }
            }

            // 3. IPv4 / IPv6 地址判定 (必须优先于纯数字与浮点数)
            if word.contains('.') && word.chars().filter(|&c| c == '.').count() == 3 {
                if IpAddr::from_str(word).is_ok() {
                    return Ok(Token::Ident(word.to_string()));
                }
            }
            if word.contains(':') && IpAddr::from_str(word).is_ok() {
                return Ok(Token::Ident(word.to_string()));
            }

            // 4. 十进制数字或浮点数 (不含多余点号)
            if let Ok(num) = word.parse::<f64>() {
                return Ok(Token::Number(num));
            }

            // 5. 常规字段标识符 (如 ip.src, protocol)
            return Ok(Token::Ident(word.to_string()));
        }

        Err(format!("无法识别的非法字符: '{}'", ch))"""

if old_scan in code:
    code = code.replace(old_scan, new_scan, 1)
    with open(filter_ast_path, "w", encoding="utf-8") as f:
        f.write(code)
    print("Lexer unified token scanning updated successfully.")
else:
    print("Old scan pattern not found directly.")
