with open("src-tauri/src/filter_ast.rs", "r", encoding="utf-8") as f:
    text = f.read()

helper = """    /// 动态提取协议树/上下文字段原始 JSON 键值
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
"""

old_regex = """                    _ => {
                        if let Some(dyn_val) = self.eval_dynamic_field(field, fields) {
                            match dyn_val {
                                serde_json::Value::String(s) => s,
                                serde_json::Value::Number(n) => n.to_string(),
                                serde_json::Value::Bool(b) => b.to_string(),
                                _ => dyn_val.to_string(),
                            }
                        } else {
                            String::new()
                        }
                    }"""

new_regex = """                    _ => {
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
                    }"""

old_eval_dyn = """    fn eval_dynamic_field(
        &self,
        field: &str,
        op: CompOp,
        target_val: &FilterValue,
        fields: &HashMap<String, serde_json::Value>,
    ) -> bool {
        let resolved_value = fields.get(field)
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
            });"""

new_eval_dyn = """    fn eval_dynamic_field(
        &self,
        field: &str,
        op: CompOp,
        target_val: &FilterValue,
        fields: &HashMap<String, serde_json::Value>,
    ) -> bool {
        let resolved_value = Self::get_field_raw_value(field, fields);"""

text_lf = text.replace("\r\n", "\n")
old_regex_lf = old_regex.replace("\r\n", "\n")
new_regex_lf = new_regex.replace("\r\n", "\n")
old_eval_dyn_lf = old_eval_dyn.replace("\r\n", "\n")
new_eval_dyn_lf = new_eval_dyn.replace("\r\n", "\n")
helper_lf = helper.replace("\r\n", "\n")

assert old_regex_lf in text_lf
text_lf = text_lf.replace(old_regex_lf, new_regex_lf, 1)

assert old_eval_dyn_lf in text_lf
text_lf = text_lf.replace(old_eval_dyn_lf, helper_lf + "\n" + new_eval_dyn_lf, 1)

with open("src-tauri/src/filter_ast.rs", "w", encoding="utf-8") as f:
    f.write(text_lf)

print("Successfully refactored filter_ast with get_field_raw_value helper")
