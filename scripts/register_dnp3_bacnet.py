with open("src-tauri/src/filter_ast.rs", "r", encoding="utf-8") as f:
    text = f.read()

target = """        FieldDefinition { name: "http.response.code".into(), protocol: "HTTP".into(), field_type: FieldType::Integer, description: "HTTP 响应状态码 (200/404/500)".into() },
    ]"""

replacement = """        FieldDefinition { name: "http.response.code".into(), protocol: "HTTP".into(), field_type: FieldType::Integer, description: "HTTP 响应状态码 (200/404/500)".into() },
        FieldDefinition { name: "dnp3.func_code".into(), protocol: "DNP3".into(), field_type: FieldType::Integer, description: "DNP3 应用层功能码 (1:读, 2:写, 5:直接操作)".into() },
        FieldDefinition { name: "dnp3.src".into(), protocol: "DNP3".into(), field_type: FieldType::Integer, description: "DNP3 数据链路层源地址".into() },
        FieldDefinition { name: "dnp3.dst".into(), protocol: "DNP3".into(), field_type: FieldType::Integer, description: "DNP3 数据链路层目的地址".into() },
        FieldDefinition { name: "bacnet.bvll_function".into(), protocol: "BACnet".into(), field_type: FieldType::Integer, description: "BACnet/IP 虚拟链路层功能码 (0x0A:单播)".into() },
        FieldDefinition { name: "bacnet.service_choice".into(), protocol: "BACnet".into(), field_type: FieldType::Integer, description: "BACnet APDU 服务选择码 (0x0C:读属性)".into() },
    ]"""

text_lf = text.replace("\r\n", "\n")
target_lf = target.replace("\r\n", "\n")
replacement_lf = replacement.replace("\r\n", "\n")

assert target_lf in text_lf
text_lf = text_lf.replace(target_lf, replacement_lf, 1)

with open("src-tauri/src/filter_ast.rs", "w", encoding="utf-8") as f:
    f.write(text_lf)

print("Updated get_standard_field_registry successfully.")
