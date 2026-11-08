with open('src-tauri/src/sniffer.rs', 'r', encoding='utf-8') as f:
    text = f.read()

test_code = r'''
    #[test]
    fn test_sniffer_baseline_and_stream_paging_pipeline_integration() {
        // 构造虚拟数据帧，验证流式缓冲池接收与有界容量统计
        let dummy = PacketRecord {
            id: 99999,
            timestamp: "22:00:00.123".to_string(),
            timestamp_ns: 123456789,
            direction: "RX".to_string(),
            transport: "TCP".to_string(),
            protocol: "MODBUS".to_string(),
            src_ip: "192.168.1.50".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            src_port: 5020,
            dst_port: 502,
            length: 128,
            payload_hex: "000100000006010300000001".to_string(),
            raw_frame_hex: "".to_string(),
            entropy: 3.2,
            entropy_level: "safe".to_string(),
            mac_src: "".to_string(),
            mac_dst: "".to_string(),
            chain_hash: "hash_99999".to_string(),
            business_data: None,
            raw_text: None,
        };

        crate::stream_paging::buffer_packet_and_auto_flush(dummy);
        
        let stats = {
            let buf = crate::stream_paging::GLOBAL_STREAM_BUFFER.lock().unwrap();
            buf.get_stats()
        };
        assert!(stats.total_captured > 0, "流式分页缓冲池必须记录累积捕获总数");
        assert!(stats.current_buffered > 0, "内存缓冲队列必须正确增加记录");
    }
'''

if 'test_sniffer_baseline_and_stream_paging_pipeline_integration' not in text:
    last_brace = text.rfind('}')
    text = text[:last_brace] + test_code + "\n}\n"
    with open('src-tauri/src/sniffer.rs', 'w', encoding='utf-8') as f:
        f.write(text)
    print("PIPELINE_TEST_ADDED")
else:
    print("ALREADY_ADDED")
