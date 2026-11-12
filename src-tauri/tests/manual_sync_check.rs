use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// 自动化操作手册防漂移与防裂图检验 (Living Manual Verification)
/// 1. 验证 docs/USER_MANUAL.md 与 Cargo.toml 版本号一致
/// 2. 验证覆盖 src/App.vue 全部主工作台、实际界面操作入口与快捷键
/// 3. 验证手册中引用的每一张本地截图 (./manual-images/*.png) 真实存在于磁盘且非空损毁文件
#[test]
fn test_user_manual_stays_synced_with_system_design() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().expect("Cargo manifest 应位于仓库根目录下的 src-tauri");

    let docs_dir = repo_root.join("docs");
    let manual_path = docs_dir.join("USER_MANUAL.md");
    assert!(
        manual_path.exists(),
        "缺失系统软件操作手册: {:?}",
        manual_path
    );
    let manual = fs::read_to_string(&manual_path).expect("读取 USER_MANUAL.md 失败");
    assert!(
        manual.len() > 3000,
        "USER_MANUAL.md 内容过短，不符合完整操作手册要求"
    );

    // 1. 解析 Cargo.toml 版本号，核验手册与当前版本一致
    let cargo_toml = fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("读取 Cargo.toml 失败");
    let pkg_version = cargo_toml
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("version = ") {
                Some(trimmed.trim_start_matches("version = ").trim_matches('"').to_string())
            } else {
                None
            }
        })
        .expect("Cargo.toml 中未解析到 package.version");

    assert!(
        manual.contains(&format!("v{}", pkg_version)),
        "docs/USER_MANUAL.md 未更新至当前系统版本 v{}（请同步修订手册章节）",
        pkg_version
    );

    // 2. 动态解析 src/App.vue 定义的全部主工作台 label，防止新增工作台却漏更手册
    let app_vue = fs::read_to_string(repo_root.join("src").join("App.vue")).expect("读取 src/App.vue 失败");
    let mut discovered_labels = Vec::new();
    for line in app_vue.lines() {
        let trimmed = line.trim();
        if (trimmed.contains("domainCaptureTabs") || trimmed.contains("label:")) && trimmed.contains("id:") {
            if let Some(pos) = trimmed.find("label: '") {
                let after = &trimmed[pos + "label: '".len()..];
                if let Some(end) = after.find('\'') {
                    discovered_labels.push(after[..end].to_string());
                }
            }
        }
    }
    assert!(
        discovered_labels.len() >= 10,
        "App.vue 提取的主工作台标签数量异常 ({}): {:?}",
        discovered_labels.len(),
        discovered_labels
    );

    for label in &discovered_labels {
        assert!(
            manual.contains(label),
            "docs/USER_MANUAL.md 缺少主工作台「{}」的操作说明，违反文档同步演进规范",
            label
        );
    }

    // 3. 验证手册覆盖实际可见界面核心入口、波形/无线/串口操作及快捷键
    for required_ui_item in [
        "环境检查器",
        "启动嗅探",
        "多通道传感曲线",
        "寄存器示波",
        "实时 vs 历史对照",
        "VCD 数字方波",
        "无线/蓝牙",
        "BLE+经典双模扫描",
        "Ctrl + Shift + D",
        "Ctrl + ,",
        "config.json",
    ] {
        assert!(
            manual.contains(required_ui_item),
            "docs/USER_MANUAL.md 缺少核心用户界面操作入口或快捷键说明: {}",
            required_ui_item
        );
    }

    // 4. 验证手册中所有图床链接完整落地无裂图，且与 docs/manual-images/ 一一对应无孤儿冗余图
    let mut referenced_images = HashSet::new();
    let mut cursor = 0usize;
    while let Some(rel_start) = manual[cursor..].find("(./manual-images/") {
        let abs_start = cursor + rel_start + "(./manual-images/".len();
        if let Some(end_paren) = manual[abs_start..].find(')') {
            let rel_name = manual[abs_start..abs_start + end_paren].trim().to_string();
            let img_path = docs_dir.join("manual-images").join(&rel_name);
            assert!(
                img_path.exists(),
                "操作手册引用了不存在的截图文件: {:?}",
                img_path
            );
            let meta = fs::metadata(&img_path).expect("读取截图文件元信息失败");
            assert!(
                meta.len() > 10_000,
                "操作手册引用的截图文件异常过小（可能空白或损毁）: {:?} ({} bytes)",
                img_path,
                meta.len()
            );
            referenced_images.insert(rel_name);
            cursor = abs_start + end_paren;
        } else {
            break;
        }
    }

    assert!(
        referenced_images.len() >= 15,
        "完整图文操作手册应包含不少于 15 张实机操作截图，当前仅引用了 {} 张",
        referenced_images.len()
    );

    // 检查是否存在未引用的孤儿截图文件
    let images_dir = docs_dir.join("manual-images");
    if images_dir.exists() {
        for entry in fs::read_dir(&images_dir).expect("遍历 docs/manual-images 失败") {
            let entry = entry.expect("读取目录项失败");
            let file_name = entry.file_name().to_string_lossy().to_string();
            assert!(
                referenced_images.contains(&file_name),
                "docs/manual-images/{} 未在 USER_MANUAL.md 中被引用，请补充图注或清理无用图片",
                file_name
            );
        }
    }
}
