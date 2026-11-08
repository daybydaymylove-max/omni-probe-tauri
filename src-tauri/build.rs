fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}/lib", dir);

    #[cfg(windows)]
    {
        // 关键刮骨疗伤：启用 MSVC 延迟加载 (Delay-Load)
        // 确保在未安装 Npcap 驱动 (无 wpcap.dll) 的干净 Windows 机器上，主程序与测试二进制绝不会因为缺少 DLL 启动即崩溃
        // 进程正常启动，由 Windows 原生 Raw Socket 与多端口双轨监听无缝承接流量
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:comctl32.dll");
        println!("cargo:rustc-link-arg=delayimp.lib");

        let mut windows = tauri_build::WindowsAttributes::new();
        let manifest = r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <dependency>
        <dependentAssembly>
            <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
        </dependentAssembly>
    </dependency>
    <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
            <requestedPrivileges>
                <requestedExecutionLevel level="asInvoker" uiAccess="false" />
            </requestedPrivileges>
        </security>
    </trustInfo>
</assembly>
"#;
        windows = windows.app_manifest(manifest);
        let attrs = tauri_build::Attributes::new().windows_attributes(windows);
        tauri_build::try_build(attrs).expect("failed to run build script");
    }

    #[cfg(not(windows))]
    tauri_build::build();
}
