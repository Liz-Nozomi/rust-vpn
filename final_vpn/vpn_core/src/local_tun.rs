// src/tun.rs

use std::net::Ipv4Addr;
use std::process::Command; // 引入 Command
use std::str::FromStr;
use tun::{Configuration, AsyncDevice}; 

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn create_device(address: &str, netmask: &str) -> Result<AsyncDevice> {
    let ip = Ipv4Addr::from_str(address)?;
    let mask = Ipv4Addr::from_str(netmask)?;
    
    let mut config = Configuration::default();
    config
        .address(ip)
        .netmask(mask)
        .destination(ip) // 添加 destination，对于点对点接口很重要
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| { config.packet_information(false); });

    #[cfg(target_os = "macos")]
    config.platform(|_config| { 
        // macOS utun 设备默认需要 4 字节头部
    });

    let dev = tun::create_as_async(&config)?;
    Ok(dev)
}

/// 配置系统路由
/// 
/// * `dev_name`: 设备名 (例如 "utun6")
/// * `cidr`: 网段 CIDR (例如 "10.0.0.0/24")
pub fn configure_route(dev_name: &str, cidr: &str) -> Result<()> {
    println!("正在为设备 {} 配置路由 {} ...", dev_name, cidr);

    #[cfg(target_os = "macos")]
    let status = Command::new("route")
        .args(&["-n", "add", "-net", cidr, "-interface", dev_name])
        .status()?;

    #[cfg(target_os = "linux")]
    let status = Command::new("ip")
        .args(&["route", "add", cidr, "dev", dev_name])
        .status()?;

    // Windows 需要用 netsh 或 powershell，暂时省略

    if status.success() {
        Ok(())
    } else {
        // 创建一个简单的错误信息
        Err(format!("路由配置失败 (exit code: {:?})", status.code()).into())
    }
}