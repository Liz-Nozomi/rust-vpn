// src/tun.rs

use std::net::Ipv4Addr;
use std::process::Command; // 引入 Command
use std::str::FromStr;
use tun::{Configuration, AsyncDevice}; 
use anyhow::Result;

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
/// * `cidr`: 网段 CIDR (例如 "10.0.0.0/24" 或 "0.0.0.0/0" 表示默认路由)
pub fn configure_route(dev_name: &str, cidr: &str) -> Result<()> {
    println!("正在为设备 {} 配置路由 {} ...", dev_name, cidr);

    #[cfg(target_os = "macos")]
    {
        // macOS 对默认路由（0.0.0.0/0）需要特殊处理
        let status = if cidr == "0.0.0.0/0" {
            // 先删除旧的默认路由（忽略错误）
            println!("   🔄 删除旧的默认路由...");
            let _ = Command::new("route")
                .args(&["-n", "delete", "default"])
                .status();
            
            // 添加新的默认路由，指向 VPN 网关 10.0.0.1
            println!("   ➕ 添加新的默认路由 -> 10.0.0.1");
            Command::new("route")
                .args(&["-n", "add", "default", "10.0.0.1"])
                .status()?
        } else {
            // 普通路由，直接指向接口
            Command::new("route")
                .args(&["-n", "add", "-net", cidr, "-interface", dev_name])
                .status()?
        };
        
        if !status.success() {
            anyhow::bail!("路由配置失败 (exit code: {:?})", status.code())
        }
    }

    #[cfg(target_os = "linux")]
    {
        let status = Command::new("ip")
            .args(&["route", "add", cidr, "dev", dev_name])
            .status()?;
        
        if !status.success() {
            anyhow::bail!("路由配置失败 (exit code: {:?})", status.code())
        }
    }

    Ok(())
}