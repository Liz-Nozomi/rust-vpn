// vpn_core/src/gateway.rs
// 网关功能：IP转发 + NAT配置

use std::process::Command;
use anyhow::Result;

/// 启用系统IP转发
/// Linux: 修改 /proc/sys/net/ipv4/ip_forward
/// macOS: 修改 sysctl net.inet.ip.forwarding
pub fn enable_ip_forwarding() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        println!("🔧 启用 Linux IP 转发...");
        Command::new("sh")
            .arg("-c")
            .arg("echo 1 > /proc/sys/net/ipv4/ip_forward")
            .status()?;
        
        // 验证
        let output = Command::new("cat")
            .arg("/proc/sys/net/ipv4/ip_forward")
            .output()?;
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        if value == "1" {
            println!("   ✅ IP 转发已启用");
            Ok(())
        } else {
            anyhow::bail!("无法启用 IP 转发，请使用 sudo 运行")
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        println!("🔧 启用 macOS IP 转发...");
        let status = Command::new("sysctl")
            .args(&["-w", "net.inet.ip.forwarding=1"])
            .status()?;
        
        if status.success() {
            println!("   ✅ IP 转发已启用");
            Ok(())
        } else {
            anyhow::bail!("无法启用 IP 转发，请使用 sudo 运行")
        }
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err("不支持的操作系统".into())
    }
}

/// 配置 NAT（网络地址转换）
/// Linux: 使用 iptables MASQUERADE
/// macOS: 使用 pfctl（较复杂，这里先提示）
/// 
/// * `tun_device`: TUN 设备名称（如 "tun0"）
/// * `external_interface`: 外网网卡（如 "eth0", "en0", "wlan0"）
pub fn setup_nat(tun_device: &str, external_interface: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        println!("🔧 配置 NAT (iptables)...");
        println!("   VPN 接口: {}", tun_device);
        println!("   外网接口: {}", external_interface);
        
        // 1. 允许从 TUN 转发到外网接口
        let status1 = Command::new("iptables")
            .args(&["-A", "FORWARD", "-i", tun_device, "-o", external_interface, "-j", "ACCEPT"])
            .status()?;
        
        // 2. 允许外网接口的响应包返回到 TUN
        let status2 = Command::new("iptables")
            .args(&["-A", "FORWARD", "-i", external_interface, "-o", tun_device, 
                    "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            .status()?;
        
        // 3. 启用 MASQUERADE（源地址伪装）
        let status3 = Command::new("iptables")
            .args(&["-t", "nat", "-A", "POSTROUTING", "-o", external_interface, "-j", "MASQUERADE"])
            .status()?;
        
        if status1.success() && status2.success() && status3.success() {
            println!("   ✅ NAT 配置成功");
            println!("   📝 清理命令:");
            println!("      iptables -D FORWARD -i {} -o {} -j ACCEPT", tun_device, external_interface);
            println!("      iptables -D FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", external_interface, tun_device);
            println!("      iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", external_interface);
            Ok(())
        } else {
            anyhow::bail!("iptables 配置失败，请使用 sudo 运行")
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        println!("⚠️  macOS NAT 配置需要手动设置 pfctl");
        println!("   请参考: https://apple.stackexchange.com/questions/316866/");
        println!("   1. 创建 /etc/pf.anchors/vpn 文件:");
        println!("      nat on {} from 10.0.0.0/24 to any -> ({})", external_interface, external_interface);
        println!("   2. 加载规则: sudo pfctl -ef /etc/pf.anchors/vpn");
        anyhow::bail!("macOS 需要手动配置 pfctl")
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("不支持的操作系统")
    }
}

/// 清理 NAT 规则（仅 Linux）
#[allow(unused_variables)]
pub fn cleanup_nat(tun_device: &str, external_interface: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        println!("🧹 清理 NAT 规则...");
        
        // 使用 -D 删除规则（忽略错误，因为规则可能不存在）
        let _ = Command::new("iptables")
            .args(&["-D", "FORWARD", "-i", tun_device, "-o", external_interface, "-j", "ACCEPT"])
            .status();
        
        let _ = Command::new("iptables")
            .args(&["-D", "FORWARD", "-i", external_interface, "-o", tun_device, 
                    "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            .status();
        
        let _ = Command::new("iptables")
            .args(&["-t", "nat", "-D", "POSTROUTING", "-o", external_interface, "-j", "MASQUERADE"])
            .status();
        
        println!("   ✅ 清理完成");
        Ok(())
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// 自动检测默认网关接口
pub fn detect_default_interface() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(&["route", "show", "default"])
            .output()?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        // 输出格式: default via 192.168.1.1 dev eth0 proto dhcp metric 100
        for line in stdout.lines() {
            if line.contains("default") {
                if let Some(dev_pos) = line.find("dev ") {
                    let rest = &line[dev_pos + 4..];
                    if let Some(interface) = rest.split_whitespace().next() {
                        return Ok(interface.to_string());
                    }
                }
            }
        }
        anyhow::bail!("无法检测默认网卡")
    }
    
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args(&["-n", "get", "default"])
            .output()?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        // 输出格式包含: interface: en0
        for line in stdout.lines() {
            if line.trim().starts_with("interface:") {
                if let Some(interface) = line.split(':').nth(1) {
                    return Ok(interface.trim().to_string());
                }
            }
        }
        anyhow::bail!("无法检测默认网卡")
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("不支持的操作系统")
    }
}
