# 🌐 VPN 网关模式使用指南

本指南说明如何让客户端 A 通过 VPN 服务器访问互联网（使用服务器 B 的网络）。

## 📋 目录

- [功能模式对比](#功能模式对比)
- [快速开始](#快速开始)
- [Linux 完整配置](#linux-完整配置)
- [macOS 配置](#macos-配置)
- [故障排除](#故障排除)

---

## 功能模式对比

### 🔗 点对点模式（默认）
```
客户端 A <--VPN--> 服务器 <--VPN--> 客户端 B
(10.0.0.2)                          (10.0.0.3)
```
- ✅ 客户端之间可以互相通信
- ❌ 无法访问互联网
- ✅ 不需要特殊权限

### 🌐 网关模式（`--gateway`）
```
客户端 A <--VPN--> 服务器 <--NAT--> 互联网
(10.0.0.2)       (10.0.0.1)         (公网)
```
- ✅ 客户端之间可以互相通信
- ✅ 客户端可以通过服务器访问互联网
- ⚠️ 需要 `sudo` 权限（配置IP转发和NAT）

---

## 快速开始

### 1️⃣ 编译项目
```bash
cd final_vpn
cargo build --release
```

### 2️⃣ 启动服务端（网关模式）

**Linux:**
```bash
sudo ./target/release/vpn_server --gateway
```

**macOS:**
```bash
sudo ./target/release/vpn_server --gateway
# macOS 需要额外手动配置 pfctl（见下文）
```

### 3️⃣ 启动客户端

**分流模式（仅VPN网段走VPN）:**
```bash
sudo ./target/release/vpn_client 10.0.0.2 <服务器IP>:9000
```

**全隧道模式（所有流量走VPN）:**
```bash
sudo ./target/release/vpn_client 10.0.0.2 <服务器IP>:9000 --full-tunnel
```

### 4️⃣ 测试连接

**Ping 互联网（验证网关功能）:**
```bash
ping 8.8.8.8
ping google.com
```

**访问网页:**
```bash
curl https://ifconfig.me  # 应显示服务器的公网IP
```

---

## Linux 完整配置

### 服务端配置

1. **启动服务端（自动配置）**
   ```bash
   sudo ./target/release/vpn_server --gateway
   ```
   
   程序会自动：
   - ✅ 创建 TUN 设备（tun0）
   - ✅ 启用 IP 转发
   - ✅ 检测外网接口（如 eth0）
   - ✅ 配置 iptables NAT 规则

2. **手动验证配置**
   ```bash
   # 检查 IP 转发
   cat /proc/sys/net/ipv4/ip_forward
   # 输出应为: 1
   
   # 检查 iptables 规则
   sudo iptables -t nat -L POSTROUTING -n -v
   # 应看到 MASQUERADE 规则
   
   sudo iptables -L FORWARD -n -v
   # 应看到两条 ACCEPT 规则
   ```

3. **清理 NAT 规则（停止服务后）**
   ```bash
   # 假设外网接口是 eth0，TUN 设备是 tun0
   sudo iptables -D FORWARD -i tun0 -o eth0 -j ACCEPT
   sudo iptables -D FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
   sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
   ```

### 客户端配置

1. **全隧道模式（所有流量走VPN）**
   ```bash
   sudo ./target/release/vpn_client 10.0.0.2 <服务器IP>:9000 --full-tunnel
   ```
   
   效果：
   - 默认路由指向 VPN
   - 所有网络流量通过服务器
   - 公网 IP 变为服务器 IP

2. **分流模式（仅VPN网段）**
   ```bash
   sudo ./target/release/vpn_client 10.0.0.2 <服务器IP>:9000
   ```
   
   效果：
   - 仅 10.0.0.0/24 走 VPN
   - 其他流量走本地网关

---

## macOS 配置

### 服务端配置（需手动配置 pfctl）

1. **启动服务端**
   ```bash
   sudo ./target/release/vpn_server --gateway
   ```
   
   程序会提示需要手动配置 pfctl。

2. **创建 pf 规则文件**
   ```bash
   # 检测外网接口（通常是 en0 或 en1）
   route -n get default | grep interface
   
   # 假设外网接口是 en0，创建规则文件
   sudo nano /etc/pf.anchors/vpn
   ```
   
   添加以下内容：
   ```pf
   # NAT 规则：将 10.0.0.0/24 伪装成 en0 的 IP
   nat on en0 from 10.0.0.0/24 to any -> (en0)
   
   # 允许转发
   pass in on utun quick
   pass out on en0 quick
   ```

3. **加载并启用规则**
   ```bash
   # 启用 IP 转发（已由程序自动完成）
   sudo sysctl -w net.inet.ip.forwarding=1
   
   # 加载 pf 规则
   sudo pfctl -ef /etc/pf.anchors/vpn
   
   # 查看规则状态
   sudo pfctl -sr
   ```

4. **清理规则（停止服务后）**
   ```bash
   sudo pfctl -d  # 禁用 pf
   sudo pfctl -F all  # 清除所有规则
   ```

### 客户端配置

与 Linux 相同，使用 `--full-tunnel` 参数启用全隧道模式。

---

## 故障排除

### ❌ 权限错误

**问题：**
```
❌ 启用IP转发失败: Permission denied
```

**解决：**
必须使用 `sudo` 运行：
```bash
sudo ./target/release/vpn_server --gateway
sudo ./target/release/vpn_client 10.0.0.2 <服务器IP>:9000
```

---

### ❌ 客户端无法访问互联网

**排查步骤：**

1. **检查服务端是否启用网关模式**
   ```bash
   # 应该看到这行输出：
   🌐 启用网关模式（NAT转发到互联网）
   ```

2. **检查 IP 转发**
   ```bash
   # Linux
   cat /proc/sys/net/ipv4/ip_forward
   
   # macOS
   sysctl net.inet.ip.forwarding
   ```

3. **检查 NAT 规则（Linux）**
   ```bash
   sudo iptables -t nat -L POSTROUTING -n
   # 应看到 MASQUERADE 规则
   ```

4. **测试连通性**
   ```bash
   # 从客户端 ping 服务端
   ping 10.0.0.1
   
   # Ping 外网 DNS
   ping 8.8.8.8
   
   # 测试 DNS 解析
   nslookup google.com 8.8.8.8
   ```

5. **检查路由表**
   ```bash
   # Linux/macOS
   route -n
   
   # 全隧道模式应看到：
   # 0.0.0.0/0 -> tun0
   ```

---

### ❌ macOS pf 规则不生效

**问题：**
NAT 规则配置后仍无法访问互联网。

**解决：**

1. **确认 pf 已启用**
   ```bash
   sudo pfctl -s info | grep Status
   # 输出应为: Status: Enabled
   ```

2. **重新加载规则**
   ```bash
   sudo pfctl -d  # 禁用
   sudo pfctl -ef /etc/pf.anchors/vpn  # 重新启用并加载
   ```

3. **检查 utun 设备名称**
   ```bash
   ifconfig | grep utun
   # 确保与 pf 规则中的设备名一致
   ```

---

### ❌ 全隧道模式导致连接中断

**问题：**
使用 `--full-tunnel` 后无法连接服务器。

**原因：**
默认路由修改后，到服务器的连接也被路由到 VPN，形成死循环。

**解决方案 A：添加服务器路由例外**
```bash
# 在启动客户端前，添加服务器路由
sudo route add <服务器IP> <本地网关>

# 示例（假设服务器是 192.168.1.100，网关是 192.168.1.1）:
sudo route add 192.168.1.100 192.168.1.1
```

**解决方案 B：使用分流模式**
不使用 `--full-tunnel`，手动添加需要的路由：
```bash
# 只让特定网段走 VPN
sudo route add 8.8.8.0/24 10.0.0.1
```

---

### ❌ DNS 解析失败

**问题：**
可以 ping 通 IP，但无法解析域名。

**解决：**

1. **手动指定 DNS 服务器**
   ```bash
   # Linux
   echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
   
   # macOS
   sudo networksetup -setdnsservers Wi-Fi 8.8.8.8 1.1.1.1
   ```

2. **测试 DNS**
   ```bash
   nslookup google.com 8.8.8.8
   dig @8.8.8.8 google.com
   ```

---

## 高级配置

### 限制客户端只能访问特定网站

**服务端 iptables：**
```bash
# 只允许访问 Google
sudo iptables -I FORWARD -i tun0 -d 142.250.0.0/16 -j ACCEPT
sudo iptables -I FORWARD -i tun0 -j DROP
```

### 查看实时流量

**服务端：**
```bash
# 安装 iftop
sudo apt install iftop  # Debian/Ubuntu
sudo yum install iftop  # CentOS/RHEL

# 监控 TUN 设备流量
sudo iftop -i tun0
```

### 持久化配置（服务器重启后自动生效）

**Linux：**
```bash
# 创建启动脚本
sudo nano /etc/systemd/system/vpn-server.service
```

```ini
[Unit]
Description=VPN Server with Gateway
After=network.target

[Service]
Type=simple
ExecStart=/path/to/vpn_server --gateway
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable vpn-server
sudo systemctl start vpn-server
```

---

## 安全建议

1. **使用防火墙限制访问**
   ```bash
   # 只允许特定IP连接VPN服务器
   sudo ufw allow from 192.168.1.0/24 to any port 9000
   ```

2. **定期更换 PSK**
   修改 `PSK` 常量并重新编译。

3. **启用日志审计**
   记录所有客户端连接和流量。

4. **限制带宽**
   使用 `tc` (Linux) 或 `pfctl` (macOS) 限速。

---

## 性能优化

### MTU 调优
```bash
# 降低 MTU 避免分片
sudo ifconfig tun0 mtu 1400
```

### 启用多线程
修改代码使用 `tokio::spawn` 处理每个客户端。

---

## 相关命令速查

| 功能 | Linux | macOS |
|------|-------|-------|
| 查看路由表 | `ip route` | `netstat -rn` |
| 查看网卡 | `ip addr` | `ifconfig` |
| 启用IP转发 | `echo 1 > /proc/sys/net/ipv4/ip_forward` | `sysctl -w net.inet.ip.forwarding=1` |
| 查看 NAT 规则 | `iptables -t nat -L` | `pfctl -sr` |
| 删除路由 | `ip route del` | `route delete` |
| 查看连接 | `ss -tunap` | `netstat -an` |

---

## 总结

- ✅ **点对点模式**：默认启动，客户端之间互联
- ✅ **网关模式**：服务端使用 `--gateway`，客户端可访问互联网
- ✅ **全隧道模式**：客户端使用 `--full-tunnel`，所有流量走VPN
- ⚠️ **权限要求**：网关功能需要 `sudo` 权限
- ⚠️ **平台差异**：Linux 自动配置，macOS 需手动设置 pfctl

现在你可以让**计算机 A 通过计算机 B 的网络访问互联网**了！🎉

---

## 🧪 测试步骤

### 测试 1：点对点模式（客户端互联）

在项目根目录下打开 3 个终端窗口：

**终端1 - 启动服务端：**
```bash
sudo ./target/release/vpn_server
```
应该看到输出：
```
🚀 VPN Server 启动中...
🔗 点对点模式（仅客户端间互联）
✅ TUN 设备创建成功: tun0  # Linux 或 utun8（macOS）
📡 正在监听 UDP: 0.0.0.0:9000
```

**终端2 - 启动客户端A：**
```bash
sudo ./target/release/vpn_client 10.0.0.2 127.0.0.1:9000
```
应该看到输出：
```
🛡️ VPN Client Starting...
📍 虚拟 IP: 10.0.0.2
🔗 分流模式：仅VPN网段流量走VPN
🤝 开始握手...
🔑 会话密钥协商成功（X25519 + ML-KEM-768）
✅ 路由配置成功
🚀 TUN 设备 utun9 就绪
```

**终端3 - 启动客户端B：**
```bash
sudo ./target/release/vpn_client 10.0.0.3 127.0.0.1:9000
```

**返回终端2 - 测试互联：**
```bash
ping 10.0.0.3
```
应该看到：
```
PING 10.0.0.3: 56 data bytes
64 bytes from 10.0.0.3: icmp_seq=0 ttl=64 time=2.5 ms
```

**✅ 成功标志**：客户端 A 和 B 可以互相 ping 通

---

### 测试 2：网关模式（Linux，访问互联网）

**终端1 - 服务端（网关模式）：**
```bash
sudo ./target/release/vpn_server --gateway
```
应该看到：
```
🚀 VPN Server 启动中...
⚠️  注意：网关模式需要 sudo 权限！
🌐 启用网关模式（NAT转发到互联网）
✅ TUN 设备创建成功: tun0

🔧 配置网关功能...
🔧 启用 Linux IP 转发...
   ✅ IP 转发已启用
   🔍 检测到外网接口: eth0
🔧 配置 NAT (iptables)...
   VPN 接口: tun0
   外网接口: eth0
   ✅ NAT 配置成功
📡 正在监听 UDP: 0.0.0.0:9000
```

**终端2 - 客户端（全隧道模式）：**
```bash
sudo ./target/release/vpn_client 10.0.0.2 127.0.0.1:9000 --full-tunnel
```
应该看到：
```
🛡️ VPN Client Starting...
🌍 全隧道模式：所有流量将通过VPN
✅ 默认路由已设置（所有流量走VPN）
```

**测试互联网连接：**

1. **Ping 外网 DNS：**
```bash
ping -c 3 8.8.8.8
```
应该能成功（延迟会稍高）

2. **查看公网 IP：**
```bash
curl ifconfig.me
```
应该显示服务端的公网 IP（如果是本地测试，可能是 127.0.0.1）

3. **测试 DNS 解析：**
```bash
curl -I https://www.google.com
```
应该返回 HTTP 200 响应头

4. **查看路由表：**
```bash
# Linux
ip route | grep default
# 应该看到 default 指向 tun0

# macOS
netstat -rn | grep default
```

**✅ 成功标志**：
- 能 ping 通 `8.8.8.8`
- `curl ifconfig.me` 返回服务端 IP
- 可以访问外网网站

---

### 测试 3：网关模式（macOS）

**⚠️ macOS 需要额外手动配置 pfctl**

**步骤1 - 启动服务端：**
```bash
sudo ./target/release/vpn_server --gateway
```
会提示需要手动配置 pfctl

**步骤2 - 检测外网接口：**
```bash
route -n get default | grep interface
```
假设输出是 `interface: en0`

**步骤3 - 创建 pf 规则文件：**
```bash
sudo nano /etc/pf.anchors/vpn
```
添加以下内容：
```pf
nat on en0 from 10.0.0.0/24 to any -> (en0)
pass in on utun quick
pass out on en0 quick
```

**步骤4 - 加载 pf 规则：**
```bash
sudo pfctl -ef /etc/pf.anchors/vpn
```

**步骤5 - 启动客户端并测试：**
与 Linux 相同，使用 `--full-tunnel` 参数，然后测试 `ping 8.8.8.8` 和 `curl ifconfig.me`

---

### 验证命令

**检查服务端 TUN 设备：**
```bash
# Linux
ip addr show tun0

# macOS
ifconfig | grep -A 5 utun
```

**检查客户端路由：**
```bash
# Linux
ip route | grep 10.0.0

# macOS
netstat -rn | grep 10.0.0
```

**检查 NAT 规则（Linux）：**
```bash
sudo iptables -t nat -L POSTROUTING -n -v
# 应该看到 MASQUERADE 规则
```

**抓包调试：**
```bash
# 服务端监听 TUN 流量
sudo tcpdump -i tun0 -n

# 客户端监听 TUN 流量
sudo tcpdump -i utun9 -n  # 替换为实际的 utun 编号
```

---

### 停止测试

1. 在所有终端按 `Ctrl+C` 停止程序
2. （可选）清理 NAT 规则（Linux）：
```bash
# 如果外网接口是 eth0
sudo iptables -D FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -D FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
```

3. （可选）清理 pfctl 规则（macOS）：
```bash
sudo pfctl -d
```

---

### 常见问题

**Q: 客户端无法连接服务端？**
- 检查防火墙是否允许 UDP 9000 端口
- 确认服务端已启动
- 尝试 `telnet <服务器IP> 9000`（虽然是 UDP，但可以检查端口是否开放）

**Q: 能 ping 通 10.0.0.x 但无法访问互联网？**
- 确认服务端使用了 `--gateway` 参数
- 确认客户端使用了 `--full-tunnel` 参数
- 检查 NAT 规则是否生效（Linux）
- 检查 pfctl 规则是否生效（macOS）

**Q: macOS 提示 "Operation not permitted"？**
- 确保使用 `sudo` 运行
- 检查系统完整性保护（SIP）设置

**Q: 网络断开？**
- 检查是否不小心让服务器也走了 VPN（路由循环）
- 尝试不使用 `--full-tunnel`，先测试分流模式

现在可以开始测试了！🎉
