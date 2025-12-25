// src/handshake.rs

use anyhow::{Result, anyhow};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use serde::{Serialize, Deserialize};
use blake3::Hasher;
use pqc_kyber::*;

/// 握手消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// 客户端发起握手：携带客户端的临时公钥（X25519 + ML-KEM）
    ClientHello {
        client_pubkey: [u8; 32],        // X25519 公钥
        client_mlkem_pk: Vec<u8>,       // ML-KEM-768 公钥
        client_id: String,              // 客户端标识（可选，用于日志）
        virtual_ip: String,             // 客户端的虚拟 IP 地址
    },
    
    /// 服务端响应：携带服务端的临时公钥和封装的ML-KEM密文
    ServerHello {
        server_pubkey: [u8; 32],        // X25519 公钥
        mlkem_ciphertext: Vec<u8>,      // ML-KEM 密文（封装的共享密钥）
        signature: Vec<u8>,             // 服务端对握手消息的签名
    },
    
    /// 客户端确认：用会话密钥加密的确认消息
    ClientFinish {
        encrypted_confirm: Vec<u8>,  // 用会话密钥加密的随机数
    },
    
    /// 服务端最终确认
    ServerFinish {
        success: bool,
    },
}

/// 握手状态机 - 客户端
pub struct ClientHandshake {
    client_secret: EphemeralSecret,
    client_pubkey: PublicKey,
    mlkem_keypair: Keypair,         // ML-KEM-768 密钥对
    psk: [u8; 32],                  // 预共享密钥（用于认证）
}

/// 握手状态机 - 服务端
pub struct ServerHandshake {
    server_secret: EphemeralSecret,
    server_pubkey: PublicKey,
    psk: [u8; 32],
}

impl ClientHandshake {
    /// 创建新的客户端握手实例（混合：X25519 + ML-KEM-768）
    pub fn new(psk: &[u8; 32]) -> Self {
        // X25519 密钥对
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pubkey = PublicKey::from(&client_secret);
        
        // ML-KEM-768 密钥对
        let mut rng = OsRng;
        let mlkem_keypair = keypair(&mut rng).expect("Failed to generate ML-KEM keypair");
        
        Self {
            client_secret,
            client_pubkey,
            mlkem_keypair,
            psk: *psk,
        }
    }
    
    /// 生成 ClientHello 消息（包含X25519和ML-KEM公钥）
    pub fn create_client_hello(&self, client_id: String, virtual_ip: String) -> HandshakeMessage {
        HandshakeMessage::ClientHello {
            client_pubkey: self.client_pubkey.to_bytes(),
            client_mlkem_pk: self.mlkem_keypair.public.to_vec(),
            client_id,
            virtual_ip,
        }
    }
    
    /// 处理 ServerHello，计算会话密钥（混合：X25519 + ML-KEM，消耗self）
    pub fn process_server_hello(self, server_pubkey: [u8; 32], mlkem_ciphertext: &[u8]) -> Result<[u8; 32]> {
        let server_pk = PublicKey::from(server_pubkey);
        
        // 1. 执行 X25519 ECDH 密钥交换
        let ecdh_shared: x25519_dalek::SharedSecret = self.client_secret.diffie_hellman(&server_pk);
        
        // 2. 解封装 ML-KEM 共享密钥
        let mlkem_shared = decapsulate(mlkem_ciphertext, &self.mlkem_keypair.secret)
            .map_err(|e| anyhow!("ML-KEM decapsulation failed: {:?}", e))?;
        
        // 3. 使用 BLAKE3 派生会话密钥，组合两个共享密钥和 PSK
        // 会话密钥 = KDF(ECDH_shared || ML-KEM_shared || PSK)
        let session_key = derive_hybrid_session_key(
            ecdh_shared.as_bytes(),
            mlkem_shared.as_ref(),
            &self.psk
        );
        
        Ok(session_key)
    }
    
    /// 创建 ClientFinish 消息（用会话密钥加密确认）
    pub fn create_client_finish(&self, session_key: &[u8; 32]) -> Result<HandshakeMessage> {
        use crate::symmetric::Cipher;
        
        // 生成一个随机确认消息
        let confirm_data = b"CLIENT_FINISH_CONFIRM";
        
        let cipher = Cipher::new(session_key)?;
        let encrypted_confirm = cipher.encrypt(confirm_data)?;
        
        Ok(HandshakeMessage::ClientFinish {
            encrypted_confirm,
        })
    }
}

impl ServerHandshake {
    /// 创建新的服务端握手实例
    pub fn new(psk: &[u8; 32]) -> Self {
        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_pubkey = PublicKey::from(&server_secret);
        
        Self {
            server_secret,
            server_pubkey,
            psk: *psk,
        }
    }
    
    /// 处理 ClientHello，生成 ServerHello（使用ML-KEM封装，不包含签名）
    pub fn process_client_hello(&self, _client_pubkey: [u8; 32], client_mlkem_pk: &[u8]) -> Result<(HandshakeMessage, SharedSecret)> {
        // 使用客户端的ML-KEM公钥进行封装，生成共享密钥和密文
        let mut rng = OsRng;
        let (mlkem_ciphertext, mlkem_shared) = encapsulate(client_mlkem_pk, &mut rng)
            .map_err(|e| anyhow!("ML-KEM encapsulation failed: {:?}", e))?;
        
        // 注意：signature 应该在外部由 ServerIdentity 添加
        let server_hello = HandshakeMessage::ServerHello {
            server_pubkey: self.server_pubkey.to_bytes(),
            mlkem_ciphertext: mlkem_ciphertext.to_vec(),
            signature: vec![], // 占位符，实际使用时应由外部填充
        };
        
        Ok((server_hello, mlkem_shared))
    }
    
    /// 计算会话密钥（混合：X25519 + ML-KEM，与客户端计算相同，消耗self）
    pub fn compute_session_key(self, client_pubkey: [u8; 32], mlkem_shared: &SharedSecret) -> Result<[u8; 32]> {
        let client_pk = PublicKey::from(client_pubkey);
        
        // 1. 执行 X25519 ECDH 密钥交换
        let ecdh_shared = self.server_secret.diffie_hellman(&client_pk);
        
        // 2. 使用相同的 KDF 组合两个共享密钥和 PSK
        let session_key = derive_hybrid_session_key(
            ecdh_shared.as_bytes(),
            mlkem_shared.as_ref(),
            &self.psk
        );
        
        Ok(session_key)
    }
    
    /// 验证 ClientFinish 消息
    pub fn verify_client_finish(&self, encrypted_confirm: &[u8], session_key: &[u8; 32]) -> Result<()> {
        use crate::symmetric::Cipher;
        
        let cipher = Cipher::new(session_key)?;
        let decrypted = cipher.decrypt(encrypted_confirm)?;
        
        // 验证确认消息
        if decrypted == b"CLIENT_FINISH_CONFIRM" {
            Ok(())
        } else {
            Err(anyhow!("ClientFinish verification failed"))
        }
    }
    
    /// 创建 ServerFinish 消息
    pub fn create_server_finish(&self, success: bool) -> HandshakeMessage {
        HandshakeMessage::ServerFinish { success }
    }
}

/// 密钥派生函数（KDF）- 混合模式
/// 使用 BLAKE3 从 X25519 共享密钥、ML-KEM 共享密钥和 PSK 派生会话密钥
fn derive_hybrid_session_key(ecdh_shared: &[u8], mlkem_shared: &[u8], psk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"VPN_HYBRID_SESSION_KEY_V2"); // 域分隔符（版本2表示混合模式）
    hasher.update(ecdh_shared);                  // X25519 共享密钥
    hasher.update(mlkem_shared);                 // ML-KEM 共享密钥
    hasher.update(psk);                          // 预共享密钥
    
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash.as_bytes()[..32]);
    key
}

/// 旧版密钥派生函数（保留用于向后兼容）
#[allow(dead_code)]
fn derive_session_key(ecdh_shared: &[u8], psk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"VPN_SESSION_KEY_V1"); // 域分隔符
    hasher.update(ecdh_shared);
    hasher.update(psk);
    
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash.as_bytes()[..32]);
    key
}

/// 序列化握手消息（用于网络传输）
pub fn serialize_message(msg: &HandshakeMessage) -> Result<Vec<u8>> {
    bincode::serialize(msg)
        .map_err(|e| anyhow!("Failed to serialize message: {}", e))
}

/// 反序列化握手消息
pub fn deserialize_message(data: &[u8]) -> Result<HandshakeMessage> {
    bincode::deserialize(data)
        .map_err(|e| anyhow!("Failed to deserialize message: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_full_flow() {
        // 模拟完整的握手流程（混合模式：X25519 + ML-KEM）
        let psk = b"test_preshared_key_32bytes!!"; // 28字节
        assert_eq!(psk.len(), 28); // 验证长度
        
        // 转换为32字节数组
        let mut psk_32 = [0u8; 32];
        psk_32[..28].copy_from_slice(psk);
        
        // 1. 客户端和服务端初始化
        let client = ClientHandshake::new(&psk_32);
        let server = ServerHandshake::new(&psk_32);
        
        // 2. ClientHello（包含X25519和ML-KEM公钥）
        let client_hello = client.create_client_hello("test_client".to_string(), "10.0.0.2".to_string());
        let (client_pubkey, client_mlkem_pk) = match &client_hello {
            HandshakeMessage::ClientHello { client_pubkey, client_mlkem_pk, .. } => (*client_pubkey, client_mlkem_pk.clone()),
            _ => panic!("Wrong message type"),
        };
        
        // 3. ServerHello（使用ML-KEM封装）
        let (server_hello, mlkem_shared) = server.process_client_hello(client_pubkey, &client_mlkem_pk).unwrap();
        let (server_pubkey, mlkem_ciphertext) = match &server_hello {
            HandshakeMessage::ServerHello { server_pubkey, mlkem_ciphertext, .. } => (*server_pubkey, mlkem_ciphertext.clone()),
            _ => panic!("Wrong message type"),
        };
        
        // 4. 双方计算会话密钥（注意：这会消耗 client 和 server）
        let client_session_key = client.process_server_hello(server_pubkey, &mlkem_ciphertext).unwrap();
        let server_session_key = server.compute_session_key(client_pubkey, &mlkem_shared).unwrap();
        
        // 5. 验证双方计算出相同的会话密钥
        assert_eq!(client_session_key, server_session_key);
        
        println!("✅ 混合密钥交换测试通过！");
        println!("   - X25519 ECDH: ✓");
        println!("   - ML-KEM-768: ✓");
        println!("   - 会话密钥一致: ✓");
    }
    
    #[test]
    fn test_serialization() {
        let msg = HandshakeMessage::ClientHello {
            client_pubkey: [1u8; 32],
            client_mlkem_pk: vec![2u8; 1184], // ML-KEM-768 公钥大小
            client_id: "test".to_string(),
            virtual_ip: "10.0.0.2".to_string(),
        };
        
        let serialized = serialize_message(&msg).unwrap();
        let deserialized = deserialize_message(&serialized).unwrap();
        
        match deserialized {
            HandshakeMessage::ClientHello { client_pubkey, client_mlkem_pk, client_id, virtual_ip } => {
                assert_eq!(client_pubkey, [1u8; 32]);
                assert_eq!(client_mlkem_pk, vec![2u8; 1184]);
                assert_eq!(client_id, "test");
                assert_eq!(virtual_ip, "10.0.0.2");
            }
            _ => panic!("Wrong message type"),
        }
    }
}
