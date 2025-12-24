// vpn_core/src/asymmetric.rs
// 非对称密钥管理和签名/验证功能

use anyhow::{Result, anyhow};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::fs;

const SERVER_PRIVATE_KEY_FILE: &str = "server_private.key";
const SERVER_PUBLIC_KEY_FILE: &str = "server_public.key";

/// 服务端密钥对管理
pub struct ServerIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl ServerIdentity {
    /// 从指定目录加载或生成密钥对
    pub fn load_or_generate(keys_dir: &Path) -> Result<Self> {
        // 确保目录存在
        fs::create_dir_all(keys_dir)?;
        
        let private_path = keys_dir.join(SERVER_PRIVATE_KEY_FILE);
        let public_path = keys_dir.join(SERVER_PUBLIC_KEY_FILE);
        
        // 尝试加载已有密钥
        if private_path.exists() {
            println!("📂 从文件加载密钥对...");
            return Self::load_from_file(&private_path);
        }
        
        // 生成新密钥
        println!("🔑 生成新的密钥对...");
        let identity = Self::generate();
        
        // 保存密钥
        identity.save_to_file(keys_dir)?;
        
        println!("✅ 密钥已保存到:");
        println!("   私钥: {}", private_path.display());
        println!("   公钥: {}", public_path.display());
        
        Ok(identity)
    }
    
    /// 生成新的密钥对
    fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        
        Self {
            signing_key,
            verifying_key,
        }
    }
    
    /// 从文件加载密钥对
    fn load_from_file(private_path: &Path) -> Result<Self> {
        let private_bytes = fs::read(private_path)?;
        
        if private_bytes.len() != 32 {
            return Err(anyhow!("私钥文件格式错误：长度应为32字节，实际为{}字节", private_bytes.len()));
        }
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_bytes);
        
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        
        println!("✅ 密钥加载成功");
        
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
    
    /// 保存密钥到文件
    fn save_to_file(&self, keys_dir: &Path) -> Result<()> {
        let private_path = keys_dir.join(SERVER_PRIVATE_KEY_FILE);
        let public_path = keys_dir.join(SERVER_PUBLIC_KEY_FILE);
        
        fs::write(&private_path, self.signing_key.to_bytes())?;
        fs::write(&public_path, self.verifying_key.to_bytes())?;
        
        Ok(())
    }
    
    /// 对消息进行签名
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }
    
    /// 获取公钥字节数组
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
    
    /// 打印公钥（供客户端使用）
    pub fn print_public_key(&self) {
        println!("🔑 服务端公钥（客户端需要此公钥）:");
        println!("   {}", hex::encode(self.verifying_key.to_bytes()));
    }
}

/// 客户端验证器
pub struct ClientVerifier {
    server_public_key: VerifyingKey,
}

impl ClientVerifier {
    /// 从公钥字节创建验证器
    pub fn new(public_key_bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| anyhow!("无效的公钥: {}", e))?;
        
        Ok(Self {
            server_public_key: verifying_key,
        })
    }
    
    /// 从文件加载公钥
    pub fn load_from_file(public_key_path: &Path) -> Result<Self> {
        let public_bytes = fs::read(public_key_path)?;
        
        if public_bytes.len() != 32 {
            return Err(anyhow!("公钥文件格式错误：长度应为32字节，实际为{}字节", public_bytes.len()));
        }
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&public_bytes);
        
        Self::new(&key_bytes)
    }
    
    /// 验证签名
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        if signature_bytes.len() != 64 {
            return Err(anyhow!("签名长度错误：应为64字节，实际为{}字节", signature_bytes.len()));
        }
        
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature_bytes);
        
        let signature = Signature::from_bytes(&sig_bytes);
        
        self.server_public_key.verify(message, &signature)
            .map_err(|e| anyhow!("签名验证失败: {}", e))?;
        
        Ok(())
    }
}

/// 获取密钥存储目录（项目根目录下的 keys/）
pub fn get_keys_dir() -> Result<PathBuf> {
    // 获取当前可执行文件路径
    let exe_path = std::env::current_exe()?;
    
    // 向上查找包含 Cargo.toml 的项目根目录
    let mut dir = exe_path.parent()
        .ok_or_else(|| anyhow!("无法获取可执行文件目录"))?
        .to_path_buf();
    
    // 最多向上查找10层
    for _ in 0..10 {
        if dir.join("Cargo.toml").exists() {
            return Ok(dir.join("keys"));
        }
        
        if !dir.pop() {
            break;
        }
    }
    
    // 如果找不到项目根目录，使用当前工作目录
    let cwd = std::env::current_dir()?;
    Ok(cwd.join("keys"))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sign_and_verify() {
        let identity = ServerIdentity::generate();
        let message = b"Test message";
        
        // 签名
        let signature = identity.sign(message);
        
        // 验证
        let verifier = ClientVerifier::new(&identity.public_key_bytes()).unwrap();
        assert!(verifier.verify(message, &signature).is_ok());
        
        // 验证错误的消息
        let wrong_message = b"Wrong message";
        assert!(verifier.verify(wrong_message, &signature).is_err());
    }
}
