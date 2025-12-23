// src/symmetric.rs

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};
use anyhow::{Result, anyhow};

// 定义密钥长度为 32 字节
pub const KEY_SIZE: usize = 32;
// ChaCha20Poly1305 的 Nonce 长度通常是 12 字节 (96 bits)
const NONCE_SIZE: usize = 12;

pub struct Cipher {
    // 内部保存加密算法的实例
    inner: ChaCha20Poly1305,
}

impl Cipher {
    /// 创建一个新的 Cipher 实例
    /// key 必须是 32 字节
    pub fn new(key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != KEY_SIZE {
            return Err(anyhow!("Key length must be {} bytes", KEY_SIZE));
        }
        
        // 初始化 ChaCha20Poly1305
        let key = chacha20poly1305::Key::from_slice(key_bytes);
        let inner = ChaCha20Poly1305::new(key);

        Ok(Self { inner })
    }

    /// 加密数据
    /// 返回格式: [Nonce (12 bytes)] + [Ciphertext (data + tag)]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // 1. 生成一个随机的 Nonce
        // 注意：对于同一个 Key，Nonce 绝对不能重复，否则密钥会被攻破。
        // 这里我们对每个包使用随机生成的 Nonce。
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // 2. 执行加密
        // encrypt 函数会返回 Vec<u8>，包含加密后的数据和 Poly1305 MAC Tag
        let ciphertext = self.inner.encrypt(&nonce, plaintext)
            .map_err(|_| anyhow!("Encryption failed"))?;

        // 3. 拼接结果：Nonce 在前，密文在后
        // 接收端需要先读取 Nonce 才能解密
        let mut packet = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    /// 解密数据
    /// 输入格式必须是: [Nonce (12 bytes)] + [Ciphertext]
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < NONCE_SIZE {
            return Err(anyhow!("Data too short"));
        }

        // 1. 提取 Nonce (前 12 字节)
        let nonce_bytes = &encrypted_data[..NONCE_SIZE];
        let nonce = Nonce::from_slice(nonce_bytes);

        // 2. 提取真正的密文部分
        let ciphertext = &encrypted_data[NONCE_SIZE..];

        // 3. 执行解密
        let plaintext = self.inner.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed (invalid key or tampered data)"))?;

        Ok(plaintext)
    }
}