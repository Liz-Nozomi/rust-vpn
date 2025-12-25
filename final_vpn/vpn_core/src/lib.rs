pub mod symmetric;
pub mod local_tun;
pub mod handshake;
pub mod asymmetric;
pub mod gateway;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
