extern crate std;

mod alloc;
#[allow(non_snake_case, non_upper_case_globals)]
mod prot;
mod raw;

use self::std::sync::Once;

pub const GARBAGE_VALUE: u8 = 0xd0;
pub const CANARY_SIZE: usize = 16;
pub static mut PAGE_SIZE: usize = 0;
pub static mut PAGE_MASK: usize = 0;
pub static ALLOC_INIT: Once = Once::new();
pub static mut CANARY: [u8; CANARY_SIZE] = [0; CANARY_SIZE];
