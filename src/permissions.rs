use winapi::winnt;
pub const PROT_NONE: u32 = winnt::PAGE_NOACCESS;
pub const PROT_READ: u32 = winnt::PAGE_READONLY;
pub const PROT_WRITE: u32 = winnt::PAGE_READWRITE;
pub const PROT_EXEC: u32 = winnt::PAGE_EXECUTE;
pub const PROT_READ_WRITE: u32 = winnt::PAGE_READWRITE;
pub const PROT_READ_EXEC: u32 = winnt::PAGE_EXECUTE_READ;
pub const PROT_WRITE_EXEC: u32 = winnt::PAGE_EXECUTE_READWRITE;
pub const PROT_READ_WRITE_EXEC: u32 = winnt::PAGE_EXECUTE_READWRITE;

pub type Perm = u32;

pub fn get_perms(read: bool, write: bool, exec: bool) -> Perm {
    match (read, write, exec) {
        (false, false, false) => PROT_NONE,
        (true, false, false) => PROT_READ,
        (false, true, false) => PROT_WRITE,
        (false, false, true) => PROT_EXEC,
        (true, true, false) => PROT_READ_WRITE,
        (true, false, true) => PROT_READ_EXEC,
        (false, true, true) => PROT_WRITE_EXEC,
        (true, true, true) => PROT_READ_WRITE_EXEC,
    }
}
