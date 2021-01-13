pub use winapi::shared::minwindef::DWORD as Ty;

pub const NoAccess: Ty = winapi::um::winnt::PAGE_NOACCESS;
pub const ReadOnly: Ty = winapi::um::winnt::PAGE_READONLY;
pub const ReadWrite: Ty = winapi::um::winnt::PAGE_READWRITE;
pub const WriteCopy: Ty = winapi::um::winnt::PAGE_WRITECOPY;
pub const Execute: Ty = winapi::um::winnt::PAGE_EXECUTE;
pub const ReadExec: Ty = winapi::um::winnt::PAGE_EXECUTE_READ;
pub const ReadWriteExec: Ty = winapi::um::winnt::PAGE_EXECUTE_READWRITE;
pub const WriteCopyExec: Ty = winapi::um::winnt::PAGE_EXECUTE_WRITECOPY;
pub const Guard: Ty = winapi::um::winnt::PAGE_GUARD;
pub const NoCache: Ty = winapi::um::winnt::PAGE_NOCACHE;
pub const WriteCombine: Ty = winapi::um::winnt::PAGE_WRITECOMBINE;
pub const RevertToFileMap: Ty = winapi::um::winnt::PAGE_REVERT_TO_FILE_MAP;
pub const TargetsInvalid: Ty = winapi::um::winnt::PAGE_TARGETS_INVALID;
pub const TargetsNoUpdate: Ty = winapi::um::winnt::PAGE_TARGETS_NO_UPDATE;
