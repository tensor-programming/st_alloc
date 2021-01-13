use crate::permissions::*;
use crate::traits::Allocs;

use alloc::alloc::Layout;
use core::alloc::GlobalAlloc;
use core::ptr::NonNull;

use core::ptr;

#[cfg(all(windows, target_pointer_width = "32"))]
type WindowsSize = u32;
#[cfg(all(windows, target_pointer_width = "64"))]
type WindowsSize = u64;

#[derive(Clone)]
pub struct AllocBuilder {
    read: bool,
    write: bool,
    exec: bool,
    commit: bool,
    pagesize: usize,
    object_size: Option<usize>,
    object_align: Option<usize>,
}

#[derive(Clone)]
pub struct Allocator {
    pagesize: usize,
    read: bool,
    write: bool,
    exec: bool,
    permissions: Perm,
    commit: bool,
    object_layout: Layout,
}

impl AllocBuilder {
    pub fn build(&self) -> Allocator {
        let object_size = if let Some(object_size) = self.object_size {
            assert_eq!(
                object_size & self.pagesize,
                0,
                "object size {} is not a multiple of the page size {}",
                object_size,
                self.pagesize
            );
            object_size
        } else {
            self.pagesize
        };

        let object_align = if let Some(object_align) = self.object_align {
            assert_eq!(
                object_size % object_align,
                0,
                "object size ({}) is not a multiple of the object alignment ({})",
                object_size,
                object_align,
            );
            object_align
        } else {
            self.pagesize
        };

        Allocator {
            pagesize: self.pagesize,
            read: self.read,
            write: self.write,
            exec: self.exec,
            permissions: get_perms(self.read, self.write, self.exec),
            commit: self.commit,
            object_layout: Layout::from_size_align(object_size, object_align).unwrap(),
        }
    }

    pub fn read(mut self, read: bool) -> AllocBuilder {
        self.read = read;
        self
    }

    pub fn write(mut self, write: bool) -> AllocBuilder {
        self.write = write;
        self
    }

    pub fn exec(mut self, exec: bool) -> AllocBuilder {
        self.exec = exec;
        self
    }

    pub fn no_write(mut self) -> AllocBuilder {
        self.write = false;
        self
    }

    pub fn commit(mut self, commit: bool) -> AllocBuilder {
        self.commit = commit;
        self
    }

    pub fn object_size(mut self, object_size: usize) -> AllocBuilder {
        self.object_size = Some(object_size);
        self
    }

    pub fn object_align(mut self, object_align: usize) -> AllocBuilder {
        self.object_align = Some(object_align);
        self
    }
}

impl Default for AllocBuilder {
    fn default() -> AllocBuilder {
        AllocBuilder {
            read: true,
            write: true,
            exec: false,
            commit: false,
            pagesize: sysconf::page::pagesize(),
            object_size: None,
            object_align: None,
        }
    }
}

impl Default for Allocator {
    fn default() -> Allocator {
        AllocBuilder::default().build()
    }
}

impl Allocator {
    pub unsafe fn commit(&self, ptr: NonNull<u8>, layout: Layout) {
        debug_assert!(layout.size() > 0, "commit: size of layout must be non-zero");

        #[cfg(debug_assertions)]
        self.debug_verify_ptr(ptr.as_ptr(), &layout);

        commit(ptr.as_ptr(), layout.size(), self.permissions);
    }

    pub unsafe fn uncommit(&self, ptr: NonNull<u8>, layout: Layout) {
        debug_assert!(
            layout.size() > 0,
            "uncommit: size of layout must be non-zero"
        );

        #[cfg(debug_assertions)]
        self.debug_verify_ptr(ptr.as_ptr(), &layout);
        uncommit(ptr.as_ptr(), layout.size());
    }

    #[cfg(debug_assertions)]
    fn debug_verify_ptr(&self, ptr: *mut u8, layout: &Layout) {
        debug_assert_eq!(
            ptr as usize % self.pagesize,
            0,
            "ptr {:?} not aligned to page size {}",
            ptr,
            self.pagesize
        );
        debug_assert!(layout.align() <= self.pagesize);
    }

    unsafe fn map(size: usize, perms: u32, commit: bool) -> Option<*mut u8> {
        use kernel32::VirtualAlloc;
        use winapi::winnt::{MEM_COMMIT, MEM_RESERVE};

        let typ = MEM_RESERVE | if commit { MEM_COMMIT } else { 0 };

        let ptr = VirtualAlloc(ptr::null_mut(), size as WindowsSize, typ, perms) as *mut u8;

        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }

    unsafe fn unmap(ptr: *mut u8, _size: usize) {
        use kernel32::{GetLastError, VirtualFree};
        use winapi::winnt::MEM_RELEASE;

        let ret = VirtualFree(ptr as *mut _, 0, MEM_RELEASE);
        assert_ne!(
            ret,
            0,
            "Call to VirtualFree({:?}, 0, MEM_RELEASE) failed with error code {}.",
            ptr,
            GetLastError()
        );
    }

    unsafe fn protect(ptr: *mut u8, size: usize, perm: Perm) {
        use kernel32::{GetLastError, VirtualProtect};

        let mut _old_perm: winapi::DWORD = 0;
        #[cfg(target_pointer_width = "64")]
        type U = u64;
        #[cfg(target_pointer_width = "32")]
        type U = u32;
        let ret = VirtualProtect(ptr as *mut _, size as U, perm, &mut _old_perm as *mut _);
        assert_ne!(
            ret,
            0,
            "Call to VirtualProtect({:?}, {}, {}, {}) failed with error code {}.",
            ptr,
            size,
            perm,
            _old_perm,
            GetLastError()
        );
    }

    unsafe fn realloc(&mut self, ptr: *mut u8, layout: Layout, new_size: usize) -> Option<*mut u8> {
        use core::cmp;

        debug_assert!(
            layout.size() > 0,
            "realloc: size of layout must be non-zero"
        );
        debug_assert!(new_size > 0, "realloc: new_size must be non-zero");

        let old_size = next_multiple(layout.size(), self.pagesize);
        let new_size = next_multiple(new_size, self.pagesize);

        if old_size == new_size {
            return Some(ptr);
        }

        let new_size = next_multiple(new_size, layout.align());
        let new_layout = Layout::from_size_align(new_size, layout.align()).unwrap();

        let new_ptr = Allocator::alloc(self, new_layout);

        let fix_old_perms = !self.read;
        let fix_new_perms = !self.write;
        if fix_old_perms {
            protect(ptr, old_size, get_perms(true, self.write, self.exec));
        }
        if fix_new_perms {
            protect(new_ptr, new_size, get_perms(self.read, true, self.exec));
        }
        ptr::copy_nonoverlapping(
            ptr as *const u8,
            new_ptr as *mut u8,
            cmp::min(old_size, new_size),
        );
        Allocator::dealloc(self, ptr, layout);
        if fix_new_perms {
            protect(new_ptr, new_size, self.permissions);
        }

        Some(new_ptr)
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        debug_assert!(layout.size() > 0, "alloc: size of layout must be non-zero");

        let size = next_multiple(layout.size(), self.pagesize);

        if layout.align() <= self.pagesize {
            Allocator::map(size, self.permissions, self.commit).unwrap()
        } else {
            let extra = layout.align() - self.pagesize;

            let addr = Allocator::map(size + extra, self.permissions, false).unwrap() as usize;

            let aligned_addr = next_multiple(addr, layout.align());
            let aligned_ptr = aligned_addr as *mut u8;

            let prefix_size = aligned_addr - addr;
            let suffix_size = extra - prefix_size;

            if prefix_size > 0 {
                Allocator::unmap(addr as *mut u8, prefix_size)
            }

            if suffix_size > 0 {
                Allocator::unmap((aligned_addr + size) as *mut u8, suffix_size);
            }

            if self.commit {
                commit(aligned_ptr, layout.size(), self.permissions)
            }

            aligned_ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        debug_assert!(
            layout.size() > 0,
            "dealloc: size of layout must be non-zero"
        );

        Allocator::unmap(ptr as *mut u8, layout.size());
    }
}

fn next_multiple(size: usize, unit: usize) -> usize {
    let remainder = size % unit;
    if remainder == 0 {
        size
    } else {
        size + (unit - remainder)
    }
}

unsafe fn commit(ptr: *mut u8, size: usize, perms: u32) {
    use kernel32::VirtualAlloc;
    use winapi::winnt::MEM_COMMIT;

    let ret = VirtualAlloc(ptr as *mut _, size as WindowsSize, MEM_COMMIT, perms);
    assert_eq!(ret as *mut u8, ptr);
}

unsafe fn uncommit(ptr: *mut u8, size: usize) {
    use kernel32::{GetLastError, VirtualFree};
    use winapi::winnt::MEM_DECOMMIT;

    let ret = VirtualFree(ptr as *mut _, size as WindowsSize, MEM_DECOMMIT);
    assert_ne!(
        ret,
        0,
        "Call to VirtualFree({:?}, {}, MEM_DECOMMIT) failed with error code {}.",
        ptr,
        size,
        GetLastError()
    );
}

unsafe fn protect(ptr: *mut u8, size: usize, perm: Perm) {
    use kernel32::{GetLastError, VirtualProtect};

    let mut _old_perm: winapi::DWORD = 0;
    #[cfg(target_pointer_width = "64")]
    type U = u64;
    #[cfg(target_pointer_width = "32")]
    type U = u32;
    let ret = VirtualProtect(ptr as *mut _, size as U, perm, &mut _old_perm as *mut _);
    assert_ne!(
        ret,
        0,
        "Call to VirtualProtect({:?}, {}, {}, {}) failed with error code {}.",
        ptr,
        size,
        perm,
        _old_perm,
        GetLastError()
    );
}

mod tests {
    use super::*;

    use sysconf::page::pagesize;

    trait IntoPtrU8 {
        fn into_ptr_u8(self) -> *mut u8;
    }

    impl<T: ?Sized> IntoPtrU8 for NonNull<T> {
        fn into_ptr_u8(self) -> *mut u8 {
            self.as_ptr() as *mut u8
        }
    }

    impl<T> IntoPtrU8 for *mut T {
        fn into_ptr_u8(self) -> *mut u8 {
            self as *mut u8
        }
    }

    fn assert_block_perm<P: IntoPtrU8>(ptr: P, size: usize, perm: Perm) {
        let ptr = ptr.into_ptr_u8();
        unsafe {
            use core::mem;
            let mut meminfo: winapi::winnt::MEMORY_BASIC_INFORMATION = mem::uninitialized();
            let mbi_size = mem::size_of::<winapi::winnt::MEMORY_BASIC_INFORMATION>();
            let ret =
                kernel32::VirtualQuery(ptr as *mut _, &mut meminfo as *mut _, mbi_size as u64);
            assert_ne!(ret, 0);

            assert!(meminfo.RegionSize >= size as u64);
            assert_eq!(meminfo.Protect, perm);
        }
    }

    fn test_valid_map_address(ptr: *mut u8) {
        assert!(ptr as usize > 0, "ptr: {:?}", ptr);
        assert!(ptr as usize % pagesize() == 0, "ptr: {:?}", ptr);
    }

    unsafe fn test_zero_filled<P: IntoPtrU8>(ptr: P, size: usize) {
        let ptr = ptr.into_ptr_u8();
        for i in 0..size {
            assert_eq!(*ptr.offset(i as isize), 0);
        }
    }

    unsafe fn test_write<P: IntoPtrU8>(ptr: P, size: usize) {
        let ptr = ptr.into_ptr_u8();
        for i in 0..size {
            *ptr.offset(i as isize) = (i & 0xff) as u8;
        }
    }

    unsafe fn test_read<P: IntoPtrU8>(ptr: P, size: usize) {
        let ptr = ptr.into_ptr_u8();
        for i in 0..size {
            let got = *ptr.offset(i as isize);
            let want = (i & 0xff) as u8;
            assert_eq!(
                got, want,
                "mismatch at byte {} in block {:?}: got {}, want {}",
                i, ptr, got, want
            );
        }
    }

    unsafe fn test_write_read<P: IntoPtrU8>(ptr: P, size: usize) {
        let ptr = ptr.into_ptr_u8();
        test_write(ptr, size);
        test_read(ptr, size);
    }

    #[test]
    fn test_map() {
        unsafe {
            let mut ptr = Allocator::map(pagesize(), PROT_READ_WRITE, false).unwrap();
            test_valid_map_address(ptr);

            commit(ptr, pagesize(), PROT_READ_WRITE);
            test_zero_filled(ptr, pagesize());
            Allocator::unmap(ptr as *mut u8, 16 * pagesize());
        }
    }

    #[test]
    fn test_realloc() {
        unsafe fn test(read: bool, write: bool, exec: bool) {
            let builder = AllocBuilder::default().read(read).write(write).exec(exec);

            let builder = builder.commit(true);
            let mut alloc = builder.build();

            let permissions = get_perms(read, write, exec);
            let test_conts = |ptr: *mut u8, size: usize| {
                if read && write {
                    test_write_read(ptr, size);
                } else if read {
                    test_zero_filled(ptr, size);
                } else if write {
                    test_write(ptr, size);
                }
            };

            let small = Layout::array::<u8>(1).unwrap();
            let medium = Layout::array::<u8>(2048).unwrap();
            let large = Layout::array::<u8>(4096).unwrap();

            let ptr = Allocator::alloc(&mut alloc, medium.clone());
            test_valid_map_address(ptr);

            if read {
                test_zero_filled(ptr, large.size());
            }

            test_conts(ptr.into_ptr_u8(), large.size());

            assert_block_perm(ptr, medium.size(), permissions);
            if read && write {
                test_read(ptr, small.size());
            }
            test_conts(ptr.into_ptr_u8(), small.size());

            assert_block_perm(ptr, small.size(), permissions);

            if read && write {
                test_read(ptr, small.size());
            }

            test_conts(ptr.into_ptr_u8(), large.size());

            assert_block_perm(ptr, large.size(), permissions);

            let _ = ptr;

            let ptr = Allocator::realloc(&mut alloc, ptr, large.clone(), small.size()).unwrap();

            if read && write {
                test_read(ptr, small.size());
            }

            test_conts(ptr.into_ptr_u8(), small.size());

            assert_block_perm(ptr, small.size(), permissions);

            Allocator::dealloc(&alloc, ptr, small.clone());
        }

        unsafe {
            test(false, false, false);
            test(true, false, false);
            test(false, true, false);
            test(false, false, true);
            test(true, true, false);
            test(true, false, true);
            test(false, true, true);
            test(true, true, true);
        }
    }
}
