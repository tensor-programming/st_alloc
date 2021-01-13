use core::mem;
use core::ptr::{self, NonNull};
use core::slice;

use super::raw::*;
use super::std::process::abort;
use super::*;
use getrandom::getrandom;

use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, LPVOID},
    },
    um::memoryapi::{VirtualLock, VirtualProtect, VirtualUnlock},
};

use super::prot;

use super::{CANARY_SIZE, GARBAGE_VALUE};

pub unsafe fn mlock(addr: *mut u8, len: usize) -> bool {
    VirtualLock(addr as LPVOID, len as usize) != 0
}

pub unsafe fn munlock(addr: *mut u8, len: usize) -> bool {
    memzero(addr, len);
    VirtualUnlock(addr as LPVOID, len as usize) != 0
}

#[inline(never)]
pub unsafe fn memeq(b1: *const u8, b2: *const u8, len: usize) -> bool {
    (0..len)
        .map(|i| ptr::read_volatile(b1.add(i)) ^ ptr::read_volatile(b2.add(i)))
        .fold(0, |sum, next| sum | next)
        .eq(&0)
}

#[inline(never)]
pub unsafe fn memcmp(b1: *const u8, b2: *const u8, len: usize) -> i32 {
    let mut res = 0;
    for i in (0..len).rev() {
        let diff =
            i32::from(ptr::read_volatile(b1.add(i))) - i32::from(ptr::read_volatile(b2.add(i)));
        res = (res & (((diff - 1) & !diff) >> 8)) | diff;
    }
    ((res - 1) >> 8) + (res >> 8) + 1
}

#[inline(never)]
pub unsafe fn memset(s: *mut u8, c: u8, n: usize) {
    let s = ptr::read_volatile(&s);
    let c = ptr::read_volatile(&c);
    let n = ptr::read_volatile(&n);

    for i in 0..n {
        ptr::write(s.add(i), c);
    }

    let _ = ptr::read_volatile(&s);
}

#[inline]
pub unsafe fn memzero(dest: *mut u8, n: usize) {
    memset(dest, 0, n);
}

#[inline]
unsafe fn alloc_init() {
    let mut si = mem::MaybeUninit::uninit();
    winapi::um::sysinfoapi::GetSystemInfo(si.as_mut_ptr());
    PAGE_SIZE = (*si.as_ptr()).dwPageSize as usize;

    if PAGE_SIZE < CANARY_SIZE || PAGE_SIZE < mem::size_of::<usize>() {
        panic!("page size too small");
    }

    PAGE_MASK = PAGE_SIZE - 1;

    getrandom(&mut CANARY).unwrap();
}

pub unsafe fn mprotect<T: ?Sized>(memptr: NonNull<T>, prot: prot::Ty) -> bool {
    let memptr = memptr.as_ptr() as *mut u8;

    let unprod_ptr = unprotected_ptr_from_ptr(memptr);
    let base_ptr = unprod_ptr.sub(PAGE_SIZE * 2);
    let unprotected_size = ptr::read(base_ptr as *const usize);
    _mprotect(unprod_ptr, unprotected_size, prot)
}

#[inline]
pub unsafe fn malloc<T>() -> Option<NonNull<T>> {
    _malloc(mem::size_of::<T>()).map(|memptr| {
        ptr::write_bytes(memptr, GARBAGE_VALUE, mem::size_of::<T>());
        NonNull::new_unchecked(memptr as *mut T)
    })
}

#[inline]
pub unsafe fn malloc_sized(size: usize) -> Option<NonNull<[u8]>> {
    _malloc(size).map(|memptr| {
        ptr::write_bytes(memptr, GARBAGE_VALUE, size);
        NonNull::new_unchecked(slice::from_raw_parts_mut(memptr, size))
    })
}

#[inline]
pub unsafe fn _mprotect(ptr: *mut u8, len: usize, prot: prot::Ty) -> bool {
    let mut old = mem::MaybeUninit::<DWORD>::uninit();

    VirtualProtect(
        ptr as LPVOID,
        len as SIZE_T,
        prot as DWORD,
        old.as_mut_ptr(),
    ) != 0
}

pub unsafe fn free<T: ?Sized>(memptr: NonNull<T>) {
    let memptr = memptr.as_ptr() as *mut u8;

    let canary_ptr = memptr.sub(CANARY_SIZE);
    let unprotected_ptr = unprotected_ptr_from_ptr(memptr);
    let base_ptr = unprotected_ptr.sub(PAGE_SIZE * 2);
    let unprotected_size = ptr::read(base_ptr as *const usize);

    if !memeq(canary_ptr as *const u8, CANARY.as_ptr(), CANARY_SIZE) {
        abort();
    }

    let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
    _mprotect(base_ptr, total_size, prot::ReadWrite);

    munlock(unprotected_ptr, unprotected_size);

    free_aligned(base_ptr, total_size);
}

unsafe fn _malloc(size: usize) -> Option<*mut u8> {
    ALLOC_INIT.call_once(|| alloc_init());

    if size >= ::core::usize::MAX - PAGE_SIZE * 4 {
        return None;
    }

    let size_with_canary = CANARY_SIZE + size;
    let unprotected_size = page_round(size_with_canary);
    let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
    let base_ptr = alloc_aligned(total_size)?.as_ptr();
    let unprotected_ptr = base_ptr.add(PAGE_SIZE * 2);

    _mprotect(base_ptr.add(PAGE_SIZE), PAGE_SIZE, prot::NoAccess);
    _mprotect(
        unprotected_ptr.add(unprotected_size),
        PAGE_SIZE,
        prot::NoAccess,
    );
    mlock(unprotected_ptr, unprotected_size);

    let canary_ptr = unprotected_ptr.add(unprotected_size - size_with_canary);
    let user_ptr = canary_ptr.add(CANARY_SIZE);
    ptr::copy_nonoverlapping(CANARY.as_ptr(), canary_ptr, CANARY_SIZE);
    ptr::write_unaligned(base_ptr as *mut usize, unprotected_size);
    _mprotect(base_ptr, PAGE_SIZE, prot::ReadOnly);

    assert_eq!(unprotected_ptr_from_ptr(user_ptr), unprotected_ptr);

    Some(user_ptr as *mut u8)
}

#[inline]
unsafe fn page_round(size: usize) -> usize {
    (size + PAGE_MASK) & !PAGE_MASK
}

#[inline]
unsafe fn unprotected_ptr_from_ptr(memptr: *const u8) -> *mut u8 {
    let canary_ptr = memptr.sub(CANARY_SIZE);
    let unprotected_ptr_u = canary_ptr as usize & !PAGE_MASK;
    if unprotected_ptr_u <= PAGE_SIZE * 2 {
        abort();
    }
    unprotected_ptr_u as *mut u8
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::std::{cmp, u64, vec::Vec};

    use quickcheck::quickcheck;

    #[test]
    fn test_malloc_u64() {
        unsafe {
            let mut ptr: NonNull<u64> = malloc().unwrap();
            *ptr.as_mut() = u64::MAX;

            assert_eq!(*ptr.as_ref(), u64::MAX);
            free(ptr);
        }
    }

    #[test]
    fn test_malloc_free() {
        unsafe {
            let ptr: Option<NonNull<u8>> = malloc();
            assert!(ptr.is_some());

            if let Some(ptr) = ptr {
                free(ptr);
            }

            let ptr: Option<NonNull<()>> = malloc();
            assert!(ptr.is_some());
            if let Some(ptr) = ptr {
                free(ptr);
            }

            let ptr: Option<NonNull<[u8]>> = malloc_sized(1024);
            assert!(ptr.is_some());
            if let Some(ptr) = ptr {
                free(ptr);
            }
        }
    }

    #[test]
    fn malloc_mprotect_test() {
        unsafe {
            let mut x: NonNull<[u8; 16]> = malloc().unwrap();

            memset(x.as_mut().as_mut_ptr(), 0x01, 16);
            assert!(mprotect(x, prot::ReadOnly));
            assert!(memeq(x.as_ref().as_ptr(), [1; 16].as_ptr(), 16));
            assert!(mprotect(x, prot::NoAccess));
            assert!(mprotect(x, prot::ReadWrite));
            memzero(x.as_mut().as_mut_ptr(), 16);
            free(x);
        }

        unsafe {
            let mut x: NonNull<[u8; 4096]> = malloc().unwrap();
            memset(x.as_mut().as_mut_ptr(), 0x02, 96);
            free(x);
        }

        unsafe {
            let mut x: NonNull<[u8; 4100]> = malloc().unwrap();
            memset(x.as_mut().as_mut_ptr().offset(100), 0x03, 3000);
            free(x);
        }

        unsafe {
            let mut x = malloc_sized(16).unwrap();

            memset(x.as_mut().as_mut_ptr(), 0x01, 16);
            assert!(mprotect(x, prot::ReadOnly));
            assert!(memeq(x.as_ref().as_ptr(), [1; 16].as_ptr(), 16));
            assert!(mprotect(x, prot::NoAccess));
            assert!(mprotect(x, prot::ReadWrite));
            memzero(x.as_mut().as_mut_ptr(), 16);
            free(x);
        }

        unsafe {
            let mut x = malloc_sized(4100).unwrap();
            memset(x.as_mut().as_mut_ptr().offset(100), 0x03, 3000);
            free(x);
        }
    }

    #[test]
    fn test_memzero() {
        unsafe {
            let mut x: [usize; 16] = [1; 16];
            memzero(x.as_mut_ptr() as *mut u8, mem::size_of_val(&x));
            assert_eq!(x, [0; 16]);
            x.clone_from_slice(&[1; 16]);
            assert_eq!(x, [1; 16]);
            memzero(
                x[1..11].as_mut_ptr() as *mut u8,
                10 * mem::size_of_val(&x[0]),
            );
            assert_eq!(x, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1]);
        }
    }

    #[test]
    fn test_mlock_munlock() {
        unsafe {
            let mut x = [1; 16];

            assert!(mlock(x.as_mut_ptr(), mem::size_of_val(&x)));
            assert!(munlock(x.as_mut_ptr(), mem::size_of_val(&x)));

            assert_eq!(x, [0; 16]);
        }
    }

    #[test]
    fn test_memeq() {
        let memeq = |x: Vec<u8>, y: Vec<u8>| -> bool {
            unsafe {
                let res = memeq(x.as_ptr(), y.as_ptr(), cmp::min(x.len(), y.len()));

                let libc_res = libc::memcmp(
                    x.as_ptr() as *const libc::c_void,
                    y.as_ptr() as *const libc::c_void,
                    cmp::min(x.len(), y.len()),
                ) == 0;

                res == libc_res
            }
        };

        quickcheck(memeq as fn(Vec<u8>, Vec<u8>) -> bool);
    }

    #[test]
    fn test_memcmp() {
        let memcmp = |x: Vec<u8>, y: Vec<u8>| -> bool {
            unsafe {
                let res = memcmp(x.as_ptr(), y.as_ptr(), cmp::min(x.len(), y.len()));
                let libc_output = libc::memcmp(
                    x.as_ptr() as *const libc::c_void,
                    y.as_ptr() as *const libc::c_void,
                    cmp::min(x.len(), y.len()),
                );
                (res > 0) == (libc_output > 0)
                    && (res < 0) == (libc_output < 0)
                    && (res == 0) == (libc_output == 0)
            }
        };
        quickcheck(memcmp as fn(Vec<u8>, Vec<u8>) -> bool);
    }
}
