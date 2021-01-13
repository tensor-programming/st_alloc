use super::std::alloc::{alloc, dealloc, Layout};
use super::PAGE_SIZE;
use core::ptr::NonNull;

#[inline]
pub unsafe fn alloc_aligned(size: usize) -> Option<NonNull<u8>> {
    let layout = Layout::from_size_align_unchecked(size, PAGE_SIZE);
    NonNull::new(alloc(layout))
}

#[inline]
pub unsafe fn free_aligned(memptr: *mut u8, size: usize) {
    let layout = Layout::from_size_align_unchecked(size, PAGE_SIZE);
    dealloc(memptr, layout);
}
