use alloc::alloc::Layout;
use core::ptr::NonNull;

pub unsafe trait Allocs<T> {
    unsafe fn alloc(&mut self) -> Option<NonNull<T>>;
    unsafe fn dealloc(&mut self, t: NonNull<T>);
}

pub unsafe trait UntypedAllocs {
    fn layout(&self) -> Layout;
    unsafe fn alloc(&mut self) -> Option<NonNull<u8>>;
    unsafe fn dealloc(&mut self, t: NonNull<u8>);
}

unsafe impl<T> UntypedAllocs for dyn Allocs<T> {
    fn layout(&self) -> Layout {
        Layout::new::<T>()
    }

    unsafe fn alloc(&mut self) -> Option<NonNull<u8>> {
        Allocs::alloc(self).map(|x| x.cast())
    }

    unsafe fn dealloc(&mut self, t: NonNull<u8>) {
        Allocs::dealloc(self, t.cast())
    }
}
