//! Fuchsia-specific extensions to general I/O primitives for Zircon.
//!
//! Fuchsia supports two separate ABI layers:
//!
//! - Zircon, Fuchsia's kernel, provides syscalls as part of the VDSO loaded
//!   for all executables and works with resource handles.
//! - `fdio``, Fuchsia's non-comprehensive POSIX emulation layer, provides file
//!   descriptor emulation and runs on top of Zircon syscalls.
//!
//! Beacuse Fuchsia is considered a unix platform, the implementations of files,
//! sockets, and I/O streams are all built on fdio. However, when using
//! Fuchsia's syscalls it can be desirable to use Zircon's handles directly.
//!
//! This module provides types which can be used to convert fdio's file
//! descriptors to Fuchsia handles and work with them in accordance with Rust's
//! I/O safety.
//!
//! See the [`io` module docs][io-safety] for a general descripion of I/O
//! safety.
//!
//! [io-safety]: crate::io#io-safety

#![unstable(
    feature = "fuchsia_zircon",
    reason = "Fuchsia's zircon ABI is not yet stable",
    issue = "none"
)]

use core::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    mem::{forget, MaybeUninit},
};

use fuchsia_zircon_sys::{zx_handle_close, zx_handle_t, zx_status_t, ZX_HANDLE_INVALID, ZX_OK};

use crate::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

extern "C" {
    fn fdio_unsafe_fd_to_io(fd: RawFd) -> *mut c_void;
    fn fdio_unsafe_borrow_channel(io: *mut c_void) -> zx_handle_t;
    fn fdio_unsafe_release(io: *mut c_void);
    fn fdio_fd_transfer(fd: c_int, out: *mut zx_handle_t) -> zx_status_t;
}

fn get_fd_handle(fd: RawFd) -> zx_handle_t {
    let io = unsafe { fdio_unsafe_fd_to_io(fd) };
    if io.is_null() {
        return ZX_HANDLE_INVALID;
    }

    let handle = unsafe { fdio_unsafe_borrow_channel(io) };
    if handle == ZX_HANDLE_INVALID {
        return ZX_HANDLE_INVALID;
    }

    unsafe {
        fdio_unsafe_release(io);
    }

    handle
}

fn transfer_fd(fd: RawFd) -> zx_handle_t {
    let mut handle = MaybeUninit::uninit();
    let result = unsafe { fdio_fd_transfer(fd, handle.as_mut_ptr()) };
    if result != ZX_OK {
        return ZX_HANDLE_INVALID;
    }

    unsafe { handle.assume_init() }
}

/// A trait for borrowing the underlying Zircon handle from an object.
pub trait AsHandle {
    /// Returns a handle borrowed from this object.
    fn as_handle(&self) -> BorrowedHandle<'_>;
}

/// A trait for retrieving the raw Zircon handle underlying an object.
pub trait AsRawHandle {
    /// Returns the raw Zircon handle underlying an object.
    ///
    /// Because the returned handle does not borrow from the object, it can be
    /// easy to accidentally violate I/O safety with these raw handles. Prefer
    /// [`AsHandle`] when possible to ensure that the returned handle respects
    /// I/O safety.
    ///
    /// This function may return [`INVALID_HANDLE`] for file descriptors
    /// which do not correspond to a Zircon handle, such as when `Stdin`,
    /// `Stdout`, or `Stderr` are detached.
    fn as_raw_handle(&self) -> RawHandle;
}

/// A trait for creating an object from its underlying Zircon handle.
pub trait FromRawHandle {
    /// Returns a new instance of the implementing type from the given Zircon
    /// handle.
    ///
    /// # Safety
    ///
    /// `handle` must be an open Zircon handle.
    ///
    /// Calling this function takes ownership of the provided handle. Actions
    /// which require ownership of the handle (for example, closing the handle)
    /// must not be called after calling `from_raw_handle`.
    unsafe fn from_raw_handle(handle: RawHandle) -> Self;
}

/// A trait for consuming an object and returning its underlying Zircon handle.
pub trait IntoRawHandle {
    /// Consumes the object, returning the Zircon handle underlying it.
    ///
    /// Because the returned handle will no longer be closed by default, care
    /// should be taken to ensure that the lifecycle of the returned handle is
    /// properly managed.
    ///
    /// The returned handle is not guaranteed to be open, and may be
    /// [`INVALID_HANDLE`].
    fn into_raw_handle(self) -> RawHandle;
}

/// Zircon's raw handle type.
pub type RawHandle = zx_handle_t;

/// The handle value indicating an invalid Zircon handle.
pub const INVALID_HANDLE: RawHandle = ZX_HANDLE_INVALID;

/// An owned Zircon handle.
///
/// When `OwnedHandle` is dropped, its handle will be closed.
pub struct OwnedHandle {
    handle: RawHandle,
}

impl Drop for OwnedHandle {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            let _ = zx_handle_close(self.handle);
        }
    }
}

impl AsHandle for OwnedHandle {
    #[inline]
    fn as_handle(&self) -> BorrowedHandle<'_> {
        unsafe { BorrowedHandle::new_unchecked(self.handle) }
    }
}

impl AsRawHandle for OwnedHandle {
    #[inline]
    fn as_raw_handle(&self) -> RawHandle {
        self.handle
    }
}

impl FromRawHandle for OwnedHandle {
    #[inline]
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Self { handle }
    }
}

impl IntoRawHandle for OwnedHandle {
    #[inline]
    fn into_raw_handle(self) -> RawHandle {
        let handle = self.handle;
        forget(self);
        handle
    }
}

impl FromRawFd for OwnedHandle {
    #[inline]
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        unsafe { Self::from_raw_handle(transfer_fd(fd)) }
    }
}

/// A borrowed Zircon handle.
///
/// `BorrowedHandle` borrows a type which owns a Zircon handle, ensuring that
/// its handle will not be closed while it exists.
#[derive(Clone, Copy)]
pub struct BorrowedHandle<'a> {
    handle: RawHandle,
    _phantom: PhantomData<&'a OwnedHandle>,
}

impl BorrowedHandle<'_> {
    /// Creates a borrowed handle from a raw handle.
    ///
    /// # Safety
    ///
    /// The given handle must be open and remain open for the lifetime of the
    /// the `BorrowedHandle`, or be [`INVALID_HANDLE`].
    pub unsafe fn new_unchecked(handle: RawHandle) -> Self {
        Self { handle, _phantom: PhantomData }
    }
}

impl AsHandle for BorrowedHandle<'_> {
    #[inline]
    fn as_handle(&self) -> BorrowedHandle<'_> {
        *self
    }
}

impl AsRawHandle for BorrowedHandle<'_> {
    #[inline]
    fn as_raw_handle(&self) -> RawHandle {
        self.handle
    }
}

// Trait impls

macro_rules! impl_borrowed_handle {
    ($ty:ty) => {
        impl AsHandle for $ty {
            fn as_handle(&self) -> BorrowedHandle<'_> {
                unsafe { BorrowedHandle::new_unchecked(self.as_raw_handle()) }
            }
        }

        impl AsRawHandle for $ty {
            fn as_raw_handle(&self) -> RawHandle {
                get_fd_handle(self.as_raw_fd())
            }
        }
    };
}

macro_rules! impl_borrowed_handles {
    ($($ty:ty),* $(,)?) => {
        $(
            impl_borrowed_handle!($ty);
        )*
    }
}

use crate::{
    io::{StderrLock, StdinLock, StdoutLock},
    os::fd::BorrowedFd,
};

impl_borrowed_handles! {
    BorrowedFd<'_>,
    Stderr,
    Stdin,
    Stdout,
    StderrLock<'_>,
    StdinLock<'_>,
    StdoutLock<'_>,
}

macro_rules! impl_owned_handle {
    ($ty:ty) => {
        impl_borrowed_handle!($ty);

        impl IntoRawHandle for $ty {
            fn into_raw_handle(self) -> RawHandle {
                transfer_fd(self.as_raw_fd())
            }
        }

        impl From<$ty> for OwnedHandle {
            fn from(value: $ty) -> OwnedHandle {
                unsafe { OwnedHandle::from_raw_fd(value.into_raw_fd()) }
            }
        }
    };
}

macro_rules! impl_owned_handles {
    ($($ty:ty),* $(,)?) => {
        $(
            impl_owned_handle!($ty);
        )*
    }
}

use crate::{
    fs::File,
    io::{Stderr, Stdin, Stdout},
    net::{TcpListener, TcpStream, UdpSocket},
    os::{
        fd::OwnedFd,
        unix::net::{UnixDatagram, UnixListener, UnixStream},
    },
    process::{ChildStderr, ChildStdin, ChildStdout},
};

impl_owned_handles! {
    File,
    TcpListener,
    TcpStream,
    UdpSocket,
    ChildStderr,
    ChildStdin,
    ChildStdout,
    UnixDatagram,
    UnixListener,
    UnixStream,
    OwnedFd,
}

macro_rules! impl_reference {
    ($t:ident, $ty:ty) => {
        impl<$t: AsHandle + ?Sized> AsHandle for $ty {
            fn as_handle(&self) -> BorrowedHandle<'_> {
                <$t>::as_handle(self)
            }
        }

        impl<$t: AsRawHandle + ?Sized> AsRawHandle for $ty {
            fn as_raw_handle(&self) -> RawHandle {
                <$t>::as_raw_handle(self)
            }
        }
    };
}

macro_rules! impl_references {
    ($t:ident, $($ty:ty),* $(,)?) => {
        $(
            impl_reference!($t, $ty);
        )*
    }
}

use crate::{rc::Rc, sync::Arc};

impl_references! {
    T,
    &T,
    &mut T,
    Box<T>,
    Rc<T>,
    Arc<T>,
}

impl<T: IntoRawHandle> IntoRawHandle for Box<T> {
    fn into_raw_handle(self) -> RawHandle {
        T::into_raw_handle(*self)
    }
}

impl<T: IntoRawHandle> From<Box<T>> for OwnedHandle {
    fn from(value: Box<T>) -> OwnedHandle {
        unsafe { OwnedHandle::from_raw_handle(T::into_raw_handle(*value)) }
    }
}
