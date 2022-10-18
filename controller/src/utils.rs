use core::fmt;

/// Creates an enum that can be converted from and to a primitive type, with invalid values becoming
/// a catch-all `Unknown` variant.
///
/// This is copied almost verbatim from [smoltcp].
///
/// [smoltcp]: https://github.com/m-labs/smoltcp/blob/cd893e6ab60f094d684b37be7bc013bf79f0459d/src/macros.rs
macro_rules! enum_with_unknown {
    (
        $( #[$enum_attr:meta] )*
        $v:vis enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )*
              $variant:ident = $value:expr
            ),* $(,)?
        }
    ) => {
        $( #[$enum_attr] )*
        $v enum $name {
            $(
              $( #[$variant_attr] )*
              $variant,
            )*
            Unknown($ty)
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                match value {
                    $( $value => $name::$variant, )*
                    other => $name::Unknown(other)
                }
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                match value {
                    $( $name::$variant => $value, )*
                    $name::Unknown(other) => other
                }
            }
        }

        impl crate::bytes::RawRepr<$ty> for $name {
            fn from_raw(raw: $ty) -> Self {
                Self::from(raw)
            }
            fn as_raw(&self) -> $ty {
                match self {
                    $( $name::$variant => $value, )*
                    $name::Unknown(other) => *other
                }
            }
        }
    }
}

/// `Debug`-formats its contents as a hexadecimal byte slice.
#[derive(Copy, Clone)]
pub struct HexSlice<T>(pub T)
where
    T: AsRef<[u8]>;

impl<T: AsRef<[u8]>> fmt::Debug for HexSlice<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, byte) in self.0.as_ref().iter().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        f.write_str("]")
    }
}

impl<T: AsRef<[u8]>> defmt::Format for HexSlice<T> {
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{=[u8]:x}", self.0.as_ref());
    }
}

impl<T: AsRef<[u8]>> AsRef<T> for HexSlice<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// `Debug`-formats its contents in hexadecimal.
#[derive(Copy, Clone)]
pub struct Hex<T>(pub T);

impl<T: fmt::LowerHex> fmt::Debug for Hex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl<T: defmt::Format> defmt::Format for Hex<T> {
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{:x}", self.0);
    }
}
