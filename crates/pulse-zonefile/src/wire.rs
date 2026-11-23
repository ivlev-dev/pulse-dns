//! Малоэндианные примитивы чтения/записи без паник на границах.

pub(crate) fn read_u8(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

pub(crate) fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let (_, tail) = data.split_at_checked(off)?;
    let bytes: [u8; 2] = tail.get(..2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

pub(crate) fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let (_, tail) = data.split_at_checked(off)?;
    let bytes: [u8; 4] = tail.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

pub(crate) fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    let (_, tail) = data.split_at_checked(off)?;
    let bytes: [u8; 8] = tail.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

pub(crate) fn write_u8(data: &mut [u8], off: usize, value: u8) -> bool {
    let Some((_, tail)) = data.split_at_mut_checked(off) else {
        return false;
    };
    let Some(dst) = tail.get_mut(..1) else {
        return false;
    };
    dst.copy_from_slice(&[value]);
    true
}

pub(crate) fn write_u16(data: &mut [u8], off: usize, value: u16) -> bool {
    let Some((_, tail)) = data.split_at_mut_checked(off) else {
        return false;
    };
    let Some(dst) = tail.get_mut(..2) else {
        return false;
    };
    dst.copy_from_slice(&value.to_le_bytes());
    true
}

pub(crate) fn write_u32(data: &mut [u8], off: usize, value: u32) -> bool {
    let Some((_, tail)) = data.split_at_mut_checked(off) else {
        return false;
    };
    let Some(dst) = tail.get_mut(..4) else {
        return false;
    };
    dst.copy_from_slice(&value.to_le_bytes());
    true
}

pub(crate) fn write_u64(data: &mut [u8], off: usize, value: u64) -> bool {
    let Some((_, tail)) = data.split_at_mut_checked(off) else {
        return false;
    };
    let Some(dst) = tail.get_mut(..8) else {
        return false;
    };
    dst.copy_from_slice(&value.to_le_bytes());
    true
}

pub(crate) fn write_bytes(data: &mut [u8], off: usize, value: &[u8]) -> bool {
    let Some((_, tail)) = data.split_at_mut_checked(off) else {
        return false;
    };
    let Some(dst) = tail.get_mut(..value.len()) else {
        return false;
    };
    dst.copy_from_slice(value);
    true
}
