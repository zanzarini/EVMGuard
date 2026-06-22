//! Decoding of batched calls (multicall) so the analyzer can recurse into the
//! individual calls a single transaction performs.
//!
//! Drainers commonly hide a dangerous approval inside a batch so that a checker
//! that only reads the outer selector sees an unknown call. This module decodes
//! the common batch entry points into their inner `(target, calldata)` pairs.

const WORD: usize = 32;
const SELECTOR: usize = 4;
const MAX_CALLS: usize = 1024;

const MULTICALL3_AGGREGATE3: [u8; SELECTOR] = [0x82, 0xad, 0x56, 0xcb];
const MULTICALL3_AGGREGATE: [u8; SELECTOR] = [0x25, 0x2d, 0xba, 0x42];
const MULTICALL3_AGGREGATE3_VALUE: [u8; SELECTOR] = [0x17, 0x4d, 0xea, 0x71];
const MULTICALL3_TRY_AGGREGATE: [u8; SELECTOR] = [0xbc, 0xe3, 0x8b, 0xd7];
const OPENZEPPELIN_MULTICALL: [u8; SELECTOR] = [0xac, 0x96, 0x50, 0xd8];
const SAFE_MULTI_SEND: [u8; SELECTOR] = [0x8d, 0x80, 0xff, 0x0a];

/// A single call extracted from a batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerCall {
    /// The contract the inner call targets, when the batch format carries it.
    /// `None` for self-targeted formats such as OpenZeppelin `multicall`.
    pub target: Option<String>,
    /// The inner calldata, hex encoded with a `0x` prefix.
    pub calldata: String,
}

/// Returns a human-readable batch name when the calldata selector is a known
/// batch or multicall entry point.
pub fn batch_kind(payload: &str) -> Option<&'static str> {
    let selector = payload.get(..SELECTOR * 2)?;
    Some(match selector {
        "82ad56cb" => "Multicall3 aggregate3",
        "252dba42" => "Multicall3 aggregate",
        "174dea71" => "Multicall3 aggregate3Value",
        "bce38bd7" => "Multicall3 tryAggregate",
        "ac9650d8" => "multicall",
        "8d80ff0a" => "multiSend",
        _ => return None,
    })
}

/// Decodes the inner calls of a known batch. Returns `None` when the calldata is
/// not a recognized batch or its encoding is malformed.
pub fn decode(payload: &str) -> Option<Vec<InnerCall>> {
    let bytes = decode_hex(payload)?;
    let selector: [u8; SELECTOR] = bytes.get(..SELECTOR)?.try_into().ok()?;
    let arguments = bytes.get(SELECTOR..)?;

    match selector {
        MULTICALL3_AGGREGATE3 => decode_struct_array(arguments, 0, Some(0), 2),
        MULTICALL3_AGGREGATE => decode_struct_array(arguments, 0, Some(0), 1),
        MULTICALL3_AGGREGATE3_VALUE => decode_struct_array(arguments, 0, Some(0), 3),
        MULTICALL3_TRY_AGGREGATE => decode_struct_array(arguments, 1, Some(0), 1),
        OPENZEPPELIN_MULTICALL => decode_bytes_array(arguments, 0),
        SAFE_MULTI_SEND => decode_multi_send(arguments),
        _ => None,
    }
}

/// Decodes an ABI array of structs, each carrying a target address word and a
/// dynamic `bytes` calldata field, into the inner calls.
///
/// - `array_argument_word` is the head word index holding the offset to the array.
/// - `target_word` is the word index of the target address within each struct.
/// - `calldata_word` is the word index of the dynamic `bytes` offset within each struct.
fn decode_struct_array(
    arguments: &[u8],
    array_argument_word: usize,
    target_word: Option<usize>,
    calldata_word: usize,
) -> Option<Vec<InnerCall>> {
    let array_offset = word_to_usize(read_word(arguments, array_argument_word * WORD)?)?;
    let array = arguments.get(array_offset..)?;
    let count = word_to_usize(read_word(array, 0)?)?;
    if count > MAX_CALLS {
        return None;
    }
    let elements = array.get(WORD..)?;

    let mut calls = Vec::with_capacity(count);
    for index in 0..count {
        let element_offset = word_to_usize(read_word(elements, index.checked_mul(WORD)?)?)?;
        let element = elements.get(element_offset..)?;
        let target = match target_word {
            Some(word) => Some(address_from_word(read_word(element, word * WORD)?)?),
            None => None,
        };
        let calldata_offset = word_to_usize(read_word(element, calldata_word * WORD)?)?;
        let calldata = bytes_to_hex(read_dynamic_bytes(element, calldata_offset)?);
        calls.push(InnerCall { target, calldata });
    }

    Some(calls)
}

/// Decodes an ABI `bytes[]` array (OpenZeppelin `multicall`) into self-targeted
/// inner calls.
fn decode_bytes_array(arguments: &[u8], array_argument_word: usize) -> Option<Vec<InnerCall>> {
    let array_offset = word_to_usize(read_word(arguments, array_argument_word * WORD)?)?;
    let array = arguments.get(array_offset..)?;
    let count = word_to_usize(read_word(array, 0)?)?;
    if count > MAX_CALLS {
        return None;
    }
    let elements = array.get(WORD..)?;

    let mut calls = Vec::with_capacity(count);
    for index in 0..count {
        let element_offset = word_to_usize(read_word(elements, index.checked_mul(WORD)?)?)?;
        let calldata = bytes_to_hex(read_dynamic_bytes(elements, element_offset)?);
        calls.push(InnerCall {
            target: None,
            calldata,
        });
    }

    Some(calls)
}

/// Decodes the packed encoding of Gnosis Safe `multiSend(bytes)`.
///
/// Each entry is `operation(1) + to(20) + value(32) + dataLength(32) + data`.
fn decode_multi_send(arguments: &[u8]) -> Option<Vec<InnerCall>> {
    let blob_offset = word_to_usize(read_word(arguments, 0)?)?;
    let blob = read_dynamic_bytes(arguments, blob_offset)?;

    let mut calls = Vec::new();
    let mut cursor = 0usize;
    while cursor < blob.len() {
        let to_start = cursor.checked_add(1)?;
        let value_start = to_start.checked_add(20)?;
        let length_start = value_start.checked_add(WORD)?;
        let data_start = length_start.checked_add(WORD)?;
        let to = blob.get(to_start..value_start)?;
        let data_length = word_to_usize(blob.get(length_start..data_start)?)?;
        let data_end = data_start.checked_add(data_length)?;
        let data = blob.get(data_start..data_end)?;

        let mut target = String::with_capacity(2 + 40);
        target.push_str("0x");
        for byte in to {
            target.push_str(&format!("{byte:02x}"));
        }

        calls.push(InnerCall {
            target: Some(target),
            calldata: bytes_to_hex(data),
        });
        if calls.len() > MAX_CALLS {
            return None;
        }
        cursor = data_end;
    }

    Some(calls)
}

fn decode_hex(payload: &str) -> Option<Vec<u8>> {
    if payload.len() % 2 != 0 {
        return None;
    }
    let raw = payload.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        bytes.push((high * 16 + low) as u8);
    }
    Some(bytes)
}

fn read_word(data: &[u8], offset: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(WORD)?)
}

fn word_to_usize(word: &[u8]) -> Option<usize> {
    if word.len() != WORD || word[..WORD - 8].iter().any(|&byte| byte != 0) {
        return None;
    }
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(&word[WORD - 8..]);
    Some(u64::from_be_bytes(buffer) as usize)
}

fn address_from_word(word: &[u8]) -> Option<String> {
    let tail = word.get(WORD - 20..)?;
    let mut address = String::with_capacity(2 + 40);
    address.push_str("0x");
    for byte in tail {
        address.push_str(&format!("{byte:02x}"));
    }
    Some(address)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(2 + bytes.len() * 2);
    hex.push_str("0x");
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn read_dynamic_bytes(base: &[u8], offset: usize) -> Option<&[u8]> {
    let length = word_to_usize(read_word(base, offset)?)?;
    let start = offset.checked_add(WORD)?;
    base.get(start..start.checked_add(length)?)
}
