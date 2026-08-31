use std::io::{self, Read, Write};

use alloy_primitives::{Address, FixedBytes, B256};
use dowse_types::{HintTable, PrefetchItem, SlotExpression};

// ─── Human-readable format ──────────────────────────────────────────────────

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const MAGENTA: &str = "\x1b[35m";
const BLUE: &str = "\x1b[34m";

/// Sort key for deterministic item ordering: Storage < Account < ComputedAccount,
/// then by formatted representation within each category.
fn item_sort_key(item: &PrefetchItem) -> (u8, String) {
    let (item, _) = item.scored();
    match item {
        PrefetchItem::Storage { slot } => (0, format_slot_expr(slot)),
        PrefetchItem::ExternalStorage { address, slot } => {
            (1, format!("{address}{}", format_slot_expr(slot)))
        }
        PrefetchItem::Account { address, selector } => {
            let sel_str = selector
                .map(|s| format!("0x{}", hex::encode(s)))
                .unwrap_or_default();
            (2, format!("{address}{sel_str}"))
        }
        PrefetchItem::ComputedAccount { address, selector } => {
            let sel_str = selector
                .map(|s| format!("0x{}", hex::encode(s)))
                .unwrap_or_default();
            (3, format!("{}{sel_str}", format_slot_expr(address)))
        }
        PrefetchItem::Scored { .. } => unreachable!("scored() removes wrappers"),
    }
}

pub fn write_human(table: &HintTable, w: &mut impl Write) -> io::Result<()> {
    let sorted_hashes = table.sorted_code_hashes();
    for code_hash in &sorted_hashes {
        let sel_map = &table.entries[code_hash];
        writeln!(
            w,
            "{DIM}0x{}{RESET} {DIM}(code hash){RESET}",
            hex::encode(code_hash)
        )?;
        let addrs = table.addresses_for_hash(code_hash);
        if !addrs.is_empty() {
            let addr_strs: Vec<String> =
                addrs.iter().map(|a| format!("{CYAN}{a}{RESET}")).collect();
            writeln!(w, "  addresses: {}", addr_strs.join(", "))?;
        }
        let mut sels: Vec<&dowse_types::Selector> = sel_map.keys().collect();
        sels.sort_by(|a, b| match (a, b) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.as_slice().cmp(b.as_slice()),
        });
        for selector in sels {
            let items = &sel_map[selector];
            let sel_str = match selector {
                Some(s) => format!("{BOLD}{YELLOW}0x{}{RESET}", hex::encode(s)),
                None => format!("{BOLD}{YELLOW}*{RESET}"),
            };
            writeln!(w, "  {sel_str}: {DIM}{} items{RESET}", items.len())?;

            let mut sorted_items: Vec<&PrefetchItem> = items.iter().collect();
            sorted_items.sort_by(|a, b| item_sort_key(a).cmp(&item_sort_key(b)));

            for item in sorted_items {
                let (item, confidence) = item.scored();
                if confidence < 1.0 {
                    write!(w, "    {DIM}[{confidence:.3}]{RESET} ")?;
                }
                match item {
                    PrefetchItem::Storage { slot } => {
                        writeln!(w, "    {GREEN}{}{RESET}", format_slot_expr(slot))?;
                    }
                    PrefetchItem::ExternalStorage { address, slot } => {
                        writeln!(
                            w,
                            "    {GREEN}external_storage{RESET}({CYAN}{address}{RESET}, {GREEN}{}{RESET})",
                            format_slot_expr(slot)
                        )?;
                    }
                    PrefetchItem::Account {
                        address,
                        selector: Some(sel),
                    } => {
                        writeln!(w, "    {BLUE}account{RESET}({CYAN}{address}{RESET}, {MAGENTA}0x{}{RESET})", hex::encode(sel))?;
                    }
                    PrefetchItem::Account {
                        address,
                        selector: None,
                    } => {
                        writeln!(w, "    {BLUE}account{RESET}({CYAN}{address}{RESET})")?;
                    }
                    PrefetchItem::ComputedAccount {
                        address,
                        selector: Some(sel),
                    } => {
                        writeln!(w, "    {MAGENTA}computed_account{RESET}({GREEN}{}{RESET}, {MAGENTA}0x{}{RESET})", format_slot_expr(address), hex::encode(sel))?;
                    }
                    PrefetchItem::ComputedAccount {
                        address,
                        selector: None,
                    } => {
                        writeln!(
                            w,
                            "    {MAGENTA}computed_account{RESET}({GREEN}{}{RESET})",
                            format_slot_expr(address)
                        )?;
                    }
                    PrefetchItem::Scored { .. } => unreachable!("scored() removes wrappers"),
                }
            }
        }
    }
    Ok(())
}

pub fn format_slot_expr(expr: &SlotExpression) -> String {
    match expr {
        SlotExpression::Concrete { value } => {
            let u: alloy_primitives::U256 = (*value).into();
            if u < alloy_primitives::U256::from(256) {
                format!("slot({u})")
            } else {
                format!("slot(0x{})", hex::encode(value))
            }
        }
        SlotExpression::CalldataWord { offset } => {
            format!("calldata({offset})")
        }
        SlotExpression::Caller => "msg.sender".to_string(),
        SlotExpression::Keccak256 { inputs } => {
            let inner: Vec<String> = inputs.iter().map(format_slot_expr).collect();
            format!("keccak256({})", inner.join(", "))
        }
        SlotExpression::Add { left, right } => {
            format!("({} + {})", format_slot_expr(left), format_slot_expr(right))
        }
        SlotExpression::SLoad { key } => {
            format!("sload({})", format_slot_expr(key))
        }
    }
}

// ─── Binary format ──────────────────────────────────────────────────────────
//
// Entry layout: [20B address][4B selector][1B item_count][item1][item2]...\n
//
// Item types:
//   0x01 = Account (no selector): [20B address]
//   0x02 = Storage: [encoded SlotExpression]
//   0x03 = ComputedAccount (no selector): [encoded SlotExpression]
//   0x04 = Account (with selector): [20B address][4B selector]
//   0x05 = ComputedAccount (with selector): [encoded SlotExpression][4B selector]
//   0x06 = ExternalStorage: [20B address][encoded SlotExpression]
//   0x07 = Scored: [8B confidence f64 big-endian][encoded PrefetchItem]
//
// SlotExpression encoding (1-byte tag + payload):
//   0x01 Concrete: [32B value]
//   0x02 CalldataWord: [2B offset big-endian]
//   0x03 Caller: (no payload)
//   0x04 Keccak256: [1B input_count] [inputs...]
//   0x05 Add: [left] [right]
//   0x06 SLoad: [key]

pub fn write_binary(table: &HintTable, w: &mut impl Write) -> io::Result<()> {
    let sorted_hashes = table.sorted_code_hashes();
    for code_hash in &sorted_hashes {
        let sel_map = &table.entries[code_hash];
        let mut sels: Vec<&dowse_types::Selector> = sel_map.keys().collect();
        sels.sort_by(|a, b| match (a, b) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.as_slice().cmp(b.as_slice()),
        });
        for selector in sels {
            let items = &sel_map[selector];
            w.write_all(code_hash.as_slice())?;

            match selector {
                Some(s) => w.write_all(s.as_slice())?,
                None => w.write_all(&[0x00, 0x00, 0x00, 0x00])?,
            }

            let count = items.len().min(255) as u8;
            w.write_all(&[count])?;

            for item in items.iter().take(count as usize) {
                write_binary_item(item, w)?;
            }

            w.write_all(b"\n")?;
        }
    }

    // Address→code_hash mapping section: sentinel + entries
    // Sentinel: 32 bytes of 0xFF
    w.write_all(&[0xFF; 32])?;
    let mut addrs: Vec<(&Address, &B256)> = table.code_hashes.iter().collect();
    addrs.sort_by_key(|(a, _)| *a);
    let mapping_count = addrs.len().min(u16::MAX as usize) as u16;
    w.write_all(&mapping_count.to_be_bytes())?;
    for (addr, hash) in addrs.iter().take(mapping_count as usize) {
        w.write_all(addr.as_slice())?;
        w.write_all(hash.as_slice())?;
    }
    w.write_all(b"\n")?;

    Ok(())
}

fn write_binary_item(item: &PrefetchItem, w: &mut impl Write) -> io::Result<()> {
    match item {
        PrefetchItem::Scored { confidence, item } => {
            w.write_all(&[0x07])?;
            w.write_all(&confidence.to_be_bytes())?;
            write_binary_item(item, w)?;
        }
        PrefetchItem::Account {
            address,
            selector: None,
        } => {
            w.write_all(&[0x01])?;
            w.write_all(address.as_slice())?;
        }
        PrefetchItem::Account {
            address,
            selector: Some(sel),
        } => {
            w.write_all(&[0x04])?;
            w.write_all(address.as_slice())?;
            w.write_all(sel.as_slice())?;
        }
        PrefetchItem::Storage { slot } => {
            w.write_all(&[0x02])?;
            write_binary_slot_expr(slot, w)?;
        }
        PrefetchItem::ExternalStorage { address, slot } => {
            w.write_all(&[0x06])?;
            w.write_all(address.as_slice())?;
            write_binary_slot_expr(slot, w)?;
        }
        PrefetchItem::ComputedAccount {
            address,
            selector: None,
        } => {
            w.write_all(&[0x03])?;
            write_binary_slot_expr(address, w)?;
        }
        PrefetchItem::ComputedAccount {
            address,
            selector: Some(sel),
        } => {
            w.write_all(&[0x05])?;
            write_binary_slot_expr(address, w)?;
            w.write_all(sel.as_slice())?;
        }
    }
    Ok(())
}

fn write_binary_slot_expr(expr: &SlotExpression, w: &mut impl Write) -> io::Result<()> {
    match expr {
        SlotExpression::Concrete { value } => {
            w.write_all(&[0x01])?;
            w.write_all(value.as_slice())?;
        }
        SlotExpression::CalldataWord { offset } => {
            w.write_all(&[0x02])?;
            w.write_all(&(*offset as u16).to_be_bytes())?;
        }
        SlotExpression::Caller => {
            w.write_all(&[0x03])?;
        }
        SlotExpression::Keccak256 { inputs } => {
            w.write_all(&[0x04])?;
            w.write_all(&[inputs.len().min(255) as u8])?;
            for input in inputs {
                write_binary_slot_expr(input, w)?;
            }
        }
        SlotExpression::Add { left, right } => {
            w.write_all(&[0x05])?;
            write_binary_slot_expr(left, w)?;
            write_binary_slot_expr(right, w)?;
        }
        SlotExpression::SLoad { key } => {
            w.write_all(&[0x06])?;
            write_binary_slot_expr(key, w)?;
        }
    }
    Ok(())
}

pub fn read_binary(r: &mut impl Read) -> io::Result<HintTable> {
    let mut table = HintTable::new();
    let mut data = Vec::new();
    r.read_to_end(&mut data)?;

    let sentinel = [0xFF; 32];

    // Split on newlines to get entries
    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }

        // Check for address→code_hash mapping sentinel
        if line.len() >= 34 && line[..32] == sentinel {
            // Parse mapping section
            let mapping_count = u16::from_be_bytes([line[32], line[33]]) as usize;
            let mut cursor = 34;
            for _ in 0..mapping_count {
                if cursor + 52 > line.len() {
                    break;
                }
                let addr = Address::from_slice(&line[cursor..cursor + 20]);
                cursor += 20;
                let hash = B256::from_slice(&line[cursor..cursor + 32]);
                cursor += 32;
                table.register_code_hash(addr, hash);
            }
            continue;
        }

        if line.len() < 37 {
            // Need at least 32 (code_hash) + 4 (selector) + 1 (count)
            continue;
        }

        let code_hash = B256::from_slice(&line[..32]);
        let sel_bytes = &line[32..36];
        let selector = if sel_bytes == [0x00, 0x00, 0x00, 0x00] {
            None
        } else {
            Some(FixedBytes::<4>::from_slice(sel_bytes))
        };
        let count = line[36] as usize;

        let mut cursor = 37;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            match read_binary_item(line, &mut cursor) {
                Ok(item) => items.push(item),
                Err(_) => break,
            }
        }

        table.insert_by_hash(code_hash, selector, items);
    }

    Ok(table)
}

fn read_binary_item(data: &[u8], cursor: &mut usize) -> io::Result<PrefetchItem> {
    if *cursor >= data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no item type"));
    }
    let tag = data[*cursor];
    *cursor += 1;

    match tag {
        0x07 => {
            if *cursor + 8 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated confidence",
                ));
            }
            let confidence = f64::from_be_bytes(data[*cursor..*cursor + 8].try_into().unwrap());
            *cursor += 8;
            Ok(read_binary_item(data, cursor)?.with_confidence(confidence))
        }
        0x01 => {
            // Account (no selector)
            if *cursor + 20 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated account address",
                ));
            }
            let address = Address::from_slice(&data[*cursor..*cursor + 20]);
            *cursor += 20;
            Ok(PrefetchItem::Account {
                address,
                selector: None,
            })
        }
        0x04 => {
            // Account with selector
            if *cursor + 24 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated account+selector",
                ));
            }
            let address = Address::from_slice(&data[*cursor..*cursor + 20]);
            *cursor += 20;
            let selector = Some(FixedBytes::<4>::from_slice(&data[*cursor..*cursor + 4]));
            *cursor += 4;
            Ok(PrefetchItem::Account { address, selector })
        }
        0x02 => {
            // Storage
            let slot = read_binary_slot_expr(data, cursor)?;
            Ok(PrefetchItem::Storage { slot })
        }
        0x03 => {
            // ComputedAccount (no selector)
            let address = read_binary_slot_expr(data, cursor)?;
            Ok(PrefetchItem::ComputedAccount {
                address,
                selector: None,
            })
        }
        0x05 => {
            // ComputedAccount (with selector)
            let address = read_binary_slot_expr(data, cursor)?;
            if *cursor + 4 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated computed_account selector",
                ));
            }
            let selector = Some(FixedBytes::<4>::from_slice(&data[*cursor..*cursor + 4]));
            *cursor += 4;
            Ok(PrefetchItem::ComputedAccount { address, selector })
        }
        0x06 => {
            if *cursor + 20 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated external storage address",
                ));
            }
            let address = Address::from_slice(&data[*cursor..*cursor + 20]);
            *cursor += 20;
            let slot = read_binary_slot_expr(data, cursor)?;
            Ok(PrefetchItem::ExternalStorage { address, slot })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown item type: 0x{tag:02x}"),
        )),
    }
}

fn read_binary_slot_expr(data: &[u8], cursor: &mut usize) -> io::Result<SlotExpression> {
    if *cursor >= data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no slot expr tag",
        ));
    }
    let tag = data[*cursor];
    *cursor += 1;

    match tag {
        0x01 => {
            // Concrete
            if *cursor + 32 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated concrete value",
                ));
            }
            let value = B256::from_slice(&data[*cursor..*cursor + 32]);
            *cursor += 32;
            Ok(SlotExpression::Concrete { value })
        }
        0x02 => {
            // CalldataWord
            if *cursor + 2 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated calldataword offset",
                ));
            }
            let offset = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]) as usize;
            *cursor += 2;
            Ok(SlotExpression::CalldataWord { offset })
        }
        0x03 => Ok(SlotExpression::Caller),
        0x04 => {
            // Keccak256
            if *cursor >= data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated keccak256 count",
                ));
            }
            let count = data[*cursor] as usize;
            *cursor += 1;
            let mut inputs = Vec::with_capacity(count);
            for _ in 0..count {
                inputs.push(read_binary_slot_expr(data, cursor)?);
            }
            Ok(SlotExpression::Keccak256 { inputs })
        }
        0x05 => {
            // Add
            let left = read_binary_slot_expr(data, cursor)?;
            let right = read_binary_slot_expr(data, cursor)?;
            Ok(SlotExpression::Add {
                left: Box::new(left),
                right: Box::new(right),
            })
        }
        0x06 => {
            // SLoad
            let key = read_binary_slot_expr(data, cursor)?;
            Ok(SlotExpression::SLoad { key: Box::new(key) })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown slot expr tag: 0x{tag:02x}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const DUMMY_HASH: B256 = B256::repeat_byte(0xAB);

    #[test]
    fn binary_roundtrip() {
        let mut table = HintTable::new();
        let addr = address!("0xdead000000000000000000000000000000000001");
        let target = address!("0x0000000000000000000000000000000000C0FFEE");

        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb])),
            vec![
                PrefetchItem::Account {
                    address: target,
                    selector: None,
                },
                PrefetchItem::Account {
                    address: target,
                    selector: Some(FixedBytes::from([0xd0, 0xe3, 0x0d, 0xb0])),
                },
                PrefetchItem::Storage {
                    slot: SlotExpression::Keccak256 {
                        inputs: vec![
                            SlotExpression::CalldataWord { offset: 4 },
                            SlotExpression::Concrete {
                                value: B256::with_last_byte(3),
                            },
                        ],
                    },
                }
                .with_confidence(0.625),
                PrefetchItem::Storage {
                    slot: SlotExpression::Caller,
                },
                PrefetchItem::Storage {
                    slot: SlotExpression::Add {
                        left: Box::new(SlotExpression::Concrete {
                            value: B256::with_last_byte(1),
                        }),
                        right: Box::new(SlotExpression::Concrete {
                            value: B256::with_last_byte(2),
                        }),
                    },
                },
                PrefetchItem::Storage {
                    slot: SlotExpression::SLoad {
                        key: Box::new(SlotExpression::Concrete {
                            value: B256::with_last_byte(7),
                        }),
                    },
                },
                PrefetchItem::ComputedAccount {
                    address: SlotExpression::Keccak256 {
                        inputs: vec![
                            SlotExpression::CalldataWord { offset: 4 },
                            SlotExpression::Concrete {
                                value: B256::with_last_byte(42),
                            },
                        ],
                    },
                    selector: None,
                },
            ],
        );

        let mut buf = Vec::new();
        write_binary(&table, &mut buf).unwrap();

        let restored = read_binary(&mut buf.as_slice()).unwrap();

        // Same selector count and item count
        assert_eq!(table.selector_count(), restored.selector_count());
        assert_eq!(table.item_count(), restored.item_count());

        // Lookup should work (binary roundtrip preserves code_hashes mapping)
        let sel = Some(FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb]));
        let items = restored.lookup(addr, sel).unwrap();
        assert_eq!(items.len(), 7);
        assert!(
            matches!(&items[0], PrefetchItem::Account { address, selector: None } if *address == target)
        );
        assert!(
            matches!(&items[1], PrefetchItem::Account { address, selector: Some(_) } if *address == target)
        );
        assert_eq!(items[2].scored().1, 0.625);
        assert!(matches!(&items[6], PrefetchItem::ComputedAccount { .. }));
    }

    #[test]
    fn human_output_format() {
        let mut table = HintTable::new();
        let addr = address!("0x4200000000000000000000000000000000000006");

        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb])),
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Keccak256 {
                    inputs: vec![
                        SlotExpression::CalldataWord { offset: 4 },
                        SlotExpression::Concrete {
                            value: B256::with_last_byte(3),
                        },
                    ],
                },
            }],
        );

        let mut buf = Vec::new();
        write_human(&table, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Now shows address in the addresses line, not as header
        assert!(output.contains("0x4200000000000000000000000000000000000006"));
        assert!(output.contains("keccak256(calldata(4), slot(3))"));
    }

    #[test]
    fn format_slot_expr_compact_calldata() {
        assert_eq!(
            format_slot_expr(&SlotExpression::CalldataWord { offset: 4 }),
            "calldata(4)"
        );
        assert_eq!(
            format_slot_expr(&SlotExpression::CalldataWord { offset: 36 }),
            "calldata(36)"
        );
    }

    #[test]
    fn binary_wildcard_selector() {
        let mut table = HintTable::new();
        let addr = address!("0xdead000000000000000000000000000000000001");

        table.insert(
            addr,
            DUMMY_HASH,
            None, // wildcard
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Concrete {
                    value: B256::with_last_byte(5),
                },
            }],
        );

        let mut buf = Vec::new();
        write_binary(&table, &mut buf).unwrap();
        let restored = read_binary(&mut buf.as_slice()).unwrap();

        assert_eq!(restored.selector_count(), 1);
        assert!(restored.lookup(addr, None).is_some());
    }

    #[test]
    fn external_storage_binary_and_human_roundtrip() {
        let addr = address!("0xdead000000000000000000000000000000000001");
        let external = address!("0xdead000000000000000000000000000000000002");
        let mut table = HintTable::new();
        table.insert(
            addr,
            DUMMY_HASH,
            None,
            vec![PrefetchItem::ExternalStorage {
                address: external,
                slot: SlotExpression::CalldataWord { offset: 4 },
            }],
        );

        let mut binary = Vec::new();
        write_binary(&table, &mut binary).unwrap();
        let restored = read_binary(&mut binary.as_slice()).unwrap();
        assert_eq!(restored.lookup(addr, None), table.lookup(addr, None));

        let mut human = Vec::new();
        write_human(&table, &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("external_storage"));
        assert!(human.contains(&external.to_string()));
    }

    #[test]
    fn binary_roundtrip_computed_account_with_selector() {
        let mut table = HintTable::new();
        let addr = address!("0xdead000000000000000000000000000000000001");
        let sel = FixedBytes::from([0x70, 0xa0, 0x82, 0x31]); // balanceOf

        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0x02, 0x2c, 0x0d, 0x9f])),
            vec![
                PrefetchItem::ComputedAccount {
                    address: SlotExpression::SLoad {
                        key: Box::new(SlotExpression::Concrete {
                            value: B256::with_last_byte(6),
                        }),
                    },
                    selector: Some(sel),
                },
                PrefetchItem::ComputedAccount {
                    address: SlotExpression::SLoad {
                        key: Box::new(SlotExpression::Concrete {
                            value: B256::with_last_byte(7),
                        }),
                    },
                    selector: None,
                },
            ],
        );

        let mut buf = Vec::new();
        write_binary(&table, &mut buf).unwrap();
        let restored = read_binary(&mut buf.as_slice()).unwrap();

        assert_eq!(table.selector_count(), restored.selector_count());
        assert_eq!(table.item_count(), restored.item_count());

        let items = restored
            .lookup(addr, Some(FixedBytes::from([0x02, 0x2c, 0x0d, 0x9f])))
            .unwrap();
        assert_eq!(items.len(), 2);
        // First item: ComputedAccount with selector (tag 0x05)
        assert!(matches!(
            &items[0],
            PrefetchItem::ComputedAccount { selector: Some(s), .. } if *s == sel
        ));
        // Second item: ComputedAccount without selector (tag 0x03)
        assert!(matches!(
            &items[1],
            PrefetchItem::ComputedAccount { selector: None, .. }
        ));
    }
}
