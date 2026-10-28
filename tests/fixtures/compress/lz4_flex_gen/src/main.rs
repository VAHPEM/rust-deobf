// Writes lz4_flex encoder outputs for a few benign inputs, as hex lines: name kind hex
use std::io::Write;
fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    let mut text = Vec::new();
    for i in 0..300u32 {
        text.extend_from_slice(format!("cfg host=192.0.2.{} port={} name=node{}.example\n", i % 250, 8000 + i, i).as_bytes());
    }
    let mut bin = Vec::new();
    let mut x: u32 = 12345;
    for i in 0..5000u32 { x = x.wrapping_mul(1103515245).wrapping_add(12345); bin.push(((x >> 16) as u8) & if i % 3 == 0 { 0xff } else { 0x07 }); }
    let rep: Vec<u8> = bin[..400].iter().cycle().take(3000).cloned().collect();
    vec![("text", text.clone()), ("bin", bin), ("rep", rep), ("run", vec![0x41u8; 70000]),
         ("tiny", b"abcdefghijklm".to_vec()), ("short12", b"aaaaaaaaaaaa".to_vec()),
         ("big", text.iter().cycle().take(300000).cloned().collect())]
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
fn main() {
    let out = std::io::stdout();
    let mut o = out.lock();
    for (name, data) in inputs() {
        writeln!(o, "{} plain {}", name, hex(&data)).unwrap();
        writeln!(o, "{} block {}", name, hex(&lz4_flex::block::compress(&data))).unwrap();
        writeln!(o, "{} block_sized {}", name, hex(&lz4_flex::block::compress_prepend_size(&data))).unwrap();
        let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
        enc.write_all(&data).unwrap();
        writeln!(o, "{} frame {}", name, hex(&enc.finish().unwrap())).unwrap();
        let mut info = lz4_flex::frame::FrameInfo::new();
        info.content_checksum = true;
        info.block_checksums = true;
        info.content_size = Some(data.len() as u64);
        info.block_mode = lz4_flex::frame::BlockMode::Linked;
        let mut enc = lz4_flex::frame::FrameEncoder::with_frame_info(info, Vec::new());
        enc.write_all(&data).unwrap();
        writeln!(o, "{} frame_linked_sums {}", name, hex(&enc.finish().unwrap())).unwrap();
    }
}
