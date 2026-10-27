use std::hint::black_box;
#[derive(Debug)] pub enum Shape { Circle(u64), Rect { w: u32, h: u32 }, Empty }
#[inline(never)] pub fn area(s: &Shape) -> u64 {
    match s { Shape::Circle(r) => black_box(3 * r * r),
              Shape::Rect { w, h } => black_box(*w as u64 * *h as u64),
              Shape::Empty => 0 }
}
fn main() {
    let v = black_box(Shape::Rect { w: 4, h: 5 });
    let o: Option<&u64> = black_box(None);
    println!("{} {:?}", area(&v), o.is_some());
}
