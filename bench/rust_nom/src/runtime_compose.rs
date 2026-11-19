// Runtime-composed parser on stable Rust nom 8 — the counterpart of
// bench/runtime_compose_bench.cpp (nanom, nm::dyn<>). The message layout is read from a spec
// string at run time and assembled from nom combinators behind Rc<dyn Fn> (nom's Parser trait
// is not object-safe, so a boxed closure is the idiomatic erased parser). Same spec grammar,
// same data, same hash; see docs/RUNTIME_COMPOSE.md.
//
// usage: runtime_compose <spec.txt> <data.bin> [reps]
use nom::{
    combinator::{map, verify},
    error::{Error, ErrorKind},
    multi::{fold, length_data},
    number::complete::{be_u16, be_u64, le_u32, u8 as nu8},
    IResult, Parser,
};
use std::rc::Rc;
use std::time::Instant;

type Dyn = Rc<dyn Fn(&[u8]) -> IResult<&[u8], u64>>;
fn mix(h: u64, x: u64) -> u64 {
    (h ^ x).wrapping_mul(1099511628211)
}

struct Spec<'a> {
    s: &'a [u8],
    pos: usize,
}
impl<'a> Spec<'a> {
    fn name(&mut self) -> &'a str {
        let b = self.pos;
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_alphanumeric() {
            self.pos += 1;
        }
        std::str::from_utf8(&self.s[b..self.pos]).unwrap()
    }
    fn eat(&mut self, c: u8) {
        assert_eq!(self.s[self.pos], c, "spec: expected {}", c as char);
        self.pos += 1;
    }
    fn more(&mut self) -> bool {
        if self.pos < self.s.len() && self.s[self.pos] == b',' {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn list(&mut self) -> Vec<Dyn> {
        let mut kids = vec![self.node()];
        while self.more() {
            kids.push(self.node());
        }
        self.eat(b')');
        kids
    }
    fn node(&mut self) -> Dyn {
        let n = self.name();
        match n {
            "u8" => return Rc::new(|i| map(nu8, u64::from).parse(i)),
            "u16be" => return Rc::new(|i| map(be_u16, u64::from).parse(i)),
            "u32le" => return Rc::new(|i| map(le_u32, u64::from).parse(i)),
            "u64be" => return Rc::new(|i| be_u64(i)),
            "str8" => {
                return Rc::new(|i| {
                    map(length_data(nu8), |b: &[u8]| {
                        let mut h = mix(0xcbf29ce484222325, b.len() as u64);
                        for &c in b {
                            h = mix(h, c as u64);
                        }
                        h
                    })
                    .parse(i)
                })
            }
            _ => {}
        }
        self.eat(b'(');
        match n {
            "lit" => {
                let v: u8 = self.name().parse().unwrap();
                self.eat(b')');
                Rc::new(move |i| map(verify(nu8, |b: &u8| *b == v), u64::from).parse(i))
            }
            "seq" => {
                let kids = self.list();
                Rc::new(move |mut i| {
                    let mut h = 0x5e9u64;
                    for k in &kids {
                        let (r, v) = k(i)?;
                        h = mix(h, v);
                        i = r;
                    }
                    Ok((i, h))
                })
            }
            "rep" => {
                let p = self.node();
                self.eat(b')');
                Rc::new(move |i| {
                    let p = p.clone();
                    nu8.flat_map(move |c: u8| {
                        let p = p.clone();
                        fold(c as usize..=c as usize, move |i| p(i), move || mix(0x52e9, c as u64), mix)
                    })
                    .parse(i)
                })
            }
            "alt" => {
                // nom 8's alt() takes a fixed-size array; a runtime-length list is a loop.
                let kids = self.list();
                Rc::new(move |i| {
                    for (n, k) in kids.iter().enumerate() {
                        match k(i) {
                            Ok((r, v)) => return Ok((r, mix(n as u64, v))),
                            Err(nom::Err::Error(_)) => continue,
                            Err(e) => return Err(e),
                        }
                    }
                    Err(nom::Err::Error(Error::new(i, ErrorKind::Alt)))
                })
            }
            "tag" => {
                let mut table: Vec<Option<Dyn>> = vec![None; 256];
                loop {
                    let t: usize = self.name().parse().unwrap();
                    self.eat(b':');
                    table[t] = Some(self.node());
                    if !self.more() {
                        break;
                    }
                }
                self.eat(b')');
                let table = Rc::new(table);
                Rc::new(move |i| {
                    let table = table.clone();
                    nu8.flat_map(move |t: u8| {
                        let table = table.clone();
                        move |i| match &table[t as usize] {
                            None => Err(nom::Err::Error(Error::new(i, ErrorKind::Switch))),
                            Some(p) => p(i).map(|(r, v)| (r, mix(t as u64, v))),
                        }
                    })
                    .parse(i)
                })
            }
            _ => panic!("spec: unknown node {n}"),
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: {} <spec.txt> <data.bin> [reps]", a[0]);
        std::process::exit(2);
    }
    let spec = std::fs::read_to_string(&a[1]).unwrap();
    let data = std::fs::read(&a[2]).unwrap();
    let reps: usize = a.get(3).map_or(7, |s| s.parse().unwrap());
    let msg = Spec { s: spec.trim().as_bytes(), pos: 0 }.node();
    let (mut best, mut total, mut n) = (f64::MAX, 0u64, 0usize);
    for _ in 0..reps {
        let t0 = Instant::now();
        let mut i: &[u8] = &data;
        total = 0x811c;
        n = 0;
        while !i.is_empty() {
            let (r, v) = msg(i).expect("parse");
            total = mix(total, v);
            i = r;
            n += 1;
        }
        best = best.min(t0.elapsed().as_secs_f64());
    }
    println!(
        "rust nom 8    msgs={} hash={:016x}  {:.1} ns/msg",
        n,
        total,
        if n > 0 { best * 1e9 / n as f64 } else { 0.0 }
    );
}
