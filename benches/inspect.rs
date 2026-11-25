use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use llmfence::engine::{Direction, Guard};
use llmfence::policy::Policy;
use std::hint::black_box;

fn corpus(target: usize, with_pii: bool) -> String {
    let clean = "Summarize the incident timeline and list remediation owners for each workstream. ";
    let dirty = "Contact jane.doe@contoso.com or (415) 555-0132, card 4111 1111 1111 1111. ";
    let mut s = String::with_capacity(target + 128);
    let mut i = 0;
    while s.len() < target {
        s.push_str(if with_pii && i % 8 == 0 { dirty } else { clean });
        i += 1;
    }
    s
}

fn bench(c: &mut Criterion) {
    let guard = Guard::new(Policy::default());
    let mut group = c.benchmark_group("inspect");
    for (name, text) in [
        ("clean_1kb", corpus(1024, false)),
        ("pii_1kb", corpus(1024, true)),
        ("clean_16kb", corpus(16 * 1024, false)),
        ("pii_16kb", corpus(16 * 1024, true)),
    ] {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_function(name, |b| {
            b.iter(|| guard.inspect(black_box(&text), Direction::Request))
        });
    }
    group.finish();

    let text = corpus(16 * 1024, false);
    let mut group = c.benchmark_group("components_clean_16kb");
    group.throughput(Throughput::Bytes(text.len() as u64));
    group.bench_function("detect", |b| {
        b.iter(|| llmfence::detect::scan(black_box(&text)))
    });
    group.bench_function("normalize", |b| {
        b.iter(|| llmfence::injection::normalize(black_box(&text)))
    });
    group.bench_function("injection", |b| {
        b.iter(|| llmfence::injection::score(black_box(&text)))
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
