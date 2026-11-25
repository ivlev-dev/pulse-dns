//! Counting allocator: сколько выделений делает горячий путь кодирования.
//!
//! Один тест на бинарник, чтобы счётчик не ловил чужие аллокации тест-раннера.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use pulse_dns::{
    EncodeOptions, EncodeScratch, Encoder, Flags, HeaderCounts, Message, Name, Question, Rclass,
    Rdata, Record, Rtype, Ttl,
};

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure(run: impl FnOnce()) -> usize {
    ALLOCS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    run();
    COUNTING.store(false, Ordering::Relaxed);
    ALLOCS.load(Ordering::Relaxed)
}

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn ttl(value: u32) -> Ttl {
    Ttl::new(value).expect("ttl")
}

fn record(owner: &str, rtype: Rtype, rdata: Rdata) -> Record {
    Record::new(name(owner), rtype, Rclass::IN, ttl(300), rdata).expect("record")
}

fn response() -> Message {
    let mut message = Message::query(
        0x1234,
        Question::new(name("www.example.com"), Rtype::A, Rclass::IN),
    );
    message.set_flags(Flags::new().with_qr(true).with_aa(true));
    for index in 0..10_u8 {
        message.add_answer(record(
            "www.example.com",
            Rtype::A,
            Rdata::A([192, 0, 2, index].into()),
        ));
    }
    message.add_authority(record(
        "example.com",
        Rtype::NS,
        Rdata::Ns(name("ns1.example.com")),
    ));
    message.add_additional(record(
        "ns1.example.com",
        Rtype::A,
        Rdata::A([192, 0, 2, 53].into()),
    ));
    message
}

#[test]
fn hot_encode_path_does_not_allocate() {
    let message = response();
    let mut out = vec![0_u8; 4096];
    let mut scratch = EncodeScratch::new();

    // Разогрев: таблица компрессии уже создана.
    message
        .encode_into_with(&mut out, &EncodeOptions::compressed())
        .expect("warmup");

    let into_allocs = measure(|| {
        message
            .encode_into_with(&mut out, &EncodeOptions::compressed())
            .expect("encode_into");
    });
    assert_eq!(into_allocs, 0, "encode_into allocated {into_allocs} times");

    let len_allocs = measure(|| {
        message
            .encoded_len_with(&EncodeOptions::compressed())
            .expect("encoded_len");
    });
    assert_eq!(len_allocs, 0, "encoded_len allocated {len_allocs} times");

    let streaming_allocs = measure(|| {
        let mut encoder = Encoder::new(&mut out, EncodeOptions::compressed(), &mut scratch);
        encoder.begin_message(message.id()).expect("header");
        for question in message.questions() {
            encoder.write_question(question).expect("question");
        }
        for record in message
            .answers()
            .iter()
            .chain(message.authority().iter())
            .chain(message.additional().iter())
        {
            encoder.write_record(record).expect("record");
        }
        encoder
            .finish(
                message.flags(),
                HeaderCounts {
                    question: 1,
                    answer: u16::try_from(message.answers().len()).expect("count"),
                    authority: u16::try_from(message.authority().len()).expect("count"),
                    additional: u16::try_from(message.additional().len()).expect("count"),
                },
            )
            .expect("finish");
    });
    assert_eq!(
        streaming_allocs, 0,
        "streaming encoder allocated {streaming_allocs} times"
    );

    // Прежний путь: как минимум сам `Vec` ответа.
    let legacy_allocs = measure(|| {
        message
            .encode(&EncodeOptions::compressed())
            .expect("legacy encode");
    });
    assert!(
        legacy_allocs > 0,
        "legacy encode unexpectedly allocation-free"
    );
    println!(
        "allocs: encode_into={into_allocs}, encoded_len={len_allocs}, \
         streaming={streaming_allocs}, legacy_encode={legacy_allocs}"
    );
}
