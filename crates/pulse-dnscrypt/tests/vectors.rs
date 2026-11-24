//! Тест-векторы, сгенерированные независимо `libsodium` 1.0.22
//! (`crypto_box_curve25519xchacha20poly1305`).
//!
//! Вектор фиксирует `beforenm` (`X25519` + `HChaCha20`), nonce layout, MAC-first и
//! дополнение `ISO/IEC 7816-4`. Если реализация отклонится от `libsodium`,
//! тест упадёт.

mod common;

use common::{CLIENT_MAGIC, NOW, TS_END, TS_START};
use pulse_dns::{Message, Name, Question, Rclass, Rtype};
use pulse_dnscrypt::{
    Certificate, CertificateParams, DnscryptClient, ProviderKeypair, ResolverKeypair, Transport,
};

const CLIENT_SK: &str = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";
const CLIENT_PK: &str = "4d27bcee3135c4944b28d27dd809b07be10c35160d20131caa7e85575498d07c";
const RESOLVER_SK: &str = "a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a898887868584838281";
const RESOLVER_PK: &str = "8345f35f3bd833c09af0825e20306ae392b04a7c3e02081c777905fd23033325";
const QUERY_NONCE: &str = "303132333435363738393a3b";
const QUERY_CIPHERTEXT: &str = concat!(
    "bbe2452c1193cda00c7735375218c6e0511f7564feec3a48bf34e25a618f11dd",
    "a9f901d4d6dbf27ef8ed2bd4c7da79ee73cc884b12f726c737e36cbf7b928bab",
    "08493b8488a0d55dd12b0433d5ab9dbc5d155a51f5641738dc7bfcf73817de21",
    "1e1d8dff0c6d0d1c997cacd05944657ffcb53ccdbf1ace87d25b83dfef25def5",
    "6e8809e9e12102015f66ea1716d9a1666075174dbb88adcbb50005e49adc8048",
    "a052bc78939fbe9e28dcf05ccd6dc5cf430435c08fbb4c7e825302fbe5bd0175",
    "25e00e8bc9e6317e68cc1cc4b74586e250a5b65a9d0ccee440a126a43c098b45",
    "a8866a5fa6b2b2cdf918c17ec7ad2645a4931abb7a92d5fbc0ae0cfcd79213b9",
    "7572a8965f6dea6558f9aa9524b4634e"
);
const RESPONSE_NONCE: &str = "303132333435363738393a3b606162636465666768696a6b";
const RESPONSE_CIPHERTEXT: &str = concat!(
    "1bd2ceba1f9d36f3302789dad0f27d3023f2c91085c20f87a11a39a2f9086ad",
    "7db0306f3b2d14bffdf2d4548fc93d069ce23890726484fae76c2a02f81776b1",
    "e8471e6794b85a7453065f593237d6ecc"
);

fn from_hex(text: &str) -> Vec<u8> {
    pulse_dnscrypt::from_hex(text).unwrap()
}

fn client() -> (DnscryptClient, Vec<u8>) {
    let provider = ProviderKeypair::from_seed([0x77; 32]);
    let resolver_sk: [u8; 32] = from_hex(RESOLVER_SK).try_into().unwrap();
    let resolver = ResolverKeypair::from_secret_bytes(resolver_sk);
    assert_eq!(resolver.public_key().to_hex(), RESOLVER_PK);

    let client_sk: [u8; 32] = from_hex(CLIENT_SK).try_into().unwrap();
    let client = ResolverKeypair::from_secret_bytes(client_sk);
    assert_eq!(client.public_key().to_hex(), CLIENT_PK);

    let certificate = Certificate::sign(
        &provider,
        CertificateParams::new(
            resolver.public_key().to_bytes(),
            CLIENT_MAGIC,
            1,
            TS_START,
            TS_END,
        ),
    )
    .unwrap();
    let client =
        DnscryptClient::with_keypair(certificate, provider.public_key(), NOW, client).unwrap();
    (client, from_hex(QUERY_CIPHERTEXT))
}

#[test]
fn query_matches_libsodium_vector() {
    let (client, expected_ciphertext) = client();
    let question = Question::new(Name::parse("example.com").unwrap(), Rtype::A, Rclass::IN);
    let _ = Message::query(0x1234, question);
    // libsodium-вектор использует ровно этот 12-байтовый заголовок.
    let query = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let nonce: [u8; 12] = from_hex(QUERY_NONCE).try_into().unwrap();
    let pending = client
        .build_query_with_nonce(&query, Transport::Udp, nonce)
        .unwrap();
    let packet = pending.packet();
    assert_eq!(&packet[..8], &CLIENT_MAGIC);
    assert_eq!(&packet[8..40], &from_hex(CLIENT_PK));
    assert_eq!(&packet[40..52], &nonce);
    assert_eq!(&packet[52..], expected_ciphertext.as_slice());
}

#[test]
fn response_decrypts_libsodium_vector() {
    let (client, _) = client();
    let nonce: [u8; 12] = from_hex(QUERY_NONCE).try_into().unwrap();
    let question = Question::new(Name::parse("example.com").unwrap(), Rtype::A, Rclass::IN);
    let _ = Message::query(0x1234, question);
    let pending = client
        .build_query_with_nonce(
            &[
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            Transport::Udp,
            nonce,
        )
        .unwrap();

    let mut packet = Vec::new();
    packet.extend_from_slice(b"r6fnvWj8");
    packet.extend_from_slice(&from_hex(RESPONSE_NONCE));
    packet.extend_from_slice(&from_hex(RESPONSE_CIPHERTEXT));
    let plaintext = client.decrypt_response(&pending, &packet).unwrap();
    assert_eq!(
        plaintext,
        vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]
    );
}
