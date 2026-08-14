use http::{HeaderMap, HeaderName, header::HeaderValue};
use rand::RngExt;

const RANDOM_PADDING_HEADER_MAX_WIRE_BYTES: usize = 2048;
const RANDOM_PADDING_HEADER_MAX_COUNT: usize = 32;
const RANDOM_PADDING_HEADER_NAME_SUFFIX_LEN: usize = 8;
const RANDOM_PADDING_HEADER_VALUE_MIN_LEN: usize = 8;
const RANDOM_PADDING_HEADER_VALUE_MAX_LEN: usize = 64;
const RANDOM_PADDING_HEADER_NAME_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const RANDOM_PADDING_HEADER_VALUE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(super) fn append_random_padding_headers(headers: &mut HeaderMap) {
    let mut rng = rand::rng();
    let min_header_wire_bytes =
        random_padding_header_wire_bytes(RANDOM_PADDING_HEADER_NAME_SUFFIX_LEN, RANDOM_PADDING_HEADER_VALUE_MIN_LEN);
    let mut remaining_wire_bytes = rng.random_range(min_header_wire_bytes..=RANDOM_PADDING_HEADER_MAX_WIRE_BYTES);
    let mut header_count = 0usize;

    while remaining_wire_bytes >= min_header_wire_bytes && header_count < RANDOM_PADDING_HEADER_MAX_COUNT {
        let value_budget =
            remaining_wire_bytes - random_padding_header_wire_bytes(RANDOM_PADDING_HEADER_NAME_SUFFIX_LEN, 0);
        let value_len = rng
            .random_range(RANDOM_PADDING_HEADER_VALUE_MIN_LEN..=value_budget.min(RANDOM_PADDING_HEADER_VALUE_MAX_LEN));

        let name = format!(
            "x-pad-{}",
            random_ascii(&mut rng, RANDOM_PADDING_HEADER_NAME_CHARS, RANDOM_PADDING_HEADER_NAME_SUFFIX_LEN)
        );
        let value = random_ascii(&mut rng, RANDOM_PADDING_HEADER_VALUE_CHARS, value_len);
        let header_wire_bytes = random_padding_header_wire_bytes(RANDOM_PADDING_HEADER_NAME_SUFFIX_LEN, value_len);

        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(&value)) {
            headers.append(name, value);
        }

        remaining_wire_bytes -= header_wire_bytes;
        header_count += 1;
    }
}

fn random_padding_header_wire_bytes(name_suffix_len: usize, value_len: usize) -> usize {
    "x-pad-".len() + name_suffix_len + ": ".len() + value_len + "\r\n".len()
}

fn random_ascii<R: rand::RngExt + ?Sized>(rng: &mut R, alphabet: &[u8], len: usize) -> String {
    let mut output = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.random_range(0..alphabet.len());
        output.push(alphabet[idx] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_padding_headers_are_http_safe() {
        for _ in 0..16 {
            let mut headers = HeaderMap::new();

            append_random_padding_headers(&mut headers);

            assert!(!headers.is_empty());
            assert!(!headers.contains_key(http::header::SERVER));

            assert!(headers.iter().count() <= RANDOM_PADDING_HEADER_MAX_COUNT);

            let total_wire_bytes: usize = headers
                .iter()
                .map(|(name, value)| {
                    random_padding_header_wire_bytes(name.as_str().len() - "x-pad-".len(), value.as_bytes().len())
                })
                .sum();
            assert!(total_wire_bytes <= RANDOM_PADDING_HEADER_MAX_WIRE_BYTES);

            for (name, value) in &headers {
                let name = name.as_str();
                assert!(name.starts_with("x-pad-"));
                assert_eq!(name.len(), "x-pad-".len() + RANDOM_PADDING_HEADER_NAME_SUFFIX_LEN);
                assert!(
                    name.bytes()
                        .skip("x-pad-".len())
                        .all(|byte| RANDOM_PADDING_HEADER_NAME_CHARS.contains(&byte))
                );

                assert!(!value.as_bytes().is_empty());
                assert!(
                    value
                        .as_bytes()
                        .iter()
                        .all(|byte| RANDOM_PADDING_HEADER_VALUE_CHARS.contains(byte))
                );
            }
        }
    }
}
