use std::time::Duration;

pub fn cli_bytes_parser<ErrorType, F>(s: String, error_generator: F) -> Result<Vec<u8>, ErrorType>
where
    F: Fn(String) -> ErrorType,
{
    let mut result = vec![0u8; 0];
    for i in 0..s.len() / 2 {
        let start = 2 * i;
        let end = start + 2;

        let value: u8 =
            u8::from_str_radix(&s[start..end], 16).map_err(|_| error_generator(s.clone()))?;
        result.push(value);
    }
    println!("Bytes parser success!");
    Ok(result)
}

pub fn parse_duration(duration_str: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds: u64 = duration_str.parse()?;
    Ok(Duration::from_secs(seconds))
}
