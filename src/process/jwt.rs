use anyhow::Result;
use core::panic;
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use std::io::Read;

use crate::JwtSignOpts;

pub fn jwt_encode(claim: &JwtSignOpts) -> Result<String> {
    let token = encode(
        &Header::default(),
        &claim,
        &EncodingKey::from_secret(b"secret"),
    )?;
    Ok(token)
}

pub fn jwt_decode(reader: &mut dyn Read) -> Result<String> {
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    // avoid accidental newlines
    let buf = buf.trim();
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["device1"]);
    let token_data = match decode::<JwtSignOpts>(
        buf,
        &DecodingKey::from_secret(b"secret".as_ref()),
        &validation,
    ) {
        Ok(c) => c,
        Err(e) => match *e.kind() {
            ErrorKind::InvalidToken => panic!("Token is invalid"),
            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"),
            ErrorKind::ExpiredSignature => panic!("Token is expired"),
            _ => panic!("Some other errors: {:?}", e.to_string()),
        },
    };
    let token = token_data.claims;
    // println!("{:?}", token);
    let token = serde_json::to_string(&token)?;
    println!("{}", token);
    Ok(token)
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use super::*;
    use crate::get_reader;

    #[test]
    fn test_jwt_encode() -> Result<()> {
        let claim = JwtSignOpts {
            sub: "acme".to_string(),
            aud: "device1".to_string(),
            exp: 10000000000,
        };
        assert_eq!(
            jwt_encode(&claim).unwrap(),
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY21lIiwiYXVkIjoiZGV2aWNlMSIsImV4cCI6MTAwMDAwMDAwMDB9.--P0fV9m9HvyGlr9n1kNOKEkYFMuzu8XRHxGhdjaj5g".to_owned()
        );
        Ok(())
    }

    #[test]
    fn test_jwt_decode() -> Result<()> {
        let input = "fixtures/jwt.txt";
        let mut reader = get_reader(input)?;
        let decoded = jwt_decode(&mut reader)?;
        assert_eq!(
            decoded,
            "{\"sub\":\"acme\",\"aud\":\"device1\",\"exp\":10000000000}".to_owned()
        );
        Ok(())
    }
}
