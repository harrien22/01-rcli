use clap::Parser;
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};

use crate::CmdExector;

use super::verify_file;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    #[command(name = "sign", about = "Sign a string with a key")]
    Sign(JwtSignOpts),
    #[command(name = "verify", about = "Verify a signed string")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser, Serialize, Deserialize)]
pub struct JwtSignOpts {
    #[arg(long, default_value = "-")]
    pub sub: String,
    #[arg(long, default_value = "-")]
    pub aud: String,
    #[arg(long, default_value_t = 1)]
    pub exp: u64,
}

#[derive(Debug, Parser, Serialize, Deserialize)]
pub struct JwtVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
}

impl CmdExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let ret = crate::jwt_encode(&self)?;
        println!("{}", ret);
        Ok(())
    }
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = crate::get_reader(&self.input)?;
        let ret = crate::jwt_decode(&mut reader)?;
        println!("{}", ret);
        Ok(())
    }
}
