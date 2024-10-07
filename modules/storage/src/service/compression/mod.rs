use async_compression::tokio::bufread;
use async_compression::tokio::write::ZstdEncoder;
use std::fmt::{Display, Formatter};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, ReadBuf};

#[derive(Copy, Clone, Eq, PartialEq, Default, Debug, strum::EnumIter, clap::ValueEnum)]
pub enum Compression {
    #[default]
    None,
    Zstd,
}

impl Display for Compression {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Compression::None => f.write_str("none"),
            Compression::Zstd => f.write_str("zstd"),
        }
    }
}

impl Compression {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Zstd => "zstd",
        }
    }

    pub async fn write<R, W>(&self, r: &mut R, w: &mut W) -> io::Result<u64>
    where
        R: AsyncBufRead + Unpin + 'static,
        W: AsyncWrite + Unpin + 'static,
    {
        match self {
            Self::None => io::copy(r, w).await,
            Self::Zstd => io::copy(r, &mut ZstdEncoder::new(w)).await,
        }
    }

    pub fn reader<R>(&self, r: R) -> DecompressionReader<R>
    where
        R: AsyncRead,
    {
        let r = BufReader::new(r);
        match self {
            Self::None => DecompressionReader {
                inner: InnerDecompression::None(r),
            },
            Self::Zstd => DecompressionReader {
                inner: InnerDecompression::Zstd(bufread::ZstdDecoder::new(r)),
            },
        }
    }
}

enum InnerDecompression<R>
where
    R: AsyncRead,
{
    None(BufReader<R>),
    Zstd(bufread::ZstdDecoder<BufReader<R>>),
}

pub struct DecompressionReader<R>
where
    R: AsyncRead,
{
    inner: InnerDecompression<R>,
}

impl<R> AsyncRead for DecompressionReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            InnerDecompression::None(ref mut r) => Pin::new(r).poll_read(cx, buf),
            InnerDecompression::Zstd(ref mut r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}
