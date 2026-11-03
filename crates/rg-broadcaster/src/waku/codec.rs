use std::io;
use std::marker::PhantomData;

use libp2p::StreamProtocol;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;

/// Waku request-response framing: one varint-length-prefixed protobuf each way per stream.
pub struct ProtoCodec<Req, Res>(PhantomData<(Req, Res)>);

impl<Req, Res> Default for ProtoCodec<Req, Res> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<Req, Res> Clone for ProtoCodec<Req, Res> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

/// Larger than any Railgun message, so a peer cannot make the client buffer without bound.
const MAX_MESSAGE: u64 = 4 << 20;

async fn read<T: prost::Message + Default>(
    io: &mut (impl AsyncRead + Unpin + Send),
) -> io::Result<T> {
    let mut buf = Vec::new();
    io.take(MAX_MESSAGE).read_to_end(&mut buf).await?;
    T::decode_length_delimited(buf.as_slice()).map_err(io::Error::other)
}

async fn write(
    io: &mut (impl AsyncWrite + Unpin + Send),
    message: impl prost::Message,
) -> io::Result<()> {
    io.write_all(&message.encode_length_delimited_to_vec())
        .await?;
    io.close().await
}

impl<Req, Res> Codec for ProtoCodec<Req, Res>
where
    Req: prost::Message + Default + Send + 'static,
    Res: prost::Message + Default + Send + 'static,
{
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Res;

    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Req> {
        read(io).await
    }

    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Res> {
        read(io).await
    }

    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        request: Req,
    ) -> io::Result<()> {
        write(io, request).await
    }

    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        response: Res,
    ) -> io::Result<()> {
        write(io, response).await
    }
}
