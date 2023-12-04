mod api;
mod methods;

// re-export the defined API
pub use api::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{task::Poll, pin::Pin, task::Context, future::Future, io::{ErrorKind, Error}};
    use flume::r#async::SendSink;
    use futures_util::{AsyncRead, AsyncWrite, Sink};
    
    #[derive(Clone)]
    pub struct MockStream<'a> {
        sender: SendSink<'a, Vec<u8>>,
        receiver: flume::Receiver<Vec<u8>>
    }
    
    impl Default for MockStream<'_> {
        fn default() -> Self {
            let (tx, rx) = flume::unbounded();
            let sink = tx.into_sink();
            MockStream {
                sender: sink,
                receiver: rx
            }
        }
    }
    
    impl AsyncRead for MockStream<'_> {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Error>> {
            let mut future = self.receiver.recv_async();
            match Pin::new(&mut future).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(val)) => {
                    let bytes = val.len();
                    log::debug!("{:?}", &bytes);
                    buf[..bytes].copy_from_slice(&val);
                    Poll::Ready(Ok(bytes))
                },
                Poll::Ready(Err(e)) => {
                    Poll::Ready(Err(Error::new(ErrorKind::Other, e)))
                }
            }
        }
    }

    impl AsyncWrite for MockStream<'_> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
            let mut sink = Pin::new(&mut self.sender);
            match sink.as_mut().poll_ready(cx) {
                Poll::Ready(Ok(_)) => {} ,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::new(ErrorKind::Other, e)))
            };

            let len = buf.len();
            let res = sink.start_send(buf.to_vec());
            log::debug!("{:?}", buf.to_vec());
            Poll::Ready(Ok(len))
        }
        
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            let sink = Pin::new(&mut self.sender);
            sink.poll_flush(cx).map_err(|e| Error::new(ErrorKind::Other, e))
        }

        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Pin::new(&mut self.sender).poll_close(cx).map_err(|e| Error::new(ErrorKind::Other, e))
        }
    }
}
