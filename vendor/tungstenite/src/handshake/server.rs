//! Server handshake machine.

use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    result::Result as StdResult,
};

use http::{
    response::Builder, HeaderMap, Request as HttpRequest, Response as HttpResponse, StatusCode,
};
use httparse::Status;
use log::*;

use super::{
    derive_accept_key,
    headers::{FromHttparse, MAX_HEADERS},
    machine::{HandshakeMachine, StageResult, TryParse},
    HandshakeRole, MidHandshake, ProcessingResult,
};
use crate::{
    error::{Error, ProtocolError, Result},
    protocol::{Role, WebSocket, WebSocketConfig},
};

/// Server request type.
pub type Request = HttpRequest<()>;

/// Server response type.
pub type Response = HttpResponse<()>;

/// Server error response type.
pub type ErrorResponse = HttpResponse<Option<String>>;

fn create_parts<T>(request: &HttpRequest<T>) -> Result<Builder> {
    if request.method() != http::Method::GET {
        return Err(Error::Protocol(ProtocolError::WrongHttpMethod));
    }

    if request.version() < http::Version::HTTP_11 {
        return Err(Error::Protocol(ProtocolError::WrongHttpVersion));
    }

    if !request
        .headers()
        .get("Connection")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split([' ', ',']).any(|p| p.eq_ignore_ascii_case("Upgrade")))
        .unwrap_or(false)
    {
        return Err(Error::Protocol(ProtocolError::MissingConnectionUpgradeHeader));
    }

    if !request
        .headers()
        .get("Upgrade")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return Err(Error::Protocol(ProtocolError::MissingUpgradeWebSocketHeader));
    }

    if !request.headers().get("Sec-WebSocket-Version").map(|h| h == "13").unwrap_or(false) {
        return Err(Error::Protocol(ProtocolError::MissingSecWebSocketVersionHeader));
    }

    let key = request
        .headers()
        .get("Sec-WebSocket-Key")
        .ok_or(Error::Protocol(ProtocolError::MissingSecWebSocketKey))?;

    let builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .version(request.version())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Accept", derive_accept_key(key.as_bytes()));

    Ok(builder)
}

/// Create a response for the request.
pub fn create_response(request: &Request) -> Result<Response> {
    Ok(create_parts(request)?.body(())?)
}

/// Create a response for the request with a custom body.
pub fn create_response_with_body<T1, T2>(
    request: &HttpRequest<T1>,
    generate_body: impl FnOnce() -> T2,
) -> Result<HttpResponse<T2>> {
    Ok(create_parts(request)?.body(generate_body())?)
}

/// Write `response` to the stream `w`.
pub fn write_response<T>(mut w: impl io::Write, response: &HttpResponse<T>) -> Result<()> {
    writeln!(
        w,
        "{version:?} {status}\r",
        version = response.version(),
        status = response.status()
    )?;

    for (k, v) in response.headers() {
        writeln!(w, "{}: {}\r", k, v.to_str()?)?;
    }

    writeln!(w, "\r")?;

    Ok(())
}

impl TryParse for Request {
    fn try_parse(buf: &[u8]) -> Result<Option<(usize, Self)>> {
        let mut hbuffer = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut hbuffer);
        Ok(match req.parse(buf)? {
            Status::Partial => None,
            Status::Complete(size) => Some((size, Request::from_httparse(req)?)),
        })
    }
}

impl<'h, 'b: 'h> FromHttparse<httparse::Request<'h, 'b>> for Request {
    fn from_httparse(raw: httparse::Request<'h, 'b>) -> Result<Self> {
        if raw.method.expect("Bug: no method in header") != "GET" {
            return Err(Error::Protocol(ProtocolError::WrongHttpMethod));
        }

        if raw.version.expect("Bug: no HTTP version") < /*1.*/1 {
            return Err(Error::Protocol(ProtocolError::WrongHttpVersion));
        }

        let headers = HeaderMap::from_httparse(raw.headers)?;

        let mut request = Request::new(());
        *request.method_mut() = http::Method::GET;
        *request.headers_mut() = headers;
        *request.uri_mut() = raw.path.expect("Bug: no path in header").parse()?;
        // TODO: httparse only supports HTTP 0.9/1.0/1.1 but not HTTP 2.0
        // so the only valid value we could get in the response would be 1.1.
        *request.version_mut() = http::Version::HTTP_11;

        Ok(request)
    }
}

/// The callback trait.
///
/// The callback is called when the server receives an incoming WebSocket
/// handshake request from the client. Specifying a callback allows you to analyze incoming headers
/// and add additional headers to the response that server sends to the client and/or reject the
/// connection based on the incoming headers.
pub trait Callback: Sized {
    /// Called whenever the server read the request from the client and is ready to reply to it.
    /// May return additional reply headers.
    /// Returning an error resulting in rejecting the incoming connection.
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> StdResult<Response, ErrorResponse>;
}

impl<F> Callback for F
where
    F: FnOnce(&Request, Response) -> StdResult<Response, ErrorResponse>,
{
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> StdResult<Response, ErrorResponse> {
        self(request, response)
    }
}

/// Stub for callback that does nothing.
#[derive(Clone, Copy, Debug)]
pub struct NoCallback;

impl Callback for NoCallback {
    fn on_request(
        self,
        _request: &Request,
        response: Response,
    ) -> StdResult<Response, ErrorResponse> {
        Ok(response)
    }
}

/// Server handshake role.
#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct ServerHandshake<S, C> {
    /// Callback which is called whenever the server read the request from the client and is ready
    /// to reply to it. The callback returns an optional headers which will be added to the reply
    /// which the server sends to the user.
    callback: Option<C>,
    /// WebSocket configuration.
    config: Option<WebSocketConfig>,
    /// Error code/flag. If set, an error will be returned after sending response to the client.
    error_response: Option<HttpResponse<Option<crate::maki_buffer::OwnedBuffer>>>,
    /// Internal stream type.
    _marker: PhantomData<S>,
}

impl<S: Read + Write, C: Callback> ServerHandshake<S, C> {
    /// Start server handshake. `callback` specifies a custom callback which the user can pass to
    /// the handshake, this callback will be called when the a websocket client connects to the
    /// server, you can specify the callback if you want to add additional header to the client
    /// upon join based on the incoming headers.
    pub fn start(stream: S, callback: C, config: Option<WebSocketConfig>) -> MidHandshake<Self> {
        trace!("Server handshake initiated.");
        MidHandshake {
            machine: HandshakeMachine::start_read(stream),
            role: ServerHandshake {
                callback: Some(callback),
                config,
                error_response: None,
                _marker: PhantomData,
            },
        }
    }
}

impl<S: Read + Write, C: Callback> HandshakeRole for ServerHandshake<S, C> {
    type IncomingData = Request;
    type InternalStream = S;
    type FinalResult = WebSocket<S>;

    fn stage_finished(
        &mut self,
        finish: StageResult<Self::IncomingData, Self::InternalStream>,
    ) -> Result<ProcessingResult<Self::InternalStream, Self::FinalResult>> {
        Ok(match finish {
            StageResult::DoneReading { stream, result, tail } => {
                let tail = crate::maki_buffer::OwnedBuffer::from_vec(tail);
                if !tail.is_empty() {
                    return Err(Error::Protocol(ProtocolError::JunkAfterRequest));
                }

                let response = create_response(&result)?;
                let callback_result = if let Some(callback) = self.callback.take() {
                    callback.on_request(&result, response)
                } else {
                    Ok(response)
                };

                match callback_result {
                    Ok(response) => {
                        let mut output = crate::maki_buffer::OwnedBuffer::default();
                        write_response(&mut output, &response)?;
                        ProcessingResult::Continue(HandshakeMachine::start_write(
                            stream, output.into_vec(),
                        ))
                    }

                    Err(resp) => {
                        let resp = resp.map(|body| {
                            body.map(|body| {
                                crate::maki_buffer::OwnedBuffer::from_vec(body.into_bytes())
                            })
                        });
                        if resp.status().is_success() {
                            return Err(Error::Protocol(ProtocolError::CustomResponseSuccessful));
                        }

                        self.error_response = Some(resp);
                        let resp = self.error_response.as_ref().unwrap();

                        let mut output = crate::maki_buffer::OwnedBuffer::default();
                        write_response(&mut output, resp)?;

                        if let Some(body) = resp.body() {
                            output.extend_from_slice(body);
                        }

                        ProcessingResult::Continue(HandshakeMachine::start_write(
                            stream, output.into_vec(),
                        ))
                    }
                }
            }

            StageResult::DoneWriting(stream) => {
                if let Some(err) = self.error_response.take() {
                    debug!("Server handshake failed.");

                    let (parts, body) = err.into_parts();
                    let body = body.map(crate::maki_buffer::OwnedBuffer::into_vec);
                    return Err(Error::Http(http::Response::from_parts(parts, body)));
                } else {
                    debug!("Server handshake done.");
                    let websocket = WebSocket::from_raw_socket(stream, Role::Server, self.config);
                    ProcessingResult::Done(websocket)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{super::machine::TryParse, create_response, Request};

    #[test]
    fn request_parsing() {
        const DATA: &[u8] = b"GET /script.ws HTTP/1.1\r\nHost: foo.com\r\n\r\n";
        let (_, req) = Request::try_parse(DATA).unwrap().unwrap();
        assert_eq!(req.uri().path(), "/script.ws");
        assert_eq!(req.headers().get("Host").unwrap(), &b"foo.com"[..]);
    }

    #[test]
    fn request_replying() {
        const DATA: &[u8] = b"\
            GET /script.ws HTTP/1.1\r\n\
            Host: foo.com\r\n\
            Connection: upgrade\r\n\
            Upgrade: websocket\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            \r\n";
        let (_, req) = Request::try_parse(DATA).unwrap().unwrap();
        let response = create_response(&req).unwrap();

        assert_eq!(
            response.headers().get("Sec-WebSocket-Accept").unwrap(),
            b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".as_ref()
        );
    }
}

#[cfg(test)]
mod maki_erasure_tests {
    use super::*;
    use maki_test_allocator::watch;
    use std::io::Cursor;

    fn retained_error_body(body: String) -> ServerHandshake<Cursor<Vec<u8>>, NoCallback> {
        ServerHandshake {
            callback: None,
            config: None,
            error_response: Some(
                HttpResponse::builder()
                    .status(403)
                    .body(Some(crate::maki_buffer::OwnedBuffer::from_vec(
                        body.into_bytes(),
                    )))
                    .unwrap(),
            ),
            _marker: PhantomData,
        }
    }

    #[test]
    fn maki_invalid_error_response_erases_body_before_storage() {
        let body = String::from("maki invalid callback response secret");
        let released = watch(body.as_ptr());
        let callback = move |_: &Request, _: Response| Err(HttpResponse::new(Some(body)));
        let mut handshake = ServerHandshake::<Cursor<Vec<u8>>, _> {
            callback: Some(callback),
            config: None,
            error_response: None,
            _marker: PhantomData,
        };
        let request = Request::builder()
            .uri("/")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();
        let error = handshake.stage_finished(StageResult::DoneReading {
            stream: Cursor::new(Vec::new()),
            result: request,
            tail: Vec::new(),
        });
        assert!(matches!(
            error,
            Err(Error::Protocol(ProtocolError::CustomResponseSuccessful))
        ));
        released.assert_zeroized();
    }

    #[test]
    fn maki_retained_handshake_error_body_erased_on_cancellation() {
        let body = String::from("maki retained handshake error secret");
        let released = watch(body.as_ptr());
        drop(retained_error_body(body));
        released.assert_zeroized();
    }

    #[test]
    fn maki_handshake_error_body_transfers_original_allocation() {
        use zeroize::Zeroize;
        let body = String::from("maki retained handshake error secret");
        let released = watch(body.as_ptr());
        let mut handshake = retained_error_body(body);
        let error = handshake.stage_finished(StageResult::DoneWriting(Cursor::new(Vec::new())));
        let Err(Error::Http(mut response)) = error else {
            panic!("expected HTTP rejection")
        };
        assert_eq!(
            response.body().as_deref().unwrap(),
            b"maki retained handshake error secret"
        );
        // This public output has transferred to the caller. The caller wipes
        // it before release; no separate internal String may have been freed.
        response.body_mut().as_mut().unwrap().zeroize();
        drop(response);
        released.assert_zeroized();
    }

    #[test]
    fn maki_rejected_handshake_tail_erases_early_payload() {
        let tail = b"maki rejected early websocket payload".to_vec();
        let released = watch(tail.as_ptr());
        let mut handshake = ServerHandshake::<Cursor<Vec<u8>>, NoCallback> {
            callback: None,
            config: None,
            error_response: None,
            _marker: PhantomData,
        };
        let result = handshake.stage_finished(StageResult::DoneReading {
            stream: Cursor::new(Vec::new()),
            result: Request::new(()),
            tail,
        });
        assert!(matches!(
            result,
            Err(Error::Protocol(ProtocolError::JunkAfterRequest))
        ));
        released.assert_zeroized();
    }
}
