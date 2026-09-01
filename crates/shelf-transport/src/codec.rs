//! Length-prefixed binary codec for TLS peer sessions (`shelf/2`).
//!
//! On-wire layout: magic `SHLF`, `u8` version `1`, `u32` big-endian payload
//! length, then a hand-defined payload. Payloads are [`SessionHello`] or
//! [`PeerMessage`] (Have/Op). Bare [`SignedOperation`] JSON is not a frame
//! kind. Mailbox and local IPC keep newline JSON.

use std::io;

use shelf_core::{
    AeadAlgorithm, ChunkId, ContentKind, DeviceCapabilities, DeviceId, EpochId, HybridKemPublicKey,
    MAX_FRAME_BYTES, MailboxBinding, MemberRole, MembershipCertificate, MembershipSnapshot,
    MlKem768PublicKey, ObjectId, SignatureBytes, SigningPublicKey, Timestamp, VaultId, VaultRoot,
    X25519PublicKey,
};
use shelf_protocol::{DeviceEpochWrap, EncryptedObject, Hash, HybridEpochWrap, KeyEnvelope};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::frame::{OpBody, OriginCursor, PeerMessage, SignedOperation, parse_sig_hex, sig_hex};
use crate::session::SessionHello;

const MAGIC: &[u8; 4] = b"SHLF";
const CODEC_VERSION: u8 = 1;
const HEADER_LEN: usize = 9;

const KIND_HELLO: u8 = 1;
const KIND_HAVE: u8 = 2;
const KIND_OP: u8 = 3;

const BODY_PUT: u8 = 1;
const BODY_PIN: u8 = 2;
const BODY_TOMBSTONE: u8 = 3;
const BODY_SCRATCH: u8 = 4;
const BODY_CHUNK: u8 = 5;
const BODY_NEED_CHUNKS: u8 = 6;
const BODY_EPOCH: u8 = 7;

/// Application record on a `shelf/2` TLS peer session.
///
/// Ops travel only as [`PeerMessage::Op`]. A bare [`SignedOperation`] is not
/// a valid frame (that JSON dialect is mailbox/legacy `shelf/1` only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerFrame {
    /// Membership hello (first record after TLS).
    Hello(SessionHello),
    /// Subsequent Have/Op records.
    Message(PeerMessage),
}

/// Read one length-prefixed peer frame, rejecting bad magic, unknown version,
/// and payloads larger than [`MAX_FRAME_BYTES`].
pub async fn read_peer_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<PeerFrame>> {
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < HEADER_LEN {
        let n = reader.read(&mut header[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated peer frame header",
                ))
            };
        }
        filled += n;
    }

    if header[..4] != MAGIC[..] {
        return Err(invalid("bad peer frame magic"));
    }
    if header[4] != CODEC_VERSION {
        return Err(invalid("unknown peer frame version"));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&header[5..9]);
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(invalid("frame exceeds MAX_FRAME_BYTES"));
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    decode_payload(&payload).map(Some)
}

/// Write one length-prefixed peer frame. Rejects payloads over [`MAX_FRAME_BYTES`].
pub async fn write_peer_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &PeerFrame,
) -> io::Result<()> {
    let payload = encode_payload(frame)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(invalid("frame exceeds MAX_FRAME_BYTES"));
    }
    let len = u32::try_from(payload.len()).map_err(|_| invalid("frame exceeds MAX_FRAME_BYTES"))?;
    writer.write_all(MAGIC).await?;
    writer.write_all(&[CODEC_VERSION]).await?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn encode_payload(frame: &PeerFrame) -> io::Result<Vec<u8>> {
    let mut w = W::default();
    match frame {
        PeerFrame::Hello(hello) => {
            w.u8(KIND_HELLO);
            encode_hello(&mut w, hello)?;
        }
        PeerFrame::Message(PeerMessage::Have { cursors }) => {
            w.u8(KIND_HAVE);
            encode_have(&mut w, cursors)?;
        }
        PeerFrame::Message(PeerMessage::Op { op }) => {
            w.u8(KIND_OP);
            encode_op(&mut w, op)?;
        }
    }
    Ok(w.0)
}

fn decode_payload(bytes: &[u8]) -> io::Result<PeerFrame> {
    let mut r = R(bytes);
    let kind = r.u8()?;
    let frame = match kind {
        KIND_HELLO => PeerFrame::Hello(decode_hello(&mut r)?),
        KIND_HAVE => PeerFrame::Message(PeerMessage::Have {
            cursors: decode_have(&mut r)?,
        }),
        KIND_OP => PeerFrame::Message(PeerMessage::Op {
            op: Box::new(decode_op(&mut r)?),
        }),
        _ => return Err(invalid("unknown peer frame kind")),
    };
    r.finish()?;
    Ok(frame)
}

fn encode_hello(w: &mut W, hello: &SessionHello) -> io::Result<()> {
    w.fixed(hello.vault_id.as_bytes());
    w.fixed(hello.device_id.as_bytes());
    let sig = parse_sig_hex(&hello.signature).ok_or_else(|| invalid("invalid hello signature"))?;
    w.fixed(&sig);
    Ok(())
}

fn decode_hello(r: &mut R<'_>) -> io::Result<SessionHello> {
    Ok(SessionHello {
        vault_id: VaultId::from_bytes(r.fixed32()?),
        device_id: DeviceId::from_bytes(r.fixed32()?),
        signature: sig_hex(&r.fixed64()?),
    })
}

fn encode_have(w: &mut W, cursors: &[OriginCursor]) -> io::Result<()> {
    w.u32(u32_len(cursors.len())?);
    for c in cursors {
        w.fixed(c.origin.as_bytes());
        w.u64(c.seq);
    }
    Ok(())
}

fn decode_have(r: &mut R<'_>) -> io::Result<Vec<OriginCursor>> {
    let n = r.u32()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(OriginCursor {
            origin: DeviceId::from_bytes(r.fixed32()?),
            seq: r.u64()?,
        });
    }
    Ok(out)
}

fn encode_op(w: &mut W, op: &SignedOperation) -> io::Result<()> {
    w.u64(op.seq);
    w.str16(&op.op_id)?;
    w.fixed(op.vault_id.as_bytes());
    w.u64(op.epoch.as_u64());
    w.fixed(op.origin.as_bytes());
    encode_body(w, &op.body)?;
    let sig = parse_sig_hex(&op.signature).ok_or_else(|| invalid("invalid op signature"))?;
    w.fixed(&sig);
    Ok(())
}

fn decode_op(r: &mut R<'_>) -> io::Result<SignedOperation> {
    Ok(SignedOperation {
        seq: r.u64()?,
        op_id: r.str16()?,
        vault_id: VaultId::from_bytes(r.fixed32()?),
        epoch: EpochId::new(r.u64()?),
        origin: DeviceId::from_bytes(r.fixed32()?),
        body: decode_body(r)?,
        signature: sig_hex(&r.fixed64()?),
    })
}

fn encode_body(w: &mut W, body: &OpBody) -> io::Result<()> {
    match body {
        OpBody::Put { envelope } => {
            w.u8(BODY_PUT);
            encode_object(w, envelope)?;
        }
        OpBody::Pin { object_id, at } => {
            w.u8(BODY_PIN);
            w.fixed(object_id.as_bytes());
            w.u64(at.as_millis());
        }
        OpBody::Tombstone { object_id, at } => {
            w.u8(BODY_TOMBSTONE);
            w.fixed(object_id.as_bytes());
            w.u64(at.as_millis());
        }
        OpBody::Scratch { envelope } => {
            w.u8(BODY_SCRATCH);
            encode_object(w, envelope)?;
        }
        OpBody::Chunk { parent, envelope } => {
            w.u8(BODY_CHUNK);
            w.fixed(parent.as_bytes());
            encode_object(w, envelope)?;
        }
        OpBody::NeedChunks { parent, chunk_ids } => {
            w.u8(BODY_NEED_CHUNKS);
            w.fixed(parent.as_bytes());
            w.u32(u32_len(chunk_ids.len())?);
            for id in chunk_ids {
                w.fixed(id.as_bytes());
            }
        }
        OpBody::EpochTransition {
            old_epoch,
            new_epoch,
            revoked,
            snapshot,
            envelopes,
        } => {
            w.u8(BODY_EPOCH);
            w.u64(old_epoch.as_u64());
            w.u64(new_epoch.as_u64());
            w.fixed(revoked.as_bytes());
            encode_snapshot(w, snapshot)?;
            w.u32(u32_len(envelopes.len())?);
            for env in envelopes {
                encode_device_wrap(w, env)?;
            }
        }
    }
    Ok(())
}

fn decode_body(r: &mut R<'_>) -> io::Result<OpBody> {
    match r.u8()? {
        BODY_PUT => Ok(OpBody::Put {
            envelope: decode_object(r)?,
        }),
        BODY_PIN => Ok(OpBody::Pin {
            object_id: ObjectId::from_bytes(r.fixed32()?),
            at: Timestamp::from_millis(r.u64()?),
        }),
        BODY_TOMBSTONE => Ok(OpBody::Tombstone {
            object_id: ObjectId::from_bytes(r.fixed32()?),
            at: Timestamp::from_millis(r.u64()?),
        }),
        BODY_SCRATCH => Ok(OpBody::Scratch {
            envelope: decode_object(r)?,
        }),
        BODY_CHUNK => Ok(OpBody::Chunk {
            parent: ObjectId::from_bytes(r.fixed32()?),
            envelope: decode_object(r)?,
        }),
        BODY_NEED_CHUNKS => {
            let parent = ObjectId::from_bytes(r.fixed32()?);
            let n = r.u32()? as usize;
            let mut chunk_ids = Vec::with_capacity(n);
            for _ in 0..n {
                chunk_ids.push(ChunkId::from_bytes(r.fixed32()?));
            }
            Ok(OpBody::NeedChunks { parent, chunk_ids })
        }
        BODY_EPOCH => {
            let old_epoch = EpochId::new(r.u64()?);
            let new_epoch = EpochId::new(r.u64()?);
            let revoked = DeviceId::from_bytes(r.fixed32()?);
            let snapshot = decode_snapshot(r)?;
            let n = r.u32()? as usize;
            let mut envelopes = Vec::with_capacity(n);
            for _ in 0..n {
                envelopes.push(decode_device_wrap(r)?);
            }
            Ok(OpBody::EpochTransition {
                old_epoch,
                new_epoch,
                revoked,
                snapshot,
                envelopes,
            })
        }
        _ => Err(invalid("unknown op body kind")),
    }
}

fn encode_object(w: &mut W, env: &EncryptedObject) -> io::Result<()> {
    w.u16(env.version);
    w.fixed(env.object_id.as_bytes());
    w.u64(env.epoch.as_u64());
    encode_aead(w, env.algorithm);
    w.blob(&env.nonce)?;
    encode_key_envelope(w, &env.wrapped_dek)?;
    w.blob(&env.ciphertext)?;
    w.fixed(env.ciphertext_hash.as_bytes());
    match env.content_kind {
        None => w.u8(0),
        Some(kind) => {
            w.u8(1);
            w.str16(kind.as_wire_str())?;
        }
    }
    match env.origin {
        None => w.u8(0),
        Some(origin) => {
            w.u8(1);
            w.fixed(origin.as_bytes());
        }
    }
    Ok(())
}

fn decode_object(r: &mut R<'_>) -> io::Result<EncryptedObject> {
    Ok(EncryptedObject {
        version: r.u16()?,
        object_id: ObjectId::from_bytes(r.fixed32()?),
        epoch: EpochId::new(r.u64()?),
        algorithm: decode_aead(r)?,
        nonce: r.blob()?.to_vec(),
        wrapped_dek: decode_key_envelope(r)?,
        ciphertext: r.blob()?.to_vec(),
        ciphertext_hash: Hash::from_bytes(r.fixed32()?),
        content_kind: match r.u8()? {
            0 => None,
            1 => Some(
                ContentKind::from_wire_str(&r.str16()?)
                    .ok_or_else(|| invalid("unknown content kind"))?,
            ),
            _ => return Err(invalid("invalid content-kind flag")),
        },
        origin: match r.u8()? {
            0 => None,
            1 => Some(DeviceId::from_bytes(r.fixed32()?)),
            _ => return Err(invalid("invalid origin flag")),
        },
    })
}

fn encode_key_envelope(w: &mut W, env: &KeyEnvelope) -> io::Result<()> {
    w.u16(env.version);
    w.u64(env.epoch.as_u64());
    encode_aead(w, env.algorithm);
    w.blob(&env.nonce)?;
    w.blob(&env.ciphertext)?;
    Ok(())
}

fn decode_key_envelope(r: &mut R<'_>) -> io::Result<KeyEnvelope> {
    Ok(KeyEnvelope {
        version: r.u16()?,
        epoch: EpochId::new(r.u64()?),
        algorithm: decode_aead(r)?,
        nonce: r.blob()?.to_vec(),
        ciphertext: r.blob()?.to_vec(),
    })
}

fn encode_aead(w: &mut W, algorithm: AeadAlgorithm) {
    match algorithm {
        AeadAlgorithm::XChaCha20Poly1305 => w.u8(1),
        AeadAlgorithm::Aes256Gcm => w.u8(2),
    }
}

fn decode_aead(r: &mut R<'_>) -> io::Result<AeadAlgorithm> {
    match r.u8()? {
        1 => Ok(AeadAlgorithm::XChaCha20Poly1305),
        2 => Ok(AeadAlgorithm::Aes256Gcm),
        _ => Err(invalid("unknown aead algorithm")),
    }
}

fn encode_snapshot(w: &mut W, snap: &MembershipSnapshot) -> io::Result<()> {
    encode_vault_root(w, &snap.vault_root);
    w.u64(snap.generation);
    w.u64(snap.epoch.as_u64());
    w.u32(u32_len(snap.certificates.len())?);
    for cert in &snap.certificates {
        encode_certificate(w, cert)?;
    }
    w.u32(u32_len(snap.mailbox_bindings.len())?);
    for b in &snap.mailbox_bindings {
        encode_mailbox_binding(w, b)?;
    }
    w.fixed(snap.snapshot_signature.as_bytes());
    Ok(())
}

fn decode_snapshot(r: &mut R<'_>) -> io::Result<MembershipSnapshot> {
    let vault_root = decode_vault_root(r)?;
    let generation = r.u64()?;
    let epoch = EpochId::new(r.u64()?);
    let n_certs = r.u32()? as usize;
    let mut certificates = Vec::with_capacity(n_certs);
    for _ in 0..n_certs {
        certificates.push(decode_certificate(r)?);
    }
    let n_binds = r.u32()? as usize;
    let mut mailbox_bindings = Vec::with_capacity(n_binds);
    for _ in 0..n_binds {
        mailbox_bindings.push(decode_mailbox_binding(r)?);
    }
    Ok(MembershipSnapshot {
        vault_root,
        generation,
        epoch,
        certificates,
        mailbox_bindings,
        snapshot_signature: SignatureBytes::from_bytes(r.fixed64()?),
    })
}

fn encode_vault_root(w: &mut W, root: &VaultRoot) {
    w.fixed(root.vault_id.as_bytes());
    w.fixed(root.root_signing_pubkey.as_bytes());
    w.u64(root.generation);
}

fn decode_vault_root(r: &mut R<'_>) -> io::Result<VaultRoot> {
    Ok(VaultRoot {
        vault_id: VaultId::from_bytes(r.fixed32()?),
        root_signing_pubkey: SigningPublicKey::from_bytes(r.fixed32()?),
        generation: r.u64()?,
    })
}

fn encode_certificate(w: &mut W, cert: &MembershipCertificate) -> io::Result<()> {
    w.fixed(cert.vault_id.as_bytes());
    w.fixed(cert.device_id.as_bytes());
    w.fixed(cert.signing_pubkey.as_bytes());
    encode_kem(w, &cert.kem_pubkey)?;
    w.u8(match cert.role {
        MemberRole::Member => 0,
        MemberRole::Authority => 1,
    });
    encode_caps(w, &cert.capabilities)?;
    w.u64(cert.serial);
    w.u64(cert.epoch.as_u64());
    w.fixed(cert.issuer.as_bytes());
    w.fixed(cert.issuer_signing_pubkey.as_bytes());
    w.u64(cert.issued_at.as_millis());
    match cert.expires_at {
        None => w.u8(0),
        Some(ts) => {
            w.u8(1);
            w.u64(ts.as_millis());
        }
    }
    w.fixed(&cert.request_hash);
    w.fixed(cert.issuer_signature.as_bytes());
    Ok(())
}

fn decode_certificate(r: &mut R<'_>) -> io::Result<MembershipCertificate> {
    Ok(MembershipCertificate {
        vault_id: VaultId::from_bytes(r.fixed32()?),
        device_id: DeviceId::from_bytes(r.fixed32()?),
        signing_pubkey: SigningPublicKey::from_bytes(r.fixed32()?),
        kem_pubkey: decode_kem(r)?,
        role: match r.u8()? {
            0 => MemberRole::Member,
            1 => MemberRole::Authority,
            _ => return Err(invalid("unknown member role")),
        },
        capabilities: decode_caps(r)?,
        serial: r.u64()?,
        epoch: EpochId::new(r.u64()?),
        issuer: DeviceId::from_bytes(r.fixed32()?),
        issuer_signing_pubkey: SigningPublicKey::from_bytes(r.fixed32()?),
        issued_at: Timestamp::from_millis(r.u64()?),
        expires_at: match r.u8()? {
            0 => None,
            1 => Some(Timestamp::from_millis(r.u64()?)),
            _ => return Err(invalid("invalid certificate expiry flag")),
        },
        request_hash: r.fixed32()?,
        issuer_signature: SignatureBytes::from_bytes(r.fixed64()?),
    })
}

fn encode_kem(w: &mut W, kem: &HybridKemPublicKey) -> io::Result<()> {
    w.fixed(kem.x25519.as_bytes());
    w.blob(kem.ml_kem_768.as_bytes())
}

fn decode_kem(r: &mut R<'_>) -> io::Result<HybridKemPublicKey> {
    let x25519 = X25519PublicKey::from_bytes(r.fixed32()?);
    let ml = r.blob()?.to_vec();
    let ml_kem_768 =
        MlKem768PublicKey::from_bytes(ml).map_err(|_| invalid("invalid ml-kem public key"))?;
    Ok(HybridKemPublicKey::new(x25519, ml_kem_768))
}

fn encode_caps(w: &mut W, caps: &DeviceCapabilities) -> io::Result<()> {
    w.u8(u8::from(caps.can_approve_enrollment));
    w.u8(u8::from(caps.can_issue_grants));
    match &caps.platform {
        None => w.u8(0),
        Some(p) => {
            w.u8(1);
            w.str16(p)?;
        }
    }
    Ok(())
}

fn decode_caps(r: &mut R<'_>) -> io::Result<DeviceCapabilities> {
    Ok(DeviceCapabilities {
        can_approve_enrollment: r.flag()?,
        can_issue_grants: r.flag()?,
        platform: match r.u8()? {
            0 => None,
            1 => Some(r.str16()?),
            _ => return Err(invalid("invalid platform flag")),
        },
    })
}

fn encode_mailbox_binding(w: &mut W, b: &MailboxBinding) -> io::Result<()> {
    w.fixed(b.device_id.as_bytes());
    w.str16(&b.mailbox_id)?;
    w.str16(&b.write_cap)?;
    Ok(())
}

fn decode_mailbox_binding(r: &mut R<'_>) -> io::Result<MailboxBinding> {
    Ok(MailboxBinding {
        device_id: DeviceId::from_bytes(r.fixed32()?),
        mailbox_id: r.str16()?,
        write_cap: r.str16()?,
    })
}

fn encode_device_wrap(w: &mut W, env: &DeviceEpochWrap) -> io::Result<()> {
    w.fixed(env.device_id.as_bytes());
    w.fixed(&env.wrap.x25519_ephemeral);
    w.blob(&env.wrap.ml_kem_ciphertext)?;
    w.fixed(&env.wrap.nonce);
    w.blob(&env.wrap.ciphertext)?;
    Ok(())
}

fn decode_device_wrap(r: &mut R<'_>) -> io::Result<DeviceEpochWrap> {
    Ok(DeviceEpochWrap {
        device_id: DeviceId::from_bytes(r.fixed32()?),
        wrap: HybridEpochWrap {
            x25519_ephemeral: r.fixed32()?,
            ml_kem_ciphertext: r.blob()?.to_vec(),
            nonce: r.fixed24()?,
            ciphertext: r.blob()?.to_vec(),
        },
    })
}

fn u32_len(n: usize) -> io::Result<u32> {
    u32::try_from(n).map_err(|_| invalid("list exceeds u32 length"))
}

#[derive(Default)]
struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn fixed(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }

    fn blob(&mut self, b: &[u8]) -> io::Result<()> {
        self.u32(u32_len(b.len())?);
        self.fixed(b);
        Ok(())
    }

    fn str16(&mut self, s: &str) -> io::Result<()> {
        let len = u16::try_from(s.len()).map_err(|_| invalid("string exceeds u16 length"))?;
        self.u16(len);
        self.fixed(s.as_bytes());
        Ok(())
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(invalid("truncated peer payload"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let mut arr = [0u8; 2];
        arr.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(arr))
    }

    fn u32(&mut self) -> io::Result<u32> {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(arr))
    }

    fn u64(&mut self) -> io::Result<u64> {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(arr))
    }

    fn fixed24(&mut self) -> io::Result<[u8; 24]> {
        let mut arr = [0u8; 24];
        arr.copy_from_slice(self.take(24)?);
        Ok(arr)
    }

    fn fixed32(&mut self) -> io::Result<[u8; 32]> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(self.take(32)?);
        Ok(arr)
    }

    fn fixed64(&mut self) -> io::Result<[u8; 64]> {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(self.take(64)?);
        Ok(arr)
    }

    fn blob(&mut self) -> io::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn str16(&mut self) -> io::Result<String> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| invalid("invalid utf-8 in peer payload"))
    }

    fn flag(&mut self) -> io::Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("invalid boolean flag")),
        }
    }

    fn finish(self) -> io::Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid("trailing peer payload bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn hello() -> SessionHello {
        SessionHello {
            vault_id: VaultId::from_bytes([0x11; 32]),
            device_id: DeviceId::from_bytes([0x22; 32]),
            signature: sig_hex(&[0x33; 64]),
        }
    }

    fn small_op() -> SignedOperation {
        SignedOperation {
            seq: 7,
            op_id: "aabbccddeeff0011".into(),
            vault_id: VaultId::from_bytes([0x11; 32]),
            epoch: EpochId::new(1),
            origin: DeviceId::from_bytes([0x22; 32]),
            body: OpBody::Pin {
                object_id: ObjectId::from_bytes([0x44; 32]),
                at: Timestamp::from_millis(1_700_000_000_000),
            },
            signature: sig_hex(&[0x55; 64]),
        }
    }

    async fn roundtrip(frame: &PeerFrame) -> PeerFrame {
        let mut buf = Vec::new();
        write_peer_frame(&mut buf, frame).await.unwrap();
        assert_eq!(&buf[..4], b"SHLF");
        assert_ne!(buf.first().copied(), Some(b'{'));
        let mut cur = Cursor::new(buf);
        read_peer_frame(&mut cur).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn roundtrip_session_hello() {
        let frame = PeerFrame::Hello(hello());
        assert_eq!(roundtrip(&frame).await, frame);
    }

    #[tokio::test]
    async fn roundtrip_peer_message_have() {
        let frame = PeerFrame::Message(PeerMessage::Have {
            cursors: vec![
                OriginCursor {
                    origin: DeviceId::from_bytes([0x01; 32]),
                    seq: 3,
                },
                OriginCursor {
                    origin: DeviceId::from_bytes([0x02; 32]),
                    seq: 9,
                },
            ],
        });
        assert_eq!(roundtrip(&frame).await, frame);
    }

    #[tokio::test]
    async fn roundtrip_peer_message_op() {
        let frame = PeerFrame::Message(PeerMessage::Op {
            op: Box::new(small_op()),
        });
        assert_eq!(roundtrip(&frame).await, frame);
    }

    #[tokio::test]
    async fn reject_bad_magic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"XXXX");
        buf.push(CODEC_VERSION);
        buf.extend_from_slice(&0u32.to_be_bytes());
        let err = read_peer_frame(&mut Cursor::new(buf)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("magic"));
    }

    #[tokio::test]
    async fn reject_unknown_version() {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.push(99);
        buf.extend_from_slice(&0u32.to_be_bytes());
        let err = read_peer_frame(&mut Cursor::new(buf)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("version"));
    }

    #[tokio::test]
    async fn reject_oversize_length() {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.push(CODEC_VERSION);
        let too_big = u32::try_from(MAX_FRAME_BYTES).unwrap().saturating_add(1);
        buf.extend_from_slice(&too_big.to_be_bytes());
        let err = read_peer_frame(&mut Cursor::new(buf)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("MAX_FRAME_BYTES"));
    }

    #[tokio::test]
    async fn json_signed_operation_is_not_a_peer_frame() {
        let json = serde_json::to_vec(&small_op()).unwrap();
        let err = read_peer_frame(&mut Cursor::new(json)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
