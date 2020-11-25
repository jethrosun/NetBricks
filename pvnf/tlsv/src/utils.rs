use e2d2::utils::Flow;
use rustls::internal::msgs::{
    codec::Codec,
    enums::{ContentType, ExtensionType},
    handshake::HandshakePayload::{Certificate as CertificatePayload, ClientHello},
    handshake::{ClientExtension, ServerName, ServerNamePayload},
    message::{Message as TLSMessage, MessagePayload},
};
use rustls::{ProtocolVersion, RootCertStore, ServerCertVerifier, TLSError, WebPKIVerifier};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use webpki;
use webpki_roots;

// TODO: move to failure crate!
#[derive(Debug, Clone)]
pub struct CertificateNotExtractedError;

/// Update a TLS flow entry by updating the entry with continuing TLS frame.
pub fn tlsf_update(e: Entry<Flow, Vec<u8>>, payload: &[u8]) {
    e.and_modify(|e| {
        e.extend(payload);
    });
}

/// Retrieve server name from the packet
pub fn get_server_name(buf: &[u8]) -> Option<webpki::DNSName> {
    match on_frame(&buf) {
        Some((handshake, _)) => match handshake.payload {
            ClientHello(x) => {
                let iterator = x.extensions.iter();
                let mut result = None;
                for val in iterator {
                    if ClientExtension::get_type(val) == ExtensionType::ServerName {
                        let server_name = match val {
                            ClientExtension::ServerName(x) => x,
                            _ => return None,
                        };
                        let ServerName { typ: _, payload: x } = &server_name[0];

                        if let ServerNamePayload::HostName(dns_name) = x.clone() {
                            result = Some(dns_name);
                        }
                    } else {
                        continue;
                    }
                }
                result
            }
            _ => None,
        },
        None => None,
    }
}

/// Retrieve current system time and use it to validate certificates
pub fn current_time() -> Result<webpki::Time, TLSError> {
    match webpki::Time::try_from(std::time::SystemTime::now()) {
        Ok(current_time) => Ok(current_time),
        _ => Err(TLSError::FailedToGetCurrentTime),
    }
}

static V: &WebPKIVerifier = &WebPKIVerifier { time: current_time };

/// Try to extract certificate
pub fn try_extracted_cert(certs: Vec<rustls::Certificate>, dns_name: webpki::DNSName) -> bool {
    let mut anchors = RootCertStore::empty();
    anchors.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let result = V.verify_server_cert(&anchors, &certs[..], dns_name.as_ref(), &[]);
    match result {
        Ok(_) => true,
        Err(e) => false,
    }
}

/// Parse a slice of raw bytes into a TLS frame and the size of payload.
pub fn on_frame(rest: &[u8]) -> Option<(rustls::internal::msgs::handshake::HandshakeMessagePayload, usize)> {
    match TLSMessage::read_bytes(&rest) {
        Some(mut packet) => {
            let frame_len = packet.payload.length();
            if packet.typ == ContentType::Handshake && packet.decode_payload() {
                if let MessagePayload::Handshake(x) = packet.payload {
                    Some((x, frame_len))
                } else {
                    None
                }
            } else {
                None
            }
        }
        None => None,
    }
}

/// Parse raw bytes into tls frames.
pub fn parse_tls_frame(buf: &[u8]) -> Result<Vec<rustls::Certificate>, CertificateNotExtractedError> {
    // TLS Header length is 5.
    let tls_hdr_len = 5;
    let mut _version = ProtocolVersion::Unknown(0x0000);

    //
    //  TLS FRAME One: ServerHello
    //

    let offset1 = match on_frame(&buf) {
        Some((_handshake1, offset1)) => offset1,
        None => return Err(CertificateNotExtractedError),
    };

    let (_, rest) = buf.split_at(offset1 + tls_hdr_len);

    //
    //  TLS FRAME Two: Certificate
    //

    let (handshake2, _offset2) = match on_frame(&rest) {
        Some((handshake2, _offset2)) => (handshake2, _offset2),
        None => {
            return Err(CertificateNotExtractedError);
        }
    };

    match handshake2.payload {
        CertificatePayload(payload) => Ok(payload),
        _ => Err(CertificateNotExtractedError),
    }
}

/// validate the extracted certificates with out of order segments
#[allow(clippy::too_many_arguments)]
pub fn unordered_validate(
    dns_name: webpki::DNSName,
    flow: &Flow,
    cert_count: &mut usize,
    unsafe_connection: &mut HashSet<Flow>,
    tmp_payload_cache: &mut HashMap<Flow, Vec<u8>>,
    tmp_seqnum_map: &mut HashMap<Flow, (u32, u32)>,
    payload_cache: &mut HashMap<Flow, Vec<u8>>,
    seqnum_map: &mut HashMap<Flow, u32>,
) {
    // We need to retrieve the DNS name from the entry of the current flow, and
    // also parse the entry for the reverse flow.

    let rev_flow = flow.reverse_flow();
    // We have out-of-order segment for this TLS connection.
    let (tmp_entry_seqnum, _) = tmp_seqnum_map.get(&rev_flow).unwrap();
    if seqnum_map.get(&rev_flow).unwrap() == tmp_entry_seqnum {
        if payload_cache.contains_key(&rev_flow) && tmp_payload_cache.contains_key(&rev_flow) {
            let (_, tmp_entry) = tmp_payload_cache.remove_entry(&rev_flow).unwrap();
            let _ = tmp_seqnum_map.remove_entry(&rev_flow);
            let _ = seqnum_map.remove_entry(&rev_flow);
            let (_, mut e) = payload_cache.remove_entry(&rev_flow).unwrap();
            e.extend(tmp_entry);
            let certs = parse_tls_frame(&e);

            if let Ok(chain) = certs {
                let result = try_extracted_cert(chain, dns_name);
                *cert_count += 1;
                if *cert_count % 1_000_usize == 0 {
                    println!("cert count is {}k", *cert_count / 1_000);
                }
                if !result {
                    unsafe_connection.insert(*flow);
                    unsafe_connection.insert(rev_flow);
                }
            }
        }
    }
}

/// validate certificates without out of order segments
pub fn ordered_validate(
    dns_name: webpki::DNSName,
    flow: &Flow,
    cert_count: &mut usize,
    unsafe_connection: &mut HashSet<Flow>,
    payload_cache: &mut HashMap<Flow, Vec<u8>>,
    seqnum_map: &mut HashMap<Flow, u32>,
) {
    let rev_flow = flow.reverse_flow();
    // Retrieve the payload cache and extract the cert.
    if payload_cache.contains_key(&rev_flow) {
        let (_, e) = payload_cache.remove_entry(&rev_flow).unwrap();
        let _ = seqnum_map.remove_entry(&rev_flow);
        let certs = parse_tls_frame(&e);

        if let Ok(chain) = certs {
            let result = try_extracted_cert(chain, dns_name);

            *cert_count += 1;

            if *cert_count % 1_000_usize == 0 {
                println!("cert count is {}k", *cert_count / 1_000);
            }
            if !result {
                unsafe_connection.insert(*flow);
                unsafe_connection.insert(rev_flow);
            }
        }
    }
}
