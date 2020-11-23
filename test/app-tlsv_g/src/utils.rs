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
        debug!("Before writing more bytes {:?}", e.len());
        e.extend(payload);
        debug!("After writing the bytes {:?}", e.len());
    });
}

pub fn get_server_name(buf: &[u8]) -> Option<webpki::DNSName> {
    info!("Matching server name");

    match on_frame(&buf) {
        Some((handshake, _)) => {
            match handshake.payload {
                ClientHello(x) => {
                    //info!("is client hello: {:?}\n", x.extensions);
                    let mut _iterator = x.extensions.iter();
                    let mut result = None;
                    while let Some(val) = _iterator.next() {
                        if ClientExtension::get_type(val) == ExtensionType::ServerName {
                            //info!("Getting a ServerName type {:?}\n", val);
                            let server_name = match val {
                                ClientExtension::ServerName(x) => x,
                                _ => return None,
                            };
                            let ServerName { typ: _, payload: x } = &server_name[0];

                            match x.clone() {
                                ServerNamePayload::HostName(dns_name) => {
                                    info!("DNS name is : {:?}", dns_name);
                                    result = Some(dns_name);
                                }
                                _ => (),
                            }
                        } else {
                            continue;
                        }
                    }
                    info!("info: Result is {:?}", result);
                    info!("info:",);
                    result
                }
                _ => {
                    info!("not client hello",);
                    None
                }
            }
        }
        None => {
            info!("On frame read none bytes",);
            return None;
        }
    }
}

pub fn current_time() -> Result<webpki::Time, TLSError> {
    match webpki::Time::try_from(std::time::SystemTime::now()) {
        Ok(current_time) => Ok(current_time),
        _ => Err(TLSError::FailedToGetCurrentTime),
    }
}

static V: &'static WebPKIVerifier = &WebPKIVerifier { time: current_time };

pub fn test_extracted_cert(certs: Vec<rustls::Certificate>, dns_name: webpki::DNSName) -> bool {
    info!("info: validate certs",);
    debug!("dns name is {:?}\n", dns_name);
    //info!("certs are {:?}\n", certs);
    let mut anchors = RootCertStore::empty();
    anchors.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    //let dns_name = webpki::DNSNameRef::try_from_ascii_str("github.com").unwrap();
    let result = V.verify_server_cert(&anchors, &certs[..], dns_name.as_ref(), &[]);
    match result {
        Ok(_) => {
            debug!("tlsv result: Valid cert!\n");
            return true;
        }
        Err(e) => {
            debug!("tlsv result: Non valid cert with {}\n", e);
            false
        }
    }
}

/// Parse a slice of bytes into a TLS frame and the size of payload.
pub fn on_frame(rest: &[u8]) -> Option<(rustls::internal::msgs::handshake::HandshakeMessagePayload, usize)> {
    match TLSMessage::read_bytes(&rest) {
        Some(mut packet) => {
            // info!("\nParsing this TLS frame is \n{:x?}", packet);
            // info!("length of the packet payload is {}\n", packet.payload.length());

            let frame_len = packet.payload.length();
            if packet.typ == ContentType::Handshake && packet.decode_payload() {
                if let MessagePayload::Handshake(x) = packet.payload {
                    Some((x, frame_len))
                } else {
                    info!("Message is not handshake",);
                    None
                }
            } else {
                info!("Packet type doesn't match or we can't decode payload",);
                None
            }
        }
        None => {
            //info!("ON FRAME: Read bytes but got None {:x?}", rest);
            debug!("ON FRAME: Read bytes but got None");
            None
        }
    }
}

/// Parse the bytes into tls frames.
pub fn parse_tls_frame(buf: &[u8]) -> Result<Vec<rustls::Certificate>, CertificateNotExtractedError> {
    // TLS Header length is 5.
    let tls_hdr_len = 5;
    let mut _version = ProtocolVersion::Unknown(0x0000);

    /////////////////////////////////////////////
    //
    //  TLS FRAME One: ServerHello
    //
    /////////////////////////////////////////////

    // match handshake1.payload {
    //     ClientHello(payload) => {
    //         info!("ClientHello",);
    //         info!("{:x?}", payload);
    //     }
    //     ServerHello(payload) => {
    //         info!("{:x?}", payload);
    //     }
    //     _ => info!("None"),
    // }
    let offset1 = match on_frame(&buf) {
        Some((_handshake1, offset1)) => offset1,
        None => return Err(CertificateNotExtractedError),
    };

    let (_, rest) = buf.split_at(offset1 + tls_hdr_len);
    info!("And the magic number is {}\n", offset1 + tls_hdr_len);
    //info!("info: The SECOND TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Two: Certificate
    //
    /////////////////////////////////////////////

    // if on_frame(&rest).is_none() {
    //     info!("info: Get None, abort",);
    //     return Err(CertificateNotExtractedError);
    // }
    // let (handshake2, _offset2) = on_frame(&rest).expect("oh no! parsing the Certificate failed!!");

    info!("Working on the second frame...");

    info!("Trying to read the frame using on_frame...");
    let (handshake2, _offset2) = match on_frame(&rest) {
        Some((handshake2, _offset2)) => (handshake2, _offset2),
        None => {
            debug!("Getting the certificate failed, got none");
            return Err(CertificateNotExtractedError);
        }
    };

    let certs = match handshake2.payload {
        CertificatePayload(payload) => {
            //info!("Certificate payload is\n{:x?}", payload);
            info!("Parsing the certificate payload..",);

            Ok(payload)
        }
        _ => {
            info!("None");
            Err(CertificateNotExtractedError)
        }
    };

    certs
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
    let rev_flow = flow.reverse_flow();
    // We need to retrieve the DNS name from the entry of the current flow, and
    // also parse the entry for the reverse flow.
    debug!("OOO: We have OOO segment for this connection");
    // We have out-of-order segment for this TLS connection.
    let (tmp_entry_seqnum, _) = tmp_seqnum_map.get(&rev_flow).unwrap();
    if seqnum_map.get(&rev_flow).unwrap() == tmp_entry_seqnum {
        debug!("OOO: We are ready to merge entries in two payload caches together!!!");
        if payload_cache.contains_key(&rev_flow) && tmp_payload_cache.contains_key(&rev_flow) {
            // info!("1");
            let (_, tmp_entry) = tmp_payload_cache.remove_entry(&rev_flow).unwrap();
            info!("size of the tmp entry is {:?}", tmp_entry.len());
            // info!("2");
            let _ = tmp_seqnum_map.remove_entry(&rev_flow);
            let _ = seqnum_map.remove_entry(&rev_flow);
            // info!("3");
            let (_, mut e) = payload_cache.remove_entry(&rev_flow).unwrap();
            info!("size of the entry is {:?}", e.len());
            // info!("4");
            e.extend(tmp_entry);
            info!("size of the merged entry is {:?}", e.len());
            // info!("5");
            let certs = parse_tls_frame(&e);
            info!("info: We now retrieve the certs from the tcp payload");

            match certs {
                Ok(chain) => {
                    debug!("Testing our cert");
                    let result = try_extracted_cert(chain, dns_name);
                    *cert_count += 1;
                    if *cert_count % 1_000_usize == 0 {
                        println!("cert count is {}k", *cert_count / 1_000);
                    }
                    if !result {
                        debug!("info: Certificate validation failed, both flows' connection need to be reset\n{:?}\n{:?}\n", flow, rev_flow);
                        unsafe_connection.insert(*flow);
                        unsafe_connection.insert(rev_flow);
                    }
                }
                Err(e) => {
                    debug!("ISSUE: match cert incurs error: {:?}\n", e);
                }
            }
        } else {
            debug!("ISSUE: Oops, the payload cache doesn't have the entry for this flow");
        }
    } else {
        debug!("ISSUE: Oops the expected seq# from our PLC entry doesn't match the seq# from the TPC entry");
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
    info!("No out of order segment for this connection");
    // Retrieve the payload cache and extract the cert.
    if payload_cache.contains_key(&rev_flow) {
        // info!("1");
        let (_, e) = payload_cache.remove_entry(&rev_flow).unwrap();
        // info!("2");
        let _ = seqnum_map.remove_entry(&rev_flow);
        // info!("3");
        let certs = parse_tls_frame(&e);
        info!("info: We now retrieve the certs from the tcp payload");
        info!("info: flow is {:?}", flow);

        match certs {
            Ok(chain) => {
                debug!("Testing our cert");
                let result = try_extracted_cert(chain, dns_name);

                *cert_count += 1;

                if *cert_count % 1_000_usize == 0 {
                    println!("cert count is {}k", *cert_count / 1_000);
                }
                if !result {
                    debug!(
                        "info: Certificate validation failed, both flows' connection need to be reset\n{:?}\n{:?}\n",
                        flow, rev_flow
                    );
                    unsafe_connection.insert(*flow);
                    unsafe_connection.insert(rev_flow);
                }
            }
            Err(e) => {
                debug!("ISSUE: match cert incurs error: {:?}\n", e);
            }
        }
    } else {
        debug!("ISSUE: Oops, the payload cache doesn't have the entry for this flow");
    }
}
