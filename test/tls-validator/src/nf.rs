use e2d2::headers::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use e2d2::state::*;
use e2d2::utils::Flow;
use fnv::FnvHasher;
use rustls::internal::msgs::{codec::Codec, enums::ContentType, message::Message as TLSMessage};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;

// use rustls::internal::msgs::{
//     codec::Codec, enums::ContentType, enums::ServerNameType, handshake::ClientHelloPayload,
//     handshake::HandshakePayload, handshake::HasServerExtensions, handshake::ServerHelloPayload,
//     handshake::ServerNamePayload, message::Message as TLSMessage, message::MessagePayload,
// };

type FnvHash = BuildHasherDefault<FnvHasher>;
const BUFFER_SIZE: usize = 2048;
const READ_SIZE: usize = 256;

/// Read payload.
fn read_payload(rb: &mut ReorderedBuffer, to_read: usize, flow: Flow, payload_cache: &mut HashMap<Flow, Vec<u8>>) {
    let mut read_buf = [0; READ_SIZE];
    let mut so_far = 0;
    while to_read > so_far {
        let payload = payload_cache.entry(flow).or_insert(Vec::new());
        let n = rb.read_data(&mut read_buf);
        so_far += n;
        payload.extend(&read_buf[..n]);
    }
}

/// TLS validator:
///
/// 1. identify TLS handshake messages.
/// 2. group the same handshake messages into flows
/// 3. defragment the packets into certificate(s)
/// 4. verify that the certificate is valid.
pub fn validator<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    let mut rb_map = HashMap::<Flow, ReorderedBuffer, FnvHash>::with_hasher(Default::default());

    // Create the payload cache
    let mut payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .parse::<MacHeader>()
        .transform(box move |p| {
            p.get_mut_header().swap_addresses();
        })
        .parse::<IpHeader>()
        .group_by(
            2,
            box move |p| if p.get_header().protocol() == 6 { 0 } else { 1 },
            sched,
        );

    // Create the pipeline--we perform the actual packet processing here.
    let pipe = groups
        .get_group(0)
        .unwrap()
        .metadata(box move |p| {
            let flow = p.get_header().flow().unwrap();
            println!("And the flow is: {:?}", flow);
            flow
        })
        .parse::<TcpHeader>()
        .transform(box move |p| {
            let flow = p.read_metadata();
            let mut seq = p.get_header().seq_num();
            let tcph = p.get_header();
            println!("TCP Headers: {}", tcph);
            //let mut seg_len = p.get_header().seg_len();
            //println!("seg length is {}", seg_len);
            match rb_map.entry(*flow) {
                // occupied means that there already exists an entry for the flow
                Entry::Occupied(mut e) => {
                    println!("\npkt #{} is occupied!", seq);
                    println!("\nEntry is {}", e);
                    // get entry
                    let b = e.get_mut();

                    let tls_result = TLSMessage::read_bytes(&p.get_payload());
                    let result = b.add_data(seq, p.get_payload());

                    match tls_result {
                        Some(packet) => {
                            // TODO: need to reassemble tcp segements
                            if packet.typ == ContentType::Handshake {
                                println!("Packet match handshake!");
                                println!("{:?}", packet);
                                match result {
                                    InsertionResult::Inserted { available, .. } => {
                                        println!("Inserted");
                                        read_payload(b, available, *flow, &mut payload_cache);
                                    }
                                    InsertionResult::OutOfMemory { written, .. } => {
                                        if written == 0 {
                                            println!("Resetting since receiving data that is too far ahead");
                                            b.reset();
                                            b.seq(seq, p.get_payload());
                                        }
                                    }
                                }
                            } else {
                                println!("Packet type is not matched!")
                            }
                        }
                        None => {
                            println!("\nThere is nothing, that is why we should insert the packet!!!\n");
                            println!("And the flow is: {:?}", flow);
                            match result {
                                InsertionResult::Inserted { available, .. } => {
                                    println!("Inserted");
                                    read_payload(b, available, *flow, &mut payload_cache);
                                }
                                InsertionResult::OutOfMemory { written, .. } => {
                                    if written == 0 {
                                        println!("Resetting since receiving data that is too far ahead");
                                        b.reset();
                                        b.seq(seq, p.get_payload());
                                    }
                                }
                            }
                        }
                    }
                    if p.get_header().rst_flag() {
                        println!("Packet has a reset flag--removing the entry");
                        e.remove_entry();
                    } else if p.get_header().fin_flag() {
                        println!("Packet has a fin flag");
                        match payload_cache.entry(*flow) {
                            Entry::Occupied(e) => {
                                let (_, payload) = e.remove_entry();
                                println!("Occupied: {}\n", String::from_utf8_lossy(&payload));
                            }
                            Entry::Vacant(_) => {
                                println!("dumped an empty payload for Flow={:?}", flow);
                            }
                        }
                        e.remove_entry();
                    }
                }
                // Vacant means that the entry for doesn't exist yet--we need to create one first
                Entry::Vacant(e) => {
                    println!("\nPkt #{} is Vacant", seq);
                    println!("\nEntry is {}", e);
                    match ReorderedBuffer::new(BUFFER_SIZE) {
                        Ok(mut b) => {
                            println!("  1: Has allocated a new buffer: {}", b);
                            if p.get_header().syn_flag() {
                                println!("    2: packet has a syn flag");
                                seq += 1;
                            } else {
                                println!("    2: packet recv for untracked flow did not have a syn flag, skipped");
                            }

                            let tls_result = TLSMessage::read_bytes(&p.get_payload());
                            let result = b.seq(seq, p.get_payload());

                            // match to find TLS handshake
                            match tls_result {
                                Some(packet) => {
                                    if packet.typ == ContentType::Handshake {
                                        println!("\n ************************************************ ");
                                        println!("      3: Packet match handshake!");
                                        // match to insert packet into the cache
                                        println!("      \n{:?}\n", packet);
                                        match result {
                                            InsertionResult::Inserted { available, .. } => {
                                                read_payload(&mut b, available, *flow, &mut payload_cache);
                                                println!("      4: This packet is inserted");
                                            }
                                            InsertionResult::OutOfMemory { .. } => {
                                                println!("      4: Too big a packet?");
                                            }
                                        }
                                    } else {
                                        println!("      3: Packet is not a TLS handshake so not displaying");
                                        //println!("  3: {:?}", packet);
                                    }
                                }
                                None => {
                                    println!("      3: None in the result");
                                }
                            }
                            e.insert(b);
                        }
                        Err(_) => {
                            println!("\npkt #{} Failed to allocate a buffer for the new flow!", seq);
                            ()
                        }
                    }
                }
            }
        })
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}