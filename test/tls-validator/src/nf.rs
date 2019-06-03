use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::state::{InsertionResult, ReorderedBuffer};
use e2d2::utils::Flow;
use fnv::FnvHasher;
use rustls::internal::msgs::{
    codec::Codec,
    enums::ContentType,
    handshake::HandshakePayload::{Certificate, ClientHello, ServerHello, ServerHelloDone, ServerKeyExchange},
    message::{Message as TLSMessage, MessagePayload},
};
use rustls::ProtocolVersion;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
//use std::io::Result;

type Result<T> = std::result::Result<T, CertificateNotExtractedError>;

// Define our error types. These may be customized for our error handling cases.
// Now we will be able to write our own errors, defer to an underlying error
// implementation, or do something in between.
#[derive(Debug, Clone)]
struct CertificateNotExtractedError;

type FnvHash = BuildHasherDefault<FnvHasher>;
const BUFFER_SIZE: usize = 16384; // 2048
const READ_SIZE: usize = 4096; // 256

/// Read payload into the payload cache.
fn read_payload(rb: &mut ReorderedBuffer, to_read: usize, flow: Flow, payload_cache: &mut HashMap<Flow, Vec<u8>>) {
    println!(
        "reading size of {} payload into the flow entry \n{:?} \ninto the payload cache (hashmap)\n",
        to_read, flow,
    );
    let mut read_buf = [0; READ_SIZE];
    let mut so_far = 0;
    while to_read > so_far {
        let payload = payload_cache.entry(flow).or_insert(Vec::new());
        let n = rb.read_data(&mut read_buf);
        so_far += n;
        payload.extend(&read_buf[..n]);
        //println!("\n{:?}\n", flow);
        //println!("\nAnd the entries of that flow are: {:?}\n", payload);
    }
    println!("size of the entry is: {}", so_far);
}

/// Parse the bytes into tls frames.
fn parse_tls_frame(buf: &[u8]) -> Result<Vec<rustls::Certificate>> {
    // TLS Header length is 5.
    let tls_hdr_len = 5;
    let mut _version = ProtocolVersion::Unknown(0x0000);

    /////////////////////////////////////////////
    //
    //  TLS FRAME One: ServerHello
    //
    /////////////////////////////////////////////

    let (handshake1, offset1) = on_frame(&buf).expect("oh no!  parsing the ServerHello failed!!");

    //use self::HandshakePayload::*;
    match handshake1.payload {
        ClientHello(payload) => println!("{:?}", payload), //parse_clienthello(payload, tags),
        ServerHello(payload) => println!("{:?}", payload), //parse_serverhello(payload, tags),
        _ => println!("None"),
    }

    let (_, rest) = buf.split_at(offset1 + tls_hdr_len);
    println!("\nAnd the magic number is {}\n", offset1 + tls_hdr_len);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Two: Certificate
    //
    /////////////////////////////////////////////

    if on_frame(&rest).is_none() {
        println!("Get None, abort",);
        return Err(CertificateNotExtractedError);
    }
    let (handshake2, offset2) = on_frame(&rest).expect("oh no! parsing the Certificate failed!!");

    let certs = match handshake2.payload {
        Certificate(payload) => {
            println!("Certificate payload is\n{:?}", payload);
            Ok(payload)
        }
        _ => {
            println!("None");
            Err(CertificateNotExtractedError)
        }
    };

    let (_, rest) = rest.split_at(offset2 + tls_hdr_len);
    println!("\nAnd the magic number is {}\n", offset2 + tls_hdr_len);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Three: ServerKeyExchange
    //
    /////////////////////////////////////////////

    let (handshake3, offset3) = on_frame(&rest).expect("oh no! parsing the ServerKeyExchange failed!!");

    match handshake3.payload {
        ServerKeyExchange(payload) => println!("\nServer Key Exchange \n{:?}", payload), //parse_serverhello(payload, tags),
        _ => println!("None"),
    }

    let (_, rest) = rest.split_at(offset3 + tls_hdr_len);
    println!("\nAnd the magic number is {}\n", offset3 + tls_hdr_len);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Four: ServerHelloDone
    //
    /////////////////////////////////////////////

    let (handshake4, offset4) = on_frame(&rest).expect("oh no! parsing the ServerHelloDone failed!!");
    match handshake4.payload {
        ServerHelloDone => println!("Hooray! Server Hello Done!!!"),
        _ => println!("None"),
    }
    println!("\nAnd the magic number is {}\n", offset4 + tls_hdr_len);

    certs
}

/// Parse a slice of bytes into a TLS frame and the size of payload.
fn on_frame(rest: &[u8]) -> Option<(rustls::internal::msgs::handshake::HandshakeMessagePayload, usize)> {
    match TLSMessage::read_bytes(&rest) {
        Some(mut packet) => {
            println!("\nBytes in tls frame one is \n{:x?}", packet);
            println!("\nlength of the packet payload is {}\n", packet.payload.length());

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

fn is_serverhello(buf: &[u8]) -> bool {
    if on_frame(&buf).is_none() {
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ServerHello(_) => {
                println!("is server hello",);
                true
            }
            _ => {
                println!("not server hello",);
                false
            }
        }
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

    // Unfortunately we have to store the previous flow as a state here, and initialize it with a
    // bogus flow.
    let mut prev_flow = Flow {
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
        proto: 0,
    };

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .parse::<MacHeader>()
        .transform(box move |p| {
            // FIXME: what is this>
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
            flow
        })
    .parse::<TcpHeader>()
        .transform(box move |p| {
            let flow = p.read_metadata();
            let mut seq = p.get_header().seq_num();
            let tcph = p.get_header();
            println!("\n\nTCP Headers: {}", tcph);
            //let mut seg_len = p.get_header().seg_len();
            //println!("seg length is {}", seg_len);
            match rb_map.entry(*flow) {
                // occupied means that there already exists an entry for the flow
                Entry::Occupied(mut e) => {
                    println!("\nPkt #{} is Occupied!", seq);
                    println!("\nAnd the flow is: {:?}", flow);
                    println!("Previous one is: {:?}", prev_flow);
                                        //println!("\nEntry is {:?}", e);
                    // get entry
                    let b = e.get_mut();

                    let tls_result = TLSMessage::read_bytes(&p.get_payload());
                    let result = b.add_data(seq, p.get_payload());

                    match tls_result {
                        Some(packet) => {
                            //println!("Now the packet length is {:?}", packet.length());
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
                        // NOTE: #679 and #103 are matched and inserted here
                        None => {
                            // The rest of the TLS server hello handshake should be captured here.
                            println!("\nThere is nothing, that is why we should insert the packet!!!\n");
                            match result {
                                InsertionResult::Inserted { available, .. } => {
                                    println!("Quack: Inserted");
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

                    // Analyze the flow
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
                    } else if *flow == prev_flow {
                        println!("flow and prev flow are the same\n");
                    } else if *flow != prev_flow{
                        // NOTE: we matched # 644 and exam our flow to extract certs
                        match payload_cache.entry(prev_flow) {
                            Entry::Occupied(e) => {
                                println!("Quack: occupied\n");
                                let (_, payload) = e.remove_entry();
                                println!("Displaying the payload in raw bytes \n");
                                //println!("Occupied: {}\n", String::from_utf8_lossy(&payload));
                                //println!("{:x?}", payload);
                                println!("\nThe size of the value is {}", payload.len() );
                                //println!("{:?}", payload.len());

                                // TODO: figure out why the read byte cannot read all the bytes
                                // from the payload cache.
                                println!("\n************************************************************\n");
                                println!("\nTrying to display the payload via rustls...\n");
                                println!("\n************************************************************\n");

                                if is_serverhello(&payload) {
                                    println!("DEBUG: entering");
                                    let certs  = parse_tls_frame(&payload);
                                    println!("We now retrieve the certs from the tcp payload\n{:?}", certs);
                                }
                                else {
                                    println!("We are not getting anything");
                                }
                            }
                            Entry::Vacant(_) => {
                                println!("dumped an empty payload for Flow={:?}", flow);
                            }
                        }
                        e.remove_entry();
                    } else {
                        println!("Weird case");
                    }

                }
                // Vacant means that the entry for doesn't exist yet--we need to create one first
                Entry::Vacant(e) => {
                    println!("\n\nPkt #{} is Vacant", seq);
                    println!("\nAnd the flow is: {:?}", flow);
                    println!("Previous one is: {:?}", prev_flow);
                    if *flow == prev_flow {
                        println!("flow and prev flow are the same\n");
                    } else {
                        println!("current flow is a new flow, we should invoke the reassemble function for the previous flow\n");
                        match payload_cache.entry(prev_flow) {
                            Entry::Occupied(e) => {
                                let (_, payload) = e.remove_entry();
                                println!("Occupied, start parsing\n");
                                let tls_result = TLSMessage::read_bytes(&payload);
                                match tls_result {
                                    Some(packet) => {
                                        if packet.typ == ContentType::Handshake {
                                            println!("TLS packet match handshake!");
                                            println!("\n{:?}\n", packet);
                                        } else {
                                            println!("Packet type is not matched!")
                                        }
                                    }
                                    None => {
                                        // The rest of the TLS server hello handshake should be captured here.
                                        println!("\nThere is nothing, that is why we should insert the packet!!!\n");

                                    }
                                }
                            }
                            Entry::Vacant(_) => {
                                println!("dumped an empty payload for Flow={:?}", flow);
                            }
                        }
                    }
                    //println!("\nEntry is {:?}", e);
                    match ReorderedBuffer::new(BUFFER_SIZE) {
                        Ok(mut b) => {
                            println!("  1: Has allocated a new buffer:");
                            if p.get_header().syn_flag() {
                                println!("    2: packet has a syn flag");
                                seq += 1;
                            } else {
                                println!("    2: packet recv for untracked flow did not have a syn flag, skipped");
                            }

                            let tls_result = TLSMessage::read_bytes(&p.get_payload());
                            let result = b.seq(seq, p.get_payload());

                            // match to find TLS handshake
                            // NOTE: #255 is matched and inserted here
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
                                                println!("      4: This packet is inserted, quack");
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
            prev_flow = *flow;
        })
    .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
