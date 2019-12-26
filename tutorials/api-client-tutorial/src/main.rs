/*
    Copyright 2019 Supercomputing Systems AG
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

use codec::{Decode, Encode};
use keyring::AccountKeyring;
use addax_runtime::{ Event};
use primitives::crypto::Pair;
use primitives::H256 as Hash;
use std::sync::mpsc::{channel, Receiver};
use substrate_api_client::{
    Api,
    compose_extrinsic,
    extrinsic::xt_primitives::UncheckedExtrinsicV4,
    utils::{hexstr_to_u64, hexstr_to_vec}
};

fn main() {   
    let signer = AccountKeyring::Alice.pair();
    let api = Api::new(format!("ws://127.0.0.1:9944"))
        .set_signer(signer.clone());

    let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
        api.clone(),
        "Identity",
        "test_extrinsic"
    );

    println!("[+] Extrinsic: {:?}\n", xt);

    let (events_in, events_out) = channel();
    api.subscribe_events(events_in.clone());
  

    let tx_hash = api.send_extrinsic(xt.hex_encode()).unwrap();
    println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);

    let hash: Hash = subscribe_to_extrinsic_created_event(
        &events_out,        
    );

    // get the index at which Alice's Kitty resides. Alternatively, we could listen to the StoredKitty
    // event similar to what we do in the example_contract.
    let nonce = api.get_storage("Identity",
                                  "nonce",
                                  Some(signer.public().encode())).unwrap();

    // let index = hexstr_to_u64(res_str).unwrap();
    println!("[+] Nonce : {}\n", nonce);

    // get the Kitty
    // let res_str = api.get_storage("Identity",
    //                               "Kitties",
    //                               Some(index.encode())).unwrap();

    // let res_vec = hexstr_to_vec(res_str).unwrap();

    // type annotations are needed here to know that to decode into.
    // let kitty: Kitty = Decode::decode(&mut res_vec.as_slice()).unwrap();
    // println!("[+] Cute decoded Kitty: {:?}\n", kitty);
}



fn subscribe_to_extrinsic_created_event(
    events_out: &Receiver<String>, 
) -> Result <String, system::Event> {
    loop {
        let event_str = events_out.recv()?;
        let unhex = hexstr_to_vec(event_str).unwrap();
        let mut er_enc = unhex.as_slice();
        let events = Vec::<system::EventRecord<Event, Hash>>::decode(&mut er_enc);
        if let Ok(evts) = events {
            for evr in &evts {
                // println!("{:?}", evr);
                match &evr.event {
                    Event::identity(ce) => {
                        println!("{:?}", &ce);
                        match &ce {
                            identity::RawEvent::ExtrinsicTest(account_id, nonce) => {
                                println!("{}",nonce);
                                // if *entity_type == created_entity_type
                                // && (*account_id) == creator_accountid
                                // {
                                    return Ok("result");
                                // };
                            }
                            _ => {
                                // println!("ignoring unsupported event");
                            }
                        };
                    }
                    Event::system(ce) => {
                        match &ce {
                            system::Event::ExtrinsicFailed(err) => {
                                println!("{:?}", err);
                                return err;
                            }
                            _ => {
                                println!("{:?}", &ce);
                                // println!("ignoring unsupported event");
                            }
                        };
                    }
                    _ => {
                        // println!("ignoring unsupported event");
                    }
                }
            }
        }
    }
}