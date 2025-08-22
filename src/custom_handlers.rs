/*
 * Teaparty - a STAMP protocol implementation
 * Copyright (C) 2024, 2025  Will Hawkins and Cerfcast
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use slog::{info, Logger};
use yaml_rust2::Yaml;

use crate::{
    handlers::{self, ReflectorHandlers, TlvHandlerGenerator},
    tlvs::{
        accessreport::{AccessReportTlv, AccessReportTlvReflectorConfig},
        biterrorrate::{BitErrorRateTlv, BitErrorRateTlvReflectorConfig},
        classofservice::{ClassOfServiceTlv, ClassOfServiceTlvReflectorConfig},
        destinationaddress::{DestinationAddressTlv, DestinationAddressTlvReflectorConfig},
        destinationport::{DestinationPortTlv, DestinationPortTlvReflectorConfig},
        extensionheadersreflection::{
            V6ExtensionHeadersReflectionTlv, V6ExtensionHeadersReflectionTlvReflectorConfig,
        },
        followup::{FollowupTlv, FollowupTlvReflectorConfig},
        history::{HistoryTlv, HistoryTlvReflectorConfig},
        hmac::{HmacTlv, HmacTlvReflectorConfig},
        location::{LocationTlv, LocationTlvReflectorConfig},
        padding::{PaddingTlv, PaddingTlvReflectorConfig},
        reflectedcontrol::{ReflectedControlTlv, ReflectedControlTlvReflectorConfig},
        returnpath::{ReturnPathTlv, ReturnPathTlvReflectorConfig},
        time::{TimeTlv, TimeTlvReflectorConfig},
        unrecognized::{UnrecognizedTlv, UnrecognizedTlvReflectorConfig},
    },
};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct CustomReflectorHandlersGenerators {
    generators: Vec<Arc<Mutex<dyn TlvHandlerGenerator + Send>>>,
}

impl CustomReflectorHandlersGenerators {
    #[allow(clippy::all)]
    pub fn new() -> CustomReflectorHandlersGenerators {
        let mut generators: Vec<Arc<Mutex<dyn TlvHandlerGenerator + Send>>> = vec![];
        generators.push(Arc::new(Mutex::new(TimeTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(AccessReportTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(BitErrorRateTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(ClassOfServiceTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(
            DestinationAddressTlvReflectorConfig {},
        )));
        generators.push(Arc::new(Mutex::new(DestinationPortTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(
            V6ExtensionHeadersReflectionTlvReflectorConfig {},
        )));
        generators.push(Arc::new(Mutex::new(FollowupTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(HistoryTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(HmacTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(LocationTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(PaddingTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(ReflectedControlTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(ReturnPathTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(TimeTlvReflectorConfig {})));
        generators.push(Arc::new(Mutex::new(UnrecognizedTlvReflectorConfig {})));
        CustomReflectorHandlersGenerators { generators }
    }

    pub fn config(&mut self, config_title: &str, config: &Yaml, logger: Logger) {
        for generator in &self.generators {
            let generator = generator.lock().unwrap();
            if generator.tlv_reflector_name() == config_title {
                info!(logger, "Found reflector generator with name matching config ({config_title}).");
                generator.configure(config, logger.clone());
            }
        }
    }

    pub fn generate(&self) -> ReflectorHandlers {
        let mut handlers = ReflectorHandlers::new();
        for generator in &self.generators {
            handlers.add(generator.lock().unwrap().generate());
        }
        handlers
    }
}

pub struct CustomSenderHandlers {}

impl CustomSenderHandlers {
    pub fn build() -> handlers::SenderHandlers {
        let mut handlers = handlers::SenderHandlers::new();
        let time_handler = Arc::new(Mutex::new(TimeTlv {}));
        handlers.add(time_handler);
        let dst_port_tlv: DestinationPortTlv = Default::default();
        let destination_port_handler = Arc::new(Mutex::new(dst_port_tlv));
        handlers.add(destination_port_handler);
        let dst_address_tlv: DestinationAddressTlv = Default::default();
        let destination_address_handler = Arc::new(Mutex::new(dst_address_tlv));
        handlers.add(destination_address_handler);
        let cos_tlv: ClassOfServiceTlv = Default::default();
        let cos_handler = Arc::new(Mutex::new(cos_tlv));
        handlers.add(cos_handler);
        let location_handler = Arc::new(Mutex::new(LocationTlv {}));
        handlers.add(location_handler);
        let unrecognized_handler = Arc::new(Mutex::new(UnrecognizedTlv {}));
        handlers.add(unrecognized_handler);
        let padding_handler = Arc::new(Mutex::new(PaddingTlv {}));
        handlers.add(padding_handler);
        let access_report_handler = Arc::new(Mutex::new(AccessReportTlv {}));
        handlers.add(access_report_handler);
        let history_handler = Arc::new(Mutex::new(HistoryTlv {}));
        handlers.add(history_handler);
        let followup_handler = Arc::new(Mutex::new(FollowupTlv {}));
        handlers.add(followup_handler);
        let reflected_control_tlv: ReflectedControlTlv = Default::default();
        let reflected_control_handler = Arc::new(Mutex::new(reflected_control_tlv));
        handlers.add(reflected_control_handler);
        let hmac_tlv: HmacTlv = Default::default();
        let hmac_tlv_handler = Arc::new(Mutex::new(hmac_tlv));
        handlers.add(hmac_tlv_handler);
        let ber_tlv: BitErrorRateTlv = Default::default();
        let ber_tlv_handler = Arc::new(Mutex::new(ber_tlv));
        handlers.add(ber_tlv_handler);
        let header_options_tlv: V6ExtensionHeadersReflectionTlv = Default::default();
        let header_options_tlv_handler = Arc::new(Mutex::new(header_options_tlv));
        handlers.add(header_options_tlv_handler);
        let return_path_tlv_handler = Arc::new(Mutex::new(ReturnPathTlv::default()));
        handlers.add(return_path_tlv_handler);
        handlers
    }
}
