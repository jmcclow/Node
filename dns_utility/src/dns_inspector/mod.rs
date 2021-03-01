// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

#[cfg(target_os = "windows")]
extern crate winreg;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate system_configuration;

#[cfg(target_os = "windows")]
mod adapter_wrapper;
mod dns_modifier;
mod dns_modifier_factory;
mod dynamic_store_dns_modifier;
#[cfg(target_os = "windows")]
mod ipconfig_wrapper;
mod resolv_conf_dns_modifier;
#[cfg(target_os = "windows")]
mod win_dns_modifier;
mod utils;

use std::net::IpAddr;

pub fn dns_servers () -> Result<Vec<IpAddr>, String> {
    unimplemented!()
}
