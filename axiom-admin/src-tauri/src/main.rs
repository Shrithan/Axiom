// main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // We use the library crate name directly, NO 'mod lib;' here.
    axiom_admin_lib::run();
}