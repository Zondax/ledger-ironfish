pub fn zlog(_msg: &str) {
    #[cfg(not(test))]
    unsafe {
        zemu_log_stack(_msg.as_bytes().as_ptr());
    }
    #[cfg(test)]
    std::println!("{}", _msg);
}

extern "C" {
    fn zemu_log_stack(s: *const u8);
}