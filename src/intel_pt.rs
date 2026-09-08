use libafl::executors::hooks::intel_pt::{IntelPT, IntelPTHook, PtImage};
use proc_maps::get_process_maps;
use std::{process, slice};

// Edge coverage map.
pub const MAP_SIZE: usize = 4096;
pub static mut MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];
static mut MAP_PTR: *mut u8 = &raw mut MAP as _;

// -------------------------------------------------------------------------
// Intel PT
// -------------------------------------------------------------------------

// Build the executable images used by Intel PT.
pub fn build_pt_images() -> Vec<PtImage<'static>> {
    let pid = process::id();

    let maps =
        get_process_maps(pid.try_into().unwrap()).expect("failed to get process memory maps");

    let images = maps
        .iter()
        .filter_map(|map| {
            if !map.is_exec() {
                return None;
            }

            let data = unsafe { slice::from_raw_parts(map.start() as *const u8, map.size()) };

            Some(PtImage::new(data, map.start() as u64))
        })
        .collect::<Vec<_>>();

    println!("{} executable images", images.len());

    images
}

// Create Intel PT from the supplied images.
pub fn build_pt_instance<'a>(images: &'a [PtImage<'a>]) -> IntelPT<'a> {
    IntelPT::builder()
        .images(images)
        .build()
        .expect("failed to initialize Intel PT")
}

// Create the Intel PT hook.
pub fn create_pt_hook<'a>(pt: IntelPT<'a>) -> IntelPTHook<'a, u8> {
    unsafe {
        IntelPTHook::builder()
            .intel_pt(pt)
            .map_ptr(MAP_PTR)
            .map_len(MAP_SIZE)
            .build()
    }
}
