mod ebpf;
mod fuzz;
mod intel_pt;
mod mutator;

use intel_pt::{build_pt_images, build_pt_instance, create_pt_hook};

fn main() {
    // -------------------------------------------------------------------------
    // Intel PT
    // -------------------------------------------------------------------------

    let images = build_pt_images();
    let pt = build_pt_instance(&images);
    let pt_hook = create_pt_hook(pt);

    // -------------------------------------------------------------------------
    // Fuzzing
    // -------------------------------------------------------------------------

    fuzz::run(pt_hook);
}
