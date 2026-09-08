use std::path::PathBuf;
use std::time::Duration;

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::{hooks::intel_pt::IntelPTHook, inprocess::GenericInProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    observers::ConstMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};

use libafl_bolts::{current_nanos, nonnull_raw_mut, rands::StdRand, tuples::tuple_list};

use crate::{
    ebpf::{create_vm, validate_bytes, SEED_PROG},
    intel_pt::MAP,
    mutator::EbpfMutator,
};

pub fn run<'a>(pt_hook: IntelPTHook<'a, u8>) {
    // -------------------------------------------------------------------------
    // Harness
    // -------------------------------------------------------------------------

    let mut executions = 0u64;
    let mut malformed = 0u64;
    let mut vm_rejected = 0u64;
    let mut runtime_failed = 0u64;
    let mut successful = 0u64;

    let mut harness = |input: &BytesInput| {
        let prog = input.target_bytes();
        executions += 1;

        // -------------------------------------------------------------
        // 1. Structurally malformed input
        // -------------------------------------------------------------

        if !validate_bytes(prog.as_ref()) {
            malformed += 1;
            return ExitKind::Ok;
        }

        // -------------------------------------------------------------
        // 2. rbpf VM creation + execution
        // -------------------------------------------------------------

        match create_vm(prog.as_ref()) {
            Ok(vm) => {
                let mut mem = [0u8; 64];

                match vm.execute_program(&mut mem) {
                    Ok(_) => {
                        successful += 1;
                    }

                    Err(_) => {
                        runtime_failed += 1;
                    }
                }
            }

            Err(_) => {
                vm_rejected += 1;
            }
        }

        // -------------------------------------------------------------
        // Statistics
        // -------------------------------------------------------------

        if executions % 10_000 == 0 {
            println!(
                "[eBPF] execs={executions} malformed={malformed} \
                 vm_rejected={vm_rejected} runtime_failed={runtime_failed} \
                 successful={successful}"
            );
        }

        ExitKind::Ok
    };

    // -------------------------------------------------------------------------
    // Coverage observer
    // -------------------------------------------------------------------------

    let observer = unsafe { ConstMapObserver::from_mut_ptr("edges", nonnull_raw_mut!(MAP)) };

    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).expect("failed to create crashes corpus"),
        &mut feedback,
        &mut objective,
    )
    .expect("failed to create fuzzer state");

    // -------------------------------------------------------------------------
    // Event manager
    // -------------------------------------------------------------------------

    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    // -------------------------------------------------------------------------
    // Fuzzer
    // -------------------------------------------------------------------------

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // -------------------------------------------------------------------------
    // Executor
    // -------------------------------------------------------------------------

    let mut executor = GenericInProcessExecutor::builder_generic()
        .timeout(Duration::from_millis(30000))
        .harness(&mut harness)
        .user_hooks(tuple_list!(pt_hook))
        .observers(tuple_list!(observer))
        .fuzzer(&mut fuzzer)
        .state(&mut state)
        .event_mgr(&mut mgr)
        .build()
        .expect("failed to create executor");

    // -------------------------------------------------------------------------
    // Initial corpus
    // -------------------------------------------------------------------------

    state
        .corpus_mut()
        .add(Testcase::new(BytesInput::new(SEED_PROG.to_vec())))
        .expect("failed to add seed");

    // -------------------------------------------------------------------------
    // Mutation stage
    // -------------------------------------------------------------------------

    let mutator = EbpfMutator;

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // -------------------------------------------------------------------------
    // Fuzz
    // -------------------------------------------------------------------------

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in fuzzing loop");
}
