use std::borrow::Cow;

use fast_rands::Rand;
use libafl::{
    corpus::CorpusId,
    inputs::HasMutatorBytes,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::Named;

pub struct EbpfMutator;

impl<S> Mutator<libafl::inputs::BytesInput, S> for EbpfMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut libafl::inputs::BytesInput,
    ) -> Result<MutationResult, Error> {
        let bytes = input.mutator_bytes_mut();

        // eBPF instructions are 8 bytes.
        if bytes.len() < 8 {
            return Ok(MutationResult::Skipped);
        }

        // Only mutate a complete 8-byte instruction.
        let instruction_count = bytes.len() / 8;

        let instruction = (state.rand_mut().next() as usize) % instruction_count;

        let start = instruction * 8;

        // Change exactly one byte inside that instruction.
        let byte = (state.rand_mut().next() as usize) % 8;

        bytes[start + byte] ^= 1 << ((state.rand_mut().next() as usize) % 8);

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for EbpfMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EbpfMutator");
        &NAME
    }
}
