use alloy_primitives::{Address, B256, FixedBytes};
use dowse_types::{CallKey, RecordedAccess};
use revm::bytecode::opcode::{BALANCE, EXTCODECOPY, EXTCODEHASH, EXTCODESIZE, SLOAD};
use revm::context_interface::ContextTr;
use revm::interpreter::interpreter_types::{InputsTr, Jumps, StackTr};
use revm::interpreter::{CallInputs, CallOutcome, Interpreter, InterpreterTypes};
use revm::Inspector;

/// Inspector that records actual state accesses during EVM execution.
///
/// Used to validate hint tables by comparing predicted accesses against
/// what the EVM actually touched.
pub struct RecordingInspector {
    /// Stack of active call frames: (CallKey, accesses so far).
    call_stack: Vec<(CallKey, Vec<RecordedAccess>)>,
    /// Completed call recordings: (CallKey, all accesses).
    recordings: Vec<(CallKey, Vec<RecordedAccess>)>,
}

impl RecordingInspector {
    pub fn new() -> Self {
        Self {
            call_stack: Vec::new(),
            recordings: Vec::new(),
        }
    }

    /// Return all recorded call-level accesses.
    pub fn recordings(&self) -> &[(CallKey, Vec<RecordedAccess>)] {
        &self.recordings
    }

    pub fn into_recordings(self) -> Vec<(CallKey, Vec<RecordedAccess>)> {
        self.recordings
    }
}

impl Default for RecordingInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl<CTX, INTR> Inspector<CTX, INTR> for RecordingInspector
where
    CTX: ContextTr,
    INTR: InterpreterTypes,
{
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let calldata = inputs.input.bytes(context);
        let selector = if calldata.len() >= 4 {
            Some(FixedBytes::<4>::from_slice(&calldata[..4]))
        } else {
            None
        };
        let key = CallKey {
            address: inputs.bytecode_address,
            selector,
        };
        self.call_stack.push((key, Vec::new()));
        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, _outcome: &mut CallOutcome) {
        if let Some(frame) = self.call_stack.pop() {
            self.recordings.push(frame);
        }
    }

    fn step(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        let opcode = interp.bytecode.opcode();
        let frame = match self.call_stack.last_mut() {
            Some(f) => &mut f.1,
            None => return,
        };

        // Read stack top without modifying it via data() slice.
        // In revm's stack, data() returns &[U256] where last element = top of stack.
        let stack_data = interp.stack.data();

        match opcode {
            SLOAD => {
                // Stack top is the storage slot key
                if let Some(&slot_val) = stack_data.last() {
                    let addr = interp.input.target_address();
                    let slot: B256 = slot_val.into();
                    let access = RecordedAccess::Storage {
                        address: addr,
                        slot,
                    };
                    if !frame.contains(&access) {
                        frame.push(access);
                    }
                }
            }
            BALANCE | EXTCODESIZE | EXTCODECOPY | EXTCODEHASH => {
                // Stack top is the address
                if let Some(&addr_val) = stack_data.last() {
                    let word: B256 = addr_val.into();
                    let addr = Address::from_word(word);
                    let access = RecordedAccess::Account(addr);
                    if !frame.contains(&access) {
                        frame.push(access);
                    }
                }
            }
            _ => {}
        }
    }
}
