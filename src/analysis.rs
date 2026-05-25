use std::collections::HashMap;

#[derive(Clone)]
pub struct FunctionSignature {
  pub parameter_names: Vec<String>,
}

pub struct CallFrame<Argument, Span> {
  pub callee: String,
  pub arguments: Vec<(Argument, Span)>,
}

pub struct Analyzer<Argument, Span> {
  pub signatures: HashMap<String, FunctionSignature>,
  pub call_frames: Vec<CallFrame<Argument, Span>>,
}

impl<Argument, Span> Analyzer<Argument, Span> {
  pub fn new() -> Self {
    Self {
      signatures: HashMap::new(),
      call_frames: Vec::new(),
    }
  }

  pub fn clear(&mut self) {
    self.signatures.clear();
    self.call_frames.clear();
  }

  pub fn add_signature(&mut self, name: String, signature: FunctionSignature) {
    self.signatures.insert(name, signature);
  }

  pub fn add_frame(&mut self, frame: CallFrame<Argument, Span>) {
    self.call_frames.push(frame);
  }

  pub fn get_signature(&self, name: &str) -> Option<&FunctionSignature> {
    self.signatures.get(name)
  }

  pub fn resolve_calls(
    &self,
    mut resolve: impl FnMut(&FunctionSignature, &Vec<(Argument, Span)>),
  ) {
    for frame in &self.call_frames {
      if let Some(signature) = self.signatures.get(&frame.callee) {
        resolve(signature, &frame.arguments);
      }
    }
  }
}
