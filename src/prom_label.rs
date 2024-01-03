use std::ops::Deref;
use std::fmt::Debug;
use core::hash::Hash;
use prometheus_client::encoding::EncodeLabelSet;

pub trait PromLabel: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static {}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PromLabelDefault<R>(pub R)
where
    R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static;

    
impl<R> Deref for PromLabelDefault<R>
where
    R: Clone + Debug + Hash + PartialEq + EncodeLabelSet + Eq + 'static,
{
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<R> EncodeLabelSet for PromLabelDefault<R>
where
    R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static,
{
    fn encode(
        &self,
        encoder: prometheus_client::encoding::LabelSetEncoder,
    ) -> Result<(), std::fmt::Error> {
        self.deref().encode(encoder)
    }
}

impl<R> PromLabel for PromLabelDefault<R> where
    R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static
{
}
