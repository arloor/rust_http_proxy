use core::fmt::Debug;
use core::hash::Hash;
use core::ops::Deref;
use prometheus_client::encoding::EncodeLabelSet;

/// wrapper trait for prometheus label
pub trait Label: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static {}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct LabelImpl<R>(R)
where
    R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static;

impl<R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static> From<R> for LabelImpl<R> {
    fn from(s: R) -> Self {
        Self(s)
    }
}

impl<R> Deref for LabelImpl<R>
where
    R: Clone + Debug + Hash + PartialEq + EncodeLabelSet + Eq + 'static,
{
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<R> EncodeLabelSet for LabelImpl<R>
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

impl<R> Label for LabelImpl<R> where
    R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static
{
}
