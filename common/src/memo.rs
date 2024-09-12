use std::fmt::{Debug, Formatter};

pub enum Memo<T> {
    NotProvided,
    Provided(Option<T>),
}

impl<T: Debug> Debug for Memo<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Memo::NotProvided => {
                write!(f, "NotProvided")
            }
            Memo::Provided(inner) => {
                write!(f, "Provided({inner:?})")
            }
        }
    }
}

impl<T: Clone> Clone for Memo<T> {
    fn clone(&self) -> Self {
        match self {
            Memo::NotProvided => Memo::NotProvided,
            Memo::Provided(inner) => Memo::Provided(inner.clone()),
        }
    }
}
