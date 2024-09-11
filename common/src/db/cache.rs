use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    hash::Hash,
};

#[derive(Debug)]
pub struct LookupCache<K, V>
where
    K: Eq + Hash,
{
    cache: HashMap<K, V>,
}

impl<K, V> Default for LookupCache<K, V>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
}

impl<K, V> LookupCache<K, V>
where
    K: Eq + Hash,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn lookup<F, Fut, E>(&mut self, key: K, create: F) -> Result<&V, E>
    where
        F: FnOnce(&K) -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        match self.cache.entry(key) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let value = create(entry.key()).await?;
                Ok(entry.insert(value))
            }
        }
    }
}

impl<K, V> LookupCache<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    pub async fn lookup_one<F, Fut, E>(
        &mut self,
        keys: impl IntoIterator<Item = K>,
        create: F,
    ) -> Result<Vec<V>, E>
    where
        F: Fn(&K) -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let mut result: Vec<V> = Vec::new();

        for key in keys {
            let value = self.lookup(key, &create).await?;
            result.push(value.clone());
        }

        Ok(result)
    }
}
