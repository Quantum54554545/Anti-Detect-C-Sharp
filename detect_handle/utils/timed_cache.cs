using System.Collections.Concurrent;

namespace detect_handle.utils
{
    internal sealed class timed_cache<t_key, t_value>
    {
        private readonly TimeSpan _ttl;
        private readonly ConcurrentDictionary<t_key, cache_entry> _dict = new ConcurrentDictionary<t_key, cache_entry>();

        private sealed class cache_entry
        {
            public Lazy<t_value> lazy_value;
            public DateTime expires_at_utc;
        }

        public timed_cache(TimeSpan ttl)
        {
            _ttl = ttl <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : ttl;
        }

        public t_value get_or_add(t_key key, Func<t_key, t_value> factory)
        {
            var now = DateTime.UtcNow;

            if (_dict.TryGetValue(key, out var existing) && existing.expires_at_utc > now)
            {
                return existing.lazy_value.Value;
            }

            var new_entry = new cache_entry
            {
                lazy_value = new Lazy<t_value>(() => factory(key), LazyThreadSafetyMode.ExecutionAndPublication),
                expires_at_utc = now + _ttl
            };

            var final_entry = _dict.AddOrUpdate(key, new_entry, (k, old) => old.expires_at_utc > now ? old : new_entry);
            return final_entry.lazy_value.Value;
        }

        public void invalidate(t_key key) => _dict.TryRemove(key, out _);

        public void clear() => _dict.Clear();
    }
}
