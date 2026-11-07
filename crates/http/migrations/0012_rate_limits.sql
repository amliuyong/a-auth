CREATE TABLE a_auth.rate_limits (
    bucket_key TEXT PRIMARY KEY,
    tokens DOUBLE PRECISION NOT NULL,
    last_refill DOUBLE PRECISION NOT NULL,
    CHECK (tokens >= 0 AND tokens < 'Infinity'::DOUBLE PRECISION),
    CHECK (last_refill > '-Infinity'::DOUBLE PRECISION AND last_refill < 'Infinity'::DOUBLE PRECISION)
);
