// rateQueue.js
class RateQueue {
  constructor({
    name = 'rate',
    windowMs = 60_000,
    max = 100,
    concurrency = 50,
  } = {}) {
    this.name = name;
    this.windowMs = windowMs;
    this.max = max;
    this.concurrency = concurrency;
    this.buckets = new Map();   // key → { count, resetAt }
    this.active = 0;
    this.waiting = [];          // queue of resolve functions
  }

  _getBucket(key) {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + this.windowMs };
      this.buckets.set(key, bucket);
    }
    return bucket;
  }

  async add(key, fn) {
    if (typeof key !== 'string' && typeof key !== 'number') {
      key = String(key);
    }

    const bucket = this._getBucket(key);

    // Hard rate limit
    if (bucket.count >= this.max) {
      const err = new Error(`[${this.name}] Rate limit exceeded`);
      err.code = 'RATE_LIMIT_EXCEEDED';
      err.retryAfter = Math.ceil((bucket.resetAt - Date.now()) / 1000);
      throw err;
    }

    // Soft concurrency limit
    if (this.active >= this.concurrency) {
      await new Promise((resolve) => this.waiting.push(resolve));
    }

    bucket.count++;
    this.active++;

    try {
      return await fn();
    } finally {
      this.active--;
      if (this.waiting.length > 0) {
        const next = this.waiting.shift();
        next();
      }
    }
  }

  cleanup() {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (now >= bucket.resetAt) {
        this.buckets.delete(key);
      }
    }
  }

  // Optional helper for monitoring
  getStats() {
    return {
      name: this.name,
      active: this.active,
      waiting: this.waiting.length,
      buckets: this.buckets.size,
    };
  }
}

// =====================================================
// Specialized instances
// =====================================================

const authRateQueue = new RateQueue({
  name: 'auth',
  windowMs: parseInt(process.env.AUTH_RATE_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.AUTH_RATE_MAX) || 8,                        // very strict
  concurrency: 10,
});

const registrationRateQueue = new RateQueue({
  name: 'registration',
  windowMs: parseInt(process.env.REG_RATE_WINDOW_MS) || 60 * 60 * 1000, // 1 hour
  max: parseInt(process.env.REG_RATE_MAX) || 6,
  concurrency: 5,
});

const generalRateQueue = new RateQueue({
  name: 'general',
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60 * 1000,    // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX) || 120,
  concurrency: parseInt(process.env.RATE_CONCURRENCY) || 80,
});

// Cleanup every 5 minutes
setInterval(() => {
  authRateQueue.cleanup();
  registrationRateQueue.cleanup();
  generalRateQueue.cleanup();
}, 5 * 60 * 1000).unref(); // .unref() so it doesn't keep the process alive

module.exports = {
  RateQueue,               // in case you want to create more later
  authRateQueue,
  registrationRateQueue,
  generalRateQueue,

  // convenience default (same as general)
  rateQueue: generalRateQueue,
};