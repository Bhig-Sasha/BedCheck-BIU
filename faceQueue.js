// faceQueue.js
class FaceQueue {
  constructor(concurrency = 3) {
    this.concurrency = concurrency;
    this.running = 0;
    this.queue = [];
  }

  add(taskFn) {
    return new Promise((resolve, reject) => {
      this.queue.push({ taskFn, resolve, reject });
      this._next();
    });
  }

  async _next() {
    if (this.running >= this.concurrency || this.queue.length === 0) return;

    const { taskFn, resolve, reject } = this.queue.shift();
    this.running++;

    try {
      const result = await taskFn();
      resolve(result);
    } catch (err) {
      reject(err);
    } finally {
      this.running--;
      this._next();
    }
  }

  stats() {
    return {
      running: this.running,
      waiting: this.queue.length,
      concurrency: this.concurrency
    };
  }
}

const FACE_CONCURRENCY = parseInt(process.env.FACE_CONCURRENCY || '3', 10);
module.exports = new FaceQueue(FACE_CONCURRENCY);