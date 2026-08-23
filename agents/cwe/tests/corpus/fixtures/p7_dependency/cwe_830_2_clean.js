// Background worker bootstrap.
const QUEUE = [];

importScripts("./vendor/tracker.js");

self.onmessage = function (event) {
  QUEUE.push(event.data);
};
