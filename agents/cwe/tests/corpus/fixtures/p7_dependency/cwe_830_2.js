// Background worker bootstrap.
const QUEUE = [];

importScripts("https://cdn.example.net/sdk/2.0/tracker.js");

self.onmessage = function (event) {
  QUEUE.push(event.data);
};
