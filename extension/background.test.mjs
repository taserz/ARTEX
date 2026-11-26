import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

test("capture keeps unfinished requests bounded and drops failed requests", () => {
  let onEvent;
  const chrome = {
    debugger: {
      onEvent: { addListener(listener) { onEvent = listener; } },
      onDetach: { addListener() {} },
    },
    runtime: { onMessage: { addListener() {} } },
  };
  const context = vm.createContext({ chrome });
  vm.runInContext(readFileSync(new URL("./background.js", import.meta.url), "utf8"), context);
  vm.runInContext("session.capturing = true; session.tabId = 7", context);

  for (let i = 0; i <= 500; i++) {
    onEvent({ tabId: 7 }, "Network.requestWillBeSent", {
      requestId: String(i),
      request: {
        method: "POST",
        url: "https://example.test/",
        headers: {},
        postData: i === 500 ? "x".repeat(256 * 1024 + 1) : "x",
      },
    });
  }

  assert.equal(vm.runInContext("session.requests.size", context), 500);
  assert.equal(vm.runInContext("session.requests.has('0')", context), false);
  assert.equal(vm.runInContext("session.requests.has('500')", context), true);
  assert.equal(vm.runInContext("session.requests.get('500').postData.includes('[truncated by extension]')", context), true);

  onEvent({ tabId: 7 }, "Network.loadingFailed", { requestId: "500" });
  assert.equal(vm.runInContext("session.requests.size", context), 499);
});
