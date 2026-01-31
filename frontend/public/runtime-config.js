// Runtime configuration injected at deploy time.
// The Docker frontend image overwrites this file on container start.
// You can also edit it manually when serving static files.
// Refactor: keep the exported object named for clarity.
const runtimeConfig = {
  // Example: "http://localhost:8001/api"
  API_BASE: "",
};

window.__PTW_RUNTIME_CONFIG__ = runtimeConfig;
