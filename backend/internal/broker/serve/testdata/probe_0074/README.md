# Loaded-window probe fixtures (feature 0074, T0.5)

These files are TEST fixtures only: no runtime code reads them, so removing
one does not disable anything. What the probe actually does is fixed in code
(`probe.go`):

- it sends exactly one request shape, LM Studio's `GET /api/v0/models` at the
  server root, and reads only `loaded_context_length`. Ollama (`POST
  /api/show`) and vLLM (`max_model_len`) are never asked, because the probe
  has no code for them; the synthetic bodies below pin that;
- a cloud provider (one with a canonical endpoint) is never probed;
- only a target that resolves to a loopback or private (RFC1918 / ULA)
  address is probed, so a remote gateway never receives the key on a
  speculative listing request;
- a redirect is never followed, and a window above the largest registry
  window is no value.

There is no runtime switch: the off-switch is a code revert.

| file | origin | what it pins |
|---|---|---|
| `lmstudio_api_v0_models.json` | **captured** — `GET /api/v0/models` against a local LM Studio | `loaded_context_length` is the loaded window; a model in state `not-loaded` carries only `max_context_length`, which must yield **no** value (AC4, W3) |
| `openai_v1_models.json` | **captured** — `GET /v1/models` against the same server (plain OpenAI shape) | neither window field exists, so the probe yields nothing |
| `synthetic_lmstudio_loaded_below_guess.json` | synthetic, LM Studio shape | a loaded window (8192) below the registry guess (128000) lowers the window and logs `llm_window_lowered_by_probe` (AC41) |
| `synthetic_ollama_api_show.json` | synthetic — **no Ollama capture exists** | Ollama must not be probed (`POST /api/show` never called) |
| `synthetic_vllm_v1_models.json` | synthetic — **no vLLM capture exists** | `max_model_len` must not be read |

Scrubbing (R51): the captures were checked for hostnames, local paths and model
file paths before commit; none were present, so the bodies are verbatim. Model
ids are public model names. Supporting Ollama or vLLM means adding code for its
request shape, a real capture to replace the synthetic body, and flipping the
"not probed" test for that runtime.
