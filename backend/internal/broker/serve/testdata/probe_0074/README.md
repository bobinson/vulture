# Loaded-window probe fixtures (feature 0074, T0.5)

The broker's loaded-window probe is gated per runtime on a captured response:
a runtime with no capture here is **not probed** (plan §5.2, "Fixture gate").

| file | origin | what it pins |
|---|---|---|
| `lmstudio_api_v0_models.json` | **captured** — `GET /api/v0/models` against a local LM Studio | `loaded_context_length` is the loaded window; a model in state `not-loaded` carries only `max_context_length`, which must yield **no** value (AC4, W3) |
| `openai_v1_models.json` | **captured** — `GET /v1/models` against the same server (plain OpenAI shape) | neither window field exists, so the probe yields nothing |
| `synthetic_lmstudio_loaded_below_guess.json` | synthetic, LM Studio shape | a loaded window (8192) below the registry guess (128000) lowers the window and logs `llm_window_lowered_by_probe` (AC41) |
| `synthetic_ollama_api_show.json` | synthetic — **no Ollama capture exists** | Ollama must not be probed (`POST /api/show` never called) |
| `synthetic_vllm_v1_models.json` | synthetic — **no vLLM capture exists** | `max_model_len` must not be read |

Scrubbing (R51): the captures were checked for hostnames, local paths and model
file paths before commit; none were present, so the bodies are verbatim. Model
ids are public model names. When a capture for Ollama or vLLM is added, replace
the synthetic body and flip the "not probed" test for that runtime.
