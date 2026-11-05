// Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
// The failure is handed to the caller through std::expected / std::unexpected or a
// std::promise, idioms no 0101 lexicon was tuned on. Every identifier is invented.
// HELD-OUT-TOKENS: expected, unexpected, nullopt, current_exception, set_exception
#include <expected>
#include <future>
#include <optional>
#include <string>

std::expected<PaletteConfig, std::string> load_palette(const std::string& path) {
    try {
        return parse_palette_file(path);
    } catch (const std::exception& ex) { // EXPECT: clean
        return std::unexpected(ex.what());
    }
}

std::expected<Claims, std::string> verify_bearer_token(const std::string& token) {
    try {
        return decode_and_verify_signature(token);
    } catch (const std::exception& ex) { // EXPECT: finding
        return std::unexpected(ex.what());
    }
}

std::optional<Thumbnail> render_thumbnail(const Image& image) {
    try {
        return scale_down(image, 128);
    } catch (...) { // EXPECT: finding
        return std::nullopt;
    }
}

void fetch_weather(std::promise<Forecast> outcome, const std::string& city) {
    try {
        outcome.set_value(query_forecast(city));
    } catch (...) { // EXPECT: clean
        outcome.set_exception(std::current_exception());
    }
}

void unwrap_session_key(std::promise<KeyMaterial> outcome, const Blob& wrapped) {
    try {
        outcome.set_value(decrypt_session_key(wrapped));
    } catch (...) { // EXPECT: finding
        outcome.set_exception(std::current_exception());
    }
}
