package provider

import "context"

// Stream is not yet implemented for the OpenAI-shaped adapter (deferred to the
// streaming-egress task). The Complete path is the GREEN target here.
func (a *openAIAdapter) Stream(context.Context, Credentials, CompletionRequest) (<-chan StreamChunk, error) {
	return nil, ErrNotImplemented
}

// Embed is not yet implemented for the OpenAI-shaped adapter (embeddings egress
// is handled by internal/embedding today; broker embeddings are deferred).
func (a *openAIAdapter) Embed(context.Context, Credentials, EmbeddingRequest) (*EmbeddingResponse, error) {
	return nil, ErrNotImplemented
}

// Compile-time interface assertion for the OpenAI-shaped adapter.
var _ Adapter = (*openAIAdapter)(nil)
