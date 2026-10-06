package exprruntime

import (
	"context"
	"net/http"
)

func (e *Runtime) revocationBindings(ctx context.Context, finding, captures map[string]string, components map[string]any, state *evalState) bindings {
	b := e.validationBindings(ctx, finding, captures, components, nil, state)
	rt := b["__runtime"].(*runtimeBindings)
	b["http"].(map[string]any)["delete"] = rt.httpDelete
	delete(b, "validate")
	b["revoke"] = map[string]any{"unknown": unknownResult}
	return b
}

func (rt *runtimeBindings) httpDelete(rawURL string, headers any) (map[string]any, error) {
	return rt.httpRequest(rt.ctx, http.MethodDelete, rawURL, headers, "")
}
