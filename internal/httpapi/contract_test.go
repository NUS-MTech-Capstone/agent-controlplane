package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/NUS-MTech-Capstone/agent-controlplane/api"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func contractDocument(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(api.OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	// Normalize YAML scalar types to JSON values before compiling JSON Schema.
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func contractResolve(doc map[string]any, value map[string]any) map[string]any {
	if ref, ok := value["$ref"].(string); ok {
		var current any = doc
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			current = current.(map[string]any)[strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")]
		}
		return current.(map[string]any)
	}
	return value
}

// Assert actual HTTP responses against the checked-in contract, including nested
// references and required fields. Unregistered routes are tested separately as 404s.
func assertContractResponse(t *testing.T, method, requestPath string, rec *httptest.ResponseRecorder) {
	t.Helper()
	doc := contractDocument(t)
	parsed, err := url.Parse(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	var item map[string]any
	if exact, ok := paths[parsed.Path]; ok {
		item = exact.(map[string]any)
	} else {
		actual := strings.Split(parsed.Path, "/")
		for pattern, candidate := range paths {
			parts := strings.Split(pattern, "/")
			if len(parts) != len(actual) {
				continue
			}
			matches := true
			for i, p := range parts {
				if p != actual[i] && !(strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") && actual[i] != "") {
					matches = false
					break
				}
			}
			if matches {
				item = candidate.(map[string]any)
				break
			}
		}
	}
	if item == nil {
		return
	}
	op, ok := item[strings.ToLower(method)].(map[string]any)
	if !ok {
		return
	}
	raw, ok := op["responses"].(map[string]any)[strconv.Itoa(rec.Code)].(map[string]any)
	if !ok {
		t.Fatalf("%s %s: undocumented status %d", method, parsed.Path, rec.Code)
	}
	resp := contractResolve(doc, raw)
	content, ok := resp["content"].(map[string]any)
	if !ok {
		return
	}
	media := strings.Split(rec.Header().Get("Content-Type"), ";")[0]
	entry, ok := content[media].(map[string]any)
	if !ok {
		t.Fatalf("%s %s: undocumented content type %q", method, parsed.Path, media)
	}
	schema := contractResolve(doc, entry["schema"].(map[string]any))
	root := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "components": doc["components"]}
	for k, v := range schema {
		root[k] = v
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://contracts.ddm.invalid/response.json", root); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("https://contracts.ddm.invalid/response.json")
	if err != nil {
		t.Fatal(err)
	}
	var value any = rec.Body.String()
	if media == "application/json" {
		if err := json.Unmarshal(rec.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
	}
	if err := compiled.Validate(value); err != nil {
		t.Fatalf("%s %s status %d does not conform: %v", method, parsed.Path, rec.Code, err)
	}
}

func TestOpenAPIContractVersionsProbesAndServedBytes(t *testing.T) {
	server := New(nil, nil)
	checkedIn, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest("GET", "/openapi.yaml", nil))
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), checkedIn) || !bytes.Equal(api.OpenAPI, checkedIn) {
		t.Fatal("served, embedded, and checked-in specifications differ")
	}
	health := httptest.NewRecorder()
	server.ServeHTTP(health, httptest.NewRequest("GET", "/healthz", nil))
	assertContractResponse(t, "GET", "/healthz", health)
	for path, value := range contractDocument(t)["paths"].(map[string]any) {
		if isAPIVersionExempt(path) {
			continue
		}
		for method := range value.(map[string]any) {
			if !strings.Contains(" get post put patch delete ", " "+method+" ") {
				continue
			}
			for _, version := range []string{"", "unsupported"} {
				t.Run(method+path+"/version="+version, func(t *testing.T) {
					req := httptest.NewRequest(strings.ToUpper(method), path, strings.NewReader("{}"))
					if version != "" {
						req.Header.Set("x-api-version", version)
					}
					rec := httptest.NewRecorder()
					server.ServeHTTP(rec, req)
					if rec.Code != 400 {
						t.Fatalf("version error status=%d", rec.Code)
					}
					assertContractResponse(t, req.Method, path, rec)
				})
			}
		}
	}
}
