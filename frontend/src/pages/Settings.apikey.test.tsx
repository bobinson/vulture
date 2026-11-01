import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Settings } from "./Settings";

// Feature 0102: the API key typed on the Settings page is never written to
// Web Storage, and a key stored by an earlier version is stripped on load and
// never shown. Settings.test.tsx keeps covering the rest of the page.

const STORAGE_KEY = "vulture_settings";
const TYPED_KEY = "sk-unit-typed-0102";
const LEGACY_KEY = "sk-unit-legacy-0102";
const LEGACY = JSON.stringify({ model: "gemini-pro", apiKey: LEGACY_KEY });

function apiKeyField(): HTMLInputElement {
  return screen.getByPlaceholderText("settings.apiKeyPlaceholder") as HTMLInputElement;
}

function modelSelect(): HTMLSelectElement {
  return screen.getByRole("combobox") as HTMLSelectElement;
}

function stored(): Record<string, unknown> | null {
  return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null");
}

function blockStorage(methods: ReadonlyArray<"getItem" | "setItem" | "removeItem">) {
  for (const method of methods) {
    vi.spyOn(localStorage, method).mockImplementation(() => {
      throw new DOMException("storage is blocked", "SecurityError");
    });
  }
}

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Settings API key is not persisted (0102)", () => {
  it("Save stores the model and no write carries the API key", () => {
    const setItem = vi.spyOn(localStorage, "setItem");
    render(<Settings />);
    fireEvent.change(modelSelect(), { target: { value: "claude-sonnet" } });
    fireEvent.change(apiKeyField(), { target: { value: TYPED_KEY } });
    fireEvent.click(screen.getByText("settings.save"));

    const settings = stored();
    expect(settings).toMatchObject({ model: "claude-sonnet" });
    expect(settings).not.toHaveProperty("apiKey");
    expect(setItem.mock.calls.filter(([, value]) => value.includes(TYPED_KEY))).toEqual([]);
  });

  it("strips a stored key on load, keeps the model and starts with an empty field", async () => {
    localStorage.setItem(STORAGE_KEY, LEGACY);

    render(<Settings />);

    expect(modelSelect().value).toBe("gemini-pro");
    expect(apiKeyField().value).toBe("");
    await waitFor(() => expect(localStorage.getItem(STORAGE_KEY) ?? "").not.toContain(LEGACY_KEY));
    const settings = stored();
    expect(settings).toMatchObject({ model: "gemini-pro" });
    expect(settings).not.toHaveProperty("apiKey");
  });

  it("does not show a stored key when storage refuses writes", () => {
    localStorage.setItem(STORAGE_KEY, LEGACY);
    blockStorage(["setItem", "removeItem"]);

    render(<Settings />);

    expect(screen.getByText("settings.save")).toBeInTheDocument();
    expect(apiKeyField().value).toBe("");
  });

  it("renders the defaults when storage throws", () => {
    blockStorage(["getItem", "setItem", "removeItem"]);

    render(<Settings />);

    expect(modelSelect().value).toBe("gpt-4o");
    expect(apiKeyField().value).toBe("");
  });

  it("renders the defaults when the stored settings are corrupt", () => {
    localStorage.setItem(STORAGE_KEY, "{not json");

    render(<Settings />);

    expect(modelSelect().value).toBe("gpt-4o");
    expect(apiKeyField().value).toBe("");
  });
});
