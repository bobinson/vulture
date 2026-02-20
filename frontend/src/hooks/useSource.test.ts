import { describe, expect, it } from "vitest";
import { validateGitUrl, validateLocalPath } from "./useSource";

describe("validateGitUrl", () => {
  it("accepts valid HTTPS git URL", () => {
    expect(validateGitUrl("https://github.com/org/repo.git")).toBeNull();
  });

  it("accepts valid SSH git URL", () => {
    expect(validateGitUrl("git@github.com:org/repo.git")).toBeNull();
  });

  it("rejects empty string", () => {
    expect(validateGitUrl("")).toBeTruthy();
  });

  it("rejects URL without .git suffix", () => {
    expect(validateGitUrl("https://github.com/org/repo")).toBeTruthy();
  });

  it("rejects plain text", () => {
    expect(validateGitUrl("not a url")).toBeTruthy();
  });
});

describe("validateLocalPath", () => {
  it("accepts absolute path", () => {
    expect(validateLocalPath("/home/user/project")).toBeNull();
  });

  it("rejects empty string", () => {
    expect(validateLocalPath("")).toBeTruthy();
  });

  it("rejects relative path", () => {
    expect(validateLocalPath("relative/path")).toBeTruthy();
  });
});
