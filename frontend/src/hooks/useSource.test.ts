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

  it("accepts an https URL without a .git suffix", () => {
    // GitHub/GitLab clone fine without the trailing .git; requiring it
    // would reject valid repositories. Not an error.
    expect(validateGitUrl("https://github.com/org/repo")).toBeNull();
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
