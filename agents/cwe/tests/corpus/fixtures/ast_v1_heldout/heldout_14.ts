// held-out heldout_14 (CWE-78): a spawn of a binary with an argv array in a closure; the binary and the extra arguments come from a resolved config
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";

export async function launchViewer(resolved: ViewerConfig, profile: ViewerProfile): Promise<RunningViewer> {
  const exe = findViewerBinary(resolved);
  if (!exe) {
    throw new Error("no supported viewer binary found");
  }
  const dataDir = profileDataDir(profile.name);
  fs.mkdirSync(dataDir, { recursive: true });

  const launchOnce = () => {
    const args: string[] = [`--debug-port=${profile.port}`, `--data-dir=${dataDir}`, "--no-first-run"];
    if (resolved.headless) {
      args.push("--headless");
    }
    if (resolved.extraArgs.length > 0) {
      args.push(...resolved.extraArgs);
    }
    args.push("--new-window");

    return spawn(exe.path, args, {
      stdio: "pipe",
      env: {
        ...process.env,
        HOME: os.homedir(),
      },
    });
  };

  const proc = launchOnce();
  return { pid: proc.pid, startedAt: Date.now() };
}
