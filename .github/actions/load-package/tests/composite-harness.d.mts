export function runCompositeScript(
  script: string,
  github: unknown,
  context: unknown,
  core: unknown,
  exec: unknown,
  runtimeProcess: { env: NodeJS.ProcessEnv; platform: string; arch: string },
): Promise<void>;
