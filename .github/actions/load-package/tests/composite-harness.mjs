const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

export async function runCompositeScript(script, github, context, core, exec, runtimeProcess) {
  const run = new AsyncFunction('github', 'context', 'core', 'exec', 'process', script);
  await run(github, context, core, exec, runtimeProcess);
}
