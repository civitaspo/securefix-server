const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

export async function runCompositeScript(script, github, context, core, exec) {
  const run = new AsyncFunction('github', 'context', 'core', 'exec', script);
  await run(github, context, core, exec);
}
