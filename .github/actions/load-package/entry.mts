import type { GitHubScriptArguments } from './load.mts';
import { loadPackage } from './load.mts';

export async function run(args: GitHubScriptArguments): Promise<void> {
  await loadPackage(args);
}
