/** Shared App refresh operation. Quiet background callers must catch explicitly. */
export async function refreshWorkspace<T>(
  load: () => Promise<T>,
  apply: (snapshot: T) => void,
  failed: (error: unknown) => void,
  finished: () => void,
): Promise<void> {
  try {
    apply(await load());
  } catch (error) {
    failed(error);
    throw error;
  } finally {
    finished();
  }
}
