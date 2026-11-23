import { solveTopology } from '../engine/solver';
import { TopologyState } from '../types/network';

self.onmessage = (event: MessageEvent<{ id: number; topology: TopologyState }>) => {
  const data = event.data;
  if (!data || typeof data.id !== 'number' || !data.topology) return;
  try {
    const result = solveTopology(data.topology);
    self.postMessage({ id: data.id, result });
  } catch (err) {
    self.postMessage({
      id: data.id,
      error: err instanceof Error ? err.message : String(err),
    });
  }
};

