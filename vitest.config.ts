// Pure-logic + source-scan tests need no DOM: `state.test.ts` exercises the reducer
// as plain data, and `sinkfence.test.ts`/`render-contract.test.ts` read `src/**/*.ts` as TEXT
// (fs.readFileSync) rather than importing/executing `render.ts` (which assumes a live
// `document`). Keeping the environment `node` is a deliberate part of the sink-fence contract —
// see those tests' module docs.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/__tests__/**/*.test.ts"],
  },
});
