// rollup.config.mjs
import typescript from "@rollup/plugin-typescript";

export default {
  input: "./x.hd.wallet.api.crypto.ts",
  output: [
    {
      file: "dist/x.hd.wallet.api.crypto.cjs.js",
      format: "cjs",
    },
    {
      file: "dist/x.hd.wallet.api.crypto.esm.js",
      format: "es",
    },
  ],
  plugins: [typescript()],
};
