#!/usr/bin/env node
import { run } from '../src/cli.js';

run(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`Fatal: ${err?.stack || err}`);
    process.exit(2);
  });
