# Per-package measured results

Generated with `python benchmarks/generate_tables.py`. Times are measured milliseconds, not estimates. Advisory lookups are excluded from these source-only verdicts. Error rows are excluded from FPR denominators. A dataset path/manifest version mismatch is explicitly noted; see the main benchmark report.

| Cohort | Exact identity / selected path | Verdict | Scan ms | Acquisition ms | Rule IDs / error |
| --- | --- | --- | ---: | ---: | --- |
| benign | lodash@4.17.21 | clean | 202.477 | 1136.422 | none |
| benign | chalk@5.3.0 | clean | 6.596 | 575.157 | none |
| benign | express@4.21.2 | clean | 12.597 | 629.827 | none |
| benign | axios@1.7.9 | clean | 92.945 | 1016.248 | install-script |
| benign | commander@12.1.0 | clean | 17.553 | 595.532 | none |
| benign | debug@4.3.7 | clean | 3.045 | 664.591 | none |
| benign | uuid@9.0.1 | clean | 11.864 | 568.518 | install-script |
| benign | minimist@1.2.8 | clean | 4.286 | 612.19 | none |
| benign | semver@7.6.3 | clean | 9.871 | 583.591 | none |
| benign | yargs@17.7.2 | clean | 28.154 | 699.237 | install-script |
| benign | dotenv@16.4.5 | clean | 3.045 | 1204.018 | none |
| benign | ms@2.1.3 | clean | 0.737 | 477.103 | none |
| benign | glob@10.4.5 | clean | 24.327 | 546.643 | install-script |
| benign | rimraf@5.0.10 | clean | 14.93 | 1102.038 | install-script |
| benign | mkdirp@3.0.1 | clean | 6.273 | 1084.598 | install-script |
| benign | is-odd@3.0.1 | clean | 0.516 | 467.327 | none |
| benign | is-number@7.0.0 | clean | 0.514 | 895.123 | none |
| benign | left-pad@1.3.0 | clean | 1.578 | 1152.81 | none |
| benign | is-even@1.0.0 | clean | 0.409 | 1848.03 | none |
| benign | is-positive@3.1.0 | clean | 0.352 | 1376.175 | none |
| benign | node-fetch@3.3.2 | clean | 10.137 | 876.292 | none |
| benign | cross-env@7.0.3 | clean | 1.51 | 852.682 | none |
| benign | execa@8.0.1 | clean | 6.99 | 455.122 | none |
| benign | got@13.0.0 | clean | 26.96 | 617.879 | install-script |
| benign | http-proxy@1.18.1 | clean | 6.6 | 610.203 | none |
| benign | typescript@5.6.3 | clean | 2125.052 | 10152.953 | none |
| benign | webpack@5.96.1 | clean | 591.336 | 5049.831 | install-script |
| benign | eslint@9.14.0 | clean | 400.483 | 2660.998 | none |
| benign | prettier@3.3.3 | clean | 920.348 | 6356.319 | none |
| benign | esbuild@0.24.0 | clean | 14.815 | 950.069 | install-script |
| benign | sharp@0.33.5 | clean | 37.773 | 1046.129 | install-script |
| benign | node-gyp@10.2.0 | clean | 19.357 | 1600.351 | none |
| benign | node-addon-api@8.2.2 | clean | 4.397 | 1776.89 | none |
| benign | bindings@1.5.0 | clean | 1.32 | 1040.405 | none |
| benign | node-pre-gyp@0.17.0 | clean | 9.331 | 4194.119 | none |
| benign | @mapbox/node-pre-gyp@1.0.11 | clean | 10.127 | 2395.177 | none |
| benign | protobufjs@7.4.0 | clean | 144.306 | 1503.635 | install-script |
| benign | grpc@1.24.11 | clean | 131.774 | 2004.091 | install-script |
| benign | sqlite3@5.1.7 | clean | 11.937 | 2019.117 | install-script |
| benign | bcrypt@5.1.1 | clean | 5.291 | 1092.089 | install-script |
| benign | better-sqlite3@11.5.0 | clean | 37.322 | 1614.756 | install-script |
| benign | buffer@6.0.3 | clean | 8.237 | 966.373 | none |
| benign | process@0.11.10 | clean | 1.875 | 858.686 | none |
| benign | core-js@3.39.0 | clean | 232.892 | 1481.474 | install-script |
| benign | react@18.3.1 | clean | 38.488 | 933.54 | none |
| benign | react-dom@18.3.1 | clean | 609.775 | 1569.077 | none |
| benign | vue@3.5.12 | clean | 305.607 | 1461.114 | none |
| benign | angular@1.8.3 | clean | 199.79 | 1322.917 | none |
| benign | jquery@3.7.1 | clean | 125.475 | 1249.915 | none |
| benign | d3@7.9.0 | clean | 135.271 | 1496.788 | none |
| benign | chart.js@4.4.6 | clean | 188.135 | 1634.858 | none |
| benign | moment@2.30.1 | clean | 524.414 | 1948.38 | none |
| benign | dayjs@1.11.13 | clean | 89.157 | 1552.642 | none |
| benign | rxjs@7.8.1 | clean | 354.274 | 1180.929 | none |
| benign | ramda@0.30.1 | clean | 179.632 | 1141.299 | install-script |
| benign | underscore@1.13.7 | clean | 87.698 | 1362.35 | none |
| benign | zod@3.23.8 | clean | 85.761 | 919.288 | install-script |
| benign | ajv@8.17.1 | clean | 91.544 | 991.455 | none |
| benign | joi@17.13.3 | clean | 64.701 | 806.959 | none |
| benign | yup@1.4.0 | clean | 23.507 | 1249.938 | none |
| benign | fastify@4.28.1 | clean | 228.116 | 1228.284 | none |
| benign | koa@2.15.3 | clean | 6.046 | 1122.697 | install-script |
| benign | @hapi/hapi@21.3.12 | clean | 52.717 | 1476.411 | none |
| benign | cors@2.8.5 | clean | 1.267 | 774.581 | none |
| benign | helmet@8.0.0 | clean | 5.201 | 599.751 | none |
| benign | morgan@1.10.0 | clean | 2.092 | 512.43 | none |
| benign | body-parser@1.20.3 | clean | 3.595 | 493.645 | none |
| benign | cookie@0.7.2 | clean | 1.617 | 1021.769 | none |
| benign | ws@8.18.0 | clean | 16.618 | 1105.62 | none |
| benign | socket.io@4.8.1 | clean | 65.314 | 1214.333 | none |
| benign | undici@6.21.0 | clean | 130.629 | 2498.903 | install-script |
| benign | form-data@4.0.1 | clean | 2.657 | 1030.034 | none |
| benign | mime@4.0.4 | clean | 13.217 | 803.473 | none |
| benign | mime-types@2.1.35 | clean | 1.092 | 1082.213 | none |
| benign | qs@6.13.0 | clean | 27.23 | 1054.649 | none |
| benign | query-string@9.1.1 | clean | 4.604 | 1939.7 | none |
| benign | @babel/core@7.26.0 | clean | 32.813 | 1532.512 | none |
| benign | rollup@4.24.0 | clean | 346.011 | 1309.706 | install-script |
| benign | vite@5.4.10 | clean | 445.607 | 1348.407 | none |
| benign | terser@5.36.0 | clean | 286.062 | 1256.583 | install-script |
| benign | uglify-js@3.19.3 | clean | 122.422 | 1434.491 | none |
| benign | acorn@8.14.0 | clean | 61.156 | 1256.07 | install-script |
| benign | espree@10.3.0 | clean | 7.977 | 1391.53 | none |
| benign | esprima@4.0.1 | clean | 35.051 | 1103.889 | none |
| benign | source-map@0.7.4 | clean | 19.582 | 1025.07 | none |
| benign | convert-source-map@2.0.0 | clean | 1.382 | 950.953 | none |
| benign | source-map-support@0.5.21 | clean | 9.76 | 1102.51 | none |
| benign | babel-loader@9.2.1 | clean | 2.707 | 1031.411 | none |
| benign | webpack-cli@5.1.4 | acquisition-error | — | — | Duplicate archive path |
| benign | webpack-dev-server@5.1.0 | clean | 59.949 | 1126.361 | install-script |
| benign | jest@29.7.0 | clean | 0.665 | 472.379 | none |
| benign | mocha@10.7.3 | clean | 152.031 | 1141.952 | none |
| benign | chai@5.1.2 | clean | 54.631 | 857.18 | none |
| benign | sinon@19.0.2 | clean | 635.591 | 13955.966 | none |
| benign | ava@6.2.0 | clean | 34.252 | 959.204 | none |
| benign | vitest@2.1.4 | clean | 207.644 | 1241.611 | none |
| benign | nyc@17.1.0 | clean | 5.302 | 891.651 | none |
| benign | c8@10.1.2 | clean | 4.236 | 791.026 | none |
| benign | chokidar@4.0.1 | clean | 15.737 | 1170.492 | none |
| benign | fsevents@2.3.3 | clean | 1.313 | 797.623 | none |
| benign | fs-extra@11.2.0 | clean | 5.758 | 568.131 | none |
| benign | graceful-fs@4.2.11 | clean | 3.442 | 579.156 | none |
| benign | fast-glob@3.3.2 | clean | 9.023 | 570.821 | none |
| benign | micromatch@4.0.8 | clean | 2.281 | 838.906 | none |
| benign | picomatch@4.0.2 | clean | 7.273 | 785.442 | none |
| benign | minimatch@9.0.5 | clean | 19.389 | 1266.115 | install-script |
| benign | balanced-match@1.0.2 | clean | 0.683 | 1211.55 | none |
| benign | brace-expansion@2.0.1 | clean | 0.995 | 1341.373 | none |
| benign | concat-map@0.0.1 | clean | 0.643 | 1104.894 | none |
| benign | inherits@2.0.4 | clean | 0.458 | 878.229 | none |
| benign | safe-buffer@5.2.1 | clean | 1.639 | 583.704 | none |
| benign | iconv-lite@0.6.3 | clean | 16.02 | 1232.7 | none |
| benign | string-width@5.1.2 | clean | 0.726 | 464.556 | none |
| benign | strip-ansi@7.1.0 | clean | 0.483 | 960.901 | none |
| benign | ansi-regex@6.1.0 | clean | 0.524 | 851.998 | none |
| benign | supports-color@9.4.0 | clean | 1.089 | 790.689 | none |
| benign | cliui@8.0.1 | clean | 2.821 | 1463.98 | install-script |
| benign | wrap-ansi@8.1.0 | clean | 1.243 | 1076.594 | none |
| benign | ora@8.1.1 | clean | 2.354 | 592.447 | none |
| benign | inquirer@9.3.7 | clean | 8.522 | 711.5 | none |
| benign | enquirer@2.4.1 | clean | 16.85 | 656.46 | none |
| benign | prompts@2.4.2 | clean | 19.535 | 626.222 | none |
| benign | listr2@8.2.5 | clean | 24.553 | 538.278 | none |
| benign | p-limit@5.0.0 | clean | 0.935 | 800.933 | none |
| benign | p-queue@8.0.1 | clean | 2.915 | 589.325 | none |
| benign | p-map@7.0.2 | clean | 1.966 | 779.694 | none |
| malicious | @react-native-aria/radio@0.2.14 | clean | 14.711 | — | none |
| malicious | html-to-base64-image@1.0.2 | clean | 835.635 | — | none |
| malicious | evm-checkcode-cli@1.0.14 | review | 2655.004 | — | download-execute, install-script |
| malicious | @postman/postman-collection-fork@4.3.3 | review | 2835.428 | — | download-execute, install-script |
| malicious | @react-native-aria/switch@0.2.5 | clean | 11.771 | — | none |
| malicious | @asyncapi/generator-components@0.3.3 | review | 2654.554 | — | download-execute, install-script |
| malicious | @mastra/voice-cloudflare@0.12.3 | clean | 243.739 | — | none |
| malicious | @osmanekrem/bmad@1.0.6 | review | 2890.938 | — | download-execute, install-script |
| malicious | @mastra/voice-openai@0.12.3 | clean | 256.05 | — | none |
| malicious | @yoobic/jpeg-camera-es6@1.0.12 | clean | 54.308 | — | none; manifest/path version mismatch |
| malicious | rediff-viewer@0.0.7 | review | 2794.346 | — | download-execute, install-script |
| malicious | react-native-worklet-functions@3.3.3 | review | 2605.707 | — | download-execute, install-script |
| malicious | create-hest-app@0.1.9 | clean | 1197.738 | — | install-script |
| malicious | @redhat-cloud-services/frontend-components-config-utilities@4.11.2 | clean | 889.906 | — | install-script |
| malicious | @teselagen/bio-parsers@0.4.29 | clean | 1503.081 | — | install-script |
| malicious | yargs-help-output@5.0.3 | clean | 923.483 | — | install-script |
| malicious | shinhan-limit-scrap@1.0.3 | review | 2218.885 | — | download-execute, install-script |
| malicious | @art-ws/common@2.0.28 | clean | 880.334 | — | install-script |
| malicious | @mastra/codemod@1.0.4 | clean | 65.048 | — | none |
| malicious | @redhat-cloud-services/quickstarts-client@4.0.11 | clean | 898.405 | — | install-script |
| malicious | @mastra/voice-gladia@0.12.2 | clean | 215.368 | — | none |
| malicious | eslint-config-ppf@0.128.2 | clean | 119.189 | — | install-script |
| malicious | jsonsurge@1.0.7 | review | 2593.103 | — | download-execute, install-script |
| malicious | n8n-nodes-vercel-ai-sdk@0.1.7 | review | 2715.935 | — | download-execute, install-script |
| malicious | @mastra/e2b@0.3.4 | clean | 98.324 | — | none |
| malicious | web-scraper-mcp@1.1.4 | review | 2725.631 | — | download-execute, install-script |
| malicious | @teselagen/file-utils@0.3.21 | clean | 1162.281 | — | install-script |
| malicious | @zapier/babel-preset-zapier@6.4.2 | review | 2624.652 | — | download-execute, install-script |
| malicious | @posthog/piscina@3.2.1 | review | 2752.038 | — | download-execute, install-script |
| malicious | @kvytech/medusa-plugin-newsletter@0.0.5 | review | 2647.309 | — | download-execute, install-script |
| malicious | @toptal/picasso-forms@73.3.2 | review | 364.553 | — | destructive-install, install-script, install-secret-exfil |
| malicious | medusa-plugin-momo@0.0.68 | review | 2775.942 | — | download-execute, install-script |
| malicious | @things-factory/auth-base@9.0.44 | clean | 1462.194 | — | install-script |
| malicious | @hapheus/n8n-nodes-pgp@1.5.1 | review | 2797.272 | — | download-execute, install-script |
| malicious | koa2-swagger-ui@5.11.1 | clean | 911.386 | — | install-script |
| malicious | @art-ws/openapi@0.1.12 | clean | 892.177 | — | install-script |
| synthetic | postinstall-env-exfil@ | review | 0.214 | — | env-network, install-script |
| synthetic | base64-eval@ | review | 0.241 | — | encoded-execution, install-script |
| synthetic | dropper@ | review | 0.127 | — | download-execute, install-script |
| synthetic | reverse-shell@ | review | 0.136 | — | install-script, reverse-shell |
| synthetic | typosquat-only@ | clean | 0.026 | — | install-script, typosquat |
| synthetic | private-name@ | review | 0.098 | — | install-script, private-name |
| synthetic | indirect-env-exfil-miss@ | clean | 0.164 | — | install-script |

## Every final source miss

The explanations below distinguish observed feature coverage from unresolved forensic attribution. They do not claim to have reconstructed every payload. Counts/locations and upstream artifact hashes are in final.json.

| Dataset-labeled identity | Observed limitation / remaining investigation |
| --- | --- |
| @react-native-aria/radio@0.2.14 | No modeled sensitive-read/encoded-execution chain in the inspected source set. Needs full upstream artifact and runtime investigation; no specific evasion technique is asserted. |
| html-to-base64-image@1.0.2 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| @react-native-aria/switch@0.2.5 | No modeled sensitive-read/encoded-execution chain in the inspected source set. Needs full upstream artifact and runtime investigation; no specific evasion technique is asserted. |
| @mastra/voice-cloudflare@0.12.3 | Encoding/network symbols occur without a modeled direct execution or exfiltration chain. Counting those symbols alone would recreate false positives; payload attribution remains unresolved. |
| @mastra/voice-openai@0.12.3 | Encoding/network symbols occur without a modeled direct execution or exfiltration chain. Counting those symbols alone would recreate false positives; payload attribution remains unresolved. |
| @yoobic/jpeg-camera-es6@1.0.12 | Dataset path says a different version than the manifest; artifact-level label is uncertain. Excluded in the conservative sensitivity calculation. |
| create-hest-app@0.1.9 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| @redhat-cloud-services/frontend-components-config-utilities@4.11.2 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| @teselagen/bio-parsers@0.4.29 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| yargs-help-output@5.0.3 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| @art-ws/common@2.0.28 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| @mastra/codemod@1.0.4 | Environment/process/network capabilities occur without the direct correlated patterns modeled by this engine. Alias/cross-file behavior is outside coverage; payload attribution remains unresolved. |
| @redhat-cloud-services/quickstarts-client@4.0.11 | Encoding/network symbols occur without a modeled direct execution or exfiltration chain. Counting those symbols alone would recreate false positives; payload attribution remains unresolved. |
| @mastra/voice-gladia@0.12.2 | Encoding/network symbols occur without a modeled direct execution or exfiltration chain. Counting those symbols alone would recreate false positives; payload attribution remains unresolved. |
| eslint-config-ppf@0.128.2 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| @mastra/e2b@0.3.4 | Environment/process/network capabilities occur without the direct correlated patterns modeled by this engine. Alias/cross-file behavior is outside coverage; payload attribution remains unresolved. |
| @teselagen/file-utils@0.3.21 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| @things-factory/auth-base@9.0.44 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| koa2-swagger-ui@5.11.1 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
| @art-ws/openapi@0.1.12 | Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved. |
