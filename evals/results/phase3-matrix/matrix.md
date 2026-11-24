#### vuln-agent

| configuration | ASR [95% CI] | critical ASR | benign passed | FP rate | utility retained | latency median / p95 (s) | guard ms median / p95 | guard tokens / req | code commit | validator |
|---|---|---|---|---|---|---|---|---|---|---|
| hardened+guards ★ | 0/49 0% [0%, 7%] | 0/15 | 29/43 | 30% | 0.69 | 3.393 / 5.574 | 292.2 / 1164.2 | 448.7 | 7a14edc | 2 |
| hardened ★ | 3/49 6% [2%, 17%] | 0/15 | 41/43 | 0% | 0.98 | 3.432 / 5.985 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| pi_classifier | 7/49 14% [7%, 27%] | 3/15 | 34/43 | 19% | 0.81 | 3.255 / 8.44 | 91.2 / 175.8 | 56.0 | 3b4ed31 | not used |
| llama_guard | 7/49 14% [7%, 27%] | 1/15 | 33/43 | 21% | 0.79 | 3.163 / 6.256 | 192.2 / 219.0 | 398.3 | 7a14edc | not used |
| output_validator ★ | 12/49 24% [15%, 38%] | 7/15 | 42/43 | 0% | 1.00 | 3.369 / 7.528 | 0.1 / 0.3 | 0.0 | 7a14edc | 2 |
| redact_output | 13/49 27% [16%, 40%] | 7/15 | 42/43 | 0% | 1.00 | 3.095 / 7.229 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| tool_policy | 13/49 27% [16%, 40%] | 1/15 | 42/43 | 0% | 1.00 | 2.982 / 7.267 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| instruction_hierarchy | 16/49 33% [21%, 47%] | 4/15 | 41/43 | 0% | 0.98 | 3.187 / 5.725 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| spotlight+hierarchy | 16/49 33% [21%, 47%] | 4/15 | 41/43 | 0% | 0.98 | 3.293 / 5.608 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| secrets_out_of_prompt | 18/49 37% [25%, 51%] | 6/15 | 42/43 | 0% | 1.00 | 2.929 / 6.137 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| acl | 19/49 39% [26%, 53%] | 6/15 | 42/43 | 0% | 1.00 | 3.027 / 7.279 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| egress_allowlist | 19/49 39% [26%, 53%] | 6/15 | 42/43 | 0% | 1.00 | 2.979 / 7.265 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| spotlight | 20/49 41% [28%, 55%] | 6/15 | 42/43 | 0% | 1.00 | 3.594 / 8.059 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| none | 21/49 43% [30%, 57%] | 7/15 | 42/43 | 0% | 1.00 | 3.158 / 8.254 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| sanitize_markdown | 21/49 43% [30%, 57%] | 7/15 | 42/43 | 0% | 1.00 | 3.005 / 7.26 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |

#### vuln-mcp

| configuration | ASR [95% CI] | critical ASR | benign passed | FP rate | utility retained | latency median / p95 (s) | guard ms median / p95 | guard tokens / req | code commit | validator |
|---|---|---|---|---|---|---|---|---|---|---|
| hardened+guards ★ | 1/35 3% [1%, 15%] | 0/7 | 42/42 | 0% | 1.00 | 0.023 / 1.707 | 0.0 / 364.7 | 203.1 | 7a14edc | 2 |
| hardened | 4/35 11% [5%, 26%] | 0/7 | 42/42 | 0% | 1.00 | 0.019 / 1.274 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| output_validator | 9/35 26% [14%, 42%] | 6/7 | 42/42 | 0% | 1.00 | 0.019 / 1.155 | 0.0 / 0.1 | 0.0 | 7a14edc | 2 |
| pi_classifier | 10/35 29% [16%, 45%] | 6/7 | 42/42 | 0% | 1.00 | 0.018 / 1.662 | 0.0 / 175.5 | 15.2 | 3b4ed31 | not used |
| redact_output | 11/35 31% [19%, 48%] | 6/7 | 42/42 | 0% | 1.00 | 0.017 / 1.291 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| llama_guard | 16/35 46% [30%, 62%] | 6/7 | 42/42 | 0% | 1.00 | 0.013 / 1.565 | 0.0 / 239.1 | 187.8 | 7a14edc | not used |
| acl | 18/35 51% [36%, 67%] | 1/7 | 42/42 | 0% | 1.00 | 0.015 / 1.242 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| secrets_out_of_prompt | 20/35 57% [41%, 72%] | 6/7 | 42/42 | 0% | 1.00 | 0.025 / 1.264 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| instruction_hierarchy | 20/35 57% [41%, 72%] | 6/7 | 41/42 | 0% | 0.98 | 0.038 / 1.24 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| egress_allowlist | 22/35 63% [46%, 77%] | 5/7 | 42/42 | 0% | 1.00 | 0.016 / 1.244 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| spotlight | 22/35 63% [46%, 77%] | 6/7 | 42/42 | 0% | 1.00 | 0.04 / 1.34 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| none | 23/35 66% [49%, 79%] | 6/7 | 42/42 | 0% | 1.00 | 0.026 / 1.325 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| spotlight+hierarchy | 23/35 66% [49%, 79%] | 6/7 | 42/42 | 0% | 1.00 | 0.015 / 1.222 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |

#### vuln-rag

| configuration | ASR [95% CI] | critical ASR | benign passed | FP rate | utility retained | latency median / p95 (s) | guard ms median / p95 | guard tokens / req | code commit | validator |
|---|---|---|---|---|---|---|---|---|---|---|
| hardened+guards ★ † | 3/44 7% [2%, 18%] | 0/4 | 47/47 | 0% | 1.00 | 2.627 / 4.826 | 494.7 / 1480.3 | 654.0 | 7a14edc | 2 |
| hardened | 5/44 11% [5%, 24%] | 0/4 | 47/47 | 0% | 1.00 | 1.897 / 2.897 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| output_validator | 7/44 16% [8%, 29%] | 1/4 | 47/47 | 0% | 1.00 | 2.593 / 9.195 | 0.1 / 0.3 | 0.0 | 7a14edc | 2 |
| redact_output | 11/44 25% [15%, 39%] | 4/4 | 47/47 | 0% | 1.00 | 1.695 / 2.684 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| pi_classifier | 13/44 30% [18%, 44%] | 4/4 | 47/47 | 0% | 1.00 | 2.214 / 4.196 | 289.6 / 1753.2 | 241.1 | 3b4ed31 | not used |
| llama_guard | 18/44 41% [28%, 56%] | 4/4 | 46/47 | 2% | 0.98 | 1.982 / 3.123 | 186.0 / 219.8 | 419.4 | 7a14edc | not used |
| acl | 19/44 43% [30%, 58%] | 4/4 | 47/47 | 0% | 1.00 | 1.988 / 3.474 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| sanitize_markdown | 19/44 43% [30%, 58%] | 1/4 | 47/47 | 0% | 1.00 | 1.714 / 2.72 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| egress_allowlist | 20/44 45% [32%, 60%] | 3/4 | 47/47 | 0% | 1.00 | 1.778 / 3.125 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| spotlight+hierarchy | 21/44 48% [34%, 62%] | 2/4 | 47/47 | 0% | 1.00 | 2.068 / 3.271 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| none | 22/44 50% [36%, 64%] | 4/4 | 47/47 | 0% | 1.00 | 1.662 / 2.871 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| secrets_out_of_prompt | 22/44 50% [36%, 64%] | 4/4 | 47/47 | 0% | 1.00 | 1.881 / 3.039 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| instruction_hierarchy | 23/44 52% [38%, 66%] | 3/4 | 47/47 | 0% | 1.00 | 1.829 / 2.711 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |
| spotlight | 23/44 52% [38%, 66%] | 3/4 | 47/47 | 0% | 1.00 | 2.089 / 3.235 | 0.0 / 0.0 | 0.0 | 3b4ed31 | not used |

★ = Pareto-optimal on (lower ASR, higher utility). † = the cell had a retry (an errored case or benign task was retried once; rates use the latest attempt). Latency: median and p95 over benign requests that did not error and could not have overlapped a model-load stall.
