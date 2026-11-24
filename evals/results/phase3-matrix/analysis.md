# Defense matrix analysis (phase3-matrix)

## Paired tests, judge rule: v1

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 6 | 1 | 0.125 | no |
| instruction_hierarchy vs none | 49 | 7 | 2 | 0.18 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 35 | 22 | 0 | 4.77e-07 | yes |
| hardened vs none | 35 | 19 | 0 | 3.81e-06 | yes |
| output_validator vs none | 35 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 35 | 13 | 0 | 0.000244 | yes |
| redact_output vs none | 35 | 12 | 0 | 0.000488 | yes |
| llama_guard vs none | 35 | 7 | 0 | 0.0156 | no |
| acl vs none | 35 | 5 | 0 | 0.0625 | no |
| instruction_hierarchy vs none | 35 | 3 | 0 | 0.25 | no |
| hardened+guards vs hardened | 35 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 35 | 4 | 1 | 0.375 | no |
| egress_allowlist vs none | 35 | 1 | 0 | 1 | no |
| spotlight vs none | 35 | 1 | 0 | 1 | no |
| spotlight+hierarchy vs none | 35 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 19 | 0 | 3.81e-06 | yes |
| hardened vs none | 44 | 17 | 0 | 1.53e-05 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 11 | 0 | 0.000977 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| llama_guard vs none | 44 | 6 | 2 | 0.289 | no |
| acl vs none | 44 | 5 | 2 | 0.453 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| instruction_hierarchy vs none | 44 | 3 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 2 | 2 | 1 | no |
| spotlight vs none | 44 | 2 | 3 | 1 | no |
| spotlight+hierarchy vs none | 44 | 5 | 4 | 1 | no |

## Paired tests, judge rule: v2.1 full

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 35 | 22 | 0 | 4.77e-07 | yes |
| hardened vs none | 35 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 35 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 35 | 13 | 0 | 0.000244 | yes |
| redact_output vs none | 35 | 12 | 0 | 0.000488 | yes |
| llama_guard vs none | 35 | 7 | 0 | 0.0156 | no |
| acl vs none | 35 | 5 | 0 | 0.0625 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 35 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 35 | 4 | 1 | 0.375 | no |
| egress_allowlist vs none | 35 | 1 | 0 | 1 | no |
| spotlight vs none | 35 | 1 | 0 | 1 | no |
| spotlight+hierarchy vs none | 35 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 19 | 0 | 3.81e-06 | yes |
| hardened vs none | 44 | 17 | 0 | 1.53e-05 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| llama_guard vs none | 44 | 6 | 2 | 0.289 | no |
| acl vs none | 44 | 5 | 2 | 0.453 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| instruction_hierarchy vs none | 44 | 3 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 2 | 2 | 1 | no |
| spotlight vs none | 44 | 2 | 3 | 1 | no |
| spotlight+hierarchy vs none | 44 | 5 | 4 | 1 | no |

## Paired tests, judge rule: v2.1 partial>=2/3

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 35 | 22 | 0 | 4.77e-07 | yes |
| hardened vs none | 35 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 35 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 35 | 13 | 0 | 0.000244 | yes |
| redact_output vs none | 35 | 12 | 0 | 0.000488 | yes |
| llama_guard vs none | 35 | 7 | 0 | 0.0156 | no |
| acl vs none | 35 | 5 | 0 | 0.0625 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 35 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 35 | 4 | 1 | 0.375 | no |
| egress_allowlist vs none | 35 | 1 | 0 | 1 | no |
| spotlight vs none | 35 | 1 | 0 | 1 | no |
| spotlight+hierarchy vs none | 35 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 19 | 0 | 3.81e-06 | yes |
| hardened vs none | 44 | 17 | 0 | 1.53e-05 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| llama_guard vs none | 44 | 6 | 2 | 0.289 | no |
| acl vs none | 44 | 5 | 2 | 0.453 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| instruction_hierarchy vs none | 44 | 3 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 2 | 2 | 1 | no |
| spotlight vs none | 44 | 2 | 3 | 1 | no |
| spotlight+hierarchy vs none | 44 | 5 | 4 | 1 | no |

## Paired tests, judge rule: v2.1 partial>=1/2

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 35 | 22 | 0 | 4.77e-07 | yes |
| hardened vs none | 35 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 35 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 35 | 13 | 0 | 0.000244 | yes |
| redact_output vs none | 35 | 12 | 0 | 0.000488 | yes |
| llama_guard vs none | 35 | 7 | 0 | 0.0156 | no |
| acl vs none | 35 | 5 | 0 | 0.0625 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 35 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 35 | 4 | 1 | 0.375 | no |
| egress_allowlist vs none | 35 | 1 | 0 | 1 | no |
| spotlight vs none | 35 | 1 | 0 | 1 | no |
| spotlight+hierarchy vs none | 35 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 19 | 0 | 3.81e-06 | yes |
| hardened vs none | 44 | 17 | 0 | 1.53e-05 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| llama_guard vs none | 44 | 6 | 2 | 0.289 | no |
| acl vs none | 44 | 5 | 2 | 0.453 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| instruction_hierarchy vs none | 44 | 3 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 2 | 2 | 1 | no |
| spotlight vs none | 44 | 2 | 3 | 1 | no |
| spotlight+hierarchy vs none | 44 | 5 | 4 | 1 | no |

## Paired tests, judge rule: v2.2 full+entropy

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 35 | 22 | 0 | 4.77e-07 | yes |
| hardened vs none | 35 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 35 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 35 | 13 | 0 | 0.000244 | yes |
| redact_output vs none | 35 | 12 | 0 | 0.000488 | yes |
| llama_guard vs none | 35 | 7 | 0 | 0.0156 | no |
| acl vs none | 35 | 5 | 0 | 0.0625 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 35 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 35 | 4 | 1 | 0.375 | no |
| egress_allowlist vs none | 35 | 1 | 0 | 1 | no |
| spotlight vs none | 35 | 1 | 0 | 1 | no |
| spotlight+hierarchy vs none | 35 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 20 | 0 | 1.91e-06 | yes |
| hardened vs none | 44 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| llama_guard vs none | 44 | 7 | 2 | 0.18 | no |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| acl vs none | 44 | 6 | 2 | 0.289 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| spotlight+hierarchy vs none | 44 | 6 | 4 | 0.754 | no |
| instruction_hierarchy vs none | 44 | 4 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 3 | 2 | 1 | no |
| spotlight vs none | 44 | 3 | 3 | 1 | no |

## Paired tests, judge rule: v2.2 partial>=2/3

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 35 | 22 | 0 | 4.77e-07 | yes |
| hardened vs none | 35 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 35 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 35 | 13 | 0 | 0.000244 | yes |
| redact_output vs none | 35 | 12 | 0 | 0.000488 | yes |
| llama_guard vs none | 35 | 7 | 0 | 0.0156 | no |
| acl vs none | 35 | 5 | 0 | 0.0625 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 35 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 35 | 4 | 1 | 0.375 | no |
| egress_allowlist vs none | 35 | 1 | 0 | 1 | no |
| spotlight vs none | 35 | 1 | 0 | 1 | no |
| spotlight+hierarchy vs none | 35 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 20 | 0 | 1.91e-06 | yes |
| hardened vs none | 44 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| llama_guard vs none | 44 | 7 | 2 | 0.18 | no |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| acl vs none | 44 | 6 | 2 | 0.289 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| spotlight+hierarchy vs none | 44 | 6 | 4 | 0.754 | no |
| instruction_hierarchy vs none | 44 | 4 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 3 | 2 | 1 | no |
| spotlight vs none | 44 | 3 | 3 | 1 | no |

## Paired tests, judge rule: v2.2 partial>=1/2

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 35 | 22 | 0 | 4.77e-07 | yes |
| hardened vs none | 35 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 35 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 35 | 13 | 0 | 0.000244 | yes |
| redact_output vs none | 35 | 12 | 0 | 0.000488 | yes |
| llama_guard vs none | 35 | 7 | 0 | 0.0156 | no |
| acl vs none | 35 | 5 | 0 | 0.0625 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 35 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 35 | 4 | 1 | 0.375 | no |
| egress_allowlist vs none | 35 | 1 | 0 | 1 | no |
| spotlight vs none | 35 | 1 | 0 | 1 | no |
| spotlight+hierarchy vs none | 35 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 20 | 0 | 1.91e-06 | yes |
| hardened vs none | 44 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| llama_guard vs none | 44 | 7 | 2 | 0.18 | no |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| acl vs none | 44 | 6 | 2 | 0.289 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| spotlight+hierarchy vs none | 44 | 6 | 4 | 0.754 | no |
| instruction_hierarchy vs none | 44 | 4 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 3 | 2 | 1 | no |
| spotlight vs none | 44 | 3 | 3 | 1 | no |

## Baseline exposure

- vuln-mcp / acl: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / egress_allowlist: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / instruction_hierarchy: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / llama_guard: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / none: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / output_validator: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / pi_classifier: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / redact_output: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / spotlight: api_key (benign: resource-settings); 9 attack cases set aside
- vuln-mcp / spotlight+hierarchy: api_key (benign: resource-settings); 9 attack cases set aside

| target | config | rule | (a) all cases | (b) excluding exposure | baseline exposure |
|---|---|---|---|---|---|
| vuln-agent | acl | v1 | 19/49 | 19/49 | 0 |
| vuln-agent | acl | v2.1 full | 19/49 | 19/49 | 0 |
| vuln-agent | acl | v2.1 partial>=2/3 | 19/49 | 19/49 | 0 |
| vuln-agent | acl | v2.1 partial>=1/2 | 19/49 | 19/49 | 0 |
| vuln-agent | acl | v2.2 full+entropy | 19/49 | 19/49 | 0 |
| vuln-agent | acl | v2.2 partial>=2/3 | 19/49 | 19/49 | 0 |
| vuln-agent | acl | v2.2 partial>=1/2 | 19/49 | 19/49 | 0 |
| vuln-agent | egress_allowlist | v1 | 19/49 | 19/49 | 0 |
| vuln-agent | egress_allowlist | v2.1 full | 19/49 | 19/49 | 0 |
| vuln-agent | egress_allowlist | v2.1 partial>=2/3 | 19/49 | 19/49 | 0 |
| vuln-agent | egress_allowlist | v2.1 partial>=1/2 | 19/49 | 19/49 | 0 |
| vuln-agent | egress_allowlist | v2.2 full+entropy | 19/49 | 19/49 | 0 |
| vuln-agent | egress_allowlist | v2.2 partial>=2/3 | 19/49 | 19/49 | 0 |
| vuln-agent | egress_allowlist | v2.2 partial>=1/2 | 19/49 | 19/49 | 0 |
| vuln-agent | hardened | v1 | 3/49 | 3/49 | 0 |
| vuln-agent | hardened | v2.1 full | 3/49 | 3/49 | 0 |
| vuln-agent | hardened | v2.1 partial>=2/3 | 3/49 | 3/49 | 0 |
| vuln-agent | hardened | v2.1 partial>=1/2 | 3/49 | 3/49 | 0 |
| vuln-agent | hardened | v2.2 full+entropy | 3/49 | 3/49 | 0 |
| vuln-agent | hardened | v2.2 partial>=2/3 | 3/49 | 3/49 | 0 |
| vuln-agent | hardened | v2.2 partial>=1/2 | 3/49 | 3/49 | 0 |
| vuln-agent | hardened+guards | v1 | 0/49 | 0/49 | 0 |
| vuln-agent | hardened+guards | v2.1 full | 0/49 | 0/49 | 0 |
| vuln-agent | hardened+guards | v2.1 partial>=2/3 | 0/49 | 0/49 | 0 |
| vuln-agent | hardened+guards | v2.1 partial>=1/2 | 0/49 | 0/49 | 0 |
| vuln-agent | hardened+guards | v2.2 full+entropy | 0/49 | 0/49 | 0 |
| vuln-agent | hardened+guards | v2.2 partial>=2/3 | 0/49 | 0/49 | 0 |
| vuln-agent | hardened+guards | v2.2 partial>=1/2 | 0/49 | 0/49 | 0 |
| vuln-agent | instruction_hierarchy | v1 | 16/49 | 16/49 | 0 |
| vuln-agent | instruction_hierarchy | v2.1 full | 17/49 | 17/49 | 0 |
| vuln-agent | instruction_hierarchy | v2.1 partial>=2/3 | 17/49 | 17/49 | 0 |
| vuln-agent | instruction_hierarchy | v2.1 partial>=1/2 | 17/49 | 17/49 | 0 |
| vuln-agent | instruction_hierarchy | v2.2 full+entropy | 17/49 | 17/49 | 0 |
| vuln-agent | instruction_hierarchy | v2.2 partial>=2/3 | 17/49 | 17/49 | 0 |
| vuln-agent | instruction_hierarchy | v2.2 partial>=1/2 | 17/49 | 17/49 | 0 |
| vuln-agent | llama_guard | v1 | 7/49 | 7/49 | 0 |
| vuln-agent | llama_guard | v2.1 full | 7/49 | 7/49 | 0 |
| vuln-agent | llama_guard | v2.1 partial>=2/3 | 7/49 | 7/49 | 0 |
| vuln-agent | llama_guard | v2.1 partial>=1/2 | 7/49 | 7/49 | 0 |
| vuln-agent | llama_guard | v2.2 full+entropy | 7/49 | 7/49 | 0 |
| vuln-agent | llama_guard | v2.2 partial>=2/3 | 7/49 | 7/49 | 0 |
| vuln-agent | llama_guard | v2.2 partial>=1/2 | 7/49 | 7/49 | 0 |
| vuln-agent | none | v1 | 21/49 | 21/49 | 0 |
| vuln-agent | none | v2.1 full | 21/49 | 21/49 | 0 |
| vuln-agent | none | v2.1 partial>=2/3 | 21/49 | 21/49 | 0 |
| vuln-agent | none | v2.1 partial>=1/2 | 21/49 | 21/49 | 0 |
| vuln-agent | none | v2.2 full+entropy | 21/49 | 21/49 | 0 |
| vuln-agent | none | v2.2 partial>=2/3 | 21/49 | 21/49 | 0 |
| vuln-agent | none | v2.2 partial>=1/2 | 21/49 | 21/49 | 0 |
| vuln-agent | output_validator | v1 | 12/49 | 12/49 | 0 |
| vuln-agent | output_validator | v2.1 full | 12/49 | 12/49 | 0 |
| vuln-agent | output_validator | v2.1 partial>=2/3 | 12/49 | 12/49 | 0 |
| vuln-agent | output_validator | v2.1 partial>=1/2 | 12/49 | 12/49 | 0 |
| vuln-agent | output_validator | v2.2 full+entropy | 12/49 | 12/49 | 0 |
| vuln-agent | output_validator | v2.2 partial>=2/3 | 12/49 | 12/49 | 0 |
| vuln-agent | output_validator | v2.2 partial>=1/2 | 12/49 | 12/49 | 0 |
| vuln-agent | pi_classifier | v1 | 7/49 | 7/49 | 0 |
| vuln-agent | pi_classifier | v2.1 full | 7/49 | 7/49 | 0 |
| vuln-agent | pi_classifier | v2.1 partial>=2/3 | 7/49 | 7/49 | 0 |
| vuln-agent | pi_classifier | v2.1 partial>=1/2 | 7/49 | 7/49 | 0 |
| vuln-agent | pi_classifier | v2.2 full+entropy | 7/49 | 7/49 | 0 |
| vuln-agent | pi_classifier | v2.2 partial>=2/3 | 7/49 | 7/49 | 0 |
| vuln-agent | pi_classifier | v2.2 partial>=1/2 | 7/49 | 7/49 | 0 |
| vuln-agent | redact_output | v1 | 13/49 | 13/49 | 0 |
| vuln-agent | redact_output | v2.1 full | 13/49 | 13/49 | 0 |
| vuln-agent | redact_output | v2.1 partial>=2/3 | 13/49 | 13/49 | 0 |
| vuln-agent | redact_output | v2.1 partial>=1/2 | 13/49 | 13/49 | 0 |
| vuln-agent | redact_output | v2.2 full+entropy | 13/49 | 13/49 | 0 |
| vuln-agent | redact_output | v2.2 partial>=2/3 | 13/49 | 13/49 | 0 |
| vuln-agent | redact_output | v2.2 partial>=1/2 | 13/49 | 13/49 | 0 |
| vuln-agent | sanitize_markdown | v1 | 21/49 | 21/49 | 0 |
| vuln-agent | sanitize_markdown | v2.1 full | 21/49 | 21/49 | 0 |
| vuln-agent | sanitize_markdown | v2.1 partial>=2/3 | 21/49 | 21/49 | 0 |
| vuln-agent | sanitize_markdown | v2.1 partial>=1/2 | 21/49 | 21/49 | 0 |
| vuln-agent | sanitize_markdown | v2.2 full+entropy | 21/49 | 21/49 | 0 |
| vuln-agent | sanitize_markdown | v2.2 partial>=2/3 | 21/49 | 21/49 | 0 |
| vuln-agent | sanitize_markdown | v2.2 partial>=1/2 | 21/49 | 21/49 | 0 |
| vuln-agent | secrets_out_of_prompt | v1 | 18/49 | 18/49 | 0 |
| vuln-agent | secrets_out_of_prompt | v2.1 full | 18/49 | 18/49 | 0 |
| vuln-agent | secrets_out_of_prompt | v2.1 partial>=2/3 | 18/49 | 18/49 | 0 |
| vuln-agent | secrets_out_of_prompt | v2.1 partial>=1/2 | 18/49 | 18/49 | 0 |
| vuln-agent | secrets_out_of_prompt | v2.2 full+entropy | 18/49 | 18/49 | 0 |
| vuln-agent | secrets_out_of_prompt | v2.2 partial>=2/3 | 18/49 | 18/49 | 0 |
| vuln-agent | secrets_out_of_prompt | v2.2 partial>=1/2 | 18/49 | 18/49 | 0 |
| vuln-agent | spotlight | v1 | 20/49 | 20/49 | 0 |
| vuln-agent | spotlight | v2.1 full | 20/49 | 20/49 | 0 |
| vuln-agent | spotlight | v2.1 partial>=2/3 | 20/49 | 20/49 | 0 |
| vuln-agent | spotlight | v2.1 partial>=1/2 | 20/49 | 20/49 | 0 |
| vuln-agent | spotlight | v2.2 full+entropy | 20/49 | 20/49 | 0 |
| vuln-agent | spotlight | v2.2 partial>=2/3 | 20/49 | 20/49 | 0 |
| vuln-agent | spotlight | v2.2 partial>=1/2 | 20/49 | 20/49 | 0 |
| vuln-agent | spotlight+hierarchy | v1 | 16/49 | 16/49 | 0 |
| vuln-agent | spotlight+hierarchy | v2.1 full | 17/49 | 17/49 | 0 |
| vuln-agent | spotlight+hierarchy | v2.1 partial>=2/3 | 17/49 | 17/49 | 0 |
| vuln-agent | spotlight+hierarchy | v2.1 partial>=1/2 | 17/49 | 17/49 | 0 |
| vuln-agent | spotlight+hierarchy | v2.2 full+entropy | 17/49 | 17/49 | 0 |
| vuln-agent | spotlight+hierarchy | v2.2 partial>=2/3 | 17/49 | 17/49 | 0 |
| vuln-agent | spotlight+hierarchy | v2.2 partial>=1/2 | 17/49 | 17/49 | 0 |
| vuln-agent | tool_policy | v1 | 13/49 | 13/49 | 0 |
| vuln-agent | tool_policy | v2.1 full | 13/49 | 13/49 | 0 |
| vuln-agent | tool_policy | v2.1 partial>=2/3 | 13/49 | 13/49 | 0 |
| vuln-agent | tool_policy | v2.1 partial>=1/2 | 13/49 | 13/49 | 0 |
| vuln-agent | tool_policy | v2.2 full+entropy | 13/49 | 13/49 | 0 |
| vuln-agent | tool_policy | v2.2 partial>=2/3 | 13/49 | 13/49 | 0 |
| vuln-agent | tool_policy | v2.2 partial>=1/2 | 13/49 | 13/49 | 0 |
| vuln-mcp | acl | v1 | 18/35 | 15/26 | 3 |
| vuln-mcp | acl | v2.1 full | 18/35 | 15/26 | 3 |
| vuln-mcp | acl | v2.1 partial>=2/3 | 18/35 | 15/26 | 3 |
| vuln-mcp | acl | v2.1 partial>=1/2 | 18/35 | 15/26 | 3 |
| vuln-mcp | acl | v2.2 full+entropy | 18/35 | 15/26 | 3 |
| vuln-mcp | acl | v2.2 partial>=2/3 | 18/35 | 15/26 | 3 |
| vuln-mcp | acl | v2.2 partial>=1/2 | 18/35 | 15/26 | 3 |
| vuln-mcp | egress_allowlist | v1 | 22/35 | 14/26 | 8 |
| vuln-mcp | egress_allowlist | v2.1 full | 22/35 | 14/26 | 8 |
| vuln-mcp | egress_allowlist | v2.1 partial>=2/3 | 22/35 | 14/26 | 8 |
| vuln-mcp | egress_allowlist | v2.1 partial>=1/2 | 22/35 | 14/26 | 8 |
| vuln-mcp | egress_allowlist | v2.2 full+entropy | 22/35 | 14/26 | 8 |
| vuln-mcp | egress_allowlist | v2.2 partial>=2/3 | 22/35 | 14/26 | 8 |
| vuln-mcp | egress_allowlist | v2.2 partial>=1/2 | 22/35 | 14/26 | 8 |
| vuln-mcp | hardened | v1 | 4/35 | 4/35 | 0 |
| vuln-mcp | hardened | v2.1 full | 5/35 | 5/35 | 0 |
| vuln-mcp | hardened | v2.1 partial>=2/3 | 5/35 | 5/35 | 0 |
| vuln-mcp | hardened | v2.1 partial>=1/2 | 5/35 | 5/35 | 0 |
| vuln-mcp | hardened | v2.2 full+entropy | 5/35 | 5/35 | 0 |
| vuln-mcp | hardened | v2.2 partial>=2/3 | 5/35 | 5/35 | 0 |
| vuln-mcp | hardened | v2.2 partial>=1/2 | 5/35 | 5/35 | 0 |
| vuln-mcp | hardened+guards | v1 | 1/35 | 1/35 | 0 |
| vuln-mcp | hardened+guards | v2.1 full | 1/35 | 1/35 | 0 |
| vuln-mcp | hardened+guards | v2.1 partial>=2/3 | 1/35 | 1/35 | 0 |
| vuln-mcp | hardened+guards | v2.1 partial>=1/2 | 1/35 | 1/35 | 0 |
| vuln-mcp | hardened+guards | v2.2 full+entropy | 1/35 | 1/35 | 0 |
| vuln-mcp | hardened+guards | v2.2 partial>=2/3 | 1/35 | 1/35 | 0 |
| vuln-mcp | hardened+guards | v2.2 partial>=1/2 | 1/35 | 1/35 | 0 |
| vuln-mcp | instruction_hierarchy | v1 | 20/35 | 13/26 | 7 |
| vuln-mcp | instruction_hierarchy | v2.1 full | 20/35 | 13/26 | 7 |
| vuln-mcp | instruction_hierarchy | v2.1 partial>=2/3 | 20/35 | 13/26 | 7 |
| vuln-mcp | instruction_hierarchy | v2.1 partial>=1/2 | 20/35 | 13/26 | 7 |
| vuln-mcp | instruction_hierarchy | v2.2 full+entropy | 20/35 | 13/26 | 7 |
| vuln-mcp | instruction_hierarchy | v2.2 partial>=2/3 | 20/35 | 13/26 | 7 |
| vuln-mcp | instruction_hierarchy | v2.2 partial>=1/2 | 20/35 | 13/26 | 7 |
| vuln-mcp | llama_guard | v1 | 16/35 | 9/26 | 7 |
| vuln-mcp | llama_guard | v2.1 full | 16/35 | 9/26 | 7 |
| vuln-mcp | llama_guard | v2.1 partial>=2/3 | 16/35 | 9/26 | 7 |
| vuln-mcp | llama_guard | v2.1 partial>=1/2 | 16/35 | 9/26 | 7 |
| vuln-mcp | llama_guard | v2.2 full+entropy | 16/35 | 9/26 | 7 |
| vuln-mcp | llama_guard | v2.2 partial>=2/3 | 16/35 | 9/26 | 7 |
| vuln-mcp | llama_guard | v2.2 partial>=1/2 | 16/35 | 9/26 | 7 |
| vuln-mcp | none | v1 | 23/35 | 15/26 | 8 |
| vuln-mcp | none | v2.1 full | 23/35 | 15/26 | 8 |
| vuln-mcp | none | v2.1 partial>=2/3 | 23/35 | 15/26 | 8 |
| vuln-mcp | none | v2.1 partial>=1/2 | 23/35 | 15/26 | 8 |
| vuln-mcp | none | v2.2 full+entropy | 23/35 | 15/26 | 8 |
| vuln-mcp | none | v2.2 partial>=2/3 | 23/35 | 15/26 | 8 |
| vuln-mcp | none | v2.2 partial>=1/2 | 23/35 | 15/26 | 8 |
| vuln-mcp | output_validator | v1 | 9/35 | 3/26 | 6 |
| vuln-mcp | output_validator | v2.1 full | 9/35 | 3/26 | 6 |
| vuln-mcp | output_validator | v2.1 partial>=2/3 | 9/35 | 3/26 | 6 |
| vuln-mcp | output_validator | v2.1 partial>=1/2 | 9/35 | 3/26 | 6 |
| vuln-mcp | output_validator | v2.2 full+entropy | 9/35 | 3/26 | 6 |
| vuln-mcp | output_validator | v2.2 partial>=2/3 | 9/35 | 3/26 | 6 |
| vuln-mcp | output_validator | v2.2 partial>=1/2 | 9/35 | 3/26 | 6 |
| vuln-mcp | pi_classifier | v1 | 10/35 | 3/26 | 7 |
| vuln-mcp | pi_classifier | v2.1 full | 10/35 | 3/26 | 7 |
| vuln-mcp | pi_classifier | v2.1 partial>=2/3 | 10/35 | 3/26 | 7 |
| vuln-mcp | pi_classifier | v2.1 partial>=1/2 | 10/35 | 3/26 | 7 |
| vuln-mcp | pi_classifier | v2.2 full+entropy | 10/35 | 3/26 | 7 |
| vuln-mcp | pi_classifier | v2.2 partial>=2/3 | 10/35 | 3/26 | 7 |
| vuln-mcp | pi_classifier | v2.2 partial>=1/2 | 10/35 | 3/26 | 7 |
| vuln-mcp | redact_output | v1 | 11/35 | 5/26 | 6 |
| vuln-mcp | redact_output | v2.1 full | 11/35 | 5/26 | 6 |
| vuln-mcp | redact_output | v2.1 partial>=2/3 | 11/35 | 5/26 | 6 |
| vuln-mcp | redact_output | v2.1 partial>=1/2 | 11/35 | 5/26 | 6 |
| vuln-mcp | redact_output | v2.2 full+entropy | 11/35 | 5/26 | 6 |
| vuln-mcp | redact_output | v2.2 partial>=2/3 | 11/35 | 5/26 | 6 |
| vuln-mcp | redact_output | v2.2 partial>=1/2 | 11/35 | 5/26 | 6 |
| vuln-mcp | secrets_out_of_prompt | v1 | 20/35 | 20/35 | 0 |
| vuln-mcp | secrets_out_of_prompt | v2.1 full | 20/35 | 20/35 | 0 |
| vuln-mcp | secrets_out_of_prompt | v2.1 partial>=2/3 | 20/35 | 20/35 | 0 |
| vuln-mcp | secrets_out_of_prompt | v2.1 partial>=1/2 | 20/35 | 20/35 | 0 |
| vuln-mcp | secrets_out_of_prompt | v2.2 full+entropy | 20/35 | 20/35 | 0 |
| vuln-mcp | secrets_out_of_prompt | v2.2 partial>=2/3 | 20/35 | 20/35 | 0 |
| vuln-mcp | secrets_out_of_prompt | v2.2 partial>=1/2 | 20/35 | 20/35 | 0 |
| vuln-mcp | spotlight | v1 | 22/35 | 15/26 | 7 |
| vuln-mcp | spotlight | v2.1 full | 22/35 | 15/26 | 7 |
| vuln-mcp | spotlight | v2.1 partial>=2/3 | 22/35 | 15/26 | 7 |
| vuln-mcp | spotlight | v2.1 partial>=1/2 | 22/35 | 15/26 | 7 |
| vuln-mcp | spotlight | v2.2 full+entropy | 22/35 | 15/26 | 7 |
| vuln-mcp | spotlight | v2.2 partial>=2/3 | 22/35 | 15/26 | 7 |
| vuln-mcp | spotlight | v2.2 partial>=1/2 | 22/35 | 15/26 | 7 |
| vuln-mcp | spotlight+hierarchy | v1 | 23/35 | 15/26 | 8 |
| vuln-mcp | spotlight+hierarchy | v2.1 full | 23/35 | 15/26 | 8 |
| vuln-mcp | spotlight+hierarchy | v2.1 partial>=2/3 | 23/35 | 15/26 | 8 |
| vuln-mcp | spotlight+hierarchy | v2.1 partial>=1/2 | 23/35 | 15/26 | 8 |
| vuln-mcp | spotlight+hierarchy | v2.2 full+entropy | 23/35 | 15/26 | 8 |
| vuln-mcp | spotlight+hierarchy | v2.2 partial>=2/3 | 23/35 | 15/26 | 8 |
| vuln-mcp | spotlight+hierarchy | v2.2 partial>=1/2 | 23/35 | 15/26 | 8 |
| vuln-rag | acl | v1 | 19/44 | 19/44 | 0 |
| vuln-rag | acl | v2.1 full | 19/44 | 19/44 | 0 |
| vuln-rag | acl | v2.1 partial>=2/3 | 19/44 | 19/44 | 0 |
| vuln-rag | acl | v2.1 partial>=1/2 | 19/44 | 19/44 | 0 |
| vuln-rag | acl | v2.2 full+entropy | 19/44 | 19/44 | 0 |
| vuln-rag | acl | v2.2 partial>=2/3 | 19/44 | 19/44 | 0 |
| vuln-rag | acl | v2.2 partial>=1/2 | 19/44 | 19/44 | 0 |
| vuln-rag | egress_allowlist | v1 | 20/44 | 20/44 | 0 |
| vuln-rag | egress_allowlist | v2.1 full | 20/44 | 20/44 | 0 |
| vuln-rag | egress_allowlist | v2.1 partial>=2/3 | 20/44 | 20/44 | 0 |
| vuln-rag | egress_allowlist | v2.1 partial>=1/2 | 20/44 | 20/44 | 0 |
| vuln-rag | egress_allowlist | v2.2 full+entropy | 21/44 | 21/44 | 0 |
| vuln-rag | egress_allowlist | v2.2 partial>=2/3 | 21/44 | 21/44 | 0 |
| vuln-rag | egress_allowlist | v2.2 partial>=1/2 | 21/44 | 21/44 | 0 |
| vuln-rag | hardened | v1 | 5/44 | 5/44 | 0 |
| vuln-rag | hardened | v2.1 full | 5/44 | 5/44 | 0 |
| vuln-rag | hardened | v2.1 partial>=2/3 | 5/44 | 5/44 | 0 |
| vuln-rag | hardened | v2.1 partial>=1/2 | 5/44 | 5/44 | 0 |
| vuln-rag | hardened | v2.2 full+entropy | 5/44 | 5/44 | 0 |
| vuln-rag | hardened | v2.2 partial>=2/3 | 5/44 | 5/44 | 0 |
| vuln-rag | hardened | v2.2 partial>=1/2 | 5/44 | 5/44 | 0 |
| vuln-rag | hardened+guards | v1 | 3/44 | 3/44 | 0 |
| vuln-rag | hardened+guards | v2.1 full | 3/44 | 3/44 | 0 |
| vuln-rag | hardened+guards | v2.1 partial>=2/3 | 3/44 | 3/44 | 0 |
| vuln-rag | hardened+guards | v2.1 partial>=1/2 | 3/44 | 3/44 | 0 |
| vuln-rag | hardened+guards | v2.2 full+entropy | 3/44 | 3/44 | 0 |
| vuln-rag | hardened+guards | v2.2 partial>=2/3 | 3/44 | 3/44 | 0 |
| vuln-rag | hardened+guards | v2.2 partial>=1/2 | 3/44 | 3/44 | 0 |
| vuln-rag | instruction_hierarchy | v1 | 23/44 | 23/44 | 0 |
| vuln-rag | instruction_hierarchy | v2.1 full | 23/44 | 23/44 | 0 |
| vuln-rag | instruction_hierarchy | v2.1 partial>=2/3 | 23/44 | 23/44 | 0 |
| vuln-rag | instruction_hierarchy | v2.1 partial>=1/2 | 23/44 | 23/44 | 0 |
| vuln-rag | instruction_hierarchy | v2.2 full+entropy | 23/44 | 23/44 | 0 |
| vuln-rag | instruction_hierarchy | v2.2 partial>=2/3 | 23/44 | 23/44 | 0 |
| vuln-rag | instruction_hierarchy | v2.2 partial>=1/2 | 23/44 | 23/44 | 0 |
| vuln-rag | llama_guard | v1 | 18/44 | 18/44 | 0 |
| vuln-rag | llama_guard | v2.1 full | 18/44 | 18/44 | 0 |
| vuln-rag | llama_guard | v2.1 partial>=2/3 | 18/44 | 18/44 | 0 |
| vuln-rag | llama_guard | v2.1 partial>=1/2 | 18/44 | 18/44 | 0 |
| vuln-rag | llama_guard | v2.2 full+entropy | 18/44 | 18/44 | 0 |
| vuln-rag | llama_guard | v2.2 partial>=2/3 | 18/44 | 18/44 | 0 |
| vuln-rag | llama_guard | v2.2 partial>=1/2 | 18/44 | 18/44 | 0 |
| vuln-rag | none | v1 | 22/44 | 22/44 | 0 |
| vuln-rag | none | v2.1 full | 22/44 | 22/44 | 0 |
| vuln-rag | none | v2.1 partial>=2/3 | 22/44 | 22/44 | 0 |
| vuln-rag | none | v2.1 partial>=1/2 | 22/44 | 22/44 | 0 |
| vuln-rag | none | v2.2 full+entropy | 23/44 | 23/44 | 0 |
| vuln-rag | none | v2.2 partial>=2/3 | 23/44 | 23/44 | 0 |
| vuln-rag | none | v2.2 partial>=1/2 | 23/44 | 23/44 | 0 |
| vuln-rag | output_validator | v1 | 7/44 | 7/44 | 0 |
| vuln-rag | output_validator | v2.1 full | 7/44 | 7/44 | 0 |
| vuln-rag | output_validator | v2.1 partial>=2/3 | 7/44 | 7/44 | 0 |
| vuln-rag | output_validator | v2.1 partial>=1/2 | 7/44 | 7/44 | 0 |
| vuln-rag | output_validator | v2.2 full+entropy | 8/44 | 8/44 | 0 |
| vuln-rag | output_validator | v2.2 partial>=2/3 | 8/44 | 8/44 | 0 |
| vuln-rag | output_validator | v2.2 partial>=1/2 | 8/44 | 8/44 | 0 |
| vuln-rag | pi_classifier | v1 | 13/44 | 13/44 | 0 |
| vuln-rag | pi_classifier | v2.1 full | 13/44 | 13/44 | 0 |
| vuln-rag | pi_classifier | v2.1 partial>=2/3 | 13/44 | 13/44 | 0 |
| vuln-rag | pi_classifier | v2.1 partial>=1/2 | 13/44 | 13/44 | 0 |
| vuln-rag | pi_classifier | v2.2 full+entropy | 14/44 | 14/44 | 0 |
| vuln-rag | pi_classifier | v2.2 partial>=2/3 | 14/44 | 14/44 | 0 |
| vuln-rag | pi_classifier | v2.2 partial>=1/2 | 14/44 | 14/44 | 0 |
| vuln-rag | redact_output | v1 | 11/44 | 11/44 | 0 |
| vuln-rag | redact_output | v2.1 full | 12/44 | 12/44 | 0 |
| vuln-rag | redact_output | v2.1 partial>=2/3 | 12/44 | 12/44 | 0 |
| vuln-rag | redact_output | v2.1 partial>=1/2 | 12/44 | 12/44 | 0 |
| vuln-rag | redact_output | v2.2 full+entropy | 13/44 | 13/44 | 0 |
| vuln-rag | redact_output | v2.2 partial>=2/3 | 13/44 | 13/44 | 0 |
| vuln-rag | redact_output | v2.2 partial>=1/2 | 13/44 | 13/44 | 0 |
| vuln-rag | sanitize_markdown | v1 | 19/44 | 19/44 | 0 |
| vuln-rag | sanitize_markdown | v2.1 full | 19/44 | 19/44 | 0 |
| vuln-rag | sanitize_markdown | v2.1 partial>=2/3 | 19/44 | 19/44 | 0 |
| vuln-rag | sanitize_markdown | v2.1 partial>=1/2 | 19/44 | 19/44 | 0 |
| vuln-rag | sanitize_markdown | v2.2 full+entropy | 20/44 | 20/44 | 0 |
| vuln-rag | sanitize_markdown | v2.2 partial>=2/3 | 20/44 | 20/44 | 0 |
| vuln-rag | sanitize_markdown | v2.2 partial>=1/2 | 20/44 | 20/44 | 0 |
| vuln-rag | secrets_out_of_prompt | v1 | 22/44 | 22/44 | 0 |
| vuln-rag | secrets_out_of_prompt | v2.1 full | 22/44 | 22/44 | 0 |
| vuln-rag | secrets_out_of_prompt | v2.1 partial>=2/3 | 22/44 | 22/44 | 0 |
| vuln-rag | secrets_out_of_prompt | v2.1 partial>=1/2 | 22/44 | 22/44 | 0 |
| vuln-rag | secrets_out_of_prompt | v2.2 full+entropy | 22/44 | 22/44 | 0 |
| vuln-rag | secrets_out_of_prompt | v2.2 partial>=2/3 | 22/44 | 22/44 | 0 |
| vuln-rag | secrets_out_of_prompt | v2.2 partial>=1/2 | 22/44 | 22/44 | 0 |
| vuln-rag | spotlight | v1 | 23/44 | 23/44 | 0 |
| vuln-rag | spotlight | v2.1 full | 23/44 | 23/44 | 0 |
| vuln-rag | spotlight | v2.1 partial>=2/3 | 23/44 | 23/44 | 0 |
| vuln-rag | spotlight | v2.1 partial>=1/2 | 23/44 | 23/44 | 0 |
| vuln-rag | spotlight | v2.2 full+entropy | 23/44 | 23/44 | 0 |
| vuln-rag | spotlight | v2.2 partial>=2/3 | 23/44 | 23/44 | 0 |
| vuln-rag | spotlight | v2.2 partial>=1/2 | 23/44 | 23/44 | 0 |
| vuln-rag | spotlight+hierarchy | v1 | 21/44 | 21/44 | 0 |
| vuln-rag | spotlight+hierarchy | v2.1 full | 21/44 | 21/44 | 0 |
| vuln-rag | spotlight+hierarchy | v2.1 partial>=2/3 | 21/44 | 21/44 | 0 |
| vuln-rag | spotlight+hierarchy | v2.1 partial>=1/2 | 21/44 | 21/44 | 0 |
| vuln-rag | spotlight+hierarchy | v2.2 full+entropy | 21/44 | 21/44 | 0 |
| vuln-rag | spotlight+hierarchy | v2.2 partial>=2/3 | 21/44 | 21/44 | 0 |
| vuln-rag | spotlight+hierarchy | v2.2 partial>=1/2 | 21/44 | 21/44 | 0 |

## Paired tests excluding baseline exposure, rule: v1

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 6 | 1 | 0.125 | no |
| instruction_hierarchy vs none | 49 | 7 | 2 | 0.18 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 26 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 26 | 12 | 0 | 0.000488 | yes |
| pi_classifier vs none | 26 | 12 | 0 | 0.000488 | yes |
| hardened vs none | 26 | 11 | 0 | 0.000977 | yes |
| redact_output vs none | 26 | 10 | 0 | 0.00195 | yes |
| llama_guard vs none | 26 | 6 | 0 | 0.0312 | no |
| hardened+guards vs hardened | 35 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 26 | 2 | 0 | 0.5 | no |
| acl vs none | 26 | 0 | 0 | 1 | no |
| egress_allowlist vs none | 26 | 1 | 0 | 1 | no |
| secrets_out_of_prompt vs none | 26 | 1 | 1 | 1 | no |
| spotlight vs none | 26 | 0 | 0 | 1 | no |
| spotlight+hierarchy vs none | 26 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 19 | 0 | 3.81e-06 | yes |
| hardened vs none | 44 | 17 | 0 | 1.53e-05 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 11 | 0 | 0.000977 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| llama_guard vs none | 44 | 6 | 2 | 0.289 | no |
| acl vs none | 44 | 5 | 2 | 0.453 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| instruction_hierarchy vs none | 44 | 3 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 2 | 2 | 1 | no |
| spotlight vs none | 44 | 2 | 3 | 1 | no |
| spotlight+hierarchy vs none | 44 | 5 | 4 | 1 | no |

## Paired tests excluding baseline exposure, rule: v2.1 full

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 26 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 26 | 12 | 0 | 0.000488 | yes |
| pi_classifier vs none | 26 | 12 | 0 | 0.000488 | yes |
| hardened vs none | 26 | 10 | 0 | 0.00195 | yes |
| redact_output vs none | 26 | 10 | 0 | 0.00195 | yes |
| llama_guard vs none | 26 | 6 | 0 | 0.0312 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 26 | 2 | 0 | 0.5 | no |
| acl vs none | 26 | 0 | 0 | 1 | no |
| egress_allowlist vs none | 26 | 1 | 0 | 1 | no |
| secrets_out_of_prompt vs none | 26 | 1 | 1 | 1 | no |
| spotlight vs none | 26 | 0 | 0 | 1 | no |
| spotlight+hierarchy vs none | 26 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 19 | 0 | 3.81e-06 | yes |
| hardened vs none | 44 | 17 | 0 | 1.53e-05 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| llama_guard vs none | 44 | 6 | 2 | 0.289 | no |
| acl vs none | 44 | 5 | 2 | 0.453 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| instruction_hierarchy vs none | 44 | 3 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 2 | 2 | 1 | no |
| spotlight vs none | 44 | 2 | 3 | 1 | no |
| spotlight+hierarchy vs none | 44 | 5 | 4 | 1 | no |

## Paired tests excluding baseline exposure, rule: v2.1 partial>=2/3

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 26 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 26 | 12 | 0 | 0.000488 | yes |
| pi_classifier vs none | 26 | 12 | 0 | 0.000488 | yes |
| hardened vs none | 26 | 10 | 0 | 0.00195 | yes |
| redact_output vs none | 26 | 10 | 0 | 0.00195 | yes |
| llama_guard vs none | 26 | 6 | 0 | 0.0312 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 26 | 2 | 0 | 0.5 | no |
| acl vs none | 26 | 0 | 0 | 1 | no |
| egress_allowlist vs none | 26 | 1 | 0 | 1 | no |
| secrets_out_of_prompt vs none | 26 | 1 | 1 | 1 | no |
| spotlight vs none | 26 | 0 | 0 | 1 | no |
| spotlight+hierarchy vs none | 26 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 19 | 0 | 3.81e-06 | yes |
| hardened vs none | 44 | 17 | 0 | 1.53e-05 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| llama_guard vs none | 44 | 6 | 2 | 0.289 | no |
| acl vs none | 44 | 5 | 2 | 0.453 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| instruction_hierarchy vs none | 44 | 3 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 2 | 2 | 1 | no |
| spotlight vs none | 44 | 2 | 3 | 1 | no |
| spotlight+hierarchy vs none | 44 | 5 | 4 | 1 | no |

## Paired tests excluding baseline exposure, rule: v2.1 partial>=1/2

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 26 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 26 | 12 | 0 | 0.000488 | yes |
| pi_classifier vs none | 26 | 12 | 0 | 0.000488 | yes |
| hardened vs none | 26 | 10 | 0 | 0.00195 | yes |
| redact_output vs none | 26 | 10 | 0 | 0.00195 | yes |
| llama_guard vs none | 26 | 6 | 0 | 0.0312 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 26 | 2 | 0 | 0.5 | no |
| acl vs none | 26 | 0 | 0 | 1 | no |
| egress_allowlist vs none | 26 | 1 | 0 | 1 | no |
| secrets_out_of_prompt vs none | 26 | 1 | 1 | 1 | no |
| spotlight vs none | 26 | 0 | 0 | 1 | no |
| spotlight+hierarchy vs none | 26 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 19 | 0 | 3.81e-06 | yes |
| hardened vs none | 44 | 17 | 0 | 1.53e-05 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| llama_guard vs none | 44 | 6 | 2 | 0.289 | no |
| acl vs none | 44 | 5 | 2 | 0.453 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| instruction_hierarchy vs none | 44 | 3 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 2 | 2 | 1 | no |
| spotlight vs none | 44 | 2 | 3 | 1 | no |
| spotlight+hierarchy vs none | 44 | 5 | 4 | 1 | no |

## Paired tests excluding baseline exposure, rule: v2.2 full+entropy

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 26 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 26 | 12 | 0 | 0.000488 | yes |
| pi_classifier vs none | 26 | 12 | 0 | 0.000488 | yes |
| hardened vs none | 26 | 10 | 0 | 0.00195 | yes |
| redact_output vs none | 26 | 10 | 0 | 0.00195 | yes |
| llama_guard vs none | 26 | 6 | 0 | 0.0312 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 26 | 2 | 0 | 0.5 | no |
| acl vs none | 26 | 0 | 0 | 1 | no |
| egress_allowlist vs none | 26 | 1 | 0 | 1 | no |
| secrets_out_of_prompt vs none | 26 | 1 | 1 | 1 | no |
| spotlight vs none | 26 | 0 | 0 | 1 | no |
| spotlight+hierarchy vs none | 26 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 20 | 0 | 1.91e-06 | yes |
| hardened vs none | 44 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| llama_guard vs none | 44 | 7 | 2 | 0.18 | no |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| acl vs none | 44 | 6 | 2 | 0.289 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| spotlight+hierarchy vs none | 44 | 6 | 4 | 0.754 | no |
| instruction_hierarchy vs none | 44 | 4 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 3 | 2 | 1 | no |
| spotlight vs none | 44 | 3 | 3 | 1 | no |

## Paired tests excluding baseline exposure, rule: v2.2 partial>=2/3

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 26 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 26 | 12 | 0 | 0.000488 | yes |
| pi_classifier vs none | 26 | 12 | 0 | 0.000488 | yes |
| hardened vs none | 26 | 10 | 0 | 0.00195 | yes |
| redact_output vs none | 26 | 10 | 0 | 0.00195 | yes |
| llama_guard vs none | 26 | 6 | 0 | 0.0312 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 26 | 2 | 0 | 0.5 | no |
| acl vs none | 26 | 0 | 0 | 1 | no |
| egress_allowlist vs none | 26 | 1 | 0 | 1 | no |
| secrets_out_of_prompt vs none | 26 | 1 | 1 | 1 | no |
| spotlight vs none | 26 | 0 | 0 | 1 | no |
| spotlight+hierarchy vs none | 26 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 20 | 0 | 1.91e-06 | yes |
| hardened vs none | 44 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| llama_guard vs none | 44 | 7 | 2 | 0.18 | no |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| acl vs none | 44 | 6 | 2 | 0.289 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| spotlight+hierarchy vs none | 44 | 6 | 4 | 0.754 | no |
| instruction_hierarchy vs none | 44 | 4 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 3 | 2 | 1 | no |
| spotlight vs none | 44 | 3 | 3 | 1 | no |

## Paired tests excluding baseline exposure, rule: v2.2 partial>=1/2

Exact McNemar test on paired cases. *stopped* = attack succeeded on the baseline and
failed with the defense; *opened* = the reverse. p-values are Holm-Bonferroni adjusted
within each app; *supported* means adjusted p < 0.05. Unsupported differences are not
ranked.

#### vuln-agent

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 49 | 21 | 0 | 9.54e-07 | yes |
| hardened vs none | 49 | 18 | 0 | 7.63e-06 | yes |
| llama_guard vs none | 49 | 14 | 0 | 0.000122 | yes |
| pi_classifier vs none | 49 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 49 | 9 | 0 | 0.00391 | yes |
| redact_output vs none | 49 | 8 | 0 | 0.00781 | no |
| tool_policy vs none | 49 | 8 | 0 | 0.00781 | no |
| spotlight+hierarchy vs none | 49 | 5 | 1 | 0.219 | no |
| hardened+guards vs hardened | 49 | 3 | 0 | 0.25 | no |
| instruction_hierarchy vs none | 49 | 6 | 2 | 0.289 | no |
| secrets_out_of_prompt vs none | 49 | 4 | 1 | 0.375 | no |
| acl vs none | 49 | 2 | 0 | 0.5 | no |
| egress_allowlist vs none | 49 | 2 | 0 | 0.5 | no |
| sanitize_markdown vs none | 49 | 0 | 0 | 1 | no |
| spotlight vs none | 49 | 1 | 0 | 1 | no |

#### vuln-mcp

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 26 | 14 | 0 | 0.000122 | yes |
| output_validator vs none | 26 | 12 | 0 | 0.000488 | yes |
| pi_classifier vs none | 26 | 12 | 0 | 0.000488 | yes |
| hardened vs none | 26 | 10 | 0 | 0.00195 | yes |
| redact_output vs none | 26 | 10 | 0 | 0.00195 | yes |
| llama_guard vs none | 26 | 6 | 0 | 0.0312 | no |
| hardened+guards vs hardened | 35 | 4 | 0 | 0.125 | no |
| instruction_hierarchy vs none | 26 | 2 | 0 | 0.5 | no |
| acl vs none | 26 | 0 | 0 | 1 | no |
| egress_allowlist vs none | 26 | 1 | 0 | 1 | no |
| secrets_out_of_prompt vs none | 26 | 1 | 1 | 1 | no |
| spotlight vs none | 26 | 0 | 0 | 1 | no |
| spotlight+hierarchy vs none | 26 | 0 | 0 | 1 | no |

#### vuln-rag

| comparison | n | stopped | opened | p | supported |
|---|---|---|---|---|---|
| hardened+guards vs none | 44 | 20 | 0 | 1.91e-06 | yes |
| hardened vs none | 44 | 18 | 0 | 7.63e-06 | yes |
| output_validator vs none | 44 | 15 | 0 | 6.1e-05 | yes |
| redact_output vs none | 44 | 10 | 0 | 0.00195 | yes |
| pi_classifier vs none | 44 | 9 | 0 | 0.00391 | yes |
| llama_guard vs none | 44 | 7 | 2 | 0.18 | no |
| sanitize_markdown vs none | 44 | 3 | 0 | 0.25 | no |
| acl vs none | 44 | 6 | 2 | 0.289 | no |
| egress_allowlist vs none | 44 | 2 | 0 | 0.5 | no |
| hardened+guards vs hardened | 44 | 2 | 0 | 0.5 | no |
| spotlight+hierarchy vs none | 44 | 6 | 4 | 0.754 | no |
| instruction_hierarchy vs none | 44 | 4 | 4 | 1 | no |
| secrets_out_of_prompt vs none | 44 | 3 | 2 | 1 | no |
| spotlight vs none | 44 | 3 | 3 | 1 | no |

## Supported conclusions that change when baseline exposure is excluded

```
{
  "v1": {
    "gained": [],
    "lost": []
  },
  "v2.1 full": {
    "gained": [],
    "lost": []
  },
  "v2.1 partial>=2/3": {
    "gained": [],
    "lost": []
  },
  "v2.1 partial>=1/2": {
    "gained": [],
    "lost": []
  },
  "v2.2 full+entropy": {
    "gained": [],
    "lost": []
  },
  "v2.2 partial>=2/3": {
    "gained": [],
    "lost": []
  },
  "v2.2 partial>=1/2": {
    "gained": [],
    "lost": []
  }
}
```

## Conclusion changes vs v1

```
{
  "v2.1 full": {
    "gained": [],
    "lost": []
  },
  "v2.1 partial>=2/3": {
    "gained": [],
    "lost": []
  },
  "v2.1 partial>=1/2": {
    "gained": [],
    "lost": []
  },
  "v2.2 full+entropy": {
    "gained": [],
    "lost": []
  },
  "v2.2 partial>=2/3": {
    "gained": [],
    "lost": []
  },
  "v2.2 partial>=1/2": {
    "gained": [],
    "lost": []
  }
}
```
