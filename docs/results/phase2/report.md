# Parry scan 20261123T190533Z-s1337

Seed 1337 · cases 3ac8213f9895 · commit fb68959 · judge model qwen2.5:7b-instruct

Attack success rate (ASR) = successful trials / scored trials, with 95% Wilson intervals.
Attempt rate also counts trials where the target was steered but a control stopped the effect.

| target | profile | model | ASR | attempt rate | critical ASR |
|---|---|---|---|---|---|
| hard-agent | hardened | qwen2.5:7b-instruct | 3/49 6% [2%, 17%] | 8/49 16% [9%, 29%] | 0/15 0% [0%, 20%] |
| hard-mcp | hardened | qwen2.5:7b-instruct | 3/35 9% [3%, 22%] | 4/35 11% [5%, 26%] | 0/7 0% [0%, 35%] |
| hard-rag | hardened | qwen2.5:7b-instruct | 5/44 11% [5%, 24%] | 6/44 14% [6%, 27%] | 0/4 0% [0%, 49%] |
| vuln-agent | vulnerable | qwen2.5:7b-instruct | 21/49 43% [30%, 57%] | 21/49 43% [30%, 57%] | 7/15 47% [25%, 70%] |
| vuln-mcp | vulnerable | qwen2.5:7b-instruct | 23/35 66% [49%, 79%] | 23/35 66% [49%, 79%] | 6/7 86% [49%, 97%] |
| vuln-rag | vulnerable | qwen2.5:7b-instruct | 22/44 50% [36%, 64%] | 22/44 50% [36%, 64%] | 4/4 100% [51%, 100%] |

Trials 256, scored 256, skipped 0, errors 0.

### ASR by attack family

| family | hard-agent | hard-mcp | hard-rag | vuln-agent | vuln-mcp | vuln-rag |
|---|---|---|---|---|---|---|
| excessive_agency | 0/6 0% [0%, 39%] | - | - | 6/6 100% [61%, 100%] | - | - |
| indirect_injection | 2/10 20% [6%, 51%] | 2/5 40% [12%, 77%] | 4/7 57% [25%, 84%] | 4/10 40% [17%, 69%] | 3/5 60% [23%, 88%] | 6/7 86% [49%, 97%] |
| mcp_tool_abuse | - | 0/7 0% [0%, 35%] | - | - | 7/7 100% [65%, 100%] | - |
| multi_turn | 0/3 0% [0%, 56%] | - | 0/3 0% [0%, 56%] | 3/3 100% [44%, 100%] | - | 2/3 67% [21%, 94%] |
| obfuscation | 0/11 0% [0%, 26%] | 0/11 0% [0%, 26%] | 0/14 0% [0%, 22%] | 2/11 18% [5%, 48%] | 5/11 45% [21%, 72%] | 3/14 21% [8%, 48%] |
| output_handling | 0/1 0% [0%, 79%] | - | 0/4 0% [0%, 49%] | 1/1 100% [21%, 100%] | - | 4/4 100% [51%, 100%] |
| prompt_extraction | 1/10 10% [2%, 40%] | 1/10 10% [2%, 40%] | 1/10 10% [2%, 40%] | 3/10 30% [11%, 60%] | 6/10 60% [31%, 83%] | 3/10 30% [11%, 60%] |
| sensitive_data | 0/4 0% [0%, 49%] | 0/2 0% [0%, 66%] | 0/6 0% [0%, 39%] | 2/4 50% [15%, 85%] | 2/2 100% [34%, 100%] | 4/6 67% [30%, 90%] |
| tool_poisoning | 0/4 0% [0%, 49%] | - | - | 0/4 0% [0%, 49%] | - | - |

### ASR by delivery channel

| channel | hard-agent | hard-mcp | hard-rag | vuln-agent | vuln-mcp | vuln-rag |
|---|---|---|---|---|---|---|
| direct | 1/31 3% [1%, 16%] | 1/23 4% [1%, 21%] | 1/30 3% [1%, 17%] | 13/31 42% [26%, 59%] | 13/23 57% [37%, 74%] | 10/30 33% [19%, 51%] |
| document | - | - | 3/7 43% [16%, 75%] | - | - | 6/7 86% [49%, 97%] |
| mcp_call | - | 0/7 0% [0%, 35%] | - | - | 7/7 100% [65%, 100%] | - |
| mcp_description | 0/4 0% [0%, 49%] | - | - | 0/4 0% [0%, 49%] | - | - |
| multi_turn | 0/3 0% [0%, 56%] | - | 0/3 0% [0%, 56%] | 3/3 100% [44%, 100%] | - | 2/3 67% [21%, 94%] |
| notes | - | 2/5 40% [12%, 77%] | - | - | 3/5 60% [23%, 88%] | - |
| tool_output | 1/7 14% [3%, 51%] | - | - | 3/7 43% [16%, 75%] | - | - |
| web | 1/4 25% [5%, 70%] | - | 1/4 25% [5%, 70%] | 2/4 50% [15%, 85%] | - | 4/4 100% [51%, 100%] |

### Planted content confirmed delivered

| channel | hard-agent | hard-mcp | hard-rag | vuln-agent | vuln-mcp | vuln-rag |
|---|---|---|---|---|---|---|
| direct | 31/31 100% [89%, 100%] | 23/23 100% [86%, 100%] | 30/30 100% [89%, 100%] | 31/31 100% [89%, 100%] | 23/23 100% [86%, 100%] | 30/30 100% [89%, 100%] |
| document | - | - | 7/7 100% [65%, 100%] | - | - | 7/7 100% [65%, 100%] |
| mcp_call | - | 7/7 100% [65%, 100%] | - | - | 7/7 100% [65%, 100%] | - |
| mcp_description | 0/4 0% [0%, 49%] | - | - | 4/4 100% [51%, 100%] | - | - |
| multi_turn | 3/3 100% [44%, 100%] | - | 3/3 100% [44%, 100%] | 3/3 100% [44%, 100%] | - | 3/3 100% [44%, 100%] |
| notes | - | - | - | - | - | - |
| tool_output | 7/7 100% [65%, 100%] | - | - | 7/7 100% [65%, 100%] | - | - |
| web | 2/4 50% [15%, 85%] | - | 2/4 50% [15%, 85%] | 4/4 100% [51%, 100%] | - | 4/4 100% [51%, 100%] |

### ASR over delivered trials only

| channel | hard-agent | hard-mcp | hard-rag | vuln-agent | vuln-mcp | vuln-rag |
|---|---|---|---|---|---|---|
| direct | 1/31 3% [1%, 16%] | 1/23 4% [1%, 21%] | 1/30 3% [1%, 17%] | 13/31 42% [26%, 59%] | 13/23 57% [37%, 74%] | 10/30 33% [19%, 51%] |
| document | - | - | 3/7 43% [16%, 75%] | - | - | 6/7 86% [49%, 97%] |
| mcp_call | - | 0/7 0% [0%, 35%] | - | - | 7/7 100% [65%, 100%] | - |
| mcp_description | - | - | - | 0/4 0% [0%, 49%] | - | - |
| multi_turn | 0/3 0% [0%, 56%] | - | 0/3 0% [0%, 56%] | 3/3 100% [44%, 100%] | - | 2/3 67% [21%, 94%] |
| notes | - | - | - | - | - | - |
| tool_output | 1/7 14% [3%, 51%] | - | - | 3/7 43% [16%, 75%] | - | - |
| web | 1/2 50% [9%, 91%] | - | 1/2 50% [9%, 91%] | 2/4 50% [15%, 85%] | - | 4/4 100% [51%, 100%] |

### ASR by goal

| goal | hard-agent | hard-mcp | hard-rag | vuln-agent | vuln-mcp | vuln-rag |
|---|---|---|---|---|---|---|
| exfil | 0/1 0% [0%, 79%] | 0/1 0% [0%, 79%] | 0/4 0% [0%, 49%] | 1/1 100% [21%, 100%] | 1/1 100% [21%, 100%] | 4/4 100% [51%, 100%] |
| forbidden_tool | 0/17 0% [0%, 18%] | - | - | 8/17 47% [26%, 69%] | - | - |
| hijack | 2/4 50% [15%, 85%] | 1/2 50% [9%, 91%] | 3/5 60% [23%, 88%] | 3/4 75% [30%, 95%] | 1/2 50% [9%, 91%] | 5/5 100% [57%, 100%] |
| leak_secret | 0/4 0% [0%, 49%] | 0/9 0% [0%, 30%] | 0/10 0% [0%, 28%] | 2/4 50% [15%, 85%] | 8/9 89% [57%, 98%] | 5/10 50% [24%, 76%] |
| leak_system_prompt | 1/23 4% [1%, 21%] | 1/22 5% [1%, 22%] | 1/24 4% [1%, 20%] | 7/23 30% [16%, 51%] | 12/22 55% [35%, 73%] | 7/24 29% [15%, 49%] |
| misinformation | - | 1/1 100% [21%, 100%] | 1/1 100% [21%, 100%] | - | 1/1 100% [21%, 100%] | 1/1 100% [21%, 100%] |

### Coverage (from attack metadata)

| ID | name | cases | families |
|---|---|---|---|
| LLM01:2025 | Prompt Injection | 52 | indirect_injection, multi_turn, obfuscation, output_handling, prompt_extraction, tool_poisoning |
| LLM02:2025 | Sensitive Information Disclosure | 30 | excessive_agency, indirect_injection, mcp_tool_abuse, multi_turn, obfuscation, output_handling, sensitive_data |
| LLM03:2025 | Supply Chain | 4 | tool_poisoning |
| LLM04:2025 | Data and Model Poisoning | 0 | not covered |
| LLM05:2025 | Improper Output Handling | 11 | obfuscation, output_handling |
| LLM06:2025 | Excessive Agency | 27 | excessive_agency, indirect_injection, mcp_tool_abuse, multi_turn, sensitive_data, tool_poisoning |
| LLM07:2025 | System Prompt Leakage | 25 | indirect_injection, multi_turn, obfuscation, prompt_extraction |
| LLM08:2025 | Vector and Embedding Weaknesses | 9 | indirect_injection, sensitive_data |
| LLM09:2025 | Misinformation | 2 | indirect_injection |
| LLM10:2025 | Unbounded Consumption | 0 | not covered |
| AML.T0051 | LLM Prompt Injection | 0 | not covered |
| AML.T0051.000 | LLM Prompt Injection: Direct | 18 | excessive_agency, prompt_extraction, sensitive_data |
| AML.T0051.001 | LLM Prompt Injection: Indirect | 29 | indirect_injection, output_handling, tool_poisoning |
| AML.T0054 | LLM Jailbreak | 4 | multi_turn |
| AML.T0056 | Extract LLM System Prompt | 25 | indirect_injection, multi_turn, obfuscation, prompt_extraction |
| AML.T0057 | LLM Data Leakage | 18 | indirect_injection, mcp_tool_abuse, multi_turn, obfuscation, sensitive_data |
| AML.T0053 | AI Agent Tool Invocation | 15 | excessive_agency, indirect_injection, mcp_tool_abuse, multi_turn, tool_poisoning |
| AML.T0068 | LLM Prompt Obfuscation | 14 | obfuscation |
| AML.T0070 | RAG Poisoning | 9 | indirect_injection, output_handling |
| AML.T0066 | Retrieval Content Crafting | 4 | indirect_injection |
| AML.T0077 | LLM Response Rendering | 5 | output_handling |
| AML.T0080 | AI Agent Context Poisoning | 5 | indirect_injection, tool_poisoning |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | 10 | excessive_agency, indirect_injection, mcp_tool_abuse, tool_poisoning |
| AML.T0099 | AI Agent Tool Data Poisoning | 4 | indirect_injection |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | 2 | excessive_agency, indirect_injection |
| AML.T0110 | AI Agent Tool Poisoning | 4 | tool_poisoning |
| AML.T0055 | Unsecured Credentials | 10 | mcp_tool_abuse, sensitive_data |
| AML.T0037 | Data from Local System | 9 | mcp_tool_abuse, sensitive_data |
