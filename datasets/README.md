# Datasets

Benign task sets, labeled judge sets and classifier training data. Every external dataset is
listed here with its source, license and how it is used before any of it is added. Large or
restrictively licensed data is downloaded by script rather than committed.

| Dataset | Source | License | Used for |
|---|---|---|---|
| deepset/prompt-injections | huggingface.co, rev `4f61ecb` | Apache-2.0 | classifier train/val/test (both labels) |
| SPML_Chatbot_Prompt_Injection | huggingface.co/reshabhs, rev `02ce808` | MIT | classifier train/val/test; rows sourced from Gandalf dropped |
| OASST1 (prompts file) | huggingface.co/OpenAssistant, rev `fdf72ae` | Apache-2.0 | benign English first-turn prompts |
| gandalf_ignore_instructions | huggingface.co/Lakera, rev `04737b6` | MIT | held-out source (test only) |
| NotInject | huggingface.co/leolee99, rev `847ae76` | MIT | over-defense test only |

Pinned in `classifier/sources.yaml`, downloaded by script into `datasets/external/`
(git-ignored), never committed. Licenses read on each dataset's Hugging Face page on
2026-11-24. Considered and not used: xTRam1/safe-guard-prompt-injection (no license stated),
hackaprompt (gated), jackhhao/jailbreak-classification (source licenses not stated),
databricks-dolly-15k (CC-BY-SA; not needed). Split counts and hashes:
`classifier/data-manifest.json`.
