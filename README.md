# CVE Classification Review Process

This repository contains data files and results related to the classification of CVEs (Common Vulnerabilities and Exposures) using multiple AI models and human review.

## Folder Structure and Files

- **`review/ai/`**  
  Contains JSONL files listing CVEs that were **misclassified by different AI models**. These files help identify which CVEs each AI model predicted incorrectly.

- **`review/human_classification/to_be_manually_reviewed.jsonl`**  
  This file includes around **400 CVEs** that were flagged for **manual human review**. These CVEs were predicted wrongly by at least **2 out of 3 AI models**, making them prime candidates for careful human classification.

- **`manual_review.jsonl`**  
  Contains the **final 75 CVEs** that were **truly mislabelled** after the detailed human review process. This represents the cleaned, verified subset of misclassified CVEs.

---

## Summary

- The AI classification step generates a preliminary list of potentially misclassified CVEs.
- A subset of these, where multiple AI models agree on misclassification, is passed for human manual review.
- The manual review results in a final, trusted dataset of truly mislabelled CVEs for further use in model training or analysis.

---

If you have any questions or want to contribute to improving this classification pipeline, feel free to reach out!
