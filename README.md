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


- **`data/original_dataset.jsonl`**  
  This is the **original dataset** prior to any filtering or corrections. It contains **3,458 CVE entries**, including both IoT-related and non-IoT-related vulnerabilities, before any AI classification or manual review.

- **`data/final_balanced_dataset.jsonl`**  
  This file contains the **final version of the dataset** after AI-based classification and manual review. All mislabeled entries were removed or corrected, resulting in **3,440 CVEs** evenly split between IoT and non-IoT (50/50), supporting fair and unbiased evaluation of classification models.




## Summary

- AI models were used to identify potentially misclassified CVEs.
- CVEs flagged by multiple models were manually reviewed for accuracy.
- The result is a final, verified dataset of truly mislabelled CVEs for reliable analysis and training.


---

If you have any questions or want to contribute to improving this classification pipeline, feel free to reach out!
