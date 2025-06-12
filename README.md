# CVE Classification Review Process

This repository contains data files and results related to the classification of CVEs (Common Vulnerabilities and Exposures) using multiple AI models and human review.

## Folder Structure and Files

- **`review/ai_results/`**  
  Contains JSONL files listing CVEs that were **misclassified by different AI models** and correctly classified. These files help identify which CVEs each AI model predicted incorrectly and thus we can manually review.

- **`review/human_classification/to_be_manually_reviewed.jsonl`**  
  This file includes around **125 CVEs** that were flagged for **manual human review**. These CVEs were predicted wrongly by at least **2 out of 3 AI models**, making them prime candidates for careful human classification.

- **`review/human_classification/final_misclassified.jsonl`**  
  Contains the **final 86 CVEs** that were **truly mislabelled** after the detailed human review process. This represents the cleaned, verified subset of misclassified CVEs. 

  --Note the labels in final_misclassified and to_be_manually_reviewed were the labels BEFORE correctign them (so the same as the origional one), and thus the llm's predicted the oppisite of these labels

---


- **`data/original_dataset.jsonl`**  
  This is the **original dataset** prior to any filtering or corrections. It contains **3,458 CVE entries**, including both IoT-related and non-IoT-related vulnerabilities, before any AI classification or manual review.

  
- **`data/random_sampled_dataset.jsonl`**  
  The 1000 andomlt sampled cve's from the original_dataset.jsonl were 50% is iot and 50% is non iot.

- **`data/dataset_review_correction.jsonl`**  
  This file contains the **final version of the dataset** after AI-based classification and manual review. All mislabeled entries were removed or corrected, resulting in **916 CVEs**  evenly split between IoT and non-IoT (50/50), supporting fair and unbiased evaluation of classification models.

---
- **`scripts/get_random_samples.py`**  
  The way we randomly sampeld the 1000 cve's with a 50/50 split of iot and non iot

- **`scripts/run_ollama.py`**  
  The actual prompt we gave to the llm's and the code for formatiign the resposne

- **`scripts/evaluate_iot_classifier.py`**  
Calls the run_ollama.py funtion and loads the data fromt the dataset file and saves the llm repsonse in a new jsonl file.

 - **`scripts/train_fineTuned_classifier.py`**  
The script to train the traditional/finetuned classifiers. Just comment out the model you want to use and provide the dataset.
 
---

 - **`results/*`**  
The results of all the LLM's and traditional classifiers that classified the **916 CVEs** . It's split up in correctly classified and misclassified and for the LLM's you can also see the most important field (description, affected items, product date, tags) in their decision 

## Summary

- AI models were used to identify potentially misclassified CVEs.
- CVEs flagged by multiple models were manually reviewed for accuracy.
- The result is a final, verified dataset of truly mislabelled CVEs for reliable analysis and training.


---

If you have any questions or want to contribute to improving this classification pipeline, feel free to reach out!
