import json
import time
from pathlib import Path
from collections import defaultdict
import re
from llm_analysis.ollama_test import classify_iot_cve_with_llm_locally


# Get the absolute path of the directory containing the current script
SCRIPT_DIR = Path(__file__).parent

# Construct the path to the ground truth file relative to the script's directory
# Assuming random_sampled_dataset2.jsonl is in 'pythonProject/analysis/'
# and the script is in 'pythonProject/llm_analysis/'
GROUND_TRUTH_FILE = SCRIPT_DIR.parent / "analysis" / "random_sampled_dataset2.jsonl"
OUTPUT_BASE_DIR = SCRIPT_DIR.parent / "analysis" / "model_evaluations"


EVALUATION_SAMPLE_LIMIT = 1100


def load_ground_truth(file_path: Path):
    with open(file_path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def save_results(data_list: list, file_path: Path):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        for item in data_list:
            f.write(json.dumps(item) + "\n")


def sanitize_filename(filename: str) -> str:
    sanitized = filename.replace(" ", "-")
    sanitized = re.sub(r'[^\w-]', '', sanitized)
    return sanitized


def evaluate_model(model_name: str):
    data = load_ground_truth(GROUND_TRUTH_FILE)

    if len(data) > EVALUATION_SAMPLE_LIMIT:
        print(f"Limiting evaluation to {EVALUATION_SAMPLE_LIMIT} samples for testing.")
        data = data[:EVALUATION_SAMPLE_LIMIT]

    total = len(data)

    total_correct = 0
    total_misclassified = 0
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0

    most_significant_field_counts = defaultdict(int)
    field_presence_counts = defaultdict(int)

    start_time = time.time()

    sanitized_model_name = sanitize_filename(model_name)
    print(f"Sanitized model name for directory: '{sanitized_model_name}'")

    model_output_dir = OUTPUT_BASE_DIR / sanitized_model_name
    model_output_dir.mkdir(parents=True, exist_ok=True)

    correctly_classified_file = model_output_dir / "correctly_classified.jsonl"
    misclassified_file = model_output_dir / "misclassified.jsonl"


    with open(correctly_classified_file, 'a', encoding='utf-8') as correct_f, \
         open(misclassified_file, 'a', encoding='utf-8') as misclassified_f:

        for idx, cve in enumerate(data, 1):
            print(f"\n▶ Evaluating {cve['cve_id']} ({idx}/{total})")

            cve_id = cve["cve_id"]
            description = cve["description"]
            date_published = cve.get("date_published")
            affected_items = cve.get("affected_items")
            provider_short_name = cve.get("provider_short_name")
            tags = cve.get("tags")
            true_label = cve["label"]

            # --- Field Presence Logic ---
            if description and description.strip().lower() not in ["n/a", "missing", ""]:
                field_presence_counts["description"] += 1
            if date_published and date_published.strip().lower() not in ["n/a", "missing", ""]:
                field_presence_counts["date_published"] += 1
            if provider_short_name and provider_short_name.strip().lower() not in ["n/a", "missing", ""]:
                field_presence_counts["provider_short_name"] += 1


            if affected_items:
                is_affected_items_valid = False
                for item in affected_items:
                    vendor = item.get("vendor", "").strip().lower()
                    product = item.get("product", "").strip().lower()
                    if (vendor and vendor not in ["n/a", "missing", ""]) or \
                       (product and product not in ["n/a", "missing", ""]):
                        is_affected_items_valid = True
                        break
                if is_affected_items_valid:
                    field_presence_counts["affected_items"] += 1


            if tags:
                is_tags_valid = False
                for tag in tags:
                    if tag and tag.strip().lower() not in ["n/a", "missing", ""]:
                        is_tags_valid = True
                        break
                if is_tags_valid:
                    field_presence_counts["tags"] += 1

            predicted_label = 0
            significant_field = "NOT_VALID"

            try:
                prediction_dict = classify_iot_cve_with_llm_locally(
                    cve_id=cve_id,
                    description=description,
                    date_published=date_published,
                    model_name=model_name,
                    affected_items=affected_items,
                    provider_short_name=provider_short_name,
                    tags=tags
                )

                if prediction_dict is not None:
                    predicted_label = 1 if prediction_dict.get("is_iot", False) else 0
                    significant_field = prediction_dict.get("most_significant_field", "unknown")
                else:
                    # LLM returned None (invalid/unparseable output), so predicted_label remains 0
                    print(f"Skipping metrics for {cve_id} due to invalid/unparseable LLM response, treating as NOT IoT (0).")

            except Exception as e:

                significant_field = "PROCESSING_ERROR"
                print(f"⚠️ An unexpected error occurred during LLM call for {cve_id}: {e}, treating as NOT IoT (0).")


            if predicted_label == true_label:
                total_correct += 1
                summary_entry = {
                    "cve_id": cve_id,
                    "true_label": true_label,
                    "predicted_label": predicted_label
                }
                correct_f.write(json.dumps(summary_entry) + "\n") # Write immediately
                print(f"✅ Correct: predicted {predicted_label}, actual {true_label}. Sig. Field: {significant_field}")
            else:
                total_misclassified += 1
                summary_entry = {
                    "cve_id": cve_id,
                    "true_label": true_label,
                    "predicted_label": predicted_label, # Use the determined predicted_label
                    "most_significant_field_llm": significant_field
                }
                misclassified_f.write(json.dumps(summary_entry) + "\n") # Write immediately
                print(f"❌ Wrong: predicted {predicted_label}, actual {true_label}. Sig. Field: {significant_field}")

            # Update Confusion Matrix components (TP, FP, FN, TN)
            # This is done AFTER determining predicted_label for all cases
            if predicted_label == 1 and true_label == 1:
                true_positives += 1
            elif predicted_label == 1 and true_label == 0:
                false_positives += 1
            elif predicted_label == 0 and true_label == 1:
                false_negatives += 1
            elif predicted_label == 0 and true_label == 0:
                true_negatives += 1

            # Count the significant field from the LLM's response or our assigned error
            most_significant_field_counts[significant_field] += 1

            current_total_processed = total_correct + total_misclassified
            accuracy = total_correct / current_total_processed if current_total_processed else 0

            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) else 0

            elapsed = time.time() - start_time
            print(f"📊 Accuracy: {accuracy:.2%}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1_score:.4f}")
            print(f"⏱️ Time elapsed: {elapsed:.2f} seconds")

            print("\n🔄 Current Field Presence Counts:")
            for field, count in sorted(field_presence_counts.items()):
                print(f"  - {field}: {count} (out of {idx} processed)")

            if idx % 100 == 0:
                print(f"🔍 Most Significant Field Counts (Total processed: {idx}):")
                for field, count in sorted(most_significant_field_counts.items()):
                    print(f"  {field}: {count}")


    final_total_processed = total_correct + total_misclassified
    final_accuracy = total_correct / final_total_processed if final_total_processed else 0
    final_precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0
    final_recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0
    final_f1_score = 2 * (final_precision * final_recall) / (final_precision + final_recall) if (final_precision + final_recall) else 0
    final_elapsed_time = time.time() - start_time

    print("\n" + "="*30 + " Final Evaluation Summary " + "="*30)
    print(f"Model: {model_name} (Saved to folder: {sanitized_model_name})")
    print(f"Total CVEs Evaluated: {total}")
    print(f"Correctly Classified: {total_correct}")
    print(f"Misclassified (including LLM errors): {total_misclassified}")
    print(f"Accuracy: {final_accuracy:.2%}")
    print(f"Precision: {final_precision:.4f}")
    print(f"Recall: {final_recall:.4f}")
    print(f"F1 Score: {final_f1_score:.4f}")
    print(f"Total Time Elapsed: {final_elapsed_time:.2f} seconds")

    print("\nConfusion Matrix Counts:")
    print(f"  True Positives (TP): {true_positives}")
    print(f"  False Positives (FP): {false_positives}")
    print(f"  False Negatives (FN): {false_negatives}")
    print(f"  True Negatives (TN): {true_negatives}")

    print("\nMost Significant Field Counts (as determined by LLM):")
    for field, count in sorted(most_significant_field_counts.items()):
        print(f"  - {field}: {count}")

    print("\nField Presence Counts (fields with valid data in ground truth):")
    for field, count in sorted(field_presence_counts.items()):
        print(f"  - {field}: {count} (out of {total} total samples)")
    print("="*84 + "\n")


if __name__ == "__main__":
    ollama_model_id = "llama3.1" # You can change this back to "mistral" or any other model name
    evaluate_model(ollama_model_id)