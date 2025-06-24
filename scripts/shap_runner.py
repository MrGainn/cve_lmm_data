import json
import re
from pathlib import Path
from typing import Optional

from ollama_shap import classify_iot_cve_with_llm_shap

SCRIPT_DIR = Path(__file__).parent
DATA_PATH = SCRIPT_DIR.parent / "analysis" / "balanced_cve_labels.jsonl"
OUTPUT_BASE = SCRIPT_DIR / "llm_classification_results"


def sanitize_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*\s]+', '_', name)


def save_result(llm_name: str, field_type: str, original_cve: dict, predicted_label: bool, correct: bool):
    model_dir = OUTPUT_BASE / sanitize_filename(llm_name) / field_type
    model_dir.mkdir(parents=True, exist_ok=True)
    file_path = model_dir / ("correctly_classified.jsonl" if correct else "misclassified.jsonl")

    result = dict(original_cve)  # Copy the full CVE object
    result["predicted_label"] = int(predicted_label)

    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")


def is_valid_text(value: Optional[str]) -> bool:
    return bool(value and value.strip().lower() not in ["", "n/a", "missing"])


def is_valid_affected_items(affected_items: Optional[list]) -> bool:
    if not affected_items or not isinstance(affected_items, list):
        return False

    if (
        len(affected_items) == 1 and
        affected_items[0].get("vendor", "").strip().lower() == "n/a" and
        affected_items[0].get("product", "").strip().lower() == "n/a"
    ):
        return False

    return True



def should_include_row(description: str, affected_items: list) -> bool:
    return is_valid_text(description) and is_valid_affected_items(affected_items)


def load_sample_data(limit=20):
    print(f"📥 Loading up to {limit} valid CVE samples from {DATA_PATH}")
    data = []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            obj = json.loads(line)
            description = obj.get("description", "")
            affected_items = obj.get("affected_items", [])
            if should_include_row(description, affected_items):
                data.append(obj)

            if len(data) >= limit:
                break
            if idx % 10 == 0:
                print(f"  → {len(data)} valid entries loaded so far...")

    print(f"✅ Finished loading {len(data)} valid samples.\n")
    return data


def run_shap_style_analysis(model_name: str, limit=20):
    samples = load_sample_data(limit)
    results = []

    correct_counts = {
        "both": 0,
        "description": 0,
        "affected_items": 0
    }

    for i, cve in enumerate(samples, 1):
        print(f"\n🧪 Sample {i}/{len(samples)}")

        desc = cve.get("description", "")
        affected_items = cve.get("affected_items", [])
        true_label = cve.get("label", False)

        input_combos = {
            "description": (desc, None),
            "affected_items": ("", affected_items),
            "both": (desc, affected_items)
        }

        predictions = {}

        for key, (d, a) in input_combos.items():
            print(f"🔍 Evaluating: {key}")
            result = classify_iot_cve_with_llm_shap(description=d or "", affected_items=a, model_name=model_name)
            predicted_label = result.get("is_iot") if result else False
            predictions[key] = 1.0 if predicted_label else 0.0

            correct = (predicted_label == true_label)
            if correct:
                correct_counts[key] += 1

            save_result(model_name, key, cve, predicted_label, correct=correct)

            print(f"    → Prediction ({key}): {predictions[key]}")

        full_pred = predictions["both"]
        contributions = {
            "desc_contrib": full_pred - predictions["description"],
            "affected_contrib": full_pred - predictions["affected_items"]
        }

        results.append({
            "description": desc,
            "affected_items": affected_items,
            "predictions": predictions,
            "contributions": contributions
        })

    total_desc = sum(abs(r["contributions"]["desc_contrib"]) for r in results)
    total_aff = sum(abs(r["contributions"]["affected_contrib"]) for r in results)

    print("\n📊 Overall importance summary (absolute contribution):")
    print(f"🔹 Description total contribution: {total_desc:.2f}")
    print(f"🔹 Affected_items total contribution: {total_aff:.2f}")

    if total_desc > total_aff:
        print("✅ Conclusion: 'description' was more influential overall.")
    elif total_aff > total_desc:
        print("✅ Conclusion: 'affected_items' was more influential overall.")
    else:
        print("📎 Conclusion: Both fields were equally influential.")

    # ✅ Extended Evaluation Summary
    print("\n🧾 Extended Evaluation Summary:")
    print(f"📌 Total CVEs evaluated: {len(samples)}")
    print(f"✅ Correct using 'both':           {correct_counts['both']} / {len(samples)}")
    print(f"✅ Correct using 'description':    {correct_counts['description']} / {len(samples)}")
    print(f"✅ Correct using 'affected_items': {correct_counts['affected_items']} / {len(samples)}")


if __name__ == "__main__":
    run_shap_style_analysis(model_name="mistral", limit=916)
