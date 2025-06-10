import json
import random

def create_balanced_cve_dataset(input_file="origional_dataset.jsonl", output_file="balanced_cve_dataset.jsonl", num_iot=500, num_non_iot=500):
    """
    Selects a specified number of random IoT-related (label=1) and
    non-IoT-related (label=0) CVEs from an input JSONL file,
    randomizes them, and writes them to a new JSONL file.

    Args:
        input_file (str): Path to the original dataset JSONL file.
        output_file (str): Path to the new balanced dataset JSONL file.
        num_iot (int): Desired number of IoT-related CVEs (label=1).
        num_non_iot (int): Desired number of non-IoT-related CVEs (label=0).
    """
    iot_cves = []
    non_iot_cves = []

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    cve_entry = json.loads(line)
                    if cve_entry.get("label") == 1:
                        iot_cves.append(cve_entry)
                    elif cve_entry.get("label") == 0:
                        non_iot_cves.append(cve_entry)
                except json.JSONDecodeError:
                    print(f"Skipping malformed JSON line: {line.strip()}")
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return
    except Exception as e:
        print(f"An error occurred while reading the input file: {e}")
        return

    print(f"Found {len(iot_cves)} IoT-related CVEs (label=1).")
    print(f"Found {len(non_iot_cves)} non-IoT-related CVEs (label=0).")

    # Randomly select the desired number of CVEs
    selected_iot = random.sample(iot_cves, min(num_iot, len(iot_cves)))
    selected_non_iot = random.sample(non_iot_cves, min(num_non_iot, len(non_iot_cves)))

    print(f"Selected {len(selected_iot)} IoT-related CVEs.")
    print(f"Selected {len(selected_non_iot)} non-IoT-related CVEs.")

    combined_cves = selected_iot + selected_non_iot
    random.shuffle(combined_cves)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for cve in combined_cves:
                f.write(json.dumps(cve) + '\n')
        print(f"Successfully created '{output_file}' with {len(combined_cves)} entries.")
    except Exception as e:
        print(f"An error occurred while writing to the output file: {e}")

if __name__ == "__main__":
    create_balanced_cve_dataset()