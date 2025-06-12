import os
import json
import torch
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding
)
from datasets import Dataset, DatasetDict
from sklearn.model_selection import train_test_split
from transformers.utils import logging

MODEL_NAME = "allenai/scibert_scivocab_uncased"
#MODEL_NAME = "microsoft/deberta-v3-small"
#MODEL_NAME = "distilbert-base-uncased"  # Try also: roberta-base, bert-bas  e-uncased, distilbert-base-uncased
MAX_TOKEN_LENGTH = 256
EPOCHS = 3
BATCH_SIZE = 16
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "data", "filtered_dataset.jsonl")

logging.set_verbosity_error()



def preprocess_record(record):
    description = record.get("description") or "N/A"
    date_published = record.get("date_published", "N/A")
    provider = record.get("provider_short_name") or "N/A"
    tags = ", ".join(record.get("tags") or []) or "N/A"
    affected_items_list = record.get("affected_items") or []
    affected_items_str = "; ".join(
        [f"vendor={item.get('vendor', 'N/A')} product={item.get('product', 'N/A')}" for item in affected_items_list]
    ) or "N/A"

    # Combine into a single input text
    combined_text = (
        f"Description: {description}. "
        f"Date Published: {date_published}. "
        f"Provider: {provider}. "
        f"Tags: {tags}. "
        f"Affected Items: {affected_items_str}."
    )
    return {"text": combined_text, "label": record["label"]}


# 🔧 Load your JSONL file and preprocess into list of dicts
def load_data(file_path):
    data = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            json_line = json.loads(line.strip())
            processed = preprocess_record(json_line)
            data.append(processed)
    return data


def tokenize_function(example, tokenizer):
    return tokenizer(
        example["text"],
        padding="max_length",
        truncation=True,
        max_length=MAX_TOKEN_LENGTH
    )


def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    acc = accuracy_score(labels, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary")
    return {"accuracy": acc, "precision": precision, "recall": recall, "f1": f1}


def main():
    raw_data = load_data(DATA_PATH)

    train_data, test_data = train_test_split(raw_data, test_size=0.2, random_state=42,
                                             stratify=[d['label'] for d in raw_data])
    train_data, val_data = train_test_split(train_data, test_size=0.2, random_state=42,
                                            stratify=[d['label'] for d in train_data])

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    dataset = DatasetDict({
        "train": Dataset.from_list(train_data),
        "validation": Dataset.from_list(val_data),
        "test": Dataset.from_list(test_data)
    }).map(lambda x: tokenize_function(x, tokenizer), batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

    training_args = TrainingArguments(
        output_dir=f"./results/{MODEL_NAME.replace('/', '_')}",
        eval_strategy="epoch",
        save_strategy="no",
        learning_rate=2e-5,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=32,
        num_train_epochs=EPOCHS,
        weight_decay=0.01,
        fp16=torch.cuda.is_available(),
        logging_dir="./logs",
        report_to="none"
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        tokenizer=tokenizer,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        compute_metrics=compute_metrics,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer)
    )

    trainer.train()

    print("\n📊 Evaluation on Test Set:")
    metrics = trainer.evaluate(dataset["test"])
    for key, val in metrics.items():
        print(f"{key}: {val:.4f}")

    save_path = f"./results/{MODEL_NAME.replace('/', '_')}/final"
    print(f"\n💾 Saving model and tokenizer to: {save_path}")
    trainer.save_model(save_path)
    tokenizer.save_pretrained(save_path)


if __name__ == "__main__":
    main()
