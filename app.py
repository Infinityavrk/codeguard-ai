from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
import pickle
import os
import torch.nn as nn
from transformers import RobertaModel
import numpy as np
from captum.attr import IntegratedGradients
from collections import defaultdict
import re
import gdown
import zipfile
import shutil

class MultiLabelCodeBERT(nn.Module):
    def __init__(self, model_name, num_labels):
        super().__init__()
        self.bert = RobertaModel.from_pretrained(model_name)
        self.dropout = nn.Dropout(0.3)
        self.classifier = nn.Linear(self.bert.config.hidden_size, num_labels)

    def forward(self, input_ids=None, attention_mask=None, input_ids_embeds=None):
        # Support either input_ids or input_ids_embeds (used by Captum)
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            inputs_embeds=input_ids_embeds)
        pooled_output = outputs.pooler_output
        x = self.dropout(pooled_output)
        logits = self.classifier(x)
        return {"logits": logits}

app = FastAPI(title="Code Vulnerability Detection API")

# Request models
class CodeRequest(BaseModel):
    code: str

class FixRequest(BaseModel):
    code: str
    vulnerability_types: list

# Global variables
cls_model = None
gen_model = None
bert_tokenizer = None
t5_tokenizer = None
label_binarizer = None

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BASE_OUTPUT_PATH = "vulmodels/"


def download_from_drive():
    extract_dir = "vulmodels"

    # ✅ Skip download if vulmodels/ folder already exists and is populated
    if os.path.exists(os.path.join(extract_dir, "label_binarizer.pkl")):
        print("✅ Model folder already exists. Skipping download.")
        return

    # Replace with shared Google Drive file ID
    file_id = "<FILE_ID>"
    zip_path = os.path.join(extract_dir, "vulmodels_bundle.zip")
    os.makedirs(extract_dir, exist_ok=True)

    print("⬇️ Downloading model bundle from Google Drive...")
    url = f"https://drive.google.com/uc?id={file_id}"
    gdown.download(url, zip_path, quiet=False)

    print("📦 Extracting ZIP file...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

    os.remove(zip_path)
    print("✅ Extraction complete.")

    # 🔄 Flatten folder structure if nested
    nested_path = os.path.join(extract_dir, "vulmodels")
    if os.path.exists(nested_path):
        print("📁 Flattening nested folder structure...")
        for item in os.listdir(nested_path):
            shutil.move(os.path.join(nested_path, item), os.path.join(extract_dir, item))
        shutil.rmtree(nested_path)
        print("✅ Folder structure fixed.")

# Load models
def load_models(device):
    global cls_model, gen_model, bert_tokenizer, t5_tokenizer, label_binarizer

    with open(BASE_OUTPUT_PATH + "label_binarizer.pkl", "rb") as f:
        label_binarizer = pickle.load(f)

    num_labels = len(label_binarizer.classes_)

    cls_model = MultiLabelCodeBERT("microsoft/codebert-base", num_labels=num_labels)
    cls_model.load_state_dict(torch.load(BASE_OUTPUT_PATH + "codebert-finetuned/pytorch_model.bin", map_location=device))
    cls_model.to(device)
    cls_model.eval()

    bert_tokenizer = AutoTokenizer.from_pretrained(BASE_OUTPUT_PATH + "codebert-tokenizer")
    gen_model = AutoModelForSeq2SeqLM.from_pretrained(BASE_OUTPUT_PATH + "codet5-finetuned").to(device)
    t5_tokenizer = AutoTokenizer.from_pretrained(BASE_OUTPUT_PATH + "codet5-tokenizer")
    gen_model.eval()

    print("✅ Models, tokenizers, and label binarizer loaded successfully.")

# Compute Vulnerable Line Attribution
def get_vulnerable_lines(code_snippet: str, threshold: float = 0.2) -> list:
    model = cls_model
    model.eval()

    # Tokenize and embed
    inputs = bert_tokenizer(code_snippet, return_tensors="pt", padding=True, truncation=True, max_length=512)
    input_ids = inputs["input_ids"].to(device)
    attention_mask = inputs["attention_mask"].to(device)
    embeddings = model.bert.embeddings(input_ids)

    # Captum forward wrapper
    def forward_func(input_embeds):
        outputs = model(
            input_ids=None,
            attention_mask=attention_mask,
            input_ids_embeds=input_embeds
        )
        logits = outputs["logits"]
        probs = torch.sigmoid(logits)
        return probs.sum(dim=1)

    # Run Captum
    ig = IntegratedGradients(forward_func)
    attributions, _ = ig.attribute(inputs=embeddings, return_convergence_delta=True)

    token_importance = attributions.sum(dim=-1).squeeze().detach().cpu().numpy()
    tokens = bert_tokenizer.convert_ids_to_tokens(input_ids[0])
    code_lines = code_snippet.split("\n")
    line_scores = defaultdict(float)

    # Define ignorable tokens (optional)
    ignore_tokens = set(['{', '}', ';', '(', ')', '=', 'if', 'else', '.', ','])

    # Score lines by important tokens
    for token, score in zip(tokens, token_importance):
        clean_token = token.replace("Ġ", "").replace("▁", "").strip()
        if not clean_token or clean_token in ignore_tokens or len(clean_token) < 2:
            continue
        pattern = re.escape(clean_token)
        for i, line in enumerate(code_lines):
            if re.search(rf'\b{pattern}\b', line):
                line_scores[i + 1] += abs(score)
                break

    if not line_scores:
        return []

    max_score = max(line_scores.values())
    important_lines = [
        line_num for line_num, score in line_scores.items()
        if score > threshold * max_score
    ]

    return sorted(important_lines)


def get_token_attributions(code_snippet: str):
    model = cls_model
    model.eval()

    inputs = bert_tokenizer(code_snippet, return_tensors="pt", padding=True, truncation=True, max_length=512)
    input_ids = inputs["input_ids"].to(device)
    attention_mask = inputs["attention_mask"].to(device)
    embeddings = model.bert.embeddings(input_ids)

    def forward_func(input_embeds):
        outputs = model(
            input_ids=None,
            attention_mask=attention_mask,
            input_ids_embeds=input_embeds
        )
        logits = outputs["logits"]
        probs = torch.sigmoid(logits)
        return probs.sum(dim=1)

    ig = IntegratedGradients(forward_func)
    attributions, _ = ig.attribute(inputs=embeddings, return_convergence_delta=True)

    token_importance = attributions.sum(dim=-1).squeeze().detach().cpu().numpy()
    tokens = bert_tokenizer.convert_ids_to_tokens(input_ids[0])
    tokens = [t.replace("Ġ", "").replace("▁", "") for t in tokens]

    # Normalize scores between 0 and 1
    max_score = max(abs(score) for score in token_importance) if token_importance.any() else 1
    norm_scores = [abs(score) / max_score for score in token_importance]

    #return list(zip(tokens, norm_scores))
    return [(token, float(score)) for token, score in zip(tokens, norm_scores)]

# Detection logic
def detect_vulnerability(code_snippet: str) -> list:
    cls_model.eval()
    inputs = bert_tokenizer(code_snippet, return_tensors="pt", padding=True, truncation=True, max_length=512)
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = cls_model(**inputs)

    probs = torch.sigmoid(outputs["logits"]).cpu().numpy()[0]

    print("\n🔍 Vulnerability Probabilities:")
    for cls, prob in zip(label_binarizer.classes_, probs):
        print(f"{cls}: {prob:.2f}")

    preds = (probs > 0.3).astype(int)

    '''
    if preds.sum() == 0:
        top_indices = probs.argsort()[-2:]
        preds[top_indices] = 1
    '''

    # Always return at least 3 labels
    if preds.sum() < 3:
        top_indices = probs.argsort()[-2:]
        preds[top_indices] = 1

    predicted_labels = label_binarizer.inverse_transform(np.array([preds]))[0]
    return list(predicted_labels)

# Fix generation
def generate_fix(code_snippet: str, vuln_labels: list) -> str:
    vuln_label_str = ", ".join(vuln_labels)
    prompt = f"fix vulnerability: {vuln_label_str} | code: {code_snippet.strip()}"
    inputs = t5_tokenizer(prompt, return_tensors="pt", padding=True, truncation=True, max_length=512).to(device)
    with torch.no_grad():
        output = gen_model.generate(
            input_ids=inputs["input_ids"],
            attention_mask=inputs["attention_mask"],
            num_beams=4,
            max_length=256,
            early_stopping=True,
            repetition_penalty=1.5,
            length_penalty=1.0,
            no_repeat_ngram_size=2,
        )
    return t5_tokenizer.decode(output[0], skip_special_tokens=True)

@app.on_event("startup")
def startup_event():
    print("🚀 Initializing model loading...")
    download_from_drive()  # 📦 Ensure models are present
    load_models(device)    # 🧠 Load models to memory
    print("✅ Models loaded and ready.")
# Load models on startup
#load_models(device)


# -------------------- API Routes --------------------

# ✅ Endpoint 1: /detect-type
@app.post("/detect-type")
def detect(code_req: CodeRequest):
    if not code_req.code.strip():
        raise HTTPException(status_code=400, detail="Empty code snippet provided.")
    
    vuln_labels = detect_vulnerability(code_req.code)
    print(vuln_labels)
    #vuln_lines = get_vulnerable_lines(code_req.code,threshold=0.2)
    #print(vuln_lines)
    #token_attributions = get_token_attributions(code_req.code)
    return {
        "vulnerability_types": vuln_labels,
    }

# ✅ Endpoint 2: /detect-lines
@app.post("/detect-lines")
def detect(code_req: CodeRequest):
    if not code_req.code.strip():
        raise HTTPException(status_code=400, detail="Empty code snippet provided.")
    
    vuln_lines = get_vulnerable_lines(code_req.code,threshold=0.2)
    print(vuln_lines)
    #token_attributions = get_token_attributions(code_req.code)
    return {
        "vulnerable_lines": vuln_lines
    }

# ✅ Endpoint 3: /fix
@app.post("/fix")
def fix(fix_req: FixRequest):
    if not fix_req.code.strip():
        raise HTTPException(status_code=400, detail="Empty code snippet provided.")
    
    if not fix_req.vulnerability_types:
        raise HTTPException(status_code=400, detail="No vulnerability types provided.")
    
    fixed_code = generate_fix(fix_req.code, fix_req.vulnerability_types)
    print(fixed_code)
    return {"suggested_fix": fixed_code}
