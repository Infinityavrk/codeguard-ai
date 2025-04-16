#!/bin/bash
ENV_NAME="vuln-detect-env"
echo "Checking if Conda environment '$ENV_NAME' exists..."
if ! conda info --envs | grep -q "$ENV_NAME"; then
echo "Environment not found. Creating from environment.yml..."
conda env create -f environment.yml
else
echo "Environment found."
fi
echo "Activating environment: $ENV_NAME"
eval "$(conda shell.bash hook)"
conda activate $ENV_NAME
echo "Starting FastAPI backend on http://localhost:8000 ..."
uvicorn app:app --reload --port 8000 &
sleep 3
echo “ Starting Streamlit UI on http://localhost:8501 ..."
cd UI
streamlit run app.py --server.port 8501