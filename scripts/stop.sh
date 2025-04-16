#!/bin/bash
echo " Stopping FastAPI and Streamlit..."
# Kill FastAPI (uvicorn)
PIDS=$(ps aux | grep "uvicorn app:app" | grep -v grep | awk '{print $2}')
if [ -n "$PIDS" ]; then
echo "Killing FastAPI (uvicorn) PID(s): $PIDS"
kill $PIDS
else
echo "No FastAPI (uvicorn) process found."
fi
# Kill Streamlit
PIDS=$(ps aux | grep "streamlit run app.py" | grep -v grep | awk '{print $2}')
if [ -n "$PIDS" ]; then
echo "Killing Streamlit PID(s): $PIDS"
kill $PIDS
else
echo " No Streamlit process found."
fi
echo "All processes stopped."