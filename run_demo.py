import os
import webbrowser
import uvicorn

if __name__ == "__main__":
    print("==================================================")
    print("  LAUNCHING SECURE BRIDGE UI DEMO (PORT 8000)     ")
    print("==================================================")
    webbrowser.open("http://127.0.0.1:8000")
    
    uvicorn.run("gateway:app", host="127.0.0.1", port=8000, reload=True)