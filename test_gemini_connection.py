"""
test_gemini_connection.py
Quick script to verify that the Gemini API key in .env works and test model response.
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
if not api_key or api_key == "your-gemini-api-key-here":
    print("ERROR: No valid GEMINI_API_KEY found in .env")
    sys.exit(1)

model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
print(f"Testing Gemini API key with model '{model_name}'...")

try:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model_name,
        contents="Respond with 'Gemini API connection verified successfully.'",
        config=types.GenerateContentConfig(
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True)
        ),
    )
    print("SUCCESS! Model output:")
    print(response.text.strip())
except Exception as e:
    print(f"FAILED: {e}")
    sys.exit(2)
