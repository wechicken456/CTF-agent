import gradio as gr
from typing import Dict, List
from openai import OpenAI
from dotenv import load_dotenv 
import os
load_dotenv()

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai_client = OpenAI(api_key=OPENAI_API_KEY)

def clean_history_openai(history : List[Dict]) -> List[Dict]:
    cleaned = [{"role": msg["role"], "content": msg["content"]} for msg in history]
    return cleaned 

def query_openai(message: Dict, history : list[Dict]):
    """
    Not supporting file uploads at the moment
    """
    messages = clean_history_openai(history) + [{"role": "user", "content": message["text"]}]
    stream = openai_client.responses.create(
        model="gpt-4o-mini", 
        input = messages,
        store = False,
        stream = True
    )
    
    partial = "" 
    for event in stream:
        if event.type == "response.output_text.delta":
            partial += event.delta
            yield partial 
        elif event.type == "response.completed":
            break

def query_llm(message : Dict, history : list[Dict]) :
    """
    Send user message & chat history to LLM and return its response as a string
    Args: 
        message: {
                    "text": "user input", 
                    "files": [
                        "updated_file_1_path.ext",
                        "updated_file_2_path.ext", 
                        ...
                    ]
                }
        history: [
                    {"role" : "user", "content": ...},
                    {"role" : "assistant", "content": ...}
                ]
    Returns: llm response as a string
    """
    print("messsage: ", message)
    print("history: ", history)
    print()
    yield from query_openai(message,history)

gr.ChatInterface(fn = query_llm, 
                 type="messages",
                 title="Random Title",
                 description="Random Description",
                 multimodal=True).launch()
