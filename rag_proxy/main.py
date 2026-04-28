import os # Standard library for environment variables
import torch # The primary library for running deep learning models
from fastapi import FastAPI # Web framework for our RAG proxy
from pydantic import BaseModel # Data validation for incoming requests
from typing import List # Type hinting for better code structure
import chromadb # Client for our vector database
from langchain_huggingface import HuggingFaceEmbeddings, HuggingFacePipeline # LangChain tools for local HF models
import transformers
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline # Tools to load and run the model locally
from langchain_core.prompts import PromptTemplate # Helps structure our "You are a SSH" instructions

print(f"DEBUG: Transformers version: {transformers.__version__}")

# Initialize the FastAPI web server
app = FastAPI()

# --- STEP C: Setup Embedding Model (Local) ---
# Small model to convert text to vectors; runs locally in the container
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# --- STEP D: Setup Vector Database Connection ---
# Connecting to the ChromaDB service in the Docker network
chroma_client = chromadb.HttpClient(host=os.getenv("CHROMA_HOST", "chromadb"), port=8000)
# Collection to store our "fake" Linux system knowledge
collection = chroma_client.get_or_create_collection(name="ssh_knowledge")

# --- STEP G: Setup LOCAL LLM (Offline) ---
# We use Phi-3-mini because it is small (approx 2.3GB) and smart
model_id = "microsoft/Phi-3-mini-4k-instruct"

# Load the tokenizer (turns text into IDs the model understands)
tokenizer = AutoTokenizer.from_pretrained(model_id)

# Load the actual model with 4-bit quantization to save RAM
model = AutoModelForCausalLM.from_pretrained(
    model_id, 
    device_map="auto", # Automatically detects if a GPU is available, otherwise uses CPU
    torch_dtype="auto", # Sets the numeric precision automatically
    trust_remote_code=False, # Use the stable, native transformers implementation and works ofr models like pHi-3
    attn_implementation="eager" # Suggested by the model to avoid flash-attention warnings
)

# Create the local text generation pipeline
local_pipe = pipeline(
    "text-generation",
    model=model,
    tokenizer=tokenizer,
    max_new_tokens=150, # Limits the length of the shell output for faster responses
    temperature=0.1, # Makes the AI more literal and less creative
    top_p=0.9, # Sampling setting for better output diversity
    repetition_penalty=1.1 # Prevents the AI from repeating the same text
)

# Wrap the pipeline in LangChain's HuggingFacePipeline class
llm = HuggingFacePipeline(pipeline=local_pipe)

# --- Define Data Structure for Cowrie ---
class ChatMessage(BaseModel):
    role: str # 'user' or 'assistant'
    content: str # The command text

class ChatRequest(BaseModel):
    model: str # The model name (can be any string)
    messages: List[ChatMessage] # The chat history

# --- STEP F: The "System Prompt" + Context ---
ssh_prompt_template = """
You are a vulnerable Linux SSH server running Ubuntu 22.04. 
Respond to the attacker's command exactly as a real bash shell would.
Use the context below for realistic file contents or system states.
Output ONLY the shell response. No explanations or conversational filler.

CONTEXT FROM SYSTEM KNOWLEDGE:
{context}

ATTACKER COMMAND:
{command}

SHELL OUTPUT:
"""

# Turn the template string into a LangChain Prompt object
prompt_obj = PromptTemplate(template=ssh_prompt_template, input_types={"context": str, "command": str})

# --- STEP E, F, G, H: Main Route ---
@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    # Get the latest command typed by the attacker
    user_command = request.messages[-1].content
    
    # --- STEP D & E: Similarity Search ---
    # Query ChromaDB for the 3 most relevant bits of knowledge
    results = collection.query(
        query_texts=[user_command],
        n_results=3
    )
    
    # Combine retrieved documents into a context block
    retrieved_context = "\n".join([doc for sublist in results['documents'] for doc in sublist])
    
    # --- STEP F & G: Generating the Answer ---
    # Format the prompt and run it through the local model pipeline
    final_prompt = prompt_obj.format(context=retrieved_context, command=user_command)
    ai_response = llm.invoke(final_prompt)
    
    # --- STEP H: Sending back to Cowrie ---
    # Wrap result in JSON format Cowrie expects (mimics OpenAI response)
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": ai_response.strip() # Remove whitespace from AI output
                }
            }
        ]
    }

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy"}
