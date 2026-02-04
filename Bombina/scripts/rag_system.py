#!/usr/bin/env python3
"""
Bombina RAG System - Cybersecurity Knowledge Base
Uses LlamaIndex + ChromaDB + Ollama for local RAG
"""

import os
from pathlib import Path
from llama_index.core import (
    VectorStoreIndex,
    SimpleDirectoryReader,
    Settings,
    StorageContext,
)
from llama_index.llms.ollama import Ollama
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.core.node_parser import SentenceSplitter
import chromadb
from llama_index.vector_stores.chroma import ChromaVectorStore

# Paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data" / "rag"
CHROMA_DIR = BASE_DIR / "data" / "chroma_db"

def setup_bombina_rag():
    """Initialize the Bombina RAG system with ChromaDB"""
    
    # Configure LLM (Bombina model via Ollama)
    llm = Ollama(
        model="bombina",
        base_url="http://localhost:11434",
        request_timeout=120.0,
        temperature=0.7,
    )
    
    # Configure embedding model (runs locally)
    embed_model = HuggingFaceEmbedding(
        model_name="BAAI/bge-small-en-v1.5",
        cache_folder=str(BASE_DIR / "models" / "embeddings"),
    )
    
    # Set global settings
    Settings.llm = llm
    Settings.embed_model = embed_model
    Settings.node_parser = SentenceSplitter(chunk_size=512, chunk_overlap=50)
    
    # Initialize ChromaDB
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    chroma_client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    
    # Get or create collection
    chroma_collection = chroma_client.get_or_create_collection(
        name="bombina_security_kb",
        metadata={"description": "Cybersecurity knowledge base for Bombina"}
    )
    
    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)
    
    return storage_context, chroma_collection

def ingest_documents(storage_context):
    """Ingest documents from the RAG data directory"""
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check if there are documents to ingest
    docs_exist = any(DATA_DIR.iterdir()) if DATA_DIR.exists() else False
    
    if not docs_exist:
        print(f"No documents found in {DATA_DIR}")
        print("Add security docs (txt, pdf, md) to this folder and run again.")
        return None
    
    print(f"Loading documents from {DATA_DIR}...")
    documents = SimpleDirectoryReader(
        input_dir=str(DATA_DIR),
        recursive=True,
        filename_as_id=True,
    ).load_data()
    
    print(f"Loaded {len(documents)} documents. Creating index...")
    
    index = VectorStoreIndex.from_documents(
        documents,
        storage_context=storage_context,
        show_progress=True,
    )
    
    print("Index created and persisted to ChromaDB!")
    return index

def load_existing_index(storage_context):
    """Load existing index from ChromaDB"""
    return VectorStoreIndex.from_vector_store(
        storage_context.vector_store,
    )

def query_bombina(query: str, index: VectorStoreIndex):
    """Query Bombina with RAG-enhanced context"""
    
    query_engine = index.as_query_engine(
        similarity_top_k=5,
        response_mode="tree_summarize",
    )
    
    response = query_engine.query(query)
    return response

def interactive_chat():
    """Start interactive chat with Bombina RAG"""
    
    print("🐸 Initializing Bombina RAG System...")
    storage_context, collection = setup_bombina_rag()
    
    # Check if we have existing data
    if collection.count() > 0:
        print(f"Found {collection.count()} existing embeddings. Loading index...")
        index = load_existing_index(storage_context)
    else:
        print("No existing index found. Attempting to ingest documents...")
        index = ingest_documents(storage_context)
        if index is None:
            print("\nRunning in direct mode (no RAG context)")
            # Fall back to direct Ollama queries
            from ollama import chat
            while True:
                try:
                    user_input = input("\n🐸 Bombina> ").strip()
                    if user_input.lower() in ['exit', 'quit', 'q']:
                        break
                    response = chat(model='bombina', messages=[
                        {'role': 'user', 'content': user_input}
                    ])
                    print(f"\n{response['message']['content']}")
                except KeyboardInterrupt:
                    break
            return
    
    print("\n🐸 Bombina RAG Ready! Type 'exit' to quit.\n")
    
    while True:
        try:
            user_input = input("🐸 Bombina> ").strip()
            if user_input.lower() in ['exit', 'quit', 'q']:
                print("Goodbye!")
                break
            if not user_input:
                continue
                
            response = query_bombina(user_input, index)
            print(f"\n{response}\n")
            
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break

if __name__ == "__main__":
    interactive_chat()
