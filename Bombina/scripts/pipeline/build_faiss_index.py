#!/usr/bin/env python3
"""
Bombina RAG Vector Index Builder
Creates FAISS index from RAG knowledge base
Uses sentence-transformers for embeddings
"""

import json
import pickle
from pathlib import Path
from typing import List, Dict
import numpy as np

try:
    from sentence_transformers import SentenceTransformer
    import faiss
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False
    print("⚠️ Missing dependencies. Install with:")
    print("   pip install sentence-transformers faiss-cpu")


class RAGIndexBuilder:
    """Build FAISS vector index for Bombina RAG"""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        if not HAS_DEPS:
            raise ImportError("Required packages not installed")
        
        print(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        self.documents = []
        self.embeddings = None
        self.index = None
    
    def load_documents(self, rag_index_path: str):
        """Load documents from RAG index"""
        print(f"\nLoading documents from {rag_index_path}")
        
        with open(rag_index_path) as f:
            for line in f:
                doc = json.loads(line)
                self.documents.append(doc)
        
        print(f"   Loaded {len(self.documents)} documents")
    
    def create_embeddings(self, batch_size: int = 32):
        """Create embeddings for all documents"""
        print(f"\nCreating embeddings (batch size: {batch_size})...")
        
        # Prepare texts for embedding
        texts = []
        for doc in self.documents:
            # Combine title and content for better retrieval
            text = f"{doc.get('title', '')} {doc.get('content', '')}"
            texts.append(text[:2000])  # Limit length
        
        # Create embeddings in batches
        all_embeddings = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i+batch_size]
            batch_embeddings = self.model.encode(batch, show_progress_bar=False)
            all_embeddings.extend(batch_embeddings)
            print(f"   Processed {min(i+batch_size, len(texts))}/{len(texts)}")
        
        self.embeddings = np.array(all_embeddings).astype('float32')
        print(f"   Embeddings shape: {self.embeddings.shape}")
    
    def build_faiss_index(self):
        """Build FAISS index from embeddings"""
        print("\nBuilding FAISS index...")
        
        dimension = self.embeddings.shape[1]
        
        # Use IndexFlatIP for cosine similarity (after normalization)
        faiss.normalize_L2(self.embeddings)
        self.index = faiss.IndexFlatIP(dimension)
        self.index.add(self.embeddings)
        
        print(f"   Index size: {self.index.ntotal} vectors")
        print(f"   Dimension: {dimension}")
    
    def save_index(self, output_dir: str):
        """Save FAISS index and document metadata"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save FAISS index
        index_file = output_path / "bombina_rag.index"
        faiss.write_index(self.index, str(index_file))
        print(f"\n💾 Saved FAISS index: {index_file}")
        
        # Save document metadata
        docs_file = output_path / "bombina_docs.pkl"
        with open(docs_file, "wb") as f:
            pickle.dump(self.documents, f)
        print(f"💾 Saved documents: {docs_file}")
        
        # Save config
        config = {
            "model_name": "all-MiniLM-L6-v2",
            "dimension": self.embeddings.shape[1],
            "total_documents": len(self.documents),
            "index_type": "IndexFlatIP"
        }
        config_file = output_path / "config.json"
        with open(config_file, "w") as f:
            json.dump(config, f, indent=2)
        print(f"💾 Saved config: {config_file}")
    
    def search(self, query: str, k: int = 5) -> List[Dict]:
        """Search the index for relevant documents"""
        # Encode query
        query_embedding = self.model.encode([query]).astype('float32')
        faiss.normalize_L2(query_embedding)
        
        # Search
        scores, indices = self.index.search(query_embedding, k)
        
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0:  # Valid index
                doc = self.documents[idx].copy()
                doc['score'] = float(score)
                results.append(doc)
        
        return results


class RAGRetriever:
    """Load and query pre-built RAG index"""
    
    def __init__(self, index_dir: str, model_name: str = "all-MiniLM-L6-v2"):
        if not HAS_DEPS:
            raise ImportError("Required packages not installed")
        
        index_path = Path(index_dir)
        
        # Load model
        print(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        
        # Load FAISS index
        index_file = index_path / "bombina_rag.index"
        print(f"Loading FAISS index: {index_file}")
        self.index = faiss.read_index(str(index_file))
        
        # Load documents
        docs_file = index_path / "bombina_docs.pkl"
        print(f"Loading documents: {docs_file}")
        with open(docs_file, "rb") as f:
            self.documents = pickle.load(f)
        
        print(f"✅ RAG ready: {len(self.documents)} documents indexed")
    
    def retrieve(self, query: str, k: int = 5, doc_type: str = None) -> List[Dict]:
        """Retrieve relevant documents for a query"""
        # Encode query
        query_embedding = self.model.encode([query]).astype('float32')
        faiss.normalize_L2(query_embedding)
        
        # Search (get more results if filtering by type)
        search_k = k * 3 if doc_type else k
        scores, indices = self.index.search(query_embedding, search_k)
        
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0 and len(results) < k:
                doc = self.documents[idx].copy()
                
                # Filter by type if specified
                if doc_type and doc.get('type') != doc_type:
                    continue
                
                doc['score'] = float(score)
                results.append(doc)
        
        return results
    
    def get_context(self, query: str, k: int = 3) -> str:
        """Get formatted context for LLM prompt"""
        results = self.retrieve(query, k=k)
        
        context_parts = []
        for i, doc in enumerate(results, 1):
            context_parts.append(f"[{i}] {doc['title']}\n{doc['content'][:500]}...")
        
        return "\n\n---\n\n".join(context_parts)


def build_index():
    """Build FAISS index from RAG knowledge"""
    base_dir = Path("/home/redbend/MyLocalProjects/Bombina/scripts/data/rag_knowledge")
    rag_index = base_dir / "rag_index.jsonl"
    
    if not rag_index.exists():
        print(f"RAG index not found: {rag_index}")
        print("Run build_rag_knowledge.py first")
        return
    
    builder = RAGIndexBuilder()
    builder.load_documents(str(rag_index))
    builder.create_embeddings()
    builder.build_faiss_index()
    builder.save_index(str(base_dir / "faiss_index"))
    
    # Test search
    print("\n" + "="*60)
    print("🔍 Testing RAG Search")
    print("="*60)
    
    test_queries = [
        "How to perform Kerberoasting attack",
        "SQL injection vulnerability",
        "Privilege escalation on Windows"
    ]
    
    for query in test_queries:
        print(f"\nQuery: {query}")
        results = builder.search(query, k=3)
        for r in results:
            print(f"  [{r['score']:.3f}] {r['title']}")


def main():
    if not HAS_DEPS:
        print("\n⚠️ Cannot build index - missing dependencies")
        print("Install with: pip install sentence-transformers faiss-cpu")
        return
    
    build_index()


if __name__ == "__main__":
    main()
