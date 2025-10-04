from langchain_groq import ChatGroq
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
from langchain_community.document_loaders import TextLoader, PyPDFLoader
from typing import List, Optional
import os


class RAGPipeline:
    def __init__(
        self,
        groq_api_key: str,
        model_name: str = "mixtral-8x7b-32768",
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
        persist_directory: str = "./chroma_db",
        chunk_size: int = 1000,
        chunk_overlap: int = 200
    ):
        self.groq_api_key = groq_api_key
        self.model_name = model_name
        self.persist_directory = persist_directory
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        
        self.llm = ChatGroq(
            groq_api_key=self.groq_api_key,
            model_name=self.model_name,
            temperature=0.7
        )
        
        self.embeddings = HuggingFaceEmbeddings(
            model_name=embedding_model
        )
        
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap
        )
        
        self.vectorstore = None
        self.qa_chain = None
        
    def load_documents(self, file_paths: List[str]) -> List:
        documents = []
        for file_path in file_paths:
            if file_path.endswith('.pdf'):
                loader = PyPDFLoader(file_path)
            elif file_path.endswith('.txt'):
                loader = TextLoader(file_path)
            else:
                raise ValueError(f"Unsupported file type: {file_path}")
            documents.extend(loader.load())
        return documents
    
    def create_vectorstore(self, documents: List):
        splits = self.text_splitter.split_documents(documents)
        
        self.vectorstore = Chroma.from_documents(
            documents=splits,
            embedding=self.embeddings,
            persist_directory=self.persist_directory
        )
        
    def load_vectorstore(self):
        self.vectorstore = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=self.embeddings
        )
        
    def create_qa_chain(self, custom_prompt: Optional[str] = None):
        if self.vectorstore is None:
            raise ValueError("Vectorstore not initialized. Load or create vectorstore first.")
        
        if custom_prompt:
            prompt_template = PromptTemplate(
                template=custom_prompt,
                input_variables=["context", "question"]
            )
            self.qa_chain = RetrievalQA.from_chain_type(
                llm=self.llm,
                chain_type="stuff",
                retriever=self.vectorstore.as_retriever(search_kwargs={"k": 3}),
                chain_type_kwargs={"prompt": prompt_template}
            )
        else:
            self.qa_chain = RetrievalQA.from_chain_type(
                llm=self.llm,
                chain_type="stuff",
                retriever=self.vectorstore.as_retriever(search_kwargs={"k": 3}),
                return_source_documents=True
            )
    
    def query(self, question: str) -> dict:
        if self.qa_chain is None:
            raise ValueError("QA chain not initialized. Create QA chain first.")
        
        response = self.qa_chain.invoke({"query": question})
        return response
    
    def add_documents(self, file_paths: List[str]):
        if self.vectorstore is None:
            raise ValueError("Vectorstore not initialized.")
        
        documents = self.load_documents(file_paths)
        splits = self.text_splitter.split_documents(documents)
        self.vectorstore.add_documents(splits)
    
    def similarity_search(self, query: str, k: int = 3) -> List:
        if self.vectorstore is None:
            raise ValueError("Vectorstore not initialized.")
        
        return self.vectorstore.similarity_search(query, k=k)