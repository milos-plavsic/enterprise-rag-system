"""Enterprise RAG pipeline with RBAC enforcement"""
import json
import sqlite3
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer, util
from rank_bm25 import BM25Okapi
import numpy as np

from config import (
    DATA_DIR, DB_PATH, RBAC_PATH, USERS_PATH, LOGS_PATH,
    EMBEDDING_MODEL, TOP_K_RESULTS, VECTOR_WEIGHT, BM25_WEIGHT,
    MIN_RELEVANCE_SCORE, CONFIDENCE_HIGH_THRESHOLD, CONFIDENCE_MED_THRESHOLD,
    SENSITIVE_KEYWORDS, SENSITIVE_MIN_ROLE, logger
)


class EnterpriseRAG:
    def __init__(self):
        self.encoder = SentenceTransformer(EMBEDDING_MODEL)
        self.embeddings = None
        self.bm25 = None
        self.documents = []
        self.doc_texts = []
        self.load_data()

    def load_data(self):
        """Load all enterprise data with error handling"""
        try:
            with open(RBAC_PATH, "r") as f:
                self.rbac = json.load(f)
            logger.info("Loaded RBAC policies")
        except Exception as e:
            logger.error(f"Failed to load RBAC: {e}")
            raise

        # Load and index PDFs
        self._load_documents()

        # Build search indexes
        if self.doc_texts:
            self._build_indexes()
            logger.info(f"Built search indexes for {len(self.documents)} documents")

    def _load_documents(self):
        """Load PDFs and build document index"""
        pdf_content = {
            "financial_report.pdf": (
                "Q2 2024 Revenue: $5.2M. EMEA region contributed $2.1M. "
                "Gold customers: $1.8M. Platinum: $2.1M.",
                ["analyst", "manager"]
            ),
            "security_policy.pdf": (
                "Access to financial data requires manager role. "
                "Logs are restricted to auditors only. Audit trail maintained 90 days.",
                ["auditor", "manager"]
            ),
            "employee_handbook.pdf": (
                "Employees get 20 PTO days. HR queries go to peopleops@company.com. "
                "Benefits include health insurance and 401k with 4% match.",
                ["manager"]
            )
        }

        for filename, (content, allowed_roles) in pdf_content.items():
            self.documents.append({
                "id": filename,
                "content": content,
                "source_type": "pdf",
                "allowed_roles": allowed_roles
            })
            self.doc_texts.append(content)

    def _build_indexes(self):
        """Build vector and BM25 indexes"""
        try:
            self.embeddings = self.encoder.encode(self.doc_texts, convert_to_tensor=True)
            tokenized = [text.split() for text in self.doc_texts]
            self.bm25 = BM25Okapi(tokenized)
            logger.info("Search indexes built successfully")
        except Exception as e:
            logger.error(f"Failed to build indexes: {e}")
            raise

    def _get_db_connection(self):
        """Get database connection with error handling"""
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def sql_query(self, query: str, user_role: str) -> List[Dict]:
        """Convert natural language to SQL with RBAC"""
        allowed_sources = self.rbac["roles"].get(user_role, {}).get("allowed_sources", [])

        if not allowed_sources:
            logger.warning(f"No allowed sources for role: {user_role}")
            return []

        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()

            if ("revenue" in query.lower() or "sales" in query.lower()) and "sales_transactions" in allowed_sources:
                cursor.execute("SELECT region, amount, customer_tier FROM sales_transactions")
                results = [dict(row) for row in cursor.fetchall()]
                logger.info(f"SQL query returned {len(results)} rows")
                return results

            elif "employee" in query.lower() and "employees" in allowed_sources:
                cursor.execute("SELECT name, department FROM employees")
                results = [dict(row) for row in cursor.fetchall()]
                logger.info(f"SQL query returned {len(results)} rows")
                return results

            return []
        except Exception as e:
            logger.error(f"SQL query failed: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def search_pdfs(self, query: str, user_role: str, top_k: int = TOP_K_RESULTS) -> List[Dict]:
        """Hybrid search (vector + BM25) with RBAC filtering"""
        allowed_docs = [d for d in self.documents if user_role in d["allowed_roles"]]

        if not allowed_docs or not self.embeddings is not None:
            return []

        try:
            query_embedding = self.encoder.encode(query, convert_to_tensor=True)
            results = []

            for doc_idx, doc in enumerate(allowed_docs):
                if doc_idx >= len(self.embeddings):
                    continue

                # Vector similarity
                vector_score = float(util.cos_sim(query_embedding, self.embeddings[doc_idx])[0][0])

                # BM25 score
                doc_text_idx = self.doc_texts.index(doc["content"]) if doc["content"] in self.doc_texts else -1
                bm25_score = 0.0
                if doc_text_idx >= 0 and self.bm25:
                    tokenized_query = query.split()
                    bm25_scores = self.bm25.get_scores(tokenized_query)
                    bm25_score = float(bm25_scores[doc_text_idx]) if doc_text_idx < len(bm25_scores) else 0.0

                # Combined score
                combined_score = (vector_score * VECTOR_WEIGHT) + (bm25_score * BM25_WEIGHT)

                if combined_score >= MIN_RELEVANCE_SCORE:
                    results.append({
                        "content": doc["content"],
                        "source": doc["id"],
                        "score": combined_score,
                        "vector_score": vector_score,
                        "bm25_score": bm25_score
                    })

            results.sort(key=lambda x: x["score"], reverse=True)
            logger.info(f"Found {len(results)} PDF results for query")
            return results[:top_k]
        except Exception as e:
            logger.error(f"PDF search failed: {e}")
            return []

    def search_logs(self, query: str, user_role: str) -> List[Dict]:
        """Search JSON logs with RBAC"""
        allowed = self.rbac["roles"].get(user_role, {}).get("allowed_sources", [])

        if "logs.json" not in allowed:
            logger.warning(f"User role {user_role} not allowed to access logs")
            return []

        try:
            with open(LOGS_PATH, "r") as f:
                logs = json.load(f)

            relevant = []
            query_terms = query.lower().split()

            for log in logs:
                if any(term in log["msg"].lower() for term in query_terms):
                    relevant.append(log)

            logger.info(f"Found {len(relevant)} log entries")
            return relevant
        except Exception as e:
            logger.error(f"Log search failed: {e}")
            return []

    def retrieve(self, query: str, user_role: str) -> Dict[str, Any]:
        """Main retrieval orchestrator with multi-source reasoning"""
        context = []
        sources = []

        # Route to appropriate sources based on query
        if any(term in query.lower() for term in ["revenue", "sales", "customer", "amount"]):
            sql_results = self.sql_query(query, user_role)
            if sql_results:
                context.append(f"SQL Data: {json.dumps(sql_results)}")
                sources.append({
                    "type": "sql",
                    "table": "sales_transactions",
                    "rows": len(sql_results)
                })

        if any(term in query.lower() for term in ["pdf", "document", "report", "policy", "handbook"]):
            pdf_results = self.search_pdfs(query, user_role)
            for res in pdf_results:
                context.append(f"Document [{res['source']}]: {res['content']}")
                sources.append({
                    "type": "pdf",
                    "source": res["source"],
                    "score": round(res["score"], 3)
                })

        if any(term in query.lower() for term in ["log", "error", "alert", "warn"]):
            log_results = self.search_logs(query, user_role)
            if log_results:
                context.append(f"Logs: {json.dumps(log_results)}")
                sources.append({"type": "log", "count": len(log_results)})

        return {
            "context": "\n\n".join(context) if context else "No relevant information found.",
            "sources": sources,
            "has_context": len(context) > 0
        }

    def generate_response(self, query: str, user_role: str) -> Dict[str, Any]:
        """Grounded response generation with citations"""
        retrieval = self.retrieve(query, user_role)

        if not retrieval["has_context"]:
            return {
                "answer": "I don't have sufficient information to answer this query based on the available data sources.",
                "confidence": "Low",
                "citations": [],
                "sources": retrieval["sources"]
            }

        answer_parts = []
        citations = []
        score_sum = sum(s.get("score", 0) for s in retrieval["sources"] if s["type"] == "pdf")

        # Extract SQL results
        if "SQL Data:" in retrieval["context"]:
            try:
                match = re.search(r"SQL Data: (\[.*?\])", retrieval["context"], re.DOTALL)
                if match:
                    data = json.loads(match.group(1))
                    if data and isinstance(data[0], dict) and "amount" in data[0]:
                        total = sum(item.get("amount", 0) for item in data)
                        answer_parts.append(f"Based on sales data, total revenue is ${total:,}")
                        citations.append("sales_transactions table")
            except (json.JSONDecodeError, IndexError, TypeError) as e:
                logger.warning(f"Failed to parse SQL results: {e}")

        # Extract PDF content
        for source in retrieval["sources"]:
            if source["type"] == "pdf":
                pattern = rf"Document \[{re.escape(source['source'])}\]: (.*?)(?:\n\n|$)"
                match = re.search(pattern, retrieval["context"], re.DOTALL)
                if match:
                    content = match.group(1).strip()[:200]
                    answer_parts.append(f"According to {source['source']}: {content}")
                    citations.append(source["source"])

        if not answer_parts:
            answer_parts.append("Found relevant information but couldn't extract specific details.")

        # Confidence based on sources and scores
        if len(citations) >= CONFIDENCE_HIGH_THRESHOLD and score_sum > 1.0:
            confidence = "High"
        elif len(citations) >= CONFIDENCE_MED_THRESHOLD:
            confidence = "Medium"
        else:
            confidence = "Low"

        return {
            "answer": " ".join(answer_parts),
            "confidence": confidence,
            "citations": citations,
            "sources": retrieval["sources"]
        }


class RBACEnforcer:
    """Enforce RBAC policies and handle sensitive queries"""

    def __init__(self, rag_system):
        self.rag = rag_system
        self.users = self._load_users()

    def _load_users(self) -> Dict[str, Dict]:
        """Load user-to-role mappings"""
        try:
            with open(USERS_PATH, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load users: {e}")
            return {}

    def _validate_user_and_role(self, user_id: str) -> Optional[str]:
        """Validate user exists and return their role"""
        if user_id not in self.users:
            logger.warning(f"Unauthorized access attempt: {user_id}")
            return None

        role = self.users[user_id].get("role")

        if role not in self.rag.rbac.get("roles", {}):
            logger.error(f"Invalid role {role} for user {user_id}")
            return None

        return role

    def _check_sensitive_query(self, query: str, user_role: str) -> Optional[Dict]:
        """Block sensitive queries from unauthorized users"""
        if any(keyword in query.lower() for keyword in SENSITIVE_KEYWORDS):
            if user_role != SENSITIVE_MIN_ROLE:
                logger.warning(f"Blocked sensitive query from {user_role}")
                return {
                    "answer": f"You don't have permission to access sensitive information. "
                              f"Contact {SENSITIVE_MIN_ROLE} for access.",
                    "confidence": "High",
                    "citations": [],
                    "sources": [],
                    "error_code": "RBAC_VIOLATION"
                }
        return None

    def query(self, user_id: str, query_text: str) -> Dict[str, Any]:
        """Process query with RBAC enforcement"""
        # Validate user and get role
        user_role = self._validate_user_and_role(user_id)
        if not user_role:
            return {
                "answer": "Access denied: Invalid user or role",
                "confidence": "High",
                "citations": [],
                "sources": [],
                "error_code": "AUTH_FAILURE"
            }

        # Check for sensitive queries
        sensitive_result = self._check_sensitive_query(query_text, user_role)
        if sensitive_result:
            return sensitive_result

        # Generate response with RBAC applied
        response = self.rag.generate_response(query_text, user_role)

        # Add explainability
        response["explainability"] = {
            "user_role": user_role,
            "retrieval_trace": response["sources"],
            "rbac_applied": True
        }

        logger.info(f"Query processed for user {user_id} (role: {user_role})")
        return response
