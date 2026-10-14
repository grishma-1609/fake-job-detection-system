"""
Database Layer: JSON Database Engine with Thread-Safe File Locking and Atomic Operations.
Designed to be modular so it can easily be swapped with SQLite or PostgreSQL in production.
"""

import json
import os
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


class JSONDatabase:
    """Thread-safe JSON Database Engine with atomic write operations and full CRUD support."""

    _instance = None
    _lock = threading.RLock()

    def __new__(cls, data_dir: Optional[str] = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(JSONDatabase, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, data_dir: Optional[str] = None):
        if data_dir is not None:
            self.data_dir = os.path.abspath(data_dir)
        elif not getattr(self, "_initialized", False) or not getattr(self, "data_dir", None):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.data_dir = os.path.join(base_dir, "data")

        os.makedirs(self.data_dir, exist_ok=True)
        if not hasattr(self, "file_locks"):
            self.file_locks: Dict[str, threading.Lock] = {}
        self._initialized = True

        # Ensure default collections exist
        self._init_collections(["users", "jobs", "analyses", "reports", "settings"])

    def _get_file_lock(self, collection_name: str) -> threading.Lock:
        with self._lock:
            if collection_name not in self.file_locks:
                self.file_locks[collection_name] = threading.Lock()
            return self.file_locks[collection_name]

    def _get_collection_path(self, collection_name: str) -> str:
        return os.path.join(self.data_dir, f"{collection_name}.json")

    def _init_collections(self, collections: List[str]) -> None:
        for coll in collections:
            path = self._get_collection_path(coll)
            if not os.path.exists(path):
                self._write_file(coll, [])

    def _read_file(self, collection_name: str) -> List[Dict[str, Any]]:
        path = self._get_collection_path(collection_name)
        if not os.path.exists(path):
            return []

        lock = self._get_file_lock(collection_name)
        with lock:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if not content:
                        return []
                    data = json.loads(content)
                    return data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError) as e:
                # In case of corruption, handle safely
                return []

    def _write_file(self, collection_name: str, data: List[Dict[str, Any]]) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        path = self._get_collection_path(collection_name)
        temp_path = f"{path}.tmp_{uuid.uuid4().hex}"
        lock = self._get_file_lock(collection_name)

        with lock:
            try:
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                # Atomic replace
                os.replace(temp_path, path)
            except Exception as e:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
                raise e

    # ==========================================
    # CRUD Operations
    # ==========================================

    def insert(self, collection_name: str, document: Dict[str, Any]) -> Dict[str, Any]:
        """Insert a new record with auto-generated id and timestamp."""
        doc = document.copy()
        if "id" not in doc or not doc["id"]:
            doc["id"] = str(uuid.uuid4())

        now = datetime.utcnow().isoformat() + "Z"
        if "created_at" not in doc:
            doc["created_at"] = now
        doc["updated_at"] = now

        items = self._read_file(collection_name)
        items.append(doc)
        self._write_file(collection_name, items)
        return doc

    def get_by_id(self, collection_name: str, doc_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a document by unique ID."""
        items = self._read_file(collection_name)
        for item in items:
            if item.get("id") == str(doc_id):
                return item
        return None

    def find(
        self,
        collection_name: str,
        query: Optional[Dict[str, Any]] = None,
        sort_key: Optional[str] = "created_at",
        reverse: bool = True,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Find records matching key-value pairs in query."""
        items = self._read_file(collection_name)

        if query:
            filtered = []
            for item in items:
                matches = True
                for k, v in query.items():
                    if item.get(k) != v:
                        matches = False
                        break
                if matches:
                    filtered.append(item)
            items = filtered

        if sort_key:
            items.sort(key=lambda x: str(x.get(sort_key, "")), reverse=reverse)

        if limit is not None and limit > 0:
            items = items[:limit]

        return items

    def update(
        self, collection_name: str, doc_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update fields of an existing document."""
        items = self._read_file(collection_name)
        updated_doc = None

        for idx, item in enumerate(items):
            if item.get("id") == str(doc_id):
                # Preserve id and created_at
                orig_id = item.get("id")
                orig_created = item.get("created_at")
                item.update(updates)
                item["id"] = orig_id
                item["created_at"] = orig_created
                item["updated_at"] = datetime.utcnow().isoformat() + "Z"
                items[idx] = item
                updated_doc = item
                break

        if updated_doc is not None:
            self._write_file(collection_name, items)

        return updated_doc

    def delete(self, collection_name: str, doc_id: str) -> bool:
        """Delete a record by ID."""
        items = self._read_file(collection_name)
        new_items = [item for item in items if item.get("id") != str(doc_id)]

        if len(new_items) != len(items):
            self._write_file(collection_name, new_items)
            return True
        return False

    def delete_many(self, collection_name: str, query: Dict[str, Any]) -> int:
        """Delete multiple records matching query."""
        items = self._read_file(collection_name)
        remaining = []
        deleted_count = 0

        for item in items:
            matches = True
            for k, v in query.items():
                if item.get(k) != v:
                    matches = False
                    break
            if matches:
                deleted_count += 1
            else:
                remaining.append(item)

        if deleted_count > 0:
            self._write_file(collection_name, remaining)

        return deleted_count

    def count(self, collection_name: str, query: Optional[Dict[str, Any]] = None) -> int:
        """Count records matching optional query."""
        return len(self.find(collection_name, query, sort_key=None))

    def clear_collection(self, collection_name: str) -> None:
        """Clear all records from a collection."""
        self._write_file(collection_name, [])


# Singleton database instance getter
def get_db(data_dir: Optional[str] = None) -> JSONDatabase:
    return JSONDatabase(data_dir=data_dir)
