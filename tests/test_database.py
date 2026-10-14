"""
Unit tests for JSON Database Layer CRUD operations.
"""

import os
import shutil
import tempfile
import unittest

from database.json_db import JSONDatabase


class TestJSONDatabase(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db = JSONDatabase(data_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        JSONDatabase(data_dir=os.path.join(base_dir, "data"))

    def test_insert_and_get_by_id(self):
        item = {"title": "Software Engineer", "company": "Tech Corp"}
        created = self.db.insert("jobs", item)

        self.assertIn("id", created)
        self.assertIn("created_at", created)

        retrieved = self.db.get_by_id("jobs", created["id"])
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["title"], "Software Engineer")

    def test_find_with_query(self):
        self.db.insert("jobs", {"title": "Junior Dev", "category": "Engineering"})
        self.db.insert("jobs", {"title": "Senior Dev", "category": "Engineering"})
        self.db.insert("jobs", {"title": "HR Manager", "category": "HR"})

        eng_jobs = self.db.find("jobs", {"category": "Engineering"})
        self.assertEqual(len(eng_jobs), 2)

        hr_jobs = self.db.find("jobs", {"category": "HR"})
        self.assertEqual(len(hr_jobs), 1)

    def test_update_record(self):
        item = self.db.insert("jobs", {"title": "Old Title", "salary": "$50k"})
        updated = self.db.update("jobs", item["id"], {"title": "New Title"})

        self.assertIsNotNone(updated)
        self.assertEqual(updated["title"], "New Title")
        self.assertEqual(updated["salary"], "$50k")

    def test_delete_record(self):
        item = self.db.insert("jobs", {"title": "To Delete"})
        self.assertTrue(self.db.delete("jobs", item["id"]))
        self.assertIsNone(self.db.get_by_id("jobs", item["id"]))

    def test_count_and_clear_collection(self):
        self.db.insert("jobs", {"title": "A"})
        self.db.insert("jobs", {"title": "B"})
        self.assertEqual(self.db.count("jobs"), 2)

        self.db.clear_collection("jobs")
        self.assertEqual(self.db.count("jobs"), 0)


if __name__ == "__main__":
    unittest.main()
