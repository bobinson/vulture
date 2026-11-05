# held-out heldout_15 (CWE-22): a management command opening a JSON file at a path joined from two constants
import json
import os

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Loads the lesson rows from a bundled JSON file."

    def handle(self, *args, **options):
        file_path = os.path.join("lessons", "lessons.json")

        try:
            with open(file_path, "r") as json_file:
                rows = json.load(json_file)
        except FileNotFoundError:
            self.stderr.write(f"file not found: {file_path}")
            return
        except json.JSONDecodeError as e:
            self.stderr.write(f"bad JSON: {e}")
            return

        for row in rows:
            self.stdout.write(row.get("name", ""))
