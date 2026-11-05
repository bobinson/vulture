from .store import remove


def delete_record(caller, record_id):
    remove(record_id, by=caller.id)
