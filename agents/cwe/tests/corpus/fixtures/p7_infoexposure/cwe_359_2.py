def fetch_record(session, dob):
    url = f"https://ehr.example.com/records?dob={dob}"
    return session.get(url, timeout=5).json()
