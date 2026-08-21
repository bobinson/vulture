def fetch_record(session, dob):
    url = "https://ehr.example.com/records"
    return session.post(url, json={"dob": dob}, timeout=5).json()
