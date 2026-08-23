def persist_credentials(pw):
    open("/etc/app/state.txt", "w").write(f"password={pw}")
