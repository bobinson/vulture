# ruff: noqa
def z():
    try:
        do()
    except Exception as e:
        # EXPECT-NEXT: clean  known-gap fastapi detail str e
        raise HTTPException(status_code=500, detail=str(e))
