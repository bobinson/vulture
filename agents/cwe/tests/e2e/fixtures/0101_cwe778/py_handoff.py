# ruff: noqa -- a CWE-778 fixture read as text: undefined names and unused bindings are its subject.
# Feature 0101, CWE-778 Concept A in Python. Every identifier is invented.


def describe_job(job):
    try:
        return render_job(job)
    except ValueError as exc:  # EXPECT: clean
        return f"Error: {exc}"


class Poller:
    def poll(self):
        try:
            self.rows = self.source.fetch()
        except OSError as exc:  # EXPECT: clean
            self._last_error = exc

    def poll_all(self, errors):
        for src in self.sources:
            try:
                src.fetch()
            except OSError as exc:  # EXPECT: clean
                errors.append(exc)


# ---- these record nothing, or guard a security operation: all reported ----


def classify_row(row):
    try:
        return parse_row(row)
    except ValueError as exc:  # EXPECT: finding
        return {"kind": type(exc).__name__}


def looks_numeric(raw):
    try:
        float(raw)
        return True
    except ValueError:  # EXPECT: finding
        return False


def check_signature(payload, sig):
    try:
        return Success(signer.verify(payload, sig))
    except ValueError as exc:  # EXPECT: finding
        return Failure(exc)


def confirm_address(raw):
    try:
        return unpack_ticket(raw)
    except (BadSignature, SignatureExpired) as e:  # EXPECT: finding
        return str(e)


def check_attempt(user, attempt):
    try:
        return bcrypt.checkpw(attempt.encode(), user.pw_digest)
    except ValueError as exc:  # EXPECT: finding
        return Outcome(error=exc)


def read_ticket(sig):
    try:
        return jws.loads(sig, KEY)
    except ValueError as e:  # EXPECT: finding
        return {'error': e}


def second_factor(code, errors):
    try:
        return otp_check(code)
    except ValueError as e:  # EXPECT: finding
        errors.append(e)


def describe_upload(raw):
    try:
        return describe(raw)
    except ValueError as exc:  # EXPECT: finding
        detail = str(exc)
        return None
