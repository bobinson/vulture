# ruff: noqa -- a CWE-778 fixture read as text: undefined names and unused bindings are its subject.
# Feature 0101, CWE-778 Concept A security gate (RED round 2, R2-4): privilege
# change, credential stores, remote login, secret release, sandboxing, device
# attestation and lockout/rate-limit primitives are security operations, so a
# handler that only stores their failure is reported. The ordinary twins at the
# bottom are excused. Every identifier is invented.


class Worker:
    def drop_user(self):
        try:
            os.setuid(self.uid)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def drop_group(self):
        try:
            os.setgid(self.gid)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def drop_effective(self):
        try:
            os.seteuid(self.uid)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def drop_all(self):
        try:
            os.setresuid(self.uid, self.uid, self.uid)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def join_groups(self):
        try:
            os.setgroups(self.groups)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def init_groups(self):
        try:
            os.initgroups(self.user, self.gid)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def read_keyring(self):
        try:
            keyring.get(self.service)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def open_tunnel(self):
        try:
            ssh.connect(self.host, pkey=self.k)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def agent_login(self):
        try:
            sess.userauth_agent(self.user)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def open_box(self):
        try:
            box.unseal(self.blob)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def open_vault(self):
        try:
            vault.unlock(self.master)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def load_filter(self):
        try:
            seccomp.load(self.filter)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def enter_jail(self):
        try:
            self.sandbox.enter(self.profile)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def copy_item(self):
        try:
            SecItemCopyMatching(query, result)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def read_slot(self):
        try:
            SecureStore.getItem(self.slot)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def finish_assertion(self):
        try:
            fido.complete(self.assertion)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def register_device(self):
        try:
            webauthn.verify_registration(self.reply)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def load_bundle(self):
        try:
            load_pkcs12(self.blob)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def clear_lockout(self):
        try:
            self.lockout.reset(self.user)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def check_pinning(self):
        try:
            self.pinning.check(self.chain)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def take_slot(self):
        try:
            self.limiter.consume(self.ip)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def take_quota(self):
        try:
            self.ratelimit.hit(self.ip)
        except Exception as exc:  # EXPECT: finding
            self.last_error = exc

    def load_row(self):
        try:
            self.cache.load(self.key)
        except Exception as exc:  # EXPECT: clean
            self.last_error = exc

    def paint_frame(self):
        try:
            self.canvas.paint(self.frame)
        except Exception as exc:  # EXPECT: clean
            self.last_error = exc

    def set_title(self):
        try:
            self.window.set_title(self.title)
        except Exception as exc:  # EXPECT: clean
            self.last_error = exc

    def setup_grid(self):
        try:
            self.grid.setup(self.rows)
        except Exception as exc:  # EXPECT: clean
            self.last_error = exc
