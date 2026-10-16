# ruff: noqa
# Known gap: a caller-facing class name raised while validating UPSTREAM data. The message
# embeds the upstream instance and schema, but the class is read by its words alone; telling
# what the try body validated needs data flow into the library call. Pinned to the observed verdict.
class ProfileHandler:
    def get(self):
        upstream = billing_client.get_profile()
        try:
            schema_lib.validate(upstream, PROFILE_SCHEMA)
        except schema_lib.ValidationError as exc:
            self.write(str(exc))  # EXPECT: clean gap-validation-of-upstream-data
