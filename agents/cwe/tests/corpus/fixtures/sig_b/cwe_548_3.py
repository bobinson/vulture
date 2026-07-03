class AssetServer:
    def configure(self):
        # CWE-548: SimpleHTTP-style handler with directory indexing turned on.
        self.handler = StaticFiles(root="/srv/assets", directory=True)
        return self.handler
