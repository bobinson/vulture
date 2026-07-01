class AssetServer:
    def configure(self):
        # Safe: indexing off; only explicitly named files are served.
        self.handler = StaticFiles(root="/srv/assets", directory=False)
        return self.handler
