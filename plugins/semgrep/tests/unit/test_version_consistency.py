"""Feature 0102: every place that names the plugin's version agrees, at 0.1.1 or later.

The supervisor builds the plugin image from its Dockerfile, on the user's
machine, under the tag in plugin.toml. A bump that misses a site either keeps
running an image built from older source or a 0.1.0 image, which predates the
/run token, Host and Content-Type guards. The image name is local: no registry
holds it, because publishing it would redistribute the Semgrep engine inside.
"""

import re
import tomllib
from pathlib import Path

from src import wrapper

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
IMAGE = "vulture-plugin-semgrep"
FIRST_GUARDED_RELEASE = (0, 1, 1)


def _version_sites() -> dict[str, str]:
    manifest = tomllib.loads((PLUGIN_ROOT / "plugin.toml").read_text())
    project = tomllib.loads((PLUGIN_ROOT / "pyproject.toml").read_text())
    readme = (PLUGIN_ROOT / "README.md").read_text()
    image, _, tag = manifest["runtime"]["image"].rpartition(":")
    assert image == IMAGE, manifest["runtime"]["image"]
    sites = {
        "plugin.toml [plugin].version": manifest["plugin"]["version"],
        "plugin.toml [runtime].image tag": tag,
        "pyproject.toml [project].version": project["project"]["version"],
        "wrapper /info version": wrapper.info()["version"],
    }
    readme_tags = re.findall(r"(?<![\w./-])" + re.escape(IMAGE) + r":([0-9][0-9A-Za-z.+-]*)", readme)
    assert readme_tags, "README.md no longer names the bundled image tag"
    sites.update({f"README.md bundled image tag #{i}": v for i, v in enumerate(readme_tags, 1)})
    return sites


def test_version_consistency():
    sites = _version_sites()
    assert len(set(sites.values())) == 1, f"version sites disagree: {sites}"
    version = sites["plugin.toml [plugin].version"]
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    assert match, f"plugin version {version!r} is not semver"
    assert tuple(map(int, match.groups())) >= FIRST_GUARDED_RELEASE, (
        f"plugin version {version} predates the /run guards; images before "
        f"{'.'.join(map(str, FIRST_GUARDED_RELEASE))} accept any caller"
    )


def test_image_is_local_only():
    """No registry or namespace in the name, so nothing can pull it from one."""
    image = tomllib.loads((PLUGIN_ROOT / "plugin.toml").read_text())["runtime"]["image"]
    assert "/" not in image, f"plugin image {image!r} names a registry; the image must be built locally"
