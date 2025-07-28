import os
import urllib.request
from pathlib import Path
from urllib.error import URLError


def get_base_path() -> str:
    return os.path.abspath(os.path.dirname(__file__))


def download_sample_file(binary_path: str) -> str:
    filepath = os.path.join(get_base_path(), "../..", binary_path)

    path = Path(filepath).resolve()
    if path.exists():
        return filepath

    if not path.parent.exists():
        path.parent.mkdir(parents=True)

    url = "https://sourceforge.net/projects/chomper-emu/files/%s/download" % binary_path
    print(f"Downloading sample file: {url}")

    urllib.request.urlretrieve(url, path)

    try:
        download_sample_file(f"{binary_path}/../Info.plist")
    except URLError:
        pass

    return filepath
