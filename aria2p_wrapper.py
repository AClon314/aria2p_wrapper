#!/bin/env python
"""
continue suspended file, simulate request as from browser, support smart auto retry when speed is too low.

```python
from aria2p_wrapper import Aria, File
aria = Aria()
aria.download(File('https://',path=''))
```
"""
import aria2p
import asyncio, hashlib, logging, subprocess
from time import sleep
from pathlib import Path
from datetime import timedelta
from typing import Callable, Literal, Sequence, TypedDict, Unpack, Any, get_args

try:
    import requests, httpx

    Response = requests.Response | httpx.Response | Any
except ImportError:
    ...
_ARIA_CMD = "aria2c --enable-rpc --rpc-listen-port={} --continue=true"
TYPE_HASH = Literal["md5", "sha1", "sha256", "sha512", "shake_128", "shake_256"]
HASH = get_args(TYPE_HASH)
Log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s %(levelname)s] %(filename)s:%(lineno)s\t%(message)s",
    datefmt="%H:%M:%S",
)
IS_DEBUG = Log.isEnabledFor(logging.DEBUG)
CHECK_HASH = False  # set True in production env


def calc_hash(file_path: str | Path, algorithm: TYPE_HASH | str = "sha256") -> str:
    """sync func"""
    Log.debug(f"🖩 Calc {algorithm}: {file_path}")
    h = getattr(hashlib, algorithm)()
    with open(file_path, "rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024 * 1024), b""
        ):  # 1GB mem read per each
            h.update(chunk)
    return h.hexdigest()


async def calc_hash_(file_path: str | Path, algorithm: TYPE_HASH | str = "sha256"):
    return await asyncio.to_thread(calc_hash, file_path, algorithm)


class Kw_options(TypedDict, total=False):
    """
    aria2 download option
    header: see https://github.com/pawamoy/aria2p/issues/100"""

    dir: str
    out: str | Callable[..., str]
    max_connection_per_server: str
    split: str
    user_agent: str
    referer: str
    max_tries: str
    header: str


def to_options(response: "requests.Response") -> dict[str, str]:
    """from response to aria2p options"""
    options: dict[str, str] = {}
    req_headers = response.request.headers
    req_opt = {
        "User-Agent": "user-agent",
        "Referer": "referer",
        "Accept-Encoding": "",
        "Connection": "",
    }
    for req_key, opt_key in req_opt.items():
        if req_key in req_headers and opt_key:
            options[opt_key] = req_headers[req_key]
    if "Accept-Encoding" in req_headers:
        ce = req_headers["Accept-Encoding"].lower()
        options["http-accept-gzip"] = (
            "true" if "gzip" in ce or "deflate" in ce else "false"
        )
    options["enable-http-keep-alive"] = (
        "true" if req_headers["Connection"].lower() == "keep-alive" else "false"
    )

    excluded = req_opt.keys()
    header = [f"{k}: {v}" for k, v in req_headers.items() if not k in excluded]
    if header:
        options["header"] = "\r\n".join(header)

    Log.debug(f"{options=}")
    return options


class File:
    """Record file metadata with checksum and aria2p options"""

    @property
    def md5(self):
        return calc_hash_(self.path, "md5")

    @md5.setter
    def md5(self, value: str):
        self.expect_md5 = value

    @property
    def sha256(self):
        return calc_hash_(self.path, "sha256")

    @sha256.setter
    def sha256(self, value: str):
        self.expect_sha256 = value

    def __init__(
        self,
        *urls: str,
        path: Sequence[str] | str | Path = ".",
        md5: str | None = None,
        sha256: str | None = None,
        **options,
    ):
        """
        Args:
            urls: source urls for the same file, used with mirror site for high loss network
            md5: without connect to Internet if file exists and checksum matches.
            sha256: same as above.
            options: for `aria2p.API.add_uris(...)`, key/value **use str, not int**

        `max-connection-per-server`: `-x`
        `split`: `-s`
        `user-agent`: mozilla/5.0
        `referer`: domain url
        `max-tries`: default `-m 3`, see `_OPT`
        ~~`header`~~: not implemented due to aria2p only accept `str` for 1 header"""
        self.urls = list(urls)
        self.path = (
            Path(path).resolve()
            if isinstance(path, (str, Path))
            else Path(*path).resolve()
        )
        self.expect_sha256 = sha256
        self.expect_md5 = md5
        for k, v in options.items():
            setattr(self, k, v)

    def exists(self, check_hash=CHECK_HASH, follow_symlinks: bool = True):
        """return is_exist and checksum"""
        is_exist = self.path.exists(follow_symlinks=follow_symlinks)
        return (is_exist and self.checksum()) if check_hash else is_exist

    def checksum(self, hash: str | None = None, algorithm: TYPE_HASH = "md5") -> bool:
        """raise ValueError if no hash is set, return True if hash matches"""
        _hash = calc_hash_(self.path, algorithm)
        if not hash:
            hash = next((h for h in (self.expect_sha256, self.expect_md5) if h), None)
        if not hash:
            raise ValueError(f"unset `md5` or `sha256`: {self}")
        is_hash = _hash == hash
        (
            Log.warning(f"{self.path.name}: {hash}(expected) ≠ {_hash}(current)")
            if is_hash == False
            else Log.debug(f"{self.path.name}: {hash}(expected)")
        )
        return is_hash


def get_aria(
    host="http://localhost",
    port=6800,
    secret="",
    timeout: float | int = 60.0,
    Raise=False,
) -> tuple[aria2p.API, subprocess.Popen | None]:
    """
    Args:
        Raise: if False, start a new aria2c local process when connection refused

    Returns:
        aria2p.API: The connected Aria2 API instance.

    Raises:
        ConnectionError: If the server refuses the connection.
        TimeoutError: If the connection times out.
    """
    api = aria2p.API(
        aria2p.Client(
            host=host,
            port=port,
            secret=secret,
            timeout=timeout,
        )
    )
    process = None
    try:
        api.get_stats()
    except ConnectionError:
        if Raise:
            raise
        Log.warning("Aria2 RPC server not running, starting a new one...")
        process = subprocess.Popen(_ARIA_CMD.format(port), shell=True)
        api, _ = get_aria(host, port, secret, timeout, Raise=True)
    return api, process


def get_slowest(
    dls: Sequence[aria2p.Download],
):
    """the slowest download task"""
    longest_eta = timedelta()
    _slowest = None
    for _dl in dls:
        if _dl.is_active and not _dl.is_complete and longest_eta < _dl.eta:
            longest_eta = _dl.eta
            _slowest = _dl
    return _slowest


def done_and_not(dls: Sequence["aria2p.Download"]):
    complete = [dl for dl in dls if dl.is_complete]
    NOT = [dl for dl in dls if not dl.is_complete]
    return complete, NOT


class Aria:
    downloads: list[aria2p.Download] = []
    """the downloads that we are **listening and managing**"""

    INTERVAL = 0.5
    """How often to poll for small tasks. You can set this longer if you connect to a remote slow server."""

    OPTION = {
        "continue": "true",
        "split": 5,
        "max-connection-per-server": 5,
        "max-concurrent-downloads": 3,
        "min-split-size": "20M",  # don't split if file size < 40M
        # "retry-wait": INTERVAL * 10,
        "max-tries": 3,
    }

    @property
    def OPTIONS(self):
        """default options for aria2p.API.add_uris(...)"""
        return {k: str(v) for k, v in self.OPTION.items()}

    @property
    def dls(self):
        """get the latest download tasks from aria2p.get_downloads()"""
        return self.api.get_downloads([dl.gid for dl in self.downloads])

    @property
    def slowest(self):
        """the slowest download task"""
        return get_slowest(self.dls)

    @property
    def done_and_not(self):
        """the uncomplete download tasks"""
        return done_and_not(self.dls)

    def __init__(
        self,
        host="http://localhost",
        port=6800,
        secret="",
        launch=True,
        options: dict | None = None,
    ):
        """
        Args:
            launch: if True, will start local aria2c process after failed to connect to aria2c.
        """
        self.api, self.process = get_aria(
            host=host,
            port=port,
            secret=secret,
            Raise=not launch,
        )
        if options is not None:
            self.OPTION = options
            self.api.set_global_options(self.OPTIONS)

    def download(
        self,
        *file: File,
        position: int | None = None,
        response: "Response | None" = None,
        **options: Unpack[Kw_options],
    ):
        """check exists and checksum, or download files with aria2p

        Args:
            options: default `OPT`, for `aria2p.API.add_uris(...)`, key/value **use str, not int**

        `max-connection-per-server`: `-x`
        `split`: `-s`
        `user-agent`: mozilla/5.0
        `referer`: domain url
        `max-tries`: default `-m 3`, see `OPT`
        ~~`header`~~: not implemented due to aria2p only accept `str` for 1 header
        ~~`out`: output filename~~, has set in `file`
        ~~`dir`: download directory~~, has set in `file`

        [⚙️for more options](https://aria2.github.io/manual/en/html/aria2c.html#input-file)
        """
        files = [d for d in file if not d.exists()]
        if files:
            _info = (
                [f"({f.path},{f.urls})\t" for f in files]
                if IS_DEBUG
                else [f"{f.path.name}" for f in files]
            )
            Log.debug(f"⬇ {_info}")
        dls: list[aria2p.Download] = []
        for f in files:
            response_options = (
                to_options(response)
                if isinstance(response, "requests.Response")
                else {}
            )
            _options = {
                **self.OPTIONS,
                **response_options,
                "dir": str(f.path.parent),
                "out": str(f.path.name),
                **options,
            }
            dl = self.api.add_uris(f.urls, options=_options, position=position)
            dls.append(dl)
        self.downloads.extend(dls)
        return dls

    def __str__(self):
        stat = self.api.get_stats()
        ico = []
        if stat.num_active:
            ico += [f"{stat.num_active}⬇"]
        if stat.num_waiting:
            ico += [f"{stat.num_waiting}⏸"]
        if stat.num_stopped:
            ico += [f"{stat.num_stopped}⏹"]
        ico += [stat.download_speed_string()]
        return f"{'  '.join(ico)} Aria@{id(self):x}"

    def __repr__(self):
        cli = self.api.client
        return f"{self.__class__.__name__}(host={cli.host},port={cli.port},secret={cli.secret})"

    def str_(self, slowest: aria2p.Download | None = None):
        if not slowest:
            slowest = self.slowest
        if slowest:
            return f"{slowest.name} ETA={slowest.eta_string()}"
        return ""

    def wait_all(self, interval=INTERVAL * 2):
        while slowest := self.slowest:
            if slowest:
                Log.info(f"{self}\t🐌{self.str_(slowest)}")
            sleep(interval)

    async def till_all(self, interval=INTERVAL):
        """⚠️ Warn: this run **forever**! You need manually kill this.
        ```python
        done, pending = await asyncio.wait(
            [asyncio.gather(*tasks), asyncio.create_task(wait_all_dl())],
            return_when=asyncio.FIRST_COMPLETED
        )
        ret = done.pop().result()
        for task in pending:
            task.cancel()
        ```
        """
        while slowest := self.slowest:
            if slowest:
                Log.info(
                    f"⬇ {slowest.name} ETA: {slowest.eta}. {self.api.get_stats()._struct}"
                )
            await asyncio.sleep(interval)


async def test():
    aria = Aria()
    aria.download(
        File(
            "https://dldir1.qq.com/qqfile/qq/PCQQ9.7.17/QQ9.7.17.29225.exe",
            path="qq.bin",
        )
    )
    await aria.till_all()


if __name__ == "__main__":
    asyncio.run(test())
