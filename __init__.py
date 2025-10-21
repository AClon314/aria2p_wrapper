"""
continue suspended file, simulate request as from browser, support smart auto retry when speed is too low.

```python
from aria2p_wrapper import Aria, File
aria = await Aria()
aria.download(File('https://',path=''))
```
"""

from aria2p_wrapper.aria2p_wrapper import (
    File,
    Aria,
    get_aria,
    get_slowest,
    done_and_not,
    calc_hash,
    calc_hash_,
    to_options,
)
