# aria2p_wrapper
continue suspended file thanks to aria2c, simulate request as from browser, ~~support smart auto retry when speed is too low~~.

stripped from `mocap-wrapper`, as a second-hand wrapper for aria2p.

## Usage

```python
from aria2p_wrapper import Aria, File
aria = Aria()
aria.download(File('https://',path=''))
```