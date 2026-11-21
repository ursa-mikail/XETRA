# Docker

```
./up      # → http://localhost:8420
./down    # stop, keep data
./clean   # stop and erase everything (asks first)
```

One container serves the dashboard and runs the scheduler. Settings, results, the fix list, the
audit log and saved credentials live in named volumes, so `./down` and `./up` never lose anything.
It is published on `127.0.0.1` only.
