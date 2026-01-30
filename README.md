# Dimscord With Windows Native TLS Option
Modification of [dimscord](https://github.com/krisppurg/dimscord) (Discord bot & REST library for Nim made by [krisppurg](https://github.com/krisppurg), with an **option** to disable OpenSSL requirement and use Windows native WinHTTP/SChannel transport instead. 

## Why using WinHTTP/SChannel instead of OpenSSL?

1. This approach fixes the following errors which occur on bot startup on Windows machines that doesn't have `libssl`/`libcrypto` DLLs instaled:

```
could not load: (libssl-1_1-x64|ssleay64|libssl64).dll
```
and
```
could not load: (libcrypto-1_1-x64|libeay64).dll
```

2. If your goal is to ship a bot as a standalone binary and ensure it will run on a bigger part of Windows machines (hi red team)


## Requirements
- Nim >= 2.0.6


## Install
Clone repo:

```bash
git clone https://github.com/imitxtion/dimscord_nossl
```


## Usage
1. Add the following to your `config.nims`:

```nim
when defined(windows):
switch("define", "windowsNativeTls") # Use WinHTTP/SChannel on Windows.
```

**Or** add `-d:windowsNativeTls` flag every time you compile for Windows.
Example:

```bash
nim c -d:windowsNativeTls bot.nim
```

Accordingly, don't add it when compiling for **Linux** or **MacOS**, compiler will use OpenSSL.

2. Add appropriate import to your files:
```nim
import dimscord_nossl
```

Otherwise, the usage is absolutely the same as with the original [dimscord](https://github.com/krisppurg/dimscord). There you can find documentation, examples, solutions for other library-related problems, and so on.