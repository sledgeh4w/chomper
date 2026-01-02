## v0.3.7

Released: 2026-01-03

- Add handling for xpc messages to support calls like `-[UIDevice identifierForVendor]` and `-[NSFileManager ubiquityIdentityToken]`.
- Add compatibility for `nanosleep`, `vm_region_64`, `vm_read_overwrite` and `-[UIScreen brightness]`.
- Optimize module memory layout for Mach-O.
- Fix an error if the `oldp` argument for `sysctl` is null ([issue #218][issue_218]).

[issue_218]: https://github.com/sledgeh4w/chomper/issues/218

## v0.3.6

Released: 2025-10-08

- Add `return_callback` parameter to `add_hook` for handling hook function returns.
- Fix `pthread_mutex_lock` failures when a mutex's type is set to `PTHREAD_MUTEX_ERRORCHECK`.
- Optimize performance of module loading and fixup.
- Refactor the Objective-C API.
- Add support for dispatch semaphore.
- Fix the issue where `+[CADisplay displays]` returns empty.

## v0.3.5

Released: 2025-06-08

- Compatible with rebasing in the `LC_DYLD_CHAINED_FIXUPS` command.
- Fix zero-size memory allocation in `os_alloc_once`.
- Implement dynamic loading of system modules at runtime for `dlopen`.
- Add support for standard IO: `stdin`, `stdout`, `stderr`.
- Add `Block` class for easier Objective-C block construction.
- Add `add_mem_hook` method for exporting unicorn memory hook functionality.
- Support emulation of device files such as `/dev/null` and `/dev/urandom`.
- Add compatibility for `-[NSFileManager directoryContentsAtPath:]`, `-[NSUserDefaults setObject:forKey:]`, `NSLog` and `CFNetworkCopySystemProxySettings`.
- Compatible with capstone 6.0.0a4.

## v0.3.4

Released: 2025-03-06

- Add extensive support for system calls and file system.
- Support `NSDateFormatter` and `NSTimeZone`.
- Support initialization of `NSURLSession`.
- Partial compatibility with `arm64e` architecture.
- Add fault handling for `readClass` to enhance class loading reliability.
- Fix incorrect number formatting in `sscanf`.
- Fix missing relocation.

## v0.3.3

Released: 2024-12-06

- Compatibility with unicorn 2.1.0.
- Fix no memory to map ([issue #93][issue_93]).
- Support more system calls (`read`, `open`, `close`, `lseek`, `stat`).
- Support `NSBundle` initialization.

[issue_93]: https://github.com/sledgeh4w/chomper/issues/93

## v0.3.2

Released: 2024-07-22

- Load `libmacho.dylib` instead of mocking.
- Fix initialization of large-sized `NSData`.
- Compatibility with lief 0.15.0.
- Improve performance of `read_string`.

## v0.3.1

Released: 2024-05-12

- Fix an error when creating `NSURLRequest` object ([issue #68][issue_68]).
- Add `ObjC` which provided friendly interface to Objective-C runtime.
- Add hook for preferences related functions.
- Add hook for `MGCopyAnswe` which used by `UIDevice`.
- Add hook for keychain related functions.

[issue_68]: https://github.com/sledgeh4w/chomper/issues/68

## v0.3.0

Released: 2024-04-12

- Support emulating iOS executable files.
- Support working with Objective-C.
- Drop support for Python 3.7.

## v0.2.0

Released: 2022-11-26

- Rename project to Chomper.

## v0.1.1

Released: 2022-11-21

- Change `add_hook` to return the handle from `Uc.hook_add` and add `del_hook` method.
- Close library files after loaded.

## v0.1.0

Released: 2022-09-17

- Support emulating ARM architecture libraries.

## v0.0.2

Released: 2022-09-10

- Fix wrong `end` argument when calling `Uc.hook_add`.
- Add `user_data` param to `add_hook` to pass params to callback.
- Support tracing symbol calls by using `trace_symbol_calls` param.
- Improve exception message of `EmulatorCrashedException` when missing symbol is required.
- Add `logger` param to `Infernum`.
- Add `free` method to `Infernum` to release allocated memory.

## v0.0.1

Released: 2022-09-08

- Initial release.
