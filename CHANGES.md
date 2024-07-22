## v0.3.2

Released: 2024-07-22

- Emulate `libmacho.dylib` instead of hooking.
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

- Change ``add_hook`` to return the handle from ``Uc.hook_add`` and add ``del_hook`` method.
- Close library files after loaded.

## v0.1.0

Released: 2022-09-17

- Support emulating ARM architecture libraries.

## v0.0.2

Released: 2022-09-10

- Fix wrong ``end`` argument when calling ``Uc.hook_add``.
- Add ``user_data`` param to ``add_hook`` to pass params to callback.
- Support tracing symbol calls by using ``trace_symbol_calls`` param.
- Improve exception message of ``EmulatorCrashedException`` when missing symbol is required.
- Add ``logger`` param to ``Infernum``.
- Add ``free`` method to ``Infernum`` to release allocated memory.

## v0.0.1

Released: 2022-09-08

- Initial release.
