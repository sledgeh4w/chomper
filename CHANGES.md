## v0.2.1

Released: -

## v0.2.0

Released: 2022-11-26

- Rename project to Chomper.

## v0.1.1

Released: 2022-11-21

- Change ``add_hook`` to return the handle from ``Uc.hook_add`` and add ``del_hook`` method.
- Close library files after loaded.

## v0.1.0

Released: 2022-09-17

- Support emulate library files on arch ARM.

## v0.0.2

Released: 2022-09-10

- Fix wrong ``end`` argument when calling ``Uc.hook_add``.
- Add ``user_data`` param to ``add_hook`` to pass params to callback.
- Support trace symbol calls by using ``trace_symbol_calls`` param.
- Improve exception message of ``EmulatorCrashedException`` when missing symbol is required.
- Add ``logger`` param to ``Infernum``.
- Add ``free`` method to ``Infernum`` to release allocated memory.

## v0.0.1

Released: 2022-09-08

- Initial release.
