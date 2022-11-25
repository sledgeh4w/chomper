## v0.1.1

Released: 2022-11-21

- Make ``add_hook`` return from ``hook_add`` of ``Unicorn`` and add ``del_hook`` method for ``Chomper``.
- Close the library file after loading.
- Move default symbol hooks to ``arch`` module.

## v0.1.0

Released: 2022-09-17

- Support to emulate library file on arch ARM.

## v0.0.2

Released: 2022-09-10

- Fix wrong ``end`` param of ``hook_add``.
- Add ``user_data`` param for ``add_hook`` to customize params of callback.
- Support trace symbol calls by using ``trace_symbol_calls`` param.
- Raise ``EmulatorCrashedException`` with prompt message when missing symbol is required.
- Add a default logger for ``Chomper``.
- Add ``free`` method for ``Chomper``.

## v0.0.1

Released: 2022-09-08

- Initial release.
