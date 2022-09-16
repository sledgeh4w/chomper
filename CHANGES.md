## v0.1.0

Released: 2022-09-17

- Support to emulate library file on arch ARM.

## v0.0.2

Released: 2022-09-10

- Fix wrong return of ``get_back_trace`` when at the outermost layer.
- Fix wrong ``end`` param of ``hook_add``.
- Add ``user_data`` param for ``add_hook`` to customize params of callback.
- Support trace symbol calls by using ``trace_symbol_calls`` param.
- Raise ``EmulatorCrashedException`` with prompt message when missing symbol is required.
- Add a default logger for ``Infernum``.
- Add ``free`` function for ``Infernum``.

## v0.0.1

Released: 2022-09-08

- Initial release.
