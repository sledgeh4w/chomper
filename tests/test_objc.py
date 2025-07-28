# from chomper.objc import pyobj2nsobj, pyobj2cfobj
#
#
# def test_pyobj2nsobj(emu_ios):
#     result = pyobj2nsobj(emu_ios, 1)
#     assert result
#
#     result = pyobj2nsobj(emu_ios, "chomper")
#     assert result
#
#     result = pyobj2nsobj(emu_ios, b"chomper")
#     assert result
#
#     result = pyobj2nsobj(emu_ios, [1, 2, 3])
#     assert result
#
#     result = pyobj2nsobj(
#         emu_ios,
#         {
#             "name": "chomper",
#         },
#     )
#     assert result
#
#
# def test_pyobj2cfobj(emu_ios):
#     result = pyobj2cfobj(emu_ios, 1)
#     assert result
#
#     result = pyobj2cfobj(emu_ios, "chomper")
#     assert result
#
#     result = pyobj2cfobj(emu_ios, b"chomper")
#     assert result
#
#     result = pyobj2cfobj(emu_ios, [1, 2, 3])
#     assert result
#
#     result = pyobj2cfobj(
#         emu_ios,
#         {
#             "name": "chomper",
#         },
#     )
#     assert result
