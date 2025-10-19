# Copyright 2023 Hendrik Wingbermuehle, Denys Serdyukov

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Inspired by https://github.com/python/cpython/blob/3.11/Lib/plistlib.py

from plistlib import InvalidFileException, PlistFormat
from plistlib import load as plistlibLoad
import struct
from io import BytesIO
import math
import json

__version__="0.0.3"

__all__ = [
    "_BinaryPlist17Parser",
    "_BinaryPlist17Writer"
]

class _BinaryPlist17Parser:
    """
    Read or write a bplist17 file.
    Raise InvalidFileException in case of error, otherwise return the
    root object.
    """

    def __init__(self, dict_type):
        self._dict_type = dict_type

    def parse(self, fp, with_type_info=False):
        try:
            # The basic file format:
            # MAGIC (6 bytes)
            # VERSION (2 bytes)
            
            # ROOT Object
            
            self._fp = fp
            # self._fp.seek(-32, os.SEEK_END)
            self._fp.seek(0)
            magic = self._fp.read(0x6)
            # print(magic)
            version = self._fp.read(0x2)
            # print(version)

            return self._read_object_at(0x8, with_type_info=with_type_info)

        except (OSError, IndexError, struct.error, OverflowError,
                ValueError):
            raise InvalidFileException()

    # def _get_size(self, tokenL):
    #     """ return the size of the next object."""
    #     if tokenL == 0xF:
    #         m = self._fp.read(1)[0] & 0x3
    #         s = 1 << m
    #         f = '>' + _BINARY_FORMAT[s]
    #         return struct.unpack(f, self._fp.read(s))[0]

    #     return tokenL

    # def _read_ints(self, n, size):
    #     data = self._fp.read(size * n)
    #     if size in _BINARY_FORMAT:
    #         return struct.unpack(f'>{n}{_BINARY_FORMAT[size]}', data)
    #     else:
    #         if not size or len(data) != size * n:
    #             raise InvalidFileException()
    #         return tuple(int.from_bytes(data[i: i + size], 'big')
    #                      for i in range(0, size * n, size))

    # def _read_refs(self, n):
    #     return self._read_ints(n, self._ref_size)

    def _read_object_at(self, addr, with_type_info=False):
        """
        read the object by reference.

        May recursively read sub-objects (content of an array/dict/set)
        """
        # print("Entered _read_object_at: ", addr)
        totalReadBytes = []
        self._fp.seek(addr)
        token = self._fp.read(1)[0]
        totalReadBytes.append(token)
        tokenH, tokenL = token & 0xF0, token & 0x0F

        # elif token == 0x0f:
        #     result = b''

        if tokenH == 0x10:  # int
            # Integer (length tokenL)
            result_type = 'int'
            result_value = int.from_bytes(self._fp.read(tokenL), 'little', signed=True)

        elif token == 0x22: # real
            result_type = 'float'
            result_value = struct.unpack('<f', self._fp.read(4))[0]

        elif token == 0x23: # real
            result_type = 'double'
            result_value = struct.unpack('<d', self._fp.read(8))[0]

        elif tokenH == 0x40:  # data
            size = self._read_dynamic_size(totalReadBytes, tokenL)
            bytesData = self._fp.read(size)
            
            nestedData = BytesIO(bytesData)

            nestedData.seek(0)
            magic = nestedData.read(0x6)
            # print(magic)
            version = nestedData.read(0x2)
            # print(version)
            nestedData.seek(0)
            
            if len(bytesData) != size:
                raise InvalidFileException()
            
            result_type = 'data.hexstring'
            result_value = ''.join('{:02x}'.format(x) for x in bytesData)
            
            if magic == b'bplist':
                if version == b'00':
                    # parse bplist00
                    #TODO Fix BPlist00 parser
                    # type = 'data.bplist00'
                    # result = plistlibLoad(nestedData, fmt=PlistFormat.FMT_XML)
                    result_value = result_value
                elif version == b'17':
                    result_type = 'data.bplist17'
                    result_value = _BinaryPlist17Parser(dict).parse(nestedData, with_type_info=with_type_info)

        elif tokenH == 0x60:  # unicode string
            size = self._read_dynamic_size(totalReadBytes, tokenL) * 2
            data = self._fp.read(size)
            if len(data) != size:
                raise InvalidFileException()
            result_type = 'string_utf16le'
            result_value = data.decode('utf-16le')
        
        elif tokenH == 0x70:  # ascii string
            size = self._read_dynamic_size(totalReadBytes, tokenL)
            data = self._fp.read(size)
            if len(data) != size:
                raise InvalidFileException()
            result_type = 'string_ascii'
            result_value = data.decode('ascii').rstrip('\x00')

        elif tokenH == 0x80:  # Referenced Object
            size = self._read_dynamic_size(totalReadBytes, tokenL)
            address = int.from_bytes(self._fp.read(size), 'little')
            currentAddr = self._fp.tell()
            result = self._read_object_at(address, with_type_info=with_type_info)
            self._fp.seek(currentAddr)
            return result # return early, because the result of _read_object_at() is the final result
                          # i.e. it already combines (type, value) if with_type_info == True

        elif tokenH == 0xA0:  # array
            endAddress = int.from_bytes(self._fp.read(0x8), 'little')
            result_type = 'array'
            result_value = []
            while(self._fp.tell() <= endAddress):
                result_value.append(self._read_object_at(self._fp.tell(), with_type_info=with_type_info))
            
            if self._fp.tell() != (endAddress + 1):
                raise InvalidFileException() # TODO: Descriptive Exception

        elif token == 0xB0:
            result_type = 'bool'
            result_value = True

        elif token == 0xC0:
            result_type = 'bool'
            result_value = False

        elif tokenH == 0xD0:  # dict
            endAddress = int.from_bytes(self._fp.read(0x8), 'little')
            result_type = 'dict'
            result_value = self._dict_type()
            try:
                while(self._fp.tell() <= endAddress):
                    key = self._read_object_at(self._fp.tell(), with_type_info=False)
                    value = self._read_object_at(self._fp.tell(), with_type_info=with_type_info)
                    result_value[key] = value
            except TypeError:
                raise InvalidFileException()
            
            if self._fp.tell() != (endAddress + 1):
                raise InvalidFileException() # TODO: Descriptive Exception
            
            result_value = self._transformDictionary(result_value, with_type_info=with_type_info)
        
        elif token == 0xE0:
            result_type = 'null'
            result_value = None

        elif tokenH == 0xF0:
            result_type = 'uint'
            result_value = int.from_bytes(self._fp.read(tokenL), 'big', signed=False)

        else:
            # raise InvalidFileException()
            raise TypeError("unsupported type: %s at: %s" % (''.join('{:02x}'.format(x) for x in totalReadBytes), addr))

        if with_type_info:
            result = self._dict_type()
            result['type'] = result_type
            result['value'] = result_value
            return result
        else:
            return result_value

    def _read_dynamic_size(self, totalReadBytes, tokenL):
        if tokenL == 0xF:
            token2 = self._fp.read(1)[0]
            totalReadBytes.append(token2)
            length = token2 & 0xF # extract last 4 bits from token2 as length
            if length != 0 and ((token2 & 0xF0) == 0x10) :
                size = int.from_bytes(self._fp.read(length), 'little')
            else:
                raise TypeError("unsupported type: %s" % ''.join('{:02x}'.format(x) for x in totalReadBytes))
        else:
            size = tokenL
        return size
    
    def _transformDictionary(self, dictionary, with_type_info=False):
        transformed_dict = {}
        if with_type_info:
             return dictionary
        else:
            class_value = dictionary["$class"]
            if class_value == "NSDictionary" or class_value == "NSMutableDictionary":
                transformed_dict["$class"] = class_value
                keys = dictionary["NS.keys"]
                objects = dictionary["NS.objects"]
                for index in range(len(keys)):
                    transformed_dict[keys[index]] = objects[index]
                
                return transformed_dict
            else:
                return dictionary
    
        

class _BinaryPlist17Writer:
    def __init__(self, fp):
        self._fp = fp
        self.known_objects = {}
    
    def write(self, value, with_type_info=False):
        plist_bytes = 'bplist17'.encode()
        current_position = len(plist_bytes)
        value_bytes = self._pack(value=value, position=current_position, with_type_info=with_type_info)

        self._fp.write(plist_bytes + value_bytes)
        return self._fp
    
    def _pack_dict(self, value, position, with_type_info):
        element_bytes = bytes()
        curr_position = position + 9
        for key, val in value.items():
            element_bytes = element_bytes + self._pack(key, position=curr_position+len(element_bytes), with_type_info=False)
            element_bytes = element_bytes + self._pack(val, position=curr_position+len(element_bytes), with_type_info=with_type_info)
    
        previous_instance_position = self._get_previous_instance_position(json.dumps(value), position=position, type='dict')
        if previous_instance_position is not None :
            return self._pack_addr(previous_instance_position)
        size = len(element_bytes)
        endposition = curr_position +  size - 1
        header_bytes = b'\xD0' + endposition.to_bytes(length=8, byteorder='little')
        return header_bytes + element_bytes

    def _pack_array(self, value, position, with_type_info):
        element_bytes = bytes()
        curr_position = position + 9
        for element in value:
            element_bytes = element_bytes + self._pack(element, position=curr_position+len(element_bytes), with_type_info=with_type_info)
        
        size = len(element_bytes)
        endposition = curr_position +  size - 1
        header_bytes = b'\xA0' + endposition.to_bytes(length=8, byteorder='little')

        return header_bytes + element_bytes
    
    def _pack_int(self, value):

        if value < 0:
            if value < -2**63:
                raise ValueError("value: %i out of range of int64" % value)
            else:
                buff_size = 8
        else:
            buff_size = math.ceil((math.log(value + 1, 2) + 1) / 8)

        value_bytes = self._calc_datatype_prefix(datatype=0x10, size=buff_size) + value.to_bytes(buff_size, byteorder='little', signed=True)
        return value_bytes

    def _pack_uint(self, value):
        buff_size = max(1, math.ceil((math.log(value + 1, 2)) / 8))

        value_bytes = self._calc_datatype_prefix(datatype=0xF0, size=buff_size) + value.to_bytes(buff_size, byteorder='little', signed=False)
        return value_bytes

    def _pack_float(self, value):
        return b'\x22' + struct.pack('<f', value)
    
    def _pack_double(self, value):
        return b'\x23' + struct.pack('<d', value)
    
    def _pack_bool(self, value):
        if value:
            return b'\xB0'
        else:
            return b'\xC0'
        
    def _pack_null(self):
        return b'\xE0'

    def _pack_str_ascii(self, value):
        str_bytes = value.encode(encoding='utf-8') + b'\x00'
        return self._calc_datatype_prefix(datatype=0x70, size=len(str_bytes)) + str_bytes
    
    def _pack_str_utf16le(self, value):
        str_bytes = value.encode(encoding='utf-16le')
        return self._calc_datatype_prefix(datatype=0x60, size=len(str_bytes)//2) + str_bytes

    def _pack_data(self, value):
        return self._calc_datatype_prefix(datatype=0x40, size=len(value)) + value
    
    def _pack_addr(self, value):
        addr_length = math.ceil(math.log(value + 1, 2) / 8)
        addr_bytes = value.to_bytes(length=addr_length, byteorder='little')
        return self._calc_datatype_prefix(datatype=0x80, size=addr_length) + addr_bytes
    
    def _get_previous_instance_position(self, value, position, type):
        if isinstance(value, (str, bytes)):
            objects_with_type = self.known_objects.get(type)
            if objects_with_type is None:
                objects_with_type = {}
                self.known_objects[type] = objects_with_type
            
            previous_instance_position = objects_with_type.get(value, None)
            if previous_instance_position is not None:
                return previous_instance_position
            else:
                self.known_objects[type][value] = position
                return None

    def _pack(self, value, position, with_type_info):
        if with_type_info:
            return self._pack_with_type_info(value=value, position=position)
        else:
            return self._pack_without_type_info(value=value, position=position)
        
    def _pack_without_type_info(self, value, position):
        if isinstance(value, dict):
            transformed_value = self._transformDictionary(value, with_type_info=False)
            return self._pack_dict(value=transformed_value, position=position, with_type_info=False)

        elif isinstance(value, (list, tuple)):
            return self._pack_array(value=value, position=position, with_type_info=False)
        
        elif isinstance(value, bool):
            return self._pack_bool(value=value)

        elif isinstance(value, int):
            return self._pack_int(value=value)

        elif isinstance(value, float):
            # TODO float or double depending on parsing/specification TBD
            return self._pack_float(value=value)
            # return self._pack_double(value=value)

        elif isinstance(value, str):
            previous_instance_position = self._get_previous_instance_position(value, position=position, type='string')
            if previous_instance_position is not None :
                return self._pack_addr(previous_instance_position)
            # TODO ascii or utf-16le depending on parsing/specification TBD
            return self._pack_str_ascii(value=value)
        
        elif isinstance(value, (bytes, bytearray)):
            return self._pack_data(value=value)

        elif value is None:
            return self._pack_null()

        else:
            raise TypeError("unsupported value type: %s" % (type(value)))
        
            
    def _pack_with_type_info(self, value, position):
        type_def = value.get('type')
        contained_value = value.get('value')

        types = type_def.split('.')
        
        if types[0] == 'int':
            return self._pack_int(value=contained_value)
        elif types[0] == 'float':
            return self._pack_float(value=contained_value)
        elif types[0] == 'double':
            return self._pack_double(value=contained_value)
        elif types[0] == 'data':
            # TODO handle data
            print('handle data')
            if types[1] == 'hexstring':
                return self._pack_data(bytes.fromhex(contained_value))
            else:
                print('handle %s' % type_def)
        elif types[0] == 'string_utf16le':
            previous_instance_position = self._get_previous_instance_position(contained_value, position=position, type=types[0])
            if previous_instance_position is not None :
                return self._pack_addr(previous_instance_position)
            return self._pack_str_utf16le(value=contained_value)
        elif types[0] == 'string_ascii':
            previous_instance_position = self._get_previous_instance_position(contained_value, position=position, type=types[0])
            if previous_instance_position is not None :
                return self._pack_addr(previous_instance_position)
            return self._pack_str_ascii(value=contained_value)
        elif types[0] == 'array':
            return self._pack_array(value=contained_value, position=position, with_type_info=True)
        elif types[0] == 'bool':
            return self._pack_bool(value=contained_value)
        elif types[0] == 'dict':
            return self._pack_dict(value=contained_value, position=position, with_type_info=True)
        elif types[0] == 'null':
            return self._pack_null()
        elif types[0] == 'uint':
            return self._pack_uint(value=contained_value)
        else:
            raise TypeError('unsupported value type %s' % types[0])
    
    def _calc_datatype_prefix(self, datatype, size):
        if size < 0xF:
            return (datatype | size).to_bytes(length=1, byteorder='little')
        else:
            return (datatype | 0x0F).to_bytes(length=1, byteorder='little') + self._pack(size, position=0, with_type_info=False)
        
    def _transformDictionary(self, dictionary: dict, with_type_info=False):
        transformed_dict = {}
        if with_type_info:
             return dictionary
        else:
            class_value = dictionary["$class"]
            if class_value == "NSDictionary" or class_value == "NSMutableDictionary":
                transformed_dict["$class"] = class_value
                keys = []
                objects = []
                for key in dictionary.keys():
                    if key != "$class":
                        keys.append(key)
                        objects.append(dictionary[key])
                transformed_dict["NS.keys"] = keys
                transformed_dict["NS.objects"] = objects
                return transformed_dict
            else:
                return dictionary
