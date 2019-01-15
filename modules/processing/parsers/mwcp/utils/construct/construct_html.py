"""This module is used to convert constructs to an HTML document.

To use, run the html_hex with a construct and data:
    print html_hex(CONSTRUCT, data)
"""
from __future__ import print_function

import binascii
import codecs
import os
import construct
import itertools
import jinja2
import sys


PY3 = sys.version_info.major == 3


try:
    # Python 2
    from itertools import izip_longest
except ImportError:
    # Python 3
    from itertools import zip_longest as izip_longest


# Monkey patch Range so it adds the index in the "path" variable.
# Okay so this is a little hacky, but it's the only way to reliably get list indexes for children.
def _parse(self, stream, context, path):
    min = self.min(context) if callable(self.min) else self.min
    max = self.max(context) if callable(self.max) else self.max
    if not 0 <= min <= max <= sys.maxsize:
        raise construct.RangeError("unsane min %s and max %s" % (min, max))
    obj = construct.ListContainer()
    context = construct.Container(_ = context)
    try:
        # PATCH: add counter to path, so we know the children's index when viewing results.
        counter = 0
        while len(obj) < max:
            fallback = stream.tell()
            obj.append(self.subcon._parse(stream, context._, path + '[{}]'.format(counter)))
            context[len(obj)-1] = obj[-1]
            counter += 1
    except StopIteration:
        pass
    except construct.ExplicitError:
        raise
    except Exception:
        if len(obj) < min:
            raise construct.RangeError("expected %d to %d, found %d" % (min, max, len(obj)))
        stream.seek(fallback)
    return obj
construct.Range._parse = _parse


COLORPALLETTE = [
        '#00ff00', '#0000ff', '#00ffff', '#ff0000', '#ffff00', '#ff00ff',
        '#008000', '#000080', '#008080', '#00ff80', '#0080ff', '#800000', '#808000', '#80ff00',
        '#800080', '#808080', '#80ff80', '#8000ff', '#8080ff', '#80ffff', '#ff8000', '#ff0080',
        '#ff8080', '#ffff80', '#ff80ff',
        '#004000', '#00bf00', '#000040', '#004040', '#008040', '#00bf40', '#00ff40', '#004080',
        '#00bf80', '#0000bf', '#0040bf', '#0080bf', '#00bfbf', '#00ffbf', '#0040ff', '#00bfff',
        '#400000', '#404000', '#408000', '#40bf00', '#40ff00', '#400040', '#404040', '#408040',
        '#40bf40', '#40ff40', '#400080', '#404080', '#408080', '#40bf80', '#40ff80', '#4000bf',
        '#4040bf', '#4080bf', '#40bfbf', '#40ffbf', '#4000ff', '#4040ff', '#4080ff', '#40bfff',
        '#40ffff', '#804000', '#80bf00', '#800040', '#804040', '#808040', '#80bf40', '#80ff40',
        '#804080', '#80bf80', '#8000bf', '#8040bf', '#8080bf', '#80bfbf', '#80ffbf', '#8040ff',
        '#80bfff', '#bf0000', '#bf4000', '#bf8000', '#bfbf00', '#bfff00', '#bf0040', '#bf4040',
        '#bf8040', '#bfbf40', '#bfff40', '#bf0080', '#bf4080', '#bf8080', '#bfbf80', '#bfff80',
        '#bf00bf', '#bf40bf', '#bf80bf', '#bfbfbf', '#bfffbf', '#bf00ff', '#bf40ff', '#bf80ff',
        '#bfbfff', '#bfffff', '#ff4000', '#ffbf00', '#ff0040', '#ff4040', '#ff8040', '#ffbf40',
        '#ffff40', '#ff4080', '#ffbf80', '#ff00bf', '#ff40bf', '#ff80bf', '#ffbfbf', '#ffffbf',
        '#ff40ff', '#ffbfff'
    ]


def brightness(hexcode):
    """Calculates brightness for give html hex code of the format #xxxxxx"""
    return int(hexcode[1:3], 16) * .299 + int(hexcode[3:5], 16) * .587 + int(hexcode[5:7], 16) * .114

# Calculate brightness for each color and determine if text should be black or white.
FORMAT_COLORS = [(bg_color, '#000000' if brightness(bg_color) >= 128 else '#ffffff') for bg_color in COLORPALLETTE]


def grouper(n, iterable, fillvalue=None):
    """
    Groups iterable into n length chunks.
    If the last chunk doesn't have n items, the remaining is filled with fillvalue.

    >>> list(grouper(3, 'ABCDEFG', fillvalue='x'))
    [('A', 'B', 'C'), ('D', 'E', 'F'), ('G', 'x', 'x')]
    """
    args = [iter(iterable)] * n
    return izip_longest(fillvalue=fillvalue, *args)


def _iter_colors(data, color_map, default=None):
    """Yields byte and format color for each byte of data according to the member_map.

    :param data: Data to iterate over.
    :param color_map: Dictionary that matches offset a member and color to use
    :param default: default colors to use.

    :yield: tuple containing (byte, format_color_tuple)
    """
    iter_data = enumerate(data)
    for offset, datum in iter_data:
        if offset in color_map:
            colors, member = color_map[offset]
            yield datum, colors
            for offset, datum in itertools.islice(iter_data, 0, member.length - 1):
                yield datum, colors
        else:
            yield datum, default


class Member(construct.RawCopy):
    """
    This is a subconstruct that collects offset, data, and size information into the given
    member table, but then returns the original parsed value, like nothing happened.
    (This is to allow the callbacks work like they originally functioned.)
    """

    def __init__(self, member_map, subcon):
        """
        :param member_map: a defaultdict(list) mapping the offsets to the parsed objects
        :param subcon:
        """
        self._member_map = member_map
        super(Member, self).__init__(subcon)

    def _generate_value_str(self, value, indent=0):
        tabs = '\t' * indent
        if isinstance(value, construct.ListContainer):
            return '- ' + tabs + ('\n' + '- ' + tabs).join(
                self._generate_value_str(value_, indent=indent+1).lstrip() for value_ in value)
        elif isinstance(value, construct.Container):
            # NOTE: must use items() instead of iteritems() to keep order.
            return tabs + ('\n' + tabs).join(
                '{}: \n{}'.format(name, self._generate_value_str(value_, indent=indent+1)) for name, value_ in value.items())
        elif isinstance(value, bytes):
            # Escape unprintable bytes with "\x" notation.
            # (using codecs necessary to get this to work in both python 2 and 3)
            return tabs + codecs.escape_encode(value)[0].decode('utf-8')
        else:
            return tabs + '{}'.format(value)

    def _parse(self, stream, context, path):
        obj = super(Member, self)._parse(stream, context, path)
        # Store offset, data, and size information then return original object like nothing happened...
        if self.name:
            obj.name = self.name
            # Create a string representation of the value.
            obj.value_str = self._generate_value_str(obj.value)
            # Need path to so we can pull name history.
            obj.path = path

            # Map ourselves to every byte we cover.
            for index in range(obj.offset1, obj.offset2):
                self._member_map.setdefault(index, [])
                self._member_map[index].append(obj)

        return obj.value

    def _build(self, obj, stream, context, path):
        raise NotImplementedError('Unable to build using Member class.')


class MemberMap(construct.Adapter):
    r"""
    Wraps Subconstruct to produce a member map of all the parsed objections and their offsets:

    {offset: [list of parsed Containers in order of descending depth]}

    Needs to implement ``_decode()`` and ``_encode()``.

    :param subcon: the construct to wrap
    """
    def __init__(self, subcon):
        # member_map is a dictionary mapping the offsets of elements to a list of elements it portrays
        self._member_map = {}
        subcon = self._wrap_subcon(subcon)
        super(MemberMap, self).__init__(subcon)

    def _wrap_subcon(self, subcon):
        """Recursively wraps all subconstructs with Member."""
        # Recursively wrap internals as until we hit an adapter or non-Construct object.
        if isinstance(subcon, construct.Construct) and not isinstance(subcon, construct.Adapter):
            if hasattr(subcon, 'subcon'):
                subcon.subcon = self._wrap_subcon(subcon.subcon)
            elif hasattr(subcon, 'subcons'):
                new_subcons = []
                for _subcon in subcon.subcons:
                    new_subcons.append(self._wrap_subcon(_subcon))
                subcon.subcons = new_subcons

        # Switch uses "cases"
        if isinstance(subcon, construct.Switch):
            new_cases = {}
            for case, _subcon in subcon.cases.items():
                new_cases[case] = self._wrap_subcon(_subcon)
            subcon.cases = new_cases
            subcon.default = self._wrap_subcon(subcon.default)

        return Member(self._member_map, subcon)

    def _parse(self, stream, context, path):
        # Clear the member_table from previous use.
        self._member_map.clear()
        return super(MemberMap, self)._parse(stream, context, path)

    def _decode(self, obj, context):
        """Returns a copy of the member map."""
        return self._member_map.copy()

    def _encode(self, obj, context):
        raise NotImplementedError('Not supported.')


def _gen_color_map(member_map, depth=1):
    """
    Generates a color map that maps beginning offsets to a member.

    :param member_map: A dictionary map, mapping byte offsets to members.
    :param depth: The number of levels deep to display in table (defaults to all levels)
    :return:
    """
    if depth is not None and depth <= 0:
        raise ValueError('Invalid depth. Must be >= 1 or None.')
    color_map = {}
    color_generator = itertools.cycle(FORMAT_COLORS)

    # Contains set of parent members that are not allowed to be present.
    # (This helps to prevent a parent being displayed when a child contains a unnamed member (e.g. Padding))
    blacklist = set()

    curr_member = None
    for offset, members in sorted(member_map.items()):
        members = list(reversed(members))  # Members are generated in reverse with most depth being first.

        # Grab member based on requested level, (use furthest depth member if not requested)
        if depth is None:
            idx = len(members) - 1
        else:
            idx = min(depth - 1, len(members) - 1)
        member = members[idx]
        blacklist.update(id(m) for m in members[:idx])

        # Add to member to color map only if its the first time we are seeing it.
        if member != curr_member and id(member) not in blacklist:
            # Rename member to contain parent names.
            # ([1:] to remove the "parsing" name)
            member.name = ' / '.join(member.path.split(' -> ')[1:] + [member.name])
            color_map[offset] = (next(color_generator), member)
            curr_member = member

    return color_map


def html_hex(struct, data, width=16, depth=None):
    """
    Uses construct to parse data and creates a user-friendly html hex dump.

    :param struct: A construct.Construct object to parse.
    :param data: Data to dump.
    :param width: The number of bytes displayed for each line.
    :param depth: The number of levels deep to display in table (defaults to all levels)

    :raises ConstructError: If given struct fails to parse given data.
    """
    member_map = MemberMap(struct).parse(data)
    color_map = _gen_color_map(member_map, depth=depth)

    hex_dump = []
    for line_number, line in enumerate(grouper(width, _iter_colors(data, color_map), fillvalue=(None, None))):
        offset = line_number * width
        hex_line = []
        ascii_line = []
        # Generate hex and ascii version of each byte.
        current_color = None
        for byte, color in line:
            prefix, suffix = '', ''
            if color:
                if color != current_color:
                    bg_color, text_color = color
                    # End previous highlighting.
                    if current_color:
                        prefix += '</span>'
                    prefix += '<span style="background:{};color:{}">'.format(bg_color, text_color)
                    current_color = color
            # Clear highlighting.
            elif current_color:
                prefix = '</span>'
                current_color = None

            if byte is not None:
                if not PY3:
                    byte = ord(byte)
                hex_ = '{:02X}'.format(byte)
                ascii = chr(byte) if 32 < byte < 127 else '.'
            else:
                hex_ = '&nbsp;&nbsp;'
                ascii = '&nbsp;'

            hex_line.append('{}{}{}'.format(prefix, hex_, suffix))
            ascii_line.append('{}{}{}'.format(prefix, ascii, suffix))

        hex_line = '&nbsp;'.join(hex_line)
        ascii_line = ''.join(ascii_line)

        # Clear highlighting.
        if current_color:
            hex_line += '</span>'
            ascii_line += '</span>'

        hex_dump.append(('{:06x}'.format(offset), hex_line, ascii_line))

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__))),
        trim_blocks=True, lstrip_blocks=True)
    template = env.get_template('construct_template.html')

    return template.render(hex_dump=hex_dump, color_map=color_map)

if __name__ == '__main__':
    # Run an example if called directly.
    from .helpers import IP4Address, HexString
    from construct import this

    EMBED_SPEC = construct.Struct(
        'a' / IP4Address,
        'b' / IP4Address,
        'c' / IP4Address,
        'd' / IP4Address
    )

    address_struct = construct.Struct(
        'first' / construct.Struct('a' / construct.Byte, 'b' / construct.Byte),
        'second' / construct.Struct('inner2' / construct.Bytes(2))
        # 'internal' / IP4Address
    )

    PACKET = construct.Struct(
        construct.Padding(0x9),
        'Hardcoded Value 1' / HexString(construct.Int32ul),
        'Hardcoded Value 2' / HexString(construct.Int32ul),
        'Hardcoded Value 3' / HexString(construct.Int32ul),
        construct.Padding(0x17),
        'Compromised Host IP' / IP4Address,  # Use IP adapter
        # 'Unknown IP Addresses' / construct.Switch(
        #     this['Hardcoded Value 1'],
        #     {
        #         '0x1f4' : EMBED_SPEC
        #     },
        # ),
        'Unknown IP Addresses' / address_struct[4],
        # 'Unknown IP Addresses' / IP4Address[4],
        construct.Padding(8),
        'Unknown Indicator' / construct.String(0xF),
        construct.Padding(2),
        'Number of CPUs' / construct.Int32ul,
        'CPU Mhz' / construct.Int32ul,
        'Total Memory (MB)' / construct.Int32ul,
        'Compromised System Kernel' / construct.CString(),
        'Possible Trojan Version' / construct.CString()
    )

    data = (b'\x01\x00\x00\x00}\x00\x00\x00\x00\xf4\x01\x00\x002\x00\x00\x00\xe8'
            b'\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x01\x00\x00\x00\x00\x01\x00\x00\x00\xc0\xa8\x01\r\xc0\xa8\x01\r\xc0'
            b'\xa8\x01\r\xc0\xa8\x01\r\xc0\xa8\x01\r\xff\xff\x01\x00\x00\x00\x00\x00'
            b'-== Love AV ==-:\x00\x01\x00\x00\x00d\n\x00\x00\xc4\x07\x00\x00'
            b'Linux 3.13.0-93-generic\x001:G2.40\x00')

    print(html_hex(PACKET, data, depth=1))

