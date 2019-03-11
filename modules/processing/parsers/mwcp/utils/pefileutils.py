"""
Description: Utility for generic, repeated functions. Expandable as needed
python version: 2.7.8
"""

import logging
import os

logger = logging.getLogger(__name__)

import pefile


def obtain_pe(file_data):
    """
    Given file data, create a pefile.PE object from the data.

    :param file_data: Input PE file data

    :return: A pefile.PE object or None
    """
    if not file_data:
        return None
    try:
        return pefile.PE(data=file_data)
    except pefile.PEFormatError:
        logger.debug('A pefile.PE object on the file data could not be created.')
        return None


def obtain_section(section_name, pe=None, file_data=None):
    """
    Obtain the section obtain for a specficied PE section of a file.

    :param section_name: The name of the section from which to extract data.
    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: The PE secton object, or None.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        for section in pe.sections:
            if section.Name.rstrip('\0') == section_name:
                return section
        return None
    else:
        return None


def obtain_section_data(section_name, pe=None, file_data=None, min_size=0):
    """
    Obtain the data in a specified PE section of a file.

    :param section_name: The name of the section from which to extract data.
    :param pe: pefile.PE object
    :param file_data: Input file data
    :param min_size: The minimum acceptable size for the section_data

    :return: The PE section data, or None.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        section = obtain_section(section_name, pe)
        if section:
            section_data = section.get_data()
            if len(section_data) > min_size:
                return section_data
            return None
        return None
    else:
        return None


def check_section(section_name, pe=None, file_data=None):
    """
    Check if a specified PE section exists in a file.

    :param section_name: The name of the section from which to extract data.
    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: True if the section name is observed, False if it is not.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        for section in pe.sections:
            if section.Name.rstrip('\0') == section_name:
                return True
        return False
    return False


def obtain_physical_offset(mem_offset, pe=None, file_data=None):
    """
    For an PE file, convert a provided memory offset to a raw offset.

    :param mem_offset: The memory offset to convert to a raw offset
    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: Raw offset, or None.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        rva = mem_offset - pe.OPTIONAL_HEADER.ImageBase
        return pe.get_physical_by_rva(rva)
    else:
        return None


def obtain_memory_offset(raw_offset, pe=None, file_data=None):
    """
    For an PE file, convert a provided raw offset to a memory offset.

    :param raw_offset: The raw offset to convert to a memory offset
    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: Memory offset, or None.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        return pe.OPTIONAL_HEADER.ImageBase + pe.get_rva_from_offset(raw_offset)
    else:
        return None


def obtain_physical_offset_x64(rel_loc, inst_end_raw, pe=None, file_data=None):
    """
    For a 64-bit PE file, pointers to data elements are relative to the end of the assembly instruction. Therefore,
    given a location (rel_loc) relative to the end of an instruction (inst_end_raw), convert the end instruction
    address to a memory offset, add that value to the relative location of the data, and convert that to a raw
    offset.

    :param rel_loc: Location of data element relative to the end of the instruction address in inst_end_raw
    :param inst_end_raw: End of an instruction address referencing the data for rel_loc
    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: Raw offset for the data, or None.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        inst_end_mem = obtain_memory_offset(inst_end_raw, pe=pe)
        # Obtain the memory location of the data and convert it to a physical offset
        mem_loc = rel_loc + inst_end_mem
        return obtain_physical_offset(mem_loc, pe=pe)
    else:
        return None


def obtain_exports_list(pe=None, file_data=None):
    """
    Obtain a list of export names for the input PE file.

    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: A list of export names, or None.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        try:
            return [export.name for export in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        except AttributeError:
            return []
    else:
        return []


def check_export(export_name, pe=None, file_data=None):
    """
    Check if the provided export name is in the list of exports for the file.

    :param export_name: Target export name
    :param pe: pefile.PE object
    :param file_data: Input file data

    :return bool: Indicating if provided export name is in file exports
    """
    exports = obtain_exports_list(pe, file_data)
    return export_name in exports


def obtain_imported_dlls(pe=None, file_data=None):
    """
    Obtain a list of imported DLL names for the input PE file.

    :param pe: pefile.PE object, or None by default
    :param file_data: file data from which to create a pefile.PE object, or None by default

    :return: List of imported DLLs, or None
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        try:
            return [imp.dll for imp in pe.DIRECTORY_ENTRY_IMPORT]
        except AttributeError:
            return None
    else:
        return None


def obtain_imports_list(dll_name, pe=None, file_data=None):
    """
    Obtain a list of imports from a specified DLL for the input PE file.

    :param dll_name: Name of the DLL to obtain imports from
    :param pe: pefile.PE object, or None by default
    :param file_data: file data from which to create a pefile.PE object, or None by default

    :return: List of imports from the specified DLL, or None
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        try:
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                if imp.dll.lower() == dll_name.lower():
                    return [imp_func.name for imp_func in imp.imports]
        except AttributeError:
            return None
    else:
        return None


def is_imported(dll_name, func_name, pe=None, file_data=None):
    """
    Determines if a specified function is imported by the file.

    :param dll_name: Name of the DLL containing the imported function in question
    :param func_name: Name of the imported function within dll_name
    :param pe: pefile.PE object, or None by default
    :param file_data: file data from which to create a pefile.PE object, or None by default

    :return: True if function is imported
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        imported_funcs = obtain_imports_list(dll_name, pe=pe)
        if imported_funcs:
            for func in imported_funcs:
                if func.lower() == func_name.lower():
                    return True
    else:
        return None


def obtain_file_ext(pe=None, file_data=None):
    """
    Attempt to return the appropriate file extension for the input PE file. Use .bin as the default if it cannot be
    recovered or None if the file is not a PE file.

    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: The appropriate file extension for the PE file, .bin, or None.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        if pe.is_driver():
            return '.sys'
        elif pe.is_exe():
            return '.exe'
        elif pe.is_dll():
            return '.dll'
        else:
            return '.bin'
    else:
        return None


def is_64bit(pe=None, file_data=None):
    """
    Evaluate whether an input pefile.PE object or file data is 64-bit.

    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: True if 64-bit, False if 32-bit, None if could not be determined.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            return True
        elif pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
            return False
        else:
            logger.debug('The architecture type for the file could not be determined.')
    return None


def obtain_architecture_string(pe=None, file_data=None, bitterm=True):
    """
    Obtain an architecture type string for the input PE file. Allow the bitterm variable to determine if the string
    should be in the format of "32-bit" (default) or "x86" (must specify False). Return "Undetermined" if neither.

    :param pe: pefile.PE object
    :param file_data: Input file data
    :param bitterm: Flag to determine return string type

    :return: A string representing the architecture for the input PE file.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        is64 = is_64bit(pe=pe)
        if is64:
            if bitterm:
                return "64-bit"
            else:
                return "x64"
        # Specifically check if the return value is False, because that indicates 32-bit, None indicates undetermined.
        elif is64 is False:
            if bitterm:
                return "32-bit"
            else:
                return "x86"
        else:
            return "Undetermined"
    else:
        return None


def __obtain_exif_fname__(pe):
    """
    Obtain the filename from the pe.FileInfo listing of exif metadata.

    :param pe: pefile.PE object

    :return:
    """
    try:
        for file_info in pe.FileInfo:
            if file_info.Key == 'StringFileInfo':
                for string_table in file_info.StringTable:
                    for field_name, name_value in string_table.entries.iteritems():
                        if field_name == 'OriginalFilename':
                            return name_value
    except AttributeError:
        return None


def __obtain_exportdir_fname__(pe):
    """
    Obtain the filename from the export directory of the pefile.PE object.

    :param pe: pefile.PE object

    :return: The filename from the export directory, or None.
    """
    try:
        filename = pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
        return filename
    except AttributeError:
        return None


def obtain_original_filename(def_stub, pe=None, file_data=None, use_arch=False, ext='.bin'):
    """
    Attempt to obtain the original filename, either from the export directory or the pe.FileInfo, of the input file.
    If the filename cannot be recovered from either of those locations, append the applicable architecture string and
    file extension to the default stub and return that value. If no pefile.PE object is provided or can be created
    from the provided file data, return the default stub appended with ".bin".

    :param def_stub: Default filename stub, sans extension, to utilize if the filename cannot be recovered.
    :param pe: pefile.PE object
    :param file_data: Input file data
    :param use_arch: Flag indicating if the file architecture should be included in the name, False by default.
    :param ext: Extension to default to if it could not be determined. (defaults to ".bin")

    :return: The recovered filename from the pe metadata or a generated filename using def_stub.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        ext = obtain_file_ext(pe=pe)
        arch = obtain_architecture_string(pe=pe, bitterm=False)
        filename = __obtain_exportdir_fname__(pe) or __obtain_exif_fname__(pe)
        if filename:
            if use_arch:
                base, ext = os.path.splitext(filename)
                filename = base + "_" + arch + ext
            return filename
        else:
            return def_stub + "_" + arch + ext
    else:
        return def_stub + ext


def is_memory_mapped(file_data):
    """
    Takes file data and tries to determine if it's a memory-mapped image (which can be squashed)
    or a normal executable file

    :param file_data: The executable file to determine whether it's a memory-mapped image

    :return True if it's a memory-mapped image, false otherwise
    """
    pe = obtain_pe(file_data)
    if pe:
        for i in range(len(pe.sections) - 1):
            if i == len(pe.sections) - 1:
                section_end = pe.OPTIONAL_HEADER.SizeOfImage
            else:
                section_end = pe.sections[i + 1].VirtualAddress
            section_start = pe.sections[i].VirtualAddress + pe.sections[i].SizeOfRawData
            if file_data[section_start:section_end] != '\x00' * (section_end - section_start):
                return False
        return True
    return False


def squash_flat_executable(memory_mapped, pe=None):
    """
    Takes a memory mapped executable image and squashes it back down to a file that IDA can load or that can be
    executed. Note that hashes for files output by this function cannot be relied upon as valid.

    :param memory_mapped: Memory-mapped input file data
    :param pe: pefile.PE object

    :return The squashed image or None
    """
    if not pe:
        pe = obtain_pe(memory_mapped)
    if pe:
        squashed = pe.header
        for section in pe.sections:
            squashed += '\x00' * (section.PointerToRawData - len(squashed))
            squashed += memory_mapped[section.VirtualAddress:section.VirtualAddress + section.SizeOfRawData]
        squashed += '\x00' * (-len(squashed) & 0x1ff)
        squashed += memory_mapped[pe.OPTIONAL_HEADER.SizeOfImage:]
        return squashed
    return None


def obtain_raw_file_size(pe=None, file_data=None):
    """
    Obtain the raw file size based on the image header information. Specifically the SizeOfHeaders parameter from the
    IMAGE_OPTIONAL_HEADER, and the SizeOfRawData parameter for each PE section.

    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: The raw calculated size of the file from the PE headers.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        size = pe.OPTIONAL_HEADER.SizeOfHeaders
        for section in pe.sections:
            size += section.SizeOfRawData
        return size
    return None


def has_resources(pe):
    """
    Determine if the pefile.PE object contains resources.

    :param pe: pefile.PE object to check

    :return: Boolean value on whether the pefile.PE object has a DIRECTORY_ENTRY_RESOURCE.
    """
    return hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE')


class Resource(object):
    """
    Object for encapsulating resource information in a simplistic format.

    :param pe: pefile.PE object
    :param entry: pe.DIRECTORY_ENTRY_RESOURCE.entries[i].directory.entries[j] resource object.
    :param dirtype: Directory name / type string
    :param data: Data for the resource
    :param offset: Starting offset to resource data.
    :param idname: ID or name string for the resource (note: always a string)
    :param rsrc_entry: String of the dirtype\idname
    """

    def __init__(self, pe, entry, dirtype):
        self._data = None
        self._pe = pe
        self._entry = entry
        self._offset = None
        self.dirtype = dirtype
        if entry.name:
            self.idname = str(entry.name)
        else:
            self.idname = str(entry.id)
        self.rsrc_entry = "%s\\%s" % (self.dirtype, self.idname)
        self.fname_stub = "%s_%s" % (self.dirtype, self.idname)

    @property
    def data(self):
        """
        Obtain the data corresponding to the resource.

        :return: Data extracted for the specified resource.
        """
        if not self._data:
            rva = self._entry.directory.entries[0].data.struct.OffsetToData
            size = self._entry.directory.entries[0].data.struct.Size
            self._data = self._pe.get_memory_mapped_image()[rva:rva + size]
        return self._data

    @data.setter
    def data(self, value):
        """
        Sets the data for given resource.
        """
        self._data = value

    @property
    def offset(self):
        if not self._offset:
            rva = self._entry.directory.entries[0].data.struct.OffsetToData
            self._offset = self._pe.get_physical_by_rva(rva)
        return self._offset


def iter_rsrc(pe, dirtype=None):
    """
    Iterates through resources for given pe file.

    :param pe: pefile.PE object
    :param dirtype: Optional resource directory type or name to iterate.
        defaults to iterating all directories.

    :yield: pefileutils.Resources objects
    """
    if has_resources(pe):
        for dir_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            # Generate dirtype
            if dir_entry.name:
                extracted_dirtype = str(dir_entry.name)
            else:
                for key, id in pefile.RESOURCE_TYPE.items():
                    if id == dir_entry.id:
                        extracted_dirtype = key
                        break
                else:
                    extracted_dirtype = str(dir_entry.id)

            # Extract entries.
            if not dirtype or str(dirtype) == extracted_dirtype:
                for entry in dir_entry.directory.entries:
                    yield Resource(pe, entry, extracted_dirtype)


def extract_all_rsrc(pe=None, file_data=None):
    """
    For a specified file, extract all resources to a list of pefileutils.Resource objects.

    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: List of pefileutils.Resource objects, or an empty list.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        return list(iter_rsrc(pe))
    return []


def extract_rsrc_dir(dirtype, pe=None, file_data=None):
    """
    For a specified file, extract all resources of in a specific directory (by name or type) to a list of
    pefileutils.Resource objects.

    :param dirtype: The resource directory type or name
    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: List of pefileutils.Resource objects matching the dirtype, or an empty list.
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        return list(iter_rsrc(pe, dirtype=dirtype))
    return []


def extract_target_rsrc(dirtype, idname, pe=None, file_data=None):
    """
    For a specified file, extract a specific resource by name/id from a specific directory (by name or type) as a
    pefileutils.Resource object.

    :param dirtype: The resource directory type or name
    :param idname: The resource name or id, must be a string
    :param pe: pefile.PE object
    :param file_data: Input file data

    :return: A pefileutils.Resource object matching the dirtype/idname
    """
    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        for rsrc in iter_rsrc(pe, dirtype=dirtype):
            if rsrc.idname == idname:
                return rsrc
    return None


def check_rsrc_dir(dirtype, pe=None, file_data=None):
    """
    For a specified file, check if a specific resource directory (by name or type) exists

    :param dirtype: The resource directory type or name
    :param pe: pefile.PE object
    :param file_data: Input file data
    :return: Boolean value indicating if resource directory exists
    """

    if file_data:
        pe = obtain_pe(file_data)
    if pe:
        for _ in iter_rsrc(pe, dirtype=dirtype):
            return True
    return False
