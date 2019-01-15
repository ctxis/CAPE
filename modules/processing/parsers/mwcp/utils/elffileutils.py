"""
Description: Utility for elftools python library.
"""

import logging

logger = logging.getLogger(__name__)

import elftools.elf.elffile as elffile
import io


def obtain_elf(file_data):
    """
    Given file data, create an elftools.ELFFile object from the data.

    :param file_data: Input ELF file data

    :return: An elftools.ELFFile object or None
    """
    try:
        elf = elffile.ELFFile(io.BytesIO(file_data))
        return elf
    except elffile.ELFError:
        logger.debug('An elftools.ELFFile object on the file data could not be created.')
        return None


def obtain_section(section_name, elf=None, file_data=None):
    """
    Obtain the section obtain for a specficied ELF section of a file.

    :param section_name: The name of the section to obtain
    :param elf: elftools.ELFFile object
    :param file_data: Input file data

    :return: The elftools.Section object, or None.
    """
    if file_data:
        elf = obtain_elf(file_data)
    if elf:
        for section in elf.iter_sections():
            if section.name == section_name:
                    return section
        return None
    else:
        return None


def obtain_section_data(section_name, elf=None, file_data=None, min_size=0):
    """
    Obtain the data in a specified ELF section of a file.

    :param section_name: The name of the section from which to extract data.
    :param elf: elftools.ELFFile object
    :param file_data: Input file data
    :param min_size: The minimum acceptable size for the section_data

    :return: The PE section data, or None.
    """
    if file_data:
        elf = obtain_elf(file_data)
    if elf:
        section = obtain_section(section_name, elf)
        if section:
            section_data = section.data()
            if len(section_data) > min_size:
                return section_data
            return None
        return None
    else:
        return None


def check_section(section_name, elf=None, file_data=None):
    """
    Check if a specified ELF section exists in a file.

    :param section_name: The name of the section from which to extract data.
    :param elf: elftools.ELFFile object
    :param file_data: Input file data

    :return: True if the section name is observed, False if it is not.
    """
    if file_data:
        elf = obtain_elf(file_data)
    if elf and obtain_section(section_name, elf):
        return True
    return False


def obtain_physical_offset(mem_offset, elf=None, file_data=None):
    """
    For an ELF file (in x86), convert a provided memory offset to a raw offset.

    :param mem_offset: The memory offset to convert to a raw offset
    :param elf: elftools.ELFFile object
    :param file_data: Input file data

    :return: Raw offset, or None.
    """
    if file_data:
        elf = obtain_elf(file_data)
    if elf:
        for phy_offset in elf.address_offsets(mem_offset):
            return phy_offset
    return None


def obtain_memory_offset(phy_offset, elf=None, file_data=None):
    """
    For an ELF file, convert a provided raw offset to a memory offset.

    :param phy_offset: The raw offset to convert to a memory offset
    :param elf: elftools.ELFFile object
    :param file_data: Input file data

    :return: Memory offset, or None.
    """
    if file_data:
        elf = obtain_elf(file_data)
    if elf:
        for seg in elf.iter_segments():
            if seg['p_offset'] <= phy_offset < (seg['p_offset'] + seg['p_filesz']):
                return phy_offset - seg['p_offset'] + seg['p_vaddr']
        return None
    else:
        return None
