"""
This module processes a logarchive packet by extracting metadata from tracev3,
timesync, and version plist files. It aggregates this information into a
structured Info.plist file needed to use the log show command with a logarchive
packet from macOS 26.4 and above.

The script:
1. Validates the input logarchive directory
2. Processes timesync data to get the last boot UUID
3. Extracts metadata and retrieves the most recent continuous time from tracev3
    files in Special, Signpost, Persist, and HighVolume directories
4. Retrieves information from version.plist
5. Generates an Info.plist file with all collected metadata

Usage:
    python logarchive_info.py <path_to_logarchive_packet>
        Path to the logarchive packet directory (must be an existing directory)

Outputs:
    Info.plist: A plist file containing requested metadata to be able to use
    the log show command with a logarchive packet from macOS 26.4 and above.
"""


import plistlib
import struct
import uuid
import argparse
from pathlib import Path


def get_timesync_uuid_from(directory_name):
    """
    Extract UUID from the most recent .timesync files in a given directory.
    Args:
        directory_name: Path to the directory containing .timesync files.
    Returns:
        None: Modifies the global plist_data dictionary with the following keys:
            - LiveMetadata (dict): Contains "OldestTimeRef" with ContinuousTime (0) and UUID.
            - EndTimeRef (dict): Contains estimated continuous time and UUID.
    """
    timesync_header = b'\xb0\xbb\x30\x00\x00\x00\x00\x00'
    timesync_filenames = []
    for timesync_filename in Path(directory_name).iterdir():
        if timesync_filename.suffix == ".timesync":
            with open(timesync_filename, "rb") as timesync_file:
                if timesync_file.read(8) == timesync_header:
                    timesync_filenames.append(timesync_filename)
    if timesync_filenames:
        with open(sorted(timesync_filenames)[-1], "rb") as timesync_file:
            timesync_data = timesync_file.read()
            last_timesync_boot_record_offset = timesync_data.rfind(timesync_header)
            timesync_file.seek(last_timesync_boot_record_offset + 0x08)
            data = timesync_file.read(0x10)
            return str(uuid.UUID(bytes=data)).upper()
    return None


def get_data_from_version_plist(version_plist_path):
    """
    Extract version information from the version.plist file and populate
    plist_data dictionary.
    Args:
        version_plist_path: A Path object pointing to the version.plist file.
    Returns:
        None. The function modifies plist_data in place.
    """
    if version_plist_path.exists():
        with open(version_plist_path, "rb") as version_plist_file:
            version_plist_data = plistlib.load(version_plist_file)
            if version_plist_data:
                if "Identifier" in version_plist_data:
                    plist_data["SourceIdentifier"] = version_plist_data["Identifier"]
                ttl = plist_data["SpecialMetadata"].setdefault("TTL", {})
                ttl_keys = ["ttl01", "ttl03", "ttl07", "ttl14", "ttl30"]
                for ttl_key in ttl_keys:
                    if ttl_key in version_plist_data:
                        ttl[ttl_key] = version_plist_data[ttl_key]


def get_oldest_and_most_recent_tracev3_files_from(directory_name):
    """
    Retrieve the oldest and most recent tracev3 files from a specified directory.
    Args:
        directory_name: The path to the directory to search for tracev3 files.
    Returns:
        list[Path]: A list containing up to two Path objects:
            - If tracev3 files are found: [oldest_file, most_recent_file]
            - If no valid tracev3 files are found: An empty list []
    """
    tracev3_header = b'\x00\x10\x00\x00\x11\x00\x00\x00\xd0\x00\x00\x00\x00\x00\x00\x00'
    tracev3_filenames = []
    for tracev3_filename in Path(directory_name).iterdir():
        if tracev3_filename.suffix == ".tracev3":
            with open(tracev3_filename, "rb") as tracev3_file:
                if tracev3_file.read(16) == tracev3_header:
                    tracev3_filenames.append(tracev3_filename)
    if tracev3_filenames:
        sorted_tracev3_filenames = sorted(tracev3_filenames)
        tracev3_filenames = [
            sorted_tracev3_filenames[0],
            sorted_tracev3_filenames[-1],
        ]
    return tracev3_filenames


def get_metadata_and_last_continous_time(metadata_directory, uuid_timesync):
    """
    Extract metadata and last continuous time from tracev3 files.
    Args:
        metadata_directory: Path to the directory containing tracev3 files.
    Returns:
        None: Updates global dictionaries `plist_data` and `last_continuous_time`
        with extracted metadata and file modification timestamp.
    """
    tracev3_filename = get_oldest_and_most_recent_tracev3_files_from(metadata_directory)
    if tracev3_filename:
        metadata = plist_data.setdefault(f"{directory}Metadata", {})
        with open(tracev3_filename[0], "rb") as tracev3_file:
            header = tracev3_file.read(0xA0)
            metadata["OldestTimeRef"] = {
                "ContinuousTime": struct.unpack("<Q", header[0x40:0x48])[0],
                "UUID": str(uuid.UUID(bytes=header[0x90:0xA0])).upper(),
                "WallTime": struct.unpack("<L", header[0x20:0x24])[0] * 1_000_000_000,
            }
        with open(tracev3_filename[-1], "rb") as tracev3_file:
            catalog_chunk_signature = b'\x0B\x60\x00\x00\x11\x00\x00\x00'
            header = tracev3_file.read(0xA0)
            tracev3_uuid = str(uuid.UUID(bytes=header[0x90:0xA0])).upper()
            if tracev3_uuid == uuid_timesync:
                tracev3_file.seek(0, 2)
                tracev3_file_size = tracev3_file.tell()
                chunk_size = 0x1000
                while tracev3_file_size > 0:
                    chunk_start = max(0, tracev3_file_size - chunk_size)
                    tracev3_file.seek(chunk_start)
                    chunk = tracev3_file.read(chunk_size)
                    offset = chunk.rfind(catalog_chunk_signature)
                    if offset != -1:
                        catalog_chunk_start = chunk_start + offset
                        break
                    else:
                        tracev3_file_size -= chunk_size
                tracev3_file.seek(catalog_chunk_start)
                catalog_chunk_header = tracev3_file.read(0x28)
                catalog_sub_chunk_start = struct.unpack("<H", catalog_chunk_header[0x16:0x18])[0]
                number_of_sub_chunks = struct.unpack("<H", catalog_chunk_header[0x18:0x1A])[0]
                tracev3_file.seek(catalog_sub_chunk_start, 1)
                for _ in range(number_of_sub_chunks):
                    tracev3_file.seek(0x08, 1)
                    end_continuous_time = struct.unpack("<Q", tracev3_file.read(8))[0]
                    tracev3_file.seek(0x08, 1)
                    index_number = struct.unpack("<L", tracev3_file.read(4))[0]
                    tracev3_file.seek(0x02 * index_number, 1)
                    string_ofset_number = struct.unpack("<L", tracev3_file.read(4))[0]
                    tracev3_file.seek(0x02 * string_ofset_number, 1)
                    align_padding = (8 - (tracev3_file.tell() % 8)) % 8
                    tracev3_file.seek(align_padding, 1)
                last_continuous_times.append(end_continuous_time)


def existing_directory(user_path):
    """
    Validate that the provided path is an existing directory.
    Args:
        user_path: The path to validate.
    Returns:
        Path: The absolute path if it is a valid directory.
    """
    if not Path(user_path).is_dir():
        raise argparse.ArgumentTypeError(f"'{user_path}' is not an existing logarchive packet.")
    return Path(user_path).absolute()


parser = argparse.ArgumentParser(description="Parse a logarchive packet.")
parser.add_argument("directory", type=existing_directory, help="Path to the logarchive packet.")
args = parser.parse_args()

plist_data = {}
plist_data["OSArchiveVersion"] = 5
last_continuous_times = []

print(f"logarchive packet to parse: {args.directory}")
logarchive_directory = args.directory
most_recent_timesync_uuid = get_timesync_uuid_from(logarchive_directory.joinpath("timesync"))
metadata_directories = ["Special", "Signpost", "Persist", "HighVolume"]

for directory in metadata_directories:
    metadata_path = logarchive_directory.joinpath(directory)
    get_metadata_and_last_continous_time(metadata_path, most_recent_timesync_uuid)


live_metadata = plist_data.setdefault("LiveMetadata", {})
live_metadata["OldestTimeRef"] = {
    "ContinuousTime": 0,
    "UUID": most_recent_timesync_uuid,
}

last_continuous_time = max(last_continuous_times)
plist_data["EndTimeRef"] = {
    "ContinuousTime": last_continuous_time,
    "UUID": most_recent_timesync_uuid,
}

if "SpecialMetadata" in plist_data:
    get_data_from_version_plist(logarchive_directory.joinpath("version.plist"))


plist_path = logarchive_directory.joinpath("Info.plist")
with open(plist_path, "wb") as plist_file:
    plistlib.dump(plist_data, plist_file, sort_keys=True)
    print(f"Info.plist generated in {plist_path}")
