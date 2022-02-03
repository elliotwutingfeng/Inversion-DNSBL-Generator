"""
For fetching and scanning URLs from Domains Project
"""
import os
import pathlib
from collections.abc import AsyncIterator

from more_itertools.more import chunked, sort_together

from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions
from modules.utils.log import init_logger

logger = init_logger()

async def _get_local_file_url_list(txt_filepath: str) -> AsyncIterator[list[str]]:
    """Yields all listed URLs in batches from local text file.

    Args:
        txt_filepath (str): Filepath of local text file containing URLs

    Yields:
        AsyncIterator[list[str]]: Batch of URLs as a list
    """
    try:
        with open(txt_filepath, "r") as file:
            for raw_urls in chunked((_.strip() for _ in file.readlines()),
            hostname_expression_batch_size):
                yield generate_hostname_expressions(raw_urls)
    except OSError as error:
        logger.error(
            "Failed to retrieve local list (%s); yielding empty list: %s",
            txt_filepath,
            error,
            exc_info=True,
        )
        yield []


def _retrieve_domainsproject_txt_filepaths_and_db_filenames() -> tuple[
list[str], list[str]
]:
    """Scans for Domains Project .txt source files and generates filepaths
    to .txt source files, and database filenames for each .txt source file.

    Returns:
        tuple[list[str], list[str]]: (Filepaths to .txt source files,
        Database filenames for each .txt source file)
    """
    # Scan Domains Project's "domains" directory for domainsproject_urls_db_filenames
    domainsproject_dir = pathlib.Path.cwd().parents[0] / "domains" / "data"
    domainsproject_txt_filepaths: list[str] = []
    domainsproject_urls_db_filenames: list[str] = []
    for root, _, files in os.walk(domainsproject_dir):
        for file in files:
            if file.lower().endswith(".txt"):
                domainsproject_urls_db_filenames.append(f"{file[:-4]}")
                domainsproject_txt_filepaths.append(os.path.join(root, file))

    # Sort domainsproject_txt_filepaths and domainsproject_urls_db_filenames by ascending filesize
    domainsproject_filesizes: list[int] = [
        os.path.getsize(path) for path in domainsproject_txt_filepaths
    ]
    [
        domainsproject_filesizes,
        domainsproject_txt_filepaths,
        domainsproject_urls_db_filenames,
    ] = [
        list(_)
        for _ in sort_together(
            (
                domainsproject_filesizes,
                domainsproject_txt_filepaths,
                domainsproject_urls_db_filenames,
            )
        )
    ]
    return domainsproject_txt_filepaths, domainsproject_urls_db_filenames

class DomainsProject:
    """
    For fetching and scanning URLs from Domains Project
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        self.txt_filepaths: list[str] = []
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "domainsproject" in parser_args["sources"]:
            (self.txt_filepaths, self.db_filenames) \
            = _retrieve_domainsproject_txt_filepaths_and_db_filenames()
            if parser_args["fetch"]:
                # Extract and Add Domains Project URLs to database
                self.jobs = [
                    (
                        _get_local_file_url_list,
                        update_time,
                        db_filename,
                        {"txt_filepath": txt_filepath},
                    )
                    for txt_filepath, db_filename in zip(
                        self.txt_filepaths, self.db_filenames
                    )
                ]
