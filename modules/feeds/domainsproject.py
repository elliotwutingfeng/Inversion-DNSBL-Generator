"""
For fetching and scanning URLs from Domains Project
"""
import os
import pathlib
from collections.abc import AsyncIterator

from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.log import init_logger
from more_itertools.more import chunked, sort_together

logger = init_logger()


async def _get_local_file_url_list(
    txt_filepath: str,
) -> AsyncIterator[set[str]]:
    """Yield all listed URLs in batches from local text file.

    Args:
        txt_filepath (str): Filepath of local text file containing URLs

    Yields:
        AsyncIterator[set[str]]: Batch of URLs as a set
    """
    try:
        with open(txt_filepath, "r") as file:
            for raw_urls in chunked(
                (_.strip() for _ in file.readlines()),
                hostname_expression_batch_size,
            ):
                yield generate_hostname_expressions(raw_urls)
    except OSError as error:
        logger.error(
            "Failed to retrieve local list (%s); yielding empty list: %s",
            txt_filepath,
            error,
            exc_info=True,
        )
        yield set()


def _retrieve_domainsproject_txt_filepaths_and_db_filenames() -> (
    tuple[list[str], list[str]]
):
    """Scan for Domains Project .txt source files and generate filepaths
    to .txt source files, and database filenames for each .txt source file.

    Returns:
        tuple[list[str], list[str]]: (Filepaths to .txt source files,
        Database filenames for each .txt source file)
    """
    # Scan Domains Project's "domains" directory for
    # domainsproject_urls_db_filenames
    domainsproject_txt_filepaths: list[str] = []
    domainsproject_urls_db_filenames: list[str] = []
    try:
        domainsproject_dir = pathlib.Path.cwd().parents[0] / "domains" / "data"
        for root, _, files in os.walk(domainsproject_dir):
            for file in files:
                if file.lower().endswith(".txt"):
                    domainsproject_urls_db_filenames.append(f"{file[:-4]}")
                    domainsproject_txt_filepaths.append(os.path.join(root, file))

        # Sort domainsproject_txt_filepaths and
        # domainsproject_urls_db_filenames by descending filesize
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
                ),
                reverse=True,
            )
        ]
    except ValueError as error:
        logger.error(
            "Scan for Domains Project source files failed, check if Domains Project folder has been downloaded correctly | %s",
            repr(error),
        )
    return domainsproject_txt_filepaths, domainsproject_urls_db_filenames


class DomainsProject:
    """
    For fetching and scanning URLs from Domains Project
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.txt_filepaths: list[str] = []
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        if "domainsproject" in parser_args["sources"]:
            (
                self.txt_filepaths,
                self.db_filenames,
            ) = _retrieve_domainsproject_txt_filepaths_and_db_filenames()
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
