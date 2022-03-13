"""
For fetching and scanning URLs from AFNIC.fr
"""
import csv
from collections.abc import AsyncIterator
from datetime import date
from io import BytesIO, TextIOWrapper
from itertools import count, groupby
from typing import Any, Iterator, Optional
from zipfile import ZipFile

import cv2
import numpy as np
import pytesseract
import tldextract
from dateutil.relativedelta import relativedelta
from modules.utils.feeds import (
    generate_hostname_expressions,
    hostname_expression_batch_size,
)
from modules.utils.http_requests import get_async
from modules.utils.log import init_logger
from modules.utils.parallel_compute import execute_with_ray
from more_itertools import chunked, flatten

# import secrets


logger = init_logger()

YYYYMMDD_STR_FORMAT: str = "{dt:%Y}{dt:%m}{dt:%d}"
YYYYMM_STR_FORMAT: str = "{dt:%Y}{dt:%m}"


async def deflank(img: np.ndarray) -> np.ndarray:
    """Remove excess left/right flank whitespace
    and pad `img` image with white border to improve OCR accuracy

    See
    https://github.com/tesseract-ocr/tessdoc/blob/main/ImproveQuality.md#page-segmentation-method

    Args:
        img (np.ndarray): `img` image as numpy array

    Returns:
        np.ndarray: Cropped `img` image as numpy array
    """
    # Find all indexes of vertical pixel lines that are completely white (255)
    L = [idx for (idx, column) in enumerate(img.T) if 0 not in column]

    # Group these indexes together to index ranges
    groups: groupby[Any, int] = groupby(
        L, key=lambda item, c=count(): item - next(c)  # type:ignore
    )
    ranges: list[tuple[int, int]] = [(h[0], h[-1]) for _, g in groups if (h := list(g))]

    # Vertical pixel lines at which to split image will be the extremes of each
    # of these index ranges
    lines_to_split_at: list[int] = list(flatten(ranges))

    # Start and end of text block
    start, end = lines_to_split_at[1], lines_to_split_at[-2]

    # Pad image with 5 pixel thick white border
    return np.pad(img[:, start:end], pad_width=5, mode="constant", constant_values=255)


async def extract_text_string(image: np.ndarray, link: str) -> list[str]:
    """Scan and extract text from `image` numpy array with Google Tesseract

    Args:
        image (np.ndarray): To be scanned for text
        link (str): URL source of image to be scanned

    Returns:
        list[str]: List of text lines detected in `image`
    """
    try:
        pytesseract_results = pytesseract.image_to_string(
            image,
            config=r"--oem 0 --psm 7 -c load_system_dawg=0 -c "
            "load_freq_dawg=0 -c min_characters_to_try=4",
        )
        return pytesseract_results.splitlines()
    except pytesseract.pytesseract.TesseractError as error:
        # with open(f'{link.replace("/","")}_'
        # f'{secrets.token_urlsafe(16)}.npy','wb') as f:
        #    np.save(f,image)
        logger.warning("%s %s", error, image.shape)
        return []


def ocr_extract(image_data: bytes, link: str, tld: str) -> list[str]:
    """Scan for all valid URLs from a given `image_data` bytes string

    Args:
        image_data (bytes): Bytes string of image to be scanned
        link (str): URL source of image to be scanned
        tld (str): Top Level Domain to scan for

    Returns:
        list[str]: Valid URLs found in `image_data`
    """
    # Read image as grayscale
    main_img = cv2.imdecode(np.asarray(bytearray(image_data), dtype="uint8"), cv2.IMREAD_GRAYSCALE)
    # Enlarge image
    main_img = cv2.resize(main_img, None, fx=4, fy=4, interpolation=cv2.INTER_LANCZOS4)
    # Convert to black and white
    (_, main_img) = cv2.threshold(main_img, 210, 255, cv2.THRESH_BINARY)

    # Find all indexes of horizontal pixel lines
    # that are completely white (255)
    L = [idx for (idx, row) in enumerate(main_img) if 0 not in row]

    # Group these indexes together to index ranges
    groups: groupby[Any, int] = groupby(
        L, key=lambda item, c=count(): item - next(c)  # type:ignore
    )
    ranges: list[tuple[int, int]] = [(h[0], h[-1]) for _, g in groups if (h := list(g))]

    # Horizontal pixel lines at which to split main_img will be the extremes of each
    # of these index ranges
    lines_to_split_at: Iterator[int] = flatten(ranges)

    # Split img vertically at each line, exclude purely white line_imgs
    # Remove whitespace on left and right flanks of each line_img

    line_imgs_before_deflank: list[tuple] = [
        (line_img,)
        for line_img in np.split(main_img, list(lines_to_split_at))
        if bool((line_img != 255).any())  # line_img must have at least 1 black pixel
        and all(line_img.shape)  # line_img cannot be empty
    ]
    del main_img
    line_imgs = execute_with_ray(deflank, line_imgs_before_deflank, progress_bar=False)

    # Extract text from each line_img
    text_lines: list[str] = list(
        flatten(
            execute_with_ray(
                extract_text_string,
                [(image,) for image in line_imgs],
                object_store={"link": link},
                progress_bar=False,
            )
        )
    )

    # Filter away lines with '#', remove spaces, replace '’', "'", "`" with i, I with l
    text_lines = [
        text_line.replace(" ", "")
        .translate({ord(chr): "i" for chr in ["’", "'", "`"]})
        .replace("I", "l")
        for text_line in text_lines
        if "#" not in text_line
    ]
    # Repair missing '.' in tld suffix
    urls: list[str] = [
        text_line[:-2] + f".{tld}"
        if (text_line.endswith(tld) and not text_line.endswith(f".{tld}"))
        else text_line
        for text_line in text_lines
    ]

    # Exclude invalid URLs
    urls = [u for u in urls if tldextract.extract(u).suffix == tld]

    return urls


async def get_afnic_daily_updates(tld: str, num_days: Optional[int]) -> AsyncIterator[set[str]]:
    """Download and extract domains from AFNIC.fr daily updates (PNG files) for a given `tld`
    and yield all listed URLs in batches.

    Args:
        tld (str): AFNIC.fr tld
        num_days (int, optional): Counting back from current date,
        the number of days of AFNIC.fr daily updates to fetch and/or analyse. If set to `None`,
        `num days` will be set to 0.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    raw_urls: list[str] = []

    today = date.today()

    if num_days is None:
        num_days = 0
    days = [today + relativedelta(days=-x) for x in range(num_days)]

    links: list[str] = [
        "https://www.afnic.fr/wp-sites/uploads/domaineTLD_Afnic/"
        f"{YYYYMMDD_STR_FORMAT}_CREA_{tld}.png".format(dt=date)
        for date in days
    ]

    for link in links:
        # Download PNG file to memory
        image_data: bytes = (await get_async(links, max_concurrent_requests=1, max_retries=2))[link]
        if image_data != b"{}":
            # Extract URLs from PNG file
            raw_urls = ocr_extract(image_data, link, tld)
            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)


async def get_afnic_monthly_archives() -> AsyncIterator[set[str]]:
    """Download and extract domains from AFNIC.fr monthly archives
    and yield all listed URLs in batches.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    raw_urls: list[str] = []

    today = date.today()

    # Archives files are only kept for the past 24 months, we only need the latest version
    months = [today + relativedelta(months=-x) for x in range(24)]

    # AFNIC.fr monthly archive files
    endpoints: list[str] = [
        "https://www.afnic.fr/wp-media/ftp/documentsOpenData/"
        f"{YYYYMM_STR_FORMAT}_OPENDATA_A-NomsDeDomaineEnPointFr.zip".format(dt=date)
        for date in months
    ]

    for endpoint in endpoints:
        with BytesIO() as file:
            resp = (await get_async([endpoint], max_concurrent_requests=1, max_retries=2))[endpoint]
            if resp != b"{}":
                file.write(resp)
                file.seek(0)
                zfile = ZipFile(file)
                csv_filename = [
                    filename for filename in zfile.namelist() if filename.endswith(".csv")
                ][0]
                with zfile.open(csv_filename) as csvfile:
                    reader = csv.reader(TextIOWrapper(csvfile, "ISO-8859-1"), delimiter=";")
                    next(reader, None)  # skip the headers
                    for row in reader:
                        raw_urls.append(row[0])
                for batch in chunked(raw_urls, hostname_expression_batch_size):
                    yield generate_hostname_expressions(batch)
                break  # we only need the first accessible archive


class AFNIC:
    """
    For fetching and scanning URLs from AFNIC.fr
    """

    def __init__(self, parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        self.num_days: Optional[int] = parser_args["afnic_num_days"]

        if "afnic" in parser_args["sources"]:
            tlds: tuple[str, ...] = ("fr", "re", "pm", "tf", "wf", "yt")
            self.db_filenames = [f"afnic_{tld}" for tld in tlds] + ["afnic_monthly_archive"]
            if parser_args["fetch"]:
                # Download and Add AFNIC.fr URLs to database
                # Use list() otherwise mypy will complain about list invariance
                self.jobs = list(
                    [
                        (
                            get_afnic_daily_updates,
                            update_time,
                            db_filename,
                            {"tld": tld, "num_days": self.num_days},
                        )
                        for db_filename, tld in zip(self.db_filenames, tlds)
                    ]
                    + [
                        (
                            get_afnic_monthly_archives,
                            update_time,
                            self.db_filenames[-1],
                        )  # type:ignore
                    ]
                )
