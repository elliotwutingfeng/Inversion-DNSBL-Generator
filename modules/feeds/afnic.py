"""
For fetching and scanning URLs from AFNIC.fr
"""
from itertools import groupby, count
from collections.abc import AsyncIterator
from datetime import datetime,timedelta
from typing import Any,Union
# import secrets

import cv2
import pytesseract
import numpy as np
import tldextract
from more_itertools import chunked,flatten
from modules.utils.http import get_async

from modules.utils.log import init_logger
from modules.utils.feeds import hostname_expression_batch_size,generate_hostname_expressions
from modules.utils.parallel_compute import execute_with_ray


logger = init_logger()

DATE_STR_FORMAT: str = "{dt:%Y}{dt:%m}{dt:%d}"

async def deflank(img: np.ndarray) -> np.ndarray:
    """Remove excess left/right flank whitespace 
    and pad `img` image with white border to improve OCR accuracy

    See https://github.com/tesseract-ocr/tessdoc/blob/main/ImproveQuality.md#page-segmentation-method

    Args:
        img (np.ndarray): `img` image as numpy array

    Returns:
        np.ndarray: Cropped `img` image as numpy array
    """
    # Find all indexes of vertical pixel lines that are completely white (255)
    L = [idx for (idx,column) in enumerate(img.T) if 0 not in column]
    
    # Group these indexes together to index ranges
    groups: groupby[Any,int] = groupby(L, key=lambda item, c=count():item-next(c)) # type:ignore
    ranges: list[tuple[int,int]] = [(h[0],h[-1]) for _, g in groups if (h:= list(g))]
    
    # Vertical pixel lines at which to split image will be the extremes of each
    # of these index ranges
    lines_to_split_at: list[int] = list(flatten(ranges))

    # Start and end of text block
    start,end = lines_to_split_at[1],lines_to_split_at[-2]
    
    # Pad image with 5 pixel thick white border
    return np.pad(img[:,start:end], pad_width=5, mode='constant', constant_values=255)

async def extract_text_string(image: np.ndarray, link: str) -> list[str]:
    """Scan and extract text from `image` numpy array with Google Tesseract

    Args:
        image (np.ndarray): To be scanned for text
        link (str): URL source of image to be scanned

    Returns:
        list[str]: List of text lines detected in `image`
    """
    try:
        pytesseract_results = pytesseract.image_to_string(image,
        config=r'--oem 0 --psm 7 -c load_system_dawg=0 -c load_freq_dawg=0 -c min_characters_to_try=4')
        return pytesseract_results.splitlines()
    except pytesseract.pytesseract.TesseractError as error:
        # with open(f'{link.replace("/","")}_{secrets.token_urlsafe(16)}.npy','wb') as f:
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
    main_img = cv2.resize(main_img, None, fx=10, fy=10, interpolation=cv2.INTER_LANCZOS4)
    # Convert to black and white
    (_,main_img) = cv2.threshold(main_img, 210, 255, cv2.THRESH_BINARY)
    
    # Find all indexes of horizontal pixel lines that are completely white (255)
    L = [idx for (idx,row) in enumerate(main_img) if 0 not in row]

    # Group these indexes together to index ranges
    groups: groupby[Any,int] = groupby(L, key=lambda item, c=count():item-next(c)) # type:ignore
    ranges: list[tuple[int,int]] = [(h[0],h[-1]) for _, g in groups if (h:= list(g))]

    # Horizontal pixel lines at which to split main_img will be the extremes of each
    # of these index ranges
    lines_to_split_at: list[int] = list(flatten(ranges))

    # Split img vertically at each line of lines_to_split_at, exclude purely white line_imgs
    # Remove whitespace on left and right flanks of each line_img
    line_imgs = execute_with_ray(deflank,[(line_img,) for line_img in np.split(main_img,lines_to_split_at) 
                if bool((line_img != 255).any()) # line_img must have at least 1 black pixel
                and all(line_img.shape) # line_img cannot be empty
                                         ], progress_bar=False)
    
    del main_img

    # Extract text from each line_img
    text_lines: list[str] = list(flatten(execute_with_ray(extract_text_string,
    [(image,) for image in line_imgs], object_store={"link":link} , progress_bar=False)))
    
    # Filter away lines with '#', remove spaces, replace '’', "'", "`" with i, I with l
    text_lines = [text_line
                  .replace(' ','')
                  .translate({ord(chr): 'i' for chr in ['’', "'", "`"]})
                  .replace("I","l")
            for text_line in text_lines if '#' not in text_line]
    # Repair missing '.' in tld suffix
    urls: list[str] = [text_line[:-2]+f".{tld}" if (text_line.endswith(tld) and not text_line.endswith(f".{tld}"))
            else text_line for text_line in text_lines]
    
    # Exclude invalid URLs
    urls = [u for u in urls if tldextract.extract(u).suffix == tld]
    
    return urls

async def get_afnic_domains(tld: str, num_days: Union[int, None]) -> AsyncIterator[set[str]]:
    """Download and extract domains from AFNIC.fr PNG files for a given `tld`
    and yield all listed URLs in batches.

    Args:
        tld (str): AFNIC.fr tld
        num_days (int, optional): Counting back from current date, 
        the number of days of AFNIC.fr data to fetch and/or analyse. If set to `None`,
        all available data dating back to 1 February 2021 will be considered.

    Yields:
        Iterator[AsyncIterator[set[str]]]: Batch of URLs as a set
    """
    now = datetime.now()
    if num_days is None:
        num_days = (now - datetime.strptime("1 February 2021", "%d %B %Y")).days
    dates = [now - timedelta(days=x) for x in range(num_days)]

    # Download PNG files to memory
    links: list[str] = [
        f"https://www.afnic.fr/wp-sites/uploads/domaineTLD_Afnic/{DATE_STR_FORMAT}_CREA_{tld}.png".format(dt=date)
    for date in dates]
    images: dict[str,bytes] = await get_async(links, max_concurrent_requests=1, max_retries=2)

    # Extract URLs from each PNG file
    for link,image_data in images.items():
        if image_data != b"{}":
            raw_urls: list[str] = ocr_extract(image_data,link,tld)
            for batch in chunked(raw_urls, hostname_expression_batch_size):
                yield generate_hostname_expressions(batch)


class AFNIC:
    """
    For fetching and scanning URLs from AFNIC.fr
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,parser_args: dict, update_time: int):
        self.db_filenames: list[str] = []
        self.jobs: list[tuple] = []
        self.num_days: Union[int,None] = parser_args["afnic_num_days"]

        tlds: tuple[str,...] = ("fr", "re", "pm", "tf", "wf", "yt")

        if "afnic" in parser_args["sources"]:
            self.db_filenames = [f"afnic_{tld}" for tld in tlds]
            if parser_args["fetch"]:
                # Download and Add AFNIC.fr URLs to database
                self.jobs = [(get_afnic_domains, update_time, db_filename, {'tld':tld,'num_days': self.num_days})
                for db_filename,tld in zip(self.db_filenames,tlds)]