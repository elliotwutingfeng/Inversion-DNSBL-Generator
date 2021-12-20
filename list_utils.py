# Utility functions for manipulating lists
def flatten(list_of_lists):
    """Flattens a list_of_lists. Returns a generator"""
    return (item for sublist in list_of_lists for item in sublist)


def chunks(lst: list, n: int) -> list:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]