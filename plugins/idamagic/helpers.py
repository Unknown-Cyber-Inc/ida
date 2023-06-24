def to_bool(param, default=False):
    """Convert a string environment variable to a boolean value.

    * Strings are case insensitive.

    Parameters
    ----------
    param: str
    default: Any
        Value to return if the param is not a know boolean value.
    """
    try:
        param = param.lower()
    except AttributeError:
        # This will happen when param isn't a string
        pass

    if param in {1, "1", "true", "yes", "y", True}:
        return True

    if param in {0, "0", "false", "no", "n", "", False}:
        return False

    return default
