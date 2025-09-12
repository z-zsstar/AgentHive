import time
import asyncio
from functools import wraps

def time_it(func):
    """
    A decorator that prints the execution time of the function it decorates.
    Supports both synchronous and asynchronous functions.
    """
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        start_time = time.time()
        result = await func(*args, **kwargs)
        end_time = time.time()
        print(f"Executing {func.__name__} took {end_time - start_time:.2f} seconds.")
        return result

    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"Executing {func.__name__} took {end_time - start_time:.2f} seconds.")
        return result

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper
