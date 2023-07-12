from typing import Callable, Coroutine
import asyncio

async def in_sequence(
    *arg_tasks: Callable[[], Coroutine]
) -> Callable[[], Coroutine]:  # <-- New signature
    """
    Builds the coroutines just in time (JIT) before execution,
    similar to how daemons execute arbitrary methods.
    """

    async def coro():
        """Executes coroutines in sequence"""
        tasks = iter(arg_tasks)
        try:
            for task in tasks:
                await task()  # <-- create JIT

        # Terminates all other tasks scheduled for execution in event loop to prevent "RuntimeWarning: coroutine was never awaited" message
        finally:
            for remaining_task in tasks:
                pass
                # remaining_task.close() # <-- Not needed now

    return coro


async def amain(devs):
    """example usage"""
    await asyncio.gather(
        in_sequence(
            await devs.dev0.methodA(),
            await devs.dev0.methodB(),
        )
        if devs.dev0
        else asyncio.sleep(0),
        in_sequence(
            await devs.dev1.stop(),
            await devs.dev1.cfg(1),
            await devs.dev1.start(),
        )
        if devs.dev1
        else asyncio.sleep(0),
     )

if __name__ == "__main__":
    asyncio.run(amain())