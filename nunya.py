import asyncio


def mark_done(future):
    future.set_result(None)


class Nun:
    """Set this in lieu of another class. Any method calls to this class fail silently"""

    def __init__(self) -> None:
        pass

    def __getattr__(self, name: str):
        """
        Return another instance of Nun so chained attribute calls inevitably result in
        __call__ or __getattr__ to a Nun object"""
        return Nun()

    def __call__(self, *args, **kwargs):
        return Nun()

    def __iter__(self):
        return self

    def __next__(self):

        return 1

    def __bool__(self):
        return False

    def __await__(self):
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        loop.call_soon(mark_done, future)
        return future.__await__()


class Hachiko:
    def __init__(self) -> None:
        self.dut = Nun()
        self.cut = Nun()
        self.but = Nun()
        self.aut = Nun()


async def amain():
    hk = Hachiko()
    x, y, z = hk.dut.syncmethod()  # returns None
    hk.dut.attribute  # returns None
    hk.dut.attribute.syncmethod()
    hk.dut.a.a.a.a
    await hk.dut.amethod()
    nun = Nun()
    nun.a()
    await nun  # dut
    await nun.a()  # dut.method()

    await nun.a().a()  # dut.method() i dont even know which method is async here

    print(x)

if __name__ == "__main__":
    asyncio.run(amain())
