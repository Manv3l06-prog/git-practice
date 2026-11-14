import asyncio
from time import perf_counter

async def request():
    await asyncio.sleep(2)
    return "Answer is got"

async def request1(name, delay):
    await asyncio.sleep(delay)
    return f"{name}: done"

async def main():
    start = perf_counter()

    result = await asyncio.gather(
        request1("A", 1),
        request1("B", 3),
        request1("C", 2),
    )
    print(result)
    print(f"Прошло: {perf_counter() - start:.2f} секунд")

asyncio.run(main())