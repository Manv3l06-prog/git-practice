import asyncio
import time

async def slow_operation():
    print("Start wait")
    await asyncio.sleep(3)
    print("End wait")

async def ticker():
    for number in range(1, 4):
        await asyncio.sleep(1)
        print(f"Тик {number}")

async def main():
    await asyncio.gather(
        slow_operation(),
        ticker(),
    )

asyncio.run(main())