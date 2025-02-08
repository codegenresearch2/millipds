import asyncio
import sqlite3

async def queue_get_task(queue):
    try:
        return await queue.get()
    except asyncio.QueueEmpty:
        return None

async def service_run_and_capture_port(service_command, queue):
    process = await asyncio.create_subprocess_exec(*service_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f'Service failed with error: {stderr.decode()}')
    port = stdout.decode().strip()
    await queue.put(port)

def initialize_database():
    conn = sqlite3.connect('config.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS config
                      (key TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()
    conn.close()

async def update_config(key, value):
    conn = sqlite3.connect('config.db')
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

async def main():
    initialize_database()
    queue = asyncio.Queue()
    service_command = ['your_service_command_here']
    await asyncio.gather(
        service_run_and_capture_port(service_command, queue),
        update_config('service_port', await queue_get_task(queue))
    )

if __name__ == '__main__':
    asyncio.run(main())