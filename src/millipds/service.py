python\"\"\"\nimport aiohttp\nfrom aiohttp import web\nimport json\n\nasync def middleware(request, handler):\n    response = await handler(request)\n    response.headers['Content-Type'] = 'application/json'\n    return response\n\napp = web.Application(middlewares=[middleware])\n\nasync def get_data(request):\n    data = {"status": "success", "message": "Here is your data"}\n    return web.json_response(data, status=200)\n\napp.router.add_get('/data', get_data)\n\nif __name__ == '__main__':\n    web.run_app(app)\n\"\"\"\n