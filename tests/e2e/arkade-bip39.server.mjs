import {createServer} from 'node:http'

createServer((_request, response) => {
  response.writeHead(200, {'content-type': 'text/html'})
  response.end('<!doctype html><title>Arkade browser proof</title>')
}).listen(4173, '127.0.0.1')
