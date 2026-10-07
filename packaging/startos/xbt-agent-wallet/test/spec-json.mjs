// Print the package's container spec (startos/spec.ts) for a config, as JSON: the StartOS-shaped regtest
// (packaging/startos/test-startos.sh) runs exactly these containers. `npm run spec -- '<config json>'`
import { IMAGES, PORTS, services } from '../startos/spec.ts'

const cfg = JSON.parse(process.argv[2] ?? '{}')
console.log(JSON.stringify({ images: IMAGES, ports: PORTS, services: services(cfg) }))
