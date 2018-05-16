import fs = require('fs');
import util = require('util');
export const readFile = util.promisify(fs.readFile);
export const writeFile = util.promisify(fs.writeFile);
export const unlink = util.promisify(fs.unlink);
export const access = util.promisify(fs.access);
export const chmod = util.promisify(fs.chmod);
