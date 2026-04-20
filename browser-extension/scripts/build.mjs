import {readFile,mkdir,cp} from 'node:fs/promises';
const manifest=JSON.parse(await readFile(new URL('../manifest.json',import.meta.url)));
if(manifest.manifest_version!==3||manifest.host_permissions?.length||manifest.permissions.some(p=>['history','cookies','downloads','bookmarks','tabs'].includes(p)))throw Error('Unexpected extension permissions');
await mkdir(new URL('../dist',import.meta.url),{recursive:true});await cp(new URL('../manifest.json',import.meta.url),new URL('../dist/manifest.json',import.meta.url));await cp(new URL('../src',import.meta.url),new URL('../dist/src',import.meta.url),{recursive:true});console.log('Unpacked MV3 extension built in browser-extension/dist');
