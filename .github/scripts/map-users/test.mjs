import * as fs from 'fs';
import { channelMessage, Mapper } from "./main.mjs";

// const github = JSON.parse(fs.readFileSync('payload.json'))?.github;
// const output = channelMessage(github.event)

const payload = JSON.parse(fs.readFileSync('payload.json'));
const output = channelMessage(payload)

console.log("Output:", output)

const args = new Mapper(payload).directMessageArguments();
console.log("Direct:", args)

