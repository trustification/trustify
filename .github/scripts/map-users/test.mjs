import * as fs from 'fs';
import { channelMessage, Mapper } from "./main.mjs";

const github = JSON.parse(fs.readFileSync('payload.json'))?.github;

const output = channelMessage(github.event)

console.log("Output:", output)

const args = new Mapper(github.event).directMessageArguments();
console.log("Direct:", args)

