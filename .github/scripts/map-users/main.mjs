import * as fs from 'fs';
import * as yaml from 'js-yaml';

export class Mapper {
  constructor(payload) {
    this.payload = payload;

    const mappingFile = new URL("../../matrix-users.yaml", import.meta.url);
    this.mappings = yaml.load(fs.readFileSync(mappingFile));
  }

  requestedReviewers() {
    let users = [];

    for (let user of this.payload?.pull_request?.requested_reviewers) {

      const login = user?.login;
      if (login === undefined) {
        continue;
      }

      users.push(login);
    }

    return users;
  }

  _formatMessage(matrixUsers) {
    if (!matrixUsers.length) {
      return undefined;
    }

    let s = (matrixUsers.length > 1) ? "s" : "";

    matrixUsers = matrixUsers.join(", ")

    return `Assigned ${matrixUsers} as reviewer${s} for PR: ${this.payload?.pull_request?.html_url}`
  }

  mapForChannel() {
    let matrixUsers = [];

    for (let user of this.requestedReviewers()) {
      let m = this.mappings?.mapForChannel?.[user];
      if (m !== undefined) {
        matrixUsers.push(m);
      }
    }

    return matrixUsers;
  }

  mapForDirectMessage () {
    let matrixUsers = [];

    for (let user of this.requestedReviewers()) {
      let m = this.mappings?.mapForDirectMessage?.[user];
      if (m !== undefined) {
        matrixUsers.push(m);
      }
    }

    return matrixUsers;
  }

  /// Return the message which should be sent to the channel (or none).
  channelMessage () {
    return this._formatMessage(this.mapForChannel());
  }

  /// Return the users receiving a direct message, as `--user <user>` arguments, ready to be passed to matrix-commander
  directMessageArguments() {
    return this.mapForDirectMessage().map(user => `--user "${user}"`).join(" ");
  }
}

export function channelMessage(payload) {
  const mapper = new Mapper(payload);

  const users = mapper.requestedReviewers();
  const channelUsers = mapper.mapForChannel();

  console.log("Users:", users);
  console.log("Matrix Users:", channelUsers);

  return mapper.channelMessage();
}

export function directMessage(payload) {
  const mapper = new Mapper(payload);

  const users = mapper.requestedReviewers();
  const channelUsers = mapper.mapForDirectMessage();

  console.log("Users:", users);
  console.log("Matrix Users:", channelUsers);

  return mapper.directMessageArguments();
}
