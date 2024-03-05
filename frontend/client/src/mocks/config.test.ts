import { parseMock } from "./config";

describe.each([
  // off
  {
    str: "",
    expected: { enabled: false, passthrough: false, full: false, stub: false },
  },
  {
    str: "off",
    expected: { enabled: false, passthrough: false, full: false, stub: false },
  },
  {
    str: "  off     ",
    expected: { enabled: false, passthrough: false, full: false, stub: false },
  },

  // just "full"
  {
    str: "full",
    expected: { enabled: true, passthrough: false, full: true, stub: false },
  },
  {
    str: "-full",
    expected: { enabled: false, passthrough: false, full: false, stub: false },
  },
  {
    str: "+full",
    expected: { enabled: true, passthrough: false, full: true, stub: false },
  },

  // just "passthrough"
  {
    str: "pass",
    expected: { enabled: true, passthrough: true, full: false, stub: false },
  },
  {
    str: "-pass",
    expected: { enabled: false, passthrough: false, full: false, stub: false },
  },
  {
    str: "+passthrough",
    expected: { enabled: true, passthrough: true, full: false, stub: false },
  },

  // just "stub" in various forms
  {
    str: "stub",
    expected: { enabled: true, passthrough: false, full: false, stub: "*" },
  },
  {
    str: "stub=*",
    expected: { enabled: true, passthrough: false, full: false, stub: "*" },
  },
  {
    str: "stub=A,b",
    expected: {
      enabled: true,
      passthrough: false,
      full: false,
      stub: ["a", "b"],
    },
  },
  {
    str: "stub=Alpha, Bravo, Charlie",
    expected: {
      enabled: true,
      passthrough: false,
      full: false,
      stub: ["alpha", "bravo", "charlie"],
    },
  },

  // Combine forms
  {
    str: "+full.+pass",
    expected: { enabled: true, passthrough: true, full: true, stub: false },
  },
  {
    str: "-pass.-full",
    expected: { enabled: false, passthrough: false, full: false, stub: false },
  },
  {
    str: "stub=whiskey,tango,foxtrot.pass",
    expected: {
      enabled: true,
      passthrough: true,
      full: false,
      stub: ["whiskey", "tango", "foxtrot"],
    },
  },
  {
    str: "-pass.stub=wink,nudge",
    expected: {
      enabled: true,
      passthrough: false,
      full: false,
      stub: ["wink", "nudge"],
    },
  },
  {
    str: "+pass.stub=wink,nudge.off",
    expected: {
      enabled: false,
      passthrough: true,
      full: false,
      stub: ["wink", "nudge"],
    },
  },
])("MOCK='$str'", ({ str, expected }) => {
  test("config string parses as expected", () => {
    expect(parseMock(str)).toStrictEqual(expected);
  });
});
