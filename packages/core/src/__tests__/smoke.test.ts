import { describe, expect, it } from "vitest";

import { PROTOCOL_VERSION } from "../index";

describe("core 骨架", () => {
  it("导出协议版本", () => {
    expect(PROTOCOL_VERSION).toBe("0.1.0");
  });
});
