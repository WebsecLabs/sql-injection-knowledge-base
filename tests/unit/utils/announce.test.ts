/**
 * Tests for the screen reader announcer
 * @vitest-environment jsdom
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { announce } from "../../../src/utils/announce";

describe("announce", () => {
  beforeEach(() => {
    document.body.replaceChildren();
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });
  });

  it("creates one polite status region and writes the message", () => {
    announce("Code copied to clipboard");
    announce("Code copied to clipboard");

    const regions = document.querySelectorAll('[role="status"]');
    expect(regions).toHaveLength(1);
    expect(regions[0].classList.contains("sr-only")).toBe(true);
    expect(regions[0].textContent).toBe("Code copied to clipboard");
  });

  it("clears the region before writing so repeats are announced", () => {
    const frames: FrameRequestCallback[] = [];
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => frames.push(cb));

    announce("first");
    frames.shift()!(0);
    announce("first");

    expect(document.getElementById("sr-announcer")!.textContent).toBe("");
    frames.shift()!(0);
    expect(document.getElementById("sr-announcer")!.textContent).toBe("first");
  });

  it("recreates the region after the body is replaced", () => {
    announce("one");
    document.body.replaceChildren();
    announce("two");

    expect(document.getElementById("sr-announcer")!.textContent).toBe("two");
  });
});
