/* eslint-disable @typescript-eslint/triple-slash-reference */
/// <reference path="../.astro/types.d.ts" />
/// <reference types="astro/client" />

// @pagefind/default-ui ships without type declarations
declare module "@pagefind/default-ui" {
  export class PagefindUI {
    constructor(options: Record<string, unknown>);
    triggerSearch(term: string): void;
    destroy(): void;
  }
}
